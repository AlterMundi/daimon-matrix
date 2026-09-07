"""Private persistence for authenticated sparse foreign evidence, not /we history."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from .canonical import canonical_bytes
from .relationship_store import _prepare_path


class MessagingInboxError(ValueError):
    """Foreign evidence conflicts or local persistence is unsafe."""


class MessagingOutboxStore:
    """Owner-local prepared envelopes, separate from inbox and RPC journals."""

    def __init__(self, path: Path) -> None:
        self.path = path.absolute()
        with self._database() as database:
            database.execute("""
                CREATE TABLE IF NOT EXISTS messaging_outbox (
                    owner TEXT NOT NULL,
                    send_id TEXT NOT NULL,
                    plan BLOB NOT NULL,
                    evidence BLOB,
                    message BLOB,
                    PRIMARY KEY(owner, send_id),
                    CHECK ((evidence IS NULL) = (message IS NULL))
                )
            """)

    @contextmanager
    def _database(self) -> Iterator[sqlite3.Connection]:
        _prepare_path(self.path)
        database = sqlite3.connect(self.path, timeout=5)
        try:
            database.row_factory = sqlite3.Row
            database.execute("PRAGMA journal_mode=DELETE")
            database.execute("PRAGMA synchronous=FULL")
            with database:
                yield database
        finally:
            database.close()

    def _reserve(
        self, owner: str, send_id: str, plan: dict[str, Any]
    ) -> dict[str, Any]:
        with self._database() as database:
            database.execute("BEGIN IMMEDIATE")
            row = database.execute(
                "SELECT plan FROM messaging_outbox WHERE owner=? AND send_id=?",
                (owner, send_id),
            ).fetchone()
            if row is not None:
                existing = dict(json.loads(row["plan"]))
                if any(
                    existing[key] != plan[key]
                    for key in (
                        "client_id",
                        "request_hash",
                        "policy_hash",
                        "origin",
                    )
                ):
                    raise ValueError("messaging_send_conflict")
                return existing
            database.execute(
                "INSERT INTO messaging_outbox (owner, send_id, plan) VALUES (?, ?, ?)",
                (owner, send_id, canonical_bytes(plan)),
            )
        return plan

    def _check_time(self, owner: str, send_id: str, now: int) -> None:
        with self._database() as database:
            row = database.execute(
                "SELECT plan FROM messaging_outbox WHERE owner=? AND send_id=?",
                (owner, send_id),
            ).fetchone()
        if row is not None:
            plan = json.loads(row["plan"])
            if now >= plan["expires_at_ms"]:
                raise ValueError("messaging_authorization_expired")
            if now < plan["issued_at_ms"]:
                raise ValueError("messaging_authorization_not_yet_valid")

    def _prepared(self, owner: str, send_id: str) -> tuple[bytes, bytes] | None:
        with self._database() as database:
            row = database.execute(
                "SELECT evidence, message FROM messaging_outbox "
                "WHERE owner=? AND send_id=?",
                (owner, send_id),
            ).fetchone()
        if row is None or row["evidence"] is None:
            return None
        return bytes(row["evidence"]), bytes(row["message"])

    def _commit(
        self, owner: str, send_id: str, envelopes: tuple[bytes, bytes]
    ) -> tuple[bytes, bytes]:
        with self._database() as database:
            database.execute("BEGIN IMMEDIATE")
            database.execute(
                "UPDATE messaging_outbox SET evidence=?, message=? "
                "WHERE owner=? AND send_id=? AND evidence IS NULL",
                (*envelopes, owner, send_id),
            )
            row = database.execute(
                "SELECT evidence, message FROM messaging_outbox "
                "WHERE owner=? AND send_id=?",
                (owner, send_id),
            ).fetchone()
            if row is None:
                raise ValueError("messaging_outbox_missing")
            result = bytes(row["evidence"]), bytes(row["message"])
        return result


class MessagingInboxStore:
    """Internal materialization sink. Receive through MessagingChannel only."""

    def __init__(self, path: Path) -> None:
        self.path = path.absolute()
        with self._database() as database:
            database.executescript("""
                CREATE TABLE IF NOT EXISTS deliveries (
                    delivery_id TEXT PRIMARY KEY,
                    bytes_hash TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS identities (
                    event_id TEXT PRIMARY KEY,
                    being_ref TEXT NOT NULL,
                    incarnation_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    bytes_hash TEXT NOT NULL,
                    UNIQUE(being_ref, incarnation_id, sequence)
                );
                CREATE TABLE IF NOT EXISTS evidence (
                    message_id TEXT NOT NULL,
                    authorization_id TEXT NOT NULL,
                    policy_hash TEXT NOT NULL,
                    event BLOB NOT NULL,
                    envelope BLOB NOT NULL,
                    PRIMARY KEY(message_id, authorization_id)
                );
                CREATE TABLE IF NOT EXISTS inbox (
                    inbox_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    message_id TEXT NOT NULL UNIQUE,
                    policy_hash TEXT NOT NULL,
                    message BLOB NOT NULL,
                    evidence BLOB NOT NULL,
                    envelope BLOB NOT NULL
                );
            """)

    @contextmanager
    def _database(self) -> Iterator[sqlite3.Connection]:
        _prepare_path(self.path)
        database = sqlite3.connect(self.path, timeout=5)
        try:
            database.row_factory = sqlite3.Row
            database.execute("PRAGMA journal_mode=DELETE")
            database.execute("PRAGMA synchronous=FULL")
            with database:
                yield database
        finally:
            database.close()

    @staticmethod
    def _delivery(database: sqlite3.Connection, raw: bytes, *, retain: bool) -> None:
        identifier = json.loads(raw)["delivery_id"]
        digest = hashlib.sha256(raw).hexdigest()
        row = database.execute(
            "SELECT bytes_hash FROM deliveries WHERE delivery_id=?", (identifier,)
        ).fetchone()
        if row is not None and row["bytes_hash"] != digest:
            raise MessagingInboxError("messaging_delivery_conflict")
        if retain and row is None:
            database.execute(
                "INSERT INTO deliveries VALUES (?, ?)", (identifier, digest)
            )

    def _check_delivery(self, raw: bytes) -> None:
        with self._database() as database:
            self._delivery(database, raw, retain=False)

    @staticmethod
    def _identity(database: sqlite3.Connection, event: Mapping[str, Any]) -> None:
        binding = (
            event["event_id"],
            event["being_ref"],
            event["origin"]["incarnation_id"],
            event["sequence"],
            hashlib.sha256(canonical_bytes(event)).hexdigest(),
        )
        rows = database.execute(
            "SELECT * FROM identities WHERE event_id=? OR "
            "(being_ref=? AND incarnation_id=? AND sequence=?)",
            binding[:4],
        ).fetchall()
        if rows:
            if len(rows) != 1 or tuple(rows[0]) != binding:
                raise MessagingInboxError("messaging_event_conflict")
            return
        database.execute("INSERT INTO identities VALUES (?, ?, ?, ?, ?)", binding)

    def _retain_evidence(
        self, event: Mapping[str, Any], raw: bytes, policy_hash: str
    ) -> None:
        payload = event["payload"]
        with self._database() as database:
            database.execute("BEGIN IMMEDIATE")
            self._delivery(database, raw, retain=True)
            self._identity(database, event)
            self._identity(database, payload["resolution_event"])
            existing = database.execute(
                "SELECT event, policy_hash FROM evidence "
                "WHERE message_id=? AND authorization_id=?",
                (payload["message_id"], payload["message_authorization_id"]),
            ).fetchone()
            if existing is not None:
                if (
                    bytes(existing["event"]) != canonical_bytes(event)
                    or existing["policy_hash"] != policy_hash
                ):
                    raise MessagingInboxError("messaging_evidence_conflict")
                return
            database.execute(
                "INSERT INTO evidence VALUES (?, ?, ?, ?, ?)",
                (
                    payload["message_id"],
                    payload["message_authorization_id"],
                    policy_hash,
                    canonical_bytes(event),
                    raw,
                ),
            )

    def _evidence(
        self, message_id: str, authorization_id: str, policy_hash: str
    ) -> dict[str, Any] | None:
        with self._database() as database:
            row = database.execute(
                "SELECT event FROM evidence "
                "WHERE message_id=? AND authorization_id=? AND policy_hash=?",
                (message_id, authorization_id, policy_hash),
            ).fetchone()
        return None if row is None else dict(json.loads(row["event"]))

    def _retain_message(
        self,
        message: Mapping[str, Any],
        evidence: Mapping[str, Any],
        raw: bytes,
        policy_hash: str,
    ) -> dict[str, Any]:
        with self._database() as database:
            database.execute("BEGIN IMMEDIATE")
            self._delivery(database, raw, retain=True)
            self._identity(database, message)
            existing = database.execute(
                "SELECT * FROM inbox WHERE message_id=?", (message["event_id"],)
            ).fetchone()
            if existing is not None:
                if (
                    bytes(existing["message"]) != canonical_bytes(message)
                    or existing["policy_hash"] != policy_hash
                ):
                    raise MessagingInboxError("messaging_message_conflict")
                return {
                    "inbox_sequence": existing["inbox_sequence"],
                    "message_id": message["event_id"],
                }
            cursor = database.execute(
                "INSERT INTO inbox "
                "(message_id, policy_hash, message, evidence, envelope) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    message["event_id"],
                    policy_hash,
                    canonical_bytes(message),
                    canonical_bytes(evidence),
                    raw,
                ),
            )
            return {
                "inbox_sequence": cursor.lastrowid,
                "message_id": message["event_id"],
            }

    def _page(
        self, *, after: int, limit: int, policy_hash: str
    ) -> list[dict[str, Any]]:
        if (
            type(after) is not int
            or not 0 <= after <= 2**53 - 1
            or type(limit) is not int
            or not 1 <= limit <= 100
        ):
            raise MessagingInboxError("messaging_page_bounds")
        with self._database() as database:
            rows = database.execute(
                "SELECT inbox_sequence, message, evidence FROM inbox "
                "WHERE inbox_sequence>? AND policy_hash=? "
                "ORDER BY inbox_sequence LIMIT ?",
                (after, policy_hash, limit),
            ).fetchall()
        return [
            {
                "inbox_sequence": row["inbox_sequence"],
                "message": json.loads(row["message"]),
                "evidence": json.loads(row["evidence"]),
            }
            for row in rows
        ]
