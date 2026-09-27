"""Private persistence for authenticated sparse foreign evidence, not /we history."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from collections.abc import Callable, Iterator, Mapping
from contextlib import closing, contextmanager
from pathlib import Path
from typing import Any

from .canonical import canonical_bytes
from .native_egress import MandatoryEgressController, OperationBinding
from .relationship_store import _prepare_path


class MessagingInboxError(ValueError):
    """Foreign evidence conflicts or local persistence is unsafe."""


class MessagingOutboxStore:
    """Owner-local prepared envelopes, separate from inbox and RPC journals."""

    def __init__(self, path: Path) -> None:
        self.path = path.absolute()
        self._egress: MandatoryEgressController | None = None
        self._egress_catalog: str | None = None
        self._egress_authorizers: dict[str, Callable[[OperationBinding], bool]] = {}
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
            database.execute("""
                CREATE TABLE IF NOT EXISTS messaging_transport_stages (
                    owner TEXT NOT NULL,
                    send_id TEXT NOT NULL,
                    phase TEXT NOT NULL CHECK (phase IN ('evidence', 'message')),
                    binding BLOB NOT NULL,
                    request BLOB NOT NULL,
                    request_sha256 TEXT NOT NULL,
                    transport_status TEXT NOT NULL CHECK (transport_status IN
                        ('prepared', 'pending', 'recipient-intake',
                         'refused', 'hub-accepted')),
                    result_sha256 TEXT,
                    response BLOB,
                    PRIMARY KEY(owner, send_id, phase)
                )
            """)

    def bind_egress(
        self,
        controller: MandatoryEgressController,
        *,
        catalog_id: str,
        owner: str,
        authorize: Callable[[OperationBinding], bool],
    ) -> None:
        if self._egress is None:
            self._egress = controller
            self._egress_catalog = catalog_id
            controller.register_catalog(
                catalog_id=catalog_id,
                path=self.path,
                resolve=self._resolve_egress,
                authorize=lambda binding: self._authorize_egress(binding),
            )
            controller.register_path("messaging-evidence-request", catalog_id)
            controller.register_path("messaging-message-request", catalog_id)
        elif self._egress is not controller or self._egress_catalog != catalog_id:
            raise ValueError("messaging_egress_already_bound")
        if owner in self._egress_authorizers:
            raise ValueError("messaging_egress_already_bound")
        self._egress_authorizers[owner] = authorize

    def _authorize_egress(self, binding: OperationBinding) -> bool:
        try:
            owner, _send_id, _phase = binding.locator.split("\0")
            authorize = self._egress_authorizers[owner]
        except (ValueError, KeyError):
            return False
        return authorize(binding) is True

    def _resolve_egress(self, locator: str) -> bytes:
        try:
            owner, send_id, phase = locator.split("\0")
        except ValueError:
            raise ValueError("messaging_egress_locator_invalid") from None
        with self._database() as database:
            row = database.execute(
                "SELECT request FROM messaging_transport_stages "
                "WHERE owner=? AND send_id=? AND phase=?",
                (owner, send_id, phase),
            ).fetchone()
        if row is None:
            raise ValueError("messaging_transport_missing")
        return bytes(row[0])

    def _transport_stages(
        self,
        owner: str,
        send_id: str,
        bindings: Mapping[str, Mapping[str, Any]],
        prepare: Callable[[str], bytes],
        *,
        projections: Mapping[str, Mapping[str, Any]],
        deadline_ms: int,
        authority_head: str,
        create: bool = True,
    ) -> dict[str, dict[str, Any]]:
        """Bind both stages atomically; local-only prepare is not called on retry."""
        if self._egress is None or self._egress_catalog is None:
            raise ValueError("messaging_egress_unbound")
        with self._database() as database:
            database.execute("BEGIN IMMEDIATE")
            if (
                database.execute(
                    "SELECT 1 FROM messaging_outbox WHERE owner=? AND send_id=? "
                    "AND evidence IS NOT NULL",
                    (owner, send_id),
                ).fetchone()
                is None
            ):
                raise ValueError("messaging_outbox_missing")
            stages = {}
            for phase, binding in bindings.items():
                encoded = canonical_bytes(binding)
                row = database.execute(
                    "SELECT binding, request, request_sha256, transport_status, "
                    "response, result_sha256 "
                    "FROM messaging_transport_stages "
                    "WHERE owner=? AND send_id=? AND phase=?",
                    (owner, send_id, phase),
                ).fetchone()
                if row is not None:
                    if (
                        bytes(row["binding"]) != encoded
                        or hashlib.sha256(row["request"]).hexdigest()
                        != row["request_sha256"]
                    ):
                        raise ValueError("messaging_transport_conflict")
                    raw, status = bytes(row["request"]), row["transport_status"]
                else:
                    if not create:
                        raise ValueError("messaging_transport_missing")
                    raw, status = prepare(phase), "prepared"
                    database.execute(
                        "INSERT INTO messaging_transport_stages "
                        "(owner, send_id, phase, binding, request, "
                        "request_sha256, transport_status) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (
                            owner,
                            send_id,
                            phase,
                            encoded,
                            raw,
                            hashlib.sha256(raw).hexdigest(),
                            status,
                        ),
                    )
                stages[phase] = {
                    "request": raw,
                    "transport_status": status,
                    "response": None if row is None else row["response"],
                    "result_sha256": None if row is None else row["result_sha256"],
                }
                self._egress.admit_in_transaction(
                    database,
                    catalog_id=self._egress_catalog,
                    path_id=f"messaging-{phase}-request",
                    operation_id=f"{send_id}:{phase}",
                    locator="\0".join((owner, send_id, phase)),
                    native_bytes=raw,
                    projection=projections[phase],
                    deadline_ms=deadline_ms,
                    authority_head=authority_head,
                )
        return stages

    def _transport_status(
        self,
        owner: str,
        send_id: str,
        phase: str,
        *,
        result: Mapping[str, Any] | None = None,
        response: bytes | None = None,
    ) -> str:
        """Commit pending before I/O; atomically retain authenticated response proof."""
        if (result is None) != (response is None):
            raise ValueError("messaging_transport_response_missing")
        status = "pending" if result is None else result["outcome"]
        digest = (
            None
            if result is None
            else hashlib.sha256(canonical_bytes(result)).hexdigest()
        )
        with self._database() as database:
            database.execute("BEGIN IMMEDIATE")
            database.execute(
                "UPDATE messaging_transport_stages "
                "SET transport_status=?, result_sha256=?, response=? "
                "WHERE owner=? AND send_id=? AND phase=? "
                "AND transport_status IN ('prepared', 'pending')",
                (status, digest, response, owner, send_id, phase),
            )
            row = database.execute(
                "SELECT transport_status FROM messaging_transport_stages "
                "WHERE owner=? AND send_id=? AND phase=?",
                (owner, send_id, phase),
            ).fetchone()
            if row is None:
                raise ValueError("messaging_transport_missing")
            return str(row["transport_status"])

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

    def _carrier(
        self,
        owner: str,
        logical_send_id: str,
        logical_plan: Mapping[str, Any],
        *,
        now: int,
        max_ttl_ms: int,
    ) -> tuple[str, dict[str, Any]]:
        """Return the live immutable carrier or durably reserve its successor."""

        with self._database() as database:
            database.execute("BEGIN IMMEDIATE")
            rows = database.execute(
                "SELECT send_id, plan FROM messaging_outbox WHERE owner=?",
                (owner,),
            ).fetchall()
            carriers: list[tuple[int, str, dict[str, Any]]] = []
            for row in rows:
                plan = dict(json.loads(row["plan"]))
                row_logical_id = plan.get("logical_send_id", row["send_id"])
                if row_logical_id != logical_send_id:
                    continue
                generation = int(plan.get("carrier_generation", 1))
                carriers.append((generation, str(row["send_id"]), plan))
            if not carriers:
                raise ValueError("messaging_outbox_missing")
            carriers.sort(key=lambda item: item[0])
            if [item[0] for item in carriers] != list(range(1, len(carriers) + 1)):
                raise ValueError("messaging_carrier_conflict")
            generation, carrier_send_id, carrier_plan = carriers[-1]
            if now < int(carrier_plan["issued_at_ms"]):
                raise ValueError("messaging_authorization_not_yet_valid")
            if now < int(carrier_plan["expires_at_ms"]):
                return carrier_send_id, carrier_plan

            generation += 1
            carrier_send_id = str(
                uuid.uuid5(
                    uuid.NAMESPACE_URL,
                    f"dm.messaging.carrier/v1:{logical_send_id}:{generation}",
                )
            )
            carrier_plan = dict(logical_plan)
            carrier_plan.update(
                {
                    "logical_send_id": logical_send_id,
                    "carrier_generation": generation,
                    "issued_at_ms": now,
                    "expires_at_ms": now + max_ttl_ms,
                    "message_authorization_id": str(
                        uuid.uuid5(uuid.UUID(carrier_send_id), "message-authorization")
                    ),
                    "evidence_authorization_id": str(
                        uuid.uuid5(uuid.UUID(carrier_send_id), "evidence-authorization")
                    ),
                }
            )
            database.execute(
                "INSERT INTO messaging_outbox (owner, send_id, plan) VALUES (?, ?, ?)",
                (owner, carrier_send_id, canonical_bytes(carrier_plan)),
            )
            return carrier_send_id, carrier_plan

    def _carrier_for_envelopes(
        self,
        owner: str,
        logical_send_id: str,
        envelopes: tuple[bytes, bytes],
    ) -> str:
        with self._database() as database:
            rows = database.execute(
                "SELECT send_id, plan FROM messaging_outbox "
                "WHERE owner=? AND evidence=? AND message=?",
                (owner, *envelopes),
            ).fetchall()
        matches = [
            str(row["send_id"])
            for row in rows
            if json.loads(row["plan"]).get("logical_send_id", row["send_id"])
            == logical_send_id
        ]
        if len(matches) != 1:
            raise ValueError("messaging_carrier_conflict")
        return matches[0]

    def _check_client(self, owner: str, send_id: str, client_id: str) -> None:
        with self._database() as database:
            row = database.execute(
                "SELECT plan FROM messaging_outbox WHERE owner=? AND send_id=?",
                (owner, send_id),
            ).fetchone()
        if row is None or json.loads(row["plan"])["client_id"] != client_id:
            raise ValueError("messaging_send_conflict")

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
                    envelope BLOB NOT NULL,
                    admission_version INTEGER NOT NULL DEFAULT 1
                        CHECK(admission_version IN (1, 2))
                );
            """)

    @staticmethod
    def _has_admission_version(database: sqlite3.Connection) -> bool:
        return any(
            row["name"] == "admission_version"
            for row in database.execute("PRAGMA table_info(inbox)")
        )

    @classmethod
    def upgrade_admission_path(cls, path: Path) -> None:
        """Durably classify all existing rows as V1 before V2 can be admitted."""

        path = path.absolute()
        with (
            closing(sqlite3.connect(path.as_uri() + "?mode=rw", uri=True)) as database,
            database,
        ):
            database.row_factory = sqlite3.Row
            database.execute("BEGIN IMMEDIATE")
            if not cls._has_admission_version(database):
                database.execute(
                    "ALTER TABLE inbox ADD COLUMN admission_version INTEGER NOT NULL "
                    "DEFAULT 1 CHECK(admission_version IN (1, 2))"
                )

    def upgrade_admission_v2(self) -> None:
        self.upgrade_admission_path(self.path)

    def _admission_version(self, message_id: str, current: int) -> int:
        with self._database() as database:
            if not self._has_admission_version(database):
                return 1
            row = database.execute(
                "SELECT admission_version FROM inbox WHERE message_id=?", (message_id,)
            ).fetchone()
        return current if row is None else int(row["admission_version"])

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
        admission_version: int = 1,
    ) -> dict[str, Any]:
        if admission_version not in {1, 2}:
            raise MessagingInboxError("messaging_admission_version_invalid")
        with self._database() as database:
            database.execute("BEGIN IMMEDIATE")
            versioned = self._has_admission_version(database)
            if admission_version == 2 and not versioned:
                raise MessagingInboxError("messaging_admission_migration_required")
            self._delivery(database, raw, retain=True)
            self._identity(database, message)
            existing = database.execute(
                "SELECT * FROM inbox WHERE message_id=?", (message["event_id"],)
            ).fetchone()
            if existing is not None:
                if (
                    bytes(existing["message"]) != canonical_bytes(message)
                    or existing["policy_hash"] != policy_hash
                    or (
                        versioned and existing["admission_version"] != admission_version
                    )
                ):
                    raise MessagingInboxError("messaging_message_conflict")
                return {
                    "inbox_sequence": existing["inbox_sequence"],
                    "message_id": message["event_id"],
                }
            fields = "message_id, policy_hash, message, evidence, envelope"
            values: tuple[Any, ...] = (
                message["event_id"],
                policy_hash,
                canonical_bytes(message),
                canonical_bytes(evidence),
                raw,
            )
            if versioned:
                fields += ", admission_version"
                values += (admission_version,)
            cursor = database.execute(
                f"INSERT INTO inbox ({fields}) VALUES ("
                + ", ".join("?" for _ in values)
                + ")",
                values,
            )
            return {
                "inbox_sequence": cursor.lastrowid,
                "message_id": message["event_id"],
            }

    def _message(self, message_id: str, policy_hash: str) -> dict[str, Any]:
        with self._database() as database:
            admission = (
                "admission_version"
                if self._has_admission_version(database)
                else "1 AS admission_version"
            )
            row = database.execute(
                f"SELECT inbox_sequence, message, evidence, {admission} FROM inbox "
                "WHERE message_id=? AND policy_hash=?",
                (message_id, policy_hash),
            ).fetchone()
        if row is None:
            raise MessagingInboxError("messaging_message_missing")
        return {
            "inbox_sequence": row["inbox_sequence"],
            "admission_version": row["admission_version"],
            "message": json.loads(row["message"]),
            "evidence": json.loads(row["evidence"]),
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
            admission = (
                "admission_version"
                if self._has_admission_version(database)
                else "1 AS admission_version"
            )
            rows = database.execute(
                f"SELECT inbox_sequence, message, evidence, {admission} FROM inbox "
                "WHERE inbox_sequence>? AND policy_hash=? "
                "ORDER BY inbox_sequence LIMIT ?",
                (after, policy_hash, limit),
            ).fetchall()
        return [
            {
                "inbox_sequence": row["inbox_sequence"],
                "admission_version": row["admission_version"],
                "message": json.loads(row["message"]),
                "evidence": json.loads(row["evidence"]),
            }
            for row in rows
        ]
