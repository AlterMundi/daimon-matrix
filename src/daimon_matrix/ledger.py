"""Independent transactional SQLite ledger for one authorized embodiment."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import sqlite3
import stat
import time
import uuid
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from .canonical import canonical_bytes
from .weave import (
    MAX_PAGE_BYTES,
    MAX_PAGE_EVENTS,
    Event,
    EventAuthority,
    EventSigner,
    WeaveProtocolError,
    create_event,
    page_bytes,
    verify_event,
)

SCHEMA_VERSION: Final = 3
BUSY_TIMEOUT_MS: Final = 5_000

Clock = Callable[[], int]
UUIDFactory = Callable[[], uuid.UUID]


class LedgerError(RuntimeError):
    """Base class for stable ledger failures."""


class LedgerGapError(LedgerError):
    """A page skipped an immutable origin-chain predecessor."""


class LedgerEquivocationError(LedgerError):
    """Different signed bytes occupied one immutable event identity/position."""

    def __init__(self, evidence: Mapping[str, Any]) -> None:
        super().__init__("origin_equivocation")
        self.evidence = copy.deepcopy(dict(evidence))


class LedgerStateError(LedgerError):
    """The filesystem or SQLite state cannot be trusted."""


@dataclass(frozen=True)
class Preview:
    received: int
    missing: int
    incomplete: int
    event_ids: tuple[str, ...]

    def as_dict(self, manifest_hash: str) -> dict[str, Any]:
        return {
            "schema": "dm.we.preview/v1",
            "manifest_hash": manifest_hash,
            "received": self.received,
            "missing": self.missing,
            "incomplete": self.incomplete,
            "event_ids": list(self.event_ids),
        }


def _now_ms() -> int:
    return int(time.time() * 1000)


def _assert_owner_directory(path: Path) -> None:
    if path.is_symlink():
        raise LedgerStateError("ledger_parent_symlink")
    try:
        info = path.stat()
    except FileNotFoundError as exception:
        raise LedgerStateError("ledger_parent_missing") from exception
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise LedgerStateError("ledger_parent_not_owner_only")


def _assert_owner_file(path: Path) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise LedgerStateError("ledger_file_not_owner_only")


def _prepare_path(path: Path) -> None:
    if not path.parent.exists():
        missing: list[Path] = []
        candidate = path.parent
        while not candidate.exists():
            if candidate.is_symlink():
                raise LedgerStateError("ledger_ancestor_symlink")
            missing.append(candidate)
            if candidate == candidate.parent:
                raise LedgerStateError("ledger_parent_missing")
            candidate = candidate.parent
        if candidate.is_symlink():
            raise LedgerStateError("ledger_ancestor_symlink")
        for directory in reversed(missing):
            with suppress(FileExistsError):
                directory.mkdir(mode=0o700)
            _assert_owner_directory(directory)
    _assert_owner_directory(path.parent)
    ancestor = path.parent
    while ancestor != ancestor.parent:
        if ancestor.is_symlink():
            raise LedgerStateError("ledger_ancestor_symlink")
        ancestor = ancestor.parent
    _assert_owner_file(path)
    if not path.exists():
        try:
            descriptor = os.open(
                path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
        except FileExistsError:
            _assert_owner_file(path)
        else:
            os.close(descriptor)


class Ledger:
    """One embodiment's ledger; never shared as a writable database."""

    def __init__(
        self,
        path: str | Path,
        *,
        authority: EventAuthority,
        local_origin: Mapping[str, str],
        clock: Clock = _now_ms,
        uuid_factory: UUIDFactory = uuid.uuid4,
    ) -> None:
        self.path = Path(os.path.abspath(path))
        self.authority = authority
        self.local_origin = copy.deepcopy(dict(local_origin))
        self.clock = clock
        self.uuid_factory = uuid_factory
        if set(self.local_origin) != {
            "embodiment_id",
            "incarnation_id",
            "principal_id",
            "body_ref",
        }:
            raise LedgerStateError("invalid_local_origin")

    def _connect(self) -> sqlite3.Connection:
        _prepare_path(self.path)
        connection = sqlite3.connect(
            self.path,
            timeout=BUSY_TIMEOUT_MS / 1000,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
        connection.execute("PRAGMA foreign_keys=ON")
        mode = connection.execute("PRAGMA journal_mode=DELETE").fetchone()[0]
        if str(mode).lower() != "delete":
            connection.close()
            raise LedgerStateError("unsupported_journal_mode")
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    @contextmanager
    def _database(self) -> Iterator[sqlite3.Connection]:
        database = self._connect()
        try:
            yield database
        finally:
            database.close()

    def initialize(self) -> None:
        with self._database() as database:
            database.executescript(
                """
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                ) WITHOUT ROWID;
                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY,
                    incarnation_id TEXT NOT NULL,
                    embodiment_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    kind TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    content_hash TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('known', 'incomplete')),
                    event_json BLOB NOT NULL,
                    imported_from TEXT NOT NULL,
                    inserted_order INTEGER NOT NULL,
                    UNIQUE(incarnation_id, sequence)
                );
                CREATE TABLE IF NOT EXISTS event_dependencies (
                    event_id TEXT NOT NULL
                        REFERENCES events(event_id) ON DELETE CASCADE,
                    parent_event_id TEXT NOT NULL,
                    PRIMARY KEY(event_id, parent_event_id)
                ) WITHOUT ROWID;
                CREATE TABLE IF NOT EXISTS peer_cursors (
                    peer_id TEXT NOT NULL,
                    incarnation_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    tip_event_id TEXT NOT NULL,
                    tip_hash TEXT NOT NULL,
                    PRIMARY KEY(peer_id, incarnation_id)
                ) WITHOUT ROWID;
                CREATE TABLE IF NOT EXISTS peer_sync_state (
                    peer_id TEXT PRIMARY KEY,
                    state TEXT NOT NULL
                        CHECK(state IN ('coherent', 'gap', 'quarantined')),
                    error TEXT,
                    updated_at_ms INTEGER NOT NULL
                ) WITHOUT ROWID;
                CREATE TABLE IF NOT EXISTS equivocations (
                    evidence_hash TEXT PRIMARY KEY,
                    evidence_json BLOB NOT NULL,
                    detected_at_ms INTEGER NOT NULL
                ) WITHOUT ROWID;
                CREATE TABLE IF NOT EXISTS outbound_sync (
                    request_id TEXT PRIMARY KEY,
                    request_hash TEXT NOT NULL,
                    response_json BLOB NOT NULL
                ) WITHOUT ROWID;
                CREATE TABLE IF NOT EXISTS issued_sync (
                    request_id TEXT PRIMARY KEY,
                    request_hash TEXT NOT NULL,
                    request_json BLOB NOT NULL
                ) WITHOUT ROWID;
                CREATE TABLE IF NOT EXISTS inbound_sync (
                    peer_id TEXT NOT NULL,
                    request_id TEXT NOT NULL,
                    page_hash TEXT NOT NULL,
                    receipt_json BLOB NOT NULL,
                    PRIMARY KEY(peer_id, request_id)
                ) WITHOUT ROWID;
                CREATE TABLE IF NOT EXISTS projection_cache (
                    slot INTEGER PRIMARY KEY CHECK(slot=1),
                    projection_hash TEXT NOT NULL,
                    snapshot_json BLOB NOT NULL
                );
                CREATE TABLE IF NOT EXISTS local_operations (
                    client_id TEXT NOT NULL,
                    request_id TEXT NOT NULL,
                    request_hash TEXT NOT NULL,
                    event_id TEXT NOT NULL REFERENCES events(event_id),
                    PRIMARY KEY(client_id, request_id)
                ) WITHOUT ROWID;
                CREATE TABLE IF NOT EXISTS rpc_requests (
                    client_id TEXT NOT NULL,
                    request_id TEXT NOT NULL,
                    request_hash TEXT NOT NULL,
                    method TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(state IN ('pending', 'completed')),
                    response_json BLOB,
                    created_at_ms INTEGER NOT NULL,
                    completed_at_ms INTEGER,
                    PRIMARY KEY(client_id, request_id),
                    CHECK(
                        (state='pending' AND response_json IS NULL
                            AND completed_at_ms IS NULL)
                        OR
                        (state='completed' AND response_json IS NOT NULL
                            AND completed_at_ms IS NOT NULL)
                    )
                ) WITHOUT ROWID;
                CREATE INDEX IF NOT EXISTS events_kind_subject
                    ON events(kind, subject);
                CREATE INDEX IF NOT EXISTS events_status
                    ON events(status);
                """
            )
            expected = {
                "accepted_manifest_hashes": json.dumps(
                    list(
                        getattr(
                            self.authority,
                            "accepted_manifest_hashes",
                            (self.authority.manifest.digest,),
                        )
                    ),
                    separators=(",", ":"),
                ),
                "being_ref": self.authority.manifest.being_ref,
                "local_embodiment_id": self.local_origin["embodiment_id"],
                "manifest_hash": self.authority.manifest.digest,
                "schema_version": str(SCHEMA_VERSION),
                "trust_mode": self.authority.manifest.trust_mode,
            }
            rows = {
                str(row["key"]): str(row["value"])
                for row in database.execute("SELECT key, value FROM metadata")
            }
            if not rows:
                database.executemany(
                    "INSERT INTO metadata(key, value) VALUES (?, ?)",
                    sorted(expected.items()),
                )
            elif rows != expected:
                prior_versions = (
                    {**expected, "schema_version": "1"},
                    {**expected, "schema_version": "2"},
                )
                if rows in prior_versions:
                    database.execute(
                        "UPDATE metadata SET value=? WHERE key='schema_version'",
                        (str(SCHEMA_VERSION),),
                    )
                elif self._authority_epoch_advance(rows, expected):
                    self._commit_authority_epoch(database, expected)
                else:
                    raise LedgerStateError("ledger_metadata_mismatch")
        _assert_owner_file(self.path)

    @staticmethod
    def _authority_epoch_advance(
        current: Mapping[str, str], expected: Mapping[str, str]
    ) -> bool:
        """Recognize only monotonic expansion already verified by authority."""

        stable = {
            "being_ref",
            "local_embodiment_id",
            "trust_mode",
        }
        if set(current) != set(expected) or any(
            current.get(field) != expected.get(field) for field in stable
        ):
            return False
        if current.get("schema_version") not in {"1", "2", str(SCHEMA_VERSION)}:
            return False
        try:
            old_hashes = json.loads(current["accepted_manifest_hashes"])
            new_hashes = json.loads(expected["accepted_manifest_hashes"])
        except (KeyError, json.JSONDecodeError, TypeError):
            return False
        if (
            not isinstance(old_hashes, list)
            or not isinstance(new_hashes, list)
            or old_hashes != sorted(set(old_hashes))
            or new_hashes != sorted(set(new_hashes))
            or not all(isinstance(value, str) for value in (*old_hashes, *new_hashes))
        ):
            return False
        return bool(
            set(old_hashes) < set(new_hashes)
            and set(old_hashes) <= set(new_hashes)
            and current.get("manifest_hash") in new_hashes
            and expected.get("manifest_hash") in new_hashes
            and current.get("manifest_hash") != expected.get("manifest_hash")
        )

    def _commit_authority_epoch(
        self, database: sqlite3.Connection, expected: Mapping[str, str]
    ) -> None:
        """Verify every immutable event, then atomically advance metadata."""

        database.execute("BEGIN IMMEDIATE")
        try:
            rows = database.execute(
                "SELECT event_id, incarnation_id, embodiment_id, sequence, kind, "
                "subject, content_hash, event_json FROM events ORDER BY inserted_order"
            )
            for row in rows:
                try:
                    raw = bytes(row["event_json"])
                    event = verify_event(json.loads(raw), self.authority)
                except (
                    json.JSONDecodeError,
                    TypeError,
                    WeaveProtocolError,
                ) as exception:
                    raise LedgerStateError(
                        "authority_epoch_event_verification_failed"
                    ) from exception
                if (
                    canonical_bytes(event) != raw
                    or row["event_id"] != event["event_id"]
                    or row["incarnation_id"] != event["origin"]["incarnation_id"]
                    or row["embodiment_id"] != event["origin"]["embodiment_id"]
                    or int(row["sequence"]) != event["sequence"]
                    or row["kind"] != event["kind"]
                    or row["subject"] != event["subject"]
                    or row["content_hash"] != event["content_hash"]
                ):
                    raise LedgerStateError("authority_epoch_event_verification_failed")
            database.executemany(
                "UPDATE metadata SET value=? WHERE key=?",
                [
                    (expected["accepted_manifest_hashes"], "accepted_manifest_hashes"),
                    (expected["manifest_hash"], "manifest_hash"),
                    (expected["schema_version"], "schema_version"),
                ],
            )
            database.execute("DELETE FROM projection_cache")
            database.commit()
        except BaseException:
            database.rollback()
            raise

    def integrity_check(self) -> None:
        self.initialize()
        with self._database() as database:
            result = database.execute("PRAGMA integrity_check").fetchone()[0]
            if result != "ok":
                raise LedgerStateError("ledger_integrity_failed")

    @staticmethod
    def _head(database: sqlite3.Connection, incarnation_id: str) -> sqlite3.Row | None:
        row: sqlite3.Row | None = database.execute(
            "SELECT event_id, sequence, content_hash FROM events "
            "WHERE incarnation_id=? ORDER BY sequence DESC LIMIT 1",
            (incarnation_id,),
        ).fetchone()
        return row

    @staticmethod
    def _dependencies(event: Mapping[str, Any]) -> set[str]:
        dependencies = set(event["causal_parents"])
        if event["previous_event_id"] is not None:
            dependencies.add(event["previous_event_id"])
        if event["kind"] == "adoption.decided":
            dependencies.add(event["payload"]["target_event_id"])
        if event["kind"] == "projection.receipted":
            dependencies.add(event["payload"]["target_event_id"])
            dependencies.add(event["payload"]["decision_event_id"])
        if event["supersedes"] is not None:
            dependencies.add(event["supersedes"])
        return dependencies

    def append_local(
        self,
        *,
        kind: str,
        subject: str,
        payload: Mapping[str, Any],
        signer: EventSigner,
        sensitivity: str = "personal",
        causal_parents: Sequence[str] = (),
        supersedes: str | None = None,
        occurred_at_ms: int | None = None,
        event_id: str | None = None,
    ) -> Event:
        self.initialize()
        with self._database() as database:
            database.execute("BEGIN IMMEDIATE")
            try:
                event = self._append_local(
                    database,
                    kind=kind,
                    subject=subject,
                    payload=payload,
                    signer=signer,
                    sensitivity=sensitivity,
                    causal_parents=causal_parents,
                    supersedes=supersedes,
                    occurred_at_ms=occurred_at_ms,
                    event_id=event_id,
                )
                database.commit()
                return event
            except BaseException:
                database.rollback()
                raise

    def _append_local(
        self,
        database: sqlite3.Connection,
        *,
        kind: str,
        subject: str,
        payload: Mapping[str, Any],
        signer: EventSigner,
        sensitivity: str,
        causal_parents: Sequence[str],
        supersedes: str | None,
        occurred_at_ms: int | None,
        event_id: str | None,
    ) -> Event:
        head = self._head(database, self.local_origin["incarnation_id"])
        sequence = 1 if head is None else int(head["sequence"]) + 1
        event = create_event(
            self.authority,
            self.local_origin,
            signer,
            event_id=str(self.uuid_factory()) if event_id is None else event_id,
            sequence=sequence,
            previous_event_id=None if head is None else str(head["event_id"]),
            occurred_at_ms=self.clock() if occurred_at_ms is None else occurred_at_ms,
            causal_parents=causal_parents,
            kind=kind,
            subject=subject,
            payload=payload,
            supersedes=supersedes,
            sensitivity=sensitivity,
        )
        unavailable = [
            dependency
            for dependency in self._dependencies(event)
            if database.execute(
                "SELECT 1 FROM events WHERE event_id=? AND status='known'",
                (dependency,),
            ).fetchone()
            is None
        ]
        if unavailable:
            raise LedgerGapError("local_causal_dependency_missing")
        self._insert(database, event, source="local", status="known")
        self._promote(database)
        return event

    def append_local_idempotent(
        self,
        *,
        client_id: str,
        request_id: str,
        request_hash: str,
        kind: str,
        subject: str,
        payload: Mapping[str, Any],
        signer: EventSigner,
        sensitivity: str = "personal",
        causal_parents: Sequence[str] = (),
        supersedes: str | None = None,
        occurred_at_ms: int | None = None,
        event_id: str | None = None,
    ) -> Event:
        """Author one event and its local-operation receipt in one transaction."""

        self._validate_rpc_identity(client_id, request_id, request_hash)
        self.initialize()
        try:
            with self._database() as database:
                database.execute("BEGIN IMMEDIATE")
                try:
                    existing = database.execute(
                        "SELECT request_hash, event_id FROM local_operations "
                        "WHERE client_id=? AND request_id=?",
                        (client_id, request_id),
                    ).fetchone()
                    if existing is not None:
                        if existing["request_hash"] != request_hash:
                            raise LedgerEquivocationError(
                                {
                                    "schema": "dm.we.equivocation/v1",
                                    "lane": "local_operation",
                                    "client_id": client_id,
                                    "request_id": request_id,
                                    "existing_request_hash": existing["request_hash"],
                                    "presented_request_hash": request_hash,
                                }
                            )
                        row = database.execute(
                            "SELECT event_json FROM events WHERE event_id=?",
                            (existing["event_id"],),
                        ).fetchone()
                        if row is None:
                            raise LedgerStateError("local_operation_event_missing")
                        result: Event = json.loads(bytes(row["event_json"]))
                    else:
                        result = self._append_local(
                            database,
                            kind=kind,
                            subject=subject,
                            payload=payload,
                            signer=signer,
                            sensitivity=sensitivity,
                            causal_parents=causal_parents,
                            supersedes=supersedes,
                            occurred_at_ms=occurred_at_ms,
                            event_id=event_id,
                        )
                        database.execute(
                            "INSERT INTO local_operations VALUES (?, ?, ?, ?)",
                            (client_id, request_id, request_hash, result["event_id"]),
                        )
                    database.commit()
                except BaseException:
                    database.rollback()
                    raise
        except LedgerEquivocationError as exception:
            self._record_equivocation(exception.evidence)
            raise
        return result

    @staticmethod
    def _validate_rpc_identity(
        client_id: str, request_id: str, request_hash: str
    ) -> None:
        if (
            not isinstance(client_id, str)
            or not 1 <= len(client_id.encode("utf-8")) <= 128
        ):
            raise LedgerError("invalid_rpc_client_id")
        try:
            if str(uuid.UUID(request_id)) != request_id:
                raise ValueError
        except (AttributeError, TypeError, ValueError) as exception:
            raise LedgerError("invalid_rpc_request_id") from exception
        if (
            not isinstance(request_hash, str)
            or len(request_hash) != 64
            or any(character not in "0123456789abcdef" for character in request_hash)
        ):
            raise LedgerError("invalid_rpc_request_hash")

    def begin_rpc(
        self,
        *,
        client_id: str,
        request_id: str,
        request_hash: str,
        method: str,
    ) -> dict[str, Any] | None:
        """Journal an authenticated API request or return its completed response."""

        self._validate_rpc_identity(client_id, request_id, request_hash)
        if not isinstance(method, str) or not 1 <= len(method.encode("utf-8")) <= 128:
            raise LedgerError("invalid_rpc_method")
        self.initialize()
        try:
            with self._database() as database:
                database.execute("BEGIN IMMEDIATE")
                try:
                    row = database.execute(
                        "SELECT request_hash, method, state, response_json "
                        "FROM rpc_requests WHERE client_id=? AND request_id=?",
                        (client_id, request_id),
                    ).fetchone()
                    if row is None:
                        database.execute(
                            "INSERT INTO rpc_requests VALUES "
                            "(?, ?, ?, ?, 'pending', NULL, ?, NULL)",
                            (
                                client_id,
                                request_id,
                                request_hash,
                                method,
                                self.clock(),
                            ),
                        )
                        result = None
                    else:
                        if (
                            row["request_hash"] != request_hash
                            or row["method"] != method
                        ):
                            raise LedgerEquivocationError(
                                {
                                    "schema": "dm.we.equivocation/v1",
                                    "lane": "rpc_request",
                                    "client_id": client_id,
                                    "request_id": request_id,
                                    "existing_request_hash": row["request_hash"],
                                    "presented_request_hash": request_hash,
                                }
                            )
                        if row["state"] == "pending":
                            result = None
                        elif row["state"] == "completed" and row["response_json"]:
                            loaded = json.loads(bytes(row["response_json"]))
                            if not isinstance(loaded, dict):
                                raise LedgerStateError("rpc_response_corrupt")
                            result = loaded
                        else:
                            raise LedgerStateError("rpc_journal_corrupt")
                    database.commit()
                except BaseException:
                    database.rollback()
                    raise
        except LedgerEquivocationError as exception:
            self._record_equivocation(exception.evidence)
            raise
        return result

    def rpc_request_matches(
        self,
        *,
        client_id: str,
        request_id: str,
        request_hash: str,
        method: str,
    ) -> bool:
        """Return whether an authenticated stale retry already has a journal row."""

        self._validate_rpc_identity(client_id, request_id, request_hash)
        self.initialize()
        with self._database() as database:
            row = database.execute(
                "SELECT request_hash, method FROM rpc_requests "
                "WHERE client_id=? AND request_id=?",
                (client_id, request_id),
            ).fetchone()
        return bool(
            row is not None
            and row["request_hash"] == request_hash
            and row["method"] == method
        )

    def finish_rpc(
        self,
        *,
        client_id: str,
        request_id: str,
        request_hash: str,
        method: str,
        response: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Store the first exact API response; a concurrent finisher reuses it."""

        self._validate_rpc_identity(client_id, request_id, request_hash)
        raw = canonical_bytes(response)
        self.initialize()
        try:
            with self._database() as database:
                database.execute("BEGIN IMMEDIATE")
                try:
                    row = database.execute(
                        "SELECT request_hash, method, state, response_json "
                        "FROM rpc_requests WHERE client_id=? AND request_id=?",
                        (client_id, request_id),
                    ).fetchone()
                    if row is None:
                        raise LedgerStateError("rpc_request_not_started")
                    if row["request_hash"] != request_hash or row["method"] != method:
                        raise LedgerEquivocationError(
                            {
                                "schema": "dm.we.equivocation/v1",
                                "lane": "rpc_request",
                                "client_id": client_id,
                                "request_id": request_id,
                                "existing_request_hash": row["request_hash"],
                                "presented_request_hash": request_hash,
                            }
                        )
                    if row["state"] == "completed":
                        loaded = json.loads(bytes(row["response_json"]))
                        if not isinstance(loaded, dict):
                            raise LedgerStateError("rpc_response_corrupt")
                        result = loaded
                    elif row["state"] == "pending":
                        database.execute(
                            "UPDATE rpc_requests SET state='completed', "
                            "response_json=?, completed_at_ms=? "
                            "WHERE client_id=? AND request_id=?",
                            (raw, self.clock(), client_id, request_id),
                        )
                        result = copy.deepcopy(dict(response))
                    else:
                        raise LedgerStateError("rpc_journal_corrupt")
                    database.commit()
                except BaseException:
                    database.rollback()
                    raise
        except LedgerEquivocationError as exception:
            self._record_equivocation(exception.evidence)
            raise
        return result

    def rpc_requests(self) -> list[dict[str, Any]]:
        self.initialize()
        with self._database() as database:
            return [
                dict(row)
                for row in database.execute(
                    "SELECT client_id, request_id, request_hash, method, state, "
                    "created_at_ms, completed_at_ms FROM rpc_requests "
                    "ORDER BY client_id, request_id"
                )
            ]

    def _insert(
        self,
        database: sqlite3.Connection,
        event: Mapping[str, Any],
        *,
        source: str,
        status: str,
    ) -> None:
        next_order = int(
            database.execute(
                "SELECT COALESCE(MAX(inserted_order), 0) + 1 FROM events"
            ).fetchone()[0]
        )
        database.execute(
            "INSERT INTO events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                event["event_id"],
                event["origin"]["incarnation_id"],
                event["origin"]["embodiment_id"],
                event["sequence"],
                event["kind"],
                event["subject"],
                event["content_hash"],
                status,
                canonical_bytes(event),
                source,
                next_order,
            ),
        )
        database.executemany(
            "INSERT INTO event_dependencies(event_id, parent_event_id) VALUES (?, ?)",
            [
                (event["event_id"], parent)
                for parent in sorted(self._dependencies(event))
            ],
        )

    def _ordered_page(self, events: Sequence[Mapping[str, Any]]) -> list[Event]:
        if len(events) > MAX_PAGE_EVENTS or len(page_bytes(events)) > MAX_PAGE_BYTES:
            raise WeaveProtocolError("delta_page_too_large")
        validated = [verify_event(event, self.authority) for event in events]

        def event_key(event: Mapping[str, Any]) -> tuple[str, int, str]:
            return (
                event["origin"]["incarnation_id"],
                event["sequence"],
                event["event_id"],
            )

        if validated != sorted(validated, key=event_key):
            raise WeaveProtocolError("delta_page_not_sorted")
        if len({event["event_id"] for event in validated}) != len(validated):
            raise WeaveProtocolError("duplicate_page_event")
        return validated

    def _plan(
        self, database: sqlite3.Connection, events: Sequence[Mapping[str, Any]]
    ) -> tuple[list[Event], list[Event], int]:
        validated = self._ordered_page(events)
        staged_ids: set[str] = set()
        missing: list[Event] = []
        staged_heads: dict[str, tuple[int, str | None]] = {}
        staged_positions: dict[tuple[str, int], Event] = {}
        available_known = {
            str(row["event_id"])
            for row in database.execute(
                "SELECT event_id FROM events WHERE status='known'"
            )
        }
        for event in validated:
            existing_id = database.execute(
                "SELECT incarnation_id, sequence, content_hash, event_json "
                "FROM events WHERE event_id=?",
                (event["event_id"],),
            ).fetchone()
            if existing_id is not None:
                if (
                    existing_id["content_hash"] != event["content_hash"]
                    or existing_id["incarnation_id"]
                    != event["origin"]["incarnation_id"]
                    or int(existing_id["sequence"]) != event["sequence"]
                    or bytes(existing_id["event_json"]) != canonical_bytes(event)
                ):
                    raise self._equivocation(database, event, "event_id")
                continue
            incarnation = event["origin"]["incarnation_id"]
            position_key = (incarnation, event["sequence"])
            staged_conflict = staged_positions.get(position_key)
            if staged_conflict is not None:
                raise LedgerEquivocationError(
                    {
                        "schema": "dm.we.equivocation/v1",
                        "lane": "origin_sequence",
                        "incarnation_id": incarnation,
                        "sequence": event["sequence"],
                        "existing_event_id": staged_conflict["event_id"],
                        "existing_content_hash": staged_conflict["content_hash"],
                        "presented_event_id": event["event_id"],
                        "presented_content_hash": event["content_hash"],
                    }
                )
            position = database.execute(
                "SELECT event_id, content_hash FROM events "
                "WHERE incarnation_id=? AND sequence=?",
                (incarnation, event["sequence"]),
            ).fetchone()
            if position is not None:
                raise self._equivocation(database, event, "origin_sequence")
            if incarnation not in staged_heads:
                head = self._head(database, incarnation)
                staged_heads[incarnation] = (
                    (0, None)
                    if head is None
                    else (int(head["sequence"]), str(head["event_id"]))
                )
            last_sequence, last_id = staged_heads[incarnation]
            if (
                event["sequence"] != last_sequence + 1
                or event["previous_event_id"] != last_id
            ):
                raise LedgerGapError("origin_sequence_gap")
            staged_ids.add(event["event_id"])
            staged_positions[position_key] = event
            staged_heads[incarnation] = (event["sequence"], event["event_id"])
            missing.append(event)
        pending = {event["event_id"]: event for event in missing}
        while True:
            promoted = [
                event_id
                for event_id, event in pending.items()
                if self._dependencies(event) <= available_known
            ]
            if not promoted:
                break
            for event_id in promoted:
                available_known.add(event_id)
                del pending[event_id]
        predicted_incomplete = len(pending)
        return validated, missing, predicted_incomplete

    @staticmethod
    def _equivocation(
        database: sqlite3.Connection, event: Mapping[str, Any], lane: str
    ) -> LedgerEquivocationError:
        if lane == "event_id":
            existing = database.execute(
                "SELECT event_id, content_hash, incarnation_id, sequence "
                "FROM events WHERE event_id=?",
                (event["event_id"],),
            ).fetchone()
        else:
            existing = database.execute(
                "SELECT event_id, content_hash, incarnation_id, sequence "
                "FROM events WHERE incarnation_id=? AND sequence=?",
                (event["origin"]["incarnation_id"], event["sequence"]),
            ).fetchone()
        evidence = {
            "schema": "dm.we.equivocation/v1",
            "lane": lane,
            "incarnation_id": event["origin"]["incarnation_id"],
            "sequence": event["sequence"],
            "existing_event_id": None if existing is None else existing["event_id"],
            "existing_content_hash": None
            if existing is None
            else existing["content_hash"],
            "presented_event_id": event["event_id"],
            "presented_content_hash": event["content_hash"],
        }
        return LedgerEquivocationError(evidence)

    def preview(self, events: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
        self.initialize()
        with self._database() as database:
            _, missing, incomplete = self._plan(database, events)
        return Preview(
            received=len(events),
            missing=len(missing),
            incomplete=incomplete,
            event_ids=tuple(event["event_id"] for event in missing),
        ).as_dict(self.authority.manifest.digest)

    def ingest(
        self, events: Sequence[Mapping[str, Any]], *, source: str
    ) -> dict[str, Any]:
        if not isinstance(source, str) or not 1 <= len(source.encode("utf-8")) <= 256:
            raise LedgerError("invalid_peer_id")
        self.initialize()
        try:
            with self._database() as database:
                database.execute("BEGIN IMMEDIATE")
                try:
                    validated, missing, _ = self._plan(database, events)
                    available_known = {
                        str(row["event_id"])
                        for row in database.execute(
                            "SELECT event_id FROM events WHERE status='known'"
                        )
                    }
                    for event in missing:
                        dependencies = self._dependencies(event)
                        status = (
                            "known" if dependencies <= available_known else "incomplete"
                        )
                        self._insert(database, event, source=source, status=status)
                        if status == "known":
                            available_known.add(event["event_id"])
                    self._promote(database)
                    for page_event in validated:
                        self._advance_cursor(database, source, page_event)
                    database.commit()
                except BaseException:
                    database.rollback()
                    raise
            self._set_peer_state(source, "coherent", None)
        except LedgerEquivocationError as exception:
            self._record_equivocation(exception.evidence)
            self._set_peer_state(source, "quarantined", str(exception))
            raise
        except LedgerGapError as exception:
            self._set_peer_state(source, "gap", str(exception))
            raise
        except WeaveProtocolError as exception:
            self._set_peer_state(source, "quarantined", str(exception))
            raise
        result = self.preview(events)
        result["missing"] = len(missing)
        result["event_ids"] = [event["event_id"] for event in missing]
        result["incomplete"] = self.incomplete_count()
        return result

    @staticmethod
    def _promote(database: sqlite3.Connection) -> None:
        while True:
            rows = database.execute(
                """
                SELECT e.event_id FROM events e
                WHERE e.status='incomplete'
                  AND NOT EXISTS (
                    SELECT 1 FROM event_dependencies d
                    LEFT JOIN events p ON p.event_id=d.parent_event_id
                    WHERE d.event_id=e.event_id
                      AND (p.event_id IS NULL OR p.status!='known')
                  )
                ORDER BY e.incarnation_id, e.sequence
                """
            ).fetchall()
            if not rows:
                return
            database.executemany(
                "UPDATE events SET status='known' WHERE event_id=?",
                [(row["event_id"],) for row in rows],
            )

    @staticmethod
    def _advance_cursor(
        database: sqlite3.Connection, source: str, event: Mapping[str, Any]
    ) -> None:
        database.execute(
            """
            INSERT INTO peer_cursors(
                peer_id, incarnation_id, sequence, tip_event_id, tip_hash
            ) VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(peer_id, incarnation_id) DO UPDATE SET
                sequence=excluded.sequence,
                tip_event_id=excluded.tip_event_id,
                tip_hash=excluded.tip_hash
            WHERE excluded.sequence > peer_cursors.sequence
            """,
            (
                source,
                event["origin"]["incarnation_id"],
                event["sequence"],
                event["event_id"],
                event["content_hash"],
            ),
        )

    def _set_peer_state(self, source: str, state: str, error: str | None) -> None:
        self.initialize()
        with self._database() as database:
            database.execute("BEGIN IMMEDIATE")
            database.execute(
                """
                INSERT INTO peer_sync_state(peer_id, state, error, updated_at_ms)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(peer_id) DO UPDATE SET
                    state=excluded.state,
                    error=excluded.error,
                    updated_at_ms=excluded.updated_at_ms
                """,
                (source, state, error, self.clock()),
            )
            database.commit()

    def _record_equivocation(self, evidence: Mapping[str, Any]) -> None:
        raw = canonical_bytes(evidence)
        evidence_hash = hashlib.sha256(raw).hexdigest()
        with self._database() as database:
            database.execute("BEGIN IMMEDIATE")
            database.execute(
                "INSERT OR IGNORE INTO equivocations VALUES (?, ?, ?)",
                (evidence_hash, raw, self.clock()),
            )
            database.commit()

    def incomplete_count(self) -> int:
        self.initialize()
        with self._database() as database:
            return int(
                database.execute(
                    "SELECT COUNT(*) FROM events WHERE status='incomplete'"
                ).fetchone()[0]
            )

    def events(self, *, include_incomplete: bool = True) -> list[Event]:
        self.initialize()
        query = "SELECT event_json FROM events"
        if not include_incomplete:
            query += " WHERE status='known'"
        query += " ORDER BY incarnation_id, sequence, event_id"
        with self._database() as database:
            rows = database.execute(query).fetchall()
        return [json.loads(bytes(row["event_json"])) for row in rows]

    def event(self, event_id: str, *, include_incomplete: bool = False) -> Event | None:
        try:
            if str(uuid.UUID(event_id)) != event_id:
                raise ValueError
        except (AttributeError, TypeError, ValueError) as exception:
            raise LedgerError("invalid_event_id") from exception
        self.initialize()
        query = "SELECT event_json FROM events WHERE event_id=?"
        if not include_incomplete:
            query += " AND status='known'"
        with self._database() as database:
            row = database.execute(query, (event_id,)).fetchone()
        return None if row is None else json.loads(bytes(row["event_json"]))

    def status_counts(self) -> dict[str, int]:
        self.initialize()
        with self._database() as database:
            known = int(
                database.execute(
                    "SELECT COUNT(*) FROM events WHERE status='known'"
                ).fetchone()[0]
            )
            incomplete = int(
                database.execute(
                    "SELECT COUNT(*) FROM events WHERE status='incomplete'"
                ).fetchone()[0]
            )
            peers = int(
                database.execute("SELECT COUNT(*) FROM peer_sync_state").fetchone()[0]
            )
            pending_rpc = int(
                database.execute(
                    "SELECT COUNT(*) FROM rpc_requests WHERE state='pending'"
                ).fetchone()[0]
            )
        return {
            "known_events": known,
            "incomplete_events": incomplete,
            "peer_lanes": peers,
            "pending_rpc": pending_rpc,
        }

    @staticmethod
    def _heads(database: sqlite3.Connection) -> list[dict[str, Any]]:
        rows = database.execute(
            """
            SELECT e.incarnation_id, e.sequence, e.event_id, e.content_hash
            FROM events e
            JOIN (
                SELECT incarnation_id, MAX(sequence) AS sequence
                FROM events GROUP BY incarnation_id
            ) h ON e.incarnation_id=h.incarnation_id
               AND e.sequence=h.sequence
            ORDER BY e.incarnation_id
            """
        ).fetchall()
        return [
            {
                "incarnation_id": row["incarnation_id"],
                "max_sequence": row["sequence"],
                "tip_event_id": row["event_id"],
                "tip_hash": row["content_hash"],
            }
            for row in rows
        ]

    def heads(self) -> list[dict[str, Any]]:
        self.initialize()
        with self._database() as database:
            return self._heads(database)

    @staticmethod
    def _remote_sequences(
        database: sqlite3.Connection,
        remote_heads: Sequence[Mapping[str, Any]],
    ) -> dict[str, int]:
        if len(remote_heads) > 256:
            raise LedgerError("too_many_remote_heads")
        normalized: list[dict[str, Any]] = []
        seen: set[str] = set()
        fields = {"incarnation_id", "max_sequence", "tip_event_id", "tip_hash"}
        for head in remote_heads:
            if not isinstance(head, Mapping) or set(head) != fields:
                raise LedgerError("invalid_remote_head")
            incarnation_id = head["incarnation_id"]
            sequence = head["max_sequence"]
            tip_event_id = head["tip_event_id"]
            tip_hash = head["tip_hash"]
            if (
                not isinstance(incarnation_id, str)
                or not 1 <= len(incarnation_id.encode("utf-8")) <= 256
                or not isinstance(sequence, int)
                or isinstance(sequence, bool)
                or not 1 <= sequence <= 2**53 - 1
                or not isinstance(tip_event_id, str)
                or not isinstance(tip_hash, str)
                or len(tip_hash) != 64
                or any(character not in "0123456789abcdef" for character in tip_hash)
            ):
                raise LedgerError("invalid_remote_head")
            try:
                if str(uuid.UUID(tip_event_id)) != tip_event_id:
                    raise ValueError
            except ValueError as exception:
                raise LedgerError("invalid_remote_head") from exception
            if incarnation_id in seen:
                raise LedgerError("duplicate_remote_head")
            seen.add(incarnation_id)
            normalized.append(dict(head))
        if normalized != sorted(normalized, key=lambda head: head["incarnation_id"]):
            raise LedgerError("remote_heads_not_sorted")
        for head in normalized:
            local = database.execute(
                "SELECT event_id, content_hash FROM events "
                "WHERE incarnation_id=? AND sequence=?",
                (head["incarnation_id"], head["max_sequence"]),
            ).fetchone()
            if local is not None and (
                local["event_id"] != head["tip_event_id"]
                or local["content_hash"] != head["tip_hash"]
            ):
                raise LedgerEquivocationError(
                    {
                        "schema": "dm.we.equivocation/v1",
                        "lane": "remote_head",
                        "incarnation_id": head["incarnation_id"],
                        "sequence": head["max_sequence"],
                        "existing_event_id": local["event_id"],
                        "existing_content_hash": local["content_hash"],
                        "presented_event_id": head["tip_event_id"],
                        "presented_content_hash": head["tip_hash"],
                    }
                )
        return {
            str(head["incarnation_id"]): int(head["max_sequence"])
            for head in normalized
        }

    @staticmethod
    def _delta_page(
        database: sqlite3.Connection,
        remote_sequences: Mapping[str, int],
        limit: int,
    ) -> tuple[list[Event], bool]:
        result: list[Event] = []
        rows = database.execute(
            "SELECT event_json FROM events ORDER BY incarnation_id, sequence, event_id"
        )
        for row in rows:
            event: Event = json.loads(bytes(row["event_json"]))
            if event["sequence"] <= remote_sequences.get(
                event["origin"]["incarnation_id"], 0
            ):
                continue
            candidate = [*result, event]
            if len(result) == limit or len(page_bytes(candidate)) > MAX_PAGE_BYTES:
                return result, True
            result.append(event)
        return result, False

    def delta(
        self,
        remote_heads: Sequence[Mapping[str, Any]],
        *,
        limit: int = MAX_PAGE_EVENTS,
    ) -> list[Event]:
        if (
            not isinstance(limit, int)
            or isinstance(limit, bool)
            or not 1 <= limit <= MAX_PAGE_EVENTS
        ):
            raise LedgerError("invalid_delta_limit")
        self.initialize()
        with self._database() as database:
            remote_sequences = self._remote_sequences(database, remote_heads)
            events, _ = self._delta_page(database, remote_sequences, limit)
            return events

    def delta_idempotent(
        self,
        *,
        request_id: str,
        request_hash: str,
        remote_heads: Sequence[Mapping[str, Any]],
        limit: int,
    ) -> dict[str, Any]:
        """Return one transactionally frozen page for a typed sync request."""

        self.initialize()
        try:
            with self._database() as database:
                database.execute("BEGIN IMMEDIATE")
                try:
                    cached = database.execute(
                        "SELECT request_hash, response_json FROM outbound_sync "
                        "WHERE request_id=?",
                        (request_id,),
                    ).fetchone()
                    if cached is not None:
                        if cached["request_hash"] != request_hash:
                            raise LedgerEquivocationError(
                                {
                                    "schema": "dm.we.equivocation/v1",
                                    "lane": "sync_request",
                                    "request_id": request_id,
                                    "existing_request_hash": cached["request_hash"],
                                    "presented_request_hash": request_hash,
                                }
                            )
                        response: dict[str, Any] = json.loads(
                            bytes(cached["response_json"])
                        )
                    else:
                        remote_sequences = self._remote_sequences(
                            database, remote_heads
                        )
                        events, more = self._delta_page(
                            database, remote_sequences, limit
                        )
                        response = {
                            "events": events,
                            "more": more,
                            "offered_heads": self._heads(database),
                        }
                        database.execute(
                            "INSERT INTO outbound_sync VALUES (?, ?, ?)",
                            (request_id, request_hash, canonical_bytes(response)),
                        )
                    database.commit()
                except BaseException:
                    database.rollback()
                    raise
        except LedgerEquivocationError as exception:
            self._record_equivocation(exception.evidence)
            raise
        return response

    def issued_request(self, request_id: str) -> tuple[str, dict[str, Any]] | None:
        self.initialize()
        with self._database() as database:
            row = database.execute(
                "SELECT request_hash, request_json FROM issued_sync WHERE request_id=?",
                (request_id,),
            ).fetchone()
        return (
            None
            if row is None
            else (
                str(row["request_hash"]),
                json.loads(bytes(row["request_json"])),
            )
        )

    def store_issued_request(
        self,
        *,
        request_id: str,
        request_hash: str,
        request: Mapping[str, Any],
    ) -> dict[str, Any]:
        raw = canonical_bytes(request)
        self.initialize()
        try:
            with self._database() as database:
                database.execute("BEGIN IMMEDIATE")
                try:
                    existing = database.execute(
                        "SELECT request_hash, request_json FROM issued_sync "
                        "WHERE request_id=?",
                        (request_id,),
                    ).fetchone()
                    if existing is not None:
                        if (
                            existing["request_hash"] != request_hash
                            or bytes(existing["request_json"]) != raw
                        ):
                            raise LedgerEquivocationError(
                                {
                                    "schema": "dm.we.equivocation/v1",
                                    "lane": "issued_sync_request",
                                    "request_id": request_id,
                                    "existing_request_hash": existing["request_hash"],
                                    "presented_request_hash": request_hash,
                                }
                            )
                        result: dict[str, Any] = json.loads(
                            bytes(existing["request_json"])
                        )
                    else:
                        database.execute(
                            "INSERT INTO issued_sync VALUES (?, ?, ?)",
                            (request_id, request_hash, raw),
                        )
                        result = copy.deepcopy(dict(request))
                    database.commit()
                except BaseException:
                    database.rollback()
                    raise
        except LedgerEquivocationError as exception:
            self._record_equivocation(exception.evidence)
            raise
        return result

    def ingest_idempotent(
        self,
        events: Sequence[Mapping[str, Any]],
        *,
        source: str,
        request_id: str,
        page_hash: str,
        receipt_base: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Atomically ingest one page and persist its exact retry receipt."""

        if not isinstance(source, str) or not 1 <= len(source.encode("utf-8")) <= 256:
            raise LedgerError("invalid_peer_id")
        self.initialize()
        try:
            with self._database() as database:
                database.execute("BEGIN IMMEDIATE")
                try:
                    cached = database.execute(
                        "SELECT page_hash, receipt_json FROM inbound_sync "
                        "WHERE peer_id=? AND request_id=?",
                        (source, request_id),
                    ).fetchone()
                    if cached is not None:
                        if cached["page_hash"] != page_hash:
                            raise LedgerEquivocationError(
                                {
                                    "schema": "dm.we.equivocation/v1",
                                    "lane": "sync_page",
                                    "peer_id": source,
                                    "request_id": request_id,
                                    "existing_page_hash": cached["page_hash"],
                                    "presented_page_hash": page_hash,
                                }
                            )
                        receipt: dict[str, Any] = json.loads(
                            bytes(cached["receipt_json"])
                        )
                    else:
                        validated, missing, _ = self._plan(database, events)
                        cursors = {
                            str(row["incarnation_id"]): int(row["sequence"])
                            for row in database.execute(
                                "SELECT incarnation_id, sequence "
                                "FROM peer_cursors WHERE peer_id=?",
                                (source,),
                            )
                        }
                        if any(
                            event["sequence"]
                            < cursors.get(event["origin"]["incarnation_id"], 0)
                            for event in validated
                        ):
                            raise LedgerError("peer_cursor_regression")
                        available_known = {
                            str(row["event_id"])
                            for row in database.execute(
                                "SELECT event_id FROM events WHERE status='known'"
                            )
                        }
                        for event in missing:
                            dependencies = self._dependencies(event)
                            status = (
                                "known"
                                if dependencies <= available_known
                                else "incomplete"
                            )
                            self._insert(database, event, source=source, status=status)
                            if status == "known":
                                available_known.add(event["event_id"])
                        self._promote(database)
                        for page_event in validated:
                            self._advance_cursor(database, source, page_event)
                        incomplete = int(
                            database.execute(
                                "SELECT COUNT(*) FROM events WHERE status='incomplete'"
                            ).fetchone()[0]
                        )
                        receipt_core = {
                            **copy.deepcopy(dict(receipt_base)),
                            "received": len(validated),
                            "inserted": len(missing),
                            "replayed": len(validated) - len(missing),
                            "incomplete": incomplete,
                            "achieved_heads": self._heads(database),
                            "completed_at_ms": self.clock(),
                        }
                        receipt = {
                            **receipt_core,
                            "receipt_hash": hashlib.sha256(
                                b"daimon/weave/sync-receipt/v1\x00"
                                + canonical_bytes(receipt_core)
                            ).hexdigest(),
                        }
                        database.execute(
                            "INSERT INTO inbound_sync VALUES (?, ?, ?, ?)",
                            (
                                source,
                                request_id,
                                page_hash,
                                canonical_bytes(receipt),
                            ),
                        )
                    database.commit()
                except BaseException:
                    database.rollback()
                    raise
            self._set_peer_state(source, "coherent", None)
        except LedgerEquivocationError as exception:
            self._record_equivocation(exception.evidence)
            self._set_peer_state(source, "quarantined", str(exception))
            raise
        except LedgerGapError as exception:
            self._set_peer_state(source, "gap", str(exception))
            raise
        except WeaveProtocolError as exception:
            self._set_peer_state(source, "quarantined", str(exception))
            raise
        return receipt

    def replace_projection_cache(self, snapshot: Mapping[str, Any]) -> None:
        raw = canonical_bytes(snapshot)
        projection_hash = snapshot.get("projection_hash")
        if not isinstance(projection_hash, str):
            raise LedgerError("invalid_projection_snapshot")
        self.initialize()
        with self._database() as database:
            database.execute("BEGIN IMMEDIATE")
            try:
                database.execute(
                    "INSERT INTO projection_cache VALUES (1, ?, ?) "
                    "ON CONFLICT(slot) DO UPDATE SET "
                    "projection_hash=excluded.projection_hash, "
                    "snapshot_json=excluded.snapshot_json",
                    (projection_hash, raw),
                )
                database.commit()
            except BaseException:
                database.rollback()
                raise

    def projection_cache(self) -> dict[str, Any] | None:
        self.initialize()
        with self._database() as database:
            row = database.execute(
                "SELECT snapshot_json FROM projection_cache WHERE slot=1"
            ).fetchone()
        return None if row is None else json.loads(bytes(row["snapshot_json"]))

    def peer_cursors(self, peer_id: str | None = None) -> list[dict[str, Any]]:
        self.initialize()
        query = (
            "SELECT peer_id, incarnation_id, sequence, tip_event_id, tip_hash "
            "FROM peer_cursors"
        )
        parameters: tuple[Any, ...] = ()
        if peer_id is not None:
            query += " WHERE peer_id=?"
            parameters = (peer_id,)
        query += " ORDER BY peer_id, incarnation_id"
        with self._database() as database:
            return [dict(row) for row in database.execute(query, parameters)]

    def peer_sync_states(self) -> list[dict[str, Any]]:
        self.initialize()
        with self._database() as database:
            return [
                dict(row)
                for row in database.execute(
                    "SELECT peer_id, state, error, updated_at_ms "
                    "FROM peer_sync_state ORDER BY peer_id"
                )
            ]

    def equivocations(self) -> list[dict[str, Any]]:
        self.initialize()
        with self._database() as database:
            rows = database.execute(
                "SELECT evidence_json FROM equivocations ORDER BY evidence_hash"
            ).fetchall()
        return [json.loads(bytes(row["evidence_json"])) for row in rows]

    def diff(
        self, *, kind: str | None = None, subject: str | None = None
    ) -> list[dict[str, Any]]:
        from .projections import ProjectionEngine

        entries = ProjectionEngine(self).snapshot()["entries"]
        return [
            entry
            for entry in entries
            if (kind is None or entry["kind"] == kind)
            and (subject is None or entry["subject"] == subject)
        ]


__all__ = [
    "BUSY_TIMEOUT_MS",
    "SCHEMA_VERSION",
    "Ledger",
    "LedgerEquivocationError",
    "LedgerError",
    "LedgerGapError",
    "LedgerStateError",
    "Preview",
]
