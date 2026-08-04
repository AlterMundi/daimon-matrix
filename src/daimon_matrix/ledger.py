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

SCHEMA_VERSION: Final = 1
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
                raise LedgerStateError("ledger_metadata_mismatch")
        _assert_owner_file(self.path)

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
                head = self._head(database, self.local_origin["incarnation_id"])
                sequence = 1 if head is None else int(head["sequence"]) + 1
                event = create_event(
                    self.authority,
                    self.local_origin,
                    signer,
                    event_id=str(self.uuid_factory()) if event_id is None else event_id,
                    sequence=sequence,
                    previous_event_id=None if head is None else str(head["event_id"]),
                    occurred_at_ms=self.clock()
                    if occurred_at_ms is None
                    else occurred_at_ms,
                    causal_parents=causal_parents,
                    kind=kind,
                    subject=subject,
                    payload=payload,
                    supersedes=supersedes,
                    sensitivity=sensitivity,
                )
                dependencies = self._dependencies(event)
                unavailable = [
                    dependency
                    for dependency in dependencies
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
                database.commit()
                return event
            except BaseException:
                database.rollback()
                raise

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

    def heads(self) -> list[dict[str, Any]]:
        self.initialize()
        with self._database() as database:
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
        remote_sequences = {
            head["incarnation_id"]: head["max_sequence"] for head in normalized
        }

        self.initialize()
        with self._database() as database:
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
        result: list[Event] = []
        for event in self.events():
            if event["sequence"] <= remote_sequences.get(
                event["origin"]["incarnation_id"], 0
            ):
                continue
            candidate = [*result, event]
            if len(page_bytes(candidate)) > MAX_PAGE_BYTES:
                break
            result.append(event)
            if len(result) == limit:
                break
        return result

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
        known = self.events(include_incomplete=False)
        decisions: dict[str, Event] = {}
        for event in known:
            if (
                event["kind"] == "adoption.decided"
                and event["origin"]["embodiment_id"]
                == self.local_origin["embodiment_id"]
            ):
                decisions[event["payload"]["target_event_id"]] = event
        result: list[dict[str, Any]] = []
        excluded = {
            "adoption.decided",
            "projection.receipted",
            "lifecycle.announced",
        }
        for event in known:
            if event["kind"] in excluded:
                continue
            if kind is not None and event["kind"] != kind:
                continue
            if subject is not None and event["subject"] != subject:
                continue
            decision = decisions.get(event["event_id"])
            value = None if decision is None else decision["payload"]["decision"]
            state = {
                None: "pending",
                "adopt": "adopted",
                "reject": "rejected",
                "defer": "deferred",
                "revert": "reverted",
            }[value]
            result.append(
                {
                    "event_id": event["event_id"],
                    "kind": event["kind"],
                    "subject": event["subject"],
                    "origin": event["origin"],
                    "state": state,
                    "decision_event_id": None
                    if decision is None
                    else decision["event_id"],
                }
            )
        return result


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
