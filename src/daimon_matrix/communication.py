"""Canonical logical communication projections above disposable routes.

DM-052 deliberately stores its projections in the same SQLite database as the
DM-023 ledger.  Signed ``dm.we.v1`` events remain the authority; every table in
this module is rebuildable state or explicitly operational delivery evidence.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import secrets
import sqlite3
import stat
import uuid
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from typing import Any, Final, Protocol

from .canonical import CanonicalError, b64url, canonical_bytes, unb64url
from .ledger import Ledger, LedgerStateError
from .weave import Event, EventAuthority, WeaveProtocolError, verify_event

MESSAGE_PAYLOAD_SCHEMA: Final = "dm.communication.message/v1"
RESOLUTION_PAYLOAD_SCHEMA: Final = "dm.communication.resolution/v1"
RECEIPT_PAYLOAD_SCHEMA: Final = "dm.communication.receipt/v1"
LOGICAL_MESSAGE_SCHEMA: Final = "dm.logical-message/v1"
SEMANTIC_LEG_SCHEMA: Final = "dm.semantic-leg/v1"
ROUTE_ATTEMPT_SCHEMA: Final = "dm.route-attempt/v1"
SEMANTIC_RECEIPT_SCHEMA: Final = "dm.semantic-receipt/v1"
PAGE_SCHEMA: Final = "dm.communication.page/v1"
RESULT_SCHEMA: Final = "dm.communication.result/v1"
STORE_SCHEMA_VERSION: Final = 1
MAX_PAGE_SIZE: Final = 256
MAX_TARGETS: Final = 256
MAX_BODY_BYTES: Final = 192 * 1024
TERMINAL_OUTCOMES: Final = frozenset(
    {
        "delivered",
        "failed:transport",
        "refused:policy",
        "expired",
        "resolved:unroutable",
    }
)
LEG_STATES: Final = frozenset({"accepted", *TERMINAL_OUTCOMES, "quarantined"})
SCOPE_KINDS: Final = frozenset({"we", "relationship", "direct"})
RECIPIENT_TYPES: Final = frozenset({"embodiment", "relationship"})
ATTEMPT_STATES: Final = frozenset({"accepted", "route-acked", "route-failed"})
_ANCHOR_SCHEMA: Final = "dm.communication.anchor/v1"
_CURSOR_PREFIX: Final = "dm:cursor:v1:"
_ID_TEXT = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:@/-"
)

Clock = Callable[[], int]
UUIDFactory = Callable[[], uuid.UUID]
TokenFactory = Callable[[int], bytes]


class CommunicationError(ValueError):
    """Stable fail-closed logical communication error."""

    def __init__(self, code: str, *, retryable: bool = False) -> None:
        super().__init__(code)
        self.code = code
        self.retryable = retryable


class RouteProvider(Protocol):
    """The DM-018-shaped narrow waist used by later route implementations."""

    @property
    def provider_ref(self) -> str: ...

    def deliver(self, attempt: Mapping[str, Any]) -> Mapping[str, Any]: ...


@dataclass(frozen=True)
class MessageProjection:
    message_id: str
    event_hash: str
    thread_id: str
    author: Mapping[str, str]
    intent: Mapping[str, str]
    resolution_event_id: str
    resolution_hash: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": LOGICAL_MESSAGE_SCHEMA,
            "message_id": self.message_id,
            "event_hash": self.event_hash,
            "thread_id": self.thread_id,
            "author": copy.deepcopy(dict(self.author)),
            "intent": copy.deepcopy(dict(self.intent)),
            "resolution_event_id": self.resolution_event_id,
            "resolution_hash": self.resolution_hash,
        }


def _now_ms() -> int:
    import time

    return int(time.time() * 1000)


def _closed(value: Any, fields: set[str], error: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise CommunicationError(error)
    return value


def _text(value: Any, error: str, *, maximum: int = 256) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > maximum
        or any(character not in _ID_TEXT for character in value)
    ):
        raise CommunicationError(error)
    return value


def _uuid(value: Any, error: str) -> str:
    if not isinstance(value, str):
        raise CommunicationError(error)
    try:
        parsed = uuid.UUID(value)
    except ValueError as exception:
        raise CommunicationError(error) from exception
    if str(parsed) != value:
        raise CommunicationError(error)
    return value


def _hash(value: Any, error: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise CommunicationError(error)
    return value


def _uint(value: Any, error: str, *, minimum: int = 0) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not minimum <= value <= 2**53 - 1
    ):
        raise CommunicationError(error)
    return value


def _canonical(value: Any, error: str) -> bytes:
    try:
        return canonical_bytes(value)
    except CanonicalError as exception:
        raise CommunicationError(error) from exception


def _event(value: Any, authority: EventAuthority) -> Event:
    try:
        return verify_event(value, authority)
    except WeaveProtocolError as exception:
        raise CommunicationError("communication_event_rejected") from exception


def _message_payload(event: Mapping[str, Any]) -> Mapping[str, Any]:
    if event["kind"] != "experience.observed" or event["subject"] != "communication":
        raise CommunicationError("not_communication_message")
    payload = _closed(
        event["payload"],
        {"body", "intent", "reply", "schema"},
        "invalid_message_payload",
    )
    if payload["schema"] != MESSAGE_PAYLOAD_SCHEMA:
        raise CommunicationError("unsupported_message_payload")
    intent = _closed(
        payload["intent"],
        {"operation", "scope", "thread_id"},
        "invalid_message_intent",
    )
    _text(intent["operation"], "invalid_message_intent", maximum=128)
    _text(intent["scope"], "invalid_message_intent", maximum=240)
    _uuid(intent["thread_id"], "invalid_thread_id")
    if not isinstance(payload["body"], Mapping):
        raise CommunicationError("invalid_message_body")
    if len(_canonical(payload["body"], "invalid_message_body")) > MAX_BODY_BYTES:
        raise CommunicationError("message_body_too_large")
    reply = payload["reply"]
    if reply is not None:
        value = _closed(
            reply,
            {
                "direct_recipient_embodiment_id",
                "reply_parent_event_ids",
                "schema",
            },
            "invalid_direct_reply",
        )
        if value["schema"] != "daimon-reply/v1":
            raise CommunicationError("unsupported_direct_reply")
        _text(
            value["direct_recipient_embodiment_id"],
            "invalid_direct_reply",
            maximum=240,
        )
        parents = value["reply_parent_event_ids"]
        if (
            not isinstance(parents, list)
            or not parents
            or parents != sorted(set(parents))
            or len(parents) > 64
        ):
            raise CommunicationError("invalid_direct_reply")
        for parent in parents:
            _uuid(parent, "invalid_direct_reply")
        if not set(parents) <= set(event["causal_parents"]):
            raise CommunicationError("reply_parent_not_causal")
    return payload


def _resolution_payload(
    event: Mapping[str, Any], *, message_id: str, scope: str
) -> tuple[Mapping[str, Any], list[Mapping[str, Any]]]:
    if (
        event["kind"] != "experience.observed"
        or event["subject"] != "communication-resolution"
    ):
        raise CommunicationError("not_communication_resolution")
    payload = _closed(
        event["payload"],
        {"message_id", "schema", "scope", "targets"},
        "invalid_resolution_evidence",
    )
    if payload["schema"] != RESOLUTION_PAYLOAD_SCHEMA:
        raise CommunicationError("unsupported_resolution_evidence")
    if payload["message_id"] != message_id:
        raise CommunicationError("resolution_message_mismatch")
    if payload["scope"] != scope:
        raise CommunicationError("resolution_scope_mismatch")
    if message_id not in event["causal_parents"]:
        raise CommunicationError("resolution_message_not_causal")
    targets = payload["targets"]
    if not isinstance(targets, list) or not 1 <= len(targets) <= MAX_TARGETS:
        raise CommunicationError("invalid_resolution_targets")
    normalized: list[Mapping[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for row in targets:
        target = _closed(
            row,
            {
                "evidence_cursor",
                "receipt_origin_embodiment_id",
                "recipient_id",
                "recipient_type",
                "scope_kind",
            },
            "invalid_resolution_target",
        )
        scope_kind = target["scope_kind"]
        recipient_type = target["recipient_type"]
        if scope_kind not in SCOPE_KINDS or recipient_type not in RECIPIENT_TYPES:
            raise CommunicationError("invalid_resolution_target")
        if scope_kind in {"we", "direct"} and recipient_type != "embodiment":
            raise CommunicationError("invalid_resolution_target")
        if scope_kind == "relationship" and recipient_type != "relationship":
            raise CommunicationError("invalid_resolution_target")
        recipient_id = _text(
            target["recipient_id"], "invalid_resolution_target", maximum=240
        )
        _text(
            target["receipt_origin_embodiment_id"],
            "invalid_resolution_target",
            maximum=240,
        )
        _text(
            target["evidence_cursor"],
            "invalid_resolution_target",
            maximum=512,
        )
        key = (str(recipient_type), recipient_id)
        if key in seen:
            raise CommunicationError("duplicate_semantic_recipient")
        seen.add(key)
        normalized.append(copy.deepcopy(dict(target)))
    expected = sorted(
        normalized,
        key=lambda item: (str(item["recipient_type"]), str(item["recipient_id"])),
    )
    if normalized != expected:
        raise CommunicationError("resolution_targets_not_sorted")
    return payload, normalized


def _receipt_payload(event: Mapping[str, Any]) -> Mapping[str, Any]:
    if (
        event["kind"] != "experience.observed"
        or event["subject"] != "communication-receipt"
    ):
        raise CommunicationError("not_communication_receipt")
    payload = _closed(
        event["payload"],
        {
            "evidence_ref",
            "message_id",
            "observed_at_ms",
            "outcome",
            "recipient_id",
            "recipient_type",
            "schema",
            "thread_id",
        },
        "invalid_semantic_receipt",
    )
    if payload["schema"] != RECEIPT_PAYLOAD_SCHEMA:
        raise CommunicationError("unsupported_semantic_receipt")
    _uuid(payload["message_id"], "invalid_semantic_receipt")
    _uuid(payload["thread_id"], "invalid_semantic_receipt")
    if payload["recipient_type"] not in RECIPIENT_TYPES:
        raise CommunicationError("invalid_semantic_receipt")
    _text(payload["recipient_id"], "invalid_semantic_receipt", maximum=240)
    if payload["outcome"] not in TERMINAL_OUTCOMES:
        raise CommunicationError("invalid_semantic_receipt")
    _uint(payload["observed_at_ms"], "invalid_semantic_receipt")
    if payload["message_id"] not in event["causal_parents"]:
        raise CommunicationError("receipt_message_not_causal")
    evidence = payload["evidence_ref"]
    if evidence is not None:
        _text(evidence, "invalid_semantic_receipt", maximum=512)
    return payload


def _leg_id(message_id: str, recipient_type: str, recipient_id: str) -> str:
    preimage = {
        "message_id": message_id,
        "recipient_id": recipient_id,
        "recipient_type": recipient_type,
        "schema": "dm.semantic-key/v1",
    }
    return "dm:semantic-leg:v1:" + b64url(
        hashlib.sha256(
            b"daimon/semantic-leg/v1\x00" + canonical_bytes(preimage)
        ).digest()
    )


def _row_document(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "schema": SEMANTIC_LEG_SCHEMA,
        "leg_id": str(row["leg_id"]),
        "message_id": str(row["message_id"]),
        "thread_id": str(row["thread_id"]),
        "recipient_type": str(row["recipient_type"]),
        "recipient_id": str(row["recipient_id"]),
        "receipt_origin_embodiment_id": str(row["receipt_origin_embodiment_id"]),
        "resolution_event_id": str(row["resolution_event_id"]),
        "resolution_hash": str(row["resolution_hash"]),
        "evidence_cursor": str(row["evidence_cursor"]),
        "sequence": int(row["sequence"]),
        "state": str(row["state"]),
        "terminal_receipt_event_id": row["terminal_receipt_event_id"],
        "terminal_receipt_hash": row["terminal_receipt_hash"],
    }


class CommunicationStore:
    """Durable logical-message reducer and operational queue projection."""

    def __init__(
        self,
        ledger: Ledger,
        *,
        clock: Clock = _now_ms,
        uuid_factory: UUIDFactory = uuid.uuid4,
        token_factory: TokenFactory = secrets.token_bytes,
    ) -> None:
        self.ledger = ledger
        self.clock = clock
        self.uuid_factory = uuid_factory
        self.token_factory = token_factory
        self.anchor_path = ledger.path.with_name(
            ledger.path.name + ".communication-anchor.json"
        )

    @contextmanager
    def _database(self) -> Iterator[sqlite3.Connection]:
        with self.ledger._database() as database:
            yield database

    def _anchor(self) -> tuple[str, int] | None:
        try:
            info = self.anchor_path.lstat()
        except FileNotFoundError:
            return None
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & 0o077
        ):
            raise CommunicationError("communication_anchor_unsafe")
        descriptor = os.open(
            self.anchor_path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            raw = os.read(descriptor, 4097)
        finally:
            os.close(descriptor)
        if not raw or len(raw) > 4096:
            raise CommunicationError("communication_anchor_corrupt")
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exception:
            raise CommunicationError("communication_anchor_corrupt") from exception
        anchor = _closed(
            value,
            {"generation", "mutation_counter", "schema"},
            "communication_anchor_corrupt",
        )
        if anchor["schema"] != _ANCHOR_SCHEMA or canonical_bytes(anchor) != raw:
            raise CommunicationError("communication_anchor_corrupt")
        generation = _text(
            anchor["generation"], "communication_anchor_corrupt", maximum=128
        )
        counter = _uint(anchor["mutation_counter"], "communication_anchor_corrupt")
        return generation, counter

    def _write_anchor(self, generation: str, mutation_counter: int) -> None:
        value = canonical_bytes(
            {
                "schema": _ANCHOR_SCHEMA,
                "generation": generation,
                "mutation_counter": mutation_counter,
            }
        )
        temporary = self.anchor_path.with_name(
            self.anchor_path.name + f".{self.uuid_factory()}.tmp"
        )
        descriptor: int | None = None
        try:
            descriptor = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            written = 0
            while written < len(value):
                written += os.write(descriptor, value[written:])
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = None
            os.replace(temporary, self.anchor_path)
            directory = os.open(self.anchor_path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if descriptor is not None:
                os.close(descriptor)
            with suppress(FileNotFoundError):
                temporary.unlink()

    @staticmethod
    def _meta(database: sqlite3.Connection) -> tuple[str, int, int]:
        rows = {
            str(row["key"]): str(row["value"])
            for row in database.execute(
                "SELECT key, value FROM communication_meta ORDER BY key"
            )
        }
        if set(rows) != {
            "generation",
            "mutation_counter",
            "schema_version",
            "sequence_highwater",
        } or rows["schema_version"] != str(STORE_SCHEMA_VERSION):
            raise CommunicationError("communication_metadata_mismatch")
        try:
            counter = int(rows["mutation_counter"])
            highwater = int(rows["sequence_highwater"])
        except ValueError as exception:
            raise CommunicationError("communication_metadata_mismatch") from exception
        return (
            rows["generation"],
            _uint(counter, "communication_metadata_mismatch"),
            _uint(highwater, "communication_metadata_mismatch"),
        )

    def initialize(self) -> None:
        self.ledger.initialize()
        with self._database() as database:
            database.execute("BEGIN IMMEDIATE")
            try:
                database.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS communication_meta (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL
                    ) WITHOUT ROWID;
                    CREATE TABLE IF NOT EXISTS communication_messages (
                        message_id TEXT PRIMARY KEY
                            REFERENCES events(event_id) ON DELETE RESTRICT,
                        event_hash TEXT NOT NULL,
                        thread_id TEXT NOT NULL,
                        author_json BLOB NOT NULL,
                        intent_json BLOB NOT NULL,
                        resolution_event_id TEXT NOT NULL
                            REFERENCES events(event_id) ON DELETE RESTRICT,
                        resolution_hash TEXT NOT NULL,
                        message_json BLOB NOT NULL,
                        created_at_ms INTEGER NOT NULL
                    ) WITHOUT ROWID;
                    CREATE TABLE IF NOT EXISTS communication_legs (
                        leg_id TEXT PRIMARY KEY,
                        message_id TEXT NOT NULL
                            REFERENCES communication_messages(message_id)
                            ON DELETE RESTRICT,
                        thread_id TEXT NOT NULL,
                        recipient_type TEXT NOT NULL
                            CHECK(recipient_type IN ('embodiment', 'relationship')),
                        recipient_id TEXT NOT NULL,
                        receipt_origin_embodiment_id TEXT NOT NULL,
                        resolution_event_id TEXT NOT NULL,
                        resolution_hash TEXT NOT NULL,
                        evidence_cursor TEXT NOT NULL,
                        immutable_hash TEXT NOT NULL,
                        sequence INTEGER NOT NULL UNIQUE,
                        state TEXT NOT NULL,
                        terminal_receipt_event_id TEXT,
                        terminal_receipt_hash TEXT,
                        created_at_ms INTEGER NOT NULL,
                        UNIQUE(message_id, recipient_type, recipient_id),
                        CHECK(
                            (state='accepted' AND terminal_receipt_event_id IS NULL
                                AND terminal_receipt_hash IS NULL)
                            OR
                            (state IN ('delivered', 'failed:transport',
                                'refused:policy', 'expired',
                                'resolved:unroutable')
                                AND terminal_receipt_event_id IS NOT NULL
                                AND terminal_receipt_hash IS NOT NULL)
                            OR
                            state='quarantined'
                        )
                    );
                    CREATE TABLE IF NOT EXISTS communication_queue (
                        sequence INTEGER PRIMARY KEY,
                        leg_id TEXT NOT NULL UNIQUE
                            REFERENCES communication_legs(leg_id) ON DELETE RESTRICT,
                        recipient_id TEXT NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS communication_queue_recipient
                        ON communication_queue(recipient_id, sequence);
                    CREATE TABLE IF NOT EXISTS communication_attempts (
                        attempt_id TEXT PRIMARY KEY,
                        leg_id TEXT NOT NULL
                            REFERENCES communication_legs(leg_id) ON DELETE RESTRICT,
                        attempt_hash TEXT NOT NULL,
                        provider_ref TEXT NOT NULL,
                        route_ref TEXT NOT NULL,
                        credential_ref TEXT NOT NULL,
                        body_ref TEXT NOT NULL,
                        deadline_ms INTEGER NOT NULL,
                        state TEXT NOT NULL
                            CHECK(state IN ('accepted', 'route-acked', 'route-failed')),
                        ack_hash TEXT,
                        attempt_json BLOB NOT NULL,
                        created_at_ms INTEGER NOT NULL
                    ) WITHOUT ROWID;
                    CREATE INDEX IF NOT EXISTS communication_attempt_leg
                        ON communication_attempts(leg_id, created_at_ms, attempt_id);
                    CREATE TABLE IF NOT EXISTS communication_deliveries (
                        delivery_id TEXT PRIMARY KEY,
                        attempt_id TEXT NOT NULL
                            REFERENCES communication_attempts(attempt_id)
                            ON DELETE RESTRICT,
                        envelope_hash TEXT NOT NULL,
                        created_at_ms INTEGER NOT NULL
                    ) WITHOUT ROWID;
                    CREATE TABLE IF NOT EXISTS communication_receipts (
                        leg_id TEXT PRIMARY KEY
                            REFERENCES communication_legs(leg_id) ON DELETE RESTRICT,
                        receipt_event_id TEXT NOT NULL UNIQUE
                            REFERENCES events(event_id) ON DELETE RESTRICT,
                        receipt_hash TEXT NOT NULL,
                        outcome TEXT NOT NULL,
                        receipt_json BLOB NOT NULL,
                        recorded_at_ms INTEGER NOT NULL
                    ) WITHOUT ROWID;
                    CREATE TABLE IF NOT EXISTS communication_conflicts (
                        conflict_hash TEXT PRIMARY KEY,
                        leg_id TEXT NOT NULL,
                        lane TEXT NOT NULL,
                        evidence_json BLOB NOT NULL,
                        detected_at_ms INTEGER NOT NULL
                    ) WITHOUT ROWID;
                    CREATE TABLE IF NOT EXISTS communication_page_cursors (
                        token_hash TEXT PRIMARY KEY,
                        recipient_id TEXT NOT NULL,
                        consumer_id TEXT NOT NULL,
                        generation TEXT NOT NULL,
                        cutoff_sequence INTEGER NOT NULL,
                        last_sequence INTEGER NOT NULL,
                        created_at_ms INTEGER NOT NULL
                    ) WITHOUT ROWID;
                    CREATE TABLE IF NOT EXISTS communication_page_requests (
                        consumer_id TEXT NOT NULL,
                        request_id TEXT NOT NULL,
                        request_hash TEXT NOT NULL,
                        response_json BLOB NOT NULL,
                        PRIMARY KEY(consumer_id, request_id)
                    ) WITHOUT ROWID;
                    CREATE TABLE IF NOT EXISTS communication_claim_batches (
                        claim_id TEXT PRIMARY KEY,
                        request_hash TEXT NOT NULL,
                        response_json BLOB NOT NULL
                    ) WITHOUT ROWID;
                    CREATE TABLE IF NOT EXISTS communication_claim_rows (
                        recipient_id TEXT NOT NULL,
                        sequence INTEGER NOT NULL
                            REFERENCES communication_queue(sequence)
                            ON DELETE CASCADE,
                        claim_id TEXT NOT NULL
                            REFERENCES communication_claim_batches(claim_id)
                            ON DELETE CASCADE,
                        consumer_id TEXT NOT NULL,
                        lease_until_ms INTEGER NOT NULL,
                        PRIMARY KEY(recipient_id, sequence)
                    ) WITHOUT ROWID;
                    CREATE INDEX IF NOT EXISTS communication_claim_expiry
                        ON communication_claim_rows(lease_until_ms);
                    CREATE TABLE IF NOT EXISTS communication_consumers (
                        recipient_id TEXT NOT NULL,
                        consumer_id TEXT NOT NULL,
                        generation TEXT NOT NULL,
                        sequence INTEGER NOT NULL,
                        PRIMARY KEY(recipient_id, consumer_id)
                    ) WITHOUT ROWID;
                    """
                )
                # sqlite3.executescript() commits its input transaction.  Retake
                # the writer lock before inspecting or creating generation state.
                database.execute("BEGIN IMMEDIATE")
                count = int(
                    database.execute(
                        "SELECT COUNT(*) FROM communication_meta"
                    ).fetchone()[0]
                )
                if count == 0:
                    if self._anchor() is not None:
                        raise CommunicationError("communication_state_rollback")
                    generation = "dm:communication-store:v1:" + str(self.uuid_factory())
                    database.executemany(
                        "INSERT INTO communication_meta(key, value) VALUES (?, ?)",
                        [
                            ("generation", generation),
                            ("mutation_counter", "0"),
                            ("schema_version", str(STORE_SCHEMA_VERSION)),
                            ("sequence_highwater", "0"),
                        ],
                    )
                    database.commit()
                    self._write_anchor(generation, 0)
                    return
                generation, counter, _highwater = self._meta(database)
                anchor = self._anchor()
                if anchor is None:
                    if counter != 0:
                        raise CommunicationError("communication_state_rollback")
                    self._write_anchor(generation, counter)
                elif anchor != (generation, counter):
                    raise CommunicationError("communication_state_rollback")
                database.commit()
            except BaseException:
                database.rollback()
                raise

    def _arm_commit(self, database: sqlite3.Connection) -> None:
        generation, counter, _highwater = self._meta(database)
        next_counter = counter + 1
        self._write_anchor(generation, next_counter)
        database.execute(
            "UPDATE communication_meta SET value=? WHERE key='mutation_counter'",
            (str(next_counter),),
        )
        database.commit()

    @staticmethod
    def _known_event(database: sqlite3.Connection, event_id: str) -> Event:
        row = database.execute(
            "SELECT event_json FROM events WHERE event_id=? AND status='known'",
            (event_id,),
        ).fetchone()
        if row is None:
            raise CommunicationError("canonical_event_not_known", retryable=True)
        value = json.loads(bytes(row["event_json"]))
        if not isinstance(value, dict):
            raise LedgerStateError("canonical_event_corrupt")
        return value

    def accept(
        self, *, message_event_id: str, resolution_event_id: str
    ) -> dict[str, Any]:
        """Materialize one message and exactly one leg per signed target."""

        _uuid(message_event_id, "invalid_message_id")
        _uuid(resolution_event_id, "invalid_resolution_event_id")
        self.initialize()
        with self._database() as database:
            database.execute("BEGIN IMMEDIATE")
            try:
                message = _event(
                    self._known_event(database, message_event_id),
                    self.ledger.authority,
                )
                payload = _message_payload(message)
                resolution = _event(
                    self._known_event(database, resolution_event_id),
                    self.ledger.authority,
                )
                _resolution, targets = _resolution_payload(
                    resolution,
                    message_id=message_event_id,
                    scope=str(payload["intent"]["scope"]),
                )
                reply = payload["reply"]
                if reply is not None:
                    direct = [
                        target
                        for target in targets
                        if target["scope_kind"] == "direct"
                        and target["recipient_type"] == "embodiment"
                        and target["recipient_id"]
                        == reply["direct_recipient_embodiment_id"]
                    ]
                    if len(targets) != 1 or len(direct) != 1:
                        raise CommunicationError("direct_reply_target_mismatch")
                    for parent_id in reply["reply_parent_event_ids"]:
                        parent = database.execute(
                            "SELECT thread_id FROM communication_messages "
                            "WHERE message_id=?",
                            (parent_id,),
                        ).fetchone()
                        if parent is None:
                            raise CommunicationError(
                                "reply_parent_not_known", retryable=True
                            )
                        if parent["thread_id"] != payload["intent"]["thread_id"]:
                            raise CommunicationError("reply_thread_mismatch")
                projection = MessageProjection(
                    message_id=message_event_id,
                    event_hash=str(message["content_hash"]),
                    thread_id=str(payload["intent"]["thread_id"]),
                    author=copy.deepcopy(dict(message["origin"])),
                    intent=copy.deepcopy(dict(payload["intent"])),
                    resolution_event_id=resolution_event_id,
                    resolution_hash=str(resolution["content_hash"]),
                )
                message_document = projection.as_dict()
                raw_message = canonical_bytes(message_document)
                existing_message = database.execute(
                    "SELECT message_json FROM communication_messages "
                    "WHERE message_id=?",
                    (message_event_id,),
                ).fetchone()
                changed = False
                if existing_message is None:
                    database.execute(
                        "INSERT INTO communication_messages VALUES "
                        "(?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            message_event_id,
                            message["content_hash"],
                            payload["intent"]["thread_id"],
                            canonical_bytes(message["origin"]),
                            canonical_bytes(payload["intent"]),
                            resolution_event_id,
                            resolution["content_hash"],
                            raw_message,
                            self.clock(),
                        ),
                    )
                    changed = True
                elif bytes(existing_message["message_json"]) != raw_message:
                    raise CommunicationError("message_projection_conflict")
                for target in targets:
                    recipient_type = str(target["recipient_type"])
                    recipient_id = str(target["recipient_id"])
                    leg_id = _leg_id(message_event_id, recipient_type, recipient_id)
                    immutable = {
                        "message_id": message_event_id,
                        "thread_id": payload["intent"]["thread_id"],
                        "recipient_type": recipient_type,
                        "recipient_id": recipient_id,
                        "receipt_origin_embodiment_id": target[
                            "receipt_origin_embodiment_id"
                        ],
                        "resolution_event_id": resolution_event_id,
                        "resolution_hash": resolution["content_hash"],
                        "evidence_cursor": target["evidence_cursor"],
                    }
                    immutable_hash = hashlib.sha256(
                        canonical_bytes(immutable)
                    ).hexdigest()
                    existing = database.execute(
                        "SELECT immutable_hash FROM communication_legs "
                        "WHERE message_id=? AND recipient_type=? AND recipient_id=?",
                        (message_event_id, recipient_type, recipient_id),
                    ).fetchone()
                    if existing is not None:
                        if existing["immutable_hash"] != immutable_hash:
                            raise CommunicationError("semantic_leg_conflict")
                        continue
                    highwater = int(
                        database.execute(
                            "SELECT value FROM communication_meta "
                            "WHERE key='sequence_highwater'"
                        ).fetchone()[0]
                    )
                    sequence = highwater + 1
                    database.execute(
                        "UPDATE communication_meta SET value=? "
                        "WHERE key='sequence_highwater'",
                        (str(sequence),),
                    )
                    database.execute(
                        "INSERT INTO communication_legs VALUES "
                        "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'accepted', "
                        "NULL, NULL, ?)",
                        (
                            leg_id,
                            message_event_id,
                            payload["intent"]["thread_id"],
                            recipient_type,
                            recipient_id,
                            target["receipt_origin_embodiment_id"],
                            resolution_event_id,
                            resolution["content_hash"],
                            target["evidence_cursor"],
                            immutable_hash,
                            sequence,
                            self.clock(),
                        ),
                    )
                    database.execute(
                        "INSERT INTO communication_queue VALUES (?, ?, ?)",
                        (sequence, leg_id, recipient_id),
                    )
                    changed = True
                result = self._result(database, message_event_id)
                if changed:
                    self._arm_commit(database)
                else:
                    database.commit()
                return result
            except BaseException:
                database.rollback()
                raise

    @staticmethod
    def _result(database: sqlite3.Connection, message_id: str) -> dict[str, Any]:
        message = database.execute(
            "SELECT thread_id FROM communication_messages WHERE message_id=?",
            (message_id,),
        ).fetchone()
        if message is None:
            raise CommunicationError("message_not_known")
        rows = database.execute(
            "SELECT * FROM communication_legs WHERE message_id=? "
            "ORDER BY recipient_type, recipient_id",
            (message_id,),
        ).fetchall()
        legs = [_row_document(row) for row in rows]
        return {
            "schema": RESULT_SCHEMA,
            "message_id": message_id,
            "thread_id": str(message["thread_id"]),
            "terminal": bool(legs)
            and all(leg["state"] in TERMINAL_OUTCOMES for leg in legs),
            "legs": legs,
        }

    def result(
        self, message_id: str, *, require_terminal: bool = False
    ) -> dict[str, Any]:
        _uuid(message_id, "invalid_message_id")
        self.initialize()
        with self._database() as database:
            result = self._result(database, message_id)
        if require_terminal and not result["terminal"]:
            raise CommunicationError("terminal_result_incomplete", retryable=True)
        return result

    def rebuild_plan(self, message_id: str) -> dict[str, Any]:
        """Return canonical event/evidence plus stable legs, never old ciphertext."""

        _uuid(message_id, "invalid_message_id")
        self.initialize()
        with self._database() as database:
            row = database.execute(
                "SELECT m.message_id, m.resolution_event_id, m.message_json, "
                "e.event_json, "
                "r.event_json AS resolution_json "
                "FROM communication_messages m "
                "JOIN events e ON e.event_id=m.message_id "
                "JOIN events r ON r.event_id=m.resolution_event_id "
                "WHERE m.message_id=? AND e.status='known' AND r.status='known'",
                (message_id,),
            ).fetchone()
            if row is None:
                raise CommunicationError("message_not_known")
            legs = database.execute(
                "SELECT * FROM communication_legs WHERE message_id=? "
                "ORDER BY recipient_type, recipient_id",
                (message_id,),
            ).fetchall()
            return {
                "schema": "dm.communication.rebuild-plan/v1",
                "projection": json.loads(bytes(row["message_json"])),
                "message": json.loads(bytes(row["event_json"])),
                "resolution": json.loads(bytes(row["resolution_json"])),
                "legs": [_row_document(item) for item in legs],
            }

    @staticmethod
    def _attempt_document(value: Any) -> Mapping[str, Any]:
        attempt = _closed(
            value,
            {
                "attempt_id",
                "body_ref",
                "credential_ref",
                "deadline_ms",
                "leg_id",
                "provider_ref",
                "route_ref",
                "schema",
            },
            "invalid_route_attempt",
        )
        if attempt["schema"] != ROUTE_ATTEMPT_SCHEMA:
            raise CommunicationError("unsupported_route_attempt")
        _uuid(attempt["attempt_id"], "invalid_route_attempt")
        for field in (
            "leg_id",
            "body_ref",
            "credential_ref",
            "provider_ref",
            "route_ref",
        ):
            _text(attempt[field], "invalid_route_attempt", maximum=256)
        _uint(attempt["deadline_ms"], "invalid_route_attempt")
        return attempt

    def record_attempt(self, value: Any) -> dict[str, Any]:
        attempt = self._attempt_document(value)
        raw = canonical_bytes(attempt)
        digest = hashlib.sha256(raw).hexdigest()
        self.initialize()
        with self._database() as database:
            database.execute("BEGIN IMMEDIATE")
            try:
                leg = database.execute(
                    "SELECT state FROM communication_legs WHERE leg_id=?",
                    (attempt["leg_id"],),
                ).fetchone()
                if leg is None:
                    raise CommunicationError("semantic_leg_not_known")
                existing = database.execute(
                    "SELECT attempt_hash, state, ack_hash FROM communication_attempts "
                    "WHERE attempt_id=?",
                    (attempt["attempt_id"],),
                ).fetchone()
                if existing is not None:
                    if existing["attempt_hash"] != digest:
                        raise CommunicationError("route_attempt_conflict")
                    database.commit()
                    return {
                        **copy.deepcopy(dict(attempt)),
                        "state": str(existing["state"]),
                        "ack_hash": existing["ack_hash"],
                    }
                if leg["state"] != "accepted":
                    raise CommunicationError("semantic_leg_not_accepted")
                if attempt["deadline_ms"] <= self.clock():
                    raise CommunicationError("route_attempt_expired")
                database.execute(
                    "INSERT INTO communication_attempts VALUES "
                    "(?, ?, ?, ?, ?, ?, ?, ?, 'accepted', NULL, ?, ?)",
                    (
                        attempt["attempt_id"],
                        attempt["leg_id"],
                        digest,
                        attempt["provider_ref"],
                        attempt["route_ref"],
                        attempt["credential_ref"],
                        attempt["body_ref"],
                        attempt["deadline_ms"],
                        raw,
                        self.clock(),
                    ),
                )
                self._arm_commit(database)
                return {
                    **copy.deepcopy(dict(attempt)),
                    "state": "accepted",
                    "ack_hash": None,
                }
            except BaseException:
                database.rollback()
                raise

    def record_delivery(
        self, *, attempt_id: str, delivery_id: str, envelope_hash: str
    ) -> dict[str, Any]:
        _uuid(attempt_id, "invalid_attempt_id")
        _uuid(delivery_id, "invalid_delivery_id")
        _hash(envelope_hash, "invalid_envelope_hash")
        self.initialize()
        with self._database() as database:
            database.execute("BEGIN IMMEDIATE")
            try:
                attempt = database.execute(
                    "SELECT leg_id FROM communication_attempts WHERE attempt_id=?",
                    (attempt_id,),
                ).fetchone()
                if attempt is None:
                    raise CommunicationError("route_attempt_not_known")
                existing = database.execute(
                    "SELECT d.attempt_id, d.envelope_hash, a.leg_id "
                    "FROM communication_deliveries d "
                    "JOIN communication_attempts a ON a.attempt_id=d.attempt_id "
                    "WHERE d.delivery_id=?",
                    (delivery_id,),
                ).fetchone()
                if existing is not None:
                    if (
                        existing["attempt_id"] == attempt_id
                        and existing["envelope_hash"] == envelope_hash
                    ):
                        database.commit()
                        return {
                            "delivery_id": delivery_id,
                            "attempt_id": attempt_id,
                            "envelope_hash": envelope_hash,
                            "replayed": True,
                        }
                    evidence = {
                        "schema": "dm.communication.conflict/v1",
                        "lane": "delivery",
                        "delivery_id": delivery_id,
                        "existing_attempt_id": existing["attempt_id"],
                        "existing_leg_id": existing["leg_id"],
                        "existing_envelope_hash": existing["envelope_hash"],
                        "presented_attempt_id": attempt_id,
                        "presented_leg_id": attempt["leg_id"],
                        "presented_envelope_hash": envelope_hash,
                    }
                    self._quarantine(database, str(attempt["leg_id"]), evidence)
                    if existing["leg_id"] != attempt["leg_id"]:
                        database.execute(
                            "UPDATE communication_legs SET state='quarantined' "
                            "WHERE leg_id=?",
                            (existing["leg_id"],),
                        )
                    self._arm_commit(database)
                    raise CommunicationError("delivery_id_conflict")
                database.execute(
                    "INSERT INTO communication_deliveries VALUES (?, ?, ?, ?)",
                    (delivery_id, attempt_id, envelope_hash, self.clock()),
                )
                self._arm_commit(database)
                return {
                    "delivery_id": delivery_id,
                    "attempt_id": attempt_id,
                    "envelope_hash": envelope_hash,
                    "replayed": False,
                }
            except CommunicationError as exception:
                if exception.code != "delivery_id_conflict":
                    database.rollback()
                raise
            except BaseException:
                database.rollback()
                raise

    def record_route_ack(
        self, *, attempt_id: str, ack: Mapping[str, Any], failed: bool = False
    ) -> dict[str, Any]:
        _uuid(attempt_id, "invalid_attempt_id")
        raw = _canonical(ack, "invalid_route_ack")
        digest = hashlib.sha256(raw).hexdigest()
        state = "route-failed" if failed else "route-acked"
        self.initialize()
        with self._database() as database:
            database.execute("BEGIN IMMEDIATE")
            try:
                row = database.execute(
                    "SELECT state, ack_hash FROM communication_attempts "
                    "WHERE attempt_id=?",
                    (attempt_id,),
                ).fetchone()
                if row is None:
                    raise CommunicationError("route_attempt_not_known")
                if row["state"] == state and row["ack_hash"] == digest:
                    database.commit()
                    return {
                        "attempt_id": attempt_id,
                        "state": state,
                        "ack_hash": digest,
                    }
                if row["state"] != "accepted":
                    raise CommunicationError("route_ack_conflict")
                database.execute(
                    "UPDATE communication_attempts SET state=?, ack_hash=? "
                    "WHERE attempt_id=?",
                    (state, digest, attempt_id),
                )
                self._arm_commit(database)
                return {"attempt_id": attempt_id, "state": state, "ack_hash": digest}
            except BaseException:
                database.rollback()
                raise

    def _quarantine(
        self, database: sqlite3.Connection, leg_id: str, evidence: Mapping[str, Any]
    ) -> None:
        raw = canonical_bytes(evidence)
        digest = hashlib.sha256(raw).hexdigest()
        database.execute(
            "INSERT OR IGNORE INTO communication_conflicts VALUES (?, ?, ?, ?, ?)",
            (digest, leg_id, evidence["lane"], raw, self.clock()),
        )
        database.execute(
            "UPDATE communication_legs SET state='quarantined' WHERE leg_id=?",
            (leg_id,),
        )

    def record_receipt(self, receipt_event_id: str) -> dict[str, Any]:
        _uuid(receipt_event_id, "invalid_receipt_event_id")
        self.initialize()
        with self._database() as database:
            database.execute("BEGIN IMMEDIATE")
            committed_conflict = False
            try:
                receipt = _event(
                    self._known_event(database, receipt_event_id),
                    self.ledger.authority,
                )
                payload = _receipt_payload(receipt)
                leg = database.execute(
                    "SELECT * FROM communication_legs WHERE message_id=? "
                    "AND recipient_type=? AND recipient_id=?",
                    (
                        payload["message_id"],
                        payload["recipient_type"],
                        payload["recipient_id"],
                    ),
                ).fetchone()
                if leg is None:
                    raise CommunicationError("semantic_leg_not_known")
                if leg["thread_id"] != payload["thread_id"]:
                    raise CommunicationError("receipt_thread_mismatch")
                if (
                    payload["outcome"] == "delivered"
                    and receipt["origin"]["embodiment_id"]
                    != leg["receipt_origin_embodiment_id"]
                ):
                    raise CommunicationError("receipt_origin_mismatch")
                existing = database.execute(
                    "SELECT receipt_event_id, receipt_hash, outcome, receipt_json "
                    "FROM communication_receipts WHERE leg_id=?",
                    (leg["leg_id"],),
                ).fetchone()
                raw_projection = canonical_bytes(
                    {
                        "schema": SEMANTIC_RECEIPT_SCHEMA,
                        "leg_id": leg["leg_id"],
                        "receipt_event_id": receipt_event_id,
                        "receipt_hash": receipt["content_hash"],
                        "outcome": payload["outcome"],
                    }
                )
                if existing is not None:
                    if (
                        existing["receipt_event_id"] == receipt_event_id
                        and existing["receipt_hash"] == receipt["content_hash"]
                        and bytes(existing["receipt_json"]) == raw_projection
                    ):
                        database.commit()
                        return self._result(database, str(payload["message_id"]))
                    evidence = {
                        "schema": "dm.communication.conflict/v1",
                        "lane": "terminal-receipt",
                        "leg_id": leg["leg_id"],
                        "existing_receipt_event_id": existing["receipt_event_id"],
                        "existing_receipt_hash": existing["receipt_hash"],
                        "existing_outcome": existing["outcome"],
                        "presented_receipt_event_id": receipt_event_id,
                        "presented_receipt_hash": receipt["content_hash"],
                        "presented_outcome": payload["outcome"],
                    }
                    self._quarantine(database, str(leg["leg_id"]), evidence)
                    self._arm_commit(database)
                    committed_conflict = True
                    raise CommunicationError("terminal_receipt_conflict")
                if leg["state"] == "quarantined":
                    raise CommunicationError("semantic_leg_quarantined")
                database.execute(
                    "INSERT INTO communication_receipts VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        leg["leg_id"],
                        receipt_event_id,
                        receipt["content_hash"],
                        payload["outcome"],
                        raw_projection,
                        self.clock(),
                    ),
                )
                database.execute(
                    "UPDATE communication_legs SET state=?, "
                    "terminal_receipt_event_id=?, terminal_receipt_hash=? "
                    "WHERE leg_id=?",
                    (
                        payload["outcome"],
                        receipt_event_id,
                        receipt["content_hash"],
                        leg["leg_id"],
                    ),
                )
                result = self._result(database, str(payload["message_id"]))
                self._arm_commit(database)
                return result
            except CommunicationError:
                if not committed_conflict:
                    database.rollback()
                raise
            except BaseException:
                database.rollback()
                raise

    @staticmethod
    def _cursor_token(value: Any) -> str:
        if not isinstance(value, str) or not value.startswith(_CURSOR_PREFIX):
            raise CommunicationError("cursor_rejected")
        try:
            unb64url(value.removeprefix(_CURSOR_PREFIX), length=32)
        except CanonicalError as exception:
            raise CommunicationError("cursor_rejected") from exception
        return value

    def page(
        self,
        *,
        recipient_id: str,
        consumer_id: str,
        request_id: str,
        cursor: str | None,
        limit: int = 100,
    ) -> dict[str, Any]:
        _text(recipient_id, "invalid_page_binding", maximum=240)
        _text(consumer_id, "invalid_page_binding", maximum=128)
        _uuid(request_id, "invalid_page_request_id")
        _uint(limit, "invalid_page_limit", minimum=1)
        if limit > MAX_PAGE_SIZE:
            raise CommunicationError("invalid_page_limit")
        if cursor is not None:
            self._cursor_token(cursor)
        request = {
            "recipient_id": recipient_id,
            "consumer_id": consumer_id,
            "request_id": request_id,
            "cursor": cursor,
            "limit": limit,
        }
        request_hash = hashlib.sha256(canonical_bytes(request)).hexdigest()
        self.initialize()
        with self._database() as database:
            database.execute("BEGIN IMMEDIATE")
            try:
                existing = database.execute(
                    "SELECT request_hash, response_json "
                    "FROM communication_page_requests "
                    "WHERE consumer_id=? AND request_id=?",
                    (consumer_id, request_id),
                ).fetchone()
                if existing is not None:
                    if existing["request_hash"] != request_hash:
                        raise CommunicationError("page_request_conflict")
                    result = json.loads(bytes(existing["response_json"]))
                    if not isinstance(result, dict):
                        raise CommunicationError("page_state_corrupt")
                    database.commit()
                    return result
                generation, _counter, highwater = self._meta(database)
                if cursor is None:
                    cutoff = highwater
                    last = 0
                else:
                    token_hash = hashlib.sha256(cursor.encode("ascii")).hexdigest()
                    token = database.execute(
                        "SELECT * FROM communication_page_cursors WHERE token_hash=?",
                        (token_hash,),
                    ).fetchone()
                    if (
                        token is None
                        or token["recipient_id"] != recipient_id
                        or token["consumer_id"] != consumer_id
                        or token["generation"] != generation
                    ):
                        raise CommunicationError("cursor_rejected")
                    cutoff = int(token["cutoff_sequence"])
                    last = int(token["last_sequence"])
                    if cutoff > highwater or last > cutoff:
                        raise CommunicationError("cursor_rejected")
                rows = database.execute(
                    "SELECT l.* FROM communication_queue q "
                    "JOIN communication_legs l ON l.leg_id=q.leg_id "
                    "WHERE q.recipient_id=? AND q.sequence>? AND q.sequence<=? "
                    "ORDER BY q.sequence LIMIT ?",
                    (recipient_id, last, cutoff, limit + 1),
                ).fetchall()
                selected = rows[:limit]
                next_cursor: str | None = None
                if len(rows) > limit:
                    raw_token = self.token_factory(32)
                    if not isinstance(raw_token, bytes) or len(raw_token) != 32:
                        raise CommunicationError("cursor_entropy_failed")
                    next_cursor = _CURSOR_PREFIX + b64url(raw_token)
                    token_hash = hashlib.sha256(next_cursor.encode("ascii")).hexdigest()
                    database.execute(
                        "INSERT INTO communication_page_cursors VALUES "
                        "(?, ?, ?, ?, ?, ?, ?)",
                        (
                            token_hash,
                            recipient_id,
                            consumer_id,
                            generation,
                            cutoff,
                            int(selected[-1]["sequence"]),
                            self.clock(),
                        ),
                    )
                result = {
                    "schema": PAGE_SCHEMA,
                    "recipient_id": recipient_id,
                    "consumer_id": consumer_id,
                    "generation": generation,
                    "snapshot_highwater": cutoff,
                    "items": [_row_document(row) for row in selected],
                    "next_cursor": next_cursor,
                }
                database.execute(
                    "INSERT INTO communication_page_requests VALUES (?, ?, ?, ?)",
                    (consumer_id, request_id, request_hash, canonical_bytes(result)),
                )
                self._arm_commit(database)
                return result
            except BaseException:
                database.rollback()
                raise

    def advance_consumer(
        self, *, recipient_id: str, consumer_id: str, sequence: int
    ) -> dict[str, Any]:
        _text(recipient_id, "invalid_consumer_binding", maximum=240)
        _text(consumer_id, "invalid_consumer_binding", maximum=128)
        _uint(sequence, "invalid_consumer_sequence")
        self.initialize()
        with self._database() as database:
            database.execute("BEGIN IMMEDIATE")
            try:
                generation, _counter, highwater = self._meta(database)
                if sequence > highwater:
                    raise CommunicationError("cursor_beyond_highwater")
                row = database.execute(
                    "SELECT generation, sequence FROM communication_consumers "
                    "WHERE recipient_id=? AND consumer_id=?",
                    (recipient_id, consumer_id),
                ).fetchone()
                current = 0 if row is None else int(row["sequence"])
                if row is not None and row["generation"] != generation:
                    raise CommunicationError("consumer_generation_mismatch")
                if sequence < current:
                    raise CommunicationError("consumer_cursor_regression")
                if sequence == current:
                    database.commit()
                    return {
                        "recipient_id": recipient_id,
                        "consumer_id": consumer_id,
                        "generation": generation,
                        "sequence": current,
                    }
                terminal = tuple(sorted(TERMINAL_OUTCOMES))
                target = database.execute(
                    "SELECT l.state FROM communication_queue q "
                    "JOIN communication_legs l ON l.leg_id=q.leg_id "
                    "WHERE q.recipient_id=? AND q.sequence=?",
                    (recipient_id, sequence),
                ).fetchone()
                if target is None:
                    raise CommunicationError("consumer_target_not_owned")
                pending = database.execute(
                    "SELECT q.sequence FROM communication_queue q "
                    "JOIN communication_legs l ON l.leg_id=q.leg_id "
                    "WHERE q.recipient_id=? AND q.sequence>? AND q.sequence<=? "
                    f"AND l.state NOT IN ({','.join('?' for _ in terminal)}) "
                    "ORDER BY q.sequence LIMIT 1",
                    (recipient_id, current, sequence, *terminal),
                ).fetchone()
                if pending is not None:
                    raise CommunicationError("consumer_prefix_not_terminal")
                database.execute(
                    "INSERT INTO communication_consumers VALUES (?, ?, ?, ?) "
                    "ON CONFLICT(recipient_id, consumer_id) "
                    "DO UPDATE SET sequence=excluded.sequence",
                    (recipient_id, consumer_id, generation, sequence),
                )
                self._arm_commit(database)
                return {
                    "recipient_id": recipient_id,
                    "consumer_id": consumer_id,
                    "generation": generation,
                    "sequence": sequence,
                }
            except BaseException:
                database.rollback()
                raise

    def claim(
        self,
        *,
        recipient_id: str,
        consumer_id: str,
        claim_id: str,
        limit: int,
        lease_until_ms: int,
    ) -> dict[str, Any]:
        """Lease accepted queue rows without advancing durable progress."""

        _text(recipient_id, "invalid_claim_binding", maximum=240)
        _text(consumer_id, "invalid_claim_binding", maximum=128)
        _uuid(claim_id, "invalid_claim_id")
        _uint(limit, "invalid_claim_limit", minimum=1)
        if limit > MAX_PAGE_SIZE:
            raise CommunicationError("invalid_claim_limit")
        _uint(lease_until_ms, "invalid_claim_lease")
        now = self.clock()
        if not now < lease_until_ms <= now + 86_400_000:
            raise CommunicationError("invalid_claim_lease")
        request = {
            "recipient_id": recipient_id,
            "consumer_id": consumer_id,
            "claim_id": claim_id,
            "limit": limit,
            "lease_until_ms": lease_until_ms,
        }
        request_hash = hashlib.sha256(canonical_bytes(request)).hexdigest()
        self.initialize()
        with self._database() as database:
            database.execute("BEGIN IMMEDIATE")
            try:
                existing = database.execute(
                    "SELECT request_hash, response_json "
                    "FROM communication_claim_batches WHERE claim_id=?",
                    (claim_id,),
                ).fetchone()
                if existing is not None:
                    if existing["request_hash"] != request_hash:
                        raise CommunicationError("claim_id_conflict")
                    result = json.loads(bytes(existing["response_json"]))
                    if not isinstance(result, dict):
                        raise CommunicationError("claim_state_corrupt")
                    database.commit()
                    return result
                rows = database.execute(
                    "SELECT l.* FROM communication_queue q "
                    "JOIN communication_legs l ON l.leg_id=q.leg_id "
                    "LEFT JOIN communication_claim_rows c "
                    "ON c.recipient_id=q.recipient_id AND c.sequence=q.sequence "
                    "AND c.lease_until_ms>? "
                    "WHERE q.recipient_id=? AND l.state='accepted' "
                    "AND c.claim_id IS NULL ORDER BY q.sequence LIMIT ?",
                    (now, recipient_id, limit),
                ).fetchall()
                result = {
                    "schema": "dm.communication.claim/v1",
                    "claim_id": claim_id,
                    "recipient_id": recipient_id,
                    "consumer_id": consumer_id,
                    "lease_until_ms": lease_until_ms,
                    "items": [_row_document(row) for row in rows],
                }
                database.execute(
                    "INSERT INTO communication_claim_batches VALUES (?, ?, ?)",
                    (claim_id, request_hash, canonical_bytes(result)),
                )
                for row in rows:
                    database.execute(
                        "INSERT INTO communication_claim_rows VALUES (?, ?, ?, ?, ?) "
                        "ON CONFLICT(recipient_id, sequence) DO UPDATE SET "
                        "claim_id=excluded.claim_id, "
                        "consumer_id=excluded.consumer_id, "
                        "lease_until_ms=excluded.lease_until_ms "
                        "WHERE communication_claim_rows.lease_until_ms<=?",
                        (
                            recipient_id,
                            int(row["sequence"]),
                            claim_id,
                            consumer_id,
                            lease_until_ms,
                            now,
                        ),
                    )
                self._arm_commit(database)
                return result
            except BaseException:
                database.rollback()
                raise

    def compact(self, *, recipient_id: str, through_sequence: int) -> dict[str, Any]:
        """Delete only terminal queue projections; canonical receipts remain."""

        _text(recipient_id, "invalid_compaction_binding", maximum=240)
        _uint(through_sequence, "invalid_compaction_sequence")
        self.initialize()
        with self._database() as database:
            database.execute("BEGIN IMMEDIATE")
            try:
                cursors = database.execute(
                    "SELECT sequence FROM communication_consumers WHERE recipient_id=?",
                    (recipient_id,),
                ).fetchall()
                if (
                    not cursors
                    or min(int(row["sequence"]) for row in cursors) < through_sequence
                ):
                    raise CommunicationError("compaction_cursor_not_advanced")
                terminal = tuple(sorted(TERMINAL_OUTCOMES))
                pending = database.execute(
                    "SELECT q.sequence FROM communication_queue q "
                    "JOIN communication_legs l ON l.leg_id=q.leg_id "
                    "WHERE q.recipient_id=? AND q.sequence<=? "
                    f"AND l.state NOT IN ({','.join('?' for _ in terminal)}) LIMIT 1",
                    (recipient_id, through_sequence, *terminal),
                ).fetchone()
                if pending is not None:
                    raise CommunicationError("compaction_prefix_not_terminal")
                count = database.execute(
                    "DELETE FROM communication_queue WHERE recipient_id=? "
                    "AND sequence<=?",
                    (recipient_id, through_sequence),
                ).rowcount
                self._arm_commit(database)
                return {
                    "recipient_id": recipient_id,
                    "through_sequence": through_sequence,
                    "removed": count,
                }
            except BaseException:
                database.rollback()
                raise

    def conflicts(self) -> list[dict[str, Any]]:
        self.initialize()
        with self._database() as database:
            rows = database.execute(
                "SELECT conflict_hash, leg_id, lane, evidence_json, detected_at_ms "
                "FROM communication_conflicts ORDER BY detected_at_ms, conflict_hash"
            ).fetchall()
            return [
                {
                    "conflict_hash": str(row["conflict_hash"]),
                    "leg_id": str(row["leg_id"]),
                    "lane": str(row["lane"]),
                    "evidence": json.loads(bytes(row["evidence_json"])),
                    "detected_at_ms": int(row["detected_at_ms"]),
                }
                for row in rows
            ]


def dispatch_attempt(
    store: CommunicationStore,
    provider: RouteProvider,
    attempt: Mapping[str, Any],
) -> Mapping[str, Any]:
    """Exercise a provider without allowing it to mutate semantic authority."""

    accepted = store.record_attempt(attempt)
    if accepted["provider_ref"] != provider.provider_ref:
        raise CommunicationError("route_provider_mismatch")
    try:
        ack = provider.deliver(copy.deepcopy(dict(attempt)))
    except Exception as exception:
        # A lost provider response is effect-ambiguous.  Preserve the stable
        # accepted attempt for idempotent retry; only an explicit provider ACK
        # may classify the attempt as accepted or failed.
        raise CommunicationError("route_result_unknown", retryable=True) from exception
    return store.record_route_ack(
        attempt_id=str(attempt["attempt_id"]), ack=ack, failed=False
    )


__all__ = [
    "ATTEMPT_STATES",
    "LOGICAL_MESSAGE_SCHEMA",
    "MAX_PAGE_SIZE",
    "MESSAGE_PAYLOAD_SCHEMA",
    "PAGE_SCHEMA",
    "RECEIPT_PAYLOAD_SCHEMA",
    "RECIPIENT_TYPES",
    "RESOLUTION_PAYLOAD_SCHEMA",
    "RESULT_SCHEMA",
    "ROUTE_ATTEMPT_SCHEMA",
    "SCOPE_KINDS",
    "SEMANTIC_LEG_SCHEMA",
    "SEMANTIC_RECEIPT_SCHEMA",
    "TERMINAL_OUTCOMES",
    "CommunicationError",
    "CommunicationStore",
    "RouteProvider",
    "dispatch_attempt",
]
