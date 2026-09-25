"""Canonical logical communication projections above disposable routes.

DM-052 deliberately stores its projections in the same SQLite database as the
DM-023 ledger.  Signed ``dm.we.v1`` events remain the authority; every table in
this module is local projection or explicitly retained delivery evidence. V2
foreign receipt proofs cannot be reconstructed from the local Ledger alone.
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
from pathlib import Path
from typing import Any, Final

from .canonical import CanonicalError, b64url, canonical_bytes, unb64url
from .ledger import Ledger, LedgerStateError
from .native_egress import MandatoryEgressController, OperationBinding
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
RECEIPTS_V2_SCHEMA_VERSION: Final = 2
# One semantic leg per receiving body rather than per member. Gated so a store
# that never opts in keeps its delivered identity derivation and its schema.
LEGS_V3_SCHEMA_VERSION: Final = 3
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


@dataclass(frozen=True, slots=True)
class SyntheticRouteProvider:
    """Explicit side-effect-free provider for isolated communication-store tests."""

    provider_ref: str

    def deliver(self, attempt: Mapping[str, Any]) -> Mapping[str, Any]:
        return {
            "schema": "dm.route-ack/v1",
            "provider_ref": self.provider_ref,
            "attempt_id": str(attempt["attempt_id"]),
            "status": "accepted",
        }


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
    seen: set[tuple[str, str, str]] = set()
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
        # One semantic recipient may legitimately be received by several bodies,
        # each authoring its own receipt, so the author is part of what makes a
        # target a duplicate. Whether a given store can hold several legs for one
        # recipient is that store's own capability and is checked on admission;
        # the resolution format is not the place to refuse it.
        key = (
            str(recipient_type),
            recipient_id,
            _text(
                target["receipt_origin_embodiment_id"],
                "invalid_resolution_target",
                maximum=240,
            ),
        )
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


def _foreign_receipt_payload(event: Mapping[str, Any]) -> Mapping[str, Any]:
    """V2 uses foreign references, never foreign canonical dependencies."""
    error = "invalid_foreign_receipt"
    if (
        event["kind"] != "experience.observed"
        or event["subject"] != "communication-receipt"
    ):
        raise CommunicationError(error)
    payload = _closed(
        event["payload"],
        {
            "schema",
            "message_being_ref",
            "message_ref",
            "resolution_ref",
            "thread_id",
            "recipient_type",
            "recipient_id",
            "outcome",
            "observed_at_ms",
        },
        error,
    )
    if (
        payload["schema"] != "dm.communication.receipt/v2"
        or payload["recipient_type"] != "relationship"
        or payload["outcome"] != "delivered"
    ):
        raise CommunicationError(error)
    for name in ("message_ref", "resolution_ref"):
        ref = _closed(payload[name], {"event_id", "event_hash"}, error)
        _uuid(ref["event_id"], error)
        _hash(ref["event_hash"], error)
        if ref["event_id"] in event["causal_parents"]:
            raise CommunicationError("foreign_receipt_causal_parent")
    _text(payload["message_being_ref"], error)
    _text(payload["recipient_id"], error, maximum=240)
    _uuid(payload["thread_id"], error)
    if _uint(payload["observed_at_ms"], error) != event["occurred_at_ms"]:
        raise CommunicationError(error)
    return payload


def _leg_id(
    message_id: str,
    recipient_type: str,
    recipient_id: str,
    receipt_origin_embodiment_id: str | None = None,
) -> str:
    """Derive one semantic leg identity.

    Without a receipt author this is exactly the delivered derivation, so a store
    that has not opted into per-body legs reproduces its existing identities
    byte for byte. With one, two bodies of a single membership get two legs
    instead of colliding on it, which is what lets every embodiment of a member
    receive and receipt a tribe message in its own name.
    """
    preimage = {
        "message_id": message_id,
        "recipient_id": recipient_id,
        "recipient_type": recipient_type,
        "schema": "dm.semantic-key/v1",
    }
    if receipt_origin_embodiment_id is not None:
        preimage["receipt_origin_embodiment_id"] = receipt_origin_embodiment_id
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
        foreign_authority_resolver: Callable[[str], EventAuthority] | None = None,
        receipts_v2: bool = False,
        legs_v3: bool = False,
    ) -> None:
        if legs_v3 and not receipts_v2:
            raise CommunicationError("legs_v3_requires_receipts_v2")
        self.ledger = ledger
        self.foreign_authority_resolver = foreign_authority_resolver
        self.receipts_v2 = receipts_v2
        self.legs_v3 = legs_v3
        self.clock = clock
        self.uuid_factory = uuid_factory
        self.token_factory = token_factory
        self._egress: MandatoryEgressController | None = None
        self._egress_catalog: str | None = None
        self._egress_authorizers: list[Callable[[OperationBinding], bool]] = []
        self.anchor_path = ledger.path.with_name(
            ledger.path.name + ".communication-anchor.json"
        )

    @contextmanager
    def _database(self) -> Iterator[sqlite3.Connection]:
        with self.ledger._database() as database:
            yield database

    def bind_egress(
        self,
        controller: MandatoryEgressController,
        *,
        catalog_id: str,
        authorize: Callable[[OperationBinding], bool],
    ) -> None:
        if self._egress is not None:
            if self._egress is not controller or self._egress_catalog != catalog_id:
                raise CommunicationError("communication_egress_already_bound")
            self._egress_authorizers.append(authorize)
            return
        self.initialize()
        self._egress = controller
        self._egress_catalog = catalog_id
        self._egress_authorizers.append(authorize)
        controller.register_catalog(
            catalog_id=catalog_id,
            path=self.ledger.path,
            resolve=self._resolve_egress,
            authorize=self._authorize_bound_egress,
        )
        controller.register_path("route-provider-request", catalog_id)

    def _authorize_bound_egress(self, binding: OperationBinding) -> bool:
        return any(authorize(binding) for authorize in self._egress_authorizers)

    def _resolve_egress(self, locator: str) -> bytes:
        with self._database() as database:
            row = database.execute(
                "SELECT request FROM communication_egress_requests WHERE attempt_id=?",
                (locator,),
            ).fetchone()
        if row is None:
            raise CommunicationError("communication_egress_missing")
        return bytes(row[0])

    def egress_attempt(self, attempt_id: str) -> dict[str, str]:
        with self._database() as database:
            row = database.execute(
                "SELECT provider_ref, route_ref FROM communication_attempts "
                "WHERE attempt_id=?",
                (attempt_id,),
            ).fetchone()
        if row is None:
            raise CommunicationError("route_attempt_not_known")
        return {"provider_ref": str(row[0]), "route_ref": str(row[1])}

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

    def _expected_schema_version(self) -> int:
        """The one schema version this store's declared capabilities imply."""
        if self.legs_v3:
            return LEGS_V3_SCHEMA_VERSION
        if self.receipts_v2:
            return RECEIPTS_V2_SCHEMA_VERSION
        return STORE_SCHEMA_VERSION

    def _meta(self, database: sqlite3.Connection) -> tuple[str, int, int]:
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
        } or rows["schema_version"] != str(self._expected_schema_version()):
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
                if self.receipts_v2:
                    foreign = database.execute(
                        "SELECT sql FROM sqlite_schema "
                        "WHERE name='communication_foreign_receipts' AND type='table'"
                    ).fetchone()
                    if foreign is None:
                        raise CommunicationError("foreign_receipt_store_missing")
                    compactions = database.execute(
                        "SELECT sql FROM sqlite_schema "
                        "WHERE name='communication_compactions' AND type='table'"
                    ).fetchone()
                    if compactions is None:
                        raise CommunicationError(
                            "communication_compaction_store_missing"
                        )
                    self._recover_pending(database)
                    generation, counter, _ = self._meta(database)
                    if self._anchor() != (generation, counter):
                        raise CommunicationError("communication_state_rollback")
                    database.commit()
                    return
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
                    CREATE TABLE IF NOT EXISTS communication_egress_requests (
                        attempt_id TEXT PRIMARY KEY
                            REFERENCES communication_attempts(attempt_id)
                            ON DELETE RESTRICT,
                        request BLOB NOT NULL,
                        request_sha256 TEXT NOT NULL
                    ) WITHOUT ROWID;
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

    @staticmethod
    def _projection_hash(database: sqlite3.Connection) -> str:
        """Exact logical projection snapshot, including catalogs and proof bytes."""
        snapshot = []
        for name, sql in database.execute(
            "SELECT name, sql FROM sqlite_schema WHERE type='table' ORDER BY name"
        ):
            if not name.startswith("communication_"):
                continue
            quoted = '"' + name.replace('"', '""') + '"'
            rows = sorted(
                canonical_bytes(
                    [
                        {"bytes": b64url(cell)} if isinstance(cell, bytes) else cell
                        for cell in row
                    ]
                )
                for row in database.execute("SELECT * FROM " + quoted)
            )
            snapshot.append([name, sql, [b64url(row) for row in rows]])
        return hashlib.sha256(canonical_bytes(snapshot)).hexdigest()

    def _pending_path(self) -> Path:
        return self.anchor_path.with_name(self.anchor_path.name + ".pending")

    def _pending_write(self, value: Mapping[str, Any]) -> None:
        path = self._pending_path()
        temporary = path.with_name(path.name + "." + str(self.uuid_factory()) + ".tmp")
        fd = os.open(
            temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
        )
        try:
            raw = canonical_bytes(value)
            view = memoryview(raw)
            while view:
                written = os.write(fd, view)
                if not written:
                    raise OSError("communication_pending_write_failed")
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
        try:
            os.link(temporary, path, follow_symlinks=False)
        finally:
            temporary.unlink()
        self._sync_anchor_directory()

    def _sync_anchor_directory(self) -> None:
        fd = os.open(self.anchor_path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def _pending_remove(self) -> None:
        self._pending_path().unlink()
        self._sync_anchor_directory()

    def _recover_pending(self, database: sqlite3.Connection) -> None:
        path = self._pending_path()
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            return
        try:
            info = os.fstat(fd)
            if info.st_nlink == 2:
                # Crash between atomic no-replace link and staging unlink.
                aliases = [
                    candidate
                    for candidate in path.parent.glob(path.name + ".*.tmp")
                    if candidate.lstat().st_ino == info.st_ino
                    and candidate.lstat().st_dev == info.st_dev
                ]
                if len(aliases) == 1:
                    aliases[0].unlink()
                    self._sync_anchor_directory()
                    info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or info.st_mode & 0o077
                or info.st_nlink != 1
                or info.st_size > 4096
            ):
                raise CommunicationError("communication_pending_invalid")
            raw = os.read(fd, 4097)
        finally:
            os.close(fd)
        value = _closed(
            json.loads(raw),
            {
                "schema",
                "generation",
                "before_counter",
                "after_counter",
                "before_hash",
                "after_hash",
            },
            "communication_pending_invalid",
        )
        before = _uint(value["before_counter"], "communication_pending_invalid")
        after = _uint(value["after_counter"], "communication_pending_invalid")
        if (
            canonical_bytes(value) != raw
            or value["schema"] != "dm.communication.pending/v2"
            or after != before + 1
        ):
            raise CommunicationError("communication_pending_invalid")
        for field in ("before_hash", "after_hash"):
            _hash(value[field], "communication_pending_invalid")
        generation, counter, _ = self._meta(database)
        if generation != value["generation"] or self._anchor() not in {
            (generation, before),
            (generation, after),
        }:
            raise CommunicationError("communication_state_rollback")
        digest = self._projection_hash(database)
        if not (
            (counter == before and digest == value["before_hash"])
            or (counter == after and digest == value["after_hash"])
        ):
            raise CommunicationError("communication_state_rollback")
        # Only an exact journal-bound pre/post state can repair the anchor.
        # Uncommitted work is retried from retained intake/outbox, never invented.
        self._write_anchor(generation, counter)
        self._pending_remove()

    def _arm_commit(self, database: sqlite3.Connection) -> None:
        generation, counter, _highwater = self._meta(database)
        next_counter = counter + 1
        if self.receipts_v2:
            # Cursor/compaction mutations must not turn a forged terminal flag
            # into consumed progress. Revalidate proofs before arming any commit.
            self._validate_store(database)
            previous = sqlite3.connect(self.ledger.path.as_uri() + "?mode=ro", uri=True)
            try:
                before_hash = self._projection_hash(previous)
            finally:
                previous.close()
            database.execute(
                "UPDATE communication_meta SET value=? WHERE key='mutation_counter'",
                (str(next_counter),),
            )
            self._pending_write(
                {
                    "schema": "dm.communication.pending/v2",
                    "generation": generation,
                    "before_counter": counter,
                    "after_counter": next_counter,
                    "before_hash": before_hash,
                    "after_hash": self._projection_hash(database),
                }
            )
            self._write_anchor(generation, next_counter)
            database.commit()
            self._pending_remove()
            return
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
                self._validate_store(database)
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
                if not self.legs_v3:
                    seen_recipients: set[tuple[str, str]] = set()
                    for target in targets:
                        pair = (
                            str(target["recipient_type"]),
                            str(target["recipient_id"]),
                        )
                        if pair in seen_recipients:
                            # Refuse here rather than let the delivered UNIQUE
                            # constraint escape as a database integrity error.
                            raise CommunicationError("duplicate_semantic_recipient")
                        seen_recipients.add(pair)
                for target in targets:
                    recipient_type = str(target["recipient_type"])
                    recipient_id = str(target["recipient_id"])
                    receipt_origin = str(target["receipt_origin_embodiment_id"])
                    leg_id = _leg_id(
                        message_event_id,
                        recipient_type,
                        recipient_id,
                        receipt_origin if self.legs_v3 else None,
                    )
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
                        "WHERE message_id=? AND recipient_type=? AND recipient_id=?"
                        + (
                            " AND receipt_origin_embodiment_id=?"
                            if self.legs_v3
                            else ""
                        ),
                        (message_event_id, recipient_type, recipient_id, receipt_origin)
                        if self.legs_v3
                        else (message_event_id, recipient_type, recipient_id),
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

    def _validate_vector(
        self, database: sqlite3.Connection, stored: sqlite3.Row, rows: list[sqlite3.Row]
    ) -> None:
        """Validate the complete projection, not just legs retaining a receipt.

        Use the caller's transaction: Ledger/public store entrypoints would open
        another SQLite connection and can deadlock a write transaction.
        """
        message = _event(
            self._known_event(database, stored["message_id"]), self.ledger.authority
        )
        payload = _message_payload(message)
        resolution = _event(
            self._known_event(database, stored["resolution_event_id"]),
            self.ledger.authority,
        )
        _, targets = _resolution_payload(
            resolution, message_id=message["event_id"], scope=payload["intent"]["scope"]
        )
        projection = MessageProjection(
            message["event_id"],
            message["content_hash"],
            payload["intent"]["thread_id"],
            message["origin"],
            payload["intent"],
            resolution["event_id"],
            resolution["content_hash"],
        )
        if (
            stored["message_id"] != message["event_id"]
            or stored["thread_id"] != projection.thread_id
            or stored["event_hash"] != message["content_hash"]
            or stored["resolution_event_id"] != resolution["event_id"]
            or stored["resolution_hash"] != resolution["content_hash"]
            or bytes(stored["author_json"]) != canonical_bytes(message["origin"])
            or bytes(stored["intent_json"]) != canonical_bytes(payload["intent"])
            or bytes(stored["message_json"]) != canonical_bytes(projection.as_dict())
        ):
            raise CommunicationError("message_projection_corrupt")
        expected = {}
        for target in targets:
            identifier = _leg_id(
                message["event_id"],
                target["recipient_type"],
                target["recipient_id"],
                str(target["receipt_origin_embodiment_id"]) if self.legs_v3 else None,
            )
            expected[identifier] = {
                "message_id": message["event_id"],
                "thread_id": projection.thread_id,
                "recipient_type": target["recipient_type"],
                "recipient_id": target["recipient_id"],
                "receipt_origin_embodiment_id": target["receipt_origin_embodiment_id"],
                "resolution_event_id": resolution["event_id"],
                "resolution_hash": resolution["content_hash"],
                "evidence_cursor": target["evidence_cursor"],
            }
        if len(rows) != len(expected) or {row["leg_id"] for row in rows} != set(
            expected
        ):
            raise CommunicationError("semantic_vector_corrupt")
        for row in rows:
            immutable = expected[row["leg_id"]]
            if (
                any(row[key] != value for key, value in immutable.items())
                or row["immutable_hash"]
                != hashlib.sha256(canonical_bytes(immutable)).hexdigest()
            ):
                raise CommunicationError("foreign_receipt_binding_mismatch")

    @staticmethod
    def _bind_local_receipt(receipt: Event, leg: sqlite3.Row) -> Mapping[str, Any]:
        """Apply the same V1 applicability rules on admission and V2 replay."""
        payload = _receipt_payload(receipt)
        if any(
            payload[key] != leg[key]
            for key in ("message_id", "thread_id", "recipient_type", "recipient_id")
        ):
            raise CommunicationError("receipt_binding_mismatch")
        if (
            payload["outcome"] == "delivered"
            and receipt["origin"]["embodiment_id"]
            != leg["receipt_origin_embodiment_id"]
        ):
            raise CommunicationError("receipt_origin_mismatch")
        return payload

    @staticmethod
    def _validate_consumer_position(
        database: sqlite3.Connection,
        *,
        recipient_id: str,
        sequence: int,
    ) -> None:
        terminal = tuple(sorted(TERMINAL_OUTCOMES))
        target = database.execute(
            "SELECT state FROM communication_legs WHERE recipient_id=? AND sequence=?",
            (recipient_id, sequence),
        ).fetchone()
        if target is None:
            raise CommunicationError("consumer_target_not_owned")
        pending = database.execute(
            "SELECT sequence FROM communication_legs "
            "WHERE recipient_id=? AND sequence<=? "
            f"AND state NOT IN ({','.join('?' for _ in terminal)}) "
            "ORDER BY sequence LIMIT 1",
            (recipient_id, sequence, *terminal),
        ).fetchone()
        if pending is not None:
            raise CommunicationError("consumer_prefix_not_terminal")

    def _validate_queue(self, database: sqlite3.Connection) -> None:
        generation, _counter, highwater = self._meta(database)
        terminal = tuple(sorted(TERMINAL_OUTCOMES))
        compactions: dict[str, int] = {}
        for row in database.execute(
            "SELECT * FROM communication_compactions"
        ).fetchall():
            recipient_id = _text(
                row["recipient_id"],
                "communication_compaction_evidence_corrupt",
                maximum=240,
            )
            through = _uint(
                row["through_sequence"], "communication_compaction_evidence_corrupt"
            )
            if row["generation"] != generation or through > highwater:
                raise CommunicationError("communication_compaction_evidence_corrupt")
            pending = database.execute(
                "SELECT 1 FROM communication_legs WHERE recipient_id=? "
                "AND sequence<=? "
                f"AND state NOT IN ({','.join('?' for _ in terminal)}) LIMIT 1",
                (recipient_id, through, *terminal),
            ).fetchone()
            retained = database.execute(
                "SELECT 1 FROM communication_queue WHERE recipient_id=? "
                "AND sequence<=? LIMIT 1",
                (recipient_id, through),
            ).fetchone()
            if pending is not None or retained is not None:
                raise CommunicationError("communication_compaction_evidence_corrupt")
            compactions[recipient_id] = through

        queues: dict[str, sqlite3.Row] = {}
        for row in database.execute("SELECT * FROM communication_queue").fetchall():
            leg = database.execute(
                "SELECT * FROM communication_legs WHERE leg_id=?", (row["leg_id"],)
            ).fetchone()
            if (
                leg is None
                or row["sequence"] != leg["sequence"]
                or row["recipient_id"] != leg["recipient_id"]
            ):
                raise CommunicationError("communication_queue_binding_mismatch")
            queues[str(row["leg_id"])] = row

        for leg in database.execute("SELECT * FROM communication_legs").fetchall():
            if str(leg["leg_id"]) in queues:
                continue
            if leg["state"] not in TERMINAL_OUTCOMES:
                raise CommunicationError("communication_queue_incomplete")
            if compactions.get(str(leg["recipient_id"]), -1) < int(leg["sequence"]):
                raise CommunicationError("communication_queue_incomplete")

    def _migrate_legacy_compactions(self, database: sqlite3.Connection) -> None:
        """Infer only the contiguous V1 shape that the old compact() could create."""

        missing: dict[str, int] = {}
        for queue in database.execute("SELECT * FROM communication_queue").fetchall():
            leg = database.execute(
                "SELECT * FROM communication_legs WHERE leg_id=?", (queue["leg_id"],)
            ).fetchone()
            if (
                leg is None
                or queue["sequence"] != leg["sequence"]
                or queue["recipient_id"] != leg["recipient_id"]
            ):
                raise CommunicationError("communication_queue_binding_mismatch")
        for leg in database.execute("SELECT * FROM communication_legs").fetchall():
            queue = database.execute(
                "SELECT * FROM communication_queue WHERE leg_id=?", (leg["leg_id"],)
            ).fetchone()
            if queue is not None:
                if (
                    queue["sequence"] != leg["sequence"]
                    or queue["recipient_id"] != leg["recipient_id"]
                ):
                    raise CommunicationError("communication_queue_binding_mismatch")
                continue
            if leg["state"] not in TERMINAL_OUTCOMES:
                raise CommunicationError("communication_queue_incomplete")
            recipient = str(leg["recipient_id"])
            missing[recipient] = max(missing.get(recipient, 0), int(leg["sequence"]))

        generation, _counter, _highwater = self._meta(database)
        terminal = tuple(sorted(TERMINAL_OUTCOMES))
        for recipient_id, through in missing.items():
            consumers = database.execute(
                "SELECT sequence FROM communication_consumers WHERE recipient_id=?",
                (recipient_id,),
            ).fetchall()
            for consumer in consumers:
                self._validate_consumer_position(
                    database,
                    recipient_id=recipient_id,
                    sequence=_uint(consumer["sequence"], "invalid_consumer_sequence"),
                )
            pending = database.execute(
                "SELECT 1 FROM communication_legs WHERE recipient_id=? "
                "AND sequence<=? "
                f"AND state NOT IN ({','.join('?' for _ in terminal)}) LIMIT 1",
                (recipient_id, through, *terminal),
            ).fetchone()
            retained = database.execute(
                "SELECT 1 FROM communication_queue WHERE recipient_id=? "
                "AND sequence<=? LIMIT 1",
                (recipient_id, through),
            ).fetchone()
            if (
                not consumers
                or min(int(row["sequence"]) for row in consumers) < through
                or pending is not None
                or retained is not None
            ):
                raise CommunicationError("communication_queue_incomplete")
            database.execute(
                "INSERT INTO communication_compactions VALUES (?, ?, ?)",
                (recipient_id, generation, through),
            )

    def _validate_consumers(self, database: sqlite3.Connection) -> None:
        generation, _counter, highwater = self._meta(database)
        for row in database.execute("SELECT * FROM communication_consumers").fetchall():
            recipient_id = _text(
                row["recipient_id"], "invalid_consumer_binding", maximum=240
            )
            _text(row["consumer_id"], "invalid_consumer_binding", maximum=128)
            sequence = _uint(row["sequence"], "invalid_consumer_sequence")
            if row["generation"] != generation:
                raise CommunicationError("consumer_generation_mismatch")
            if sequence > highwater:
                raise CommunicationError("cursor_beyond_highwater")
            self._validate_consumer_position(
                database, recipient_id=recipient_id, sequence=sequence
            )

    def _validate_store(self, database: sqlite3.Connection) -> None:
        if self.receipts_v2:
            for (message_id,) in database.execute(
                "SELECT message_id FROM communication_messages UNION "
                "SELECT message_id FROM communication_legs"
            ).fetchall():
                self._result(database, message_id)
            for row in database.execute(
                "SELECT * FROM communication_attempts"
            ).fetchall():
                raw = bytes(row["attempt_json"])
                attempt = self._attempt_document(json.loads(raw))
                if (
                    canonical_bytes(attempt) != raw
                    or hashlib.sha256(raw).hexdigest() != row["attempt_hash"]
                    or any(
                        row[key] != value
                        for key, value in attempt.items()
                        if key != "schema"
                    )
                    or row["state"] not in ATTEMPT_STATES
                    or (row["state"] == "accepted") != (row["ack_hash"] is None)
                ):
                    raise CommunicationError("route_attempt_store_corrupt")
                if row["ack_hash"] is not None:
                    _hash(row["ack_hash"], "route_attempt_store_corrupt")
            self._validate_consumers(database)
            self._validate_queue(database)

    def _validate_snapshot(
        self,
        database: sqlite3.Connection,
        result: dict[str, Any],
        request: Mapping[str, Any],
        *,
        claim: bool = False,
    ) -> None:
        """Keep historical state, but never synthesize evidence from cached JSON.

        Accepted snapshots remain accepted after delivery or compaction. A
        terminal snapshot must still name the retained, reverified receipt;
        replay does not renew a claim or authorize another route attempt.
        """
        if not self.receipts_v2:
            return
        error = "claim_state_corrupt" if claim else "page_state_corrupt"
        fields = (
            {
                "schema",
                "claim_id",
                "recipient_id",
                "consumer_id",
                "lease_until_ms",
                "items",
            }
            if claim
            else {
                "schema",
                "recipient_id",
                "consumer_id",
                "generation",
                "snapshot_highwater",
                "items",
                "next_cursor",
            }
        )
        _closed(result, fields, error)
        binding = (
            ("recipient_id", "consumer_id", "claim_id", "lease_until_ms")
            if claim
            else ("recipient_id", "consumer_id")
        )
        if any(result[key] != request[key] for key in binding) or result["schema"] != (
            "dm.communication.claim/v1" if claim else PAGE_SCHEMA
        ):
            raise CommunicationError(error)
        items = result["items"]
        if not isinstance(items, list) or len(items) > request["limit"]:
            raise CommunicationError(error)
        generation, _, highwater = self._meta(database)
        last = 0
        cutoff = highwater
        if not claim:
            cutoff = _uint(result["snapshot_highwater"], error)
            if result["generation"] != generation or cutoff > highwater:
                raise CommunicationError(error)
            if request["cursor"] is not None:
                token = database.execute(
                    "SELECT * FROM communication_page_cursors WHERE token_hash=?",
                    (hashlib.sha256(request["cursor"].encode("ascii")).hexdigest(),),
                ).fetchone()
                if (
                    token is None
                    or any(
                        token[key] != result[key]
                        for key in ("recipient_id", "consumer_id", "generation")
                    )
                    or token["cutoff_sequence"] != cutoff
                ):
                    raise CommunicationError(error)
                last = _uint(token["last_sequence"], error)
        for item in items:
            if not isinstance(item, dict) or not isinstance(item.get("leg_id"), str):
                raise CommunicationError(error)
            row = database.execute(
                "SELECT * FROM communication_legs WHERE leg_id=?", (item["leg_id"],)
            ).fetchone()
            if row is None:
                raise CommunicationError(error)
            current = _row_document(row)
            _closed(item, set(current), error)
            mutable = {"state", "terminal_receipt_event_id", "terminal_receipt_hash"}
            if (
                any(
                    item[key] != value
                    for key, value in current.items()
                    if key not in mutable
                )
                or item["recipient_id"] != request["recipient_id"]
                or not last < _uint(item["sequence"], error) <= cutoff
            ):
                raise CommunicationError(error)
            last = item["sequence"]
            if item["state"] == "accepted":
                if any(item[key] is not None for key in mutable - {"state"}):
                    raise CommunicationError(error)
            elif claim or item["state"] not in LEG_STATES:
                raise CommunicationError(error)
            elif item["state"] == "quarantined":
                if any(item[key] != current[key] for key in mutable):
                    raise CommunicationError(error)
            else:
                # Current state may have advanced from terminal to quarantine.
                if any(item[key] != current[key] for key in mutable - {"state"}):
                    raise CommunicationError(error)
                proof = database.execute(
                    "SELECT outcome FROM communication_receipts WHERE leg_id=? "
                    "UNION ALL "
                    "SELECT outcome FROM communication_foreign_receipts WHERE leg_id=?",
                    (item["leg_id"], item["leg_id"]),
                ).fetchall()
                if len(proof) != 1 or proof[0]["outcome"] != item["state"]:
                    raise CommunicationError(error)
        if not claim and result["next_cursor"] is not None:
            token_text = self._cursor_token(result["next_cursor"])
            token = database.execute(
                "SELECT * FROM communication_page_cursors WHERE token_hash=?",
                (hashlib.sha256(token_text.encode("ascii")).hexdigest(),),
            ).fetchone()
            if (
                token is None
                or not items
                or len(items) != request["limit"]
                or any(
                    token[key] != result[key]
                    for key in ("recipient_id", "consumer_id", "generation")
                )
                or token["cutoff_sequence"] != cutoff
                or token["last_sequence"] != last
            ):
                raise CommunicationError(error)

    def _result(self, database: sqlite3.Connection, message_id: str) -> dict[str, Any]:
        message = database.execute(
            "SELECT * FROM communication_messages WHERE message_id=?",
            (message_id,),
        ).fetchone()
        if message is None:
            raise CommunicationError("message_not_known")
        rows = database.execute(
            "SELECT * FROM communication_legs WHERE message_id=? "
            "ORDER BY recipient_type, recipient_id",
            (message_id,),
        ).fetchall()
        if self.receipts_v2:
            self._validate_vector(database, message, rows)
            for row in rows:
                proof = database.execute(
                    "SELECT * FROM communication_foreign_receipts WHERE leg_id=?",
                    (row["leg_id"],),
                ).fetchone()
                if proof is not None:
                    event, bound = self._validate_foreign_receipt(
                        database,
                        json.loads(bytes(proof["receipt_json"])),
                        proof["recipient_being_ref"],
                    )
                    if (
                        bound["leg_id"] != row["leg_id"]
                        or proof["receipt_event_id"] != event["event_id"]
                        or proof["receipt_hash"] != event["content_hash"]
                        or proof["outcome"] != event["payload"]["outcome"]
                        or proof["incarnation_id"] != event["origin"]["incarnation_id"]
                        or proof["sequence"] != event["sequence"]
                        or canonical_bytes(event) != bytes(proof["receipt_json"])
                        or row["terminal_receipt_event_id"] != event["event_id"]
                        or row["terminal_receipt_hash"] != event["content_hash"]
                        or row["state"] not in {"delivered", "quarantined"}
                    ):
                        raise CommunicationError("foreign_receipt_store_corrupt")
                local = database.execute(
                    "SELECT * FROM communication_receipts WHERE leg_id=?",
                    (row["leg_id"],),
                ).fetchone()
                if local is not None:
                    event = _event(
                        self._known_event(database, local["receipt_event_id"]),
                        self.ledger.authority,
                    )
                    payload = self._bind_local_receipt(event, row)
                    projection = {
                        "schema": SEMANTIC_RECEIPT_SCHEMA,
                        "leg_id": row["leg_id"],
                        "receipt_event_id": event["event_id"],
                        "receipt_hash": event["content_hash"],
                        "outcome": payload["outcome"],
                    }
                    if (
                        proof is not None
                        or local["receipt_hash"] != event["content_hash"]
                        or local["outcome"] != payload["outcome"]
                        or bytes(local["receipt_json"]) != canonical_bytes(projection)
                        or event["content_hash"] != row["terminal_receipt_hash"]
                        or event["event_id"] != row["terminal_receipt_event_id"]
                        or row["state"] not in {payload["outcome"], "quarantined"}
                    ):
                        raise CommunicationError("foreign_receipt_store_corrupt")
                elif proof is None and (
                    row["state"] in TERMINAL_OUTCOMES
                    or row["terminal_receipt_event_id"] is not None
                    or row["terminal_receipt_hash"] is not None
                ):
                    raise CommunicationError("foreign_receipt_evidence_missing")
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
            database.execute("BEGIN")
            result = self._result(database, message_id)
        if require_terminal and not result["terminal"]:
            raise CommunicationError("terminal_result_incomplete", retryable=True)
        return result

    def rebuild_plan(self, message_id: str) -> dict[str, Any]:
        """Return canonical event/evidence plus stable legs, never old ciphertext."""

        _uuid(message_id, "invalid_message_id")
        self.initialize()
        with self._database() as database:
            database.execute("BEGIN")
            if self.receipts_v2:
                self._result(database, message_id)
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

    def leg(self, leg_id: str) -> dict[str, Any]:
        """Return one canonical semantic-leg projection for route selection."""

        _text(leg_id, "invalid_leg_id", maximum=256)
        self.initialize()
        with self._database() as database:
            database.execute("BEGIN")
            row = database.execute(
                "SELECT * FROM communication_legs WHERE leg_id=?", (leg_id,)
            ).fetchone()
            if row is None:
                raise CommunicationError("semantic_leg_not_known")
            if self.receipts_v2:
                self._result(database, row["message_id"])
            return _row_document(row)

    def route_projection(
        self, *, leg_id: str, envelope: Mapping[str, Any]
    ) -> dict[str, Any]:
        """Resolve one exact immutable logical disclosure for authenticated egress."""

        _text(leg_id, "invalid_leg_id", maximum=256)
        self.initialize()
        with self._database() as database:
            database.execute("BEGIN")
            leg = database.execute(
                "SELECT * FROM communication_legs WHERE leg_id=?", (leg_id,)
            ).fetchone()
            if leg is None:
                raise CommunicationError("semantic_leg_not_known")
            stored = database.execute(
                "SELECT * FROM communication_messages WHERE message_id=?",
                (leg["message_id"],),
            ).fetchone()
            if stored is None:
                raise CommunicationError("message_not_known")
            rows = database.execute(
                "SELECT * FROM communication_legs WHERE message_id=? "
                "ORDER BY recipient_type, recipient_id",
                (leg["message_id"],),
            ).fetchall()
            self._validate_vector(database, stored, rows)
            message = _event(
                self._known_event(database, str(leg["message_id"])),
                self.ledger.authority,
            )
            payload = _message_payload(message)
            sender = envelope.get("sender")
            if (
                envelope.get("event_id") != message["event_id"]
                or envelope.get("event_hash") != message["content_hash"]
                or not isinstance(sender, Mapping)
                or sender.get("being_ref") != message["being_ref"]
                or sender.get("embodiment_id") != message["origin"]["embodiment_id"]
            ):
                raise CommunicationError("route_envelope_event_mismatch")
            body = payload["body"]
            text = body.get("text")
            if (
                not isinstance(text, str)
                or not text
                or len(text.encode("utf-8")) > 65536
            ):
                raise CommunicationError("route_logical_event_unsupported")
            recipient = str(leg["recipient_id"])
            semantic_receipt = body.get("semantic_receipt")
            if semantic_receipt is not None:
                if payload["reply"] is not None or not isinstance(
                    semantic_receipt, Mapping
                ):
                    raise CommunicationError("route_logical_event_unsupported")
                receipt_id = semantic_receipt.get("event_id")
                if not isinstance(receipt_id, str):
                    raise CommunicationError("route_logical_event_unsupported")
                receipt = _event(
                    self._known_event(database, receipt_id), self.ledger.authority
                )
                if canonical_bytes(receipt) != canonical_bytes(semantic_receipt):
                    raise CommunicationError("route_logical_event_mismatch")
                receipt_payload = _foreign_receipt_payload(receipt)
                message_ref = receipt_payload["message_ref"]
                resolution_ref = receipt_payload["resolution_ref"]
                referenced_message = _event(
                    self._known_event(database, str(message_ref["event_id"])),
                    self.ledger.authority,
                )
                referenced_resolution = _event(
                    self._known_event(database, str(resolution_ref["event_id"])),
                    self.ledger.authority,
                )
                if (
                    referenced_message["content_hash"] != message_ref["event_hash"]
                    or referenced_resolution["content_hash"]
                    != resolution_ref["event_hash"]
                    or receipt_payload["thread_id"] != payload["intent"]["thread_id"]
                    or receipt_payload["recipient_id"] != recipient
                ):
                    raise CommunicationError("route_logical_event_mismatch")
                return {
                    "event_id": receipt["event_id"],
                    "event_digest": receipt["content_hash"],
                    "sender": receipt["being_ref"],
                    "recipients": [recipient],
                    "thread_id": receipt_payload["thread_id"],
                    "reply_to": {
                        "event_id": message_ref["event_id"],
                        "event_digest": message_ref["event_hash"],
                    },
                    "kind": "semantic-receipt",
                    "content": {"outcome": receipt_payload["outcome"]},
                }
            reply = payload["reply"]
            reply_to: dict[str, str] | None = None
            kind = "message"
            if reply is not None:
                parents = reply["reply_parent_event_ids"]
                if len(parents) != 1:
                    raise CommunicationError("route_logical_event_unsupported")
                parent = _event(
                    self._known_event(database, str(parents[0])), self.ledger.authority
                )
                parent_payload = _message_payload(parent)
                if (
                    parent_payload["intent"]["thread_id"]
                    != payload["intent"]["thread_id"]
                ):
                    raise CommunicationError("route_logical_event_mismatch")
                reply_to = {
                    "event_id": parent["event_id"],
                    "event_digest": parent["content_hash"],
                }
                kind = "reply"
            return {
                "event_id": message["event_id"],
                "event_digest": message["content_hash"],
                "sender": message["being_ref"],
                "recipients": [recipient],
                "thread_id": payload["intent"]["thread_id"],
                "reply_to": reply_to,
                "kind": kind,
                "content": {"text": text},
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

    def record_attempt(
        self,
        value: Any,
        *,
        egress_request: bytes | None = None,
        egress_projection: Mapping[str, Any] | None = None,
        authority_head: str | None = None,
    ) -> dict[str, Any]:
        attempt = self._attempt_document(value)
        if (egress_request is None) != (egress_projection is None) or (
            (egress_request is None) != (authority_head is None)
        ):
            raise CommunicationError("communication_egress_invalid")
        if egress_request is not None and (
            self._egress is None or self._egress_catalog is None
        ):
            raise CommunicationError("communication_egress_unbound")
        raw = canonical_bytes(attempt)
        digest = hashlib.sha256(raw).hexdigest()
        self.initialize()
        with self._database() as database:
            database.execute("BEGIN IMMEDIATE")
            try:
                self._validate_store(database)
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
                    if egress_request is not None:
                        self._admit_route_egress(
                            database,
                            attempt,
                            egress_request,
                            egress_projection,
                            authority_head,
                        )
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
                if egress_request is not None:
                    self._admit_route_egress(
                        database,
                        attempt,
                        egress_request,
                        egress_projection,
                        authority_head,
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

    def _admit_route_egress(
        self,
        database: sqlite3.Connection,
        attempt: Mapping[str, Any],
        request: bytes,
        projection: Mapping[str, Any] | None,
        authority_head: str | None,
    ) -> None:
        assert self._egress is not None and self._egress_catalog is not None
        assert projection is not None and authority_head is not None
        digest = hashlib.sha256(request).hexdigest()
        database.execute(
            "INSERT INTO communication_egress_requests "
            "(attempt_id, request, request_sha256) VALUES (?, ?, ?) "
            "ON CONFLICT(attempt_id) DO NOTHING",
            (attempt["attempt_id"], request, digest),
        )
        row = database.execute(
            "SELECT request, request_sha256 FROM communication_egress_requests "
            "WHERE attempt_id=?",
            (attempt["attempt_id"],),
        ).fetchone()
        if (
            row is None
            or bytes(row["request"]) != request
            or row["request_sha256"] != digest
        ):
            raise CommunicationError("communication_egress_conflict")
        self._egress.admit_in_transaction(
            database,
            catalog_id=self._egress_catalog,
            path_id="route-provider-request",
            operation_id=str(attempt["attempt_id"]),
            locator=str(attempt["attempt_id"]),
            native_bytes=request,
            projection=projection,
            deadline_ms=int(attempt["deadline_ms"]),
            authority_head=authority_head,
        )

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
                self._validate_store(database)
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
                        existing["leg_id"] == attempt["leg_id"]
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
                self._validate_store(database)
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

    def upgrade_receipts_v2(self) -> None:
        """Explicit offline successor; caller holds the runtime/application locks.

        Existing generation, counter, queue and V1 foreign keys are preserved.
        Sidecar failure retains the ordinary fail-closed rollback semantics.
        """
        self.initialize()
        if self.receipts_v2:
            return
        with self._database() as database:
            database.execute("BEGIN IMMEDIATE")
            self._meta(database)
            self._validate_consumers(database)
            database.execute("""CREATE TABLE communication_foreign_receipts (
                leg_id TEXT PRIMARY KEY REFERENCES communication_legs(leg_id),
                receipt_event_id TEXT NOT NULL UNIQUE,
                receipt_hash TEXT NOT NULL, outcome TEXT NOT NULL,
                receipt_json BLOB NOT NULL, recipient_being_ref TEXT NOT NULL,
                incarnation_id TEXT NOT NULL, sequence INTEGER NOT NULL,
                UNIQUE(recipient_being_ref, incarnation_id, sequence)
            ) WITHOUT ROWID""")
            database.execute("""CREATE TABLE communication_compactions (
                recipient_id TEXT PRIMARY KEY,
                generation TEXT NOT NULL,
                through_sequence INTEGER NOT NULL
            ) WITHOUT ROWID""")
            self._migrate_legacy_compactions(database)
            database.execute(
                "UPDATE communication_meta SET value='2' WHERE key='schema_version'"
            )
            # Schema-only transaction: no semantic mutation, no counter advance.
            # Keeping the existing anchor untouched avoids an anchor-before-DB
            # crash window during migration. SQLite atomically commits DDL/version.
            database.commit()
            self.receipts_v2 = True

    def upgrade_legs_v3(self) -> None:
        """Explicit offline successor: one semantic leg per receiving body.

        Existing rows keep their stored `leg_id` and `sequence`, so nothing already
        materialized is rewritten or re-derived and a leg from before the upgrade
        stays addressable after it. SQLite cannot alter a UNIQUE constraint in
        place and three child tables reference this one with `ON DELETE RESTRICT`
        while every connection enforces foreign keys, so the table is rebuilt with
        enforcement off, inside one transaction, and the result is verified before
        the flag is raised.
        """
        self.initialize()
        if self.legs_v3:
            return
        if not self.receipts_v2:
            raise CommunicationError("legs_v3_requires_receipts_v2")
        with self._database() as database:
            # A no-op inside a transaction, so it has to precede BEGIN.
            database.execute("PRAGMA foreign_keys=OFF")
            try:
                database.execute("BEGIN IMMEDIATE")
                self._meta(database)
                database.execute(
                    """CREATE TABLE communication_legs_v3 (
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
                        UNIQUE(message_id, recipient_type, recipient_id,
                            receipt_origin_embodiment_id),
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
                    )"""
                )
                rows = database.execute(
                    "SELECT leg_id, message_id, thread_id, recipient_type, "
                    "recipient_id, receipt_origin_embodiment_id, "
                    "resolution_event_id, resolution_hash, evidence_cursor, "
                    "immutable_hash, sequence, state, terminal_receipt_event_id, "
                    "terminal_receipt_hash, created_at_ms FROM communication_legs "
                    "ORDER BY sequence"
                ).fetchall()
                # Legs are a projection of signed events, not signed history, so
                # an explicit offline successor may recompute their identifiers.
                # Doing it here rather than tolerating two derivations forever is
                # what keeps one identity rule true of every leg in the store.
                renames: list[tuple[str, str]] = []
                for row in rows:
                    renewed = _leg_id(
                        str(row["message_id"]),
                        str(row["recipient_type"]),
                        str(row["recipient_id"]),
                        str(row["receipt_origin_embodiment_id"]),
                    )
                    carried = tuple(row[index] for index in range(1, 15))
                    database.execute(
                        "INSERT INTO communication_legs_v3 VALUES "
                        "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (renewed, *carried),
                    )
                    if renewed != str(row["leg_id"]):
                        renames.append((str(row["leg_id"]), renewed))
                renewed_ids = {new for _old, new in renames}
                if len(renewed_ids) != len(renames) or renewed_ids & {
                    str(row["leg_id"]) for row in rows
                }:
                    raise CommunicationError("communication_legs_migration_incomplete")
                if int(
                    database.execute(
                        "SELECT COUNT(*) FROM communication_legs_v3"
                    ).fetchone()[0]
                ) != len(rows):
                    raise CommunicationError("communication_legs_migration_incomplete")
                database.execute("DROP TABLE communication_legs")
                # Keep the rename from rewriting the child tables' references: they
                # name this table, and it exists again by the end of the statement.
                database.execute("PRAGMA legacy_alter_table=ON")
                database.execute(
                    "ALTER TABLE communication_legs_v3 RENAME TO communication_legs"
                )
                database.execute("PRAGMA legacy_alter_table=OFF")
                for old_id, new_id in renames:
                    for child in (
                        "communication_queue",
                        "communication_attempts",
                        "communication_receipts",
                        "communication_foreign_receipts",
                    ):
                        database.execute(
                            f"UPDATE {child} SET leg_id=? WHERE leg_id=?",
                            (new_id, old_id),
                        )
                database.execute(
                    "UPDATE communication_meta SET value=? WHERE key='schema_version'",
                    (str(LEGS_V3_SCHEMA_VERSION),),
                )
                database.commit()
            except BaseException:
                database.rollback()
                raise
            finally:
                database.execute("PRAGMA foreign_keys=ON")
            if database.execute("PRAGMA foreign_key_check").fetchall():
                raise CommunicationError("communication_store_corrupt")
            self.legs_v3 = True

    def _validate_foreign_receipt(
        self,
        database: sqlite3.Connection,
        receipt: Mapping[str, Any],
        recipient_being_ref: str,
    ) -> tuple[Event, sqlite3.Row]:
        if not self.receipts_v2 or self.foreign_authority_resolver is None:
            raise CommunicationError("foreign_receipts_not_enabled")
        event = _event(receipt, self.foreign_authority_resolver(recipient_being_ref))
        payload = _foreign_receipt_payload(event)
        if (
            event["being_ref"] != recipient_being_ref
            or event["being_ref"] == self.ledger.authority.manifest.being_ref
        ):
            raise CommunicationError("receipt_origin_mismatch")
        message = _event(
            self._known_event(database, payload["message_ref"]["event_id"]),
            self.ledger.authority,
        )
        resolution = _event(
            self._known_event(database, payload["resolution_ref"]["event_id"]),
            self.ledger.authority,
        )
        _, targets = _resolution_payload(
            resolution, message_id=message["event_id"], scope="/tribe"
        )
        matching = [
            target
            for target in targets
            if target["recipient_type"] == "relationship"
            and target["recipient_id"] == payload["recipient_id"]
        ]
        if (
            _message_payload(message)["body"].get("recipient_being_ref")
            != recipient_being_ref
            or payload["message_being_ref"] != message["being_ref"]
            or payload["message_ref"]["event_hash"] != message["content_hash"]
            or payload["resolution_ref"]["event_hash"] != resolution["content_hash"]
            or payload["thread_id"] != _message_payload(message)["intent"]["thread_id"]
            or payload["observed_at_ms"] < message["occurred_at_ms"]
            or len(matching) != 1
            or matching[0]["receipt_origin_embodiment_id"]
            != event["origin"]["embodiment_id"]
        ):
            raise CommunicationError("foreign_receipt_binding_mismatch")
        # Select by the receipt author as well as the recipient. Under today's
        # leg uniqueness this changes nothing: at most one row matches either
        # way, and a leg whose author differs already failed the check below with
        # the same closed error. Naming the author here is what keeps the lookup
        # exact once one membership legitimately has several receiving bodies,
        # each with its own leg.
        leg = database.execute(
            "SELECT * FROM communication_legs WHERE message_id=? "
            "AND recipient_type='relationship' AND recipient_id=? "
            "AND receipt_origin_embodiment_id=?",
            (
                message["event_id"],
                payload["recipient_id"],
                event["origin"]["embodiment_id"],
            ),
        ).fetchone()
        if (
            leg is None
            or leg["resolution_event_id"] != resolution["event_id"]
            or leg["resolution_hash"] != resolution["content_hash"]
            or leg["thread_id"] != payload["thread_id"]
            or leg["receipt_origin_embodiment_id"] != event["origin"]["embodiment_id"]
        ):
            raise CommunicationError("semantic_leg_not_known")
        immutable = {
            "message_id": message["event_id"],
            "thread_id": payload["thread_id"],
            "recipient_type": "relationship",
            "recipient_id": payload["recipient_id"],
            "receipt_origin_embodiment_id": matching[0]["receipt_origin_embodiment_id"],
            "resolution_event_id": resolution["event_id"],
            "resolution_hash": resolution["content_hash"],
            "evidence_cursor": matching[0]["evidence_cursor"],
        }
        projection = MessageProjection(
            message["event_id"],
            message["content_hash"],
            payload["thread_id"],
            message["origin"],
            message["payload"]["intent"],
            resolution["event_id"],
            resolution["content_hash"],
        )
        stored = database.execute(
            "SELECT * FROM communication_messages WHERE message_id=?",
            (message["event_id"],),
        ).fetchone()
        if (
            any(leg[key] != value for key, value in immutable.items())
            or leg["immutable_hash"]
            != hashlib.sha256(canonical_bytes(immutable)).hexdigest()
            or leg["leg_id"]
            != _leg_id(
                message["event_id"],
                "relationship",
                payload["recipient_id"],
                str(event["origin"]["embodiment_id"]) if self.legs_v3 else None,
            )
            or stored is None
            or stored["thread_id"] != payload["thread_id"]
            or stored["event_hash"] != message["content_hash"]
            or stored["resolution_event_id"] != resolution["event_id"]
            or stored["resolution_hash"] != resolution["content_hash"]
            or bytes(stored["author_json"]) != canonical_bytes(message["origin"])
            or bytes(stored["intent_json"])
            != canonical_bytes(message["payload"]["intent"])
            or bytes(stored["message_json"]) != canonical_bytes(projection.as_dict())
        ):
            raise CommunicationError("foreign_receipt_binding_mismatch")
        return event, leg

    def record_foreign_receipt(
        self, receipt: Mapping[str, Any], *, recipient_being_ref: str
    ) -> dict[str, Any]:
        """Trusted intake only: independently enrolled recipient, not model input."""
        self.initialize()
        with self._database() as database:
            database.execute("BEGIN IMMEDIATE")
            self._validate_store(database)
            event, leg = self._validate_foreign_receipt(
                database, receipt, recipient_being_ref
            )
            raw = canonical_bytes(event)
            existing = database.execute(
                "SELECT * FROM communication_foreign_receipts WHERE leg_id=? "
                "OR receipt_event_id=? OR (recipient_being_ref=? "
                "AND incarnation_id=? AND sequence=?)",
                (
                    leg["leg_id"],
                    event["event_id"],
                    recipient_being_ref,
                    event["origin"]["incarnation_id"],
                    event["sequence"],
                ),
            ).fetchall()
            local = database.execute(
                "SELECT * FROM communication_receipts WHERE leg_id=?", (leg["leg_id"],)
            ).fetchone()
            if (
                len(existing) == 1
                and bytes(existing[0]["receipt_json"]) == raw
                and existing[0]["leg_id"] == leg["leg_id"]
                and local is None
            ):
                database.commit()
                return self._result(database, leg["message_id"])
            if existing or local is not None:
                evidence = {
                    "schema": "dm.communication.conflict/v2",
                    "lane": "terminal-receipt",
                    "presented_receipt": event,
                    "existing_receipts": [
                        json.loads(bytes(row["receipt_json"])) for row in existing
                    ],
                }
                if local is not None:
                    evidence["local_receipt"] = self._known_event(
                        database, local["receipt_event_id"]
                    )
                for identifier in {leg["leg_id"], *(row["leg_id"] for row in existing)}:
                    self._quarantine(database, identifier, evidence)
                self._arm_commit(database)
                raise CommunicationError("terminal_receipt_conflict")
            if leg["state"] != "accepted":
                raise CommunicationError("semantic_leg_quarantined")
            database.execute(
                "INSERT INTO communication_foreign_receipts "
                "VALUES (?, ?, ?, 'delivered', ?, ?, ?, ?)",
                (
                    leg["leg_id"],
                    event["event_id"],
                    event["content_hash"],
                    raw,
                    recipient_being_ref,
                    event["origin"]["incarnation_id"],
                    event["sequence"],
                ),
            )
            database.execute(
                "UPDATE communication_legs SET state='delivered', "
                "terminal_receipt_event_id=?, terminal_receipt_hash=? WHERE leg_id=?",
                (event["event_id"], event["content_hash"], leg["leg_id"]),
            )
            self._arm_commit(database)
            return self._result(database, leg["message_id"])

    def record_receipt(self, receipt_event_id: str) -> dict[str, Any]:
        _uuid(receipt_event_id, "invalid_receipt_event_id")
        self.initialize()
        with self._database() as database:
            database.execute("BEGIN IMMEDIATE")
            committed_conflict = False
            try:
                self._validate_store(database)
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
                self._bind_local_receipt(receipt, leg)
                if self.receipts_v2:
                    foreign = database.execute(
                        "SELECT receipt_json FROM communication_foreign_receipts "
                        "WHERE leg_id=?",
                        (leg["leg_id"],),
                    ).fetchone()
                    if foreign is not None:
                        self._quarantine(
                            database,
                            leg["leg_id"],
                            {
                                "schema": "dm.communication.conflict/v2",
                                "lane": "terminal-receipt",
                                "presented_receipt": receipt,
                                "existing_receipt": json.loads(
                                    bytes(foreign["receipt_json"])
                                ),
                            },
                        )
                        self._arm_commit(database)
                        committed_conflict = True
                        raise CommunicationError("terminal_receipt_conflict")
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
                self._validate_store(database)
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
                    self._validate_snapshot(database, result, request, claim=False)
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
                self._validate_snapshot(database, result, request, claim=False)
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
                self._validate_store(database)
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
                self._validate_consumer_position(
                    database, recipient_id=recipient_id, sequence=sequence
                )
                if sequence == current:
                    database.commit()
                    return {
                        "recipient_id": recipient_id,
                        "consumer_id": consumer_id,
                        "generation": generation,
                        "sequence": current,
                    }
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
                self._validate_store(database)
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
                    self._validate_snapshot(database, result, request, claim=True)
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
                self._validate_snapshot(database, result, request, claim=True)
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
                self._validate_store(database)
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
                    "SELECT sequence FROM communication_legs "
                    "WHERE recipient_id=? AND sequence<=? "
                    f"AND state NOT IN ({','.join('?' for _ in terminal)}) LIMIT 1",
                    (recipient_id, through_sequence, *terminal),
                ).fetchone()
                if pending is not None:
                    raise CommunicationError("compaction_prefix_not_terminal")
                count = database.execute(
                    "DELETE FROM communication_queue WHERE recipient_id=? "
                    "AND sequence<=?",
                    (recipient_id, through_sequence),
                ).rowcount
                if self.receipts_v2:
                    generation, _counter, _highwater = self._meta(database)
                    database.execute(
                        "INSERT INTO communication_compactions VALUES (?, ?, ?) "
                        "ON CONFLICT(recipient_id) DO UPDATE SET "
                        "through_sequence=max(through_sequence, "
                        "excluded.through_sequence) "
                        "WHERE generation=excluded.generation",
                        (recipient_id, generation, through_sequence),
                    )
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
    provider: SyntheticRouteProvider,
    attempt: Mapping[str, Any],
) -> Mapping[str, Any]:
    """Exercise only the explicit, side-effect-free synthetic provider."""

    if type(provider) is not SyntheticRouteProvider:
        raise CommunicationError("route_provider_not_gated")
    accepted = store.record_attempt(attempt)
    if accepted["provider_ref"] != provider.provider_ref:
        raise CommunicationError("route_provider_mismatch")
    ack = SyntheticRouteProvider.deliver(provider, copy.deepcopy(dict(attempt)))
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
    "SyntheticRouteProvider",
    "dispatch_attempt",
]
