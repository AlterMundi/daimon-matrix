"""Carrier-neutral DM-053 route providers and opaque inbox mechanics.

Routes operate below signed scope resolution, recipient encryption and logical
communication state.  They can move exact ``dm.sealed-delivery/v1`` bytes and
return authenticated operational evidence; they cannot author Matrix events or
decide semantic delivery.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import html
import http.client
import json
import os
import socket
import sqlite3
import stat
import struct
import uuid
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Protocol, cast
from urllib.parse import urlsplit

from .canonical import CanonicalError, b64url, canonical_bytes, unb64url
from .communication import CommunicationStore
from .sealed import SealedDeliveryError, inspect_delivery

ROUTE_PROFILE_SCHEMA: Final = "dm.route-profile/v1"
ROUTE_BINDING_SCHEMA: Final = "dm.route-binding/v1"
ROUTE_SUBMISSION_SCHEMA: Final = "dm.route-submission/v1"
PROVIDER_RESULT_SCHEMA: Final = "dm.route-provider-result/v1"
PROVIDER_MANIFEST_SCHEMA: Final = "dm.route-provider-manifest/v1"
TRANSPORT_REQUEST_SCHEMA: Final = "dm.transport-request/v1"
TRANSPORT_RESPONSE_SCHEMA: Final = "dm.transport-response/v1"
TRANSPORT_AUTH_SCHEMA: Final = "dm.transport-auth/v1"
INBOX_ITEM_SCHEMA: Final = "dm.opaque-inbox-item/v1"
INBOX_CLAIM_SCHEMA: Final = "dm.opaque-inbox-claim/v1"
GATEWAY_POLICY_SCHEMA: Final = "dm.gateway-policy/v1"
GATEWAY_RENDER_SCHEMA: Final = "dm.gateway-render/v1"
GATEWAY_PROPOSAL_SCHEMA: Final = "dm.gateway-proposal/v1"
POLICY_VERSION: Final = "dm.route-policy/v1"
TRANSPORT_VERSION: Final = "v1"
MAX_TRANSPORT_BYTES: Final = 5 * 1024 * 1024
MAX_ROUTE_ROWS: Final = 256
MAX_CLAIM_SIZE: Final = 256
MAX_CLOCK_SKEW_MS: Final = 60_000
_ATTEMPT_NAMESPACE: Final = uuid.UUID("0cf5ecf9-c25b-4dd1-bf44-eb83bbcb51c8")
_CLASS_ORDER: Final = {"local": 0, "direct-anyvpn": 1, "direct": 2, "hub": 3}
_ID_CHARS: Final = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:@/-"
)

Clock = Callable[[], int]
RoundTrip = Callable[[bytes], bytes]
IntakeValidator = Callable[[bytes], None]
IntakeGate = Callable[[str, str], None]
TerminalValidator = Callable[[str, str, str], None]
GatewayPolicyValidator = Callable[[Mapping[str, Any]], None]


class RouteError(ValueError):
    """Stable fail-closed route error."""

    def __init__(self, code: str, *, retryable: bool = False) -> None:
        super().__init__(code)
        self.code = code
        self.retryable = retryable


class RouteAmbiguous(RouteError):
    """The effect may have happened but no authenticated result was received."""

    def __init__(self) -> None:
        super().__init__("route_result_unknown", retryable=True)


def _closed(value: Any, fields: set[str], code: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise RouteError(code)
    return value


def _text(value: Any, code: str, *, maximum: int = 256) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > maximum
        or any(character not in _ID_CHARS for character in value)
    ):
        raise RouteError(code)
    return value


def _free_text(value: Any, code: str, *, maximum: int) -> str:
    if not isinstance(value, str) or not 1 <= len(value.encode("utf-8")) <= maximum:
        raise RouteError(code)
    return value


def _uint(value: Any, code: str, *, minimum: int = 0) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not minimum <= value <= 2**53 - 1
    ):
        raise RouteError(code)
    return value


def _uuid(value: Any, code: str) -> str:
    if not isinstance(value, str):
        raise RouteError(code)
    try:
        parsed = uuid.UUID(value)
    except ValueError as exception:
        raise RouteError(code) from exception
    if str(parsed) != value or parsed.variant != uuid.RFC_4122:
        raise RouteError(code)
    return value


def _digest(value: Any, code: str) -> str:
    text = _text(value, code, maximum=64)
    if len(text) != 64 or any(
        character not in "0123456789abcdef" for character in text
    ):
        raise RouteError(code)
    return text


def _canonical(value: Any, code: str) -> bytes:
    try:
        return canonical_bytes(value)
    except CanonicalError as exception:
        raise RouteError(code) from exception


def _opaque_evidence(value: Mapping[str, Any]) -> str:
    digest = hashlib.sha256(canonical_bytes(value)).digest()
    return f"dm:evidence:v1:{b64url(digest)}"


def _safe_database_path(path: Path) -> Path:
    resolved = Path(os.path.abspath(path))
    parent = resolved.parent
    info = parent.lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise RouteError("provider_state_not_owner_only")
    ancestor = parent
    while ancestor != ancestor.parent:
        if ancestor.is_symlink():
            raise RouteError("provider_state_ancestor_symlink")
        ancestor = ancestor.parent
    try:
        file_info = resolved.lstat()
    except FileNotFoundError:
        descriptor = os.open(
            resolved,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        os.close(descriptor)
        return resolved
    if (
        stat.S_ISLNK(file_info.st_mode)
        or not stat.S_ISREG(file_info.st_mode)
        or file_info.st_uid != os.geteuid()
        or stat.S_IMODE(file_info.st_mode) & 0o077
    ):
        raise RouteError("provider_state_not_owner_only")
    return resolved


@dataclass(frozen=True)
class RouteBinding:
    adapter_id: str
    provider_ref: str
    route_ref: str
    route_class: str
    priority: int
    recipient_id: str
    recipient_body_ref: str
    credential_ref: str
    enabled: bool

    @classmethod
    def from_value(cls, value: Any) -> RouteBinding:
        row = _closed(
            value,
            {
                "adapter_id",
                "credential_ref",
                "enabled",
                "priority",
                "provider_ref",
                "recipient_body_ref",
                "recipient_id",
                "route_class",
                "route_ref",
                "schema",
            },
            "invalid_route_binding",
        )
        if (
            row["schema"] != ROUTE_BINDING_SCHEMA
            or row["route_class"] not in _CLASS_ORDER
        ):
            raise RouteError("unsupported_route_binding")
        for field in (
            "adapter_id",
            "credential_ref",
            "provider_ref",
            "recipient_body_ref",
            "recipient_id",
            "route_ref",
        ):
            _text(row[field], "invalid_route_binding")
        if not isinstance(row["enabled"], bool):
            raise RouteError("invalid_route_binding")
        return cls(
            adapter_id=cast(str, row["adapter_id"]),
            provider_ref=cast(str, row["provider_ref"]),
            route_ref=cast(str, row["route_ref"]),
            route_class=cast(str, row["route_class"]),
            priority=_uint(row["priority"], "invalid_route_binding"),
            recipient_id=cast(str, row["recipient_id"]),
            recipient_body_ref=cast(str, row["recipient_body_ref"]),
            credential_ref=cast(str, row["credential_ref"]),
            enabled=row["enabled"],
        )

    def public(self) -> dict[str, Any]:
        return {
            "schema": ROUTE_BINDING_SCHEMA,
            "adapter_id": self.adapter_id,
            "credential_ref": self.credential_ref,
            "enabled": self.enabled,
            "priority": self.priority,
            "provider_ref": self.provider_ref,
            "recipient_body_ref": self.recipient_body_ref,
            "recipient_id": self.recipient_id,
            "route_class": self.route_class,
            "route_ref": self.route_ref,
        }


@dataclass(frozen=True)
class RouteProfile:
    profile_id: str
    body_ref: str
    principal_id: str
    enabled: bool
    local_recipient_ids: frozenset[str]
    routes: tuple[RouteBinding, ...]

    @classmethod
    def from_value(cls, value: Any) -> RouteProfile:
        profile = _closed(
            value,
            {
                "body_ref",
                "enabled",
                "local_recipient_ids",
                "policy_version",
                "principal_id",
                "profile_id",
                "routes",
                "schema",
            },
            "invalid_route_profile",
        )
        if (
            profile["schema"] != ROUTE_PROFILE_SCHEMA
            or profile["policy_version"] != POLICY_VERSION
        ):
            raise RouteError("unsupported_route_profile")
        for field in ("profile_id", "body_ref", "principal_id"):
            _text(profile[field], "invalid_route_profile")
        if not isinstance(profile["enabled"], bool):
            raise RouteError("invalid_route_profile")
        local = profile["local_recipient_ids"]
        if (
            not isinstance(local, list)
            or len(local) > MAX_ROUTE_ROWS
            or local != sorted(set(local))
        ):
            raise RouteError("invalid_route_profile")
        for recipient in local:
            _text(recipient, "invalid_route_profile")
        rows = profile["routes"]
        if not isinstance(rows, list) or len(rows) > MAX_ROUTE_ROWS:
            raise RouteError("invalid_route_profile")
        routes = tuple(RouteBinding.from_value(row) for row in rows)
        identities = {
            (row.provider_ref, row.route_ref, row.recipient_id) for row in routes
        }
        if len(identities) != len(routes):
            raise RouteError("duplicate_route_binding")
        return cls(
            profile_id=cast(str, profile["profile_id"]),
            body_ref=cast(str, profile["body_ref"]),
            principal_id=cast(str, profile["principal_id"]),
            enabled=profile["enabled"],
            local_recipient_ids=frozenset(cast(list[str], local)),
            routes=routes,
        )

    def candidates(self, recipient_id: str) -> tuple[RouteBinding, ...]:
        return tuple(
            sorted(
                (
                    row
                    for row in self.routes
                    if row.enabled and row.recipient_id == recipient_id
                ),
                key=lambda row: (
                    _CLASS_ORDER[row.route_class],
                    row.priority,
                    row.adapter_id,
                    row.route_ref,
                ),
            )
        )

    def public(self) -> dict[str, Any]:
        return {
            "schema": ROUTE_PROFILE_SCHEMA,
            "profile_id": self.profile_id,
            "body_ref": self.body_ref,
            "principal_id": self.principal_id,
            "policy_version": POLICY_VERSION,
            "enabled": self.enabled,
            "local_recipient_ids": sorted(self.local_recipient_ids),
            "routes": [
                row.public()
                for row in sorted(
                    self.routes,
                    key=lambda binding: (
                        binding.provider_ref,
                        binding.route_ref,
                        binding.recipient_id,
                    ),
                )
            ],
        }


class Provider(Protocol):
    @property
    def provider_ref(self) -> str: ...

    @property
    def route_ref(self) -> str: ...

    @property
    def route_class(self) -> str: ...

    def inspect(self) -> Mapping[str, Any]: ...

    def deliver(self, submission: Mapping[str, Any]) -> Mapping[str, Any]: ...

    def manifest(self) -> Mapping[str, Any]: ...


class OpaqueInbox:
    """Provider-owned durable opaque queue with stable sequences and leases."""

    def __init__(self, path: Path, *, clock: Clock) -> None:
        self.path = _safe_database_path(path)
        self.clock = clock
        with self._database() as database:
            database.executescript(
                "CREATE TABLE IF NOT EXISTS inbox_meta ("
                "singleton INTEGER PRIMARY KEY CHECK(singleton=1), "
                "next_sequence INTEGER NOT NULL);"
                "INSERT OR IGNORE INTO inbox_meta VALUES (1, 1);"
                "CREATE TABLE IF NOT EXISTS inbox_items ("
                "sequence INTEGER PRIMARY KEY, delivery_id TEXT UNIQUE NOT NULL, "
                "recipient_id TEXT NOT NULL, envelope_hash TEXT NOT NULL, "
                "envelope BLOB NOT NULL, received_at_ms INTEGER NOT NULL, "
                "state TEXT NOT NULL CHECK(state IN ('pending','acked')), "
                "claim_id TEXT, consumer_id TEXT, lease_until_ms INTEGER);"
                "CREATE TABLE IF NOT EXISTS inbox_requests ("
                "request_id TEXT PRIMARY KEY, request_hash TEXT NOT NULL, "
                "delivery_id TEXT NOT NULL);"
                "CREATE TABLE IF NOT EXISTS inbox_tombstones ("
                "delivery_id TEXT PRIMARY KEY, recipient_id TEXT NOT NULL, "
                "envelope_hash TEXT NOT NULL, received_at_ms INTEGER NOT NULL, "
                "sequence INTEGER NOT NULL UNIQUE);"
                "CREATE TABLE IF NOT EXISTS inbox_claims ("
                "claim_id TEXT PRIMARY KEY, request_hash TEXT NOT NULL, "
                "result_json BLOB NOT NULL);"
            )

    @contextmanager
    def _database(self) -> Iterator[sqlite3.Connection]:
        _safe_database_path(self.path)
        database = sqlite3.connect(self.path, isolation_level=None, timeout=30)
        try:
            database.row_factory = sqlite3.Row
            mode = database.execute("PRAGMA journal_mode=DELETE").fetchone()[0]
            database.execute("PRAGMA synchronous=FULL")
            if (
                str(mode).lower() != "delete"
                or database.execute("PRAGMA synchronous").fetchone()[0] != 2
            ):
                raise RouteError("provider_state_unavailable", retryable=True)
            yield database
        finally:
            database.close()

    def ingest(
        self,
        *,
        request_id: str,
        request_hash: str,
        recipient_id: str,
        envelope: bytes,
    ) -> dict[str, Any]:
        _uuid(request_id, "invalid_transport_request")
        _digest(request_hash, "invalid_transport_request")
        _text(recipient_id, "invalid_transport_request")
        metadata = inspect_delivery(envelope, at_ms=self.clock())
        envelope_hash = cast(str, metadata["envelope_sha256"])
        delivery_id = cast(str, metadata["delivery_id"])
        with self._database() as database:
            database.execute("BEGIN IMMEDIATE")
            try:
                request = database.execute(
                    "SELECT request_hash, delivery_id FROM inbox_requests "
                    "WHERE request_id=?",
                    (request_id,),
                ).fetchone()
                if request is not None and (
                    request["request_hash"] != request_hash
                    or request["delivery_id"] != delivery_id
                ):
                    raise RouteError("transport_request_conflict")
                existing = database.execute(
                    "SELECT * FROM inbox_items WHERE delivery_id=?", (delivery_id,)
                ).fetchone()
                tombstone = database.execute(
                    "SELECT * FROM inbox_tombstones WHERE delivery_id=?",
                    (delivery_id,),
                ).fetchone()
                replayed = existing is not None or tombstone is not None
                if existing is not None:
                    if (
                        existing["envelope_hash"] != envelope_hash
                        or existing["recipient_id"] != recipient_id
                        or bytes(existing["envelope"]) != envelope
                    ):
                        raise RouteError("delivery_id_conflict")
                    row = existing
                elif tombstone is not None:
                    if (
                        tombstone["envelope_hash"] != envelope_hash
                        or tombstone["recipient_id"] != recipient_id
                    ):
                        raise RouteError("delivery_id_conflict")
                    row = tombstone
                else:
                    next_sequence = int(
                        database.execute(
                            "SELECT next_sequence FROM inbox_meta WHERE singleton=1"
                        ).fetchone()[0]
                    )
                    received = self.clock()
                    database.execute(
                        "INSERT INTO inbox_items VALUES "
                        "(?, ?, ?, ?, ?, ?, 'pending', NULL, NULL, NULL)",
                        (
                            next_sequence,
                            delivery_id,
                            recipient_id,
                            envelope_hash,
                            envelope,
                            received,
                        ),
                    )
                    database.execute(
                        "UPDATE inbox_meta SET next_sequence=? WHERE singleton=1",
                        (next_sequence + 1,),
                    )
                    row = database.execute(
                        "SELECT * FROM inbox_items WHERE delivery_id=?", (delivery_id,)
                    ).fetchone()
                if request is None:
                    database.execute(
                        "INSERT INTO inbox_requests VALUES (?, ?, ?)",
                        (request_id, request_hash, delivery_id),
                    )
                database.commit()
                assert row is not None
                evidence = {
                    "delivery_id": delivery_id,
                    "envelope_sha256": envelope_hash,
                    "received_at_ms": int(row["received_at_ms"]),
                    "recipient_id": recipient_id,
                    "sequence": int(row["sequence"]),
                }
                return {
                    "schema": INBOX_ITEM_SCHEMA,
                    **evidence,
                    "evidence_ref": _opaque_evidence(evidence),
                    "replayed": replayed,
                    "state": "acked" if tombstone is not None else str(row["state"]),
                }
            except BaseException:
                if database.in_transaction:
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
        _text(recipient_id, "invalid_inbox_claim")
        _text(consumer_id, "invalid_inbox_claim")
        _uuid(claim_id, "invalid_inbox_claim")
        _uint(limit, "invalid_inbox_claim", minimum=1)
        _uint(lease_until_ms, "invalid_inbox_claim")
        if limit > MAX_CLAIM_SIZE:
            raise RouteError("invalid_inbox_claim")
        request = {
            "recipient_id": recipient_id,
            "consumer_id": consumer_id,
            "claim_id": claim_id,
            "limit": limit,
            "lease_until_ms": lease_until_ms,
        }
        request_hash = hashlib.sha256(canonical_bytes(request)).hexdigest()
        with self._database() as database:
            database.execute("BEGIN IMMEDIATE")
            try:
                prior = database.execute(
                    "SELECT request_hash, result_json FROM inbox_claims "
                    "WHERE claim_id=?",
                    (claim_id,),
                ).fetchone()
                if prior is not None:
                    if prior["request_hash"] != request_hash:
                        raise RouteError("inbox_claim_conflict")
                    database.commit()
                    return cast(dict[str, Any], json.loads(bytes(prior["result_json"])))
                now = self.clock()
                if lease_until_ms <= now:
                    raise RouteError("invalid_inbox_claim")
                rows = database.execute(
                    "SELECT * FROM inbox_items WHERE recipient_id=? "
                    "AND state='pending' "
                    "AND (lease_until_ms IS NULL OR lease_until_ms<=?) "
                    "ORDER BY sequence LIMIT ?",
                    (recipient_id, now, limit),
                ).fetchall()
                for row in rows:
                    database.execute(
                        "UPDATE inbox_items SET claim_id=?, consumer_id=?, "
                        "lease_until_ms=? "
                        "WHERE sequence=?",
                        (claim_id, consumer_id, lease_until_ms, row["sequence"]),
                    )
                result = {
                    "schema": INBOX_CLAIM_SCHEMA,
                    "claim_id": claim_id,
                    "recipient_id": recipient_id,
                    "consumer_id": consumer_id,
                    "lease_until_ms": lease_until_ms,
                    "items": [
                        {
                            "sequence": int(row["sequence"]),
                            "delivery_id": str(row["delivery_id"]),
                            "envelope_sha256": str(row["envelope_hash"]),
                            "envelope": b64url(bytes(row["envelope"])),
                        }
                        for row in rows
                    ],
                }
                database.execute(
                    "INSERT INTO inbox_claims VALUES (?, ?, ?)",
                    (claim_id, request_hash, canonical_bytes(result)),
                )
                database.commit()
                return result
            except BaseException:
                if database.in_transaction:
                    database.rollback()
                raise

    def ack(
        self,
        *,
        recipient_id: str,
        consumer_id: str,
        delivery_id: str,
        envelope_hash: str,
    ) -> dict[str, Any]:
        _text(recipient_id, "invalid_inbox_ack")
        _text(consumer_id, "invalid_inbox_ack")
        _uuid(delivery_id, "invalid_inbox_ack")
        _digest(envelope_hash, "invalid_inbox_ack")
        with self._database() as database:
            database.execute("BEGIN IMMEDIATE")
            row = database.execute(
                "SELECT * FROM inbox_items WHERE delivery_id=?", (delivery_id,)
            ).fetchone()
            if row is None:
                database.rollback()
                raise RouteError("inbox_item_not_known")
            if (
                row["recipient_id"] != recipient_id
                or row["envelope_hash"] != envelope_hash
            ):
                database.rollback()
                raise RouteError("inbox_ack_conflict")
            if row["consumer_id"] != consumer_id:
                database.rollback()
                raise RouteError("inbox_claim_not_owned")
            database.execute(
                "UPDATE inbox_items SET state='acked', lease_until_ms=NULL "
                "WHERE delivery_id=?",
                (delivery_id,),
            )
            database.commit()
            return {
                "delivery_id": delivery_id,
                "envelope_sha256": envelope_hash,
                "recipient_id": recipient_id,
                "sequence": int(row["sequence"]),
                "state": "acked",
            }

    def compact(
        self,
        *,
        recipient_id: str,
        through_sequence: int,
        terminal_validator: TerminalValidator,
    ) -> dict[str, Any]:
        _text(recipient_id, "invalid_inbox_compaction")
        _uint(through_sequence, "invalid_inbox_compaction")
        with self._database() as database:
            database.execute("BEGIN IMMEDIATE")
            pending = database.execute(
                "SELECT 1 FROM inbox_items WHERE recipient_id=? AND sequence<=? "
                "AND state!='acked' LIMIT 1",
                (recipient_id, through_sequence),
            ).fetchone()
            if pending is not None:
                database.rollback()
                raise RouteError("inbox_compaction_not_acked")
            rows = database.execute(
                "SELECT delivery_id, envelope_hash FROM inbox_items "
                "WHERE recipient_id=? AND sequence<=? ORDER BY sequence",
                (recipient_id, through_sequence),
            ).fetchall()
            try:
                for row in rows:
                    terminal_validator(
                        recipient_id,
                        str(row["delivery_id"]),
                        str(row["envelope_hash"]),
                    )
            except (RouteError, ValueError) as exception:
                database.rollback()
                raise RouteError("inbox_compaction_not_terminal") from exception
            database.execute(
                "INSERT OR IGNORE INTO inbox_tombstones "
                "(delivery_id, recipient_id, envelope_hash, received_at_ms, sequence) "
                "SELECT delivery_id, recipient_id, envelope_hash, received_at_ms, "
                "sequence FROM inbox_items WHERE recipient_id=? AND sequence<=?",
                (recipient_id, through_sequence),
            )
            removed = database.execute(
                "DELETE FROM inbox_items WHERE recipient_id=? AND sequence<=?",
                (recipient_id, through_sequence),
            ).rowcount
            database.commit()
            return {
                "recipient_id": recipient_id,
                "through_sequence": through_sequence,
                "removed": removed,
            }


def _auth(secret: bytes, value: Mapping[str, Any]) -> str:
    if len(secret) != 32:
        raise RouteError("invalid_transport_secret")
    return b64url(hmac.digest(secret, canonical_bytes(value), "sha256"))


class TransportIngress:
    """Authenticate one route credential and durably accept opaque bytes."""

    def __init__(
        self,
        *,
        provider_ref: str,
        route_ref: str,
        key_ref: str,
        secret: bytes,
        recipient_id: str,
        recipient_body_ref: str,
        inbox: OpaqueInbox,
        clock: Clock,
        hub: bool = False,
        presence_ref: str | None = None,
        fence_ref: str | None = None,
        intake_validator: IntakeValidator | None = None,
        intake_gate: IntakeGate | None = None,
    ) -> None:
        for value in (
            provider_ref,
            route_ref,
            key_ref,
            recipient_id,
            recipient_body_ref,
        ):
            _text(value, "invalid_transport_ingress")
        if (presence_ref is None) != (fence_ref is None) or (presence_ref is None) != (
            intake_gate is None
        ):
            raise RouteError("incomplete_intake_gate")
        if not hub and intake_validator is None:
            raise RouteError("intake_validator_required")
        if presence_ref is not None:
            _text(presence_ref, "invalid_transport_ingress")
            _text(fence_ref, "invalid_transport_ingress")
        if len(secret) != 32:
            raise RouteError("invalid_transport_secret")
        self.provider_ref = provider_ref
        self.route_ref = route_ref
        self.key_ref = key_ref
        self._secret = bytes(secret)
        self.recipient_id = recipient_id
        self.recipient_body_ref = recipient_body_ref
        self.inbox = inbox
        self.clock = clock
        self.hub = hub
        self.presence_ref = presence_ref
        self.fence_ref = fence_ref
        self.intake_validator = intake_validator
        self.intake_gate = intake_gate

    def handle(self, raw: bytes) -> bytes:
        try:
            request = _decode_canonical(raw, "transport_request_rejected")
            value = _closed(
                request,
                {
                    "auth",
                    "expires_at_ms",
                    "issued_at_ms",
                    "provider_ref",
                    "request_id",
                    "route_ref",
                    "schema",
                    "sender_body_ref",
                    "sender_principal",
                    "submission",
                    "version",
                },
                "transport_request_rejected",
            )
            auth = _closed(
                value["auth"],
                {"alg", "key_ref", "schema", "value"},
                "transport_request_rejected",
            )
            if (
                value["schema"] != TRANSPORT_REQUEST_SCHEMA
                or value["version"] != TRANSPORT_VERSION
                or value["provider_ref"] != self.provider_ref
                or value["route_ref"] != self.route_ref
                or auth["schema"] != TRANSPORT_AUTH_SCHEMA
                or auth["alg"] != "HMAC-SHA256"
                or auth["key_ref"] != self.key_ref
            ):
                raise RouteError("transport_request_rejected")
            request_id = _uuid(value["request_id"], "transport_request_rejected")
            issued = _uint(value["issued_at_ms"], "transport_request_rejected")
            expires = _uint(value["expires_at_ms"], "transport_request_rejected")
            now = self.clock()
            if not issued - MAX_CLOCK_SKEW_MS <= now < expires or expires <= issued:
                raise RouteError("transport_request_rejected")
            sender_principal = _text(
                value["sender_principal"], "transport_request_rejected"
            )
            sender_body_ref = _text(
                value["sender_body_ref"], "transport_request_rejected"
            )
            unsigned = {
                key: copy.deepcopy(item) for key, item in value.items() if key != "auth"
            }
            presented = unb64url(cast(str, auth["value"]), length=32)
            expected = hmac.digest(self._secret, canonical_bytes(unsigned), "sha256")
            if not hmac.compare_digest(presented, expected):
                raise RouteError("transport_request_rejected")
            request_hash = hashlib.sha256(canonical_bytes(unsigned)).hexdigest()
            try:
                submission = _submission(value["submission"])
                if submission["recipient_id"] != self.recipient_id:
                    raise RouteError("transport_request_refused")
                if (
                    sender_principal.endswith("@localhost")
                    and sender_body_ref != self.recipient_body_ref
                ):
                    raise RouteError("transport_request_refused")
                envelope = unb64url(cast(str, submission["envelope"]))
                if (
                    len(envelope) > MAX_TRANSPORT_BYTES
                    or hashlib.sha256(envelope).hexdigest()
                    != submission["envelope_sha256"]
                ):
                    raise RouteError("transport_request_refused")
                metadata = inspect_delivery(envelope, at_ms=now)
                if (
                    metadata["delivery_id"] != submission["delivery_id"]
                    or metadata["event_id"] != submission["message_id"]
                    or self.recipient_id not in metadata["recipient_embodiment_ids"]
                ):
                    raise RouteError("transport_request_refused")
                if self.intake_gate is not None:
                    assert self.presence_ref is not None
                    assert self.fence_ref is not None
                    self.intake_gate(self.presence_ref, self.fence_ref)
                if self.intake_validator is not None:
                    self.intake_validator(envelope)
                intake = self.inbox.ingest(
                    request_id=request_id,
                    request_hash=request_hash,
                    recipient_id=self.recipient_id,
                    envelope=envelope,
                )
            except (RouteError, SealedDeliveryError, CanonicalError, ValueError):
                evidence = _opaque_evidence(
                    {
                        "provider_ref": self.provider_ref,
                        "request_sha256": request_hash,
                        "route_ref": self.route_ref,
                        "status": "refused",
                    }
                )
                return self._response(
                    request_id=request_id,
                    request_hash=request_hash,
                    status="refused",
                    outcome="refused",
                    evidence_ref=evidence,
                    intake=None,
                )
            intake_evidence: dict[str, Any] | None = None
            outcome = "hub-accepted" if self.hub else "recipient-intake"
            if not self.hub:
                intake_evidence = {
                    "schema": "dm.transport-intake/v1",
                    "delivery_id": submission["delivery_id"],
                    "recipient_id": self.recipient_id,
                    "recipient_body_ref": self.recipient_body_ref,
                    "envelope_sha256": submission["envelope_sha256"],
                    "accepted_at_ms": intake["received_at_ms"],
                    "evidence_ref": intake["evidence_ref"],
                    "presence_ref": self.presence_ref,
                    "fence_ref": self.fence_ref,
                }
            return self._response(
                request_id=request_id,
                request_hash=request_hash,
                status="accepted",
                outcome=outcome,
                evidence_ref=cast(str, intake["evidence_ref"]),
                intake=intake_evidence,
            )
        except (
            RouteError,
            SealedDeliveryError,
            CanonicalError,
            ValueError,
        ) as exception:
            if isinstance(exception, RouteError):
                raise
            raise RouteError("transport_request_rejected") from exception

    def _response(
        self,
        *,
        request_id: str,
        request_hash: str,
        status: str,
        outcome: str,
        evidence_ref: str,
        intake: Mapping[str, Any] | None,
    ) -> bytes:
        response_unsigned = {
            "schema": TRANSPORT_RESPONSE_SCHEMA,
            "version": TRANSPORT_VERSION,
            "request_id": request_id,
            "request_sha256": request_hash,
            "provider_ref": self.provider_ref,
            "route_ref": self.route_ref,
            "status": status,
            "outcome": outcome,
            "evidence_ref": evidence_ref,
            "intake": copy.deepcopy(intake),
        }
        return canonical_bytes(
            {
                **response_unsigned,
                "auth": {
                    "schema": TRANSPORT_AUTH_SCHEMA,
                    "alg": "HMAC-SHA256",
                    "key_ref": self.key_ref,
                    "value": _auth(self._secret, response_unsigned),
                },
            }
        )


def _decode_canonical(raw: bytes, code: str) -> Mapping[str, Any]:
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_TRANSPORT_BYTES:
        raise RouteError(code)
    try:
        value = json.loads(raw, object_pairs_hook=_unique_object)
        if not isinstance(value, Mapping) or canonical_bytes(value) != raw:
            raise RouteError(code)
        return value
    except (
        CanonicalError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
    ) as exception:
        raise RouteError(code) from exception


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RouteError("duplicate_transport_field")
        result[key] = value
    return result


def _submission(value: Any) -> Mapping[str, Any]:
    row = _closed(
        value,
        {
            "attempt_id",
            "deadline_ms",
            "delivery_id",
            "envelope",
            "envelope_sha256",
            "leg_id",
            "message_id",
            "recipient_id",
            "schema",
        },
        "invalid_route_submission",
    )
    if row["schema"] != ROUTE_SUBMISSION_SCHEMA:
        raise RouteError("unsupported_route_submission")
    for field in ("attempt_id", "delivery_id", "message_id"):
        _uuid(row[field], "invalid_route_submission")
    for field in ("leg_id", "recipient_id"):
        _text(row[field], "invalid_route_submission")
    _digest(row["envelope_sha256"], "invalid_route_submission")
    _uint(row["deadline_ms"], "invalid_route_submission")
    envelope = unb64url(cast(str, row["envelope"]))
    if not envelope or len(envelope) > MAX_TRANSPORT_BYTES:
        raise RouteError("invalid_route_submission")
    return row


class AuthenticatedProvider:
    """A body-bound authenticated provider over an injected byte round trip."""

    def __init__(
        self,
        *,
        provider_ref: str,
        route_ref: str,
        route_class: str,
        key_ref: str,
        secret: bytes,
        sender_principal: str,
        sender_body_ref: str,
        round_trip: RoundTrip,
        clock: Clock,
        available: bool = True,
    ) -> None:
        for value in (
            provider_ref,
            route_ref,
            key_ref,
            sender_principal,
            sender_body_ref,
        ):
            _text(value, "invalid_route_provider")
        if route_class not in _CLASS_ORDER or len(secret) != 32:
            raise RouteError("invalid_route_provider")
        self._provider_ref = provider_ref
        self._route_ref = route_ref
        self._route_class = route_class
        self._key_ref = key_ref
        self._secret = bytes(secret)
        self._sender_principal = sender_principal
        self._sender_body_ref = sender_body_ref
        self._round_trip = round_trip
        self._clock = clock
        self._available = available

    @property
    def provider_ref(self) -> str:
        return self._provider_ref

    @property
    def route_ref(self) -> str:
        return self._route_ref

    @property
    def route_class(self) -> str:
        return self._route_class

    def inspect(self) -> Mapping[str, Any]:
        evidence = {
            "provider_ref": self.provider_ref,
            "route_ref": self.route_ref,
            "route_class": self.route_class,
            "available": self._available,
        }
        return {**evidence, "evidence_ref": _opaque_evidence(evidence)}

    def manifest(self) -> Mapping[str, Any]:
        return {
            "schema": PROVIDER_MANIFEST_SCHEMA,
            "provider_ref": self.provider_ref,
            "route_ref": self.route_ref,
            "route_class": self.route_class,
            "versions": [TRANSPORT_VERSION],
            "operations": ["inspect", "submit"],
            "limits": {
                "max_input_bytes": MAX_TRANSPORT_BYTES,
                "max_output_bytes": MAX_TRANSPORT_BYTES,
                "max_runtime_ms": 30_000,
            },
            "authority": {
                "matrix_authority": False,
                "may_append_ledger": False,
                "may_issue_presence": False,
                "may_mint_membership": False,
                "may_sign_as_me": False,
            },
        }

    def deliver(self, submission: Mapping[str, Any]) -> Mapping[str, Any]:
        value = _submission(submission)
        if not self._available:
            return self._result(value, "unavailable", "unavailable", None)
        issued = self._clock()
        expires = cast(int, value["deadline_ms"])
        request_id = str(
            uuid.uuid5(_ATTEMPT_NAMESPACE, f"request:{value['attempt_id']}")
        )
        unsigned = {
            "schema": TRANSPORT_REQUEST_SCHEMA,
            "version": TRANSPORT_VERSION,
            "request_id": request_id,
            "issued_at_ms": issued,
            "expires_at_ms": expires,
            "provider_ref": self.provider_ref,
            "route_ref": self.route_ref,
            "sender_principal": self._sender_principal,
            "sender_body_ref": self._sender_body_ref,
            "submission": copy.deepcopy(dict(value)),
        }
        request_hash = hashlib.sha256(canonical_bytes(unsigned)).hexdigest()
        request = canonical_bytes(
            {
                **unsigned,
                "auth": {
                    "schema": TRANSPORT_AUTH_SCHEMA,
                    "alg": "HMAC-SHA256",
                    "key_ref": self._key_ref,
                    "value": _auth(self._secret, unsigned),
                },
            }
        )
        try:
            raw_response = self._round_trip(request)
        except (ConnectionError, OSError, TimeoutError) as exception:
            raise RouteAmbiguous() from exception
        response = _decode_canonical(raw_response, "transport_response_rejected")
        expected_fields = {
            "auth",
            "evidence_ref",
            "intake",
            "outcome",
            "provider_ref",
            "request_id",
            "request_sha256",
            "route_ref",
            "schema",
            "status",
            "version",
        }
        value_response = _closed(
            response, expected_fields, "transport_response_rejected"
        )
        auth = _closed(
            value_response["auth"],
            {"alg", "key_ref", "schema", "value"},
            "transport_response_rejected",
        )
        response_unsigned = {
            key: copy.deepcopy(item)
            for key, item in value_response.items()
            if key != "auth"
        }
        if (
            value_response["schema"] != TRANSPORT_RESPONSE_SCHEMA
            or value_response["version"] != TRANSPORT_VERSION
            or value_response["request_id"] != request_id
            or value_response["request_sha256"] != request_hash
            or value_response["provider_ref"] != self.provider_ref
            or value_response["route_ref"] != self.route_ref
            or value_response["status"] not in {"accepted", "refused"}
            or value_response["outcome"]
            not in {"recipient-intake", "hub-accepted", "refused"}
            or auth["schema"] != TRANSPORT_AUTH_SCHEMA
            or auth["alg"] != "HMAC-SHA256"
            or auth["key_ref"] != self._key_ref
        ):
            raise RouteError("transport_response_rejected")
        expected_auth = hmac.digest(
            self._secret, canonical_bytes(response_unsigned), "sha256"
        )
        if not hmac.compare_digest(
            unb64url(cast(str, auth["value"]), length=32), expected_auth
        ):
            raise RouteError("transport_response_rejected")
        if (
            value_response["status"] == "accepted"
            and value_response["outcome"] not in {"recipient-intake", "hub-accepted"}
        ) or (
            value_response["status"] == "refused"
            and (
                value_response["outcome"] != "refused"
                or value_response["intake"] is not None
            )
        ):
            raise RouteError("transport_response_rejected")
        if value_response["status"] == "accepted":
            if value_response["outcome"] == "recipient-intake":
                _intake_evidence(value_response["intake"], value)
            elif value_response["intake"] is not None:
                raise RouteError("transport_response_rejected")
        return self._result(
            value,
            cast(str, value_response["status"]),
            cast(str, value_response["outcome"]),
            value_response["intake"],
            evidence_ref=cast(str, value_response["evidence_ref"]),
        )

    def _result(
        self,
        submission: Mapping[str, Any],
        status: str,
        outcome: str,
        intake: Any,
        *,
        evidence_ref: str | None = None,
    ) -> dict[str, Any]:
        evidence = evidence_ref or _opaque_evidence(
            {
                "attempt_id": submission["attempt_id"],
                "provider_ref": self.provider_ref,
                "route_ref": self.route_ref,
                "status": status,
            }
        )
        return {
            "schema": PROVIDER_RESULT_SCHEMA,
            "attempt_id": submission["attempt_id"],
            "provider_ref": self.provider_ref,
            "route_ref": self.route_ref,
            "status": status,
            "outcome": outcome,
            "evidence_ref": evidence,
            "intake": copy.deepcopy(intake),
        }


def _unix_round_trip(path: Path, *, timeout_seconds: float) -> RoundTrip:
    private_path = Path(os.path.abspath(path))

    def call(raw: bytes) -> bytes:
        try:
            info = private_path.lstat()
        except FileNotFoundError as exception:
            raise ConnectionError("transport unavailable") from exception
        if (
            not stat.S_ISSOCK(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & 0o077
        ):
            raise RouteError("unsafe_transport_socket")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(timeout_seconds)
            connection.connect(str(private_path))
            if hasattr(socket, "SO_PEERCRED"):
                peer = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
                _pid, uid, _gid = cast(tuple[int, int, int], struct.unpack("3i", peer))
                if uid != os.geteuid():
                    raise RouteError("unsafe_transport_peer")
            connection.sendall(len(raw).to_bytes(4, "big") + raw)
            header = _recv_exact(connection, 4)
            size = int.from_bytes(header, "big")
            if not 1 <= size <= MAX_TRANSPORT_BYTES:
                raise ConnectionError("invalid transport frame")
            return _recv_exact(connection, size)

    return call


def _recv_exact(connection: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = connection.recv(remaining)
        if not chunk:
            raise ConnectionError("truncated transport frame")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def serve_transport_connection(
    ingress: TransportIngress,
    connection: socket.socket,
    *,
    timeout_seconds: float = 5.0,
) -> None:
    """Serve one bounded authenticated transport frame over an existing socket."""

    connection.settimeout(timeout_seconds)
    header = _recv_exact(connection, 4)
    size = int.from_bytes(header, "big")
    if not 1 <= size <= MAX_TRANSPORT_BYTES:
        raise RouteError("invalid_transport_frame")
    response = ingress.handle(_recv_exact(connection, size))
    connection.sendall(len(response).to_bytes(4, "big") + response)


def _http_round_trip(url: str, *, timeout_seconds: float) -> RoundTrip:
    parsed = urlsplit(url)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.fragment
    ):
        raise RouteError("invalid_provider_endpoint")
    if parsed.query:
        raise RouteError("invalid_provider_endpoint")
    hostname = parsed.hostname
    assert hostname is not None
    port = parsed.port
    target = parsed.path or "/"

    def call(raw: bytes) -> bytes:
        connection_class = (
            http.client.HTTPSConnection
            if parsed.scheme == "https"
            else http.client.HTTPConnection
        )
        connection = connection_class(hostname, port=port, timeout=timeout_seconds)
        try:
            connection.request(
                "POST",
                target,
                body=raw,
                headers={
                    "Content-Type": "application/daimon+jcs",
                    "Content-Length": str(len(raw)),
                },
            )
            response = connection.getresponse()
            body = response.read(MAX_TRANSPORT_BYTES + 1)
            if response.status != 200 or len(body) > MAX_TRANSPORT_BYTES:
                raise ConnectionError("transport unavailable")
            return body
        finally:
            connection.close()

    return call


class LocalIPCProvider(AuthenticatedProvider):
    def __init__(
        self, *, socket_path: Path, timeout_seconds: float = 5.0, **kwargs: Any
    ) -> None:
        super().__init__(
            round_trip=_unix_round_trip(socket_path, timeout_seconds=timeout_seconds),
            **kwargs,
        )


class DirectHTTPProvider(AuthenticatedProvider):
    def __init__(
        self, *, endpoint: str, timeout_seconds: float = 5.0, **kwargs: Any
    ) -> None:
        super().__init__(
            round_trip=_http_round_trip(endpoint, timeout_seconds=timeout_seconds),
            **kwargs,
        )


class HubProvider(DirectHTTPProvider):
    pass


class RouteCoordinator:
    """Select and dispatch routes without acquiring semantic authority."""

    def __init__(
        self,
        store: CommunicationStore,
        profile: RouteProfile,
        providers: Mapping[str, Provider],
        *,
        clock: Clock,
    ) -> None:
        self.store = store
        self.profile = profile
        self.providers = dict(providers)
        self.clock = clock
        for binding in profile.routes:
            provider = self.providers.get(binding.provider_ref)
            if provider is None:
                continue
            if (
                provider.provider_ref != binding.provider_ref
                or provider.route_ref != binding.route_ref
                or provider.route_class != binding.route_class
            ):
                raise RouteError("route_provider_binding_mismatch")
            _provider_manifest(provider.manifest(), binding)

    def _locality_gate(self, message_id: str) -> None:
        if not self.profile.principal_id.endswith("@localhost"):
            return
        result = self.store.result(message_id)
        recipients = [str(row["recipient_id"]) for row in result["legs"]]
        if not recipients or any(
            recipient not in self.profile.local_recipient_ids
            for recipient in recipients
        ):
            raise RouteError("localhost_scope_refused")
        for recipient in recipients:
            if any(
                row.enabled
                and row.recipient_id == recipient
                and (
                    row.route_class != "local"
                    or row.recipient_body_ref != self.profile.body_ref
                )
                for row in self.profile.routes
            ):
                raise RouteError("localhost_scope_refused")

    def inspect(self, *, leg_id: str) -> dict[str, Any]:
        if not self.profile.enabled:
            raise RouteError("route_profile_disabled")
        leg = self.store.leg(leg_id)
        self._locality_gate(cast(str, leg["message_id"]))
        return {
            "schema": "dm.route-inspection/v1",
            "profile_id": self.profile.profile_id,
            "policy_version": POLICY_VERSION,
            "leg_id": leg_id,
            "candidates": self._inspect_candidates(cast(str, leg["recipient_id"])),
        }

    def inspect_recipient(self, *, recipient_id: str) -> dict[str, Any]:
        """Inspect one already-authorized recipient without creating an attempt."""

        if not self.profile.enabled:
            raise RouteError("route_profile_disabled")
        _text(recipient_id, "invalid_route_recipient")
        return {
            "schema": "dm.route-recipient-inspection/v1",
            "profile_id": self.profile.profile_id,
            "policy_version": POLICY_VERSION,
            "recipient_id": recipient_id,
            "candidates": self._inspect_candidates(recipient_id),
        }

    def _inspect_candidates(self, recipient_id: str) -> list[dict[str, Any]]:
        candidates: list[dict[str, Any]] = []
        for binding in self.profile.candidates(recipient_id):
            provider = self.providers.get(binding.provider_ref)
            if provider is None:
                status: Mapping[str, Any] = {
                    "available": False,
                    "evidence_ref": _opaque_evidence(binding.public()),
                }
            else:
                status = _provider_inspection(provider.inspect(), binding)
            candidates.append(
                {
                    "adapter_id": binding.adapter_id,
                    "provider_ref": binding.provider_ref,
                    "route_ref": binding.route_ref,
                    "route_class": binding.route_class,
                    "priority": binding.priority,
                    "available": bool(status["available"]),
                    "evidence_ref": status["evidence_ref"],
                }
            )
        return candidates

    def dispatch(
        self, *, leg_id: str, envelope: bytes, deadline_ms: int
    ) -> dict[str, Any]:
        if not self.profile.enabled:
            raise RouteError("route_profile_disabled")
        if deadline_ms <= self.clock():
            raise RouteError("route_attempt_expired")
        leg = self.store.leg(leg_id)
        if leg["state"] != "accepted":
            raise RouteError("semantic_leg_not_accepted")
        message_id = cast(str, leg["message_id"])
        recipient_id = cast(str, leg["recipient_id"])
        self._locality_gate(message_id)
        try:
            metadata = inspect_delivery(envelope, at_ms=self.clock())
        except SealedDeliveryError as exception:
            raise RouteError("sealed_delivery_rejected") from exception
        if (
            metadata["event_id"] != message_id
            or recipient_id not in metadata["recipient_embodiment_ids"]
        ):
            raise RouteError("route_recipient_mismatch")
        delivery_id = cast(str, metadata["delivery_id"])
        envelope_hash = cast(str, metadata["envelope_sha256"])
        evidence: list[dict[str, Any]] = []
        candidates = self.profile.candidates(recipient_id)
        if not candidates:
            raise RouteError("route_unroutable")
        for binding in candidates:
            provider = self.providers.get(binding.provider_ref)
            if provider is None:
                evidence.append(
                    {
                        "provider_ref": binding.provider_ref,
                        "route_ref": binding.route_ref,
                        "status": "unavailable",
                        "evidence_ref": _opaque_evidence(binding.public()),
                    }
                )
                continue
            attempt_id = str(
                uuid.uuid5(
                    _ATTEMPT_NAMESPACE,
                    f"{leg_id}\0{delivery_id}\0{binding.provider_ref}\0"
                    f"{binding.route_ref}\0{deadline_ms}",
                )
            )
            attempt = {
                "schema": "dm.route-attempt/v1",
                "attempt_id": attempt_id,
                "leg_id": leg_id,
                "provider_ref": binding.provider_ref,
                "route_ref": binding.route_ref,
                "credential_ref": binding.credential_ref,
                "body_ref": binding.recipient_body_ref,
                "deadline_ms": deadline_ms,
            }
            self.store.record_attempt(attempt)
            self.store.record_delivery(
                attempt_id=attempt_id,
                delivery_id=delivery_id,
                envelope_hash=envelope_hash,
            )
            submission = {
                "schema": ROUTE_SUBMISSION_SCHEMA,
                "attempt_id": attempt_id,
                "leg_id": leg_id,
                "message_id": message_id,
                "recipient_id": recipient_id,
                "delivery_id": delivery_id,
                "envelope_sha256": envelope_hash,
                "envelope": b64url(envelope),
                "deadline_ms": deadline_ms,
            }
            try:
                result = dict(provider.deliver(submission))
            except RouteAmbiguous:
                evidence.append(
                    {
                        "provider_ref": binding.provider_ref,
                        "route_ref": binding.route_ref,
                        "status": "ambiguous",
                        "attempt_id": attempt_id,
                    }
                )
                continue
            checked = _provider_result(result, attempt_id, binding, submission)
            status = cast(str, checked["status"])
            if status == "unavailable":
                self.store.record_route_ack(
                    attempt_id=attempt_id, ack=checked, failed=True
                )
                evidence.append(copy.deepcopy(dict(checked)))
                continue
            if status == "refused":
                self.store.record_route_ack(
                    attempt_id=attempt_id, ack=checked, failed=True
                )
                return {
                    "schema": "dm.route-dispatch/v1",
                    "policy_version": POLICY_VERSION,
                    "profile_id": self.profile.profile_id,
                    "leg_id": leg_id,
                    "delivery_id": delivery_id,
                    "status": "refused",
                    "selected": copy.deepcopy(dict(checked)),
                    "attempts": [*evidence, copy.deepcopy(dict(checked))],
                }
            self.store.record_route_ack(
                attempt_id=attempt_id, ack=checked, failed=False
            )
            return {
                "schema": "dm.route-dispatch/v1",
                "policy_version": POLICY_VERSION,
                "profile_id": self.profile.profile_id,
                "leg_id": leg_id,
                "delivery_id": delivery_id,
                "status": "accepted",
                "selected": copy.deepcopy(dict(checked)),
                "attempts": [*evidence, copy.deepcopy(dict(checked))],
            }
        return {
            "schema": "dm.route-dispatch/v1",
            "policy_version": POLICY_VERSION,
            "profile_id": self.profile.profile_id,
            "leg_id": leg_id,
            "delivery_id": delivery_id,
            "status": "pending",
            "selected": None,
            "attempts": evidence,
        }


def _provider_result(
    value: Any,
    attempt_id: str,
    binding: RouteBinding,
    submission: Mapping[str, Any],
) -> Mapping[str, Any]:
    result = _closed(
        value,
        {
            "attempt_id",
            "evidence_ref",
            "intake",
            "outcome",
            "provider_ref",
            "route_ref",
            "schema",
            "status",
        },
        "invalid_provider_result",
    )
    if (
        result["schema"] != PROVIDER_RESULT_SCHEMA
        or result["attempt_id"] != attempt_id
        or result["provider_ref"] != binding.provider_ref
        or result["route_ref"] != binding.route_ref
        or result["status"] not in {"accepted", "unavailable", "refused"}
        or result["outcome"]
        not in {"recipient-intake", "hub-accepted", "unavailable", "refused"}
    ):
        raise RouteError("invalid_provider_result")
    _text(result["evidence_ref"], "invalid_provider_result")
    expected_accepted = (
        "hub-accepted" if binding.route_class == "hub" else "recipient-intake"
    )
    if (
        (result["status"] == "accepted" and result["outcome"] != expected_accepted)
        or (result["status"] == "unavailable" and result["outcome"] != "unavailable")
        or (result["status"] == "refused" and result["outcome"] != "refused")
    ):
        raise RouteError("invalid_provider_result")
    if result["status"] != "accepted" and result["intake"] is not None:
        raise RouteError("invalid_provider_result")
    if result["status"] == "accepted":
        if binding.route_class == "hub":
            if result["intake"] is not None:
                raise RouteError("invalid_provider_result")
        else:
            intake = _intake_evidence(result["intake"], submission)
            if intake["recipient_body_ref"] != binding.recipient_body_ref:
                raise RouteError("invalid_provider_result")
    return result


def _provider_inspection(value: Any, binding: RouteBinding) -> Mapping[str, Any]:
    inspection = _closed(
        value,
        {
            "available",
            "evidence_ref",
            "provider_ref",
            "route_class",
            "route_ref",
        },
        "invalid_provider_inspection",
    )
    if (
        inspection["provider_ref"] != binding.provider_ref
        or inspection["route_ref"] != binding.route_ref
        or inspection["route_class"] != binding.route_class
        or not isinstance(inspection["available"], bool)
    ):
        raise RouteError("invalid_provider_inspection")
    _text(inspection["evidence_ref"], "invalid_provider_inspection")
    return inspection


def _intake_evidence(value: Any, submission: Mapping[str, Any]) -> Mapping[str, Any]:
    intake = _closed(
        value,
        {
            "accepted_at_ms",
            "delivery_id",
            "envelope_sha256",
            "evidence_ref",
            "fence_ref",
            "presence_ref",
            "recipient_body_ref",
            "recipient_id",
            "schema",
        },
        "transport_response_rejected",
    )
    if (
        intake["schema"] != "dm.transport-intake/v1"
        or intake["delivery_id"] != submission["delivery_id"]
        or intake["recipient_id"] != submission["recipient_id"]
        or intake["envelope_sha256"] != submission["envelope_sha256"]
        or (intake["presence_ref"] is None) != (intake["fence_ref"] is None)
    ):
        raise RouteError("transport_response_rejected")
    _uint(intake["accepted_at_ms"], "transport_response_rejected")
    for field in ("evidence_ref", "recipient_body_ref"):
        _text(intake[field], "transport_response_rejected")
    for field in ("presence_ref", "fence_ref"):
        if intake[field] is not None:
            _text(intake[field], "transport_response_rejected")
    return intake


def _provider_manifest(value: Any, binding: RouteBinding) -> Mapping[str, Any]:
    manifest = _closed(
        value,
        {
            "authority",
            "limits",
            "operations",
            "provider_ref",
            "route_class",
            "route_ref",
            "schema",
            "versions",
        },
        "invalid_provider_manifest",
    )
    authority = _closed(
        manifest["authority"],
        {
            "matrix_authority",
            "may_append_ledger",
            "may_issue_presence",
            "may_mint_membership",
            "may_sign_as_me",
        },
        "invalid_provider_manifest",
    )
    limits = _closed(
        manifest["limits"],
        {"max_input_bytes", "max_output_bytes", "max_runtime_ms"},
        "invalid_provider_manifest",
    )
    if (
        manifest["schema"] != PROVIDER_MANIFEST_SCHEMA
        or manifest["provider_ref"] != binding.provider_ref
        or manifest["route_ref"] != binding.route_ref
        or manifest["route_class"] != binding.route_class
        or manifest["versions"] != [TRANSPORT_VERSION]
        or manifest["operations"] != ["inspect", "submit"]
        or any(value is not False for value in authority.values())
    ):
        raise RouteError("invalid_provider_manifest")
    for limit in limits.values():
        _uint(limit, "invalid_provider_manifest", minimum=1)
    return manifest


@dataclass(frozen=True)
class GatewayPolicy:
    gateway_ref: str
    enabled: bool
    destinations: frozenset[str]
    operations: frozenset[str]
    classifications: frozenset[str]
    source_scopes: frozenset[str]
    max_chunk_bytes: int

    @classmethod
    def from_value(
        cls,
        value: Any,
        *,
        authority_validator: GatewayPolicyValidator | None = None,
    ) -> GatewayPolicy:
        policy = _closed(
            value,
            {
                "classifications",
                "destinations",
                "enabled",
                "gateway_ref",
                "max_chunk_bytes",
                "operations",
                "schema",
                "source_scopes",
            },
            "invalid_gateway_policy",
        )
        if policy["schema"] != GATEWAY_POLICY_SCHEMA or not isinstance(
            policy["enabled"], bool
        ):
            raise RouteError("invalid_gateway_policy")
        gateway_ref = _text(policy["gateway_ref"], "invalid_gateway_policy")

        def values(field: str) -> frozenset[str]:
            rows = policy[field]
            if (
                not isinstance(rows, list)
                or len(rows) > 128
                or rows != sorted(set(rows))
            ):
                raise RouteError("invalid_gateway_policy")
            for row in rows:
                _text(row, "invalid_gateway_policy")
            return frozenset(cast(list[str], rows))

        maximum = _uint(policy["max_chunk_bytes"], "invalid_gateway_policy", minimum=64)
        if maximum > 16_384:
            raise RouteError("invalid_gateway_policy")
        if policy["enabled"]:
            if authority_validator is None:
                raise RouteError("gateway_policy_authority_required")
            try:
                authority_validator(copy.deepcopy(dict(policy)))
            except (RouteError, ValueError) as exception:
                raise RouteError("gateway_policy_authority_rejected") from exception
        return cls(
            gateway_ref=gateway_ref,
            enabled=policy["enabled"],
            destinations=values("destinations"),
            operations=values("operations"),
            classifications=values("classifications"),
            source_scopes=values("source_scopes"),
            max_chunk_bytes=maximum,
        )


def render_gateway(
    policy: GatewayPolicy,
    *,
    destination: str,
    operation: str,
    classification: str,
    source_scope: str,
    source_ref: str,
    message_id: str,
    text: str,
) -> dict[str, Any]:
    for value in (destination, operation, classification, source_scope, source_ref):
        _text(value, "gateway_render_refused")
    _uuid(message_id, "gateway_render_refused")
    _free_text(text, "gateway_render_refused", maximum=192 * 1024)
    if (
        not policy.enabled
        or destination not in policy.destinations
        or operation not in policy.operations
        or classification not in policy.classifications
        or source_scope not in policy.source_scopes
    ):
        raise RouteError("gateway_render_refused")
    rendered = (
        f"[{html.escape(source_ref, quote=True)} {message_id}] "
        f"{html.escape(text, quote=True)}"
    )
    chunks = _utf8_chunks(rendered, policy.max_chunk_bytes)
    return {
        "schema": GATEWAY_RENDER_SCHEMA,
        "gateway_ref": policy.gateway_ref,
        "destination": destination,
        "operation": operation,
        "classification": classification,
        "source_scope": source_scope,
        "source_ref": source_ref,
        "message_id": message_id,
        "chunks": chunks,
    }


def _utf8_chunks(value: str, maximum: int) -> list[str]:
    chunks: list[str] = []
    current = ""
    size = 0
    for character in value:
        encoded = character.encode("utf-8")
        if size and size + len(encoded) > maximum:
            chunks.append(current)
            current = ""
            size = 0
        if len(encoded) > maximum:
            raise RouteError("gateway_character_too_large")
        current += character
        size += len(encoded)
    if current:
        chunks.append(current)
    return chunks


def gateway_proposal(
    *,
    gateway_ref: str,
    destination: str,
    external_id: str,
    observed_at_ms: int,
    text: str,
) -> dict[str, Any]:
    for value in (gateway_ref, destination, external_id):
        _text(value, "invalid_gateway_proposal")
    _uint(observed_at_ms, "invalid_gateway_proposal")
    _free_text(text, "invalid_gateway_proposal", maximum=64 * 1024)
    return {
        "schema": GATEWAY_PROPOSAL_SCHEMA,
        "authority": "external-source-only",
        "gateway_ref": gateway_ref,
        "destination": destination,
        "external_id": external_id,
        "observed_at_ms": observed_at_ms,
        "body": {"text": text},
    }


__all__ = [
    "GATEWAY_POLICY_SCHEMA",
    "GATEWAY_PROPOSAL_SCHEMA",
    "GATEWAY_RENDER_SCHEMA",
    "INBOX_CLAIM_SCHEMA",
    "INBOX_ITEM_SCHEMA",
    "POLICY_VERSION",
    "PROVIDER_MANIFEST_SCHEMA",
    "PROVIDER_RESULT_SCHEMA",
    "ROUTE_BINDING_SCHEMA",
    "ROUTE_PROFILE_SCHEMA",
    "ROUTE_SUBMISSION_SCHEMA",
    "TRANSPORT_REQUEST_SCHEMA",
    "TRANSPORT_RESPONSE_SCHEMA",
    "AuthenticatedProvider",
    "DirectHTTPProvider",
    "GatewayPolicy",
    "HubProvider",
    "LocalIPCProvider",
    "OpaqueInbox",
    "Provider",
    "RouteAmbiguous",
    "RouteBinding",
    "RouteCoordinator",
    "RouteError",
    "RouteProfile",
    "TransportIngress",
    "gateway_proposal",
    "render_gateway",
    "serve_transport_connection",
]
