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
import io
import ipaddress
import json
import math
import os
import socket
import sqlite3
import ssl
import stat
import struct
import time
import uuid
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Protocol, cast
from urllib.parse import urlsplit

from .canonical import CanonicalError, b64url, canonical_bytes, unb64url
from .communication import CommunicationError, CommunicationStore
from .mandatory_echo import (
    INTAKE_FAILURE_CODES,
    LOCAL_EGRESS_DIAGNOSTIC_CODES,
    write_diagnostic,
)
from .native_egress import (
    MandatoryEgressController,
    NativeEgressError,
    OperationBinding,
)
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


def _intake_failure_code(failure: Exception) -> str:
    """Closed local diagnostics; exception text never becomes retained payload."""
    current: BaseException | None = failure
    result = "intake_failure_unknown"
    for _ in range(5):
        if current is None:
            break
        if isinstance(current, sqlite3.Error):
            code = getattr(current, "sqlite_errorcode", None)
            if isinstance(code, int) and code & 255 in (
                sqlite3.SQLITE_BUSY,
                sqlite3.SQLITE_LOCKED,
            ):
                return "intake_storage_busy"
            return "intake_storage_unavailable"
        code = current.code if isinstance(current, RouteError) else str(current)
        if code in INTAKE_FAILURE_CODES:
            result = "intake_" + code
        if isinstance(current, OSError):
            result = "intake_storage_unavailable"
        current = current.__cause__
    return result


@dataclass(frozen=True)
class _AttemptDeadline:
    """One monotonic budget; successful partial I/O never renews it."""

    deadline_ns: int

    @classmethod
    def start(
        cls, seconds: float, *, deadline_ms: int, clock: Clock, started_ns: int
    ) -> _AttemptDeadline:
        if (
            isinstance(seconds, bool)
            or not isinstance(seconds, (int, float))
            or not math.isfinite(seconds)
            or not 0 < seconds <= 60
        ):
            raise RouteError("invalid_transport_deadline")
        remaining = (deadline_ms - clock()) / 1000
        return cls(started_ns + int(min(seconds, remaining) * 1_000_000_000))

    def remaining(self) -> float:
        seconds = (self.deadline_ns - time.monotonic_ns()) / 1_000_000_000
        if seconds <= 0:
            raise TimeoutError("transport attempt deadline")
        return seconds

    def child(self, seconds: float) -> _AttemptDeadline:
        return _AttemptDeadline(
            min(self.deadline_ns, time.monotonic_ns() + int(seconds * 1_000_000_000))
        )


class _DeadlineReader(io.RawIOBase):
    """Keep http.client's status/header/chunk loops inside the same budget."""

    def __init__(self, connection: _DeadlineSocket) -> None:
        self._connection = connection
        connection._reader_count += 1

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: Any) -> int:
        raw = self._connection.recv(len(buffer))
        buffer[: len(raw)] = raw
        return len(raw)

    def close(self) -> None:
        if not self.closed:
            try:
                super().close()
            finally:
                self._connection._reader_count -= 1
                self._connection._close_if_unused()


class _DeadlineSocket:
    """Owned socket with deadline-aware raw reads and complete offset writes."""

    def __init__(self, connection: socket.socket, deadline: _AttemptDeadline) -> None:
        self.connection = connection
        self.deadline = deadline
        self._reader_count = 0
        self._close_requested = False
        self._timeout_cap: float | None = None

    def _io_timeout(self) -> float:
        remaining = self.deadline.remaining()
        return (
            remaining
            if self._timeout_cap is None
            else min(remaining, self._timeout_cap)
        )

    def settimeout(self, seconds: float | None) -> None:
        self._timeout_cap = seconds

    def gettimeout(self) -> float | None:
        return self._timeout_cap

    def fileno(self) -> int:
        return self.connection.fileno()

    def shutdown(self, how: int) -> None:
        self.connection.shutdown(how)

    def setsockopt(self, level: int, option: int, value: Any) -> None:
        self.connection.setsockopt(level, option, value)

    def recv(self, size: int) -> bytes:
        self.connection.settimeout(self._io_timeout())
        raw = self.connection.recv(size)
        self.deadline.remaining()
        return raw

    def sendall(self, raw: bytes) -> None:
        remaining = memoryview(raw)
        while remaining:
            self.connection.settimeout(self._io_timeout())
            size = self.connection.send(remaining)
            self.deadline.remaining()
            if size <= 0:
                raise ConnectionError("transport write incomplete")
            remaining = remaining[size:]

    def makefile(self, mode: str = "r", buffering: int | None = None) -> Any:
        if mode != "rb":
            raise RouteError("unsupported_transport_stream")
        if self._close_requested:
            raise ConnectionError("transport stream closed")
        # Retain socket.makefile's ownership rule: http.client can close its
        # connection after headers while its response reader still owns the body.
        # Raw reads still go through the same deadline rather than socket.makefile.
        return io.BufferedReader(_DeadlineReader(self), buffer_size=8192)

    def close(self) -> None:
        self._close_requested = True
        self._close_if_unused()

    def _close_if_unused(self) -> None:
        if self._close_requested and self._reader_count == 0:
            self.connection.close()


@dataclass(frozen=True)
class _TransportExchange:
    write: Callable[[bytes], None]
    read: Callable[[], bytes]
    close: Callable[[], None]


@dataclass(frozen=True)
class _SplitRoundTrip:
    """Maintained adapters release bytes under the fence, then wait outside it."""

    open: Callable[[], _TransportExchange]
    bounded_open: Callable[[_AttemptDeadline], _TransportExchange] | None = None
    total_timeout_seconds: float | None = None

    def __call__(self, raw: bytes) -> bytes:
        exchange = (
            self.open()
            if self.bounded_open is None
            else self.bounded_open(
                _AttemptDeadline(
                    time.monotonic_ns()
                    + int(cast(float, self.total_timeout_seconds) * 1_000_000_000)
                )
            )
        )
        try:
            exchange.write(raw)
            return exchange.read()
        finally:
            exchange.close()


@dataclass(frozen=True)
class RouteEgressSpec:
    controller: MandatoryEgressController
    catalog_id: str
    path_id: str
    deadline_ms: int
    authority_head: str
    projection: Mapping[str, Any]


IntakeValidator = Callable[[bytes], None]


@dataclass(frozen=True)
class DurableIntakeTicket:
    """Owner-local committed intake, with per-request technical completion."""

    received_at_ms: int
    metadata: Mapping[str, Any]
    acknowledge: Callable[[bytes], None]
    after_response: Callable[[], None]
    after_response_bounded: Callable[[int], None] | None = None


@dataclass(frozen=True)
class TransportReply:
    """HTTP writes the exact ACK before invoking its retained completion ticket."""

    response: bytes
    after_response: Callable[[], None]
    release_writer: Callable[[Callable[[bytes], None], int], None] | None = None
    after_response_bounded: Callable[[int], None] | None = None

    def write_to(self, writer: Callable[[bytes], None], *, deadline_ns: int) -> None:
        if self.release_writer is None:
            raise RouteError("transport_owned_reply_required")
        self.release_writer(writer, deadline_ns)

    def complete(self, *, deadline_ns: int) -> None:
        if time.monotonic_ns() >= deadline_ns:
            return  # Durable intent remains pending; no new work is started.
        if self.after_response_bounded is not None:
            self.after_response_bounded(deadline_ns)
        else:
            self.after_response()


IntakeAdmission = Callable[[Mapping[str, Any]], DurableIntakeTicket]
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

    def __init__(
        self, code: str = "route_result_unknown", *, fallback_allowed: bool = True
    ) -> None:
        super().__init__(code, retryable=True)
        self.fallback_allowed = fallback_allowed


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

    def prepare_submission(self, submission: Mapping[str, Any]) -> bytes: ...

    def send_prepared(self, request: bytes) -> Mapping[str, Any]: ...

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
                "delivery_id TEXT NOT NULL, response BLOB, response_sha256 TEXT, "
                "egress_path_id TEXT);"
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
        response_factory: Callable[[Mapping[str, Any]], tuple[bytes, RouteEgressSpec]]
        | None = None,
        carrier_inspector: Callable[..., Mapping[str, Any]] = inspect_delivery,
    ) -> dict[str, Any]:
        _uuid(request_id, "invalid_transport_request")
        _digest(request_hash, "invalid_transport_request")
        _text(recipient_id, "invalid_transport_request")
        metadata = carrier_inspector(envelope, at_ms=self.clock())
        return self._finalize_retained_intake(
            request_id=request_id,
            request_hash=request_hash,
            recipient_id=recipient_id,
            envelope=envelope,
            metadata=metadata,
            received_at_ms=self.clock(),
            response_factory=response_factory,
        )

    def _finalize_retained_intake(
        self,
        *,
        request_id: str,
        request_hash: str,
        recipient_id: str,
        envelope: bytes,
        metadata: Mapping[str, Any],
        received_at_ms: int,
        response_factory: Callable[[Mapping[str, Any]], tuple[bytes, RouteEgressSpec]]
        | None = None,
    ) -> dict[str, Any]:
        """Owner-local bookkeeping from validated durable intake, not wire admission.

        The group owner verifies its signed admission, readable inbox and exact
        receipt obligation before invoking this path. It neither decrypts a frame
        nor supplies fresh transmission permission after expiry.
        """
        _uuid(request_id, "invalid_transport_request")
        _digest(request_hash, "invalid_transport_request")
        _text(recipient_id, "invalid_transport_request")
        _uint(received_at_ms, "invalid_transport_request")
        # Persist the exact outer carrier, even when inspection opens a sealed
        # envelope inside a group frame or validates a signed receipt frame.
        envelope_hash = hashlib.sha256(envelope).hexdigest()
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
                    received = received_at_ms
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
                        "INSERT INTO inbox_requests "
                        "(request_id, request_hash, delivery_id) VALUES (?, ?, ?)",
                        (request_id, request_hash, delivery_id),
                    )
                assert row is not None
                evidence = {
                    "delivery_id": delivery_id,
                    "envelope_sha256": envelope_hash,
                    "received_at_ms": int(row["received_at_ms"]),
                    "recipient_id": recipient_id,
                    "sequence": int(row["sequence"]),
                }
                result = {
                    "schema": INBOX_ITEM_SCHEMA,
                    **evidence,
                    "evidence_ref": _opaque_evidence(evidence),
                    "replayed": replayed,
                    "state": "acked" if tombstone is not None else str(row["state"]),
                }
                if response_factory is not None:
                    response, spec = response_factory(result)
                    if spec.deadline_ms <= self.clock():
                        # An expired retained ACK is history, not a newly admitted
                        # egress operation. The group persists its exact bytes in
                        # the signed intake-ack record; ordinary ingest cannot
                        # enter here because it rechecks the carrier's lifetime.
                        retained_response = database.execute(
                            "SELECT response,response_sha256,egress_path_id "
                            "FROM inbox_requests WHERE request_id=?",
                            (request_id,),
                        ).fetchone()
                        if retained_response["response"] is not None and (
                            bytes(retained_response["response"]) != response
                            or retained_response["response_sha256"]
                            != hashlib.sha256(response).hexdigest()
                            or retained_response["egress_path_id"] != spec.path_id
                        ):
                            raise RouteError("transport_response_conflict")
                        result["_historical_response"] = True
                    else:
                        self._admit_response(
                            database,
                            request_id=request_id,
                            request_hash=request_hash,
                            response=response,
                            spec=spec,
                        )
                    result["_egress_response"] = response
                database.commit()
                return result
            except BaseException:
                if database.in_transaction:
                    database.rollback()
                raise

    def _admit_response(
        self,
        database: sqlite3.Connection,
        *,
        request_id: str,
        request_hash: str,
        response: bytes,
        spec: RouteEgressSpec,
    ) -> None:
        digest = hashlib.sha256(response).hexdigest()
        row = database.execute(
            "SELECT request_hash, response, response_sha256, egress_path_id "
            "FROM inbox_requests WHERE request_id=?",
            (request_id,),
        ).fetchone()
        if row is None or row["request_hash"] != request_hash:
            raise RouteError("transport_response_conflict")
        if row["response"] is None:
            if row["response_sha256"] is not None or row["egress_path_id"] is not None:
                raise RouteError("transport_response_conflict")
            database.execute(
                "UPDATE inbox_requests SET response=?, response_sha256=?, "
                "egress_path_id=? WHERE request_id=?",
                (response, digest, spec.path_id, request_id),
            )
        elif (
            bytes(row["response"]) != response
            or row["response_sha256"] != digest
            or row["egress_path_id"] != spec.path_id
        ):
            raise RouteError("transport_response_conflict")
        spec.controller.admit_in_transaction(
            database,
            catalog_id=spec.catalog_id,
            path_id=spec.path_id,
            operation_id=request_id,
            locator=request_id,
            native_bytes=response,
            projection=spec.projection,
            deadline_ms=spec.deadline_ms,
            authority_head=spec.authority_head,
        )

    def admit_response(
        self,
        *,
        request_id: str,
        request_hash: str,
        delivery_id: str,
        response: bytes,
        spec: RouteEgressSpec,
    ) -> None:
        with self._database() as database:
            database.execute("BEGIN IMMEDIATE")
            row = database.execute(
                "SELECT request_hash, delivery_id FROM inbox_requests "
                "WHERE request_id=?",
                (request_id,),
            ).fetchone()
            if row is None:
                database.execute(
                    "INSERT INTO inbox_requests "
                    "(request_id, request_hash, delivery_id) VALUES (?, ?, ?)",
                    (request_id, request_hash, delivery_id),
                )
            elif (
                row["request_hash"] != request_hash or row["delivery_id"] != delivery_id
            ):
                raise RouteError("transport_request_conflict")
            self._admit_response(
                database,
                request_id=request_id,
                request_hash=request_hash,
                response=response,
                spec=spec,
            )
            database.commit()

    def resolve_response(self, request_id: str) -> bytes:
        with self._database() as database:
            row = database.execute(
                "SELECT response, response_sha256 FROM inbox_requests "
                "WHERE request_id=?",
                (request_id,),
            ).fetchone()
        if row is None or not isinstance(row[0], bytes):
            raise RouteError("transport_response_missing")
        response = bytes(row[0])
        if hashlib.sha256(response).hexdigest() != row[1]:
            raise RouteError("transport_response_conflict")
        return response

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
        recipient_embodiment_id: str | None = None,
        inbox: OpaqueInbox,
        clock: Clock,
        egress: MandatoryEgressController,
        egress_catalog_id: str,
        egress_authority_head: str | None = None,
        egress_authorizer: Callable[[OperationBinding], bool] | None = None,
        hub: bool = False,
        presence_ref: str | None = None,
        fence_ref: str | None = None,
        intake_validator: IntakeValidator | None = None,
        intake_admission: IntakeAdmission | None = None,
        intake_gate: IntakeGate | None = None,
        store_guard: Callable[[], None] | None = None,
        carrier_inspector: Callable[..., Mapping[str, Any]] = inspect_delivery,
    ) -> None:
        for value in (
            provider_ref,
            route_ref,
            key_ref,
            recipient_id,
            recipient_body_ref,
        ):
            _text(value, "invalid_transport_ingress")
        concrete_recipient = (
            recipient_id if recipient_embodiment_id is None else recipient_embodiment_id
        )
        _text(concrete_recipient, "invalid_transport_ingress")
        if (presence_ref is None) != (fence_ref is None) or (presence_ref is None) != (
            intake_gate is None
        ):
            raise RouteError("incomplete_intake_gate")
        if not hub and intake_validator is None and intake_admission is None:
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
        self.recipient_embodiment_id = concrete_recipient
        self.inbox = inbox
        self.clock = clock
        if not isinstance(egress, MandatoryEgressController):
            raise RouteError("transport_egress_required")
        if egress_authority_head is None and egress_authorizer is None:
            if getattr(egress, "_catalog_mode", None) != "synthetic":
                raise RouteError("transport_egress_authority_required")
            egress_authority_head = (
                "synthetic-route-authority:"
                + hashlib.sha256(egress_catalog_id.encode()).hexdigest()
            )
            expected_synthetic_head = egress_authority_head

            def synthetic_authorizer(binding: OperationBinding) -> bool:
                return binding.authority_head == expected_synthetic_head

            egress_authorizer = synthetic_authorizer
        if egress_authority_head is None or egress_authorizer is None:
            raise RouteError("transport_egress_authority_required")
        authority_head = _text(
            egress_authority_head, "transport_egress_authority_required"
        )
        if not callable(egress_authorizer):
            raise RouteError("transport_egress_authority_required")
        self.egress = egress
        self.egress_catalog_id = egress_catalog_id
        self.egress_authority_head = authority_head
        self.egress_authorizer = egress_authorizer
        egress.register_catalog(
            catalog_id=egress_catalog_id,
            path=inbox.path,
            resolve=lambda locator: inbox.resolve_response(locator),
            authorize=self._authorize_egress,
        )
        egress.register_path("messaging-evidence-result", egress_catalog_id)
        egress.register_path("messaging-message-result", egress_catalog_id)
        self.hub = hub
        self.presence_ref = presence_ref
        self.fence_ref = fence_ref
        self.intake_validator = intake_validator
        self.intake_admission = intake_admission
        self.intake_gate = intake_gate
        self.store_guard = store_guard
        self.carrier_inspector = carrier_inspector

    def _authorize_egress(self, binding: OperationBinding) -> bool:
        if binding.authority_head != self.egress_authority_head:
            return False
        try:
            return self.egress_authorizer(binding) is True
        except Exception:
            return False

    def handle(self, raw: bytes) -> bytes:
        """Existing byte-only API for ordinary synchronous transport adapters."""
        if self.intake_admission is not None:
            raise RouteError("transport_owned_reply_required")
        response = self.handle_deferred(raw)
        assert isinstance(response, bytes)
        return response

    def handle_deferred(
        self, raw: bytes, *, socket_writer: bool = False
    ) -> bytes | TransportReply:
        """Owned adapters write the ACK before consuming technical completion."""
        ticket = None
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
            # Authentication precedes local storage observation. A changed
            # loaded store is uncertain before semantic admission or refusal
            # persistence; it must never become a sticky peer refusal.
            if self.store_guard is not None:
                self.store_guard()
            intake_stage = "intake-validation"
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
                metadata = self.carrier_inspector(envelope, at_ms=now)
                if (
                    metadata["delivery_id"] != submission["delivery_id"]
                    or metadata["event_id"] != submission["message_id"]
                    or self.recipient_embodiment_id
                    not in metadata["recipient_embodiment_ids"]
                ):
                    raise RouteError("transport_request_refused")
                if self.intake_gate is not None:
                    assert self.presence_ref is not None
                    assert self.fence_ref is not None
                    self.intake_gate(self.presence_ref, self.fence_ref)
                if self.intake_admission is not None:
                    intake_stage = "intake-admission"
                    ticket = self.intake_admission(
                        {
                            "request": dict(value),
                            "request_hash": request_hash,
                            "metadata": dict(metadata),
                            "binding": self.intake_binding(),
                        }
                    )
                elif self.intake_validator is not None:
                    self.intake_validator(envelope)

                def response_factory(
                    item: Mapping[str, Any],
                ) -> tuple[bytes, RouteEgressSpec]:
                    return self._accepted_response(value, request_hash, item)

                if ticket is None:
                    intake = self.inbox.ingest(
                        request_id=request_id,
                        request_hash=request_hash,
                        recipient_id=self.recipient_id,
                        envelope=envelope,
                        response_factory=response_factory,
                        carrier_inspector=self.carrier_inspector,
                    )
                else:
                    intake_stage = "intake-ack-transaction"
                    intake = self.inbox._finalize_retained_intake(
                        request_id=request_id,
                        request_hash=request_hash,
                        recipient_id=self.recipient_id,
                        envelope=envelope,
                        metadata=ticket.metadata,
                        received_at_ms=ticket.received_at_ms,
                        response_factory=response_factory,
                    )
                    intake_stage = "intake-ack-record"
                    ticket.acknowledge(intake["_egress_response"])
            except (
                RouteError,
                SealedDeliveryError,
                CanonicalError,
                ValueError,
                OSError,
                sqlite3.Error,
            ) as failure:
                if intake_stage != "intake-validation":
                    # Transaction cleanup precedes this independent sidecar.
                    # Observability must not replace the retained-intake result.
                    with suppress(ValueError, OSError, sqlite3.Error):
                        write_diagnostic(
                            self.inbox.path,
                            intake_stage,
                            request_id,
                            _intake_failure_code(failure),
                            self.clock(),
                        )
                if ticket is not None:
                    raise RouteAmbiguous(
                        "transport_intake_recovery_pending"
                    ) from failure
                if isinstance(failure, RouteError) and failure.retryable:
                    raise
                if isinstance(failure, (OSError, sqlite3.Error)):
                    raise RouteAmbiguous(
                        "transport_intake_storage_unavailable"
                    ) from failure
                evidence = _opaque_evidence(
                    {
                        "provider_ref": self.provider_ref,
                        "request_sha256": request_hash,
                        "route_ref": self.route_ref,
                        "status": "refused",
                    }
                )
                response = self._response(
                    request_id=request_id,
                    request_hash=request_hash,
                    status="refused",
                    outcome="refused",
                    evidence_ref=evidence,
                    intake=None,
                )
                refused_delivery = request_id
                stage = "evidence"
                if "submission" in value and isinstance(value["submission"], Mapping):
                    refused_delivery = str(
                        value["submission"].get("delivery_id", request_id)
                    )
                    if str(value["submission"].get("leg_id", "")).endswith("message"):
                        stage = "message"
                projection = {
                    "event_id": request_id,
                    "event_digest": request_hash,
                    "sender": self.recipient_id,
                    "recipients": [sender_principal],
                    "thread_id": request_id,
                    "reply_to": None,
                    "kind": "transport-result",
                    "content": {"stage": stage, "outcome": "refused"},
                }
                self.inbox.admit_response(
                    request_id=request_id,
                    request_hash=request_hash,
                    delivery_id=refused_delivery,
                    response=response,
                    spec=RouteEgressSpec(
                        controller=self.egress,
                        catalog_id=self.egress_catalog_id,
                        path_id=f"messaging-{stage}-result",
                        deadline_ms=expires,
                        authority_head=self.egress_authority_head,
                        projection=projection,
                    ),
                )
                if socket_writer:
                    return self._owned_reply(
                        request_id, response, after_response=lambda: None
                    )
                return self.egress.release(
                    self.egress.binding(self.egress_catalog_id, request_id),
                    response,
                    lambda result: result,
                )
            stored_response = intake.get("_egress_response")
            if not isinstance(stored_response, bytes):
                raise RouteError("transport_response_missing")
            if socket_writer or ticket is not None:
                return self._owned_reply(
                    request_id,
                    stored_response,
                    after_response=(
                        (lambda: None) if ticket is None else ticket.after_response
                    ),
                    after_response_bounded=(
                        None if ticket is None else ticket.after_response_bounded
                    ),
                )
            return self.egress.release(
                self.egress.binding(self.egress_catalog_id, request_id),
                stored_response,
                lambda value: value,
            )
        except (
            RouteError,
            SealedDeliveryError,
            CanonicalError,
            ValueError,
        ) as exception:
            if isinstance(exception, RouteError):
                raise
            if ticket is not None:
                raise RouteAmbiguous("transport_intake_recovery_pending") from exception
            raise RouteError("transport_request_rejected") from exception

    def _owned_reply(
        self,
        request_id: str,
        response: bytes,
        *,
        after_response: Callable[[], None],
        after_response_bounded: Callable[[int], None] | None = None,
    ) -> TransportReply:
        binding = self.egress.binding(self.egress_catalog_id, request_id)
        # Preserve the selected visibility prerequisite, including legacy
        # profiles that publish control results. This preparation is separate
        # from the check-only socket release; it never grants a reusable permit.
        self.egress.prepare_visibility(binding)

        def release(writer: Callable[[bytes], None], deadline_ns: int) -> None:
            self.egress.release_bounded(
                binding, response, writer, deadline_ns=deadline_ns
            )

        return TransportReply(
            bytes(response), after_response, release, after_response_bounded
        )

    def intake_binding(self) -> dict[str, Any]:
        return {
            "provider_ref": self.provider_ref,
            "route_ref": self.route_ref,
            "key_ref": self.key_ref,
            "secret_sha256": hashlib.sha256(self._secret).hexdigest(),
            "recipient_id": self.recipient_id,
            "recipient_body_ref": self.recipient_body_ref,
            "recipient_embodiment_id": self.recipient_embodiment_id,
        }

    def finalize_retained_intake(
        self, context: Mapping[str, Any], ticket: DurableIntakeTicket
    ) -> bytes:
        """Finish exact durable ACK only; no expired frame open or socket write."""
        if context["binding"] != self.intake_binding():
            raise RouteError("transport_retained_binding_conflict")
        value = context["request"]
        unsigned = {key: item for key, item in value.items() if key != "auth"}
        expected = hmac.digest(self._secret, canonical_bytes(unsigned), "sha256")
        if (
            value["auth"]["key_ref"] != self.key_ref
            or not hmac.compare_digest(
                expected, unb64url(value["auth"]["value"], length=32)
            )
            or hashlib.sha256(canonical_bytes(unsigned)).hexdigest()
            != context["request_hash"]
        ):
            raise RouteError("transport_retained_binding_conflict")
        submission = _submission(value["submission"])
        envelope = unb64url(submission["envelope"])
        if (
            hashlib.sha256(envelope).hexdigest() != submission["envelope_sha256"]
            or ticket.metadata != context["metadata"]
            or ticket.metadata["delivery_id"] != submission["delivery_id"]
            or ticket.metadata["event_id"] != submission["message_id"]
            or self.recipient_embodiment_id
            not in ticket.metadata["recipient_embodiment_ids"]
        ):
            raise RouteError("transport_retained_binding_conflict")
        result = self.inbox._finalize_retained_intake(
            request_id=value["request_id"],
            request_hash=context["request_hash"],
            recipient_id=self.recipient_id,
            envelope=envelope,
            metadata=ticket.metadata,
            received_at_ms=ticket.received_at_ms,
            response_factory=lambda item: self._accepted_response(
                value, context["request_hash"], item
            ),
        )
        response = result["_egress_response"]
        ticket.acknowledge(response)
        return bytes(response)

    def _accepted_response(
        self,
        value: Mapping[str, Any],
        request_hash: str,
        item: Mapping[str, Any],
    ) -> tuple[bytes, RouteEgressSpec]:
        submission = value["submission"]
        request_id = value["request_id"]
        sender_principal = value["sender_principal"]
        expires = value["expires_at_ms"]
        outcome = "hub-accepted" if self.hub else "recipient-intake"
        intake_evidence: dict[str, Any] | None = None
        if not self.hub:
            intake_evidence = {
                "schema": "dm.transport-intake/v1",
                "delivery_id": submission["delivery_id"],
                "recipient_id": self.recipient_id,
                "recipient_body_ref": self.recipient_body_ref,
                "envelope_sha256": submission["envelope_sha256"],
                "accepted_at_ms": item["received_at_ms"],
                "evidence_ref": item["evidence_ref"],
                "presence_ref": self.presence_ref,
                "fence_ref": self.fence_ref,
            }
        response = self._response(
            request_id=request_id,
            request_hash=request_hash,
            status="accepted",
            outcome=outcome,
            evidence_ref=cast(str, item["evidence_ref"]),
            intake=intake_evidence,
        )
        stage = (
            "evidence" if str(submission["leg_id"]).endswith("evidence") else "message"
        )
        projection = {
            "event_id": submission["message_id"],
            "event_digest": submission["envelope_sha256"],
            "sender": self.recipient_id,
            "recipients": [sender_principal],
            "thread_id": submission["leg_id"],
            "reply_to": None,
            "kind": "transport-result",
            "content": {"stage": stage, "outcome": "accepted"},
        }
        return response, RouteEgressSpec(
            controller=self.egress,
            catalog_id=self.egress_catalog_id,
            path_id=f"messaging-{stage}-result",
            deadline_ms=expires,
            authority_head=self.egress_authority_head,
            projection=projection,
        )

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
        egress: MandatoryEgressController,
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
        if not isinstance(egress, MandatoryEgressController):
            raise RouteError("invalid_route_provider")
        self._egress = egress
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

    @property
    def egress(self) -> MandatoryEgressController:
        return self._egress

    def inspect(self) -> Mapping[str, Any]:
        evidence = {
            "provider_ref": self.provider_ref,
            "route_ref": self.route_ref,
            "route_class": self.route_class,
            "available": self._available,
        }
        return {**evidence, "evidence_ref": _opaque_evidence(evidence)}

    def retained_binding(self) -> dict[str, Any]:
        """Owner-local exact selection fingerprint; never permission to send."""
        return {
            "provider_ref": self.provider_ref,
            "route_ref": self.route_ref,
            "route_class": self.route_class,
            "key_ref": self._key_ref,
            "secret_sha256": hashlib.sha256(self._secret).hexdigest(),
            "sender_principal": self._sender_principal,
            "sender_body_ref": self._sender_body_ref,
            "endpoint_sha256": getattr(self, "_endpoint_sha256", None),
        }

    def manifest(self) -> Mapping[str, Any]:
        total = (
            self._round_trip.total_timeout_seconds
            if isinstance(self._round_trip, _SplitRoundTrip)
            else None
        )
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
                "max_runtime_ms": 30_000 if total is None else math.ceil(total * 1000),
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
        return self.send_prepared(self.prepare_submission(value))

    def prepare_submission(self, submission: Mapping[str, Any]) -> bytes:
        """Build exact authenticated request bytes; caller persists before I/O."""
        value = _submission(submission)
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
        return request

    def _prepared_submission(
        self, request: bytes, *, check_time: bool = True
    ) -> tuple[Mapping[str, Any], str, str]:
        """Revalidate persisted framing, local credential binding and lifetime."""
        code = "transport_request_rejected"
        try:
            prepared = _closed(
                _decode_canonical(request, code),
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
                code,
            )
            auth = _closed(
                prepared["auth"], {"alg", "key_ref", "schema", "value"}, code
            )
            value = _submission(prepared["submission"])
            request_id = _uuid(prepared["request_id"], code)
            issued = _uint(prepared["issued_at_ms"], code)
            expires = _uint(prepared["expires_at_ms"], code)
            now = _uint(self._clock(), code)
            if (
                prepared["schema"] != TRANSPORT_REQUEST_SCHEMA
                or prepared["version"] != TRANSPORT_VERSION
                or prepared["provider_ref"] != self.provider_ref
                or prepared["route_ref"] != self.route_ref
                or prepared["sender_principal"] != self._sender_principal
                or prepared["sender_body_ref"] != self._sender_body_ref
                or auth["schema"] != TRANSPORT_AUTH_SCHEMA
                or auth["alg"] != "HMAC-SHA256"
                or auth["key_ref"] != self._key_ref
                or expires != value["deadline_ms"]
                or expires <= issued
                or (check_time and not issued - MAX_CLOCK_SKEW_MS <= now < expires)
                or request_id
                != str(uuid.uuid5(_ATTEMPT_NAMESPACE, f"request:{value['attempt_id']}"))
            ):
                raise RouteError(code)
            unsigned = {key: item for key, item in prepared.items() if key != "auth"}
            encoded = canonical_bytes(unsigned)
            if not hmac.compare_digest(
                unb64url(cast(str, auth["value"]), length=32),
                hmac.digest(self._secret, encoded, "sha256"),
            ):
                raise RouteError(code)
            return value, request_id, hashlib.sha256(encoded).hexdigest()
        except (CanonicalError, ValueError, KeyError, TypeError) as exception:
            raise RouteError(code) from exception

    def send_prepared(
        self,
        request: bytes,
        *,
        response_sink: Callable[[bytes], None] | None = None,
        carrier_binding: OperationBinding | None = None,
        attempt_deadline_ns: int | None = None,
        authorize: Callable[[], None] | None = None,
        require_bounded_write: bool = False,
    ) -> Mapping[str, Any]:
        """Transmit exact bytes; optionally retain the authenticated response."""
        started_ns = time.monotonic_ns()
        if type(require_bounded_write) is not bool:
            raise RouteError("route_bounded_transport_required")
        if attempt_deadline_ns is not None and (
            type(attempt_deadline_ns) is not int or attempt_deadline_ns <= started_ns
        ):
            raise RouteAmbiguous("route_timeout", fallback_allowed=False)
        value, _, _ = self._prepared_submission(request)
        carrier = unb64url(cast(str, value["envelope"]))
        if carrier_binding is not None and (
            carrier_binding.path_id
            not in {"tribe-message-request", "tribe-receipt-request"}
            or carrier_binding.native_sha256 != hashlib.sha256(carrier).hexdigest()
        ):
            raise RouteError("route_group_carrier_mismatch")
        if carrier_binding is not None:
            group = _decode_canonical(carrier, "route_group_carrier_mismatch")
            if carrier_binding.path_id == "tribe-message-request":
                if group.get("schema") not in {
                    "dm.tribe.conversation/v1",
                    "dm.tribe.direct-conversation/v1",
                }:
                    raise RouteError("route_group_carrier_mismatch")
                if (
                    require_bounded_write
                    or group["schema"] == "dm.tribe.direct-conversation/v1"
                ) and (
                    type(self._round_trip) is not _SplitRoundTrip
                    or self._round_trip.bounded_open is None
                ):
                    # The new reader guard must execute inside the actual write
                    # fence. Legacy opaque callbacks are not this qualification.
                    raise RouteError("route_bounded_transport_required")
                sealed = unb64url(cast(str, group["envelope"]))
                metadata = inspect_delivery(sealed, at_ms=self._clock())
                sender = _decode_canonical(sealed, "route_group_carrier_mismatch")[
                    "sender"
                ]
                if (
                    value["message_id"] != metadata["event_id"]
                    or value["delivery_id"] != metadata["delivery_id"]
                    or value["recipient_id"] not in metadata["recipient_embodiment_ids"]
                    or sender["being_ref"] != self._sender_principal
                ):
                    raise RouteError("route_group_carrier_mismatch")
            elif (
                group.get("schema") != "dm.tribe.intake-result/v1"
                or group["receipt"]["being_ref"] != self._sender_principal
                or value["message_id"] != group["receipt"]["event_id"]
                or value["delivery_id"]
                != str(
                    uuid.uuid5(
                        uuid.UUID(group["receipt"]["event_id"]), "tribe-receipt/v1"
                    )
                )
            ):
                raise RouteError("route_group_carrier_mismatch")
        if not self._available:
            return self._result(value, "unavailable", "unavailable", None)
        try:
            paths = frozenset(
                {
                    "route-provider-request",
                    "messaging-evidence-request",
                    "messaging-message-request",
                }
            )
            if type(self._round_trip) is _SplitRoundTrip:
                deadline = (
                    None
                    if self._round_trip.bounded_open is None
                    else _AttemptDeadline.start(
                        cast(float, self._round_trip.total_timeout_seconds),
                        deadline_ms=cast(int, value["deadline_ms"]),
                        clock=self._clock,
                        started_ns=started_ns,
                    )
                )
                if attempt_deadline_ns is not None:
                    if deadline is None:
                        raise RouteError("route_bounded_transport_required")
                    deadline = _AttemptDeadline(
                        min(deadline.deadline_ns, attempt_deadline_ns)
                    )
                exchange = (
                    self._round_trip.open()
                    if deadline is None
                    else self._round_trip.bounded_open(deadline)  # type: ignore[misc]
                )
                try:

                    def write(checked: bytes) -> None:
                        if authorize is not None:
                            authorize()
                        if deadline is not None:
                            deadline.remaining()
                        if self._clock() >= value["deadline_ms"]:
                            raise NativeEgressError("egress_authority_blocked")
                        exchange.write(checked)

                    if carrier_binding is None:
                        if deadline is None:
                            self._egress.release_registered(
                                request, allowed_paths=paths, effect=write
                            )
                        else:
                            self._egress.release_registered_bounded(
                                request,
                                allowed_paths=paths,
                                effect=write,
                                deadline_ns=deadline.deadline_ns,
                            )
                    else:
                        if deadline is None:
                            self._egress.release(
                                carrier_binding,
                                carrier,
                                lambda _carrier: write(request),
                            )
                        else:
                            self._egress.release_bounded(
                                carrier_binding,
                                carrier,
                                lambda _carrier: write(request),
                                deadline_ns=deadline.deadline_ns,
                            )
                    raw_response = exchange.read()
                finally:
                    exchange.close()
            else:
                if attempt_deadline_ns is not None:
                    raise RouteError("route_bounded_transport_required")
                # Opaque callbacks have no separate write boundary. Preserve
                # their existing atomic authorization/execution semantics.
                if carrier_binding is None:
                    raw_response = self._egress.release_registered(
                        request, allowed_paths=paths, effect=self._round_trip
                    )
                else:
                    raw_response = self._egress.release(
                        carrier_binding,
                        carrier,
                        lambda _carrier: self._round_trip(request),
                    )
            result = self.validate_prepared_response(request, raw_response)
            if response_sink is not None:
                response_sink(raw_response)
            return result
        except RouteError as exception:
            # Retain possible remote effects and exact retry bytes, but an
            # invalid response must not authorize trying a different route.
            raise RouteAmbiguous(exception.code, fallback_allowed=False) from exception
        except NativeEgressError as exception:
            # A local visibility/authority failure is not route unavailability.
            cause = str(exception)
            code = {
                "egress_echo_not_confirmed": "route_echo_unconfirmed",
                "egress_authority_blocked": "route_authority_blocked",
                "echo_authorization_blocked": "route_authority_blocked",
                "egress_attempt_deadline": "route_timeout",
            }.get(
                cause,
                "route_" + cause
                if cause in LOCAL_EGRESS_DIAGNOSTIC_CODES
                else "route_egress_blocked",
            )
            raise RouteAmbiguous(code, fallback_allowed=False) from exception
        except TimeoutError as exception:
            raise RouteAmbiguous("route_timeout") from exception
        except http.client.HTTPException as exception:
            raise RouteAmbiguous("route_http_incomplete") from exception
        except (ConnectionError, OSError) as exception:
            raise RouteAmbiguous("route_connection_failed") from exception

    def validate_prepared_response(
        self, request: bytes, raw_response: bytes
    ) -> Mapping[str, Any]:
        """Validate historical proof, not permission to transmit an expired request."""
        # A response can arrive after expiry for an operation admitted beforehand.
        # Fresh I/O remains lifetime-gated in send_prepared, and application cached
        # disclosure must separately recheck current policy and authorization.
        value, request_id, request_hash = self._prepared_submission(
            request, check_time=False
        )
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


def _unix_round_trip(
    path: Path, *, timeout_seconds: float, response_timeout_seconds: float
) -> RoundTrip:
    private_path = Path(os.path.abspath(path))

    def open_exchange() -> _TransportExchange:
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

        def write(raw: bytes) -> None:
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
            connection.settimeout(timeout_seconds)
            connection.connect(str(private_path))
            if hasattr(socket, "SO_PEERCRED"):
                peer = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
                _pid, uid, _gid = cast(tuple[int, int, int], struct.unpack("3i", peer))
                if uid != os.geteuid():
                    raise RouteError("unsafe_transport_peer")
            connection.sendall(len(raw).to_bytes(4, "big") + raw)

        def read() -> bytes:
            connection.settimeout(response_timeout_seconds)
            header = _recv_exact(connection, 4)
            size = int.from_bytes(header, "big")
            if not 1 <= size <= MAX_TRANSPORT_BYTES:
                raise ConnectionError("invalid transport frame")
            return _recv_exact(connection, size)

        return _TransportExchange(write, read, connection.close)

    return _SplitRoundTrip(open_exchange)


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

    deadline = _AttemptDeadline(
        time.monotonic_ns() + int(timeout_seconds * 1_000_000_000)
    )
    wrapped = _DeadlineSocket(connection, deadline)
    header = _recv_exact(cast(socket.socket, wrapped), 4)
    size = int.from_bytes(header, "big")
    if not 1 <= size <= MAX_TRANSPORT_BYTES:
        raise RouteError("invalid_transport_frame")
    raw = _recv_exact(cast(socket.socket, wrapped), size)
    response = ingress.handle_deferred(raw, socket_writer=True)
    if isinstance(response, TransportReply):
        try:

            def write(raw_response: bytes) -> None:
                wrapped.sendall(len(raw_response).to_bytes(4, "big") + raw_response)

            response.write_to(write, deadline_ns=deadline.deadline_ns)
        finally:
            # The admitted connection owns one technical completion attempt,
            # even if the peer did not observe the ACK write.
            with suppress(Exception):
                response.complete(deadline_ns=deadline.deadline_ns)
    else:
        wrapped.sendall(len(response).to_bytes(4, "big") + response)


def _http_round_trip(
    url: str,
    *,
    timeout_seconds: float,
    response_timeout_seconds: float,
    total_timeout_seconds: float | None = None,
) -> _SplitRoundTrip:
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

    def open_exchange() -> _TransportExchange:
        connection_class = (
            http.client.HTTPSConnection
            if parsed.scheme == "https"
            else http.client.HTTPConnection
        )
        connection = connection_class(hostname, port=port, timeout=timeout_seconds)

        def write(raw: bytes) -> None:
            connection.request(
                "POST",
                target,
                body=raw,
                headers={
                    "Content-Type": "application/daimon+jcs",
                    "Content-Length": str(len(raw)),
                },
            )

        def read() -> bytes:
            assert connection.sock is not None
            connection.sock.settimeout(response_timeout_seconds)
            response = connection.getresponse()
            body = response.read(MAX_TRANSPORT_BYTES + 1)
            if response.status != 200 or len(body) > MAX_TRANSPORT_BYTES:
                raise RouteAmbiguous("route_http_response_invalid")
            return body

        return _TransportExchange(write, read, connection.close)

    if total_timeout_seconds is None:
        return _SplitRoundTrip(open_exchange)
    if port is not None and not 1 <= port <= 65535:
        raise RouteError("invalid_provider_endpoint")
    for limit in (timeout_seconds, response_timeout_seconds, total_timeout_seconds):
        if (
            isinstance(limit, bool)
            or not isinstance(limit, (int, float))
            or not math.isfinite(limit)
            or not 0 < limit <= 60
        ):
            raise RouteError("invalid_transport_deadline")
    try:
        address = ipaddress.ip_address(hostname)
        if "%" in hostname:
            raise ValueError("scoped address")
    except ValueError:
        # A socket timeout does not bound getaddrinfo/NSS. Legacy hostname
        # adapters remain available, but cannot select this bounded profile.
        raise RouteError("bounded_transport_numeric_endpoint_required") from None
    context = ssl.create_default_context() if parsed.scheme == "https" else None
    selected_port = port if port is not None else (443 if context is not None else 80)

    def bounded_open(deadline: _AttemptDeadline) -> _TransportExchange:
        connect_deadline = deadline.child(timeout_seconds)
        family = socket.AF_INET if address.version == 4 else socket.AF_INET6
        owned = socket.socket(family, socket.SOCK_STREAM)
        try:
            owned.settimeout(connect_deadline.remaining())
            target_address: Any = (
                (str(address), selected_port)
                if address.version == 4
                else (str(address), selected_port, 0, 0)
            )
            owned.connect(target_address)
            connect_deadline.remaining()
            if context is not None:
                owned = context.wrap_socket(
                    owned, server_hostname=hostname, do_handshake_on_connect=False
                )
                owned.settimeout(connect_deadline.remaining())
                owned.do_handshake()
                connect_deadline.remaining()
            wrapped = _DeadlineSocket(owned, deadline)
            connection = http.client.HTTPConnection(hostname, port=selected_port)
            connection.auto_open = 0  # Never reconnect outside the selected setup.
            connection.sock = cast(socket.socket, wrapped)

            def write(raw: bytes) -> None:
                wrapped.deadline = deadline.child(timeout_seconds)
                wrapped.deadline.remaining()
                connection.request(
                    "POST",
                    target,
                    body=raw,
                    headers={
                        "Content-Type": "application/daimon+jcs",
                        "Content-Length": str(len(raw)),
                    },
                )
                wrapped.deadline.remaining()

            def read() -> bytes:
                wrapped.deadline = deadline.child(response_timeout_seconds)
                response = connection.getresponse()
                try:
                    body = response.read(MAX_TRANSPORT_BYTES + 1)
                    wrapped.deadline.remaining()
                    if response.status != 200 or len(body) > MAX_TRANSPORT_BYTES:
                        raise RouteAmbiguous("route_http_response_invalid")
                    return body
                finally:
                    response.close()

            return _TransportExchange(write, read, connection.close)
        except BaseException:
            owned.close()
            raise

    return _SplitRoundTrip(open_exchange, bounded_open, total_timeout_seconds)


class LocalIPCProvider(AuthenticatedProvider):
    def __init__(
        self,
        *,
        socket_path: Path,
        timeout_seconds: float = 5.0,
        response_timeout_seconds: float = 30.0,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            round_trip=_unix_round_trip(
                socket_path,
                timeout_seconds=timeout_seconds,
                response_timeout_seconds=response_timeout_seconds,
            ),
            **kwargs,
        )


class DirectHTTPProvider(AuthenticatedProvider):
    def __init__(
        self,
        *,
        endpoint: str,
        timeout_seconds: float = 5.0,
        response_timeout_seconds: float = 30.0,
        total_timeout_seconds: float | None = None,
        **kwargs: Any,
    ) -> None:
        self._endpoint_sha256 = hashlib.sha256(endpoint.encode()).hexdigest()
        super().__init__(
            round_trip=_http_round_trip(
                endpoint,
                timeout_seconds=timeout_seconds,
                response_timeout_seconds=response_timeout_seconds,
                total_timeout_seconds=total_timeout_seconds,
            ),
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
        egress: MandatoryEgressController | None = None,
        egress_catalog_id: str | None = None,
    ) -> None:
        self.store = store
        self.profile = profile
        self.providers = dict(providers)
        self.clock = clock
        if egress is None:
            controllers = {
                provider.egress
                for provider in self.providers.values()
                if isinstance(provider, AuthenticatedProvider)
            }
            if len(controllers) != 1:
                raise RouteError("route_egress_required")
            egress = controllers.pop()
        if egress_catalog_id is None:
            egress_catalog_id = (
                "route-" + hashlib.sha256(profile.profile_id.encode()).hexdigest()[:24]
            )
        self.egress = egress
        store.bind_egress(
            egress,
            catalog_id=egress_catalog_id,
            authorize=self._authorize_egress,
        )
        for binding in profile.routes:
            provider = self.providers.get(binding.provider_ref)
            if provider is None:
                continue
            if type(provider) not in {
                AuthenticatedProvider,
                LocalIPCProvider,
                DirectHTTPProvider,
                HubProvider,
            }:
                raise RouteError("route_provider_not_gated")
            if (
                provider.provider_ref != binding.provider_ref
                or provider.route_ref != binding.route_ref
                or provider.route_class != binding.route_class
            ):
                raise RouteError("route_provider_binding_mismatch")
            _provider_manifest(provider.manifest(), binding)

    def _authorize_egress(self, binding: OperationBinding) -> bool:
        if not self.profile.enabled:
            return False
        try:
            attempt = self.store.egress_attempt(binding.operation_id)
        except (CommunicationError, ValueError):
            return False
        return binding.authority_head == self.profile.body_ref and any(
            route.enabled
            and route.provider_ref == attempt["provider_ref"]
            and route.route_ref == attempt["route_ref"]
            for route in self.profile.routes
        )

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
            or leg["receipt_origin_embodiment_id"]
            not in metadata["recipient_embodiment_ids"]
        ):
            raise RouteError("route_recipient_mismatch")
        delivery_id = cast(str, metadata["delivery_id"])
        envelope_hash = cast(str, metadata["envelope_sha256"])
        projection = self.store.route_projection(leg_id=leg_id, envelope=metadata)
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
            authenticated = cast(AuthenticatedProvider, provider)
            request = AuthenticatedProvider.prepare_submission(
                authenticated, submission
            )
            self.store.record_attempt(
                attempt,
                egress_request=request,
                egress_projection=projection,
                authority_head=self.profile.body_ref,
            )
            self.store.record_delivery(
                attempt_id=attempt_id,
                delivery_id=delivery_id,
                envelope_hash=envelope_hash,
            )
            try:
                result = dict(
                    AuthenticatedProvider.send_prepared(authenticated, request)
                )
            except RouteAmbiguous as exception:
                if not exception.fallback_allowed:
                    raise
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
