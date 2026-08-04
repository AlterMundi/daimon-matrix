"""Root-authorized scope and topology resolution for DM-054."""

from __future__ import annotations

import copy
import hashlib
import json
import sqlite3
import uuid
from collections import Counter
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Final, Protocol, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .authority_epochs import RootHistoryAuthority
from .canonical import CanonicalError, b64url, canonical_bytes, unb64url
from .cluster import (
    BODY_SNAPSHOT_SCHEMA,
    ClusterEvidenceError,
    validate_body_snapshot,
)
from .identity import VerificationError, verify_embodiment_credential
from .ledger import Ledger
from .projections import ProjectionEngine
from .relationships import RelationshipError, VerifiedTribeSnapshot
from .routes import RouteCoordinator, RouteError
from .sync import SyncEngine
from .weave import BoundHistoryAuthority, EventSigner, RootAuthority, WeaveProtocolError

ME_SCHEMA: Final = "dm.scope.me/v1"
WE_SCHEMA: Final = "dm.scope.we/v1"
DIFF_SCHEMA: Final = "dm.scope.we-diff/v1"
RESOLUTION_SCHEMA: Final = "dm.scope-resolution/v1"
RESOLUTION_DOMAIN: Final = b"daimon/scope-resolution/v1\x00"
SYNC_PLAN_SCHEMA: Final = "dm.scope.sync-plan/v1"
FANOUT_SCHEMA: Final = "dm.scope.fanout/v1"
REQUEST_SCHEMA: Final = "dm.scope.request/v1"
RESPONSE_SCHEMA: Final = "dm.scope.response/v1"
REQUEST_DOMAIN: Final = b"daimon/scope-request/v1\x00"
RESPONSE_DOMAIN: Final = b"daimon/scope-response/v1\x00"
MAX_CAPABILITIES: Final = 256
MAX_FANOUT_TARGETS: Final = 256
MAX_RESPONSE_BYTES: Final = 1024 * 1024
MAX_DEADLINE_SPAN_MS: Final = 60_000
Clock = Callable[[], int]
BodyReader = Callable[[str, str, str, int], Mapping[str, Any]]


class PeerCall(Protocol):
    def __call__(
        self,
        target: Mapping[str, Any],
        request: Mapping[str, Any],
        deadline_ms: int,
    ) -> Mapping[str, Any]: ...


class ScopeError(ValueError):
    """Scope resolution failed without widening authority."""

    def __init__(self, code: str, *, retryable: bool = False) -> None:
        super().__init__(code)
        self.code = code
        self.retryable = retryable


def _text(value: Any, code: str, maximum: int = 256) -> str:
    if not isinstance(value, str) or not 1 <= len(value.encode()) <= maximum:
        raise ScopeError(code)
    return value


def _uuid_text(value: Any, code: str) -> str:
    import uuid

    text = _text(value, code, 36)
    try:
        if str(uuid.UUID(text)) != text:
            raise ScopeError(code)
    except ValueError as exception:
        raise ScopeError(code) from exception
    return text


def _evidence(value: Mapping[str, Any]) -> str:
    digest = hashlib.sha256(canonical_bytes(value)).digest()
    return "dm:scope-evidence:v1:" + b64url(digest)


def _closed(value: Any, fields: set[str], code: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ScopeError(code)
    return value


def _uint(value: Any, code: str, *, minimum: int = 0) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not minimum <= value <= 2**53 - 1
    ):
        raise ScopeError(code)
    return value


def _hash(value: Any, code: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ScopeError(code)
    return value


def _origin(value: Any) -> dict[str, str]:
    row = _closed(
        value,
        {"body_ref", "embodiment_id", "incarnation_id", "principal_id"},
        "invalid_scope_origin",
    )
    return {
        field: _text(row[field], "invalid_scope_origin")
        for field in ("body_ref", "embodiment_id", "incarnation_id", "principal_id")
    }


def _signature(value: Any) -> Mapping[str, str]:
    row = _closed(value, {"alg", "kid", "value"}, "invalid_scope_signature")
    if row["alg"] != "Ed25519":
        raise ScopeError("invalid_scope_signature")
    kid = _text(row["kid"], "invalid_scope_signature", 128)
    signature = _text(row["value"], "invalid_scope_signature", 128)
    try:
        unb64url(signature, length=64)
    except CanonicalError as exception:
        raise ScopeError("invalid_scope_signature") from exception
    return {"alg": "Ed25519", "kid": kid, "value": signature}


def _sign(
    core: Mapping[str, Any], signer: EventSigner, domain: bytes
) -> dict[str, Any]:
    if len(signer.seed) != 32:
        raise ScopeError("invalid_scope_signer")
    content_hash = hashlib.sha256(domain + canonical_bytes(core)).hexdigest()
    signature = Ed25519PrivateKey.from_private_bytes(signer.seed).sign(
        domain + bytes.fromhex(content_hash)
    )
    return {
        **copy.deepcopy(dict(core)),
        "content_hash": content_hash,
        "signature": {
            "alg": "Ed25519",
            "kid": signer.key_id,
            "value": b64url(signature),
        },
    }


def _verify_signed(
    value: Mapping[str, Any],
    *,
    core_fields: set[str],
    domain: bytes,
    authority: RootAuthority,
    at_ms: int,
) -> dict[str, Any]:
    row = _closed(
        value,
        core_fields | {"content_hash", "signature"},
        "invalid_scope_document",
    )
    core = {
        key: copy.deepcopy(item)
        for key, item in row.items()
        if key not in {"content_hash", "signature"}
    }
    expected = hashlib.sha256(domain + canonical_bytes(core)).hexdigest()
    if _hash(row["content_hash"], "invalid_scope_hash") != expected:
        raise ScopeError("scope_hash_mismatch")
    signature = _signature(row["signature"])
    origin = cast(
        Mapping[str, Any],
        core["requester"] if "requester" in core else core["responder"],
    )
    try:
        member = authority.validate_origin(origin, require_active=True)
        credential = authority.credentials[member["embodiment_credential_id"]]
        credential_body = verify_embodiment_credential(
            credential, authority.state, at_ms=at_ms
        )
        signing = credential_body["signing_key"]
        principals = {
            item["principal_id"] for item in credential_body["transport_principals"]
        }
        if (
            signature["kid"] != signing["key_id"]
            or origin["principal_id"] not in principals
        ):
            raise ScopeError("scope_signer_mismatch")
        Ed25519PublicKey.from_public_bytes(
            unb64url(signing["public"], length=32)
        ).verify(
            unb64url(signature["value"], length=64),
            domain + bytes.fromhex(expected),
        )
    except (
        InvalidSignature,
        CanonicalError,
        KeyError,
        VerificationError,
        WeaveProtocolError,
    ) as exception:
        raise ScopeError("scope_signature_rejected") from exception
    return copy.deepcopy(dict(row))


@dataclass(frozen=True)
class ScopeResolver:
    ledger: Ledger
    clock: Clock
    router: RouteCoordinator | None = None
    body_capabilities: tuple[str, ...] = ()
    body_reader: BodyReader | None = None
    tribes: Mapping[str, VerifiedTribeSnapshot] | None = None

    def __post_init__(self) -> None:
        if not isinstance(
            self.ledger.authority,
            (RootAuthority, RootHistoryAuthority, BoundHistoryAuthority),
        ):
            raise ScopeError("scope_requires_root_authority")
        if len(self.body_capabilities) > MAX_CAPABILITIES or list(
            self.body_capabilities
        ) != sorted(set(self.body_capabilities)):
            raise ScopeError("invalid_body_capabilities")
        for capability in self.body_capabilities:
            _text(capability, "invalid_body_capabilities", 128)
        self.ledger.authority.validate_origin(
            self.ledger.local_origin, require_active=True
        )
        active = [
            row
            for row in self.authority.manifest.value["embodiments"]
            if row["status"] == "active"
        ]
        if len({row["embodiment_id"] for row in active}) != len(active):
            raise ScopeError("ambiguous_active_incarnation")

    @property
    def authority(self) -> RootAuthority:
        authority = self.ledger.authority
        if isinstance(authority, BoundHistoryAuthority):
            return authority.active
        if isinstance(authority, RootHistoryAuthority):
            return authority.active
        if isinstance(authority, RootAuthority):
            return authority
        raise ScopeError("scope_requires_root_authority")

    @property
    def local_origin(self) -> dict[str, str]:
        return copy.deepcopy(dict(self.ledger.local_origin))

    def me(self) -> dict[str, Any]:
        return self._me_at(_uint(self.clock(), "invalid_scope_time"))

    def _me_at(self, now: int) -> dict[str, Any]:
        origin = self.local_origin
        body: Mapping[str, Any] | None = None
        if self.body_reader is not None:
            try:
                value = self.body_reader(
                    origin["body_ref"],
                    origin["embodiment_id"],
                    origin["incarnation_id"],
                    now,
                )
            except (ScopeError, ValueError) as exception:
                raise ScopeError("body_snapshot_rejected") from exception
            if not isinstance(value, Mapping):
                raise ScopeError("body_snapshot_rejected")
            try:
                body = validate_body_snapshot(
                    value,
                    body_ref=origin["body_ref"],
                    embodiment_id=origin["embodiment_id"],
                    incarnation_id=origin["incarnation_id"],
                    evaluated_at_ms=now,
                )
            except ClusterEvidenceError as exception:
                raise ScopeError("body_snapshot_rejected") from exception
        member = self.authority.validate_origin(origin, require_active=True)
        return {
            "schema": ME_SCHEMA,
            "being_ref": self.authority.manifest.being_ref,
            "manifest_hash": self.authority.manifest.digest,
            "evaluated_at_ms": now,
            "origin": origin,
            "credential_ref": member["embodiment_credential_id"],
            "incarnation_authorization_ref": member["incarnation_authorization_id"],
            "body_capabilities": list(self.body_capabilities),
            "body": body,
            "heads": SyncEngine(self.ledger).heads(),
            "effective": ProjectionEngine(self.ledger).snapshot(),
        }

    def we(self) -> dict[str, Any]:
        return self._we_at(_uint(self.clock(), "invalid_scope_time"))

    def _we_at(self, now: int) -> dict[str, Any]:
        rows = [self._topology(member, now) for member in self._members()]
        return {
            "schema": WE_SCHEMA,
            "being_ref": self.authority.manifest.being_ref,
            "manifest_hash": self.authority.manifest.digest,
            "evaluated_at_ms": now,
            "local_origin": self.local_origin,
            "embodiments": rows,
            "partial": any(
                row["manifest_status"] == "active"
                and row["availability"] not in {"local", "available"}
                for row in rows
            ),
        }

    def _members(self) -> list[Mapping[str, Any]]:
        return sorted(
            self.authority.manifest.value["embodiments"],
            key=lambda row: (row["embodiment_id"], row["incarnation_id"]),
        )

    def _topology(self, member: Mapping[str, Any], now: int) -> dict[str, Any]:
        credential = self.authority.credentials[member["embodiment_credential_id"]]
        try:
            body = verify_embodiment_credential(
                credential,
                self.authority.state,
                at_ms=now,
                allow_revoked_history=member["status"] == "retired",
            )
        except VerificationError as exception:
            if member["status"] == "active":
                raise ScopeError("active_manifest_credential_invalid") from exception
            body = credential["body"]
        principals = copy.deepcopy(body["transport_principals"])
        local = member["embodiment_id"] == self.local_origin["embodiment_id"]
        route: Mapping[str, Any] | None = None
        availability = "retired" if member["status"] == "retired" else "unconfigured"
        if member["status"] == "active" and local:
            availability = "local"
        elif member["status"] == "active" and self.router is not None:
            try:
                route = self.router.inspect_recipient(
                    recipient_id=cast(str, member["embodiment_id"])
                )
                candidates = cast(list[Mapping[str, Any]], route["candidates"])
                availability = (
                    "available"
                    if any(candidate["available"] for candidate in candidates)
                    else "unavailable"
                    if candidates
                    else "unconfigured"
                )
            except RouteError as exception:
                if exception.code != "route_profile_disabled":
                    raise ScopeError("route_topology_rejected") from exception
                availability = "unconfigured"
        core = {
            "body_ref": member["body_ref"],
            "embodiment_id": member["embodiment_id"],
            "incarnation_id": member["incarnation_id"],
            "manifest_status": member["status"],
            "transport_principals": principals,
            "availability": availability,
            "route": copy.deepcopy(route),
        }
        return {**core, "evidence_ref": _evidence(core)}

    def diff(self) -> dict[str, Any]:
        projection = ProjectionEngine(self.ledger).snapshot()
        by_origin: dict[str, Counter[str]] = {}
        for entry in projection["entries"]:
            origin = entry["origin"]["embodiment_id"]
            by_origin.setdefault(origin, Counter())[entry["state"]] += 1
        summaries = [
            {
                "embodiment_id": embodiment,
                "states": dict(sorted(states.items())),
            }
            for embodiment, states in sorted(by_origin.items())
        ]
        return {
            "schema": DIFF_SCHEMA,
            "being_ref": self.authority.manifest.being_ref,
            "manifest_hash": self.authority.manifest.digest,
            "local_embodiment_id": self.local_origin["embodiment_id"],
            "projection_hash": projection["projection_hash"],
            "origin_summaries": summaries,
            "entries": copy.deepcopy(projection["entries"]),
        }

    def sync_plan(self, *, request_id: str, limit: int) -> dict[str, Any]:
        request_id = _uuid_text(request_id, "invalid_scope_request_id")
        if (
            not isinstance(limit, int)
            or isinstance(limit, bool)
            or not 1 <= limit <= 256
        ):
            raise ScopeError("invalid_scope_sync_limit")
        topology = self.we()
        targets = []
        engine = SyncEngine(self.ledger)
        for row in topology["embodiments"]:
            if (
                row["manifest_status"] != "active"
                or row["embodiment_id"] == self.local_origin["embodiment_id"]
            ):
                continue
            target_request_id = str(
                uuid.uuid5(
                    uuid.UUID(request_id),
                    f"{row['embodiment_id']}\x00{row['incarnation_id']}",
                )
            )
            targets.append(
                {
                    "embodiment_id": row["embodiment_id"],
                    "incarnation_id": row["incarnation_id"],
                    "availability": row["availability"],
                    "evidence_ref": row["evidence_ref"],
                    "request": engine.request(
                        request_id=target_request_id, limit=limit
                    ),
                }
            )
        return {
            "schema": SYNC_PLAN_SCHEMA,
            "plan_id": request_id,
            "targets": targets,
            "partial": any(row["availability"] != "available" for row in targets),
        }

    def tribe(self, *, tribe_ref: str) -> dict[str, Any]:
        return self._tribe_at(
            tribe_ref=tribe_ref,
            at_ms=_uint(self.clock(), "invalid_scope_time"),
        )

    def _tribe_at(self, *, tribe_ref: str, at_ms: int) -> dict[str, Any]:
        _text(tribe_ref, "invalid_tribe_ref")
        snapshot = None if self.tribes is None else self.tribes.get(tribe_ref)
        if snapshot is None:
            raise ScopeError("tribe_not_configured")
        principal = self.local_origin["principal_id"]
        try:
            return snapshot.resolve(principal_id=principal, at_ms=at_ms)
        except RelationshipError as exception:
            raise ScopeError(exception.code) from exception

    def resolution(
        self, *, scope: str, request_id: str, tribe_ref: str | None = None
    ) -> dict[str, Any]:
        request_id = _uuid_text(request_id, "invalid_scope_request_id")
        now = _uint(self.clock(), "invalid_scope_time")
        if scope not in {"/me", "/we", "/tribe"}:
            raise ScopeError("unsupported_scope")
        targets: list[dict[str, Any]] = []
        if scope == "/me":
            self._me_at(now)
            origins: Sequence[Mapping[str, Any]] = [self.local_origin]
        elif scope == "/we":
            origins = [
                row
                for row in self._we_at(now)["embodiments"]
                if row["manifest_status"] == "active"
            ]
        else:
            if tribe_ref is None:
                raise ScopeError("tribe_ref_required")
            tribe = self._tribe_at(tribe_ref=tribe_ref, at_ms=now)
            origins = cast(list[Mapping[str, Any]], tribe["members"])
        for row in origins:
            embodiment_id = cast(str, row["embodiment_id"])
            relationship = scope == "/tribe"
            targets.append(
                {
                    "scope_kind": "relationship" if relationship else "we",
                    "recipient_type": "relationship" if relationship else "embodiment",
                    "recipient_id": row["membership_ref"]
                    if relationship
                    else embodiment_id,
                    "receipt_origin_embodiment_id": embodiment_id,
                    "evidence_cursor": _evidence(
                        {
                            "request_id": request_id,
                            "scope": scope,
                            "target": embodiment_id,
                        }
                    ),
                }
            )
        targets.sort(key=lambda row: (row["recipient_type"], row["recipient_id"]))
        core = {
            "schema": RESOLUTION_SCHEMA,
            "request_id": request_id,
            "being_ref": self.authority.manifest.being_ref,
            "manifest_hash": self.authority.manifest.digest,
            "scope": scope,
            "tribe_ref": tribe_ref,
            "evaluated_at_ms": now,
            "origin": self.local_origin,
            "targets": targets,
        }
        return {
            **core,
            "resolution_hash": hashlib.sha256(
                RESOLUTION_DOMAIN + canonical_bytes(core)
            ).hexdigest(),
        }


REQUEST_FIELDS: Final = {
    "being_ref",
    "deadline_ms",
    "issued_at_ms",
    "manifest_hash",
    "max_response_bytes",
    "request_id",
    "requester",
    "schema",
    "scope",
}
RESPONSE_FIELDS: Final = {
    "being_ref",
    "completed_at_ms",
    "content",
    "error",
    "manifest_hash",
    "request_hash",
    "request_id",
    "responder",
    "schema",
    "status",
}


def create_scope_request(
    resolver: ScopeResolver,
    signer: EventSigner,
    *,
    request_id: str,
    deadline_ms: int,
    max_response_bytes: int = MAX_RESPONSE_BYTES,
) -> dict[str, Any]:
    request_id = _uuid_text(request_id, "invalid_scope_request_id")
    now = _uint(resolver.clock(), "invalid_scope_time")
    deadline = _uint(deadline_ms, "invalid_scope_deadline", minimum=now + 1)
    if deadline - now > MAX_DEADLINE_SPAN_MS:
        raise ScopeError("invalid_scope_deadline")
    maximum = _uint(max_response_bytes, "invalid_scope_response_limit", minimum=1)
    if maximum > MAX_RESPONSE_BYTES:
        raise ScopeError("invalid_scope_response_limit")
    core = {
        "schema": REQUEST_SCHEMA,
        "request_id": request_id,
        "being_ref": resolver.authority.manifest.being_ref,
        "manifest_hash": resolver.authority.manifest.digest,
        "requester": resolver.local_origin,
        "scope": "/me",
        "issued_at_ms": now,
        "deadline_ms": deadline,
        "max_response_bytes": maximum,
    }
    return _sign(core, signer, REQUEST_DOMAIN)


def validate_scope_request(
    value: Any, authority: RootAuthority, *, now_ms: int
) -> dict[str, Any]:
    now_ms = _uint(now_ms, "invalid_scope_time")
    if not isinstance(value, Mapping):
        raise ScopeError("invalid_scope_request")
    row = _verify_signed(
        value,
        core_fields=REQUEST_FIELDS,
        domain=REQUEST_DOMAIN,
        authority=authority,
        at_ms=_uint(value.get("issued_at_ms"), "invalid_scope_request"),
    )
    if (
        row["schema"] != REQUEST_SCHEMA
        or row["being_ref"] != authority.manifest.being_ref
        or row["manifest_hash"] != authority.manifest.digest
        or row["scope"] != "/me"
    ):
        raise ScopeError("scope_authority_mismatch")
    _uuid_text(row["request_id"], "invalid_scope_request")
    _origin(row["requester"])
    issued = _uint(row["issued_at_ms"], "invalid_scope_request")
    deadline = _uint(row["deadline_ms"], "invalid_scope_request", minimum=issued + 1)
    maximum = _uint(row["max_response_bytes"], "invalid_scope_request", minimum=1)
    if deadline - issued > MAX_DEADLINE_SPAN_MS or maximum > MAX_RESPONSE_BYTES:
        raise ScopeError("invalid_scope_request")
    if now_ms > deadline:
        raise ScopeError("scope_request_expired")
    return row


def create_scope_response(
    resolver: ScopeResolver,
    signer: EventSigner,
    request: Mapping[str, Any],
    *,
    status: str,
    content: Mapping[str, Any] | None,
    error: str | None,
) -> dict[str, Any]:
    now = _uint(resolver.clock(), "invalid_scope_time")
    validated = validate_scope_request(request, resolver.authority, now_ms=now)
    if status not in {"responded", "refused"} or (status == "responded") != (
        content is not None and error is None
    ):
        raise ScopeError("invalid_scope_response")
    if status == "refused":
        _text(error, "invalid_scope_response", 128)
        if content is not None:
            raise ScopeError("invalid_scope_response")
    core = {
        "schema": RESPONSE_SCHEMA,
        "request_id": validated["request_id"],
        "request_hash": validated["content_hash"],
        "being_ref": resolver.authority.manifest.being_ref,
        "manifest_hash": resolver.authority.manifest.digest,
        "responder": resolver.local_origin,
        "completed_at_ms": now,
        "status": status,
        "content": None if content is None else copy.deepcopy(dict(content)),
        "error": error,
    }
    response = _sign(core, signer, RESPONSE_DOMAIN)
    if len(canonical_bytes(response)) > validated["max_response_bytes"]:
        raise ScopeError("scope_response_too_large")
    return response


def validate_scope_response(
    value: Any,
    request: Mapping[str, Any],
    authority: RootAuthority,
    *,
    expected_origin: Mapping[str, Any],
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ScopeError("invalid_scope_response")
    issued = _uint(value.get("completed_at_ms"), "invalid_scope_response")
    row = _verify_signed(
        value,
        core_fields=RESPONSE_FIELDS,
        domain=RESPONSE_DOMAIN,
        authority=authority,
        at_ms=issued,
    )
    responder = _origin(row["responder"])
    expected = {
        field: expected_origin.get(field)
        for field in ("body_ref", "embodiment_id", "incarnation_id")
    }
    actual = {field: responder[field] for field in expected}
    principal = expected_origin.get("principal_id")
    if (
        row["schema"] != RESPONSE_SCHEMA
        or row["request_id"] != request["request_id"]
        or row["request_hash"] != request["content_hash"]
        or row["being_ref"] != request["being_ref"]
        or row["manifest_hash"] != request["manifest_hash"]
        or actual != expected
        or (principal is not None and responder["principal_id"] != principal)
        or issued > request["deadline_ms"]
    ):
        raise ScopeError("scope_response_binding_mismatch")
    if row["status"] == "responded":
        if not isinstance(row["content"], Mapping) or row["error"] is not None:
            raise ScopeError("invalid_scope_response")
        content = _closed(
            row["content"],
            {
                "being_ref",
                "body",
                "body_capabilities",
                "credential_ref",
                "effective",
                "evaluated_at_ms",
                "heads",
                "incarnation_authorization_ref",
                "manifest_hash",
                "origin",
                "schema",
            },
            "invalid_scope_response",
        )
        if (
            content["schema"] != ME_SCHEMA
            or content["being_ref"] != request["being_ref"]
            or content["manifest_hash"] != request["manifest_hash"]
            or _origin(content["origin"]) != responder
        ):
            raise ScopeError("scope_response_binding_mismatch")
    elif row["status"] == "refused":
        if row["content"] is not None:
            raise ScopeError("invalid_scope_response")
        _text(row["error"], "invalid_scope_response", 128)
    else:
        raise ScopeError("invalid_scope_response")
    if len(canonical_bytes(row)) > request["max_response_bytes"]:
        raise ScopeError("scope_response_too_large")
    return row


class ScopeExchangeStore:
    """Durable exact replay/conflict journal for scope exchanges."""

    def __init__(self, ledger: Ledger) -> None:
        self.ledger = ledger

    @contextmanager
    def _database(self) -> Iterator[sqlite3.Connection]:
        with self.ledger._database() as database:
            yield database

    def initialize(self) -> None:
        self.ledger.initialize()
        with self._database() as database:
            database.executescript(
                """
                CREATE TABLE IF NOT EXISTS scope_requests (
                    direction TEXT NOT NULL CHECK(direction IN ('inbound','outbound')),
                    requester_embodiment_id TEXT NOT NULL,
                    request_id TEXT NOT NULL,
                    request_hash TEXT NOT NULL,
                    request_json BLOB NOT NULL,
                    response_json BLOB,
                    PRIMARY KEY(direction, requester_embodiment_id, request_id)
                ) WITHOUT ROWID;
                CREATE TABLE IF NOT EXISTS scope_responses (
                    request_id TEXT NOT NULL,
                    responder_embodiment_id TEXT NOT NULL,
                    response_hash TEXT NOT NULL,
                    response_json BLOB NOT NULL,
                    PRIMARY KEY(request_id, responder_embodiment_id)
                ) WITHOUT ROWID;
                """
            )

    def freeze_request(
        self, request: Mapping[str, Any], *, direction: str
    ) -> Mapping[str, Any] | None:
        if direction not in {"inbound", "outbound"}:
            raise ScopeError("invalid_scope_direction")
        raw = canonical_bytes(request)
        requester = _origin(request["requester"])["embodiment_id"]
        with self._database() as database:
            database.execute(
                "INSERT OR IGNORE INTO scope_requests VALUES(?,?,?,?,?,NULL)",
                (
                    direction,
                    requester,
                    request["request_id"],
                    request["content_hash"],
                    raw,
                ),
            )
            row = database.execute(
                "SELECT request_hash, request_json, response_json FROM scope_requests "
                "WHERE direction=? AND requester_embodiment_id=? AND request_id=?",
                (direction, requester, request["request_id"]),
            ).fetchone()
            if row is None:
                raise ScopeError("scope_store_unavailable", retryable=True)
            if (
                row["request_hash"] != request["content_hash"]
                or bytes(row["request_json"]) != raw
            ):
                raise ScopeError("scope_request_conflict")
            return (
                None
                if row["response_json"] is None
                else cast(Mapping[str, Any], json.loads(bytes(row["response_json"])))
            )

    def cache_inbound_response(
        self, request: Mapping[str, Any], response: Mapping[str, Any]
    ) -> dict[str, Any]:
        raw = canonical_bytes(response)
        requester = _origin(request["requester"])["embodiment_id"]
        with self._database() as database:
            database.execute(
                "UPDATE scope_requests SET response_json=? "
                "WHERE direction='inbound' AND requester_embodiment_id=? "
                "AND request_id=? AND response_json IS NULL",
                (raw, requester, request["request_id"]),
            )
            row = database.execute(
                "SELECT request_hash, response_json FROM scope_requests "
                "WHERE direction='inbound' AND requester_embodiment_id=? "
                "AND request_id=?",
                (requester, request["request_id"]),
            ).fetchone()
            if row is None or row["request_hash"] != request["content_hash"]:
                raise ScopeError("scope_request_not_frozen")
            if row["response_json"] is None:
                raise ScopeError("scope_store_unavailable", retryable=True)
            existing = bytes(row["response_json"])
            if existing != raw:
                raise ScopeError("scope_response_conflict")
            return cast(dict[str, Any], json.loads(existing))

    def record_response(self, response: Mapping[str, Any]) -> dict[str, Any]:
        raw = canonical_bytes(response)
        responder = _origin(response["responder"])["embodiment_id"]
        with self._database() as database:
            database.execute(
                "INSERT OR IGNORE INTO scope_responses VALUES(?,?,?,?)",
                (
                    response["request_id"],
                    responder,
                    response["content_hash"],
                    raw,
                ),
            )
            row = database.execute(
                "SELECT response_hash, response_json FROM scope_responses "
                "WHERE request_id=? AND responder_embodiment_id=?",
                (response["request_id"], responder),
            ).fetchone()
            if row is None:
                raise ScopeError("scope_store_unavailable", retryable=True)
            if (
                row["response_hash"] != response["content_hash"]
                or bytes(row["response_json"]) != raw
            ):
                raise ScopeError("scope_response_conflict")
            return cast(dict[str, Any], json.loads(bytes(row["response_json"])))


def serve_scope_request(
    resolver: ScopeResolver,
    signer: EventSigner,
    store: ScopeExchangeStore,
    request: Mapping[str, Any],
) -> dict[str, Any]:
    observed_now = resolver.clock()
    unsigned_deadline = request.get("deadline_ms")
    validation_time = (
        min(observed_now, unsigned_deadline)
        if isinstance(unsigned_deadline, int)
        and not isinstance(unsigned_deadline, bool)
        else observed_now
    )
    validated = validate_scope_request(
        request, resolver.authority, now_ms=validation_time
    )
    cached = store.freeze_request(validated, direction="inbound")
    if cached is not None:
        return copy.deepcopy(dict(cached))
    if observed_now > validated["deadline_ms"]:
        raise ScopeError("scope_request_expired")
    try:
        response = create_scope_response(
            resolver,
            signer,
            validated,
            status="responded",
            content=resolver.me(),
            error=None,
        )
    except ScopeError as exception:
        if exception.code in {
            "scope_request_expired",
            "scope_response_too_large",
            "body_snapshot_rejected",
        }:
            response = create_scope_response(
                resolver,
                signer,
                validated,
                status="refused",
                content=None,
                error=exception.code,
            )
        else:
            raise
    return store.cache_inbound_response(validated, response)


@dataclass(frozen=True)
class ScopeFanout:
    resolver: ScopeResolver
    signer: EventSigner
    store: ScopeExchangeStore
    peer_call: PeerCall

    def execute(
        self,
        *,
        request_id: str,
        deadline_ms: int,
        max_response_bytes: int = MAX_RESPONSE_BYTES,
    ) -> dict[str, Any]:
        request = create_scope_request(
            self.resolver,
            self.signer,
            request_id=request_id,
            deadline_ms=deadline_ms,
            max_response_bytes=max_response_bytes,
        )
        return self.execute_exact(request)

    def execute_exact(self, request: Mapping[str, Any]) -> dict[str, Any]:
        """Retry one previously issued request without changing a byte."""

        deadline_ms = request.get("deadline_ms")
        if not isinstance(deadline_ms, int) or isinstance(deadline_ms, bool):
            raise ScopeError("invalid_scope_request")
        validated = validate_scope_request(
            request,
            self.resolver.authority,
            now_ms=min(self.resolver.clock(), deadline_ms),
        )
        if _origin(validated["requester"]) != self.resolver.local_origin:
            raise ScopeError("scope_requester_mismatch")
        request = validated
        self.store.freeze_request(request, direction="outbound")
        topology = self.resolver.we()
        outcomes: list[dict[str, Any]] = []
        for target in topology["embodiments"]:
            if (
                target["manifest_status"] != "active"
                or target["embodiment_id"]
                == self.resolver.local_origin["embodiment_id"]
            ):
                continue
            principals = sorted(
                {
                    row["principal_id"]
                    for row in target["transport_principals"]
                    if isinstance(row, Mapping)
                    and isinstance(row.get("principal_id"), str)
                }
            )
            identity = {
                "body_ref": target["body_ref"],
                "embodiment_id": target["embodiment_id"],
                "incarnation_id": target["incarnation_id"],
                "principal_ids": principals,
            }
            base = {
                "target": identity,
                "availability": target["availability"],
                "evidence_ref": target["evidence_ref"],
            }
            if not principals:
                outcomes.append(
                    {
                        **base,
                        "state": "unavailable",
                        "response": None,
                        "error": "target_principal_absent",
                    }
                )
                continue
            if target["availability"] != "available":
                outcomes.append({**base, "state": "unavailable", "response": None})
                continue
            if self.resolver.clock() > deadline_ms:
                outcomes.append({**base, "state": "missing", "response": None})
                continue
            try:
                raw = self.peer_call(target, request, deadline_ms)
                response = validate_scope_response(
                    raw,
                    request,
                    self.resolver.authority,
                    expected_origin={
                        key: identity[key]
                        for key in ("body_ref", "embodiment_id", "incarnation_id")
                    },
                )
                response = self.store.record_response(response)
                state = "responded" if response["status"] == "responded" else "refused"
                outcomes.append({**base, "state": state, "response": response})
            except TimeoutError:
                outcomes.append({**base, "state": "missing", "response": None})
            except OSError:
                outcomes.append(
                    {
                        **base,
                        "state": "unavailable",
                        "response": None,
                        "error": "peer_unavailable",
                    }
                )
            except ScopeError as exception:
                outcomes.append(
                    {
                        **base,
                        "state": "refused",
                        "response": None,
                        "error": exception.code,
                    }
                )
        outcomes.sort(
            key=lambda row: (
                row["target"]["embodiment_id"],
                row["target"]["incarnation_id"],
            )
        )
        return {
            "schema": FANOUT_SCHEMA,
            "request": request,
            "local": self.resolver.me(),
            "outcomes": outcomes,
            "partial": any(row["state"] != "responded" for row in outcomes),
            "completed_at_ms": self.resolver.clock(),
        }


__all__ = [
    "BODY_SNAPSHOT_SCHEMA",
    "DIFF_SCHEMA",
    "FANOUT_SCHEMA",
    "ME_SCHEMA",
    "RESOLUTION_SCHEMA",
    "SYNC_PLAN_SCHEMA",
    "WE_SCHEMA",
    "ScopeError",
    "ScopeExchangeStore",
    "ScopeFanout",
    "ScopeResolver",
    "create_scope_request",
    "create_scope_response",
    "serve_scope_request",
    "validate_scope_request",
    "validate_scope_response",
]
