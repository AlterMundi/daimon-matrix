"""Canonical ``dm.we.v1`` events with provisional and root-bound authority."""

from __future__ import annotations

import copy
import hashlib
import re
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final, Protocol, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .canonical import CanonicalError, b64url, canonical_bytes, unb64url
from .cluster import (
    ClusterEvidenceError,
    validate_observed_postcondition,
    validate_resource_fence_position,
)
from .identity import (
    ControlState,
    VerificationError,
    verify_embodiment_credential,
    verify_history_binding,
    verify_incarnation_authorization,
)

Artifact = Mapping[str, Any]
Event = dict[str, Any]

PROTOCOL: Final = "dm.we.v1"
EVENT_DOMAIN: Final = b"daimon/weave/event/v1\x00"
MAX_EVENT_BYTES: Final = 256 * 1024
MAX_PAGE_BYTES: Final = 1024 * 1024
MAX_PAGE_EVENTS: Final = 256
MAX_CAUSAL_PARENTS: Final = 64
MAX_PAYLOAD_DEPTH: Final = 16
MAX_PAYLOAD_NODES: Final = 4096
MAX_TEXT_BYTES: Final = 64 * 1024

EVENT_KINDS: Final = frozenset(
    {
        "experience.observed",
        "skill.proposed",
        "preference.proposed",
        "configuration.proposed",
        "adoption.decided",
        "projection.receipted",
        "lifecycle.announced",
    }
)
DECISIONS: Final = frozenset({"adopt", "reject", "defer", "revert"})
SENSITIVITIES: Final = frozenset({"personal", "private", "shareable"})
PROJECTION_RESULTS: Final = frozenset({"applied", "failed", "reconciled", "stale"})
PROJECTION_AUTHORITIES: Final = frozenset({"daimon", "human"})

_SECRET_NAMES: Final = re.compile(
    r"(?:^|_)(?:password|passwd|token|secret|private_key|api_key|bearer)(?:$|_)",
    re.IGNORECASE,
)
_PRIVATE_VALUE: Final = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")
_SCOPED_ID: Final = re.compile(r"^[A-Za-z0-9._:-]{1,240}$")


class WeaveProtocolError(ValueError):
    """Stable fail-closed protocol error."""


def _canonical(value: Any) -> bytes:
    try:
        return canonical_bytes(value)
    except CanonicalError as exception:
        raise WeaveProtocolError("invalid_canonical_value") from exception


def _closed(value: Any, fields: set[str], error: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise WeaveProtocolError(error)
    return value


def _text(value: Any, error: str, *, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > maximum:
        raise WeaveProtocolError(error)
    _canonical(value)
    return value


def _uint(value: Any, error: str, *, minimum: int = 0) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not minimum <= value <= 2**53 - 1
    ):
        raise WeaveProtocolError(error)
    return value


def _uuid(value: Any, error: str) -> str:
    if not isinstance(value, str):
        raise WeaveProtocolError(error)
    try:
        parsed = uuid.UUID(value)
    except ValueError as exception:
        raise WeaveProtocolError(error) from exception
    if str(parsed) != value:
        raise WeaveProtocolError(error)
    return value


def _legacy_ref(value: Any, prefix: str) -> str:
    if not isinstance(value, str) or not value.startswith(prefix + ":"):
        raise WeaveProtocolError(f"invalid_{prefix}_id")
    _uuid(value.split(":", 1)[1], f"invalid_{prefix}_id")
    return value


def _derived_ref(value: Any, prefix: str, error: str) -> str:
    if not isinstance(value, str) or not value.startswith(prefix):
        raise WeaveProtocolError(error)
    try:
        unb64url(value.removeprefix(prefix), length=32)
    except CanonicalError as exception:
        raise WeaveProtocolError(error) from exception
    return value


def _hex_hash(value: Any, error: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise WeaveProtocolError(error)
    return value


def _scoped_id(value: Any, prefix: str, error: str) -> str:
    if (
        not isinstance(value, str)
        or not value.startswith(prefix)
        or _SCOPED_ID.fullmatch(value.removeprefix(prefix)) is None
    ):
        raise WeaveProtocolError(error)
    return value


def _validate_payload(
    value: Any, *, depth: int = 0, counter: list[int] | None = None
) -> None:
    if counter is None:
        counter = [0]
    counter[0] += 1
    if counter[0] > MAX_PAYLOAD_NODES or depth > MAX_PAYLOAD_DEPTH:
        raise WeaveProtocolError("payload_too_complex")
    if value is None or isinstance(value, (bool, int)):
        _canonical(value)
        return
    if isinstance(value, str):
        if len(value.encode("utf-8")) > MAX_TEXT_BYTES:
            raise WeaveProtocolError("payload_text_too_large")
        if _PRIVATE_VALUE.search(value):
            raise WeaveProtocolError("secret_value_forbidden")
        _canonical(value)
        return
    if isinstance(value, list):
        for item in value:
            _validate_payload(item, depth=depth + 1, counter=counter)
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise WeaveProtocolError("invalid_payload_key")
            if _SECRET_NAMES.search(key) and not key.endswith("_ref"):
                raise WeaveProtocolError(f"secret_value_forbidden:{key}")
            _validate_payload(item, depth=depth + 1, counter=counter)
        _canonical(value)
        return
    raise WeaveProtocolError("invalid_payload_value")


@dataclass(frozen=True)
class BeingManifest:
    """Exact membership/configuration view used by one Weave ledger."""

    value: Mapping[str, Any]
    digest: str
    trust_mode: str

    @classmethod
    def from_value(cls, value: Any) -> BeingManifest:
        if not isinstance(value, Mapping):
            raise WeaveProtocolError("invalid_manifest")
        schema = value.get("schema")
        if schema == "being-manifest/v1":
            normalized = _provisional_manifest(value)
            mode = "provisional"
        elif schema == "being-manifest/v2":
            normalized = _root_manifest(value)
            mode = "root-bound"
        else:
            raise WeaveProtocolError("unsupported_manifest")
        exact = copy.deepcopy(dict(normalized))
        return cls(
            value=exact,
            digest=hashlib.sha256(_canonical(exact)).hexdigest(),
            trust_mode=mode,
        )

    @property
    def being_ref(self) -> str:
        return str(self.value["being_ref"])

    def member(
        self, embodiment_id: str, incarnation_id: str | None = None
    ) -> Mapping[str, Any]:
        candidates = [
            row
            for row in self.value["embodiments"]
            if row["embodiment_id"] == embodiment_id
            and row["status"] in {"active", "retired"}
            and (incarnation_id is None or row.get("incarnation_id") == incarnation_id)
        ]
        if len(candidates) != 1:
            raise WeaveProtocolError("origin_not_manifested")
        return cast(Mapping[str, Any], candidates[0])


def _provisional_manifest(value: Mapping[str, Any]) -> Mapping[str, Any]:
    _closed(
        value,
        {"schema", "being_ref", "revision", "embodiments"},
        "invalid_manifest_fields",
    )
    _legacy_ref(value["being_ref"], "being")
    _uint(value["revision"], "invalid_manifest_revision", minimum=1)
    rows = value["embodiments"]
    if not isinstance(rows, list) or not 1 <= len(rows) <= 256:
        raise WeaveProtocolError("invalid_manifest_embodiments")
    seen_embodiments: set[str] = set()
    seen_principals: set[str] = set()
    for row in rows:
        _closed(
            row,
            {"embodiment_id", "principal_id", "body_ref", "status"},
            "invalid_manifest_embodiment",
        )
        embodiment_id = _legacy_ref(row["embodiment_id"], "embodiment")
        principal_id = _text(
            row["principal_id"], "invalid_manifest_embodiment", maximum=128
        )
        _text(row["body_ref"], "invalid_manifest_embodiment")
        if row["status"] not in {"active", "retired"}:
            raise WeaveProtocolError("invalid_manifest_embodiment")
        if embodiment_id in seen_embodiments or principal_id in seen_principals:
            raise WeaveProtocolError("duplicate_manifest_member")
        seen_embodiments.add(embodiment_id)
        seen_principals.add(principal_id)
    if rows != sorted(rows, key=lambda row: row["embodiment_id"]):
        raise WeaveProtocolError("manifest_members_not_sorted")
    return value


def _root_manifest(value: Mapping[str, Any]) -> Mapping[str, Any]:
    _closed(
        value,
        {
            "schema",
            "being_ref",
            "control_head",
            "history_binding_id",
            "revision",
            "embodiments",
        },
        "invalid_manifest_fields",
    )
    _derived_ref(value["being_ref"], "dm:being:v1:", "invalid_being_ref")
    _derived_ref(value["control_head"], "dm:identity:v1:", "invalid_control_head")
    binding_id = value["history_binding_id"]
    if binding_id is not None:
        _derived_ref(binding_id, "dm:identity:v1:", "invalid_history_binding_id")
    _uint(value["revision"], "invalid_manifest_revision", minimum=1)
    rows = value["embodiments"]
    if not isinstance(rows, list) or not 1 <= len(rows) <= 256:
        raise WeaveProtocolError("invalid_manifest_embodiments")
    fields = {
        "body_ref",
        "embodiment_credential_id",
        "embodiment_id",
        "incarnation_authorization_id",
        "incarnation_id",
        "status",
    }
    seen_incarnations: set[str] = set()
    for row in rows:
        _closed(row, fields, "invalid_manifest_embodiment")
        _text(row["body_ref"], "invalid_manifest_embodiment")
        _derived_ref(
            row["embodiment_credential_id"],
            "dm:identity:v1:",
            "invalid_manifest_embodiment",
        )
        _scoped_id(row["embodiment_id"], "embodiment:", "invalid_manifest_embodiment")
        _derived_ref(
            row["incarnation_authorization_id"],
            "dm:identity:v1:",
            "invalid_manifest_embodiment",
        )
        _scoped_id(row["incarnation_id"], "incarnation:", "invalid_manifest_embodiment")
        if row["status"] not in {"active", "retired"}:
            raise WeaveProtocolError("invalid_manifest_embodiment")
        if row["incarnation_id"] in seen_incarnations:
            raise WeaveProtocolError("duplicate_manifest_member")
        seen_incarnations.add(row["incarnation_id"])
    if rows != sorted(
        rows, key=lambda row: (row["embodiment_id"], row["incarnation_id"])
    ):
        raise WeaveProtocolError("manifest_members_not_sorted")
    return value


class EventAuthority(Protocol):
    @property
    def manifest(self) -> BeingManifest:
        """Return the exact membership/configuration view."""

    def public_key(self, event: Mapping[str, Any]) -> bytes:
        """Validate the event origin and return its authorized Ed25519 key."""

    def validate_origin(
        self, origin: Mapping[str, Any], *, require_active: bool = False
    ) -> Mapping[str, Any]:
        """Validate one configured origin without granting transport authority."""

    def validate_transport_principal(
        self,
        origin: Mapping[str, Any],
        *,
        scheme: str,
        principal_id: str,
    ) -> Mapping[str, Any]:
        """Bind authenticated transport metadata to one configured origin."""


@dataclass(frozen=True)
class ProvisionalAuthority:
    manifest: BeingManifest
    public_keys: Mapping[str, str]

    def __post_init__(self) -> None:
        if self.manifest.trust_mode != "provisional":
            raise WeaveProtocolError("provisional_authority_requires_v1_manifest")

    def validate_origin(
        self, origin: Mapping[str, Any], *, require_active: bool = False
    ) -> Mapping[str, Any]:
        member = self.manifest.member(origin["embodiment_id"])
        if require_active and member["status"] != "active":
            raise WeaveProtocolError("origin_not_active")
        if (
            member["principal_id"] != origin["principal_id"]
            or member["body_ref"] != origin["body_ref"]
        ):
            raise WeaveProtocolError("origin_manifest_mismatch")
        return member

    def public_key(self, event: Mapping[str, Any]) -> bytes:
        self.validate_origin(event["origin"])
        public = self.public_keys.get(event["signature"]["kid"])
        if public is None:
            raise WeaveProtocolError("unknown_signing_key")
        return unb64url(public, length=32)

    def validate_transport_principal(
        self,
        origin: Mapping[str, Any],
        *,
        scheme: str,
        principal_id: str,
    ) -> Mapping[str, Any]:
        raise WeaveProtocolError("provisional_transport_authority_unsupported")


@dataclass(frozen=True)
class RootAuthority:
    manifest: BeingManifest
    state: ControlState
    credentials: Mapping[str, Artifact]
    incarnations: Mapping[str, Artifact]

    def __post_init__(self) -> None:
        if self.manifest.trust_mode != "root-bound":
            raise WeaveProtocolError("root_authority_requires_v2_manifest")
        if (
            self.manifest.being_ref != self.state.being_ref
            or self.manifest.value["control_head"] != self.state.head
        ):
            raise WeaveProtocolError("manifest_control_anchor_mismatch")
        if self.manifest.value["history_binding_id"] != self.state.activated_binding:
            raise WeaveProtocolError("manifest_binding_mismatch")
        for member in self.manifest.value["embodiments"]:
            incarnation = self.incarnations.get(member["incarnation_authorization_id"])
            if not isinstance(incarnation, Mapping):
                raise WeaveProtocolError("missing_origin_authorization")
            body = incarnation.get("body")
            if not isinstance(body, Mapping):
                raise WeaveProtocolError("missing_origin_authorization")
            started_at_ms = body.get("started_at_ms")
            if not isinstance(started_at_ms, int) or isinstance(started_at_ms, bool):
                raise WeaveProtocolError("missing_origin_authorization")
            self._verify_member(member, started_at_ms)

    def _verify_member(
        self, member: Mapping[str, Any], at_ms: int
    ) -> Mapping[str, Any]:
        credential = self.credentials.get(member["embodiment_credential_id"])
        incarnation = self.incarnations.get(member["incarnation_authorization_id"])
        if credential is None or incarnation is None:
            raise WeaveProtocolError("missing_origin_authorization")
        try:
            credential_body = verify_embodiment_credential(
                credential,
                self.state,
                at_ms=at_ms,
                allow_revoked_history=True,
            )
            incarnation_body = verify_incarnation_authorization(
                incarnation,
                credential,
                self.state,
                at_ms=at_ms,
            )
        except VerificationError as exception:
            raise WeaveProtocolError("invalid_origin_authorization") from exception
        if (
            credential["artifact_id"] != member["embodiment_credential_id"]
            or incarnation["artifact_id"] != member["incarnation_authorization_id"]
            or credential_body["embodiment_id"] != member["embodiment_id"]
            or credential_body["body_ref"] != member["body_ref"]
            or incarnation_body["incarnation_id"] != member["incarnation_id"]
        ):
            raise WeaveProtocolError("origin_authorization_mismatch")
        return credential_body

    def public_key(self, event: Mapping[str, Any]) -> bytes:
        origin = event["origin"]
        member = self.validate_origin(origin)
        credential_body = self._verify_member(member, event["occurred_at_ms"])
        if (
            credential_body["embodiment_id"] != origin["embodiment_id"]
            or credential_body["body_ref"] != origin["body_ref"]
        ):
            raise WeaveProtocolError("origin_authorization_mismatch")
        principals = {
            principal["principal_id"]
            for principal in credential_body["transport_principals"]
        }
        if origin["principal_id"] not in principals:
            raise WeaveProtocolError("origin_principal_not_bound")
        signing = credential_body["signing_key"]
        if event["signature"]["kid"] != signing["key_id"]:
            raise WeaveProtocolError("wrong_embodiment_signing_key")
        return unb64url(signing["public"], length=32)

    def validate_origin(
        self, origin: Mapping[str, Any], *, require_active: bool = False
    ) -> Mapping[str, Any]:
        member = self.manifest.member(origin["embodiment_id"], origin["incarnation_id"])
        if require_active and member["status"] != "active":
            raise WeaveProtocolError("origin_not_active")
        if member["body_ref"] != origin["body_ref"]:
            raise WeaveProtocolError("origin_manifest_mismatch")
        incarnation = self.incarnations[member["incarnation_authorization_id"]]
        credential_body = self._verify_member(
            member, incarnation["body"]["started_at_ms"]
        )
        principals = {
            principal["principal_id"]
            for principal in credential_body["transport_principals"]
        }
        if origin["principal_id"] not in principals:
            raise WeaveProtocolError("origin_principal_not_bound")
        return member

    def validate_transport_principal(
        self,
        origin: Mapping[str, Any],
        *,
        scheme: str,
        principal_id: str,
    ) -> Mapping[str, Any]:
        member = self.validate_origin(origin, require_active=True)
        if origin["principal_id"] != principal_id:
            raise WeaveProtocolError("transport_principal_mismatch")
        incarnation = self.incarnations[member["incarnation_authorization_id"]]
        credential_body = self._verify_member(
            member, incarnation["body"]["started_at_ms"]
        )
        if not any(
            transport["scheme"] == scheme and transport["principal_id"] == principal_id
            for transport in credential_body["transport_principals"]
        ):
            raise WeaveProtocolError("transport_principal_not_bound")
        return member


@dataclass(frozen=True)
class BoundHistoryAuthority:
    """Root-active authority plus exactly bound provisional event history."""

    active: RootAuthority
    historical: ProvisionalAuthority
    binding: Artifact
    historical_events: Mapping[str, Artifact]

    def __post_init__(self) -> None:
        if self.active.state.activated_binding != self.binding.get("artifact_id"):
            raise WeaveProtocolError("inactive_history_binding")
        body = self.binding.get("body")
        if not isinstance(body, Mapping):
            raise WeaveProtocolError("invalid_history_binding")
        accepted_heads = body.get("accepted_heads")
        if not isinstance(accepted_heads, list):
            raise WeaveProtocolError("invalid_history_binding")
        self._verify_history_closure(accepted_heads)

        def verify_head(head: Mapping[str, Any]) -> bool:
            event = self.historical_events.get(head["event_id"])
            if event is None:
                return False
            try:
                verified = verify_event(event, self.historical)
            except WeaveProtocolError:
                return False
            return bool(
                verified["content_hash"] == head["content_hash"]
                and verified["origin"]["incarnation_id"] == head["incarnation_id"]
                and verified["origin"]["embodiment_id"] == head["origin_embodiment_id"]
                and verified["sequence"] == head["sequence"]
                and verified["signature"]["kid"] == head["signer_key_id"]
            )

        try:
            verify_history_binding(
                self.binding,
                self.active.state,
                manifest_bytes=_canonical(self.historical.manifest.value),
                manifest_revision=self.historical.manifest.value["revision"],
                accepted_heads=accepted_heads,
                verify_head=verify_head,
            )
        except VerificationError as exception:
            raise WeaveProtocolError("invalid_history_binding") from exception
        if body.get("provisional_being_ref") != self.historical.manifest.being_ref:
            raise WeaveProtocolError("history_binding_being_mismatch")

    def _verify_history_closure(
        self, accepted_heads: Sequence[Mapping[str, Any]]
    ) -> None:
        verified: dict[str, Event] = {}
        for event_id, event in self.historical_events.items():
            value = verify_event(event, self.historical)
            if event_id != value["event_id"]:
                raise WeaveProtocolError("historical_event_key_mismatch")
            verified[event_id] = value
        reachable: set[str] = set()
        pending = [head["event_id"] for head in accepted_heads]
        while pending:
            event_id = pending.pop()
            if event_id in reachable:
                continue
            history_event = verified.get(event_id)
            if history_event is None:
                raise WeaveProtocolError("history_binding_missing_ancestor")
            reachable.add(event_id)
            previous = history_event["previous_event_id"]
            if previous is not None:
                predecessor = verified.get(previous)
                if (
                    predecessor is None
                    or predecessor["origin"]["incarnation_id"]
                    != history_event["origin"]["incarnation_id"]
                    or predecessor["sequence"] != history_event["sequence"] - 1
                ):
                    raise WeaveProtocolError("invalid_historical_origin_chain")
                pending.append(previous)
            pending.extend(history_event["causal_parents"])
        if reachable != set(verified):
            raise WeaveProtocolError("unbound_historical_event")

    @property
    def manifest(self) -> BeingManifest:
        return self.active.manifest

    @property
    def accepted_manifest_hashes(self) -> tuple[str, ...]:
        return tuple(
            sorted({self.active.manifest.digest, self.historical.manifest.digest})
        )

    def select(self, event: Mapping[str, Any]) -> EventAuthority:
        manifest_hash = event.get("manifest_hash")
        if manifest_hash == self.active.manifest.digest:
            return self.active
        if manifest_hash == self.historical.manifest.digest:
            if event.get("event_id") not in self.historical_events:
                raise WeaveProtocolError("unbound_historical_event")
            return self.historical
        raise WeaveProtocolError("unknown_manifest_hash")

    def public_key(self, event: Mapping[str, Any]) -> bytes:
        return self.select(event).public_key(event)

    def validate_origin(
        self, origin: Mapping[str, Any], *, require_active: bool = False
    ) -> Mapping[str, Any]:
        return self.active.validate_origin(origin, require_active=require_active)

    def validate_transport_principal(
        self,
        origin: Mapping[str, Any],
        *,
        scheme: str,
        principal_id: str,
    ) -> Mapping[str, Any]:
        return self.active.validate_transport_principal(
            origin, scheme=scheme, principal_id=principal_id
        )


@dataclass(frozen=True)
class EventSigner:
    key_id: str
    seed: bytes

    @property
    def public_key(self) -> bytes:
        if len(self.seed) != 32:
            raise WeaveProtocolError("invalid_signing_seed")
        return (
            Ed25519PrivateKey.from_private_bytes(self.seed)
            .public_key()
            .public_bytes_raw()
        )

    def signature(self, content_hash: str) -> Mapping[str, str]:
        if len(self.seed) != 32:
            raise WeaveProtocolError("invalid_signing_seed")
        value = Ed25519PrivateKey.from_private_bytes(self.seed).sign(
            EVENT_DOMAIN + bytes.fromhex(content_hash)
        )
        return {"alg": "Ed25519", "kid": self.key_id, "value": b64url(value)}


def create_event(
    authority: EventAuthority,
    origin: Mapping[str, Any],
    signer: EventSigner,
    *,
    event_id: str,
    sequence: int,
    previous_event_id: str | None,
    occurred_at_ms: int,
    causal_parents: Sequence[str],
    kind: str,
    subject: str,
    payload: Mapping[str, Any],
    supersedes: str | None = None,
    sensitivity: str = "personal",
) -> Event:
    member = authority.manifest.member(
        str(origin.get("embodiment_id")),
        str(origin.get("incarnation_id"))
        if authority.manifest.trust_mode == "root-bound"
        else None,
    )
    if member["status"] != "active":
        raise WeaveProtocolError("origin_not_active")
    core: Event = {
        "protocol": PROTOCOL,
        "event_id": event_id,
        "being_ref": authority.manifest.being_ref,
        "manifest_hash": authority.manifest.digest,
        "origin": copy.deepcopy(dict(origin)),
        "sequence": sequence,
        "previous_event_id": previous_event_id,
        "occurred_at_ms": occurred_at_ms,
        "causal_parents": sorted(set(causal_parents)),
        "kind": kind,
        "subject": subject,
        "payload": copy.deepcopy(dict(payload)),
        "supersedes": supersedes,
        "sensitivity": sensitivity,
    }
    _validate_core(core, authority.manifest)
    content_hash = hashlib.sha256(_canonical(core)).hexdigest()
    event = {
        **core,
        "content_hash": content_hash,
        "signature": signer.signature(content_hash),
    }
    verify_event(event, authority)
    return event


def _validate_core(core: Any, manifest: BeingManifest) -> Mapping[str, Any]:
    fields = {
        "protocol",
        "event_id",
        "being_ref",
        "manifest_hash",
        "origin",
        "sequence",
        "previous_event_id",
        "occurred_at_ms",
        "causal_parents",
        "kind",
        "subject",
        "payload",
        "supersedes",
        "sensitivity",
    }
    value = _closed(core, fields, "invalid_event_fields")
    if value["protocol"] != PROTOCOL:
        raise WeaveProtocolError("unsupported_event_protocol")
    _uuid(value["event_id"], "invalid_event_id")
    if value["being_ref"] != manifest.being_ref:
        raise WeaveProtocolError("wrong_being")
    if value["manifest_hash"] != manifest.digest:
        raise WeaveProtocolError("manifest_hash_mismatch")
    origin = _closed(
        value["origin"],
        {"embodiment_id", "incarnation_id", "principal_id", "body_ref"},
        "invalid_origin",
    )
    for field in ("embodiment_id", "incarnation_id", "body_ref"):
        _text(origin[field], "invalid_origin")
    _text(origin["principal_id"], "invalid_origin", maximum=128)
    if manifest.trust_mode == "provisional":
        _legacy_ref(origin["embodiment_id"], "embodiment")
        _legacy_ref(origin["incarnation_id"], "incarnation")
    sequence = _uint(value["sequence"], "invalid_sequence", minimum=1)
    previous = value["previous_event_id"]
    if sequence == 1:
        if previous is not None:
            raise WeaveProtocolError("unexpected_predecessor")
    elif previous is None:
        raise WeaveProtocolError("missing_predecessor")
    else:
        _uuid(previous, "invalid_previous_event_id")
    _uint(value["occurred_at_ms"], "invalid_occurred_at")
    parents = value["causal_parents"]
    if (
        not isinstance(parents, list)
        or len(parents) > MAX_CAUSAL_PARENTS
        or parents != sorted(set(parents))
    ):
        raise WeaveProtocolError("invalid_causal_parents")
    for parent in parents:
        _uuid(parent, "invalid_causal_parent")
    if value["kind"] not in EVENT_KINDS:
        raise WeaveProtocolError("unsupported_event_kind")
    _text(value["subject"], "invalid_subject")
    payload = value["payload"]
    if not isinstance(payload, Mapping) or len(payload) > 64:
        raise WeaveProtocolError("invalid_payload")
    _validate_payload(payload)
    if value["supersedes"] is not None:
        _uuid(value["supersedes"], "invalid_supersedes")
    if value["sensitivity"] not in SENSITIVITIES:
        raise WeaveProtocolError("invalid_sensitivity")
    if value["kind"] == "adoption.decided":
        decision = _closed(
            payload,
            {"target_event_id", "decision", "reason"},
            "invalid_adoption_decision",
        )
        _uuid(decision["target_event_id"], "invalid_target_event_id")
        if decision["decision"] not in DECISIONS:
            raise WeaveProtocolError("invalid_adoption_decision")
        _text(decision["reason"], "invalid_adoption_decision", maximum=1024)
    if value["kind"] == "projection.receipted":
        receipt = _closed(
            payload,
            {
                "actor",
                "adapter",
                "authority",
                "completed_at_ms",
                "decision_event_id",
                "intent_hash",
                "observed_postcondition",
                "preview_hash",
                "resource_fence",
                "result",
                "started_at_ms",
                "target_event_id",
            },
            "invalid_projection_receipt",
        )
        _uuid(receipt["target_event_id"], "invalid_projection_receipt")
        _uuid(receipt["decision_event_id"], "invalid_projection_receipt")
        _text(receipt["adapter"], "invalid_projection_receipt", maximum=128)
        _hex_hash(receipt["preview_hash"], "invalid_projection_receipt")
        _hex_hash(receipt["intent_hash"], "invalid_projection_receipt")
        _text(receipt["actor"], "invalid_projection_receipt", maximum=128)
        if receipt["authority"] not in PROJECTION_AUTHORITIES:
            raise WeaveProtocolError("invalid_projection_receipt")
        if receipt["result"] not in PROJECTION_RESULTS:
            raise WeaveProtocolError("invalid_projection_receipt")
        started = _uint(receipt["started_at_ms"], "invalid_projection_receipt")
        completed = _uint(receipt["completed_at_ms"], "invalid_projection_receipt")
        if completed < started:
            raise WeaveProtocolError("invalid_projection_receipt")
        try:
            validate_observed_postcondition(receipt["observed_postcondition"])
        except ClusterEvidenceError as exception:
            raise WeaveProtocolError("invalid_projection_receipt") from exception
        fence = receipt["resource_fence"]
        if fence is not None:
            try:
                position = validate_resource_fence_position(fence)
            except ClusterEvidenceError as exception:
                raise WeaveProtocolError("invalid_projection_receipt") from exception
            if position["holder_embodiment_id"] != origin["embodiment_id"]:
                raise WeaveProtocolError("invalid_projection_receipt")
    return value


def verify_event(event: Any, authority: EventAuthority) -> Event:
    fields = {
        "protocol",
        "event_id",
        "being_ref",
        "manifest_hash",
        "origin",
        "sequence",
        "previous_event_id",
        "occurred_at_ms",
        "causal_parents",
        "kind",
        "subject",
        "payload",
        "supersedes",
        "sensitivity",
        "content_hash",
        "signature",
    }
    value = _closed(event, fields, "invalid_event_fields")
    selected: EventAuthority = (
        authority.select(value)
        if isinstance(authority, BoundHistoryAuthority)
        else authority
    )
    if len(_canonical(value)) > MAX_EVENT_BYTES:
        raise WeaveProtocolError("event_too_large")
    core = {
        key: copy.deepcopy(item)
        for key, item in value.items()
        if key not in {"content_hash", "signature"}
    }
    _validate_core(core, selected.manifest)
    content_hash = hashlib.sha256(_canonical(core)).hexdigest()
    if value["content_hash"] != content_hash:
        raise WeaveProtocolError("content_hash_mismatch")
    signature = _closed(
        value["signature"], {"alg", "kid", "value"}, "invalid_signature"
    )
    if signature["alg"] != "Ed25519":
        raise WeaveProtocolError("invalid_signature")
    _text(signature["kid"], "invalid_signature", maximum=128)
    try:
        public_key = selected.public_key(value)
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            unb64url(signature["value"], length=64),
            EVENT_DOMAIN + bytes.fromhex(content_hash),
        )
    except (CanonicalError, InvalidSignature, VerificationError) as exception:
        raise WeaveProtocolError("invalid_signature") from exception
    return copy.deepcopy(dict(value))


def page_bytes(events: Sequence[Mapping[str, Any]]) -> bytes:
    return _canonical({"events": list(events)})


__all__ = [
    "DECISIONS",
    "EVENT_DOMAIN",
    "EVENT_KINDS",
    "MAX_PAGE_BYTES",
    "MAX_PAGE_EVENTS",
    "PROJECTION_AUTHORITIES",
    "PROJECTION_RESULTS",
    "PROTOCOL",
    "SENSITIVITIES",
    "BeingManifest",
    "BoundHistoryAuthority",
    "Event",
    "EventAuthority",
    "EventSigner",
    "ProvisionalAuthority",
    "RootAuthority",
    "WeaveProtocolError",
    "create_event",
    "page_bytes",
    "verify_event",
]
