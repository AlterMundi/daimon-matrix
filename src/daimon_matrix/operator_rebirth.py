"""Two-party ceremony for adding a self-custodied embodiment to one being.

The target creates a request and proves possession of fresh body keys.  The
offline root holder countersigns only public material and an exact manifest
successor.  No function in this module requires root seeds and embodiment
private keys in the same process.
"""

from __future__ import annotations

import copy
from collections.abc import Mapping, Sequence
from typing import Any, Final

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .authority_epochs import (
    RootHistoryAuthority,
    create_embodiment_enrollment,
    verify_embodiment_enrollment,
)
from .canonical import b64url, canonical_bytes, digest, domain_bytes, unb64url
from .identity import (
    DOMAINS,
    ControlState,
    create_embodiment_credential,
    create_incarnation_authorization,
    ed25519_public,
    key_descriptor,
    key_id,
    signing_descriptor,
    verify_embodiment_credential,
    verify_incarnation_authorization,
    x25519_public,
)
from .weave import BeingManifest, RootAuthority

REQUEST_SCHEMA: Final = "dm.operator.embodiment-request/v1"
REQUEST_DOMAIN: Final = "dm.operator.embodiment-request/v1"
TRANSPORT_REQUEST_DOMAIN: Final = "dm.operator.embodiment-request-transport/v1"
REQUEST_ID_PREFIX: Final = "dm:embodiment-request:v1:"
ACTIVATION_SCHEMA: Final = "dm.operator.embodiment-activation/v1"
ACTIVATION_DOMAIN: Final = "dm.operator.embodiment-activation/v1"
ACTIVATION_ID_PREFIX: Final = "dm:embodiment-activation:v1:"
TRANSPORT_SCHEME: Final = "dm-peer-v1"
MAX_TIME: Final = 2**53 - 1
MAX_ARTIFACT_BYTES: Final = 1024 * 1024


class RebirthError(RuntimeError):
    """The enrollment ceremony is malformed, stale, or unauthorized."""


def _closed(value: Any, fields: set[str], code: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise RebirthError(code)
    return value


def _bounded(value: Any, code: str, *, maximum: int = 512) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > maximum
        or any(character.isspace() for character in value)
    ):
        raise RebirthError(code)
    return value


def _uint(value: Any, code: str) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not 0 <= value <= MAX_TIME
    ):
        raise RebirthError(code)
    return value


def _canonical(value: Any, code: str) -> bytes:
    try:
        raw = canonical_bytes(value)
    except (TypeError, ValueError) as exception:
        raise RebirthError(code) from exception
    if len(raw) > MAX_ARTIFACT_BYTES:
        raise RebirthError("rebirth_artifact_too_large")
    return raw


def _request_signature(
    seed: bytes, body: Mapping[str, Any], *, domain: str = REQUEST_DOMAIN
) -> dict[str, str]:
    public = ed25519_public(seed)
    return {
        "alg": "Ed25519",
        "kid": key_id("Ed25519", public),
        "value": b64url(
            Ed25519PrivateKey.from_private_bytes(seed).sign(domain_bytes(domain, body))
        ),
    }


def _identity_signature(seed: bytes, role: str, preimage: bytes) -> dict[str, str]:
    descriptor = signing_descriptor(seed)
    return {
        "algorithm": "Ed25519",
        "key_id": descriptor["key_id"],
        "role": role,
        "value": b64url(Ed25519PrivateKey.from_private_bytes(seed).sign(preimage)),
    }


def _origin(value: Any) -> dict[str, str]:
    row = _closed(
        value,
        {"body_ref", "embodiment_id", "incarnation_id", "principal_id"},
        "invalid_rebirth_origin",
    )
    return {
        "body_ref": _bounded(row["body_ref"], "invalid_rebirth_origin"),
        "embodiment_id": _bounded(row["embodiment_id"], "invalid_rebirth_origin"),
        "incarnation_id": _bounded(row["incarnation_id"], "invalid_rebirth_origin"),
        "principal_id": _bounded(row["principal_id"], "invalid_rebirth_origin"),
    }


def create_enrollment_request(
    base: RootAuthority,
    *,
    signing_seed: bytes,
    encryption_private: bytes,
    transport_seed: bytes,
    body_ref: str,
    embodiment_id: str,
    incarnation_id: str,
    principal_id: str,
    created_at_ms: int,
    expires_at_ms: int,
    nonce: bytes,
    purposes: Sequence[str] = ("dm.we", "messages"),
) -> dict[str, Any]:
    """Create a public request while every private body key stays local."""

    if len(nonce) != 32:
        raise RebirthError("invalid_rebirth_nonce")
    origin = _origin(
        {
            "body_ref": body_ref,
            "embodiment_id": embodiment_id,
            "incarnation_id": incarnation_id,
            "principal_id": principal_id,
        }
    )
    created = _uint(created_at_ms, "invalid_rebirth_time")
    expires = _uint(expires_at_ms, "invalid_rebirth_time")
    if not created < expires:
        raise RebirthError("invalid_rebirth_time")
    if any(
        row["embodiment_id"] == origin["embodiment_id"]
        for row in base.manifest.value["embodiments"]
    ):
        raise RebirthError("rebirth_embodiment_already_exists")
    transport_principal = {
        "scheme": TRANSPORT_SCHEME,
        "principal_id": origin["principal_id"],
        "key": key_descriptor("Ed25519", ed25519_public(transport_seed)),
    }
    # An empty root seed list intentionally creates a body-accepted partial
    # credential.  The offline half adds the threshold root signatures.
    credential = create_embodiment_credential(
        base.state,
        [],
        signing_seed,
        x25519_public(encryption_private),
        embodiment_id=origin["embodiment_id"],
        body_ref=origin["body_ref"],
        purposes=purposes,
        valid_from_ms=created,
        valid_until_ms=MAX_TIME,
        transport_principals=[transport_principal],
    )
    incarnation = create_incarnation_authorization(
        credential,
        signing_seed,
        incarnation_id=origin["incarnation_id"],
        incarnation_sequence=0,
        started_at_ms=created,
    )
    body = {
        "being_ref": base.manifest.being_ref,
        "control_head": base.state.head,
        "base_manifest_hash": base.manifest.digest,
        "base_revision": base.manifest.value["revision"],
        "origin": origin,
        "credential": credential,
        "incarnation": incarnation,
        "created_at_ms": created,
        "expires_at_ms": expires,
        "nonce": b64url(nonce),
    }
    request = {
        "schema": REQUEST_SCHEMA,
        "request_id": REQUEST_ID_PREFIX + b64url(digest(REQUEST_DOMAIN, body)),
        "body": body,
        "signature": _request_signature(signing_seed, body),
        "transport_signature": _request_signature(
            transport_seed, body, domain=TRANSPORT_REQUEST_DOMAIN
        ),
    }
    _canonical(request, "invalid_rebirth_request")
    return request


def validate_enrollment_request(
    value: Any,
    base: RootAuthority,
    *,
    observed_at_ms: int,
) -> dict[str, Any]:
    """Validate freshness, base binding, and possession before root signing."""

    row = _closed(
        value,
        {"schema", "request_id", "body", "signature", "transport_signature"},
        "invalid_rebirth_request",
    )
    if row["schema"] != REQUEST_SCHEMA:
        raise RebirthError("unsupported_rebirth_request")
    body = _closed(
        row["body"],
        {
            "being_ref",
            "control_head",
            "base_manifest_hash",
            "base_revision",
            "origin",
            "credential",
            "incarnation",
            "created_at_ms",
            "expires_at_ms",
            "nonce",
        },
        "invalid_rebirth_request",
    )
    created = _uint(body["created_at_ms"], "invalid_rebirth_time")
    expires = _uint(body["expires_at_ms"], "invalid_rebirth_time")
    observed = _uint(observed_at_ms, "invalid_rebirth_time")
    if not created <= observed < expires:
        raise RebirthError("rebirth_request_not_timely")
    try:
        nonce = b64url(unb64url(str(body["nonce"]), length=32))
    except (TypeError, ValueError) as exception:
        raise RebirthError("invalid_rebirth_nonce") from exception
    if nonce != body["nonce"]:
        raise RebirthError("invalid_rebirth_nonce")
    if (
        body["being_ref"] != base.manifest.being_ref
        or body["control_head"] != base.state.head
        or body["base_manifest_hash"] != base.manifest.digest
        or body["base_revision"] != base.manifest.value["revision"]
    ):
        raise RebirthError("rebirth_request_base_mismatch")
    origin = _origin(body["origin"])
    if any(
        existing["embodiment_id"] == origin["embodiment_id"]
        for existing in base.manifest.value["embodiments"]
    ):
        raise RebirthError("rebirth_embodiment_already_exists")
    credential = _closed(
        body["credential"],
        {"schema", "kind", "artifact_id", "body", "signatures"},
        "invalid_rebirth_credential",
    )
    credential_body = _closed(
        credential["body"],
        {
            "being_ref",
            "body_ref",
            "control_head",
            "embodiment_id",
            "encryption_key",
            "purposes",
            "revocation_generation",
            "signing_key",
            "transport_principals",
            "valid_from_ms",
            "valid_until_ms",
        },
        "invalid_rebirth_credential",
    )
    signatures = credential["signatures"]
    if (
        credential["schema"] != "dm.identity.artifact/v1"
        or credential["kind"] != "embodiment-credential"
        or not isinstance(signatures, list)
        or len(signatures) != 1
        or not isinstance(signatures[0], Mapping)
        or signatures[0].get("role") != "embodiment-acceptance"
        or credential_body["being_ref"] != base.manifest.being_ref
        or credential_body["control_head"] != base.state.head
        or credential_body["body_ref"] != origin["body_ref"]
        or credential_body["embodiment_id"] != origin["embodiment_id"]
        or credential_body["valid_from_ms"] != created
        or "dm.we" not in credential_body["purposes"]
    ):
        raise RebirthError("invalid_rebirth_credential")
    signing = _closed(
        credential_body["signing_key"],
        {"algorithm", "key_id", "public"},
        "invalid_rebirth_credential",
    )
    try:
        signing_public = unb64url(str(signing["public"]), length=32)
        if signing["algorithm"] != "Ed25519" or signing["key_id"] != key_id(
            "Ed25519", signing_public
        ):
            raise RebirthError("invalid_rebirth_credential")
    except (TypeError, ValueError) as exception:
        raise RebirthError("invalid_rebirth_credential") from exception
    signature = _closed(
        row["signature"], {"alg", "kid", "value"}, "invalid_rebirth_signature"
    )
    if signature["alg"] != "Ed25519" or signature["kid"] != signing["key_id"]:
        raise RebirthError("invalid_rebirth_signature")
    try:
        Ed25519PublicKey.from_public_bytes(signing_public).verify(
            unb64url(str(signature["value"]), length=64),
            domain_bytes(REQUEST_DOMAIN, body),
        )
    except (InvalidSignature, TypeError, ValueError) as exception:
        raise RebirthError("invalid_rebirth_signature") from exception
    principals = credential_body["transport_principals"]
    matching_principals = [
        principal
        for principal in principals
        if isinstance(principal, Mapping)
        and principal.get("scheme") == TRANSPORT_SCHEME
        and principal.get("principal_id") == origin["principal_id"]
    ]
    if len(matching_principals) != 1:
        raise RebirthError("invalid_rebirth_transport_principal")
    transport = _closed(
        matching_principals[0],
        {"scheme", "principal_id", "key"},
        "invalid_rebirth_transport_principal",
    )
    transport_key = _closed(
        transport["key"],
        {"algorithm", "key_id", "public"},
        "invalid_rebirth_transport_principal",
    )
    try:
        transport_public = unb64url(str(transport_key["public"]), length=32)
        if transport_key["algorithm"] != "Ed25519" or transport_key["key_id"] != key_id(
            "Ed25519", transport_public
        ):
            raise RebirthError("invalid_rebirth_transport_principal")
    except (TypeError, ValueError) as exception:
        raise RebirthError("invalid_rebirth_transport_principal") from exception
    transport_signature = _closed(
        row["transport_signature"],
        {"alg", "kid", "value"},
        "invalid_rebirth_transport_signature",
    )
    if (
        transport_signature["alg"] != "Ed25519"
        or transport_signature["kid"] != transport_key["key_id"]
    ):
        raise RebirthError("invalid_rebirth_transport_signature")
    try:
        Ed25519PublicKey.from_public_bytes(transport_public).verify(
            unb64url(str(transport_signature["value"]), length=64),
            domain_bytes(TRANSPORT_REQUEST_DOMAIN, body),
        )
    except (InvalidSignature, TypeError, ValueError) as exception:
        raise RebirthError("invalid_rebirth_transport_signature") from exception
    expected_id = REQUEST_ID_PREFIX + b64url(digest(REQUEST_DOMAIN, body))
    if row["request_id"] != expected_id:
        raise RebirthError("rebirth_request_id_mismatch")
    result = copy.deepcopy(dict(row))
    if _canonical(result, "invalid_rebirth_request") != _canonical(
        value, "invalid_rebirth_request"
    ):
        raise RebirthError("noncanonical_rebirth_request")
    return result


def _authorized_root_seeds(state: ControlState, seeds: Sequence[bytes]) -> list[bytes]:
    policy = state.root_policy
    allowed = {row["key_id"] for row in policy["keys"]}
    selected: dict[str, bytes] = {}
    for seed in seeds:
        kid = key_id("Ed25519", ed25519_public(seed))
        if kid not in allowed or kid in selected:
            raise RebirthError("rebirth_root_seed_mismatch")
        selected[kid] = seed
    if len(selected) < policy["threshold"]:
        raise RebirthError("rebirth_root_threshold_shortfall")
    return [selected[kid] for kid in sorted(selected)]


def authorize_enrollment_request(
    request: Any,
    base: RootAuthority,
    *,
    root_seeds: Sequence[bytes],
    issued_at_ms: int,
) -> dict[str, Any]:
    """Offline-root half: countersign and authorize one exact new body."""

    issued = _uint(issued_at_ms, "invalid_rebirth_time")
    verified = validate_enrollment_request(request, base, observed_at_ms=issued)
    selected = _authorized_root_seeds(base.state, root_seeds)
    partial = verified["body"]["credential"]
    credential = copy.deepcopy(partial)
    root_preimage = domain_bytes(DOMAINS["embodiment-credential"], credential["body"])
    credential["signatures"].extend(
        _identity_signature(seed, "root-authorization", root_preimage)
        for seed in selected
    )
    credential["signatures"].sort(key=lambda row: (row["key_id"], row["role"]))
    try:
        credential_body = verify_embodiment_credential(
            credential, base.state, at_ms=issued
        )
        incarnation = copy.deepcopy(verified["body"]["incarnation"])
        incarnation_body = verify_incarnation_authorization(
            incarnation, credential, base.state, at_ms=issued
        )
    except ValueError as exception:
        raise RebirthError("rebirth_authorization_invalid") from exception
    origin = _origin(verified["body"]["origin"])
    if (
        credential_body["embodiment_id"] != origin["embodiment_id"]
        or credential_body["body_ref"] != origin["body_ref"]
        or incarnation_body["incarnation_id"] != origin["incarnation_id"]
        or incarnation_body["incarnation_sequence"] != 0
        or incarnation_body["started_at_ms"] > issued
    ):
        raise RebirthError("rebirth_authorization_invalid")
    rows = copy.deepcopy(base.manifest.value["embodiments"])
    rows.append(
        {
            "body_ref": origin["body_ref"],
            "embodiment_credential_id": credential["artifact_id"],
            "embodiment_id": origin["embodiment_id"],
            "incarnation_authorization_id": incarnation["artifact_id"],
            "incarnation_id": origin["incarnation_id"],
            "status": "active",
        }
    )
    rows.sort(key=lambda row: (row["embodiment_id"], row["incarnation_id"]))
    manifest = BeingManifest.from_value(
        {
            **base.manifest.value,
            "revision": base.manifest.value["revision"] + 1,
            "embodiments": rows,
        }
    )
    credentials = {**base.credentials, credential["artifact_id"]: credential}
    incarnations = {
        **base.incarnations,
        incarnation["artifact_id"]: incarnation,
    }
    successor = RootAuthority(manifest, base.state, credentials, incarnations)
    transition = create_embodiment_enrollment(
        base.manifest,
        manifest,
        request_id=verified["request_id"],
        body_ref=origin["body_ref"],
        embodiment_id=origin["embodiment_id"],
        incarnation_id=origin["incarnation_id"],
        embodiment_credential_id=credential["artifact_id"],
        incarnation_authorization_id=incarnation["artifact_id"],
        principal_id=origin["principal_id"],
        root_seeds=selected,
        issued_at_ms=issued,
    )
    verify_embodiment_enrollment(transition, base, successor)
    RootHistoryAuthority(successor, [base], [transition])
    body = {
        "request_id": verified["request_id"],
        "being_ref": base.manifest.being_ref,
        "control_head": base.state.head,
        "previous_manifest_hash": base.manifest.digest,
        "successor_manifest": manifest.value,
        "credential": credential,
        "incarnation": incarnation,
        "origin": origin,
        "transition": transition,
        "issued_at_ms": issued,
    }
    activation = {
        "schema": ACTIVATION_SCHEMA,
        "activation_id": ACTIVATION_ID_PREFIX + b64url(digest(ACTIVATION_DOMAIN, body)),
        "body": body,
    }
    _canonical(activation, "invalid_rebirth_activation")
    return activation


def validate_activation(
    value: Any,
    base: RootAuthority,
    *,
    request: Any | None = None,
) -> tuple[dict[str, Any], RootAuthority, RootHistoryAuthority]:
    """Validate a public activation and return its exact authority chain."""

    row = _closed(
        value,
        {"schema", "activation_id", "body"},
        "invalid_rebirth_activation",
    )
    if row["schema"] != ACTIVATION_SCHEMA:
        raise RebirthError("unsupported_rebirth_activation")
    body = _closed(
        row["body"],
        {
            "request_id",
            "being_ref",
            "control_head",
            "previous_manifest_hash",
            "successor_manifest",
            "credential",
            "incarnation",
            "origin",
            "transition",
            "issued_at_ms",
        },
        "invalid_rebirth_activation",
    )
    if (
        body["being_ref"] != base.manifest.being_ref
        or body["control_head"] != base.state.head
        or body["previous_manifest_hash"] != base.manifest.digest
    ):
        raise RebirthError("rebirth_activation_base_mismatch")
    if request is not None:
        verified_request = validate_enrollment_request(
            request, base, observed_at_ms=body["issued_at_ms"]
        )
        if verified_request["request_id"] != body["request_id"]:
            raise RebirthError("rebirth_activation_request_mismatch")
    credential = copy.deepcopy(body["credential"])
    incarnation = copy.deepcopy(body["incarnation"])
    manifest = BeingManifest.from_value(body["successor_manifest"])
    successor = RootAuthority(
        manifest,
        base.state,
        {**base.credentials, credential["artifact_id"]: credential},
        {**base.incarnations, incarnation["artifact_id"]: incarnation},
    )
    transition = verify_embodiment_enrollment(body["transition"], base, successor)
    origin = _origin(body["origin"])
    if (
        transition["request_id"] != body["request_id"]
        or transition["body_ref"] != origin["body_ref"]
        or transition["embodiment_id"] != origin["embodiment_id"]
        or transition["incarnation_id"] != origin["incarnation_id"]
        or transition["principal_id"] != origin["principal_id"]
    ):
        raise RebirthError("rebirth_activation_origin_mismatch")
    history = RootHistoryAuthority(successor, [base], [transition])
    expected_id = ACTIVATION_ID_PREFIX + b64url(digest(ACTIVATION_DOMAIN, body))
    if row["activation_id"] != expected_id:
        raise RebirthError("rebirth_activation_id_mismatch")
    normalized = copy.deepcopy(dict(row))
    if _canonical(normalized, "invalid_rebirth_activation") != _canonical(
        value, "invalid_rebirth_activation"
    ):
        raise RebirthError("noncanonical_rebirth_activation")
    return normalized, successor, history


def apply_activation_to_runtime_bundle(
    bundle: Mapping[str, Any],
    activation: Any,
    base: RootAuthority,
    *,
    target_endpoint: str | None = None,
) -> dict[str, Any]:
    """Return a forward-only public bundle update for an existing peer."""

    verified, successor, _history = validate_activation(activation, base)
    if bundle.get("manifest") != base.manifest.value:
        raise RebirthError("rebirth_runtime_base_mismatch")
    result = copy.deepcopy(dict(bundle))
    authority_history = result.get("authority_history")
    if not isinstance(authority_history, list):
        raise RebirthError("rebirth_runtime_history_invalid")
    authority_history.append(
        {
            "manifest": copy.deepcopy(base.manifest.value),
            "successor": copy.deepcopy(verified["body"]["transition"]),
        }
    )
    result["manifest"] = copy.deepcopy(successor.manifest.value)
    result["credentials"] = list(successor.credentials.values())
    result["incarnations"] = list(successor.incarnations.values())
    if target_endpoint is not None:
        peer = result.get("peer_transport")
        if not isinstance(peer, dict) or not isinstance(peer.get("targets"), list):
            raise RebirthError("rebirth_runtime_peer_transport_missing")
        target_id = verified["body"]["origin"]["embodiment_id"]
        if any(row.get("embodiment_id") == target_id for row in peer["targets"]):
            raise RebirthError("rebirth_runtime_target_exists")
        peer["targets"].append(
            {
                "embodiment_id": target_id,
                "endpoint": _bounded(
                    target_endpoint, "invalid_rebirth_target", maximum=2048
                ),
                "timeout_ms": 5_000,
            }
        )
        peer["targets"].sort(key=lambda row: row["embodiment_id"])
    return result


__all__ = [
    "ACTIVATION_SCHEMA",
    "REQUEST_SCHEMA",
    "RebirthError",
    "apply_activation_to_runtime_bundle",
    "authorize_enrollment_request",
    "create_enrollment_request",
    "validate_activation",
    "validate_enrollment_request",
]
