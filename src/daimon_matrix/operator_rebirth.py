"""Two-party ceremony for adding a self-custodied embodiment to one being.

The target creates a request and proves possession of fresh body keys.  The
offline root holder countersigns only public material and an exact manifest
successor.  No function in this module requires root seeds and embodiment
private keys in the same process.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import sys
import tempfile
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .authority_epochs import (
    RootHistoryAuthority,
    create_embodiment_enrollment,
    create_recovery_rebirth,
    verify_embodiment_enrollment,
    verify_recovery_rebirth,
)
from .canonical import b64url, canonical_bytes, digest, domain_bytes, unb64url
from .client import CLIENT_CONFIG_SCHEMA
from .identity import (
    DOMAINS,
    ControlChain,
    ControlState,
    create_embodiment_credential,
    create_incarnation_authorization,
    create_recovery,
    ed25519_public,
    generate_ed25519_seed,
    generate_x25519_private,
    key_descriptor,
    key_id,
    signing_descriptor,
    verify_embodiment_credential,
    verify_incarnation_authorization,
    verify_recovery,
    x25519_public,
)
from .keystore import EncryptedKeystore, KeystoreError, PasswordReader
from .ledger import Ledger
from .local_api import LocalCapability, create_capability
from .peer_transport import PeerTransportError, http_peer_round_trip
from .runtime import load_runtime
from .service import SERVICE_METHODS
from .weave import BeingManifest, RootAuthority

REQUEST_SCHEMA: Final = "dm.operator.embodiment-request/v1"
REQUEST_DOMAIN: Final = "dm.operator.embodiment-request/v1"
TRANSPORT_REQUEST_DOMAIN: Final = "dm.operator.embodiment-request-transport/v1"
REQUEST_ID_PREFIX: Final = "dm:embodiment-request:v1:"
ACTIVATION_SCHEMA: Final = "dm.operator.embodiment-activation/v1"
ACTIVATION_DOMAIN: Final = "dm.operator.embodiment-activation/v1"
ACTIVATION_ID_PREFIX: Final = "dm:embodiment-activation:v1:"
RECOVERY_ACTIVATION_SCHEMA: Final = "dm.operator.recovery-activation/v1"
RECOVERY_ACTIVATION_DOMAIN: Final = "dm.operator.recovery-activation/v1"
RECOVERY_ACTIVATION_ID_PREFIX: Final = "dm:recovery-activation:v1:"
TRANSPORT_SCHEME: Final = "dm-peer-v1"
MAX_TIME: Final = 2**53 - 1
MAX_ARTIFACT_BYTES: Final = 1024 * 1024
AUTHORITY_SCHEMA: Final = "dm.operator.authority/v1"
TARGET_PROFILE_SCHEMA: Final = "dm.operator.rebirth-target-profile/v1"
PREPARATION_SCHEMA: Final = "dm.operator.rebirth-preparation/v1"
STATUS_OBSERVER_METHODS: Final = frozenset(
    {
        "runtime.status",
        "scope.me",
        "scope.we",
        "scope.we.diff",
        "scope.we.sync-plan",
    }
)
_LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class RebirthError(RuntimeError):
    """The enrollment ceremony is malformed, stale, or unauthorized."""


class _RequestBase(Protocol):
    @property
    def manifest(self) -> BeingManifest: ...

    @property
    def state(self) -> ControlState: ...


@dataclass(frozen=True)
class RecoveryRequestBase:
    """Public pre-activation view; it is never a runnable authority."""

    manifest: BeingManifest
    state: ControlState
    recovery_artifact: Mapping[str, Any]


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
    base: _RequestBase,
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
    base: _RequestBase,
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


def _exact_custody_role_seeds(
    secrets: Mapping[str, bytes],
    *,
    prefix: str,
    policy: Mapping[str, Any],
    code: str,
) -> list[bytes]:
    """Require custody to contain every and only one seed for a public role."""

    allowed = {row["key_id"] for row in policy["keys"]}
    selected: dict[str, bytes] = {}
    for slot, seed in sorted(secrets.items()):
        if not slot.startswith(prefix):
            continue
        kid = key_id("Ed25519", ed25519_public(seed))
        if kid not in allowed or kid in selected:
            raise RebirthError(code)
        selected[kid] = seed
    if set(selected) != allowed:
        raise RebirthError(code)
    return [selected[kid] for kid in sorted(selected)]


def recovery_request_base(
    previous: RootAuthority, recovery_artifact: Mapping[str, Any]
) -> RecoveryRequestBase:
    """Verify a recovery quorum artifact before target custody is generated."""

    try:
        recovered = verify_recovery(recovery_artifact, [previous.state])
    except (TypeError, ValueError) as exception:
        raise RebirthError("rebirth_recovery_artifact_invalid") from exception
    expected_revocations = sorted(
        {
            row["embodiment_id"]
            for row in previous.manifest.value["embodiments"]
            if row["status"] == "active"
        }
    )
    body = recovery_artifact.get("body")
    previous_root_ids = {row["key_id"] for row in previous.state.root_policy["keys"]}
    recovered_root_ids = {row["key_id"] for row in recovered.root_policy["keys"]}
    if (
        not isinstance(body, Mapping)
        or body.get("revoked_embodiments") != expected_revocations
    ):
        raise RebirthError("rebirth_recovery_incomplete_revocation")
    if previous_root_ids & recovered_root_ids:
        raise RebirthError("rebirth_recovery_root_reuse")
    return RecoveryRequestBase(
        previous.manifest,
        recovered,
        copy.deepcopy(dict(recovery_artifact)),
    )


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


def authorize_recovery_enrollment_request(
    request: Any,
    previous: RootAuthority,
    recovery_artifact: Mapping[str, Any],
    *,
    replacement_root_seeds: Sequence[bytes],
    issued_at_ms: int,
) -> dict[str, Any]:
    """Authorize the first fresh body directly under a recovered root."""

    issued = _uint(issued_at_ms, "invalid_rebirth_time")
    request_base = recovery_request_base(previous, recovery_artifact)
    verified = validate_enrollment_request(request, request_base, observed_at_ms=issued)
    selected = _authorized_root_seeds(request_base.state, replacement_root_seeds)
    partial = verified["body"]["credential"]
    credential = copy.deepcopy(partial)
    root_preimage = domain_bytes(DOMAINS["embodiment-credential"], credential["body"])
    credential["signatures"].extend(
        _identity_signature(seed, "root-authorization", root_preimage)
        for seed in selected
    )
    credential["signatures"].sort(key=lambda row: (row["key_id"], row["role"]))
    incarnation = copy.deepcopy(verified["body"]["incarnation"])
    try:
        credential_body = verify_embodiment_credential(
            credential, request_base.state, at_ms=issued
        )
        incarnation_body = verify_incarnation_authorization(
            incarnation, credential, request_base.state, at_ms=issued
        )
    except ValueError as exception:
        raise RebirthError("rebirth_recovery_authorization_invalid") from exception
    origin = _origin(verified["body"]["origin"])
    if (
        credential_body["embodiment_id"] != origin["embodiment_id"]
        or credential_body["body_ref"] != origin["body_ref"]
        or incarnation_body["incarnation_id"] != origin["incarnation_id"]
        or incarnation_body["incarnation_sequence"] != 0
        or incarnation_body["started_at_ms"] > issued
    ):
        raise RebirthError("rebirth_recovery_authorization_invalid")
    manifest = BeingManifest.from_value(
        {
            "schema": "being-manifest/v2",
            "being_ref": previous.manifest.being_ref,
            "control_head": request_base.state.head,
            "history_binding_id": previous.manifest.value["history_binding_id"],
            "revision": previous.manifest.value["revision"] + 1,
            "embodiments": [
                {
                    "body_ref": origin["body_ref"],
                    "embodiment_credential_id": credential["artifact_id"],
                    "embodiment_id": origin["embodiment_id"],
                    "incarnation_authorization_id": incarnation["artifact_id"],
                    "incarnation_id": origin["incarnation_id"],
                    "status": "active",
                }
            ],
        }
    )
    successor = RootAuthority(
        manifest,
        request_base.state,
        {credential["artifact_id"]: credential},
        {incarnation["artifact_id"]: incarnation},
    )
    transition = create_recovery_rebirth(
        previous.manifest,
        manifest,
        recovery_artifact=recovery_artifact,
        body_ref=origin["body_ref"],
        embodiment_id=origin["embodiment_id"],
        incarnation_id=origin["incarnation_id"],
        embodiment_credential_id=credential["artifact_id"],
        incarnation_authorization_id=incarnation["artifact_id"],
        principal_id=origin["principal_id"],
        root_seeds=selected,
        issued_at_ms=issued,
    )
    verify_recovery_rebirth(transition, previous, successor, recovery_artifact)
    RootHistoryAuthority(successor, [previous], [transition])
    body = {
        "request_id": verified["request_id"],
        "being_ref": previous.manifest.being_ref,
        "previous_control_head": previous.state.head,
        "previous_manifest_hash": previous.manifest.digest,
        "recovery_artifact": copy.deepcopy(dict(recovery_artifact)),
        "recovered_control_head": request_base.state.head,
        "successor_manifest": manifest.value,
        "credential": credential,
        "incarnation": incarnation,
        "origin": origin,
        "transition": transition,
        "issued_at_ms": issued,
    }
    activation = {
        "schema": RECOVERY_ACTIVATION_SCHEMA,
        "activation_id": RECOVERY_ACTIVATION_ID_PREFIX
        + b64url(digest(RECOVERY_ACTIVATION_DOMAIN, body)),
        "body": body,
    }
    _canonical(activation, "invalid_rebirth_recovery_activation")
    return activation


def validate_recovery_activation(
    value: Any,
    previous: RootAuthority,
    *,
    request: Any | None = None,
) -> tuple[dict[str, Any], RootAuthority, RootHistoryAuthority]:
    """Verify the recovery artifact, fresh-body request, and exact successor."""

    row = _closed(
        value,
        {"schema", "activation_id", "body"},
        "invalid_rebirth_recovery_activation",
    )
    if row["schema"] != RECOVERY_ACTIVATION_SCHEMA:
        raise RebirthError("unsupported_rebirth_recovery_activation")
    body = _closed(
        row["body"],
        {
            "request_id",
            "being_ref",
            "previous_control_head",
            "previous_manifest_hash",
            "recovery_artifact",
            "recovered_control_head",
            "successor_manifest",
            "credential",
            "incarnation",
            "origin",
            "transition",
            "issued_at_ms",
        },
        "invalid_rebirth_recovery_activation",
    )
    recovery_artifact = body["recovery_artifact"]
    if not isinstance(recovery_artifact, Mapping):
        raise RebirthError("rebirth_recovery_artifact_invalid")
    request_base = recovery_request_base(previous, recovery_artifact)
    if (
        body["being_ref"] != previous.manifest.being_ref
        or body["previous_control_head"] != previous.state.head
        or body["previous_manifest_hash"] != previous.manifest.digest
        or body["recovered_control_head"] != request_base.state.head
    ):
        raise RebirthError("rebirth_recovery_activation_base_mismatch")
    if request is not None:
        verified_request = validate_enrollment_request(
            request, request_base, observed_at_ms=body["issued_at_ms"]
        )
        if verified_request["request_id"] != body["request_id"]:
            raise RebirthError("rebirth_recovery_activation_request_mismatch")
    credential = copy.deepcopy(body["credential"])
    incarnation = copy.deepcopy(body["incarnation"])
    manifest = BeingManifest.from_value(body["successor_manifest"])
    successor = RootAuthority(
        manifest,
        request_base.state,
        {credential["artifact_id"]: credential},
        {incarnation["artifact_id"]: incarnation},
    )
    transition = verify_recovery_rebirth(
        body["transition"], previous, successor, recovery_artifact
    )
    origin = _origin(body["origin"])
    if (
        transition["embodiment_id"] != origin["embodiment_id"]
        or transition["incarnation_id"] != origin["incarnation_id"]
        or transition["body_ref"] != origin["body_ref"]
        or transition["principal_id"] != origin["principal_id"]
    ):
        raise RebirthError("rebirth_recovery_activation_origin_mismatch")
    history = RootHistoryAuthority(successor, [previous], [transition])
    expected_id = RECOVERY_ACTIVATION_ID_PREFIX + b64url(
        digest(RECOVERY_ACTIVATION_DOMAIN, body)
    )
    if row["activation_id"] != expected_id:
        raise RebirthError("rebirth_recovery_activation_id_mismatch")
    normalized = copy.deepcopy(dict(row))
    if _canonical(normalized, "invalid_rebirth_recovery_activation") != _canonical(
        value, "invalid_rebirth_recovery_activation"
    ):
        raise RebirthError("noncanonical_rebirth_recovery_activation")
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


def apply_recovery_activation_to_runtime_bundle(
    bundle: Mapping[str, Any],
    activation: Any,
    previous: RootAuthority,
) -> dict[str, Any]:
    """Return a target-only V7 bundle while preserving old public history."""

    verified, successor, _history = validate_recovery_activation(activation, previous)
    if (
        bundle.get("manifest") != previous.manifest.value
        or bundle.get("control_head") != previous.state.head
    ):
        raise RebirthError("rebirth_recovery_runtime_base_mismatch")
    result = copy.deepcopy(dict(bundle))
    authority_history = result.get("authority_history")
    control_artifacts = result.get("control_artifacts")
    credentials = result.get("credentials")
    incarnations = result.get("incarnations")
    if (
        not isinstance(authority_history, list)
        or not isinstance(control_artifacts, list)
        or not isinstance(credentials, list)
        or not isinstance(incarnations, list)
    ):
        raise RebirthError("rebirth_runtime_history_invalid")
    authority_history.append(
        {
            "manifest": copy.deepcopy(previous.manifest.value),
            "control_artifacts": copy.deepcopy(control_artifacts),
            "control_head": previous.state.head,
            "credentials": copy.deepcopy(credentials),
            "incarnations": copy.deepcopy(incarnations),
            "successor": copy.deepcopy(verified["body"]["transition"]),
        }
    )
    recovery_artifact = verified["body"]["recovery_artifact"]
    if any(
        artifact.get("artifact_id") == recovery_artifact.get("artifact_id")
        for artifact in control_artifacts
        if isinstance(artifact, Mapping)
    ):
        raise RebirthError("rebirth_recovery_artifact_replay")
    control_artifacts.append(copy.deepcopy(recovery_artifact))
    result["control_head"] = successor.state.head
    result["manifest"] = copy.deepcopy(successor.manifest.value)
    result["credentials"] = list(successor.credentials.values())
    result["incarnations"] = list(successor.incarnations.values())
    peer = result.get("peer_transport")
    if not isinstance(peer, dict) or not isinstance(peer.get("targets"), list):
        raise RebirthError("rebirth_runtime_peer_transport_missing")
    peer["targets"] = []
    return result


def _artifact_index(values: Any, code: str) -> dict[str, Mapping[str, Any]]:
    if not isinstance(values, list) or not 1 <= len(values) <= 256:
        raise RebirthError(code)
    result: dict[str, Mapping[str, Any]] = {}
    for value in values:
        if not isinstance(value, Mapping) or not isinstance(
            value.get("artifact_id"), str
        ):
            raise RebirthError(code)
        artifact_id = value["artifact_id"]
        if artifact_id in result:
            raise RebirthError(code)
        result[artifact_id] = copy.deepcopy(dict(value))
    return result


def authority_from_document(value: Any) -> RootAuthority:
    """Verify one public bootstrap authority document for a ceremony."""

    document = _closed(
        value,
        {
            "schema",
            "control_artifacts",
            "control_head",
            "manifest",
            "credentials",
            "incarnations",
        },
        "invalid_rebirth_authority",
    )
    if document["schema"] != AUTHORITY_SCHEMA:
        raise RebirthError("unsupported_rebirth_authority")
    controls = document["control_artifacts"]
    if not isinstance(controls, list) or not 1 <= len(controls) <= 1024:
        raise RebirthError("invalid_rebirth_authority")
    try:
        chain = ControlChain(controls[0])
        for artifact in controls[1:]:
            chain.add(artifact)
        state = chain.state
        if document["control_head"] != state.head:
            raise RebirthError("rebirth_authority_head_mismatch")
        authority = RootAuthority(
            BeingManifest.from_value(document["manifest"]),
            state,
            _artifact_index(document["credentials"], "invalid_rebirth_authority"),
            _artifact_index(document["incarnations"], "invalid_rebirth_authority"),
        )
    except RebirthError:
        raise
    except (AttributeError, KeyError, TypeError, ValueError) as exception:
        raise RebirthError("invalid_rebirth_authority") from exception
    return authority


def authority_from_runtime_bundle(value: Any) -> RootAuthority:
    """Verify the active root authority and signed history in one V7 bundle."""

    fields = {
        "schema",
        "control_artifacts",
        "control_head",
        "manifest",
        "authority_history",
        "credentials",
        "incarnations",
        "binding",
        "binding_activation",
        "provisional_history",
        "local_origin",
        "ledger",
        "socket",
        "keystore",
        "capabilities",
        "routing",
        "scopes",
        "peer_transport",
        "species",
        "sources",
        "relationships",
    }
    bundle = _closed(value, fields, "invalid_rebirth_runtime_bundle")
    if bundle["schema"] != "dm.runtime.bundle/v7":
        raise RebirthError("unsupported_rebirth_runtime_bundle")
    if any(
        bundle[field] is not None
        for field in ("binding", "binding_activation", "provisional_history")
    ):
        raise RebirthError("incompatible_rebirth_runtime_history")
    authority = authority_from_document(
        {
            "schema": AUTHORITY_SCHEMA,
            "control_artifacts": bundle["control_artifacts"],
            "control_head": bundle["control_head"],
            "manifest": bundle["manifest"],
            "credentials": bundle["credentials"],
            "incarnations": bundle["incarnations"],
        }
    )
    history = bundle["authority_history"]
    if not isinstance(history, list) or len(history) > 256:
        raise RebirthError("invalid_rebirth_runtime_history")
    epochs: list[Mapping[str, Any]] = []
    try:
        for entry in history:
            if isinstance(entry, Mapping) and set(entry) == {
                "manifest",
                "successor",
            }:
                epochs.append(entry)
            else:
                epochs.append(
                    _closed(
                        entry,
                        {
                            "manifest",
                            "control_artifacts",
                            "control_head",
                            "credentials",
                            "incarnations",
                            "successor",
                        },
                        "invalid_rebirth_runtime_history",
                    )
                )
        historical_reversed: list[RootAuthority] = []
        next_authority = authority
        for epoch in reversed(epochs):
            if set(epoch) == {"manifest", "successor"}:
                historical_authority = RootAuthority(
                    BeingManifest.from_value(epoch["manifest"]),
                    next_authority.state,
                    next_authority.credentials,
                    next_authority.incarnations,
                )
            else:
                historical_authority = authority_from_document(
                    {
                        "schema": AUTHORITY_SCHEMA,
                        "control_artifacts": epoch["control_artifacts"],
                        "control_head": epoch["control_head"],
                        "manifest": epoch["manifest"],
                        "credentials": epoch["credentials"],
                        "incarnations": epoch["incarnations"],
                    }
                )
            historical_reversed.append(historical_authority)
            next_authority = historical_authority
        if epochs:
            historical = list(reversed(historical_reversed))
            successors = []
            for epoch in epochs:
                successor = epoch["successor"]
                if not isinstance(successor, Mapping):
                    raise RebirthError("invalid_rebirth_runtime_history")
                successors.append(copy.deepcopy(dict(successor)))
            RootHistoryAuthority(authority, historical, successors)
    except RebirthError:
        raise
    except (KeyError, TypeError, ValueError) as exception:
        raise RebirthError("invalid_rebirth_runtime_history") from exception
    return authority


def _safe_document(path: Path, code: str) -> Any:
    try:
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise RebirthError(code)
        raw = path.read_bytes()
        if not 1 <= len(raw) <= 4 * MAX_ARTIFACT_BYTES:
            raise RebirthError(code)
        value = json.loads(raw)
        if canonical_bytes(value) != raw.rstrip(b"\n"):
            raise RebirthError(code)
        return value
    except RebirthError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exception:
        raise RebirthError(code) from exception


def _owner_directory(path: Path, code: str) -> Path:
    absolute = Path(os.path.abspath(path))
    try:
        info = absolute.lstat()
    except FileNotFoundError as exception:
        raise RebirthError(code) from exception
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise RebirthError(code)
    return absolute


def _private_write(path: Path, value: Mapping[str, Any] | bytes) -> None:
    raw = value if isinstance(value, bytes) else canonical_bytes(value)
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        offset = 0
        while offset < len(raw):
            offset += os.write(descriptor, raw[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _password(descriptor: int) -> bytearray:
    if descriptor < 0:
        raise RebirthError("invalid_rebirth_password_descriptor")
    try:
        value = os.read(descriptor, 1025)
    except OSError as exception:
        raise RebirthError("rebirth_password_unavailable") from exception
    finally:
        with suppress(OSError):
            os.close(descriptor)
    if not 12 <= len(value) <= 1024:
        raise RebirthError("invalid_rebirth_password_length")
    return bytearray(value)


def _password_reader(password: bytearray) -> PasswordReader:
    def read() -> bytearray:
        return bytearray(password)

    return read


def _target_profile(
    value: Any,
    base: _RequestBase,
    *,
    expected_targets: set[str] | None = None,
) -> dict[str, Any]:
    document = _closed(
        value,
        {
            "schema",
            "label",
            "body_ref",
            "principal_id",
            "listen_host",
            "listen_port",
            "advertised_endpoint",
            "targets",
        },
        "invalid_rebirth_target_profile",
    )
    if document["schema"] != TARGET_PROFILE_SCHEMA:
        raise RebirthError("unsupported_rebirth_target_profile")
    label = document["label"]
    listen_port = document["listen_port"]
    if (
        not isinstance(label, str)
        or _LABEL.fullmatch(label) is None
        or not isinstance(listen_port, int)
        or isinstance(listen_port, bool)
        or not 1 <= listen_port <= 65_535
    ):
        raise RebirthError("invalid_rebirth_target_profile")
    normalized: dict[str, Any] = {
        "schema": TARGET_PROFILE_SCHEMA,
        "label": label,
        "body_ref": _bounded(document["body_ref"], "invalid_rebirth_target_profile"),
        "principal_id": _bounded(
            document["principal_id"], "invalid_rebirth_target_profile"
        ),
        "listen_host": _bounded(
            document["listen_host"], "invalid_rebirth_target_profile", maximum=255
        ),
        "listen_port": listen_port,
        "advertised_endpoint": _bounded(
            document["advertised_endpoint"],
            "invalid_rebirth_target_profile",
            maximum=2048,
        ),
        "targets": [],
    }
    try:
        http_peer_round_trip(normalized["advertised_endpoint"], timeout_seconds=5.0)
    except (PeerTransportError, TypeError, ValueError) as exception:
        raise RebirthError("invalid_rebirth_target_profile") from exception
    targets = document["targets"]
    if not isinstance(targets, list) or len(targets) > 255:
        raise RebirthError("invalid_rebirth_target_profile")
    for target in targets:
        row = _closed(
            target,
            {"embodiment_id", "endpoint", "timeout_ms"},
            "invalid_rebirth_target_profile",
        )
        timeout = row["timeout_ms"]
        if (
            not isinstance(timeout, int)
            or isinstance(timeout, bool)
            or not 1 <= timeout <= 30_000
        ):
            raise RebirthError("invalid_rebirth_target_profile")
        endpoint = _bounded(
            row["endpoint"], "invalid_rebirth_target_profile", maximum=2048
        )
        try:
            http_peer_round_trip(endpoint, timeout_seconds=timeout / 1000)
        except (PeerTransportError, TypeError, ValueError) as exception:
            raise RebirthError("invalid_rebirth_target_profile") from exception
        normalized["targets"].append(
            {
                "embodiment_id": _bounded(
                    row["embodiment_id"], "invalid_rebirth_target_profile"
                ),
                "endpoint": endpoint,
                "timeout_ms": timeout,
            }
        )
    expected = (
        {
            str(row["embodiment_id"])
            for row in base.manifest.value["embodiments"]
            if row["status"] == "active"
        }
        if expected_targets is None
        else set(expected_targets)
    )
    normalized["targets"].sort(key=lambda row: row["embodiment_id"])
    if (
        {row["embodiment_id"] for row in normalized["targets"]} != expected
        or len(normalized["targets"]) != len(expected)
        or len({row["endpoint"] for row in normalized["targets"]})
        != len(normalized["targets"])
        or normalized["advertised_endpoint"]
        in {row["endpoint"] for row in normalized["targets"]}
    ):
        raise RebirthError("rebirth_target_set_mismatch")
    return normalized


def create_target_preparation(
    output: Path,
    authority: _RequestBase,
    profile: Any,
    password_reader: PasswordReader,
    *,
    created_at_ms: int,
    expires_at_ms: int,
    expected_targets: set[str] | None = None,
) -> dict[str, Any]:
    """Generate target-only encrypted custody and one public request atomically."""

    target_profile = _target_profile(
        profile, authority, expected_targets=expected_targets
    )
    target = Path(os.path.abspath(output))
    parent = _owner_directory(target.parent, "rebirth_output_parent_rejected")
    if target.exists() or target.is_symlink():
        raise RebirthError("rebirth_output_exists")
    staging: Path | None = None
    password = bytearray()
    try:
        supplied = password_reader()
        if (
            not isinstance(supplied, (bytes, bytearray))
            or not 12 <= len(supplied) <= 1024
        ):
            raise RebirthError("invalid_rebirth_password_length")
        password = bytearray(supplied)
        if isinstance(supplied, bytearray):
            supplied[:] = b"\x00" * len(supplied)
        staging = Path(tempfile.mkdtemp(prefix=f".{target.name}.tmp-", dir=parent))
        staging.chmod(0o700)
        signing_seed = generate_ed25519_seed()
        encryption_private = generate_x25519_private()
        transport_seed = generate_ed25519_seed()
        capability_key = secrets.token_bytes(32)
        status_key = secrets.token_bytes(32)
        label = target_profile["label"]
        origin = {
            "body_ref": target_profile["body_ref"],
            "embodiment_id": f"embodiment:{uuid.uuid4()}",
            "incarnation_id": f"incarnation:{uuid.uuid4()}",
            "principal_id": target_profile["principal_id"],
        }
        request = create_enrollment_request(
            authority,
            signing_seed=signing_seed,
            encryption_private=encryption_private,
            transport_seed=transport_seed,
            **origin,
            created_at_ms=created_at_ms,
            expires_at_ms=expires_at_ms,
            nonce=secrets.token_bytes(32),
        )
        capability = create_capability(
            capability_key,
            client_id=f"client:operator:{label}",
            methods=sorted(SERVICE_METHODS),
            not_before_ms=max(0, created_at_ms - 60_000),
            not_after_ms=MAX_TIME,
        )
        status_capability = create_capability(
            status_key,
            client_id=f"client:status-observer:{label}",
            methods=sorted(STATUS_OBSERVER_METHODS),
            not_before_ms=max(0, created_at_ms - 60_000),
            not_after_ms=MAX_TIME,
        )
        slots = {
            "signing": f"runtime.signing.v1:{label}",
            "encryption": f"peer.encryption.v1:{label}",
            "capability": f"runtime.capability.v1:{label}",
            "status_capability": f"runtime.capability.v1:status:{label}",
            "transport": f"transport.signing.v1:{label}",
        }
        EncryptedKeystore.create(
            staging / "custody.json",
            _password_reader(password),
            control_head=authority.state.head,
            secrets={
                slots["signing"]: signing_seed,
                slots["encryption"]: encryption_private,
                slots["capability"]: capability_key,
                slots["status_capability"]: status_key,
            },
        )
        EncryptedKeystore.create(
            staging / "transport-custody.json",
            _password_reader(password),
            control_head=authority.state.head,
            secrets={slots["transport"]: transport_seed},
        )
        preparation = {
            "schema": PREPARATION_SCHEMA,
            "request_id": request["request_id"],
            "being_ref": authority.manifest.being_ref,
            "control_head": authority.state.head,
            "base_manifest_hash": authority.manifest.digest,
            "origin": origin,
            "profile": target_profile,
            "slots": slots,
            "capabilities": {
                "operator": capability.descriptor,
                "status_observer": status_capability.descriptor,
            },
            "custody": {
                "filename": "custody.json",
                "counter": 1,
                "transport_filename": "transport-custody.json",
                "transport_counter": 1,
            },
            "created_at_ms": created_at_ms,
            "expires_at_ms": expires_at_ms,
        }
        _private_write(staging / "request.json", request)
        _private_write(staging / "preparation.json", preparation)
        _fsync_directory(staging)
        os.replace(staging, target)
        _fsync_directory(parent)
        staging = None
        return copy.deepcopy(preparation)
    finally:
        password[:] = b"\x00" * len(password)
        if staging is not None and staging.exists():
            shutil.rmtree(staging)


def create_recovery_target_preparation(
    output: Path,
    previous: RootAuthority,
    recovery_artifact: Mapping[str, Any],
    profile: Any,
    password_reader: PasswordReader,
    *,
    created_at_ms: int,
    expires_at_ms: int,
) -> dict[str, Any]:
    """Generate target custody only after the recovery quorum is public."""

    return create_target_preparation(
        output,
        recovery_request_base(previous, recovery_artifact),
        profile,
        password_reader,
        created_at_ms=created_at_ms,
        expires_at_ms=expires_at_ms,
        expected_targets=set(),
    )


def _validated_preparation(
    directory: Path,
    preparation: Any,
    request: Any,
    authority: _RequestBase,
    password_reader: PasswordReader,
    *,
    observed_at_ms: int,
    expected_targets: set[str] | None = None,
) -> tuple[dict[str, Any], Mapping[str, bytes], Mapping[str, bytes]]:
    root = _owner_directory(directory, "rebirth_preparation_directory_rejected")
    value = _closed(
        preparation,
        {
            "schema",
            "request_id",
            "being_ref",
            "control_head",
            "base_manifest_hash",
            "origin",
            "profile",
            "slots",
            "capabilities",
            "custody",
            "created_at_ms",
            "expires_at_ms",
        },
        "invalid_rebirth_preparation",
    )
    if value["schema"] != PREPARATION_SCHEMA:
        raise RebirthError("unsupported_rebirth_preparation")
    verified_request = validate_enrollment_request(
        request, authority, observed_at_ms=observed_at_ms
    )
    origin = _origin(value["origin"])
    profile = _target_profile(
        value["profile"], authority, expected_targets=expected_targets
    )
    request_body = verified_request["body"]
    if (
        value["request_id"] != verified_request["request_id"]
        or value["being_ref"] != authority.manifest.being_ref
        or value["control_head"] != authority.state.head
        or value["base_manifest_hash"] != authority.manifest.digest
        or origin != request_body["origin"]
        or origin["body_ref"] != profile["body_ref"]
        or origin["principal_id"] != profile["principal_id"]
        or value["created_at_ms"] != request_body["created_at_ms"]
        or value["expires_at_ms"] != request_body["expires_at_ms"]
    ):
        raise RebirthError("rebirth_preparation_binding_mismatch")
    slots = _closed(
        value["slots"],
        {"signing", "encryption", "capability", "status_capability", "transport"},
        "invalid_rebirth_preparation",
    )
    label = profile["label"]
    expected_slots = {
        "signing": f"runtime.signing.v1:{label}",
        "encryption": f"peer.encryption.v1:{label}",
        "capability": f"runtime.capability.v1:{label}",
        "status_capability": f"runtime.capability.v1:status:{label}",
        "transport": f"transport.signing.v1:{label}",
    }
    if slots != expected_slots:
        raise RebirthError("rebirth_preparation_slot_mismatch")
    capabilities = _closed(
        value["capabilities"],
        {"operator", "status_observer"},
        "invalid_rebirth_preparation",
    )
    custody = _closed(
        value["custody"],
        {"filename", "counter", "transport_filename", "transport_counter"},
        "invalid_rebirth_preparation",
    )
    if custody != {
        "filename": "custody.json",
        "counter": 1,
        "transport_filename": "transport-custody.json",
        "transport_counter": 1,
    }:
        raise RebirthError("invalid_rebirth_preparation")
    try:
        body_contents = EncryptedKeystore(root / custody["filename"]).open(
            password_reader,
            minimum_counter=custody["counter"],
            required_control_head=authority.state.head,
        )
        transport_contents = EncryptedKeystore(
            root / custody["transport_filename"]
        ).open(
            password_reader,
            minimum_counter=custody["transport_counter"],
            required_control_head=authority.state.head,
        )
    except (KeystoreError, KeyError, TypeError) as exception:
        raise RebirthError("rebirth_target_custody_rejected") from exception
    if set(body_contents.secrets) != {
        slots["signing"],
        slots["encryption"],
        slots["capability"],
        slots["status_capability"],
    } or set(transport_contents.secrets) != {slots["transport"]}:
        raise RebirthError("rebirth_target_custody_rejected")
    credential_body = request_body["credential"]["body"]
    principals = credential_body["transport_principals"]
    expected_principals = [
        principal
        for principal in principals
        if principal["scheme"] == TRANSPORT_SCHEME
        and principal["principal_id"] == origin["principal_id"]
    ]
    if len(expected_principals) != 1:
        raise RebirthError("rebirth_target_custody_rejected")
    if (
        signing_descriptor(body_contents.secrets[slots["signing"]])
        != credential_body["signing_key"]
        or key_descriptor(
            "X25519",
            x25519_public(body_contents.secrets[slots["encryption"]]),
        )
        != credential_body["encryption_key"]
        or key_descriptor(
            "Ed25519",
            ed25519_public(transport_contents.secrets[slots["transport"]]),
        )
        != expected_principals[0]["key"]
    ):
        raise RebirthError("rebirth_target_custody_rejected")
    try:
        operator = LocalCapability.from_value(
            capabilities["operator"], body_contents.secrets[slots["capability"]]
        )
        status = LocalCapability.from_value(
            capabilities["status_observer"],
            body_contents.secrets[slots["status_capability"]],
        )
    except (KeyError, TypeError, ValueError) as exception:
        raise RebirthError("rebirth_target_custody_rejected") from exception
    if (
        frozenset(operator.methods) != SERVICE_METHODS
        or frozenset(status.methods) != STATUS_OBSERVER_METHODS
    ):
        raise RebirthError("rebirth_target_capability_rejected")
    return (
        copy.deepcopy(dict(value)),
        body_contents.secrets,
        transport_contents.secrets,
    )


def _activate_target_runtime(
    output: Path,
    preparation_directory: Path,
    preparation: Any,
    request: Any,
    activation: Any,
    base_bundle: Any,
    password_reader: PasswordReader,
    *,
    recovery: bool,
) -> dict[str, Any]:
    """Build one fresh V7 target package without copying writable body state."""

    authority = authority_from_runtime_bundle(base_bundle)
    if recovery:
        verified_activation, successor, _history = validate_recovery_activation(
            activation, authority, request=request
        )
        request_base: _RequestBase = recovery_request_base(
            authority, verified_activation["body"]["recovery_artifact"]
        )
    else:
        verified_activation, successor, _history = validate_activation(
            activation, authority, request=request
        )
        request_base = authority
    issued_at_ms = verified_activation["body"]["issued_at_ms"]
    supplied = password_reader()
    if not isinstance(supplied, (bytes, bytearray)) or not 12 <= len(supplied) <= 1024:
        raise RebirthError("invalid_rebirth_password_length")
    password = bytearray(supplied)
    if isinstance(supplied, bytearray):
        supplied[:] = b"\x00" * len(supplied)
    staging: Path | None = None
    try:
        verified_preparation, body_secrets, transport_secrets = _validated_preparation(
            preparation_directory,
            preparation,
            request,
            request_base,
            _password_reader(password),
            observed_at_ms=issued_at_ms,
            expected_targets=set() if recovery else None,
        )
        target = Path(os.path.abspath(output))
        parent = _owner_directory(target.parent, "rebirth_output_parent_rejected")
        if target.exists() or target.is_symlink():
            raise RebirthError("rebirth_output_exists")
        staging = Path(tempfile.mkdtemp(prefix=f".{target.name}.tmp-", dir=parent))
        staging.chmod(0o700)
        runtime_root = staging / "runtime"
        runtime_root.mkdir(mode=0o700)
        host_client = staging / "host-client"
        host_client.mkdir(mode=0o700)
        slots = verified_preparation["slots"]
        capabilities = verified_preparation["capabilities"]
        profile = verified_preparation["profile"]
        origin = verified_preparation["origin"]
        bundle = (
            apply_recovery_activation_to_runtime_bundle(
                base_bundle, verified_activation, authority
            )
            if recovery
            else apply_activation_to_runtime_bundle(
                base_bundle, verified_activation, authority
            )
        )
        if bundle.get("schema") != "dm.runtime.bundle/v7":
            raise RebirthError("unsupported_rebirth_runtime_bundle")
        bundle["local_origin"] = copy.deepcopy(origin)
        bundle["ledger"] = "ledger.sqlite"
        bundle["socket"] = "matrix.sock"
        bundle["keystore"] = {
            "filename": "custody.json",
            "counter": 1,
            "signing_slot": slots["signing"],
        }
        bundle["capabilities"] = [
            {
                "descriptor": capabilities["operator"],
                "secret_slot": slots["capability"],
            },
            {
                "descriptor": capabilities["status_observer"],
                "secret_slot": slots["status_capability"],
            },
        ]
        bundle["routing"] = None
        bundle["scopes"] = {
            "body_capabilities": [],
            "relationships_filename": None,
        }
        bundle["peer_transport"] = {
            "enabled": True,
            "encryption_slot": slots["encryption"],
            "exchange_filename": "peer-exchange.sqlite",
            "listen_host": profile["listen_host"],
            "listen_port": profile["listen_port"],
            "outbox_filename": "peer-outbox.sqlite",
            "targets": copy.deepcopy(profile["targets"]),
        }
        bundle["species"] = None
        sources = bundle.get("sources")
        known_beings = (
            copy.deepcopy(sources.get("known_beings", []))
            if isinstance(sources, Mapping)
            else []
        )
        bundle["sources"] = {
            "cas_filename": "sources.sqlite3",
            "known_beings": known_beings,
        }
        relationships = bundle.get("relationships")
        known_refs = (
            copy.deepcopy(relationships.get("known_being_refs", []))
            if isinstance(relationships, Mapping)
            else []
        )
        bundle["relationships"] = {
            "known_being_refs": known_refs,
            "store_filename": "relationships.sqlite3",
        }
        EncryptedKeystore.create(
            runtime_root / "custody.json",
            _password_reader(password),
            control_head=successor.state.head,
            secrets=body_secrets,
        )
        EncryptedKeystore.create(
            runtime_root / "transport-custody.json",
            _password_reader(password),
            control_head=successor.state.head,
            secrets=transport_secrets,
        )
        _private_write(runtime_root / "runtime.json", bundle)
        _private_write(
            runtime_root / "client.json",
            {
                "schema": CLIENT_CONFIG_SCHEMA,
                "capability": capabilities["operator"],
                "expected_server": origin,
            },
        )
        _private_write(runtime_root / "client.key", body_secrets[slots["capability"]])
        _private_write(
            host_client / "client.json",
            {
                "schema": CLIENT_CONFIG_SCHEMA,
                "capability": capabilities["status_observer"],
                "expected_server": origin,
            },
        )
        _private_write(
            host_client / "capability.key",
            body_secrets[slots["status_capability"]],
        )
        _private_write(staging / "request.json", request)
        _private_write(staging / "activation.json", verified_activation)
        _private_write(staging / "target-profile.json", profile)
        receipt = {
            "schema": "dm.operator.rebirth-runtime-receipt/v1",
            "request_id": verified_activation["body"]["request_id"],
            "activation_id": verified_activation["activation_id"],
            "being_ref": successor.manifest.being_ref,
            "control_head": successor.state.head,
            "previous_manifest_hash": authority.manifest.digest,
            "successor_manifest_hash": successor.manifest.digest,
            "origin": origin,
            "runtime_schema": bundle["schema"],
            "runtime_sha256": hashlib.sha256(canonical_bytes(bundle)).hexdigest(),
            "peer_profile_sha256": digest(
                "dm.operator.rebirth-peer-profile/v1", profile
            ).hex(),
            "empty_writable_state": True,
        }
        _private_write(staging / "receipt.json", receipt)
        _fsync_directory(runtime_root)
        _fsync_directory(host_client)
        _fsync_directory(staging)
        os.replace(staging, target)
        _fsync_directory(parent)
        staging = None
        return receipt
    finally:
        password[:] = b"\x00" * len(password)
        if staging is not None and staging.exists():
            shutil.rmtree(staging)


def activate_target_runtime(
    output: Path,
    preparation_directory: Path,
    preparation: Any,
    request: Any,
    activation: Any,
    base_bundle: Any,
    password_reader: PasswordReader,
) -> dict[str, Any]:
    """Build one additional-embodiment package under the current root."""

    return _activate_target_runtime(
        output,
        preparation_directory,
        preparation,
        request,
        activation,
        base_bundle,
        password_reader,
        recovery=False,
    )


def activate_recovery_target_runtime(
    output: Path,
    preparation_directory: Path,
    preparation: Any,
    request: Any,
    activation: Any,
    base_bundle: Any,
    password_reader: PasswordReader,
) -> dict[str, Any]:
    """Build a target-only package under a recovery-quorum successor."""

    return _activate_target_runtime(
        output,
        preparation_directory,
        preparation,
        request,
        activation,
        base_bundle,
        password_reader,
        recovery=True,
    )


def restore_recovery_ledger(
    target_runtime_directory: Path,
    snapshot_runtime_directory: Path,
    password_reader: PasswordReader,
    *,
    source_evidence: Mapping[str, Any],
    clock: Callable[[], int] = lambda: time.time_ns() // 1_000_000,
) -> dict[str, Any]:
    """Restore only verified canonical events into a fresh recovered runtime.

    A recovery snapshot also contains obsolete embodiment custody and public
    runtime configuration.  Those bytes must never replace the fresh target.
    This boundary therefore reads the predecessor ledger as an untrusted event
    stream and lets the recovered history authority verify every event before
    insertion.  Derived stores, transport journals and local RPC journals are
    deliberately rebuilt rather than copied.
    """

    target_root = _owner_directory(
        target_runtime_directory, "rebirth_recovery_target_directory_rejected"
    )
    source_root = _owner_directory(
        snapshot_runtime_directory, "rebirth_recovery_snapshot_directory_rejected"
    )
    evidence = _closed(
        source_evidence,
        {"bundle_sha256", "bundle_size", "ledger_sha256", "ledger_size"},
        "rebirth_recovery_source_evidence_rejected",
    )
    source_bundle = _safe_document(
        source_root / "runtime.json", "rebirth_recovery_snapshot_bundle_rejected"
    )
    source_bundle_bytes = canonical_bytes(source_bundle)
    if evidence["bundle_sha256"] != hashlib.sha256(
        source_bundle_bytes
    ).hexdigest() or evidence["bundle_size"] != len(source_bundle_bytes):
        raise RebirthError("rebirth_recovery_source_evidence_mismatch")
    try:
        source_authority = authority_from_runtime_bundle(source_bundle)
        hosted = load_runtime(
            target_root,
            "runtime.json",
            password_reader,
            clock=clock,
        )
        target_authority = hosted.service.ledger.authority
        source_origin = _origin(source_bundle["local_origin"])
        source_authority.validate_origin(source_origin, require_active=True)
    except Exception as exception:
        raise RebirthError(
            "rebirth_recovery_snapshot_authority_rejected"
        ) from exception
    if (
        not isinstance(target_authority, RootHistoryAuthority)
        or source_authority.manifest.digest
        not in target_authority.accepted_manifest_hashes
        or source_authority.manifest.digest == target_authority.manifest.digest
    ):
        raise RebirthError("rebirth_recovery_snapshot_lineage_rejected")

    ledger_name = source_bundle.get("ledger")
    if (
        not isinstance(ledger_name, str)
        or not ledger_name
        or Path(ledger_name).name != ledger_name
    ):
        raise RebirthError("rebirth_recovery_snapshot_ledger_rejected")
    source_ledger_path = source_root / ledger_name
    try:
        info = source_ledger_path.lstat()
    except FileNotFoundError as exception:
        raise RebirthError("rebirth_recovery_snapshot_ledger_rejected") from exception
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise RebirthError("rebirth_recovery_snapshot_ledger_rejected")

    scratch = Path(tempfile.mkdtemp(prefix=".recovery-ledger-", dir=target_root.parent))
    scratch.chmod(0o700)
    try:
        copied_ledger = scratch / "ledger.sqlite"
        shutil.copyfile(source_ledger_path, copied_ledger)
        copied_ledger.chmod(0o600)
        copied_bytes = copied_ledger.read_bytes()
        if evidence["ledger_sha256"] != hashlib.sha256(
            copied_bytes
        ).hexdigest() or evidence["ledger_size"] != len(copied_bytes):
            raise RebirthError("rebirth_recovery_source_evidence_mismatch")
        source_ledger = Ledger(
            copied_ledger,
            authority=source_authority,
            local_origin=source_origin,
        )
        if source_ledger.incomplete_count() != 0:
            raise RebirthError("rebirth_recovery_snapshot_incomplete")
        source_events = source_ledger.events(include_incomplete=False)
        before_events = hosted.service.ledger.events()
        source_by_id = {event["event_id"]: event for event in source_events}
        if len(source_by_id) != len(source_events) or any(
            source_by_id.get(event["event_id"]) != event for event in before_events
        ):
            raise RebirthError("rebirth_recovery_target_not_pristine")
        source_hash = hashlib.sha256(canonical_bytes(source_events)).hexdigest()
        if before_events == source_events:
            inserted_count = 0
        else:
            inserted_count = hosted.service.ledger.ingest(
                source_events,
                source=f"recovery-backup:{source_hash}",
            )["missing"]
        after_events = hosted.service.ledger.events()
    except RebirthError:
        raise
    except Exception as exception:
        raise RebirthError("rebirth_recovery_ledger_restore_rejected") from exception
    finally:
        shutil.rmtree(scratch)
    if after_events != source_events or hosted.service.ledger.incomplete_count() != 0:
        raise RebirthError("rebirth_recovery_ledger_restore_mismatch")
    return {
        "schema": "dm.operator.recovery-ledger-restore-receipt/v1",
        "being_ref": target_authority.manifest.being_ref,
        "predecessor_manifest_hash": source_authority.manifest.digest,
        "successor_manifest_hash": target_authority.manifest.digest,
        "source_origin": source_origin,
        "event_count": len(source_events),
        "event_set_sha256": source_hash,
        "inserted_count": inserted_count,
        "incomplete_count": 0,
        "state": "restored-canonical-ledger",
    }


def create_recovery_custody(
    output: Path,
    previous: RootAuthority,
    custody_path: Path,
    current_password_reader: PasswordReader,
    replacement_password_reader: PasswordReader,
) -> dict[str, Any]:
    """Rotate a recovery quorum into fresh root custody without a body key."""

    try:
        contents = EncryptedKeystore(custody_path).open(
            current_password_reader,
            minimum_counter=1,
            required_control_head=previous.state.head,
        )
    except KeystoreError as exception:
        raise RebirthError("rebirth_recovery_custody_rejected") from exception
    if any(
        not slot.startswith(("root.signing.v1:", "recovery.signing.v1:"))
        for slot in contents.secrets
    ):
        raise RebirthError("rebirth_recovery_custody_rejected")
    _exact_custody_role_seeds(
        contents.secrets,
        prefix="root.signing.v1:",
        policy=previous.state.root_policy,
        code="rebirth_recovery_custody_rejected",
    )
    recovery_seeds = _exact_custody_role_seeds(
        contents.secrets,
        prefix="recovery.signing.v1:",
        policy=previous.state.recovery_policy,
        code="rebirth_recovery_custody_rejected",
    )
    threshold = previous.state.recovery_policy["threshold"]
    if len(recovery_seeds) < threshold:
        raise RebirthError("rebirth_recovery_threshold_shortfall")
    replacement_count = len(previous.state.root_policy["keys"])
    replacement_threshold = previous.state.root_policy["threshold"]
    replacement_roots = [generate_ed25519_seed() for _ in range(replacement_count)]
    revoked = sorted(
        {
            row["embodiment_id"]
            for row in previous.manifest.value["embodiments"]
            if row["status"] == "active"
        }
    )
    recovery_artifact = create_recovery(
        [previous.state],
        recovery_seeds[:threshold],
        replacement_roots,
        replacement_threshold,
        revoke_embodiments=revoked,
    )
    recovered = recovery_request_base(previous, recovery_artifact).state
    target = Path(os.path.abspath(output))
    parent = _owner_directory(target.parent, "rebirth_output_parent_rejected")
    if target.exists() or target.is_symlink():
        raise RebirthError("rebirth_output_exists")
    staging: Path | None = None
    try:
        staging = Path(tempfile.mkdtemp(prefix=f".{target.name}.tmp-", dir=parent))
        staging.chmod(0o700)
        EncryptedKeystore.create(
            staging / "root-custody.json",
            replacement_password_reader,
            control_head=recovered.head,
            secrets={
                **{
                    f"root.signing.v1:{index}": seed
                    for index, seed in enumerate(replacement_roots)
                },
                **{
                    f"recovery.signing.v1:{index}": seed
                    for index, seed in enumerate(recovery_seeds)
                },
            },
        )
        _private_write(staging / "recovery.json", recovery_artifact)
        receipt = {
            "schema": "dm.operator.recovery-custody-receipt/v1",
            "being_ref": previous.state.being_ref,
            "previous_control_head": previous.state.head,
            "recovered_control_head": recovered.head,
            "recovery_artifact_id": recovery_artifact["artifact_id"],
            "recovery_artifact_sha256": hashlib.sha256(
                canonical_bytes(recovery_artifact)
            ).hexdigest(),
            "revoked_embodiment_ids": revoked,
            "replacement_root_key_count": replacement_count,
            "replacement_root_threshold": replacement_threshold,
            "recovery_key_count": len(recovery_seeds),
            "recovery_threshold": threshold,
            "old_root_material_retained": False,
        }
        _private_write(staging / "receipt.json", receipt)
        _fsync_directory(staging)
        os.replace(staging, target)
        _fsync_directory(parent)
        staging = None
        return receipt
    finally:
        if staging is not None and staging.exists():
            shutil.rmtree(staging)


def authorize_recovery_from_root_custody(
    request: Any,
    previous: RootAuthority,
    recovery_artifact: Mapping[str, Any],
    custody_path: Path,
    password_reader: PasswordReader,
    *,
    issued_at_ms: int,
) -> dict[str, Any]:
    """Sign a recovered target request from only the replacement root store."""

    request_base = recovery_request_base(previous, recovery_artifact)
    try:
        contents = EncryptedKeystore(custody_path).open(
            password_reader,
            minimum_counter=1,
            required_control_head=request_base.state.head,
        )
    except KeystoreError as exception:
        raise RebirthError("rebirth_recovered_root_custody_rejected") from exception
    if any(
        not slot.startswith(("root.signing.v1:", "recovery.signing.v1:"))
        for slot in contents.secrets
    ):
        raise RebirthError("rebirth_recovered_root_custody_rejected")
    roots = _exact_custody_role_seeds(
        contents.secrets,
        prefix="root.signing.v1:",
        policy=request_base.state.root_policy,
        code="rebirth_recovered_root_custody_rejected",
    )
    _exact_custody_role_seeds(
        contents.secrets,
        prefix="recovery.signing.v1:",
        policy=request_base.state.recovery_policy,
        code="rebirth_recovered_root_custody_rejected",
    )
    threshold = request_base.state.root_policy["threshold"]
    if len(roots) < threshold:
        raise RebirthError("rebirth_root_threshold_shortfall")
    return authorize_recovery_enrollment_request(
        request,
        previous,
        recovery_artifact,
        replacement_root_seeds=roots[:threshold],
        issued_at_ms=issued_at_ms,
    )


def authorize_from_root_custody(
    request: Any,
    authority: RootAuthority,
    custody_path: Path,
    password_reader: PasswordReader,
    *,
    issued_at_ms: int,
) -> dict[str, Any]:
    """Open only offline root custody and sign one already-public request."""

    try:
        contents = EncryptedKeystore(custody_path).open(
            password_reader,
            minimum_counter=1,
            required_control_head=authority.state.head,
        )
    except KeystoreError as exception:
        raise RebirthError("rebirth_root_custody_rejected") from exception
    seeds = [
        seed
        for slot, seed in sorted(contents.secrets.items())
        if slot.startswith("root.signing.v1:")
    ]
    if len(seeds) != authority.state.root_policy["threshold"]:
        # Root custody may contain more than the threshold, but authorization
        # deliberately selects the first exact threshold in canonical slot order.
        if len(seeds) < authority.state.root_policy["threshold"]:
            raise RebirthError("rebirth_root_threshold_shortfall")
        seeds = seeds[: authority.state.root_policy["threshold"]]
    return authorize_enrollment_request(
        request,
        authority,
        root_seeds=seeds,
        issued_at_ms=issued_at_ms,
    )


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="daimon-rebirth", description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("prepare", help="generate target-owned custody")
    prepare.add_argument("--authority", type=Path, required=True)
    prepare.add_argument("--profile", type=Path, required=True)
    prepare.add_argument("--output", type=Path, required=True)
    prepare.add_argument("--password-fd", type=int, required=True)
    prepare.add_argument("--ttl-seconds", type=int, default=3600)
    authorize = commands.add_parser("authorize", help="offline-root authorization")
    authorize.add_argument("--authority", type=Path, required=True)
    authorize.add_argument("--request", type=Path, required=True)
    authorize.add_argument("--root-custody", type=Path, required=True)
    authorize.add_argument("--root-password-fd", type=int, required=True)
    authorize.add_argument("--output", type=Path, required=True)
    activate = commands.add_parser("activate", help="build a fresh target runtime")
    activate.add_argument("--base-runtime", type=Path, required=True)
    activate.add_argument("--preparation-dir", type=Path, required=True)
    activate.add_argument("--request", type=Path, required=True)
    activate.add_argument("--activation", type=Path, required=True)
    activate.add_argument("--output", type=Path, required=True)
    activate.add_argument("--password-fd", type=int, required=True)
    recover = commands.add_parser(
        "recover", help="rotate a recovery quorum into fresh root custody"
    )
    recover.add_argument("--authority", type=Path, required=True)
    recover.add_argument("--root-custody", type=Path, required=True)
    recover.add_argument("--current-password-fd", type=int, required=True)
    recover.add_argument("--replacement-password-fd", type=int, required=True)
    recover.add_argument("--output", type=Path, required=True)
    prepare_recovery = commands.add_parser(
        "prepare-recovery", help="generate target custody after recovery"
    )
    prepare_recovery.add_argument("--authority", type=Path, required=True)
    prepare_recovery.add_argument("--recovery", type=Path, required=True)
    prepare_recovery.add_argument("--profile", type=Path, required=True)
    prepare_recovery.add_argument("--output", type=Path, required=True)
    prepare_recovery.add_argument("--password-fd", type=int, required=True)
    prepare_recovery.add_argument("--ttl-seconds", type=int, default=3600)
    authorize_recovery = commands.add_parser(
        "authorize-recovery", help="authorize a target with recovered root custody"
    )
    authorize_recovery.add_argument("--authority", type=Path, required=True)
    authorize_recovery.add_argument("--recovery", type=Path, required=True)
    authorize_recovery.add_argument("--request", type=Path, required=True)
    authorize_recovery.add_argument(
        "--recovered-root-custody", type=Path, required=True
    )
    authorize_recovery.add_argument("--root-password-fd", type=int, required=True)
    authorize_recovery.add_argument("--output", type=Path, required=True)
    activate_recovery = commands.add_parser(
        "activate-recovery", help="build a recovered target-only runtime"
    )
    activate_recovery.add_argument("--base-runtime", type=Path, required=True)
    activate_recovery.add_argument("--preparation-dir", type=Path, required=True)
    activate_recovery.add_argument("--request", type=Path, required=True)
    activate_recovery.add_argument("--activation", type=Path, required=True)
    activate_recovery.add_argument("--output", type=Path, required=True)
    activate_recovery.add_argument("--password-fd", type=int, required=True)
    return result


def main(argv: Sequence[str] | None = None) -> int:
    try:
        arguments = parser().parse_args(argv)
        now = time.time_ns() // 1_000_000
        if arguments.command in {"prepare", "prepare-recovery"}:
            authority = authority_from_document(
                _safe_document(arguments.authority, "rebirth_authority_unavailable")
            )
            ttl = arguments.ttl_seconds
            if (
                not isinstance(ttl, int)
                or isinstance(ttl, bool)
                or not 60 <= ttl <= 86_400
            ):
                raise RebirthError("invalid_rebirth_ttl")
            password = _password(arguments.password_fd)
            try:
                profile = _safe_document(
                    arguments.profile, "rebirth_target_profile_unavailable"
                )
                receipt = (
                    create_recovery_target_preparation(
                        arguments.output,
                        authority,
                        _safe_document(
                            arguments.recovery,
                            "rebirth_recovery_artifact_unavailable",
                        ),
                        profile,
                        _password_reader(password),
                        created_at_ms=now,
                        expires_at_ms=now + ttl * 1000,
                    )
                    if arguments.command == "prepare-recovery"
                    else create_target_preparation(
                        arguments.output,
                        authority,
                        profile,
                        _password_reader(password),
                        created_at_ms=now,
                        expires_at_ms=now + ttl * 1000,
                    )
                )
            finally:
                password[:] = b"\x00" * len(password)
        elif arguments.command in {"authorize", "authorize-recovery"}:
            authority = authority_from_document(
                _safe_document(arguments.authority, "rebirth_authority_unavailable")
            )
            password = _password(arguments.root_password_fd)
            try:
                request = _safe_document(
                    arguments.request, "rebirth_request_unavailable"
                )
                receipt = (
                    authorize_recovery_from_root_custody(
                        request,
                        authority,
                        _safe_document(
                            arguments.recovery,
                            "rebirth_recovery_artifact_unavailable",
                        ),
                        arguments.recovered_root_custody,
                        _password_reader(password),
                        issued_at_ms=now,
                    )
                    if arguments.command == "authorize-recovery"
                    else authorize_from_root_custody(
                        request,
                        authority,
                        arguments.root_custody,
                        _password_reader(password),
                        issued_at_ms=now,
                    )
                )
                output = Path(os.path.abspath(arguments.output))
                _owner_directory(output.parent, "rebirth_output_parent_rejected")
                if output.exists() or output.is_symlink():
                    raise RebirthError("rebirth_output_exists")
                _private_write(output, receipt)
                _fsync_directory(output.parent)
            finally:
                password[:] = b"\x00" * len(password)
        elif arguments.command == "recover":
            authority = authority_from_document(
                _safe_document(arguments.authority, "rebirth_authority_unavailable")
            )
            current_password = _password(arguments.current_password_fd)
            replacement_password = _password(arguments.replacement_password_fd)
            try:
                receipt = create_recovery_custody(
                    arguments.output,
                    authority,
                    arguments.root_custody,
                    _password_reader(current_password),
                    _password_reader(replacement_password),
                )
            finally:
                current_password[:] = b"\x00" * len(current_password)
                replacement_password[:] = b"\x00" * len(replacement_password)
        else:
            password = _password(arguments.password_fd)
            try:
                preparation_directory = _owner_directory(
                    arguments.preparation_dir,
                    "rebirth_preparation_directory_rejected",
                )
                values = (
                    arguments.output,
                    preparation_directory,
                    _safe_document(
                        preparation_directory / "preparation.json",
                        "rebirth_preparation_unavailable",
                    ),
                    _safe_document(arguments.request, "rebirth_request_unavailable"),
                    _safe_document(
                        arguments.activation, "rebirth_activation_unavailable"
                    ),
                    _safe_document(
                        arguments.base_runtime, "rebirth_runtime_unavailable"
                    ),
                    _password_reader(password),
                )
                receipt = (
                    activate_recovery_target_runtime(*values)
                    if arguments.command == "activate-recovery"
                    else activate_target_runtime(*values)
                )
            finally:
                password[:] = b"\x00" * len(password)
        sys.stdout.buffer.write(canonical_bytes(receipt) + b"\n")
        return 0
    except RebirthError as exception:
        print(str(exception), file=sys.stderr)
        return 2
    except (OSError, TypeError, ValueError):
        print("rebirth_failed", file=sys.stderr)
        return 1


__all__ = [
    "ACTIVATION_SCHEMA",
    "AUTHORITY_SCHEMA",
    "PREPARATION_SCHEMA",
    "RECOVERY_ACTIVATION_SCHEMA",
    "REQUEST_SCHEMA",
    "TARGET_PROFILE_SCHEMA",
    "RebirthError",
    "RecoveryRequestBase",
    "activate_recovery_target_runtime",
    "activate_target_runtime",
    "apply_activation_to_runtime_bundle",
    "apply_recovery_activation_to_runtime_bundle",
    "authority_from_document",
    "authority_from_runtime_bundle",
    "authorize_enrollment_request",
    "authorize_from_root_custody",
    "authorize_recovery_enrollment_request",
    "authorize_recovery_from_root_custody",
    "create_enrollment_request",
    "create_recovery_custody",
    "create_recovery_target_preparation",
    "create_target_preparation",
    "main",
    "parser",
    "recovery_request_base",
    "restore_recovery_ledger",
    "validate_activation",
    "validate_enrollment_request",
    "validate_recovery_activation",
]


if __name__ == "__main__":
    raise SystemExit(main())
