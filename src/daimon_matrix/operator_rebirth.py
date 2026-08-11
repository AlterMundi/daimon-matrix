"""Two-party ceremony for adding a self-custodied embodiment to one being.

The target creates a request and proves possession of fresh body keys.  The
offline root holder countersigns only public material and an exact manifest
successor.  No function in this module requires root seeds and embodiment
private keys in the same process.
"""

from __future__ import annotations

import argparse
import copy
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
from collections.abc import Mapping, Sequence
from contextlib import suppress
from pathlib import Path
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
    ControlChain,
    ControlState,
    create_embodiment_credential,
    create_incarnation_authorization,
    ed25519_public,
    generate_ed25519_seed,
    generate_x25519_private,
    key_descriptor,
    key_id,
    signing_descriptor,
    verify_embodiment_credential,
    verify_incarnation_authorization,
    x25519_public,
)
from .keystore import EncryptedKeystore, KeystoreError, PasswordReader
from .local_api import create_capability
from .peer_transport import PeerTransportError, http_peer_round_trip
from .service import SERVICE_METHODS
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


def _target_profile(value: Any, base: RootAuthority) -> dict[str, Any]:
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
    if not isinstance(targets, list) or not 1 <= len(targets) <= 255:
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
    expected = {
        str(row["embodiment_id"])
        for row in base.manifest.value["embodiments"]
        if row["status"] == "active"
    }
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
    authority: RootAuthority,
    profile: Any,
    password_reader: PasswordReader,
    *,
    created_at_ms: int,
    expires_at_ms: int,
) -> dict[str, Any]:
    """Generate target-only encrypted custody and one public request atomically."""

    target_profile = _target_profile(profile, authority)
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
    return result


def main(argv: Sequence[str] | None = None) -> int:
    try:
        arguments = parser().parse_args(argv)
        authority = authority_from_document(
            _safe_document(arguments.authority, "rebirth_authority_unavailable")
        )
        now = time.time_ns() // 1_000_000
        if arguments.command == "prepare":
            ttl = arguments.ttl_seconds
            if (
                not isinstance(ttl, int)
                or isinstance(ttl, bool)
                or not 60 <= ttl <= 86_400
            ):
                raise RebirthError("invalid_rebirth_ttl")
            password = _password(arguments.password_fd)
            try:
                receipt = create_target_preparation(
                    arguments.output,
                    authority,
                    _safe_document(
                        arguments.profile, "rebirth_target_profile_unavailable"
                    ),
                    _password_reader(password),
                    created_at_ms=now,
                    expires_at_ms=now + ttl * 1000,
                )
            finally:
                password[:] = b"\x00" * len(password)
        else:
            password = _password(arguments.root_password_fd)
            try:
                receipt = authorize_from_root_custody(
                    _safe_document(arguments.request, "rebirth_request_unavailable"),
                    authority,
                    arguments.root_custody,
                    _password_reader(password),
                    issued_at_ms=now,
                )
                output = Path(os.path.abspath(arguments.output))
                _owner_directory(output.parent, "rebirth_output_parent_rejected")
                if output.exists() or output.is_symlink():
                    raise RebirthError("rebirth_output_exists")
                _private_write(output, receipt)
                _fsync_directory(output.parent)
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
    "REQUEST_SCHEMA",
    "TARGET_PROFILE_SCHEMA",
    "RebirthError",
    "apply_activation_to_runtime_bundle",
    "authority_from_document",
    "authorize_enrollment_request",
    "authorize_from_root_custody",
    "create_enrollment_request",
    "create_target_preparation",
    "main",
    "parser",
    "validate_activation",
    "validate_enrollment_request",
]


if __name__ == "__main__":
    raise SystemExit(main())
