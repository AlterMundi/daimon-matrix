"""Signed, append-only root-manifest succession for incarnation restart.

An epoch successor is signed by the affected embodiment key already delegated
by a root credential.  Its structural validator permits only the exact next
incarnation of that embodiment; every other manifest row remains byte-equal.
Historical events continue to select the exact authority named by their
``manifest_hash``.
"""

from __future__ import annotations

import copy
import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .canonical import b64url, canonical_bytes, unb64url
from .identity import (
    ControlState,
    VerificationError,
    ed25519_public,
    key_id,
    verify_embodiment_credential,
    verify_incarnation_authorization,
    verify_recovery,
)
from .weave import BeingManifest, RootAuthority, WeaveProtocolError

AUTHORITY_EPOCH_SCHEMA: Final = "dm.we.authority-epoch/v1"
AUTHORITY_EPOCH_DOMAIN: Final = b"daimon/weave-authority-epoch/v1\x00"
EMBODIMENT_ENROLLMENT_SCHEMA: Final = "dm.we.embodiment-enrollment/v1"
EMBODIMENT_ENROLLMENT_DOMAIN: Final = b"daimon/weave-embodiment-enrollment/v1\x00"
RECOVERY_REBIRTH_SCHEMA: Final = "dm.we.recovery-rebirth/v1"
RECOVERY_REBIRTH_DOMAIN: Final = b"daimon/weave-recovery-rebirth/v1\x00"


class AuthorityEpochError(WeaveProtocolError):
    """A manifest epoch chain is not an exact authorized successor."""


def _core(
    previous: BeingManifest,
    successor: BeingManifest,
    *,
    embodiment_id: str,
    previous_incarnation_id: str,
    successor_authorization: Mapping[str, Any],
    issued_at_ms: int,
) -> dict[str, Any]:
    body = successor_authorization.get("body")
    if not isinstance(body, Mapping):
        raise AuthorityEpochError("invalid_authority_epoch_authorization")
    return {
        "schema": AUTHORITY_EPOCH_SCHEMA,
        "being_ref": previous.being_ref,
        "previous_manifest_hash": previous.digest,
        "previous_revision": previous.value["revision"],
        "successor_manifest_hash": successor.digest,
        "successor_revision": successor.value["revision"],
        "embodiment_id": embodiment_id,
        "previous_incarnation_id": previous_incarnation_id,
        "successor_incarnation_id": body.get("incarnation_id"),
        "successor_incarnation_authorization_id": successor_authorization.get(
            "artifact_id"
        ),
        "issued_at_ms": issued_at_ms,
    }


def create_authority_epoch(
    previous: BeingManifest,
    successor: BeingManifest,
    *,
    embodiment_id: str,
    previous_incarnation_id: str,
    successor_authorization: Mapping[str, Any],
    signing_seed: bytes,
    issued_at_ms: int,
) -> dict[str, Any]:
    """Sign the exact manifest transition with the delegated embodiment key."""

    core = _core(
        previous,
        successor,
        embodiment_id=embodiment_id,
        previous_incarnation_id=previous_incarnation_id,
        successor_authorization=successor_authorization,
        issued_at_ms=issued_at_ms,
    )
    content_hash = hashlib.sha256(
        AUTHORITY_EPOCH_DOMAIN + canonical_bytes(core)
    ).hexdigest()
    private = Ed25519PrivateKey.from_private_bytes(signing_seed)
    public = private.public_key().public_bytes_raw()
    return {
        **core,
        "content_hash": content_hash,
        "signature": {
            "alg": "Ed25519",
            "kid": key_id("Ed25519", public),
            "value": b64url(
                private.sign(AUTHORITY_EPOCH_DOMAIN + bytes.fromhex(content_hash))
            ),
        },
    }


def _verify_structure(
    previous: RootAuthority,
    successor: RootAuthority,
    value: Mapping[str, Any],
) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    fields = {
        "schema",
        "being_ref",
        "previous_manifest_hash",
        "previous_revision",
        "successor_manifest_hash",
        "successor_revision",
        "embodiment_id",
        "previous_incarnation_id",
        "successor_incarnation_id",
        "successor_incarnation_authorization_id",
        "issued_at_ms",
        "content_hash",
        "signature",
    }
    if set(value) != fields or value.get("schema") != AUTHORITY_EPOCH_SCHEMA:
        raise AuthorityEpochError("invalid_authority_epoch")
    previous_manifest = previous.manifest
    successor_manifest = successor.manifest
    if (
        value.get("being_ref") != previous_manifest.being_ref
        or successor_manifest.being_ref != previous_manifest.being_ref
        or value.get("previous_manifest_hash") != previous_manifest.digest
        or value.get("successor_manifest_hash") != successor_manifest.digest
        or value.get("previous_revision") != previous_manifest.value["revision"]
        or value.get("successor_revision") != successor_manifest.value["revision"]
        or successor_manifest.value["revision"]
        != previous_manifest.value["revision"] + 1
        or successor_manifest.value["control_head"]
        != previous_manifest.value["control_head"]
        or successor_manifest.value["history_binding_id"]
        != previous_manifest.value["history_binding_id"]
        or successor.state.head != previous.state.head
    ):
        raise AuthorityEpochError("authority_epoch_lineage_mismatch")
    embodiment_id = value.get("embodiment_id")
    previous_incarnation_id = value.get("previous_incarnation_id")
    successor_incarnation_id = value.get("successor_incarnation_id")
    authorization_id = value.get("successor_incarnation_authorization_id")
    if (
        not isinstance(embodiment_id, str)
        or not isinstance(previous_incarnation_id, str)
        or not isinstance(successor_incarnation_id, str)
        or not isinstance(authorization_id, str)
    ):
        raise AuthorityEpochError("authority_epoch_member_mismatch")
    try:
        old_row = previous_manifest.member(embodiment_id, previous_incarnation_id)
        new_row = successor_manifest.member(embodiment_id, successor_incarnation_id)
    except (KeyError, TypeError, WeaveProtocolError) as exception:
        raise AuthorityEpochError("authority_epoch_member_mismatch") from exception
    authorization = successor.incarnations.get(authorization_id)
    old_authorization = previous.incarnations.get(
        old_row["incarnation_authorization_id"]
    )
    credential = successor.credentials.get(new_row["embodiment_credential_id"])
    if not isinstance(authorization, Mapping):
        raise AuthorityEpochError("authority_epoch_authorization_missing")
    if not isinstance(old_authorization, Mapping):
        raise AuthorityEpochError("authority_epoch_authorization_missing")
    if not isinstance(credential, Mapping):
        raise AuthorityEpochError("authority_epoch_authorization_missing")
    if (
        old_row["status"] != "active"
        or new_row["status"] != "active"
        or new_row["body_ref"] != old_row["body_ref"]
        or new_row["embodiment_credential_id"] != old_row["embodiment_credential_id"]
        or new_row["incarnation_authorization_id"] != authorization["artifact_id"]
    ):
        raise AuthorityEpochError("authority_epoch_member_mismatch")
    expected_rows = copy.deepcopy(previous_manifest.value["embodiments"])
    expected_old = next(
        row
        for row in expected_rows
        if row["embodiment_id"] == embodiment_id
        and row["incarnation_id"] == previous_incarnation_id
    )
    expected_old["status"] = "retired"
    expected_rows.append(copy.deepcopy(new_row))
    expected_rows.sort(key=lambda row: (row["embodiment_id"], row["incarnation_id"]))
    if successor_manifest.value["embodiments"] != expected_rows:
        raise AuthorityEpochError("authority_epoch_manifest_change_forbidden")
    active_ids = [
        row["embodiment_id"]
        for row in successor_manifest.value["embodiments"]
        if row["status"] == "active"
    ]
    if len(active_ids) != len(set(active_ids)):
        raise AuthorityEpochError("ambiguous_active_incarnation")
    issued_at_ms = value.get("issued_at_ms")
    if (
        not isinstance(issued_at_ms, int)
        or isinstance(issued_at_ms, bool)
        or issued_at_ms < 0
    ):
        raise AuthorityEpochError("invalid_authority_epoch_time")
    try:
        credential_body = verify_embodiment_credential(
            credential, successor.state, at_ms=issued_at_ms
        )
        old_body = verify_incarnation_authorization(
            old_authorization,
            credential,
            previous.state,
            at_ms=issued_at_ms,
        )
        new_body = verify_incarnation_authorization(
            authorization,
            credential,
            successor.state,
            at_ms=issued_at_ms,
        )
    except VerificationError as exception:
        raise AuthorityEpochError(
            "authority_epoch_authorization_invalid"
        ) from exception
    if (
        credential_body["embodiment_id"] != embodiment_id
        or new_body["incarnation_id"] != successor_incarnation_id
        or new_body["incarnation_sequence"] != old_body["incarnation_sequence"] + 1
        or new_body["started_at_ms"] <= old_body["started_at_ms"]
        or issued_at_ms < new_body["started_at_ms"]
    ):
        raise AuthorityEpochError("authority_epoch_sequence_invalid")
    return credential_body, authorization


def verify_authority_epoch(
    value: Mapping[str, Any],
    previous: RootAuthority,
    successor: RootAuthority,
) -> dict[str, Any]:
    """Verify signature, exact lineage, and the only allowed manifest delta."""

    credential_body, _authorization = _verify_structure(previous, successor, value)
    core = {
        key: copy.deepcopy(item)
        for key, item in value.items()
        if key not in {"content_hash", "signature"}
    }
    expected_hash = hashlib.sha256(
        AUTHORITY_EPOCH_DOMAIN + canonical_bytes(core)
    ).hexdigest()
    if value.get("content_hash") != expected_hash:
        raise AuthorityEpochError("authority_epoch_hash_mismatch")
    signature = value.get("signature")
    signing = credential_body["signing_key"]
    if (
        not isinstance(signature, Mapping)
        or set(signature) != {"alg", "kid", "value"}
        or signature.get("alg") != "Ed25519"
        or signature.get("kid") != signing["key_id"]
    ):
        raise AuthorityEpochError("authority_epoch_signature_invalid")
    try:
        Ed25519PublicKey.from_public_bytes(
            unb64url(signing["public"], length=32)
        ).verify(
            unb64url(signature["value"], length=64),
            AUTHORITY_EPOCH_DOMAIN + bytes.fromhex(expected_hash),
        )
    except (InvalidSignature, TypeError, ValueError) as exception:
        raise AuthorityEpochError("authority_epoch_signature_invalid") from exception
    return copy.deepcopy(dict(value))


def _enrollment_core(
    previous: BeingManifest,
    successor: BeingManifest,
    *,
    request_id: str,
    body_ref: str,
    embodiment_id: str,
    incarnation_id: str,
    embodiment_credential_id: str,
    incarnation_authorization_id: str,
    principal_id: str,
    issued_at_ms: int,
) -> dict[str, Any]:
    return {
        "schema": EMBODIMENT_ENROLLMENT_SCHEMA,
        "being_ref": previous.being_ref,
        "previous_manifest_hash": previous.digest,
        "previous_revision": previous.value["revision"],
        "successor_manifest_hash": successor.digest,
        "successor_revision": successor.value["revision"],
        "request_id": request_id,
        "body_ref": body_ref,
        "embodiment_id": embodiment_id,
        "incarnation_id": incarnation_id,
        "embodiment_credential_id": embodiment_credential_id,
        "incarnation_authorization_id": incarnation_authorization_id,
        "principal_id": principal_id,
        "issued_at_ms": issued_at_ms,
    }


def create_embodiment_enrollment(
    previous: BeingManifest,
    successor: BeingManifest,
    *,
    request_id: str,
    body_ref: str,
    embodiment_id: str,
    incarnation_id: str,
    embodiment_credential_id: str,
    incarnation_authorization_id: str,
    principal_id: str,
    root_seeds: Sequence[bytes],
    issued_at_ms: int,
) -> dict[str, Any]:
    """Root-sign one exact additional-embodiment manifest successor."""

    core = _enrollment_core(
        previous,
        successor,
        request_id=request_id,
        body_ref=body_ref,
        embodiment_id=embodiment_id,
        incarnation_id=incarnation_id,
        embodiment_credential_id=embodiment_credential_id,
        incarnation_authorization_id=incarnation_authorization_id,
        principal_id=principal_id,
        issued_at_ms=issued_at_ms,
    )
    content_hash = hashlib.sha256(
        EMBODIMENT_ENROLLMENT_DOMAIN + canonical_bytes(core)
    ).hexdigest()
    signatures = []
    for seed in root_seeds:
        public = ed25519_public(seed)
        signatures.append(
            {
                "alg": "Ed25519",
                "kid": key_id("Ed25519", public),
                "value": b64url(
                    Ed25519PrivateKey.from_private_bytes(seed).sign(
                        EMBODIMENT_ENROLLMENT_DOMAIN + bytes.fromhex(content_hash)
                    )
                ),
            }
        )
    signatures.sort(key=lambda row: row["kid"])
    return {**core, "content_hash": content_hash, "signatures": signatures}


def _root_public_keys(state: ControlState) -> tuple[dict[str, bytes], int]:
    policy = state.root_policy
    keys = policy.get("keys")
    threshold = policy.get("threshold")
    if (
        not isinstance(keys, list)
        or not isinstance(threshold, int)
        or isinstance(threshold, bool)
        or not 1 <= threshold <= len(keys)
    ):
        raise AuthorityEpochError("embodiment_enrollment_root_policy_invalid")
    result: dict[str, bytes] = {}
    for descriptor in keys:
        if (
            not isinstance(descriptor, Mapping)
            or set(descriptor) != {"algorithm", "key_id", "public"}
            or descriptor.get("algorithm") != "Ed25519"
        ):
            raise AuthorityEpochError("embodiment_enrollment_root_policy_invalid")
        try:
            public = unb64url(str(descriptor["public"]), length=32)
        except (TypeError, ValueError) as exception:
            raise AuthorityEpochError(
                "embodiment_enrollment_root_policy_invalid"
            ) from exception
        kid = descriptor.get("key_id")
        if (
            not isinstance(kid, str)
            or kid != key_id("Ed25519", public)
            or kid in result
        ):
            raise AuthorityEpochError("embodiment_enrollment_root_policy_invalid")
        result[kid] = public
    return result, threshold


def verify_embodiment_enrollment(
    value: Mapping[str, Any],
    previous: RootAuthority,
    successor: RootAuthority,
) -> dict[str, Any]:
    """Verify one root-approved new body without accepting unrelated deltas."""

    fields = {
        "schema",
        "being_ref",
        "previous_manifest_hash",
        "previous_revision",
        "successor_manifest_hash",
        "successor_revision",
        "request_id",
        "body_ref",
        "embodiment_id",
        "incarnation_id",
        "embodiment_credential_id",
        "incarnation_authorization_id",
        "principal_id",
        "issued_at_ms",
        "content_hash",
        "signatures",
    }
    if set(value) != fields or value.get("schema") != EMBODIMENT_ENROLLMENT_SCHEMA:
        raise AuthorityEpochError("invalid_embodiment_enrollment")
    previous_manifest = previous.manifest
    successor_manifest = successor.manifest
    if (
        value.get("being_ref") != previous_manifest.being_ref
        or successor_manifest.being_ref != previous_manifest.being_ref
        or value.get("previous_manifest_hash") != previous_manifest.digest
        or value.get("successor_manifest_hash") != successor_manifest.digest
        or value.get("previous_revision") != previous_manifest.value["revision"]
        or value.get("successor_revision") != successor_manifest.value["revision"]
        or successor_manifest.value["revision"]
        != previous_manifest.value["revision"] + 1
        or successor_manifest.value["control_head"]
        != previous_manifest.value["control_head"]
        or successor_manifest.value["history_binding_id"]
        != previous_manifest.value["history_binding_id"]
        or successor.state.head != previous.state.head
    ):
        raise AuthorityEpochError("embodiment_enrollment_lineage_mismatch")
    embodiment_id = value.get("embodiment_id")
    incarnation_id = value.get("incarnation_id")
    credential_id = value.get("embodiment_credential_id")
    authorization_id = value.get("incarnation_authorization_id")
    request_id = value.get("request_id")
    body_ref = value.get("body_ref")
    principal_id = value.get("principal_id")
    if not all(
        isinstance(item, str) and item
        for item in (
            request_id,
            body_ref,
            embodiment_id,
            incarnation_id,
            credential_id,
            authorization_id,
            principal_id,
        )
    ):
        raise AuthorityEpochError("embodiment_enrollment_member_mismatch")
    assert isinstance(embodiment_id, str)
    assert isinstance(incarnation_id, str)
    assert isinstance(credential_id, str)
    assert isinstance(authorization_id, str)
    assert isinstance(body_ref, str)
    assert isinstance(principal_id, str)
    if any(
        row["embodiment_id"] == embodiment_id
        for row in previous_manifest.value["embodiments"]
    ):
        raise AuthorityEpochError("embodiment_enrollment_reuses_identity")
    try:
        new_row = successor_manifest.member(embodiment_id, incarnation_id)
    except (KeyError, TypeError, WeaveProtocolError) as exception:
        raise AuthorityEpochError(
            "embodiment_enrollment_member_mismatch"
        ) from exception
    expected_rows = copy.deepcopy(previous_manifest.value["embodiments"])
    expected_rows.append(copy.deepcopy(new_row))
    expected_rows.sort(key=lambda row: (row["embodiment_id"], row["incarnation_id"]))
    if (
        successor_manifest.value["embodiments"] != expected_rows
        or new_row["status"] != "active"
        or new_row["body_ref"] != body_ref
        or new_row["embodiment_credential_id"] != credential_id
        or new_row["incarnation_authorization_id"] != authorization_id
    ):
        raise AuthorityEpochError("embodiment_enrollment_manifest_change_forbidden")
    active_ids = [
        row["embodiment_id"]
        for row in successor_manifest.value["embodiments"]
        if row["status"] == "active"
    ]
    if len(active_ids) != len(set(active_ids)):
        raise AuthorityEpochError("ambiguous_active_incarnation")
    credential = successor.credentials.get(credential_id)
    authorization = successor.incarnations.get(authorization_id)
    issued_at_ms = value.get("issued_at_ms")
    if (
        not isinstance(credential, Mapping)
        or not isinstance(authorization, Mapping)
        or not isinstance(issued_at_ms, int)
        or isinstance(issued_at_ms, bool)
        or issued_at_ms < 0
    ):
        raise AuthorityEpochError("embodiment_enrollment_authorization_missing")
    try:
        credential_body = verify_embodiment_credential(
            credential, successor.state, at_ms=issued_at_ms
        )
        incarnation_body = verify_incarnation_authorization(
            authorization,
            credential,
            successor.state,
            at_ms=issued_at_ms,
        )
    except VerificationError as exception:
        raise AuthorityEpochError(
            "embodiment_enrollment_authorization_invalid"
        ) from exception
    transport_principals = credential_body["transport_principals"]
    matching_principals = [
        row
        for row in transport_principals
        if row["scheme"] == "dm-peer-v1" and row["principal_id"] == principal_id
    ]
    if (
        credential_body["embodiment_id"] != embodiment_id
        or credential_body["body_ref"] != body_ref
        or incarnation_body["incarnation_id"] != incarnation_id
        or incarnation_body["incarnation_sequence"] != 0
        or incarnation_body["started_at_ms"] > issued_at_ms
        or "dm.we" not in credential_body["purposes"]
        or len(matching_principals) != 1
    ):
        raise AuthorityEpochError("embodiment_enrollment_authorization_invalid")
    core = {
        key: copy.deepcopy(item)
        for key, item in value.items()
        if key not in {"content_hash", "signatures"}
    }
    expected_hash = hashlib.sha256(
        EMBODIMENT_ENROLLMENT_DOMAIN + canonical_bytes(core)
    ).hexdigest()
    if value.get("content_hash") != expected_hash:
        raise AuthorityEpochError("embodiment_enrollment_hash_mismatch")
    signatures = value.get("signatures")
    if not isinstance(signatures, list) or not signatures:
        raise AuthorityEpochError("embodiment_enrollment_signature_invalid")
    public_keys, threshold = _root_public_keys(previous.state)
    valid: set[str] = set()
    normalized: list[Mapping[str, Any]] = []
    for signature in signatures:
        if (
            not isinstance(signature, Mapping)
            or set(signature) != {"alg", "kid", "value"}
            or signature.get("alg") != "Ed25519"
            or not isinstance(signature.get("kid"), str)
            or signature["kid"] in valid
            or signature["kid"] not in public_keys
        ):
            raise AuthorityEpochError("embodiment_enrollment_signature_invalid")
        try:
            Ed25519PublicKey.from_public_bytes(public_keys[signature["kid"]]).verify(
                unb64url(str(signature["value"]), length=64),
                EMBODIMENT_ENROLLMENT_DOMAIN + bytes.fromhex(expected_hash),
            )
        except (InvalidSignature, TypeError, ValueError) as exception:
            raise AuthorityEpochError(
                "embodiment_enrollment_signature_invalid"
            ) from exception
        valid.add(signature["kid"])
        normalized.append(signature)
    if len(valid) < threshold or list(signatures) != sorted(
        normalized, key=lambda row: str(row["kid"])
    ):
        raise AuthorityEpochError("embodiment_enrollment_signature_invalid")
    return copy.deepcopy(dict(value))


def _recovery_rebirth_core(
    previous: BeingManifest,
    successor: BeingManifest,
    *,
    recovery_artifact: Mapping[str, Any],
    body_ref: str,
    embodiment_id: str,
    incarnation_id: str,
    embodiment_credential_id: str,
    incarnation_authorization_id: str,
    principal_id: str,
    issued_at_ms: int,
) -> dict[str, Any]:
    recovery_body = recovery_artifact.get("body")
    if not isinstance(recovery_body, Mapping):
        raise AuthorityEpochError("recovery_rebirth_artifact_invalid")
    return {
        "schema": RECOVERY_REBIRTH_SCHEMA,
        "being_ref": previous.being_ref,
        "previous_control_head": previous.value["control_head"],
        "previous_manifest_hash": previous.digest,
        "previous_revision": previous.value["revision"],
        "successor_control_head": successor.value["control_head"],
        "successor_manifest_hash": successor.digest,
        "successor_revision": successor.value["revision"],
        "recovery_artifact": copy.deepcopy(dict(recovery_artifact)),
        "recovery_artifact_id": recovery_artifact.get("artifact_id"),
        "revoked_embodiment_ids": copy.deepcopy(
            recovery_body.get("revoked_embodiments")
        ),
        "body_ref": body_ref,
        "embodiment_id": embodiment_id,
        "incarnation_id": incarnation_id,
        "embodiment_credential_id": embodiment_credential_id,
        "incarnation_authorization_id": incarnation_authorization_id,
        "principal_id": principal_id,
        "issued_at_ms": issued_at_ms,
    }


def create_recovery_rebirth(
    previous: BeingManifest,
    successor: BeingManifest,
    *,
    recovery_artifact: Mapping[str, Any],
    body_ref: str,
    embodiment_id: str,
    incarnation_id: str,
    embodiment_credential_id: str,
    incarnation_authorization_id: str,
    principal_id: str,
    root_seeds: Sequence[bytes],
    issued_at_ms: int,
) -> dict[str, Any]:
    """Bind one recovery control transition directly to its fresh body.

    Recovery deliberately has no operational intermediate authority.  Every
    previously active embodiment is revoked by the recovery artifact and the
    first post-recovery manifest contains only the separately keyed target.
    """

    core = _recovery_rebirth_core(
        previous,
        successor,
        recovery_artifact=recovery_artifact,
        body_ref=body_ref,
        embodiment_id=embodiment_id,
        incarnation_id=incarnation_id,
        embodiment_credential_id=embodiment_credential_id,
        incarnation_authorization_id=incarnation_authorization_id,
        principal_id=principal_id,
        issued_at_ms=issued_at_ms,
    )
    content_hash = hashlib.sha256(
        RECOVERY_REBIRTH_DOMAIN + canonical_bytes(core)
    ).hexdigest()
    signatures = []
    for seed in root_seeds:
        public = ed25519_public(seed)
        signatures.append(
            {
                "alg": "Ed25519",
                "kid": key_id("Ed25519", public),
                "value": b64url(
                    Ed25519PrivateKey.from_private_bytes(seed).sign(
                        RECOVERY_REBIRTH_DOMAIN + bytes.fromhex(content_hash)
                    )
                ),
            }
        )
    signatures.sort(key=lambda row: row["kid"])
    return {**core, "content_hash": content_hash, "signatures": signatures}


def verify_recovery_rebirth(
    value: Mapping[str, Any],
    previous: RootAuthority,
    successor: RootAuthority,
    recovery_artifact: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Verify a recovery quorum's exact old-authority to fresh-body bridge."""

    fields = {
        "schema",
        "being_ref",
        "previous_control_head",
        "previous_manifest_hash",
        "previous_revision",
        "successor_control_head",
        "successor_manifest_hash",
        "successor_revision",
        "recovery_artifact",
        "recovery_artifact_id",
        "revoked_embodiment_ids",
        "body_ref",
        "embodiment_id",
        "incarnation_id",
        "embodiment_credential_id",
        "incarnation_authorization_id",
        "principal_id",
        "issued_at_ms",
        "content_hash",
        "signatures",
    }
    if set(value) != fields or value.get("schema") != RECOVERY_REBIRTH_SCHEMA:
        raise AuthorityEpochError("invalid_recovery_rebirth")
    embedded = value.get("recovery_artifact")
    if not isinstance(embedded, Mapping):
        raise AuthorityEpochError("recovery_rebirth_artifact_invalid")
    if recovery_artifact is not None and dict(embedded) != dict(recovery_artifact):
        raise AuthorityEpochError("recovery_rebirth_artifact_invalid")
    recovery_artifact = embedded
    try:
        recovered_state = verify_recovery(recovery_artifact, [previous.state])
    except VerificationError as exception:
        raise AuthorityEpochError("recovery_rebirth_artifact_invalid") from exception
    previous_manifest = previous.manifest
    successor_manifest = successor.manifest
    previous_root_ids = {row["key_id"] for row in previous.state.root_policy["keys"]}
    recovered_root_ids = {row["key_id"] for row in recovered_state.root_policy["keys"]}
    active_predecessors = sorted(
        {
            row["embodiment_id"]
            for row in previous_manifest.value["embodiments"]
            if row["status"] == "active"
        }
    )
    predecessor_ids = {
        row["embodiment_id"] for row in previous_manifest.value["embodiments"]
    }
    if (
        successor.state != recovered_state
        or value.get("being_ref") != previous_manifest.being_ref
        or successor_manifest.being_ref != previous_manifest.being_ref
        or value.get("previous_control_head") != previous.state.head
        or value.get("previous_manifest_hash") != previous_manifest.digest
        or value.get("previous_revision") != previous_manifest.value["revision"]
        or value.get("successor_control_head") != recovered_state.head
        or value.get("successor_manifest_hash") != successor_manifest.digest
        or value.get("successor_revision") != successor_manifest.value["revision"]
        or successor_manifest.value["revision"]
        != previous_manifest.value["revision"] + 1
        or successor_manifest.value["control_head"] != recovered_state.head
        or successor_manifest.value["history_binding_id"]
        != previous_manifest.value["history_binding_id"]
        or value.get("recovery_artifact_id") != recovery_artifact.get("artifact_id")
        or value.get("revoked_embodiment_ids") != active_predecessors
        or recovery_artifact.get("body", {}).get("revoked_embodiments")
        != active_predecessors
        or previous_root_ids & recovered_root_ids
    ):
        raise AuthorityEpochError("recovery_rebirth_lineage_mismatch")
    issued_at_ms = value.get("issued_at_ms")
    identifiers = (
        value.get("body_ref"),
        value.get("embodiment_id"),
        value.get("incarnation_id"),
        value.get("embodiment_credential_id"),
        value.get("incarnation_authorization_id"),
        value.get("principal_id"),
    )
    if (
        not isinstance(issued_at_ms, int)
        or isinstance(issued_at_ms, bool)
        or issued_at_ms < 0
        or not all(isinstance(item, str) and item for item in identifiers)
    ):
        raise AuthorityEpochError("recovery_rebirth_member_mismatch")
    rows = successor_manifest.value["embodiments"]
    if len(rows) != 1:
        raise AuthorityEpochError("recovery_rebirth_manifest_change_forbidden")
    row = rows[0]
    expected_row = {
        "body_ref": value["body_ref"],
        "embodiment_credential_id": value["embodiment_credential_id"],
        "embodiment_id": value["embodiment_id"],
        "incarnation_authorization_id": value["incarnation_authorization_id"],
        "incarnation_id": value["incarnation_id"],
        "status": "active",
    }
    if row != expected_row or value["embodiment_id"] in predecessor_ids:
        raise AuthorityEpochError("recovery_rebirth_manifest_change_forbidden")
    credential = successor.credentials.get(value["embodiment_credential_id"])
    incarnation = successor.incarnations.get(value["incarnation_authorization_id"])
    if not isinstance(credential, Mapping) or not isinstance(incarnation, Mapping):
        raise AuthorityEpochError("recovery_rebirth_authorization_missing")
    try:
        credential_body = verify_embodiment_credential(
            credential, recovered_state, at_ms=issued_at_ms
        )
        incarnation_body = verify_incarnation_authorization(
            incarnation, credential, recovered_state, at_ms=issued_at_ms
        )
    except VerificationError as exception:
        raise AuthorityEpochError(
            "recovery_rebirth_authorization_invalid"
        ) from exception
    matching_principals = [
        principal
        for principal in credential_body["transport_principals"]
        if principal["scheme"] == "dm-peer-v1"
        and principal["principal_id"] == value["principal_id"]
    ]
    if (
        credential_body["embodiment_id"] != value["embodiment_id"]
        or credential_body["body_ref"] != value["body_ref"]
        or incarnation_body["incarnation_id"] != value["incarnation_id"]
        or incarnation_body["incarnation_sequence"] != 0
        or incarnation_body["started_at_ms"] > issued_at_ms
        or "dm.we" not in credential_body["purposes"]
        or len(matching_principals) != 1
    ):
        raise AuthorityEpochError("recovery_rebirth_authorization_invalid")
    core = {
        key: copy.deepcopy(item)
        for key, item in value.items()
        if key not in {"content_hash", "signatures"}
    }
    expected_hash = hashlib.sha256(
        RECOVERY_REBIRTH_DOMAIN + canonical_bytes(core)
    ).hexdigest()
    if value.get("content_hash") != expected_hash:
        raise AuthorityEpochError("recovery_rebirth_hash_mismatch")
    signatures = value.get("signatures")
    if not isinstance(signatures, list) or not signatures:
        raise AuthorityEpochError("recovery_rebirth_signature_invalid")
    public_keys, threshold = _root_public_keys(recovered_state)
    valid: set[str] = set()
    normalized: list[Mapping[str, Any]] = []
    for signature in signatures:
        if (
            not isinstance(signature, Mapping)
            or set(signature) != {"alg", "kid", "value"}
            or signature.get("alg") != "Ed25519"
            or not isinstance(signature.get("kid"), str)
            or signature["kid"] in valid
            or signature["kid"] not in public_keys
        ):
            raise AuthorityEpochError("recovery_rebirth_signature_invalid")
        try:
            Ed25519PublicKey.from_public_bytes(public_keys[signature["kid"]]).verify(
                unb64url(str(signature["value"]), length=64),
                RECOVERY_REBIRTH_DOMAIN + bytes.fromhex(expected_hash),
            )
        except (InvalidSignature, TypeError, ValueError) as exception:
            raise AuthorityEpochError(
                "recovery_rebirth_signature_invalid"
            ) from exception
        valid.add(signature["kid"])
        normalized.append(signature)
    if len(valid) < threshold or list(signatures) != sorted(
        normalized, key=lambda item: str(item["kid"])
    ):
        raise AuthorityEpochError("recovery_rebirth_signature_invalid")
    return copy.deepcopy(dict(value))


@dataclass(frozen=True)
class RootHistoryAuthority:
    """Select one exact verified root authority for every accepted epoch."""

    active: RootAuthority
    historical: Sequence[RootAuthority]
    successors: Sequence[Mapping[str, Any]]

    def __post_init__(self) -> None:
        if len(self.historical) != len(self.successors):
            raise AuthorityEpochError("authority_epoch_chain_length_mismatch")
        chain = [*self.historical, self.active]
        hashes = [authority.manifest.digest for authority in chain]
        if len(hashes) != len(set(hashes)):
            raise AuthorityEpochError("authority_epoch_replay")
        for previous, successor, value in zip(
            chain[:-1], chain[1:], self.successors, strict=True
        ):
            if value.get("schema") == AUTHORITY_EPOCH_SCHEMA:
                verify_authority_epoch(value, previous, successor)
            elif value.get("schema") == EMBODIMENT_ENROLLMENT_SCHEMA:
                verify_embodiment_enrollment(value, previous, successor)
            elif value.get("schema") == RECOVERY_REBIRTH_SCHEMA:
                verify_recovery_rebirth(value, previous, successor)
            else:
                raise AuthorityEpochError("unsupported_authority_successor")

    @property
    def manifest(self) -> BeingManifest:
        return self.active.manifest

    @property
    def state(self) -> ControlState:
        return self.active.state

    @property
    def credentials(self) -> Mapping[str, Mapping[str, Any]]:
        return self.active.credentials

    @property
    def incarnations(self) -> Mapping[str, Mapping[str, Any]]:
        return self.active.incarnations

    @property
    def accepted_manifest_hashes(self) -> tuple[str, ...]:
        return tuple(
            sorted(
                authority.manifest.digest
                for authority in (*self.historical, self.active)
            )
        )

    def select(self, event: Mapping[str, Any]) -> RootAuthority:
        manifest_hash = event.get("manifest_hash")
        for authority in (*self.historical, self.active):
            if authority.manifest.digest == manifest_hash:
                return authority
        raise AuthorityEpochError("unknown_manifest_hash")

    def public_key(self, event: Mapping[str, Any]) -> bytes:
        return self.select(event).public_key(event)

    def validate_origin(
        self, origin: Mapping[str, Any], *, require_active: bool = False
    ) -> Mapping[str, Any]:
        return self.active.validate_origin(origin, require_active=require_active)

    def validate_transport_principal(
        self, origin: Mapping[str, Any], *, scheme: str, principal_id: str
    ) -> Mapping[str, Any]:
        return self.active.validate_transport_principal(
            origin, scheme=scheme, principal_id=principal_id
        )


__all__ = [
    "AUTHORITY_EPOCH_SCHEMA",
    "EMBODIMENT_ENROLLMENT_SCHEMA",
    "RECOVERY_REBIRTH_SCHEMA",
    "AuthorityEpochError",
    "RootHistoryAuthority",
    "create_authority_epoch",
    "create_embodiment_enrollment",
    "create_recovery_rebirth",
    "verify_authority_epoch",
    "verify_embodiment_enrollment",
    "verify_recovery_rebirth",
]
