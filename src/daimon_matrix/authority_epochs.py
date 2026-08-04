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
    key_id,
    verify_embodiment_credential,
    verify_incarnation_authorization,
)
from .weave import BeingManifest, RootAuthority, WeaveProtocolError

AUTHORITY_EPOCH_SCHEMA: Final = "dm.we.authority-epoch/v1"
AUTHORITY_EPOCH_DOMAIN: Final = b"daimon/weave-authority-epoch/v1\x00"


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
            verify_authority_epoch(value, previous, successor)

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
    "AuthorityEpochError",
    "RootHistoryAuthority",
    "create_authority_epoch",
    "verify_authority_epoch",
]
