"""Root-authorized birth and first-embodiment ceremony for DM-060.

Birth creates a new being.  It is not a same-being embodiment enrollment, a
Cluster lifecycle operation, a Tribe membership transition, or a transfer of
the parent's state.  The functions below expose only complete typed signing
ceremonies; they deliberately provide no generic root signer.
"""

from __future__ import annotations

import copy
import hashlib
import os
import sqlite3
import stat
import uuid
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Final

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .canonical import (
    CanonicalError,
    b64url,
    canonical_bytes,
    digest,
    domain_bytes,
    unb64url,
)
from .identity import (
    ControlState,
    ed25519_public,
    key_id,
    signing_descriptor,
    verify_embodiment_credential,
    verify_genesis,
    verify_incarnation_authorization,
)
from .ledger import Ledger
from .weave import BeingManifest

Artifact = dict[str, Any]
FaultHook = Callable[[str], None]

OFFER_SCHEMA: Final = "dm.birth.offer/v1"
ACCEPTANCE_SCHEMA: Final = "dm.birth.acceptance/v1"
ACTIVATION_SCHEMA: Final = "dm.birth.activation-receipt/v1"
INSPECTION_SCHEMA: Final = "dm.birth.inspection/v1"

OFFER_DOMAIN: Final = "dm.birth.offer/v1"
ACCEPTANCE_DOMAIN: Final = "dm.birth.acceptance/v1"
AWAKENING_DOMAIN: Final = "dm.birth.awakening-proof/v1"
ACTIVATION_DOMAIN: Final = "dm.birth.activation-receipt/v1"

MAX_ARTIFACT_BYTES: Final = 512 * 1024
MAX_REFERENCES: Final = 256
MAX_COMMITMENTS: Final = 256
MAX_ROUTES: Final = 32
MAX_OFFER_LIFETIME_MS: Final = 7 * 24 * 60 * 60 * 1000
BUSY_TIMEOUT_MS: Final = 5_000


class BirthError(ValueError):
    """One birth artifact or durable transition failed closed."""

    def __init__(self, code: str, *, retryable: bool = False) -> None:
        super().__init__(code)
        self.code = code
        self.retryable = retryable


def _closed(value: Any, fields: set[str], code: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise BirthError(code)
    return value


def _text(value: Any, code: str, *, maximum: int = 256) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value.encode("utf-8")) <= maximum
        or any(ord(character) < 0x20 for character in value)
    ):
        raise BirthError(code)
    return value


def _uint(value: Any, code: str, *, minimum: int = 0) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not minimum <= value <= 2**53 - 1
    ):
        raise BirthError(code)
    return value


def _uuid(value: Any, code: str) -> str:
    text = _text(value, code, maximum=36)
    try:
        if str(uuid.UUID(text)) != text:
            raise ValueError
    except (ValueError, AttributeError) as exception:
        raise BirthError(code) from exception
    return text


def _hex_hash(value: Any, code: str) -> str:
    text = _text(value, code, maximum=64)
    if len(text) != 64 or any(
        character not in "0123456789abcdef" for character in text
    ):
        raise BirthError(code)
    return text


def _derived(value: Any, prefix: str, code: str) -> str:
    text = _text(value, code, maximum=160)
    if not text.startswith(prefix):
        raise BirthError(code)
    try:
        unb64url(text.removeprefix(prefix), length=32)
    except CanonicalError as exception:
        raise BirthError(code) from exception
    return text


def _scoped(value: Any, prefix: str, code: str) -> str:
    text = _text(value, code, maximum=256)
    if not text.startswith(prefix):
        raise BirthError(code)
    return text


def _canonical(value: Any, code: str) -> bytes:
    try:
        raw = canonical_bytes(value)
    except CanonicalError as exception:
        raise BirthError(code) from exception
    if len(raw) > MAX_ARTIFACT_BYTES:
        raise BirthError("birth_artifact_too_large")
    return raw


def _signature(seed: bytes, role: str, preimage: bytes) -> dict[str, str]:
    if len(seed) != 32:
        raise BirthError("invalid_signing_seed")
    descriptor = signing_descriptor(seed)
    return {
        "alg": "Ed25519",
        "kid": descriptor["key_id"],
        "role": role,
        "value": b64url(Ed25519PrivateKey.from_private_bytes(seed).sign(preimage)),
    }


def _descriptor(value: Any, code: str) -> tuple[dict[str, str], bytes]:
    row = _closed(value, {"algorithm", "key_id", "public"}, code)
    if row["algorithm"] != "Ed25519":
        raise BirthError(code)
    try:
        public = unb64url(row["public"], length=32)
        Ed25519PublicKey.from_public_bytes(public)
    except (CanonicalError, ValueError) as exception:
        raise BirthError(code) from exception
    if row["key_id"] != key_id("Ed25519", public):
        raise BirthError(code)
    return copy.deepcopy(dict(row)), public


def _verify_signature(
    value: Any,
    *,
    public: bytes,
    key_identifier: str,
    role: str,
    preimage: bytes,
    code: str,
) -> dict[str, str]:
    row = _closed(value, {"alg", "kid", "role", "value"}, code)
    if row["alg"] != "Ed25519" or row["kid"] != key_identifier or row["role"] != role:
        raise BirthError(code)
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(
            unb64url(row["value"], length=64), preimage
        )
    except (CanonicalError, InvalidSignature, ValueError) as exception:
        raise BirthError(code) from exception
    return copy.deepcopy(dict(row))


def _policy_publics(policy: Any, code: str) -> dict[str, bytes]:
    value = _closed(policy, {"keys", "threshold"}, code)
    rows = value["keys"]
    threshold = value["threshold"]
    if (
        not isinstance(rows, list)
        or not 1 <= len(rows) <= 32
        or not isinstance(threshold, int)
        or isinstance(threshold, bool)
        or not 1 <= threshold <= len(rows)
    ):
        raise BirthError(code)
    result: dict[str, bytes] = {}
    descriptors: list[dict[str, str]] = []
    for row in rows:
        descriptor, public = _descriptor(row, code)
        if descriptor["key_id"] in result or public in result.values():
            raise BirthError(code)
        result[descriptor["key_id"]] = public
        descriptors.append(descriptor)
    if descriptors != sorted(descriptors, key=lambda item: item["key_id"]):
        raise BirthError(code)
    return result


def _verify_threshold(
    signatures: Any,
    policy: Any,
    *,
    role: str,
    preimage: bytes,
    code: str,
) -> list[dict[str, str]]:
    publics = _policy_publics(policy, code)
    threshold = policy["threshold"]
    if not isinstance(signatures, list) or not 1 <= len(signatures) <= 128:
        raise BirthError(code)
    normalized: list[dict[str, str]] = []
    seen: set[str] = set()
    for signature in signatures:
        row = _closed(signature, {"alg", "kid", "role", "value"}, code)
        key_identifier = row["kid"]
        public = publics.get(key_identifier)
        if public is None or key_identifier in seen:
            raise BirthError(code)
        normalized.append(
            _verify_signature(
                row,
                public=public,
                key_identifier=key_identifier,
                role=role,
                preimage=preimage,
                code=code,
            )
        )
        seen.add(key_identifier)
    if len(seen) < threshold:
        raise BirthError(code)
    if normalized != sorted(normalized, key=lambda item: item["kid"]):
        raise BirthError(code)
    return normalized


def _origin(value: Any, code: str) -> dict[str, str]:
    row = _closed(
        value,
        {"body_ref", "embodiment_id", "incarnation_id", "principal_id"},
        code,
    )
    return {
        "body_ref": _text(row["body_ref"], code),
        "embodiment_id": _scoped(row["embodiment_id"], "embodiment:", code),
        "incarnation_id": _scoped(row["incarnation_id"], "incarnation:", code),
        "principal_id": _text(row["principal_id"], code, maximum=128),
    }


def _references(value: Any, code: str) -> list[str]:
    if not isinstance(value, list) or len(value) > MAX_REFERENCES:
        raise BirthError(code)
    rows = [_text(item, code, maximum=512) for item in value]
    if rows != sorted(set(rows)):
        raise BirthError(code)
    return rows


def _commitment(value: Any) -> dict[str, Any]:
    row = _closed(
        value,
        {
            "delegable",
            "expires_at_ms",
            "max_delegation_depth",
            "operations",
            "resource_refs",
            "tribe_ref",
        },
        "invalid_birth_commitment",
    )
    if not isinstance(row["delegable"], bool):
        raise BirthError("invalid_birth_commitment")
    depth = _uint(row["max_delegation_depth"], "invalid_birth_commitment")
    if depth > 16:
        raise BirthError("invalid_birth_commitment")
    expiry = row["expires_at_ms"]
    if expiry is not None:
        expiry = _uint(expiry, "invalid_birth_commitment")
    return {
        "delegable": row["delegable"],
        "expires_at_ms": expiry,
        "max_delegation_depth": depth,
        "operations": _references(row["operations"], "invalid_birth_commitment"),
        "resource_refs": _references(row["resource_refs"], "invalid_birth_commitment"),
        "tribe_ref": _text(row["tribe_ref"], "invalid_birth_commitment"),
    }


def _commitments(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > MAX_COMMITMENTS:
        raise BirthError("invalid_birth_commitments")
    rows = [_commitment(item) for item in value]
    ordered = sorted(rows, key=canonical_bytes)
    if rows != ordered or len(
        {_canonical(row, "invalid_birth_commitments") for row in rows}
    ) != len(rows):
        raise BirthError("invalid_birth_commitments")
    return rows


def _routes(value: Any) -> list[dict[str, str]] | None:
    if value is None:
        return None
    if not isinstance(value, list) or len(value) > MAX_ROUTES:
        raise BirthError("invalid_birth_routes")
    rows: list[dict[str, str]] = []
    for item in value:
        row = _closed(item, {"kind", "route_id"}, "invalid_birth_routes")
        rows.append(
            {
                "kind": _text(row["kind"], "invalid_birth_routes", maximum=64),
                "route_id": _text(row["route_id"], "invalid_birth_routes", maximum=256),
            }
        )
    if rows != sorted(rows, key=lambda row: (row["kind"], row["route_id"])) or len(
        {(row["kind"], row["route_id"]) for row in rows}
    ) != len(rows):
        raise BirthError("invalid_birth_routes")
    return rows


def _credential_binding(
    state: ControlState,
    credential: Mapping[str, Any],
    origin: Mapping[str, Any],
    *,
    at_ms: int,
    purpose: str,
) -> tuple[Mapping[str, Any], bytes]:
    try:
        body = verify_embodiment_credential(credential, state, at_ms=at_ms)
    except (KeyError, ValueError) as exception:
        raise BirthError("birth_credential_rejected") from exception
    normalized_origin = _origin(origin, "invalid_birth_origin")
    if (
        body["being_ref"] != state.being_ref
        or body["body_ref"] != normalized_origin["body_ref"]
        or body["embodiment_id"] != normalized_origin["embodiment_id"]
        or purpose not in body["purposes"]
        or not any(
            principal["principal_id"] == normalized_origin["principal_id"]
            for principal in body["transport_principals"]
        )
    ):
        raise BirthError("birth_credential_scope_mismatch")
    descriptor, public = _descriptor(body["signing_key"], "birth_credential_rejected")
    if descriptor["key_id"] != body["signing_key"]["key_id"]:
        raise BirthError("birth_credential_rejected")
    return body, public


def _offer_body(value: Any) -> dict[str, Any]:
    row = _closed(
        value,
        {
            "awakening_key",
            "bootstrap_routes",
            "expires_at_ms",
            "issued_at_ms",
            "offer_nonce",
            "parent_being_ref",
            "parent_control_head",
            "parent_credential_id",
            "parent_origin",
            "source_references",
            "species_release_id",
            "tribal_commitments",
        },
        "invalid_birth_offer_body",
    )
    awakening, _ = _descriptor(row["awakening_key"], "invalid_awakening_key")
    try:
        nonce = b64url(unb64url(row["offer_nonce"], length=32))
    except (CanonicalError, TypeError) as exception:
        raise BirthError("invalid_birth_offer_nonce") from exception
    issued = _uint(row["issued_at_ms"], "invalid_birth_offer_time")
    expires = _uint(row["expires_at_ms"], "invalid_birth_offer_time")
    if not issued < expires <= issued + MAX_OFFER_LIFETIME_MS:
        raise BirthError("invalid_birth_offer_time")
    return {
        "awakening_key": awakening,
        "bootstrap_routes": _routes(row["bootstrap_routes"]),
        "expires_at_ms": expires,
        "issued_at_ms": issued,
        "offer_nonce": nonce,
        "parent_being_ref": _derived(
            row["parent_being_ref"], "dm:being:v1:", "invalid_parent_being"
        ),
        "parent_control_head": _derived(
            row["parent_control_head"],
            "dm:identity:v1:",
            "invalid_parent_control_head",
        ),
        "parent_credential_id": _derived(
            row["parent_credential_id"],
            "dm:identity:v1:",
            "invalid_parent_credential",
        ),
        "parent_origin": _origin(row["parent_origin"], "invalid_birth_origin"),
        "source_references": _references(
            row["source_references"], "invalid_birth_sources"
        ),
        "species_release_id": _text(
            row["species_release_id"], "invalid_birth_species", maximum=512
        ),
        "tribal_commitments": _commitments(row["tribal_commitments"]),
    }


def create_birth_offer(
    parent_state: ControlState,
    parent_credential: Mapping[str, Any],
    parent_signing_seed: bytes,
    awakening_public: bytes,
    *,
    parent_origin: Mapping[str, str],
    species_release_id: str,
    source_references: Sequence[str],
    tribal_commitments: Sequence[Mapping[str, Any]],
    issued_at_ms: int,
    expires_at_ms: int,
    offer_nonce: bytes,
    bootstrap_routes: Sequence[Mapping[str, str]] | None = None,
) -> Artifact:
    """Create one operationally signed, newborn-free birth offer."""

    _credential_body, public = _credential_binding(
        parent_state,
        parent_credential,
        parent_origin,
        at_ms=issued_at_ms,
        purpose="birth.offer",
    )
    if ed25519_public(parent_signing_seed) != public:
        raise BirthError("parent_signing_key_mismatch")
    body = _offer_body(
        {
            "awakening_key": {
                "algorithm": "Ed25519",
                "key_id": key_id("Ed25519", awakening_public),
                "public": b64url(awakening_public),
            },
            "bootstrap_routes": None
            if bootstrap_routes is None
            else [dict(row) for row in bootstrap_routes],
            "expires_at_ms": expires_at_ms,
            "issued_at_ms": issued_at_ms,
            "offer_nonce": b64url(offer_nonce),
            "parent_being_ref": parent_state.being_ref,
            "parent_control_head": parent_state.head,
            "parent_credential_id": parent_credential["artifact_id"],
            "parent_origin": dict(parent_origin),
            "source_references": list(source_references),
            "species_release_id": species_release_id,
            "tribal_commitments": [dict(row) for row in tribal_commitments],
        }
    )
    forbidden = _policy_publics(parent_state.root_policy, "invalid_parent_policy")
    forbidden.update(
        _policy_publics(parent_state.recovery_policy, "invalid_parent_policy")
    )
    _, awakening = _descriptor(body["awakening_key"], "invalid_awakening_key")
    if awakening in forbidden.values() or awakening == public:
        raise BirthError("awakening_key_alias")
    raw_hash = digest(OFFER_DOMAIN, body)
    result: Artifact = {
        "schema": OFFER_SCHEMA,
        "offer_id": "dm:birth-offer:v1:" + b64url(raw_hash),
        "body": body,
        "signature": _signature(
            parent_signing_seed,
            "parent-offer",
            domain_bytes(OFFER_DOMAIN, body),
        ),
    }
    _canonical(result, "invalid_birth_offer")
    return result


def validate_birth_offer(
    value: Any,
    parent_state: ControlState,
    parent_credential: Mapping[str, Any],
    *,
    observed_at_ms: int,
) -> Artifact:
    row = _closed(
        value, {"body", "offer_id", "schema", "signature"}, "invalid_birth_offer"
    )
    if row["schema"] != OFFER_SCHEMA:
        raise BirthError("unsupported_birth_offer")
    body = _offer_body(row["body"])
    expected = "dm:birth-offer:v1:" + b64url(digest(OFFER_DOMAIN, body))
    if row["offer_id"] != expected:
        raise BirthError("birth_offer_id_mismatch")
    if (
        body["parent_being_ref"] != parent_state.being_ref
        or body["parent_control_head"] != parent_state.head
        or body["parent_credential_id"] != parent_credential.get("artifact_id")
    ):
        raise BirthError("birth_offer_parent_mismatch")
    if not body["issued_at_ms"] <= observed_at_ms < body["expires_at_ms"]:
        raise BirthError("birth_offer_not_timely")
    credential_body, public = _credential_binding(
        parent_state,
        parent_credential,
        body["parent_origin"],
        at_ms=body["issued_at_ms"],
        purpose="birth.offer",
    )
    _verify_signature(
        row["signature"],
        public=public,
        key_identifier=credential_body["signing_key"]["key_id"],
        role="parent-offer",
        preimage=domain_bytes(OFFER_DOMAIN, body),
        code="invalid_birth_offer_signature",
    )
    forbidden = _policy_publics(parent_state.root_policy, "invalid_parent_policy")
    forbidden.update(
        _policy_publics(parent_state.recovery_policy, "invalid_parent_policy")
    )
    _, awakening = _descriptor(body["awakening_key"], "invalid_awakening_key")
    if awakening in forbidden.values() or awakening == public:
        raise BirthError("awakening_key_alias")
    result = {
        "schema": OFFER_SCHEMA,
        "offer_id": expected,
        "body": body,
        "signature": copy.deepcopy(dict(row["signature"])),
    }
    if _canonical(result, "invalid_birth_offer") != _canonical(
        value, "invalid_birth_offer"
    ):
        raise BirthError("noncanonical_birth_offer")
    return result


def _acceptance_core(value: Any) -> dict[str, Any]:
    row = _closed(
        value,
        {
            "acceptance_nonce",
            "accepted_at_ms",
            "newborn_being_ref",
            "newborn_genesis_id",
            "offer_hash",
            "offer_id",
            "parent_being_ref",
            "parent_control_head",
            "parent_origin",
            "source_references",
            "species_release_id",
            "tribal_commitments",
        },
        "invalid_birth_acceptance_core",
    )
    try:
        nonce = b64url(unb64url(row["acceptance_nonce"], length=32))
    except (CanonicalError, TypeError) as exception:
        raise BirthError("invalid_birth_acceptance_nonce") from exception
    return {
        "acceptance_nonce": nonce,
        "accepted_at_ms": _uint(row["accepted_at_ms"], "invalid_birth_acceptance_time"),
        "newborn_being_ref": _derived(
            row["newborn_being_ref"], "dm:being:v1:", "invalid_newborn_being"
        ),
        "newborn_genesis_id": _derived(
            row["newborn_genesis_id"],
            "dm:identity:v1:",
            "invalid_newborn_genesis",
        ),
        "offer_hash": _hex_hash(row["offer_hash"], "invalid_birth_offer_hash"),
        "offer_id": _derived(
            row["offer_id"], "dm:birth-offer:v1:", "invalid_birth_offer_id"
        ),
        "parent_being_ref": _derived(
            row["parent_being_ref"], "dm:being:v1:", "invalid_parent_being"
        ),
        "parent_control_head": _derived(
            row["parent_control_head"],
            "dm:identity:v1:",
            "invalid_parent_control_head",
        ),
        "parent_origin": _origin(row["parent_origin"], "invalid_birth_origin"),
        "source_references": _references(
            row["source_references"], "invalid_birth_sources"
        ),
        "species_release_id": _text(
            row["species_release_id"], "invalid_birth_species", maximum=512
        ),
        "tribal_commitments": _commitments(row["tribal_commitments"]),
    }


def create_birth_acceptance(
    offer: Mapping[str, Any],
    newborn_genesis: Mapping[str, Any],
    newborn_root_seeds: Sequence[bytes],
    awakening_seed: bytes,
    *,
    accepted_at_ms: int,
    acceptance_nonce: bytes,
) -> Artifact:
    """Bind a verified offer to a new independently self-certifying being."""

    offer_row = _closed(
        offer, {"body", "offer_id", "schema", "signature"}, "invalid_birth_offer"
    )
    if offer_row["schema"] != OFFER_SCHEMA:
        raise BirthError("unsupported_birth_offer")
    offer_body = _offer_body(offer_row["body"])
    try:
        newborn_state = verify_genesis(newborn_genesis)
    except ValueError as exception:
        raise BirthError("newborn_genesis_rejected") from exception
    if not offer_body["issued_at_ms"] <= accepted_at_ms < offer_body["expires_at_ms"]:
        raise BirthError("birth_acceptance_not_timely")
    root_seeds = {
        signing_descriptor(seed)["key_id"]: seed for seed in newborn_root_seeds
    }
    policy_publics = _policy_publics(
        newborn_state.root_policy, "invalid_newborn_policy"
    )
    if not set(root_seeds) <= set(policy_publics):
        raise BirthError("newborn_root_seed_mismatch")
    _, awakening_public = _descriptor(
        offer_body["awakening_key"], "invalid_awakening_key"
    )
    if ed25519_public(awakening_seed) != awakening_public:
        raise BirthError("awakening_key_mismatch")
    newborn_forbidden = set(policy_publics.values()) | set(
        _policy_publics(
            newborn_state.recovery_policy, "invalid_newborn_policy"
        ).values()
    )
    if awakening_public in newborn_forbidden:
        raise BirthError("awakening_key_alias")
    core = _acceptance_core(
        {
            "acceptance_nonce": b64url(acceptance_nonce),
            "accepted_at_ms": accepted_at_ms,
            "newborn_being_ref": newborn_state.being_ref,
            "newborn_genesis_id": newborn_state.head,
            "offer_hash": hashlib.sha256(
                _canonical(offer, "invalid_birth_offer")
            ).hexdigest(),
            "offer_id": offer_row["offer_id"],
            "parent_being_ref": offer_body["parent_being_ref"],
            "parent_control_head": offer_body["parent_control_head"],
            "parent_origin": offer_body["parent_origin"],
            "source_references": offer_body["source_references"],
            "species_release_id": offer_body["species_release_id"],
            "tribal_commitments": offer_body["tribal_commitments"],
        }
    )
    awakening_proof = _signature(
        awakening_seed,
        "awakening-proof",
        domain_bytes(AWAKENING_DOMAIN, core),
    )
    body = {"core": core, "awakening_proof": awakening_proof}
    preimage = domain_bytes(ACCEPTANCE_DOMAIN, body)
    signatures = [
        _signature(root_seeds[key], "newborn-root", preimage)
        for key in sorted(root_seeds)
    ]
    result: Artifact = {
        "schema": ACCEPTANCE_SCHEMA,
        "acceptance_id": "dm:birth-acceptance:v1:"
        + b64url(digest(ACCEPTANCE_DOMAIN, body)),
        "body": body,
        "signatures": signatures,
    }
    _canonical(result, "invalid_birth_acceptance")
    return result


def validate_birth_acceptance(
    value: Any,
    offer: Mapping[str, Any],
    parent_state: ControlState,
    parent_credential: Mapping[str, Any],
    newborn_genesis: Mapping[str, Any],
    *,
    observed_at_ms: int,
) -> Artifact:
    verified_offer = validate_birth_offer(
        offer,
        parent_state,
        parent_credential,
        observed_at_ms=observed_at_ms,
    )
    row = _closed(
        value,
        {"acceptance_id", "body", "schema", "signatures"},
        "invalid_birth_acceptance",
    )
    if row["schema"] != ACCEPTANCE_SCHEMA:
        raise BirthError("unsupported_birth_acceptance")
    body_row = _closed(
        row["body"], {"awakening_proof", "core"}, "invalid_birth_acceptance_body"
    )
    core = _acceptance_core(body_row["core"])
    try:
        newborn_state = verify_genesis(newborn_genesis)
    except ValueError as exception:
        raise BirthError("newborn_genesis_rejected") from exception
    offer_body = verified_offer["body"]
    copied = {
        "offer_id": verified_offer["offer_id"],
        "offer_hash": hashlib.sha256(canonical_bytes(verified_offer)).hexdigest(),
        "parent_being_ref": offer_body["parent_being_ref"],
        "parent_control_head": offer_body["parent_control_head"],
        "parent_origin": offer_body["parent_origin"],
        "newborn_being_ref": newborn_state.being_ref,
        "newborn_genesis_id": newborn_state.head,
        "species_release_id": offer_body["species_release_id"],
        "source_references": offer_body["source_references"],
        "tribal_commitments": offer_body["tribal_commitments"],
    }
    if any(core[field] != expected for field, expected in copied.items()):
        raise BirthError("birth_acceptance_copy_mismatch")
    if (
        not offer_body["issued_at_ms"]
        <= core["accepted_at_ms"]
        < offer_body["expires_at_ms"]
    ):
        raise BirthError("birth_acceptance_not_timely")
    if observed_at_ms < core["accepted_at_ms"]:
        raise BirthError("birth_acceptance_observation_invalid")
    awakening, awakening_public = _descriptor(
        offer_body["awakening_key"], "invalid_awakening_key"
    )
    _verify_signature(
        body_row["awakening_proof"],
        public=awakening_public,
        key_identifier=awakening["key_id"],
        role="awakening-proof",
        preimage=domain_bytes(AWAKENING_DOMAIN, core),
        code="invalid_awakening_proof",
    )
    newborn_publics = set(
        _policy_publics(newborn_state.root_policy, "invalid_newborn_policy").values()
    ) | set(
        _policy_publics(
            newborn_state.recovery_policy, "invalid_newborn_policy"
        ).values()
    )
    parent_publics = set(
        _policy_publics(parent_state.root_policy, "invalid_parent_policy").values()
    ) | set(
        _policy_publics(parent_state.recovery_policy, "invalid_parent_policy").values()
    )
    if newborn_publics & parent_publics:
        raise BirthError("birth_cross_being_key_alias")
    if awakening_public in newborn_publics:
        raise BirthError("awakening_key_alias")
    body = {
        "core": core,
        "awakening_proof": copy.deepcopy(dict(body_row["awakening_proof"])),
    }
    expected_id = "dm:birth-acceptance:v1:" + b64url(digest(ACCEPTANCE_DOMAIN, body))
    if row["acceptance_id"] != expected_id:
        raise BirthError("birth_acceptance_id_mismatch")
    signatures = _verify_threshold(
        row["signatures"],
        newborn_state.root_policy,
        role="newborn-root",
        preimage=domain_bytes(ACCEPTANCE_DOMAIN, body),
        code="invalid_birth_acceptance_signature",
    )
    result = {
        "schema": ACCEPTANCE_SCHEMA,
        "acceptance_id": expected_id,
        "body": body,
        "signatures": signatures,
    }
    if _canonical(result, "invalid_birth_acceptance") != _canonical(
        value, "invalid_birth_acceptance"
    ):
        raise BirthError("noncanonical_birth_acceptance")
    return result


def _activation_body(value: Any) -> dict[str, Any]:
    row = _closed(
        value,
        {
            "acceptance_id",
            "event_count",
            "first_credential_id",
            "first_incarnation_authorization_id",
            "ledger_state_hash",
            "manifest_hash",
            "memory_event_count",
            "newborn_being_ref",
            "observed_at_ms",
            "projection_record_count",
            "witness_being_ref",
            "witness_credential_id",
            "witness_origin",
        },
        "invalid_birth_activation_body",
    )
    return {
        "acceptance_id": _derived(
            row["acceptance_id"],
            "dm:birth-acceptance:v1:",
            "invalid_birth_acceptance_id",
        ),
        "event_count": _uint(row["event_count"], "invalid_birth_event_count"),
        "first_credential_id": _derived(
            row["first_credential_id"],
            "dm:identity:v1:",
            "invalid_first_credential",
        ),
        "first_incarnation_authorization_id": _derived(
            row["first_incarnation_authorization_id"],
            "dm:identity:v1:",
            "invalid_first_incarnation",
        ),
        "ledger_state_hash": _hex_hash(
            row["ledger_state_hash"], "invalid_birth_ledger_hash"
        ),
        "manifest_hash": _hex_hash(row["manifest_hash"], "invalid_birth_manifest_hash"),
        "memory_event_count": _uint(
            row["memory_event_count"], "invalid_birth_memory_count"
        ),
        "newborn_being_ref": _derived(
            row["newborn_being_ref"], "dm:being:v1:", "invalid_newborn_being"
        ),
        "observed_at_ms": _uint(row["observed_at_ms"], "invalid_birth_activation_time"),
        "projection_record_count": _uint(
            row["projection_record_count"], "invalid_birth_projection_count"
        ),
        "witness_being_ref": _derived(
            row["witness_being_ref"], "dm:being:v1:", "invalid_witness_being"
        ),
        "witness_credential_id": _derived(
            row["witness_credential_id"],
            "dm:identity:v1:",
            "invalid_witness_credential",
        ),
        "witness_origin": _origin(row["witness_origin"], "invalid_witness_origin"),
    }


def create_activation_receipt(
    acceptance: Mapping[str, Any],
    newborn_state: ControlState,
    first_credential: Mapping[str, Any],
    first_incarnation: Mapping[str, Any],
    manifest: BeingManifest,
    ledger: Ledger,
    witness_state: ControlState,
    witness_credential: Mapping[str, Any],
    witness_signing_seed: bytes,
    *,
    witness_origin: Mapping[str, str],
    observed_at_ms: int,
) -> Artifact:
    """Attest the exact first embodiment and mechanically empty ledger."""

    acceptance_row = _closed(
        acceptance,
        {"acceptance_id", "body", "schema", "signatures"},
        "invalid_birth_acceptance",
    )
    if acceptance_row["schema"] != ACCEPTANCE_SCHEMA:
        raise BirthError("unsupported_birth_acceptance")
    acceptance_body = _closed(
        acceptance_row["body"],
        {"awakening_proof", "core"},
        "invalid_birth_acceptance_body",
    )
    acceptance_core = _acceptance_core(acceptance_body["core"])
    if acceptance_core["newborn_being_ref"] != newborn_state.being_ref:
        raise BirthError("birth_acceptance_newborn_mismatch")
    if (
        manifest.trust_mode != "root-bound"
        or manifest.being_ref != newborn_state.being_ref
    ):
        raise BirthError("birth_manifest_mismatch")
    rows = manifest.value["embodiments"]
    if len(rows) != 1 or rows[0]["status"] != "active":
        raise BirthError("birth_requires_one_first_embodiment")
    member = rows[0]
    try:
        credential_body = verify_embodiment_credential(
            first_credential, newborn_state, at_ms=observed_at_ms
        )
        incarnation_body = verify_incarnation_authorization(
            first_incarnation,
            first_credential,
            newborn_state,
            at_ms=observed_at_ms,
        )
    except ValueError as exception:
        raise BirthError("first_embodiment_rejected") from exception
    if (
        first_credential.get("artifact_id") != member["embodiment_credential_id"]
        or first_incarnation.get("artifact_id")
        != member["incarnation_authorization_id"]
        or credential_body["embodiment_id"] != member["embodiment_id"]
        or credential_body["body_ref"] != member["body_ref"]
        or incarnation_body["incarnation_id"] != member["incarnation_id"]
        or incarnation_body["incarnation_sequence"] != 0
        or "birth.first-embodiment" not in credential_body["purposes"]
    ):
        raise BirthError("first_embodiment_mismatch")
    events = ledger.events(include_incomplete=True)
    memory_events = [event for event in events if event["kind"] == "memory.recorded"]
    projection = ledger.projection_cache()
    projection_count = 0 if projection is None else len(projection.get("entries", []))
    if events or memory_events or projection_count:
        raise BirthError("newborn_memory_not_empty")
    _witness_body, witness_public = _credential_binding(
        witness_state,
        witness_credential,
        witness_origin,
        at_ms=observed_at_ms,
        purpose="birth.witness",
    )
    if ed25519_public(witness_signing_seed) != witness_public:
        raise BirthError("witness_signing_key_mismatch")
    body = _activation_body(
        {
            "acceptance_id": acceptance_row["acceptance_id"],
            "event_count": len(events),
            "first_credential_id": first_credential["artifact_id"],
            "first_incarnation_authorization_id": first_incarnation["artifact_id"],
            "ledger_state_hash": ledger.state_hash(),
            "manifest_hash": manifest.digest,
            "memory_event_count": len(memory_events),
            "newborn_being_ref": newborn_state.being_ref,
            "observed_at_ms": observed_at_ms,
            "projection_record_count": projection_count,
            "witness_being_ref": witness_state.being_ref,
            "witness_credential_id": witness_credential["artifact_id"],
            "witness_origin": dict(witness_origin),
        }
    )
    result: Artifact = {
        "schema": ACTIVATION_SCHEMA,
        "receipt_id": "dm:birth-activation:v1:"
        + b64url(digest(ACTIVATION_DOMAIN, body)),
        "body": body,
        "signature": _signature(
            witness_signing_seed,
            "activation-witness",
            domain_bytes(ACTIVATION_DOMAIN, body),
        ),
    }
    _canonical(result, "invalid_birth_activation")
    return result


def validate_activation_receipt(
    value: Any,
    acceptance: Mapping[str, Any],
    newborn_state: ControlState,
    first_credential: Mapping[str, Any],
    first_incarnation: Mapping[str, Any],
    manifest: BeingManifest,
    ledger: Ledger,
    witness_state: ControlState,
    witness_credential: Mapping[str, Any],
) -> Artifact:
    acceptance_row = _closed(
        acceptance,
        {"acceptance_id", "body", "schema", "signatures"},
        "invalid_birth_acceptance",
    )
    if acceptance_row["schema"] != ACCEPTANCE_SCHEMA:
        raise BirthError("unsupported_birth_acceptance")
    acceptance_body = _closed(
        acceptance_row["body"],
        {"awakening_proof", "core"},
        "invalid_birth_acceptance_body",
    )
    acceptance_core = _acceptance_core(acceptance_body["core"])
    if acceptance_core["newborn_being_ref"] != newborn_state.being_ref:
        raise BirthError("birth_acceptance_newborn_mismatch")
    row = _closed(
        value, {"body", "receipt_id", "schema", "signature"}, "invalid_birth_activation"
    )
    if row["schema"] != ACTIVATION_SCHEMA:
        raise BirthError("unsupported_birth_activation")
    body = _activation_body(row["body"])
    events = ledger.events(include_incomplete=True)
    projection = ledger.projection_cache()
    expected = {
        "acceptance_id": acceptance_row["acceptance_id"],
        "newborn_being_ref": newborn_state.being_ref,
        "first_credential_id": first_credential.get("artifact_id"),
        "first_incarnation_authorization_id": first_incarnation.get("artifact_id"),
        "manifest_hash": manifest.digest,
        "ledger_state_hash": ledger.state_hash(),
        "event_count": len(events),
        "memory_event_count": len(
            [event for event in events if event["kind"] == "memory.recorded"]
        ),
        "projection_record_count": 0
        if projection is None
        else len(projection.get("entries", [])),
        "witness_being_ref": witness_state.being_ref,
        "witness_credential_id": witness_credential.get("artifact_id"),
    }
    if any(body[field] != item for field, item in expected.items()):
        raise BirthError("birth_activation_evidence_mismatch")
    if (
        body["event_count"]
        or body["memory_event_count"]
        or body["projection_record_count"]
    ):
        raise BirthError("newborn_memory_not_empty")
    try:
        credential_body = verify_embodiment_credential(
            first_credential, newborn_state, at_ms=body["observed_at_ms"]
        )
        incarnation_body = verify_incarnation_authorization(
            first_incarnation,
            first_credential,
            newborn_state,
            at_ms=body["observed_at_ms"],
        )
    except ValueError as exception:
        raise BirthError("first_embodiment_rejected") from exception
    member = manifest.member(
        credential_body["embodiment_id"], incarnation_body["incarnation_id"]
    )
    if (
        len(manifest.value["embodiments"]) != 1
        or member["status"] != "active"
        or incarnation_body["incarnation_sequence"] != 0
        or "birth.first-embodiment" not in credential_body["purposes"]
    ):
        raise BirthError("first_embodiment_mismatch")
    witness_body, public = _credential_binding(
        witness_state,
        witness_credential,
        body["witness_origin"],
        at_ms=body["observed_at_ms"],
        purpose="birth.witness",
    )
    _verify_signature(
        row["signature"],
        public=public,
        key_identifier=witness_body["signing_key"]["key_id"],
        role="activation-witness",
        preimage=domain_bytes(ACTIVATION_DOMAIN, body),
        code="invalid_birth_activation_signature",
    )
    expected_id = "dm:birth-activation:v1:" + b64url(digest(ACTIVATION_DOMAIN, body))
    if row["receipt_id"] != expected_id:
        raise BirthError("birth_activation_id_mismatch")
    result = {
        "schema": ACTIVATION_SCHEMA,
        "receipt_id": expected_id,
        "body": body,
        "signature": copy.deepcopy(dict(row["signature"])),
    }
    if _canonical(result, "invalid_birth_activation") != _canonical(
        value, "invalid_birth_activation"
    ):
        raise BirthError("noncanonical_birth_activation")
    return result


def _prepare_path(path: Path) -> None:
    parent = path.parent
    try:
        info = parent.lstat()
    except OSError as exception:
        raise BirthError("birth_store_parent_unavailable") from exception
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise BirthError("birth_store_parent_not_owner_only")
    if path.exists() or path.is_symlink():
        try:
            file_info = path.lstat()
        except OSError as exception:
            raise BirthError("birth_store_unavailable") from exception
        if (
            stat.S_ISLNK(file_info.st_mode)
            or not stat.S_ISREG(file_info.st_mode)
            or file_info.st_uid != os.geteuid()
            or stat.S_IMODE(file_info.st_mode) & 0o077
        ):
            raise BirthError("birth_store_not_owner_only")


class BirthRegistry:
    """Durable one-use offer and first-activation registry."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(os.path.abspath(path))

    def _connect(self) -> sqlite3.Connection:
        _prepare_path(self.path)
        database = sqlite3.connect(
            self.path,
            timeout=BUSY_TIMEOUT_MS / 1000,
            isolation_level=None,
        )
        database.row_factory = sqlite3.Row
        database.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
        database.execute("PRAGMA foreign_keys=ON")
        mode = database.execute("PRAGMA journal_mode=DELETE").fetchone()[0]
        if str(mode).lower() != "delete":
            database.close()
            raise BirthError("birth_store_journal_mode")
        database.execute("PRAGMA synchronous=FULL")
        return database

    @contextmanager
    def _database(self) -> Iterator[sqlite3.Connection]:
        database = self._connect()
        try:
            yield database
        finally:
            database.close()

    def initialize(self) -> None:
        with self._database() as database:
            database.executescript(
                """
                CREATE TABLE IF NOT EXISTS birth_offers (
                    offer_id TEXT PRIMARY KEY,
                    offer_hash TEXT NOT NULL,
                    offer_json BLOB NOT NULL,
                    state TEXT NOT NULL
                        CHECK(state IN ('offered','accepted','active','quarantined')),
                    accepted_id TEXT,
                    activation_id TEXT
                ) WITHOUT ROWID;
                CREATE TABLE IF NOT EXISTS birth_acceptances (
                    acceptance_id TEXT PRIMARY KEY,
                    offer_id TEXT NOT NULL REFERENCES birth_offers(offer_id),
                    being_ref TEXT NOT NULL,
                    acceptance_hash TEXT NOT NULL,
                    acceptance_json BLOB NOT NULL
                ) WITHOUT ROWID;
                CREATE TABLE IF NOT EXISTS birth_activations (
                    receipt_id TEXT PRIMARY KEY,
                    acceptance_id TEXT NOT NULL
                        REFERENCES birth_acceptances(acceptance_id),
                    receipt_hash TEXT NOT NULL,
                    receipt_json BLOB NOT NULL
                ) WITHOUT ROWID;
                """
            )
        if self.path.exists():
            os.chmod(self.path, 0o600)

    def observe_offer(
        self,
        offer: Mapping[str, Any],
        parent_state: ControlState,
        parent_credential: Mapping[str, Any],
        *,
        observed_at_ms: int,
    ) -> dict[str, Any]:
        self.initialize()
        verified = validate_birth_offer(
            offer,
            parent_state,
            parent_credential,
            observed_at_ms=observed_at_ms,
        )
        raw = _canonical(verified, "invalid_birth_offer")
        offer_id = _derived(
            verified.get("offer_id"),
            "dm:birth-offer:v1:",
            "invalid_birth_offer_id",
        )
        offer_hash = hashlib.sha256(raw).hexdigest()
        with self._database() as database:
            database.execute("BEGIN IMMEDIATE")
            try:
                row = database.execute(
                    "SELECT offer_hash, offer_json, state FROM birth_offers "
                    "WHERE offer_id=?",
                    (offer_id,),
                ).fetchone()
                if row is None:
                    database.execute(
                        "INSERT INTO birth_offers VALUES "
                        "(?, ?, ?, 'offered', NULL, NULL)",
                        (offer_id, offer_hash, raw),
                    )
                    state = "offered"
                elif row["offer_hash"] != offer_hash or bytes(row["offer_json"]) != raw:
                    raise BirthError("birth_offer_conflict")
                else:
                    state = str(row["state"])
                database.commit()
            except BaseException:
                database.rollback()
                raise
        return {"offer_id": offer_id, "state": state}

    def accept(
        self,
        acceptance: Mapping[str, Any],
        offer: Mapping[str, Any],
        parent_state: ControlState,
        parent_credential: Mapping[str, Any],
        newborn_genesis: Mapping[str, Any],
        *,
        observed_at_ms: int,
        fault_hook: FaultHook | None = None,
    ) -> dict[str, Any]:
        """Commit first acceptance or quarantine every valid double acceptance."""

        self.initialize()
        verified = validate_birth_acceptance(
            acceptance,
            offer,
            parent_state,
            parent_credential,
            newborn_genesis,
            observed_at_ms=observed_at_ms,
        )
        raw = _canonical(verified, "invalid_birth_acceptance")
        acceptance_id = _derived(
            verified.get("acceptance_id"),
            "dm:birth-acceptance:v1:",
            "invalid_birth_acceptance_id",
        )
        body = _closed(
            verified.get("body"),
            {"awakening_proof", "core"},
            "invalid_birth_acceptance_body",
        )
        core = _acceptance_core(body["core"])
        offer_id = core["offer_id"]
        being_ref = core["newborn_being_ref"]
        acceptance_hash = hashlib.sha256(raw).hexdigest()
        with self._database() as database:
            database.execute("BEGIN IMMEDIATE")
            try:
                offer = database.execute(
                    "SELECT offer_hash, state, accepted_id FROM birth_offers "
                    "WHERE offer_id=?",
                    (offer_id,),
                ).fetchone()
                if offer is None:
                    raise BirthError("birth_offer_not_observed")
                existing = database.execute(
                    "SELECT acceptance_hash, acceptance_json FROM birth_acceptances "
                    "WHERE acceptance_id=?",
                    (acceptance_id,),
                ).fetchone()
                if existing is not None:
                    if (
                        existing["acceptance_hash"] != acceptance_hash
                        or bytes(existing["acceptance_json"]) != raw
                    ):
                        raise BirthError("birth_acceptance_conflict")
                    state = str(offer["state"])
                else:
                    database.execute(
                        "INSERT INTO birth_acceptances VALUES (?, ?, ?, ?, ?)",
                        (acceptance_id, offer_id, being_ref, acceptance_hash, raw),
                    )
                    if offer["accepted_id"] is None:
                        database.execute(
                            "UPDATE birth_offers SET state='accepted', accepted_id=? "
                            "WHERE offer_id=?",
                            (acceptance_id, offer_id),
                        )
                        state = "accepted"
                    elif offer["accepted_id"] == acceptance_id:
                        state = str(offer["state"])
                    else:
                        database.execute(
                            "UPDATE birth_offers SET state='quarantined', "
                            "activation_id=NULL WHERE offer_id=?",
                            (offer_id,),
                        )
                        state = "quarantined"
                if fault_hook is not None:
                    fault_hook("before_accept_commit")
                database.commit()
            except BaseException:
                database.rollback()
                raise
        return {
            "acceptance_id": acceptance_id,
            "offer_id": offer_id,
            "state": state,
        }

    def activate(
        self,
        receipt: Mapping[str, Any],
        acceptance: Mapping[str, Any],
        newborn_state: ControlState,
        first_credential: Mapping[str, Any],
        first_incarnation: Mapping[str, Any],
        manifest: BeingManifest,
        ledger: Ledger,
        witness_state: ControlState,
        witness_credential: Mapping[str, Any],
        *,
        fault_hook: FaultHook | None = None,
    ) -> dict[str, Any]:
        self.initialize()
        verified = validate_activation_receipt(
            receipt,
            acceptance,
            newborn_state,
            first_credential,
            first_incarnation,
            manifest,
            ledger,
            witness_state,
            witness_credential,
        )
        raw = _canonical(verified, "invalid_birth_activation")
        receipt_id = _derived(
            verified.get("receipt_id"),
            "dm:birth-activation:v1:",
            "invalid_birth_activation_id",
        )
        body = _activation_body(verified.get("body"))
        acceptance_id = body["acceptance_id"]
        receipt_hash = hashlib.sha256(raw).hexdigest()
        with self._database() as database:
            database.execute("BEGIN IMMEDIATE")
            try:
                acceptance_row = database.execute(
                    "SELECT offer_id, being_ref, acceptance_hash, acceptance_json "
                    "FROM birth_acceptances WHERE acceptance_id=?",
                    (acceptance_id,),
                ).fetchone()
                if acceptance_row is None:
                    raise BirthError("birth_acceptance_not_observed")
                supplied_acceptance = _canonical(acceptance, "invalid_birth_acceptance")
                if (
                    acceptance_row["being_ref"] != body["newborn_being_ref"]
                    or acceptance_row["acceptance_hash"]
                    != hashlib.sha256(supplied_acceptance).hexdigest()
                    or bytes(acceptance_row["acceptance_json"]) != supplied_acceptance
                ):
                    raise BirthError("birth_activation_acceptance_mismatch")
                offer = database.execute(
                    "SELECT state, accepted_id, activation_id FROM birth_offers "
                    "WHERE offer_id=?",
                    (acceptance_row["offer_id"],),
                ).fetchone()
                if offer is None or offer["state"] == "quarantined":
                    raise BirthError("birth_lineage_quarantined")
                if offer["accepted_id"] != acceptance_id:
                    raise BirthError("birth_acceptance_not_selected")
                existing = database.execute(
                    "SELECT receipt_hash, receipt_json FROM birth_activations "
                    "WHERE receipt_id=?",
                    (receipt_id,),
                ).fetchone()
                if existing is not None:
                    if (
                        existing["receipt_hash"] != receipt_hash
                        or bytes(existing["receipt_json"]) != raw
                    ):
                        raise BirthError("birth_activation_conflict")
                elif offer["activation_id"] is not None:
                    raise BirthError("birth_activation_already_committed")
                else:
                    database.execute(
                        "INSERT INTO birth_activations VALUES (?, ?, ?, ?)",
                        (receipt_id, acceptance_id, receipt_hash, raw),
                    )
                    database.execute(
                        "UPDATE birth_offers SET state='active', activation_id=? "
                        "WHERE offer_id=?",
                        (receipt_id, acceptance_row["offer_id"]),
                    )
                if fault_hook is not None:
                    fault_hook("before_activation_commit")
                database.commit()
            except BaseException:
                database.rollback()
                raise
        return {
            "acceptance_id": acceptance_id,
            "offer_id": str(acceptance_row["offer_id"]),
            "receipt_id": receipt_id,
            "state": "active",
        }

    def inspect(self, offer_id: str) -> dict[str, Any]:
        self.initialize()
        _derived(offer_id, "dm:birth-offer:v1:", "invalid_birth_offer_id")
        with self._database() as database:
            offer = database.execute(
                "SELECT state, accepted_id, activation_id FROM birth_offers "
                "WHERE offer_id=?",
                (offer_id,),
            ).fetchone()
            if offer is None:
                raise BirthError("birth_offer_unknown")
            acceptances = [
                {
                    "acceptance_id": str(row["acceptance_id"]),
                    "being_ref": str(row["being_ref"]),
                }
                for row in database.execute(
                    "SELECT acceptance_id, being_ref FROM birth_acceptances "
                    "WHERE offer_id=? ORDER BY acceptance_id",
                    (offer_id,),
                )
            ]
        return {
            "schema": INSPECTION_SCHEMA,
            "offer_id": offer_id,
            "state": str(offer["state"]),
            "accepted_id": offer["accepted_id"],
            "activation_id": offer["activation_id"],
            "acceptances": acceptances,
        }
