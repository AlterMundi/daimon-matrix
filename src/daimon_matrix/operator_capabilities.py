"""Bounded, disjoint operator capabilities for provisioned runtimes."""

from __future__ import annotations

import hashlib
import re
import secrets
from collections.abc import Callable, Mapping
from typing import Any, Final

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .canonical import b64url, canonical_bytes, unb64url
from .identity import key_descriptor, signing_descriptor
from .local_api import LocalCapability, create_capability
from .service import CURATOR_METHODS, OPERATOR_CAPABILITY_PROFILES

OPERATOR_CAPABILITY_TTL_MS: Final = 30 * 24 * 60 * 60 * 1_000
OPERATOR_CAPABILITY_REPROVISION_LEAD_MS: Final = 7 * 24 * 60 * 60 * 1_000
OPERATOR_CAPABILITY_NOT_BEFORE_SKEW_MS: Final = 60_000
OPERATOR_CAPABILITY_PROFILE_SCHEMA: Final = "dm.operator.capability-profile/v1"
OPERATOR_CAPABILITY_BINDING_SCHEMA: Final = "dm.operator.capability-binding/v1"
OPERATOR_RUNTIME_ID_SCHEMA: Final = "dm.operator.runtime-identity/v1"
OPERATOR_PROFILE_NAMES: Final = tuple(sorted(OPERATOR_CAPABILITY_PROFILES))
OBSERVE_PROFILE: Final = "observe"
STATUS_OBSERVER_METHODS: Final = frozenset(
    {
        "runtime.status",
        "scope.me",
        "scope.we",
        "scope.we.diff",
        "scope.we.sync-plan",
    }
)
HOST_CAPABILITY_PROFILES: Final = {
    "curator": CURATOR_METHODS,
    "status": STATUS_OBSERVER_METHODS,
}
HOST_PROFILE_NAMES: Final = tuple(sorted(HOST_CAPABILITY_PROFILES))
HOST_CAPABILITY_PROFILE_SCHEMA: Final = "dm.host.capability-profile/v1"

_LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_CAPABILITY_SET_DOMAIN: Final = b"daimon/operator-capability-set/v1\x00"
_CAPABILITY_BINDING_DOMAIN: Final = b"daimon/operator-capability-binding/v1\x00"


class OperatorCapabilityError(ValueError):
    """An operator capability set is incomplete, regrouped, or stale."""


def operator_capability_profile(profile: str) -> dict[str, str]:
    """Return the exact runtime/client placement metadata for one role."""

    if profile not in OPERATOR_CAPABILITY_PROFILES:
        raise OperatorCapabilityError("invalid_operator_capability_identity")
    observe = profile == OBSERVE_PROFILE
    return {
        "schema": OPERATOR_CAPABILITY_PROFILE_SCHEMA,
        "role": profile,
        "client_directory": "." if observe else f"operator-clients/{profile}",
        "client_config_filename": "client.json",
        "client_key_filename": "client.key" if observe else "capability.key",
    }


def host_capability_profile(profile: str) -> dict[str, str]:
    """Return the exact portable placement metadata for one host role."""

    if profile not in HOST_CAPABILITY_PROFILES:
        raise OperatorCapabilityError("invalid_host_capability_identity")
    return {
        "schema": HOST_CAPABILITY_PROFILE_SCHEMA,
        "role": profile,
        "client_directory": f"host-clients/{profile}",
        "client_config_filename": "client.json",
        "client_key_filename": "capability.key",
    }


def operator_runtime_id(
    label: str,
    being_ref: str,
    origin: Mapping[str, Any],
    signing_key_id: str,
) -> str:
    """Derive one content-addressed runtime identity from root-authorized facts."""

    origin_fields = {"body_ref", "embodiment_id", "incarnation_id", "principal_id"}
    if (
        _LABEL.fullmatch(label) is None
        or not isinstance(being_ref, str)
        or not 1 <= len(being_ref.encode("utf-8")) <= 256
        or not isinstance(signing_key_id, str)
        or not signing_key_id.startswith("dm:key:v1:")
        or not isinstance(origin, Mapping)
        or set(origin) != origin_fields
        or any(
            not isinstance(origin[field], str)
            or not 1 <= len(origin[field].encode("utf-8")) <= 256
            for field in origin_fields
        )
    ):
        raise OperatorCapabilityError("invalid_operator_runtime_identity")
    body = {
        "schema": OPERATOR_RUNTIME_ID_SCHEMA,
        "runtime_label": label,
        "being_ref": being_ref,
        "origin": {field: origin[field] for field in sorted(origin_fields)},
        "signing_key_id": signing_key_id,
    }
    return "dm:runtime:v1:" + b64url(
        hashlib.sha256(
            b"daimon/operator-runtime-identity/v1\x00" + canonical_bytes(body)
        ).digest()
    )


def operator_capability_slot(label: str, profile: str) -> str:
    """Return the unique encrypted-custody slot for one operator role."""

    if _LABEL.fullmatch(label) is None or profile not in OPERATOR_CAPABILITY_PROFILES:
        raise OperatorCapabilityError("invalid_operator_capability_identity")
    return f"runtime.capability.v1:{profile}:{label}"


def host_capability_slot(label: str, profile: str) -> str:
    """Return the unique encrypted-custody slot for one host-bound role."""

    if _LABEL.fullmatch(label) is None or profile not in HOST_CAPABILITY_PROFILES:
        raise OperatorCapabilityError("invalid_host_capability_identity")
    return f"runtime.host-capability.v1:{profile}:{label}"


def operator_capability_set_hash(capability_rows: Any) -> str:
    if not isinstance(capability_rows, list) or len(capability_rows) != (
        len(OPERATOR_PROFILE_NAMES) + len(HOST_PROFILE_NAMES)
    ):
        raise OperatorCapabilityError("invalid_operator_capability_binding")
    try:
        encoded = canonical_bytes(capability_rows)
    except (TypeError, ValueError) as exception:
        raise OperatorCapabilityError(
            "invalid_operator_capability_binding"
        ) from exception
    return "dm:operator-capability-set:v1:" + b64url(
        hashlib.sha256(_CAPABILITY_SET_DOMAIN + encoded).digest()
    )


def create_operator_capability_binding(
    *,
    runtime_id: str,
    runtime_label: str,
    being_ref: str,
    origin: Mapping[str, Any],
    signing_seed: bytes,
    capability_rows: Any,
) -> dict[str, Any]:
    """Sign all exact operator and host material with the embodiment key."""

    try:
        signing_key = signing_descriptor(signing_seed)
        expected_runtime_id = operator_runtime_id(
            runtime_label, being_ref, origin, signing_key["key_id"]
        )
        capability_set_hash = operator_capability_set_hash(capability_rows)
    except (TypeError, ValueError) as exception:
        raise OperatorCapabilityError(
            "invalid_operator_capability_binding"
        ) from exception
    if runtime_id != expected_runtime_id:
        raise OperatorCapabilityError("invalid_operator_capability_binding")
    body = {
        "runtime_id": runtime_id,
        "runtime_label": runtime_label,
        "being_ref": being_ref,
        "origin": {
            field: origin[field]
            for field in ("body_ref", "embodiment_id", "incarnation_id", "principal_id")
        },
        "signing_key_id": signing_key["key_id"],
        "capability_set_hash": capability_set_hash,
    }
    signature = Ed25519PrivateKey.from_private_bytes(signing_seed).sign(
        _CAPABILITY_BINDING_DOMAIN + canonical_bytes(body)
    )
    return {
        "schema": OPERATOR_CAPABILITY_BINDING_SCHEMA,
        "body": body,
        "signature": {
            "algorithm": "Ed25519",
            "key_id": signing_key["key_id"],
            "value": b64url(signature),
        },
    }


def verify_operator_capability_binding(
    value: Any,
    *,
    runtime_id: str,
    runtime_label: str,
    being_ref: str,
    origin: Mapping[str, Any],
    signing_key: Mapping[str, Any],
    capability_rows: Any,
) -> None:
    """Reject relabelled capability material not signed by this embodiment."""

    try:
        if not isinstance(value, Mapping) or set(value) != {
            "schema",
            "body",
            "signature",
        }:
            raise OperatorCapabilityError("invalid_operator_capability_binding")
        if value["schema"] != OPERATOR_CAPABILITY_BINDING_SCHEMA:
            raise OperatorCapabilityError("invalid_operator_capability_binding")
        if not isinstance(signing_key, Mapping) or set(signing_key) != {
            "algorithm",
            "key_id",
            "public",
        }:
            raise OperatorCapabilityError("invalid_operator_capability_binding")
        public = unb64url(signing_key["public"], length=32)
        if signing_key != key_descriptor("Ed25519", public):
            raise OperatorCapabilityError("invalid_operator_capability_binding")
        expected_runtime_id = operator_runtime_id(
            runtime_label, being_ref, origin, signing_key["key_id"]
        )
        expected_body = {
            "runtime_id": runtime_id,
            "runtime_label": runtime_label,
            "being_ref": being_ref,
            "origin": {
                field: origin[field]
                for field in (
                    "body_ref",
                    "embodiment_id",
                    "incarnation_id",
                    "principal_id",
                )
            },
            "signing_key_id": signing_key["key_id"],
            "capability_set_hash": operator_capability_set_hash(capability_rows),
        }
        body = value["body"]
        signature = value["signature"]
        if (
            runtime_id != expected_runtime_id
            or body != expected_body
            or not isinstance(signature, Mapping)
            or set(signature) != {"algorithm", "key_id", "value"}
            or signature["algorithm"] != "Ed25519"
            or signature["key_id"] != signing_key["key_id"]
        ):
            raise OperatorCapabilityError("invalid_operator_capability_binding")
        Ed25519PublicKey.from_public_bytes(public).verify(
            unb64url(signature["value"], length=64),
            _CAPABILITY_BINDING_DOMAIN + canonical_bytes(body),
        )
    except OperatorCapabilityError:
        raise
    except (InvalidSignature, KeyError, TypeError, ValueError) as exception:
        raise OperatorCapabilityError(
            "invalid_operator_capability_binding"
        ) from exception


def operator_capability_lifecycle(issued_at_ms: int) -> dict[str, int]:
    """Return the mandatory reprovision and hard-expiry instants."""

    if (
        not isinstance(issued_at_ms, int)
        or isinstance(issued_at_ms, bool)
        or not 0 <= issued_at_ms <= 2**53 - 1 - OPERATOR_CAPABILITY_TTL_MS
    ):
        raise OperatorCapabilityError("invalid_operator_capability_time")
    expires_at_ms = issued_at_ms + OPERATOR_CAPABILITY_TTL_MS
    return {
        "reprovision_at_ms": (expires_at_ms - OPERATOR_CAPABILITY_REPROVISION_LEAD_MS),
        "expires_at_ms": expires_at_ms,
    }


def create_operator_capability_set(
    label: str,
    *,
    issued_at_ms: int,
    key_factory: Callable[[int], bytes] = secrets.token_bytes,
) -> tuple[dict[str, LocalCapability], dict[str, bytes], dict[str, str]]:
    """Mint one independently keyed capability for every disjoint role."""

    lifecycle = operator_capability_lifecycle(issued_at_ms)
    capabilities: dict[str, LocalCapability] = {}
    keys: dict[str, bytes] = {}
    slots: dict[str, str] = {}
    for profile in OPERATOR_PROFILE_NAMES:
        key = key_factory(32)
        if not isinstance(key, bytes) or len(key) != 32:
            raise OperatorCapabilityError("invalid_operator_capability_key")
        capability = create_capability(
            key,
            client_id=f"client:operator:{label}:{profile}",
            methods=sorted(OPERATOR_CAPABILITY_PROFILES[profile]),
            not_before_ms=max(0, issued_at_ms - OPERATOR_CAPABILITY_NOT_BEFORE_SKEW_MS),
            not_after_ms=lifecycle["expires_at_ms"],
        )
        capabilities[profile] = capability
        keys[profile] = key
        slots[profile] = operator_capability_slot(label, profile)
    if len(set(keys.values())) != len(keys):
        raise OperatorCapabilityError("duplicate_operator_capability_key")
    return capabilities, keys, slots


def create_host_capability_set(
    label: str,
    *,
    issued_at_ms: int,
    key_factory: Callable[[int], bytes] = secrets.token_bytes,
) -> tuple[dict[str, LocalCapability], dict[str, bytes], dict[str, str]]:
    """Mint the two independently keyed, least-authority host capabilities."""

    lifecycle = operator_capability_lifecycle(issued_at_ms)
    capabilities: dict[str, LocalCapability] = {}
    keys: dict[str, bytes] = {}
    slots: dict[str, str] = {}
    for profile in HOST_PROFILE_NAMES:
        key = key_factory(32)
        if not isinstance(key, bytes) or len(key) != 32:
            raise OperatorCapabilityError("invalid_host_capability_key")
        capability = create_capability(
            key,
            client_id=f"client:host:{label}:{profile}",
            methods=sorted(HOST_CAPABILITY_PROFILES[profile]),
            not_before_ms=max(0, issued_at_ms - OPERATOR_CAPABILITY_NOT_BEFORE_SKEW_MS),
            not_after_ms=lifecycle["expires_at_ms"],
        )
        capabilities[profile] = capability
        keys[profile] = key
        slots[profile] = host_capability_slot(label, profile)
    if len(set(keys.values())) != len(keys):
        raise OperatorCapabilityError("duplicate_host_capability_key")
    return capabilities, keys, slots


def validate_operator_capability_set(
    descriptors: Any,
    slots: Any,
    secrets_by_slot: Mapping[str, bytes],
    *,
    label: str,
    issued_at_ms: int,
    observed_at_ms: int,
) -> dict[str, LocalCapability]:
    """Validate the complete profile set and reject regrouping or stale roles."""

    if (
        not isinstance(descriptors, Mapping)
        or set(descriptors) != set(OPERATOR_PROFILE_NAMES)
        or not isinstance(slots, Mapping)
        or set(slots) != set(OPERATOR_PROFILE_NAMES)
        or not isinstance(observed_at_ms, int)
        or isinstance(observed_at_ms, bool)
    ):
        raise OperatorCapabilityError("invalid_operator_capability_set")
    lifecycle = operator_capability_lifecycle(issued_at_ms)
    expected_before = max(0, issued_at_ms - OPERATOR_CAPABILITY_NOT_BEFORE_SKEW_MS)
    capabilities: dict[str, LocalCapability] = {}
    keys: list[bytes] = []
    for profile in OPERATOR_PROFILE_NAMES:
        expected_slot = operator_capability_slot(label, profile)
        slot = slots[profile]
        if slot != expected_slot:
            raise OperatorCapabilityError("operator_capability_slot_mismatch")
        key = secrets_by_slot.get(expected_slot)
        if key is None:
            raise OperatorCapabilityError("missing_operator_capability_key")
        try:
            capability = LocalCapability.from_value(descriptors[profile], key)
        except (KeyError, TypeError, ValueError) as exception:
            raise OperatorCapabilityError(
                "operator_capability_binding_rejected"
            ) from exception
        descriptor = capability.descriptor
        if (
            capability.client_id != f"client:operator:{label}:{profile}"
            or frozenset(capability.methods) != OPERATOR_CAPABILITY_PROFILES[profile]
            or descriptor["not_before_ms"] != expected_before
            or descriptor["not_after_ms"] != lifecycle["expires_at_ms"]
            or descriptor["status"] != "active"
            or not descriptor["not_before_ms"]
            <= observed_at_ms
            < descriptor["not_after_ms"]
        ):
            raise OperatorCapabilityError("operator_capability_policy_rejected")
        capabilities[profile] = capability
        keys.append(key)
    if len(set(keys)) != len(keys):
        raise OperatorCapabilityError("duplicate_operator_capability_key")
    return capabilities


def validate_host_capability_set(
    descriptors: Any,
    slots: Any,
    secrets_by_slot: Mapping[str, bytes],
    *,
    label: str,
    issued_at_ms: int,
    observed_at_ms: int,
) -> dict[str, LocalCapability]:
    """Validate both host profiles, their distinct keys, and bounded lifetime."""

    if (
        not isinstance(descriptors, Mapping)
        or set(descriptors) != set(HOST_PROFILE_NAMES)
        or not isinstance(slots, Mapping)
        or set(slots) != set(HOST_PROFILE_NAMES)
        or not isinstance(observed_at_ms, int)
        or isinstance(observed_at_ms, bool)
    ):
        raise OperatorCapabilityError("invalid_host_capability_set")
    lifecycle = operator_capability_lifecycle(issued_at_ms)
    expected_before = max(0, issued_at_ms - OPERATOR_CAPABILITY_NOT_BEFORE_SKEW_MS)
    capabilities: dict[str, LocalCapability] = {}
    keys: list[bytes] = []
    for profile in HOST_PROFILE_NAMES:
        expected_slot = host_capability_slot(label, profile)
        if slots[profile] != expected_slot:
            raise OperatorCapabilityError("host_capability_slot_mismatch")
        key = secrets_by_slot.get(expected_slot)
        if key is None:
            raise OperatorCapabilityError("missing_host_capability_key")
        try:
            capability = LocalCapability.from_value(descriptors[profile], key)
        except (KeyError, TypeError, ValueError) as exception:
            raise OperatorCapabilityError(
                "host_capability_binding_rejected"
            ) from exception
        descriptor = capability.descriptor
        if (
            capability.client_id != f"client:host:{label}:{profile}"
            or frozenset(capability.methods) != HOST_CAPABILITY_PROFILES[profile]
            or descriptor["not_before_ms"] != expected_before
            or descriptor["not_after_ms"] != lifecycle["expires_at_ms"]
            or descriptor["status"] != "active"
            or not descriptor["not_before_ms"]
            <= observed_at_ms
            < descriptor["not_after_ms"]
        ):
            raise OperatorCapabilityError("host_capability_policy_rejected")
        capabilities[profile] = capability
        keys.append(key)
    if len(set(keys)) != len(keys):
        raise OperatorCapabilityError("duplicate_host_capability_key")
    return capabilities


__all__ = [
    "HOST_CAPABILITY_PROFILES",
    "HOST_CAPABILITY_PROFILE_SCHEMA",
    "HOST_PROFILE_NAMES",
    "OBSERVE_PROFILE",
    "OPERATOR_CAPABILITY_BINDING_SCHEMA",
    "OPERATOR_CAPABILITY_NOT_BEFORE_SKEW_MS",
    "OPERATOR_CAPABILITY_PROFILE_SCHEMA",
    "OPERATOR_CAPABILITY_REPROVISION_LEAD_MS",
    "OPERATOR_CAPABILITY_TTL_MS",
    "OPERATOR_PROFILE_NAMES",
    "OPERATOR_RUNTIME_ID_SCHEMA",
    "STATUS_OBSERVER_METHODS",
    "OperatorCapabilityError",
    "create_host_capability_set",
    "create_operator_capability_binding",
    "create_operator_capability_set",
    "host_capability_profile",
    "host_capability_slot",
    "operator_capability_lifecycle",
    "operator_capability_profile",
    "operator_capability_set_hash",
    "operator_capability_slot",
    "operator_runtime_id",
    "validate_host_capability_set",
    "validate_operator_capability_set",
    "verify_operator_capability_binding",
]
