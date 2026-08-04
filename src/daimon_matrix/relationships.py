"""Exact, externally verified tribe relationship snapshots for DM-054."""

from __future__ import annotations

import copy
import hashlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Final, cast

from .canonical import CanonicalError, b64url, canonical_bytes, unb64url

TRIBE_SNAPSHOT_SCHEMA: Final = "dm.tribe-snapshot/v1"
TRIBE_REF_PREFIX: Final = "dm:tribe:v1:"
TRIBE_DOMAIN: Final = b"daimon/tribe/declaration/v1\x00"
MAX_MEMBERS: Final = 256
MAX_GRANTS: Final = 1024
SnapshotVerifier = Callable[[Mapping[str, Any]], None]


class RelationshipError(ValueError):
    """A relationship snapshot cannot authorize scope resolution."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _closed(value: Any, fields: set[str], code: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise RelationshipError(code)
    return value


def _text(value: Any, code: str, maximum: int = 256) -> str:
    if not isinstance(value, str) or not 1 <= len(value.encode()) <= maximum:
        raise RelationshipError(code)
    try:
        canonical_bytes(value)
    except CanonicalError as exception:
        raise RelationshipError(code) from exception
    return value


def _uint(value: Any, code: str) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not 0 <= value <= 2**53 - 1
    ):
        raise RelationshipError(code)
    return value


def tribe_ref(declaration: Mapping[str, Any]) -> str:
    """Derive the exact tribe reference from its closed declaration core."""

    value = _closed(
        declaration,
        {"created_at_ms", "founder_principal_id", "nonce", "policy_ref"},
        "invalid_tribe_declaration",
    )
    _uint(value["created_at_ms"], "invalid_tribe_declaration")
    _text(value["founder_principal_id"], "invalid_tribe_declaration")
    _text(value["policy_ref"], "invalid_tribe_declaration")
    try:
        unb64url(cast(str, value["nonce"]), length=32)
    except (CanonicalError, TypeError, ValueError) as exception:
        raise RelationshipError("invalid_tribe_declaration") from exception
    digest = hashlib.sha256(TRIBE_DOMAIN + canonical_bytes(value)).digest()
    return TRIBE_REF_PREFIX + b64url(digest)


@dataclass(frozen=True)
class VerifiedTribeSnapshot:
    """A closed snapshot whose signature/history authority was checked upstream."""

    value: Mapping[str, Any]

    @classmethod
    def from_value(
        cls, value: Any, *, verifier: SnapshotVerifier | None
    ) -> VerifiedTribeSnapshot:
        if verifier is None:
            raise RelationshipError("tribe_verifier_required")
        snapshot = _closed(
            value,
            {
                "declaration",
                "founder_epoch",
                "founder_principal_id",
                "grants",
                "lineage_head_ref",
                "members",
                "schema",
                "tribe_ref",
                "verified_at_ms",
            },
            "invalid_tribe_snapshot",
        )
        if snapshot["schema"] != TRIBE_SNAPSHOT_SCHEMA:
            raise RelationshipError("unsupported_tribe_snapshot")
        expected_ref = tribe_ref(cast(Mapping[str, Any], snapshot["declaration"]))
        if snapshot["tribe_ref"] != expected_ref:
            raise RelationshipError("tribe_ref_mismatch")
        founder = _text(snapshot["founder_principal_id"], "invalid_tribe_snapshot")
        declaration = cast(Mapping[str, Any], snapshot["declaration"])
        if founder != declaration["founder_principal_id"]:
            raise RelationshipError("tribe_founder_mismatch")
        _uint(snapshot["founder_epoch"], "invalid_tribe_snapshot")
        _uint(snapshot["verified_at_ms"], "invalid_tribe_snapshot")
        _text(snapshot["lineage_head_ref"], "invalid_tribe_snapshot")
        members = snapshot["members"]
        if not isinstance(members, list) or not 1 <= len(members) <= MAX_MEMBERS:
            raise RelationshipError("invalid_tribe_members")
        normalized_members = [_member(row, expected_ref) for row in members]
        if normalized_members != sorted(
            normalized_members, key=lambda row: row["principal_id"]
        ) or len({row["principal_id"] for row in normalized_members}) != len(
            normalized_members
        ):
            raise RelationshipError("invalid_tribe_members")
        active_founders = [
            row
            for row in normalized_members
            if row["principal_id"] == founder and row["state"] == "active"
        ]
        if len(active_founders) != 1:
            raise RelationshipError("tribe_founder_not_active")
        grants = snapshot["grants"]
        if not isinstance(grants, list) or len(grants) > MAX_GRANTS:
            raise RelationshipError("invalid_tribe_grants")
        normalized_grants = [_grant(row, expected_ref) for row in grants]
        if normalized_grants != sorted(
            normalized_grants, key=lambda row: row["grant_ref"]
        ) or len({row["grant_ref"] for row in normalized_grants}) != len(
            normalized_grants
        ):
            raise RelationshipError("invalid_tribe_grants")
        normalized = {
            **copy.deepcopy(dict(snapshot)),
            "declaration": copy.deepcopy(dict(declaration)),
            "members": normalized_members,
            "grants": normalized_grants,
        }
        try:
            verifier(normalized)
        except (RelationshipError, ValueError) as exception:
            raise RelationshipError("tribe_snapshot_unverified") from exception
        return cls(normalized)

    @property
    def ref(self) -> str:
        return cast(str, self.value["tribe_ref"])

    def resolve(self, *, principal_id: str, at_ms: int) -> dict[str, Any]:
        """Return active members and currently valid grants for one member."""

        _text(principal_id, "invalid_tribe_principal")
        _uint(at_ms, "invalid_tribe_time")
        members = cast(list[Mapping[str, Any]], self.value["members"])
        requester = [row for row in members if row["principal_id"] == principal_id]
        if len(requester) != 1 or requester[0]["state"] != "active":
            raise RelationshipError("tribe_membership_not_active")
        active = [
            copy.deepcopy(dict(row)) for row in members if row["state"] == "active"
        ]
        grants = [
            copy.deepcopy(dict(row))
            for row in cast(list[Mapping[str, Any]], self.value["grants"])
            if row["grantee_principal_id"] == principal_id
            and not row["revoked"]
            and row["not_before_ms"] <= at_ms < row["not_after_ms"]
        ]
        return {
            "schema": "dm.tribe-resolution/v1",
            "tribe_ref": self.ref,
            "lineage_head_ref": self.value["lineage_head_ref"],
            "founder_epoch": self.value["founder_epoch"],
            "requester_principal_id": principal_id,
            "members": active,
            "grants": grants,
            "evaluated_at_ms": at_ms,
        }


def _member(value: Any, expected_ref: str) -> dict[str, Any]:
    row = _closed(
        value,
        {
            "embodiment_id",
            "membership_ref",
            "principal_id",
            "state",
            "tribe_ref",
        },
        "invalid_tribe_member",
    )
    if row["tribe_ref"] != expected_ref or row["state"] not in {
        "active",
        "left",
        "expelled",
    }:
        raise RelationshipError("invalid_tribe_member")
    for field in ("embodiment_id", "membership_ref", "principal_id"):
        _text(row[field], "invalid_tribe_member")
    return copy.deepcopy(dict(row))


def _grant(value: Any, expected_ref: str) -> dict[str, Any]:
    row = _closed(
        value,
        {
            "controller_principal_id",
            "grant_ref",
            "grantee_principal_id",
            "not_after_ms",
            "not_before_ms",
            "operations",
            "parent_grant_ref",
            "resource_ref",
            "revoked",
            "tribe_ref",
        },
        "invalid_tribe_grant",
    )
    if row["tribe_ref"] != expected_ref or not isinstance(row["revoked"], bool):
        raise RelationshipError("invalid_tribe_grant")
    for field in (
        "controller_principal_id",
        "grant_ref",
        "grantee_principal_id",
        "resource_ref",
    ):
        _text(row[field], "invalid_tribe_grant")
    if row["parent_grant_ref"] is not None:
        _text(row["parent_grant_ref"], "invalid_tribe_grant")
    start = _uint(row["not_before_ms"], "invalid_tribe_grant")
    end = _uint(row["not_after_ms"], "invalid_tribe_grant")
    operations = row["operations"]
    if (
        start >= end
        or not isinstance(operations, list)
        or not operations
        or operations != sorted(set(operations))
        or len(operations) > 64
    ):
        raise RelationshipError("invalid_tribe_grant")
    for operation in operations:
        _text(operation, "invalid_tribe_grant", 128)
    return copy.deepcopy(dict(row))


__all__ = [
    "TRIBE_SNAPSHOT_SCHEMA",
    "RelationshipError",
    "SnapshotVerifier",
    "VerifiedTribeSnapshot",
    "tribe_ref",
]
