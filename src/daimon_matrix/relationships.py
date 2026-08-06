"""Exact, externally verified tribe relationship snapshots for DM-054."""

from __future__ import annotations

import copy
import hashlib
import re
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

RELATIONSHIP_EVENT_KINDS: Final = frozenset(
    {
        "matrix/relationship-card",
        "matrix/relationship-offer",
        "matrix/relationship-acceptance",
        "matrix/relationship-close",
        "matrix/tribe-declaration",
        "matrix/tribe-invitation",
        "matrix/tribe-membership-acceptance",
        "matrix/tribe-membership-leave",
        "matrix/tribe-membership-expulsion",
        "matrix/tribe-founder-transfer",
        "matrix/tribe-founder-acceptance",
        "matrix/relationship-grant",
        "matrix/relationship-grant-acceptance",
        "matrix/relationship-grant-revocation",
    }
)
CARD_SCHEMA: Final = "dm.relationship.card/v1"
OFFER_SCHEMA: Final = "dm.relationship.offer/v1"
ACCEPTANCE_SCHEMA: Final = "dm.relationship.acceptance/v1"
CLOSE_SCHEMA: Final = "dm.relationship.close/v1"
DECLARATION_SCHEMA: Final = "dm.tribe.declaration/v1"
INVITATION_SCHEMA: Final = "dm.tribe.invitation/v1"
MEMBERSHIP_ACCEPTANCE_SCHEMA: Final = "dm.tribe.membership-acceptance/v1"
MEMBERSHIP_LEAVE_SCHEMA: Final = "dm.tribe.membership-leave/v1"
MEMBERSHIP_EXPULSION_SCHEMA: Final = "dm.tribe.membership-expulsion/v1"
FOUNDER_TRANSFER_SCHEMA: Final = "dm.tribe.founder-transfer/v1"
FOUNDER_ACCEPTANCE_SCHEMA: Final = "dm.tribe.founder-acceptance/v1"
GRANT_SCHEMA: Final = "dm.relationship.grant/v1"
GRANT_ACCEPTANCE_SCHEMA: Final = "dm.relationship.grant-acceptance/v1"
GRANT_REVOCATION_SCHEMA: Final = "dm.relationship.grant-revocation/v1"
RESOURCE_SCHEMA: Final = "dm.relationship.resource/v1"

MAX_ROUTES: Final = 64
MAX_CAPABILITIES: Final = 64
MAX_RESOURCES: Final = 64
MAX_ROLES: Final = 64
MAX_PROPOSED_GRANTS: Final = 64
MAX_PERMISSIONS: Final = 64
MAX_DELEGATION_DEPTH: Final = 16
MAX_GRANT_LIFETIME_MS: Final = 365 * 24 * 60 * 60 * 1000
MAX_CARD_LIFETIME_MS: Final = 30 * 24 * 60 * 60 * 1000
MAX_OFFER_LIFETIME_MS: Final = 7 * 24 * 60 * 60 * 1000
MAX_INVITATION_LIFETIME_MS: Final = 7 * 24 * 60 * 60 * 1000

_HEX_HASH = re.compile(r"^[0-9a-f]{64}$")
_OPERATION = re.compile(r"^[a-z][a-z0-9]*(?:[./-][a-z0-9]+)*$")
_CLASSIFICATION = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
_DERIVED_ID = re.compile(r"^dm:[a-z-]+:v1:[A-Za-z0-9_-]{43}$")

_CARD_DOMAIN: Final = b"daimon/relationship/card-series/v1\x00"
_RESOURCE_DOMAIN: Final = b"daimon/relationship/resource/v1\x00"
_RELATIONSHIP_DOMAIN: Final = b"daimon/relationship/id/v1\x00"
_INVITATION_DOMAIN: Final = b"daimon/tribe/invitation/v1\x00"
_TRANSFER_DOMAIN: Final = b"daimon/tribe/founder-transfer/v1\x00"
_GRANT_DOMAIN: Final = b"daimon/relationship/grant/v1\x00"


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
        founder_epoch = _uint(snapshot["founder_epoch"], "invalid_tribe_snapshot")
        if founder_epoch == 0 and founder != declaration["founder_principal_id"]:
            raise RelationshipError("tribe_founder_mismatch")
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


def _hash(value: Any, code: str) -> str:
    if not isinstance(value, str) or _HEX_HASH.fullmatch(value) is None:
        raise RelationshipError(code)
    return value


def _nonce(value: Any, code: str) -> str:
    try:
        unb64url(cast(str, value), length=32)
    except (CanonicalError, TypeError, ValueError) as exception:
        raise RelationshipError(code) from exception
    return cast(str, value)


def _derived(prefix: str, domain: bytes, core: Mapping[str, Any]) -> str:
    return prefix + b64url(hashlib.sha256(domain + canonical_bytes(core)).digest())


def _derived_id(value: Any, prefix: str, code: str) -> str:
    result = _text(value, code)
    if not result.startswith(prefix) or _DERIVED_ID.fullmatch(result) is None:
        raise RelationshipError(code)
    return result


def _sorted_texts(
    value: Any, code: str, *, maximum: int, pattern: re.Pattern[str] | None = None
) -> list[str]:
    if (
        not isinstance(value, list)
        or len(value) > maximum
        or value != sorted(set(value))
    ):
        raise RelationshipError(code)
    result: list[str] = []
    for item in value:
        text = _text(item, code)
        if pattern is not None and pattern.fullmatch(text) is None:
            raise RelationshipError(code)
        result.append(text)
    return result


def _event_ref(value: Any, code: str) -> dict[str, str]:
    row = _closed(value, {"event_hash", "event_id"}, code)
    event_id = _text(row["event_id"], code, 64)
    try:
        import uuid

        if str(uuid.UUID(event_id)) != event_id:
            raise ValueError
    except (AttributeError, TypeError, ValueError) as exception:
        raise RelationshipError(code) from exception
    return {"event_id": event_id, "event_hash": _hash(row["event_hash"], code)}


def _key_descriptor(value: Any, code: str) -> dict[str, str]:
    row = _closed(value, {"algorithm", "key_id", "public"}, code)
    if row["algorithm"] != "X25519":
        raise RelationshipError(code)
    try:
        public = unb64url(cast(str, row["public"]), length=32)
    except (CanonicalError, TypeError, ValueError) as exception:
        raise RelationshipError(code) from exception
    # Import lazily to keep this module independent of identity custody.
    from .identity import key_id

    expected = key_id("X25519", public)
    if row["key_id"] != expected:
        raise RelationshipError(code)
    return {
        "algorithm": "X25519",
        "key_id": expected,
        "public": b64url(public),
    }


def _control_position(value: Any, code: str) -> dict[str, str]:
    row = _closed(
        value,
        {"embodiment_id", "incarnation_id", "manifest_hash"},
        code,
    )
    return {
        "embodiment_id": _text(row["embodiment_id"], code),
        "incarnation_id": _text(row["incarnation_id"], code),
        "manifest_hash": _hash(row["manifest_hash"], code),
    }


def card_series_id(being_ref: str) -> str:
    being = _text(being_ref, "invalid_relationship_card")
    return _derived(
        "dm:relationship-card-series:v1:",
        _CARD_DOMAIN,
        {"being_ref": being},
    )


def resource_ref(descriptor: Mapping[str, Any]) -> str:
    value = validate_resource_descriptor(descriptor)
    return _derived("dm:relationship-resource:v1:", _RESOURCE_DOMAIN, value)


def relationship_id(
    *, nonce: str, initiator_being_ref: str, responder_being_ref: str
) -> str:
    core = {
        "initiator_being_ref": _text(initiator_being_ref, "invalid_relationship_offer"),
        "nonce": _nonce(nonce, "invalid_relationship_offer"),
        "responder_being_ref": _text(responder_being_ref, "invalid_relationship_offer"),
    }
    if core["initiator_being_ref"] == core["responder_being_ref"]:
        raise RelationshipError("relationship_requires_distinct_beings")
    return _derived("dm:relationship:v1:", _RELATIONSHIP_DOMAIN, core)


def invitation_id(
    *, tribe: str, founder_epoch: int, invitee_being_ref: str, nonce: str
) -> str:
    core = {
        "founder_epoch": _uint(founder_epoch, "invalid_tribe_invitation"),
        "invitee_being_ref": _text(invitee_being_ref, "invalid_tribe_invitation"),
        "nonce": _nonce(nonce, "invalid_tribe_invitation"),
        "tribe_ref": _derived_id(tribe, TRIBE_REF_PREFIX, "invalid_tribe_invitation"),
    }
    return _derived("dm:tribe-invitation:v1:", _INVITATION_DOMAIN, core)


def founder_transfer_id(
    *, tribe: str, from_epoch: int, successor_being_ref: str, nonce: str
) -> str:
    core = {
        "from_epoch": _uint(from_epoch, "invalid_founder_transfer"),
        "nonce": _nonce(nonce, "invalid_founder_transfer"),
        "successor_being_ref": _text(successor_being_ref, "invalid_founder_transfer"),
        "tribe_ref": _derived_id(tribe, TRIBE_REF_PREFIX, "invalid_founder_transfer"),
    }
    return _derived("dm:founder-transfer:v1:", _TRANSFER_DOMAIN, core)


def grant_id(
    *,
    nonce: str,
    relationship: str,
    grantor_being_ref: str,
    subject_being_ref: str,
) -> str:
    core = {
        "grantor_being_ref": _text(grantor_being_ref, "invalid_relationship_grant"),
        "nonce": _nonce(nonce, "invalid_relationship_grant"),
        "relationship_id": _derived_id(
            relationship, "dm:relationship:v1:", "invalid_relationship_grant"
        ),
        "subject_being_ref": _text(subject_being_ref, "invalid_relationship_grant"),
    }
    if core["grantor_being_ref"] == core["subject_being_ref"]:
        raise RelationshipError("grant_requires_distinct_beings")
    return _derived("dm:relationship-grant:v1:", _GRANT_DOMAIN, core)


def validate_resource_descriptor(value: Any) -> dict[str, Any]:
    row = _closed(
        value,
        {
            "classification",
            "controller_being_ref",
            "descriptor_ref",
            "kind",
            "operations",
            "resource_nonce",
            "schema",
        },
        "invalid_relationship_resource",
    )
    if row["schema"] != RESOURCE_SCHEMA or row["kind"] not in {
        "knowledge",
        "compute",
        "storage",
        "tool",
        "sensor",
        "actuator",
        "route",
        "other",
    }:
        raise RelationshipError("invalid_relationship_resource")
    classification = _text(row["classification"], "invalid_relationship_resource", 64)
    if _CLASSIFICATION.fullmatch(classification) is None:
        raise RelationshipError("invalid_relationship_resource")
    return {
        "schema": RESOURCE_SCHEMA,
        "resource_nonce": _nonce(
            row["resource_nonce"], "invalid_relationship_resource"
        ),
        "controller_being_ref": _text(
            row["controller_being_ref"], "invalid_relationship_resource"
        ),
        "kind": cast(str, row["kind"]),
        "classification": classification,
        "operations": _sorted_texts(
            row["operations"],
            "invalid_relationship_resource",
            maximum=MAX_PERMISSIONS,
            pattern=_OPERATION,
        ),
        "descriptor_ref": _text(row["descriptor_ref"], "invalid_relationship_resource"),
    }


def _resource_entry(value: Any, code: str) -> dict[str, Any]:
    row = _closed(value, {"descriptor", "resource_ref"}, code)
    descriptor = validate_resource_descriptor(row["descriptor"])
    expected = resource_ref(descriptor)
    if row["resource_ref"] != expected:
        raise RelationshipError(code)
    return {"resource_ref": expected, "descriptor": descriptor}


def _permission(value: Any, code: str) -> dict[str, Any]:
    row = _closed(
        value,
        {
            "classification",
            "delegable",
            "operations",
            "remaining_delegation_depth",
            "resource_ref",
        },
        code,
    )
    depth = _uint(row["remaining_delegation_depth"], code)
    if depth > MAX_DELEGATION_DEPTH or not isinstance(row["delegable"], bool):
        raise RelationshipError(code)
    if (not row["delegable"] and depth != 0) or (row["delegable"] and depth == 0):
        raise RelationshipError(code)
    classification = _text(row["classification"], code, 64)
    if _CLASSIFICATION.fullmatch(classification) is None:
        raise RelationshipError(code)
    return {
        "resource_ref": _derived_id(
            row["resource_ref"], "dm:relationship-resource:v1:", code
        ),
        "operations": _sorted_texts(
            row["operations"], code, maximum=MAX_PERMISSIONS, pattern=_OPERATION
        ),
        "classification": classification,
        "delegable": row["delegable"],
        "remaining_delegation_depth": depth,
    }


def _permissions(value: Any, code: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > MAX_PERMISSIONS:
        raise RelationshipError(code)
    result = [_permission(item, code) for item in value]
    keys = [(item["resource_ref"], item["classification"]) for item in result]
    if keys != sorted(set(keys)):
        raise RelationshipError(code)
    return result


def _proposed_grant(value: Any, code: str) -> dict[str, Any]:
    row = _closed(
        value,
        {
            "expires_at_ms",
            "grantor_being_ref",
            "not_before_ms",
            "permissions",
            "subject_being_ref",
        },
        code,
    )
    start = _uint(row["not_before_ms"], code)
    end = _uint(row["expires_at_ms"], code)
    if start >= end or end - start > MAX_GRANT_LIFETIME_MS:
        raise RelationshipError(code)
    grantor = _text(row["grantor_being_ref"], code)
    subject = _text(row["subject_being_ref"], code)
    if grantor == subject:
        raise RelationshipError(code)
    return {
        "grantor_being_ref": grantor,
        "subject_being_ref": subject,
        "permissions": _permissions(row["permissions"], code),
        "not_before_ms": start,
        "expires_at_ms": end,
    }


def _card_payload(value: Any) -> dict[str, Any]:
    code = "invalid_relationship_card"
    row = _closed(
        value,
        {
            "being_ref",
            "capability_refs",
            "card_series_id",
            "control_position",
            "encryption_key",
            "expires_at_ms",
            "issued_at_ms",
            "previous_card_event_id",
            "resources",
            "route_refs",
            "schema",
            "sequence",
        },
        code,
    )
    being = _text(row["being_ref"], code)
    sequence = _uint(row["sequence"], code)
    previous = row["previous_card_event_id"]
    if sequence == 0:
        if previous is not None:
            raise RelationshipError(code)
    elif previous is None:
        raise RelationshipError(code)
    else:
        _event_ref({"event_id": previous, "event_hash": "0" * 64}, code)
    issued = _uint(row["issued_at_ms"], code)
    expires = _uint(row["expires_at_ms"], code)
    if issued >= expires or expires - issued > MAX_CARD_LIFETIME_MS:
        raise RelationshipError(code)
    if not isinstance(row["resources"], list) or len(row["resources"]) > MAX_RESOURCES:
        raise RelationshipError(code)
    resources = [_resource_entry(item, code) for item in row["resources"]]
    if [item["resource_ref"] for item in resources] != sorted(
        {item["resource_ref"] for item in resources}
    ):
        raise RelationshipError(code)
    result = {
        "schema": CARD_SCHEMA,
        "card_series_id": card_series_id(being),
        "sequence": sequence,
        "previous_card_event_id": previous,
        "being_ref": being,
        "control_position": _control_position(row["control_position"], code),
        "encryption_key": _key_descriptor(row["encryption_key"], code),
        "route_refs": _sorted_texts(row["route_refs"], code, maximum=MAX_ROUTES),
        "capability_refs": _sorted_texts(
            row["capability_refs"], code, maximum=MAX_CAPABILITIES
        ),
        "resources": resources,
        "issued_at_ms": _uint(row["issued_at_ms"], code),
        "expires_at_ms": expires,
    }
    if (
        row["schema"] != CARD_SCHEMA
        or row["card_series_id"] != result["card_series_id"]
    ):
        raise RelationshipError(code)
    return result


def _offer_payload(value: Any) -> dict[str, Any]:
    code = "invalid_relationship_offer"
    row = _closed(
        value,
        {
            "expires_at_ms",
            "initiator_being_ref",
            "initiator_card_ref",
            "issued_at_ms",
            "nonce",
            "proposed_grants",
            "relationship_id",
            "responder_being_ref",
            "responder_card_ref",
            "roles",
            "schema",
            "terms_ref",
        },
        code,
    )
    initiator = _text(row["initiator_being_ref"], code)
    responder = _text(row["responder_being_ref"], code)
    nonce = _nonce(row["nonce"], code)
    issued = _uint(row["issued_at_ms"], code)
    expires = _uint(row["expires_at_ms"], code)
    if issued >= expires or expires - issued > MAX_OFFER_LIFETIME_MS:
        raise RelationshipError(code)
    proposed = row["proposed_grants"]
    if not isinstance(proposed, list) or len(proposed) > MAX_PROPOSED_GRANTS:
        raise RelationshipError(code)
    normalized_proposed = [_proposed_grant(item, code) for item in proposed]
    keys = [
        (
            item["grantor_being_ref"],
            item["subject_being_ref"],
            canonical_bytes(item).hex(),
        )
        for item in normalized_proposed
    ]
    if keys != sorted(set(keys)):
        raise RelationshipError(code)
    participants = {initiator, responder}
    if any(
        {item["grantor_being_ref"], item["subject_being_ref"]} != participants
        for item in normalized_proposed
    ):
        raise RelationshipError(code)
    expected = relationship_id(
        nonce=nonce,
        initiator_being_ref=initiator,
        responder_being_ref=responder,
    )
    responder_card = (
        None
        if row["responder_card_ref"] is None
        else _event_ref(row["responder_card_ref"], code)
    )
    result = {
        "schema": OFFER_SCHEMA,
        "relationship_id": expected,
        "nonce": nonce,
        "initiator_being_ref": initiator,
        "responder_being_ref": responder,
        "initiator_card_ref": _event_ref(row["initiator_card_ref"], code),
        "responder_card_ref": responder_card,
        "terms_ref": _text(row["terms_ref"], code),
        "roles": _sorted_texts(row["roles"], code, maximum=MAX_ROLES),
        "proposed_grants": normalized_proposed,
        "issued_at_ms": issued,
        "expires_at_ms": expires,
    }
    if row["schema"] != OFFER_SCHEMA or row["relationship_id"] != expected:
        raise RelationshipError(code)
    return result


def _acceptance_payload(value: Any) -> dict[str, Any]:
    code = "invalid_relationship_acceptance"
    row = _closed(
        value,
        {
            "accepted_at_ms",
            "initiator_being_ref",
            "initiator_card_ref",
            "offer_ref",
            "relationship_id",
            "responder_being_ref",
            "responder_card_ref",
            "schema",
        },
        code,
    )
    result = {
        "schema": ACCEPTANCE_SCHEMA,
        "relationship_id": _derived_id(
            row["relationship_id"], "dm:relationship:v1:", code
        ),
        "offer_ref": _event_ref(row["offer_ref"], code),
        "initiator_being_ref": _text(row["initiator_being_ref"], code),
        "responder_being_ref": _text(row["responder_being_ref"], code),
        "initiator_card_ref": _event_ref(row["initiator_card_ref"], code),
        "responder_card_ref": _event_ref(row["responder_card_ref"], code),
        "accepted_at_ms": _uint(row["accepted_at_ms"], code),
    }
    if row["schema"] != ACCEPTANCE_SCHEMA:
        raise RelationshipError(code)
    return result


def _close_payload(value: Any) -> dict[str, Any]:
    code = "invalid_relationship_close"
    row = _closed(
        value,
        {
            "acceptance_ref",
            "closed_at_ms",
            "closer_being_ref",
            "offer_ref",
            "reason",
            "relationship_id",
            "schema",
        },
        code,
    )
    if row["schema"] != CLOSE_SCHEMA:
        raise RelationshipError(code)
    return {
        "schema": CLOSE_SCHEMA,
        "relationship_id": _derived_id(
            row["relationship_id"], "dm:relationship:v1:", code
        ),
        "offer_ref": _event_ref(row["offer_ref"], code),
        "acceptance_ref": _event_ref(row["acceptance_ref"], code),
        "closer_being_ref": _text(row["closer_being_ref"], code),
        "reason": _text(row["reason"], code, 128),
        "closed_at_ms": _uint(row["closed_at_ms"], code),
    }


def _declaration_payload(value: Any) -> dict[str, Any]:
    code = "invalid_tribe_declaration"
    row = _closed(value, {"declaration", "schema", "tribe_ref"}, code)
    declaration = _closed(
        row["declaration"],
        {"created_at_ms", "founder_principal_id", "nonce", "policy_ref"},
        code,
    )
    normalized = {
        "created_at_ms": _uint(declaration["created_at_ms"], code),
        "founder_principal_id": _text(declaration["founder_principal_id"], code),
        "nonce": _nonce(declaration["nonce"], code),
        "policy_ref": _text(declaration["policy_ref"], code),
    }
    expected = tribe_ref(normalized)
    if row["schema"] != DECLARATION_SCHEMA or row["tribe_ref"] != expected:
        raise RelationshipError(code)
    return {
        "schema": DECLARATION_SCHEMA,
        "tribe_ref": expected,
        "declaration": normalized,
    }


def _invitation_payload(value: Any) -> dict[str, Any]:
    code = "invalid_tribe_invitation"
    row = _closed(
        value,
        {
            "expires_at_ms",
            "founder_being_ref",
            "founder_epoch",
            "invitation_id",
            "invitee_being_ref",
            "issued_at_ms",
            "nonce",
            "schema",
            "tribe_ref",
        },
        code,
    )
    epoch = _uint(row["founder_epoch"], code)
    invitee = _text(row["invitee_being_ref"], code)
    nonce = _nonce(row["nonce"], code)
    tribe = _derived_id(row["tribe_ref"], TRIBE_REF_PREFIX, code)
    issued = _uint(row["issued_at_ms"], code)
    expires = _uint(row["expires_at_ms"], code)
    expected = invitation_id(
        tribe=tribe,
        founder_epoch=epoch,
        invitee_being_ref=invitee,
        nonce=nonce,
    )
    if (
        row["schema"] != INVITATION_SCHEMA
        or row["invitation_id"] != expected
        or issued >= expires
        or expires - issued > MAX_INVITATION_LIFETIME_MS
    ):
        raise RelationshipError(code)
    return {
        "schema": INVITATION_SCHEMA,
        "tribe_ref": tribe,
        "founder_epoch": epoch,
        "founder_being_ref": _text(row["founder_being_ref"], code),
        "invitation_id": expected,
        "invitee_being_ref": invitee,
        "nonce": nonce,
        "issued_at_ms": issued,
        "expires_at_ms": expires,
    }


def _membership_acceptance_payload(value: Any) -> dict[str, Any]:
    code = "invalid_tribe_membership_acceptance"
    row = _closed(
        value,
        {
            "accepted_at_ms",
            "founder_epoch",
            "invitation_ref",
            "invitee_being_ref",
            "membership_sequence",
            "previous_membership_terminal_ref",
            "schema",
            "tribe_ref",
        },
        code,
    )
    if row["schema"] != MEMBERSHIP_ACCEPTANCE_SCHEMA:
        raise RelationshipError(code)
    sequence = _uint(row["membership_sequence"], code)
    previous = row["previous_membership_terminal_ref"]
    if sequence == 0:
        if previous is not None:
            raise RelationshipError(code)
    elif previous is None:
        raise RelationshipError(code)
    return {
        "schema": MEMBERSHIP_ACCEPTANCE_SCHEMA,
        "tribe_ref": _derived_id(row["tribe_ref"], TRIBE_REF_PREFIX, code),
        "founder_epoch": _uint(row["founder_epoch"], code),
        "invitation_ref": _event_ref(row["invitation_ref"], code),
        "invitee_being_ref": _text(row["invitee_being_ref"], code),
        "membership_sequence": sequence,
        "previous_membership_terminal_ref": (
            None if previous is None else _event_ref(previous, code)
        ),
        "accepted_at_ms": _uint(row["accepted_at_ms"], code),
    }


def _membership_terminal_payload(value: Any, *, expulsion: bool) -> dict[str, Any]:
    code = (
        "invalid_tribe_membership_expulsion"
        if expulsion
        else "invalid_tribe_membership_leave"
    )
    schema = MEMBERSHIP_EXPULSION_SCHEMA if expulsion else MEMBERSHIP_LEAVE_SCHEMA
    actor = "founder_being_ref" if expulsion else "member_being_ref"
    fields = {
        "founder_epoch",
        "member_being_ref",
        "membership_acceptance_ref",
        "reason",
        "schema",
        "terminated_at_ms",
        "tribe_ref",
    }
    if expulsion:
        fields.add("founder_being_ref")
    row = _closed(value, fields, code)
    if row["schema"] != schema:
        raise RelationshipError(code)
    result: dict[str, Any] = {
        "schema": schema,
        "tribe_ref": _derived_id(row["tribe_ref"], TRIBE_REF_PREFIX, code),
        "founder_epoch": _uint(row["founder_epoch"], code),
        "member_being_ref": _text(row["member_being_ref"], code),
        "membership_acceptance_ref": _event_ref(row["membership_acceptance_ref"], code),
        "reason": _text(row["reason"], code, 128),
        "terminated_at_ms": _uint(row["terminated_at_ms"], code),
    }
    if expulsion:
        result[actor] = _text(row[actor], code)
    return result


def _founder_transfer_payload(value: Any) -> dict[str, Any]:
    code = "invalid_founder_transfer"
    row = _closed(
        value,
        {
            "from_epoch",
            "issued_at_ms",
            "nonce",
            "old_founder_being_ref",
            "schema",
            "successor_being_ref",
            "to_epoch",
            "transfer_id",
            "tribe_ref",
        },
        code,
    )
    tribe = _derived_id(row["tribe_ref"], TRIBE_REF_PREFIX, code)
    old = _text(row["old_founder_being_ref"], code)
    successor = _text(row["successor_being_ref"], code)
    start = _uint(row["from_epoch"], code)
    nonce = _nonce(row["nonce"], code)
    expected = founder_transfer_id(
        tribe=tribe,
        from_epoch=start,
        successor_being_ref=successor,
        nonce=nonce,
    )
    if (
        row["schema"] != FOUNDER_TRANSFER_SCHEMA
        or row["transfer_id"] != expected
        or row["to_epoch"] != start + 1
        or old == successor
    ):
        raise RelationshipError(code)
    return {
        "schema": FOUNDER_TRANSFER_SCHEMA,
        "tribe_ref": tribe,
        "transfer_id": expected,
        "from_epoch": start,
        "to_epoch": start + 1,
        "old_founder_being_ref": old,
        "successor_being_ref": successor,
        "nonce": nonce,
        "issued_at_ms": _uint(row["issued_at_ms"], code),
    }


def _founder_acceptance_payload(value: Any) -> dict[str, Any]:
    code = "invalid_founder_acceptance"
    row = _closed(
        value,
        {
            "accepted_at_ms",
            "from_epoch",
            "schema",
            "successor_being_ref",
            "to_epoch",
            "transfer_id",
            "transfer_ref",
            "tribe_ref",
        },
        code,
    )
    start = _uint(row["from_epoch"], code)
    if row["schema"] != FOUNDER_ACCEPTANCE_SCHEMA or row["to_epoch"] != start + 1:
        raise RelationshipError(code)
    return {
        "schema": FOUNDER_ACCEPTANCE_SCHEMA,
        "tribe_ref": _derived_id(row["tribe_ref"], TRIBE_REF_PREFIX, code),
        "transfer_id": _derived_id(row["transfer_id"], "dm:founder-transfer:v1:", code),
        "transfer_ref": _event_ref(row["transfer_ref"], code),
        "from_epoch": start,
        "to_epoch": start + 1,
        "successor_being_ref": _text(row["successor_being_ref"], code),
        "accepted_at_ms": _uint(row["accepted_at_ms"], code),
    }


def _grant_payload(value: Any) -> dict[str, Any]:
    code = "invalid_relationship_grant"
    row = _closed(
        value,
        {
            "delegation_sequence",
            "expires_at_ms",
            "grant_id",
            "grantor_being_ref",
            "issued_at_ms",
            "nonce",
            "not_before_ms",
            "parent_grant_ref",
            "permissions",
            "previous_delegation_event_id",
            "relationship_id",
            "schema",
            "subject_being_ref",
            "tribe_ref",
        },
        code,
    )
    relationship = _derived_id(row["relationship_id"], "dm:relationship:v1:", code)
    grantor = _text(row["grantor_being_ref"], code)
    subject = _text(row["subject_being_ref"], code)
    if grantor == subject:
        raise RelationshipError(code)
    nonce = _nonce(row["nonce"], code)
    expected = grant_id(
        nonce=nonce,
        relationship=relationship,
        grantor_being_ref=grantor,
        subject_being_ref=subject,
    )
    start = _uint(row["not_before_ms"], code)
    end = _uint(row["expires_at_ms"], code)
    issued = _uint(row["issued_at_ms"], code)
    if start >= end or issued >= end or end - start > MAX_GRANT_LIFETIME_MS:
        raise RelationshipError(code)
    parent = (
        None
        if row["parent_grant_ref"] is None
        else _event_ref(row["parent_grant_ref"], code)
    )
    sequence = _uint(row["delegation_sequence"], code)
    previous = row["previous_delegation_event_id"]
    if parent is None:
        if sequence != 0 or previous is not None:
            raise RelationshipError(code)
    elif sequence == 0:
        if previous is not None:
            raise RelationshipError(code)
    elif previous is None:
        raise RelationshipError(code)
    else:
        _event_ref({"event_id": previous, "event_hash": "0" * 64}, code)
    tribe = (
        None
        if row["tribe_ref"] is None
        else _derived_id(row["tribe_ref"], TRIBE_REF_PREFIX, code)
    )
    if row["schema"] != GRANT_SCHEMA or row["grant_id"] != expected:
        raise RelationshipError(code)
    return {
        "schema": GRANT_SCHEMA,
        "grant_id": expected,
        "nonce": nonce,
        "relationship_id": relationship,
        "tribe_ref": tribe,
        "grantor_being_ref": grantor,
        "subject_being_ref": subject,
        "permissions": _permissions(row["permissions"], code),
        "not_before_ms": start,
        "expires_at_ms": end,
        "issued_at_ms": issued,
        "parent_grant_ref": parent,
        "delegation_sequence": sequence,
        "previous_delegation_event_id": previous,
    }


def _grant_acceptance_payload(value: Any) -> dict[str, Any]:
    code = "invalid_grant_acceptance"
    row = _closed(
        value,
        {
            "accepted_at_ms",
            "grant_id",
            "grant_ref",
            "grantor_being_ref",
            "relationship_id",
            "schema",
            "subject_being_ref",
        },
        code,
    )
    if row["schema"] != GRANT_ACCEPTANCE_SCHEMA:
        raise RelationshipError(code)
    return {
        "schema": GRANT_ACCEPTANCE_SCHEMA,
        "grant_id": _derived_id(row["grant_id"], "dm:relationship-grant:v1:", code),
        "grant_ref": _event_ref(row["grant_ref"], code),
        "relationship_id": _derived_id(
            row["relationship_id"], "dm:relationship:v1:", code
        ),
        "grantor_being_ref": _text(row["grantor_being_ref"], code),
        "subject_being_ref": _text(row["subject_being_ref"], code),
        "accepted_at_ms": _uint(row["accepted_at_ms"], code),
    }


def _grant_revocation_payload(value: Any) -> dict[str, Any]:
    code = "invalid_grant_revocation"
    row = _closed(
        value,
        {
            "acceptance_ref",
            "action",
            "actor_being_ref",
            "grant_id",
            "grant_ref",
            "reason",
            "revoked_at_ms",
            "schema",
        },
        code,
    )
    if row["schema"] != GRANT_REVOCATION_SCHEMA or row["action"] not in {
        "revoke",
        "relinquish",
    }:
        raise RelationshipError(code)
    return {
        "schema": GRANT_REVOCATION_SCHEMA,
        "grant_id": _derived_id(row["grant_id"], "dm:relationship-grant:v1:", code),
        "grant_ref": _event_ref(row["grant_ref"], code),
        "acceptance_ref": _event_ref(row["acceptance_ref"], code),
        "actor_being_ref": _text(row["actor_being_ref"], code),
        "action": cast(str, row["action"]),
        "reason": _text(row["reason"], code, 128),
        "revoked_at_ms": _uint(row["revoked_at_ms"], code),
    }


def validate_relationship_event_payload(
    kind: str,
    payload: Any,
    *,
    author_being_ref: str,
    causal_parents: list[str] | tuple[str, ...],
) -> dict[str, Any]:
    """Validate one closed relationship event and its author/reference boundary."""

    # Cross-being action references are content-bound in the payload and are
    # completed by the multi-being relationship store. They are deliberately
    # not forced into one being's local ``causal_parents`` ledger namespace.
    del causal_parents
    if kind not in RELATIONSHIP_EVENT_KINDS:
        raise RelationshipError("unsupported_relationship_event_kind")
    author = _text(author_being_ref, "invalid_relationship_author")
    validators: dict[str, Callable[[Any], dict[str, Any]]] = {
        "matrix/relationship-card": _card_payload,
        "matrix/relationship-offer": _offer_payload,
        "matrix/relationship-acceptance": _acceptance_payload,
        "matrix/relationship-close": _close_payload,
        "matrix/tribe-declaration": _declaration_payload,
        "matrix/tribe-invitation": _invitation_payload,
        "matrix/tribe-membership-acceptance": _membership_acceptance_payload,
        "matrix/tribe-membership-leave": lambda value: _membership_terminal_payload(
            value, expulsion=False
        ),
        "matrix/tribe-membership-expulsion": lambda value: _membership_terminal_payload(
            value, expulsion=True
        ),
        "matrix/tribe-founder-transfer": _founder_transfer_payload,
        "matrix/tribe-founder-acceptance": _founder_acceptance_payload,
        "matrix/relationship-grant": _grant_payload,
        "matrix/relationship-grant-acceptance": _grant_acceptance_payload,
        "matrix/relationship-grant-revocation": _grant_revocation_payload,
    }
    result = validators[kind](payload)
    author_field = {
        "matrix/relationship-card": "being_ref",
        "matrix/relationship-offer": "initiator_being_ref",
        "matrix/relationship-acceptance": "responder_being_ref",
        "matrix/relationship-close": "closer_being_ref",
        "matrix/tribe-declaration": None,
        "matrix/tribe-invitation": "founder_being_ref",
        "matrix/tribe-membership-acceptance": "invitee_being_ref",
        "matrix/tribe-membership-leave": "member_being_ref",
        "matrix/tribe-membership-expulsion": "founder_being_ref",
        "matrix/tribe-founder-transfer": "old_founder_being_ref",
        "matrix/tribe-founder-acceptance": "successor_being_ref",
        "matrix/relationship-grant": "grantor_being_ref",
        "matrix/relationship-grant-acceptance": "subject_being_ref",
        "matrix/relationship-grant-revocation": "actor_being_ref",
    }[kind]
    expected_author = (
        result["declaration"]["founder_principal_id"]
        if author_field is None
        else result[author_field]
    )
    if author != expected_author:
        raise RelationshipError("relationship_event_author_mismatch")
    return result


def relationship_event_subject(kind: str, payload: Mapping[str, Any]) -> str:
    """Return the one stable ledger subject for a validated relationship event."""

    if kind == "matrix/relationship-card":
        return cast(str, payload["card_series_id"])
    if kind.startswith("matrix/tribe-"):
        return cast(str, payload["tribe_ref"])
    if kind.startswith("matrix/relationship-grant"):
        return cast(str, payload["grant_id"])
    return cast(str, payload["relationship_id"])


def relationship_event_occurred_at(kind: str, payload: Mapping[str, Any]) -> int:
    """Return the payload timestamp that must equal the signed event time."""

    field = {
        "matrix/relationship-card": "issued_at_ms",
        "matrix/relationship-offer": "issued_at_ms",
        "matrix/relationship-acceptance": "accepted_at_ms",
        "matrix/relationship-close": "closed_at_ms",
        "matrix/tribe-declaration": None,
        "matrix/tribe-invitation": "issued_at_ms",
        "matrix/tribe-membership-acceptance": "accepted_at_ms",
        "matrix/tribe-membership-leave": "terminated_at_ms",
        "matrix/tribe-membership-expulsion": "terminated_at_ms",
        "matrix/tribe-founder-transfer": "issued_at_ms",
        "matrix/tribe-founder-acceptance": "accepted_at_ms",
        "matrix/relationship-grant": "issued_at_ms",
        "matrix/relationship-grant-acceptance": "accepted_at_ms",
        "matrix/relationship-grant-revocation": "revoked_at_ms",
    }.get(kind)
    if kind not in RELATIONSHIP_EVENT_KINDS:
        raise RelationshipError("unsupported_relationship_event_kind")
    value = payload["declaration"]["created_at_ms"] if field is None else payload[field]
    return _uint(value, "invalid_relationship_event_time")


__all__ = [
    "ACCEPTANCE_SCHEMA",
    "CARD_SCHEMA",
    "CLOSE_SCHEMA",
    "DECLARATION_SCHEMA",
    "FOUNDER_ACCEPTANCE_SCHEMA",
    "FOUNDER_TRANSFER_SCHEMA",
    "GRANT_ACCEPTANCE_SCHEMA",
    "GRANT_REVOCATION_SCHEMA",
    "GRANT_SCHEMA",
    "INVITATION_SCHEMA",
    "MEMBERSHIP_ACCEPTANCE_SCHEMA",
    "MEMBERSHIP_EXPULSION_SCHEMA",
    "MEMBERSHIP_LEAVE_SCHEMA",
    "OFFER_SCHEMA",
    "RELATIONSHIP_EVENT_KINDS",
    "RESOURCE_SCHEMA",
    "TRIBE_SNAPSHOT_SCHEMA",
    "RelationshipError",
    "SnapshotVerifier",
    "VerifiedTribeSnapshot",
    "card_series_id",
    "founder_transfer_id",
    "grant_id",
    "invitation_id",
    "relationship_event_occurred_at",
    "relationship_event_subject",
    "relationship_id",
    "resource_ref",
    "tribe_ref",
    "validate_relationship_event_payload",
    "validate_resource_descriptor",
]
