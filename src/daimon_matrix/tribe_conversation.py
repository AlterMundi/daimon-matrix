"""Tribe conversation authority: membership proofs from one being's own history.

Tribe conversation is authorized by active signed membership and by nothing else.
This module turns that membership into the closed proofs the membership sealing
profile consumes, derived from the being's own verified relationship history rather
than accepted as an assertion from a caller.

Three rules make it safe. A member the local history cannot prove is not in the
audience at all, because failing closed here is what keeps an unprovable key out of
an envelope. The member being is read from the signed event that established the
membership, and when that event names a being it must agree with the verified
snapshot, so a stale or doctored snapshot cannot redirect a proof. And nothing here
consults a grant, a resource or an operation: conversation is not disclosure.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any, Final

from .sealed import MEMBERSHIP_PROOF_SCHEMA

ACCEPTANCE_KIND: Final = "matrix/tribe-membership-acceptance"
DECLARATION_KIND: Final = "matrix/tribe-declaration"
FOUNDER_ACCEPTANCE_KIND: Final = "matrix/tribe-founder-acceptance"
EXPULSION_KIND: Final = "matrix/tribe-membership-expulsion"
LEAVE_KIND: Final = "matrix/tribe-membership-leave"

MEMBER_FIELDS: Final = frozenset(
    {"embodiment_id", "membership_ref", "principal_id", "state", "tribe_ref"}
)
# The signed event that establishes a membership, and the payload field naming the
# being it admits. A declaration has no such field: its author is the founder
# principal and the reducer keys membership by being ref.
MEMBERSHIP_EVENT_KINDS: Final = {
    ACCEPTANCE_KIND: "invitee_being_ref",
    FOUNDER_ACCEPTANCE_KIND: "successor_being_ref",
    DECLARATION_KIND: None,
}
_BEING_REF: Final = re.compile(r"^dm:being:v1:[A-Za-z0-9_-]{43}$")
_HEX64: Final = re.compile(r"^[0-9a-f]{64}$")


class TribeConversationError(ValueError):
    """Stable fail-closed error. Membership is proved from history, or absent."""


def _text(value: Any, code: str, *, maximum: int = 240) -> str:
    if not isinstance(value, str) or not value or len(value.encode()) > maximum:
        raise TribeConversationError(code)
    return value


def _closed(value: Any, fields: frozenset[str], code: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise TribeConversationError(code)
    return value


class MembershipAuthorizer:
    """Derive closed active-membership proofs from signed relationship history."""

    def __init__(self, events: Sequence[Mapping[str, Any]]) -> None:
        self._by_id: dict[str, Mapping[str, Any]] = {}
        for event in events:
            if not isinstance(event, Mapping):
                raise TribeConversationError("membership_history_invalid")
            event_id = event.get("event_id")
            if not isinstance(event_id, str) or not event_id:
                raise TribeConversationError("membership_history_invalid")
            if event_id in self._by_id:
                raise TribeConversationError("membership_history_duplicated")
            self._by_id[event_id] = event

    def proofs(
        self, *, members: Sequence[Mapping[str, Any]], tribe_ref: str
    ) -> dict[str, dict[str, Any]]:
        """One proof per active member of one exact tribe, or fail closed.

        Left and expelled members are skipped rather than proved, which is how a
        removal takes effect on the next send: their key is simply not in the
        audience, and nothing about earlier messages is rewritten.
        """
        tribe = _text(tribe_ref, "membership_tribe_ref_invalid")
        proofs: dict[str, dict[str, Any]] = {}
        for raw in members:
            member = _closed(raw, MEMBER_FIELDS, "tribe_member_invalid")
            if member["tribe_ref"] != tribe or member["state"] != "active":
                continue
            reference = _text(member["membership_ref"], "membership_ref_invalid")
            if reference in proofs:
                raise TribeConversationError("membership_proof_duplicated")
            proofs[reference] = self.proof(
                membership_ref=reference,
                tribe_ref=tribe,
                principal_id=_text(member["principal_id"], "tribe_member_invalid"),
            )
        if not proofs:
            raise TribeConversationError("tribe_audience_empty")
        return proofs

    def proof(
        self, *, membership_ref: str, tribe_ref: str, principal_id: str
    ) -> dict[str, Any]:
        """Prove one membership from the signed event that established it."""
        reference = _text(membership_ref, "membership_ref_invalid")
        tribe = _text(tribe_ref, "membership_tribe_ref_invalid")
        principal = _text(principal_id, "tribe_member_invalid")
        event = self._by_id.get(reference)
        if event is None:
            raise TribeConversationError("membership_proof_unavailable")
        kind = event.get("kind")
        payload = event.get("payload")
        content_hash = event.get("content_hash")
        if (
            kind not in MEMBERSHIP_EVENT_KINDS
            or not isinstance(payload, Mapping)
            or payload.get("tribe_ref") != tribe
            or not isinstance(content_hash, str)
            or _HEX64.fullmatch(content_hash) is None
        ):
            raise TribeConversationError("membership_proof_unavailable")
        field = MEMBERSHIP_EVENT_KINDS[kind]
        if field is None:
            # A declaration names no being ref. The reducer keys membership by
            # being ref and puts it in the snapshot's principal, so the principal
            # is accepted only when it is syntactically a being ref.
            if _BEING_REF.fullmatch(principal) is None:
                raise TribeConversationError("membership_being_ref_invalid")
            being_ref = principal
        else:
            being_ref = _text(
                payload.get(field), "membership_being_ref_invalid", maximum=240
            )
            if _BEING_REF.fullmatch(being_ref) is None or being_ref != principal:
                raise TribeConversationError("membership_proof_conflict")
        return {
            "active": True,
            "member_being_ref": being_ref,
            "membership_event_hash": content_hash,
            "membership_event_id": reference,
            "membership_ref": reference,
            "schema": MEMBERSHIP_PROOF_SCHEMA,
            "tribe_ref": tribe,
        }


__all__ = [
    "ACCEPTANCE_KIND",
    "DECLARATION_KIND",
    "EXPULSION_KIND",
    "FOUNDER_ACCEPTANCE_KIND",
    "LEAVE_KIND",
    "MEMBERSHIP_EVENT_KINDS",
    "MEMBER_FIELDS",
    "MembershipAuthorizer",
    "TribeConversationError",
]
