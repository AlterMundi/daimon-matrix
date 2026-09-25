"""One being's embodiments conversing with each other: the `/we` lane.

Authority here is root-validated same-being membership. A being has one will, so
there is no second consent to record: this lane never involves a relationship, a
tribe, a membership episode or a grant, and none may be synthesized to fill a
field. That is why `relationship_requires_distinct_beings` stays exactly as it is
while siblings still talk to each other.

Two ideas stay separate. The **audience** is every active embodiment of the being
except the sender, taken from one signed `/we` resolution, and it is who can
decrypt and hear. The **addressee** set is explicit, sorted, deduplicated and must
sit inside the audience; it is who the message is directed to. A reply names the
embodiment it answers, so an off-address answer is visible as such instead of being
silently ambiguous.

The lane is not a bypass of anything. Events are ordinary signed ledger events,
sealed per recipient with the existing root-bound delivery profile, and every
recipient authors its own receipt. What the lane does not do is post one being's
internal conversation to a shared human channel: the mandatory inter-daimon mirror
covers message, evidence, intake-result and route-submission egress, and this lane
is inventoried as intra-being in `docs/mandatory-telegram-visibility.md`.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Final

from .communication import _resolution_payload
from .sealed import (
    DeliveryCustody,
    DisclosureAuthorization,
    RecipientTarget,
    seal_event,
)
from .weave import RootAuthority

WE_LANE_SCOPE: Final = "/we"
WE_MESSAGE_CONTENT_TYPE: Final = "application/vnd.daimon.we-message+json"
WE_RECEIPT_CONTENT_TYPE: Final = "application/vnd.daimon.we-receipt+json"
MAX_ADDRESSEES: Final = 256
MAX_TEXT_BYTES: Final = 64 * 1024


class WeLaneError(ValueError):
    """Stable fail-closed error. The lane never guesses an audience or a target."""


def _text(value: Any, code: str, *, maximum: int = 240) -> str:
    if not isinstance(value, str) or not value or len(value.encode()) > maximum:
        raise WeLaneError(code)
    return value


def we_audience(
    resolution: Mapping[str, Any],
    *,
    message_id: str,
    local_embodiment_id: str,
) -> tuple[dict[str, Any], ...]:
    """Active sibling embodiments from one signed `/we` resolution.

    The sender is never a recipient of its own message; its siblings are ordinary
    recipients. An empty audience after excluding the sender fails closed rather
    than silently becoming a note to self, which belongs in the ledger lane.
    """
    local = _text(local_embodiment_id, "we_lane_origin_invalid")
    _payload, targets = _resolution_payload(
        resolution,
        message_id=_text(message_id, "we_lane_message_invalid"),
        scope=WE_LANE_SCOPE,
    )
    audience: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in targets:
        target = dict(raw)
        if (
            target.get("scope_kind") != "we"
            or target.get("recipient_type") != "embodiment"
            or target.get("recipient_id") != target.get("receipt_origin_embodiment_id")
        ):
            raise WeLaneError("we_lane_target_invalid")
        embodiment_id = _text(target["recipient_id"], "we_lane_target_invalid")
        if embodiment_id in seen:
            raise WeLaneError("we_lane_audience_duplicated")
        seen.add(embodiment_id)
        if embodiment_id != local:
            audience.append(target)
    if not audience:
        raise WeLaneError("we_lane_audience_empty")
    if len(audience) > MAX_ADDRESSEES:
        raise WeLaneError("we_lane_audience_too_large")
    return tuple(audience)


def we_addressees(
    audience: Sequence[Mapping[str, Any]], requested: Sequence[str]
) -> tuple[str, ...]:
    """Validate one explicit addressee set against the resolved audience."""
    known = {_text(row["recipient_id"], "we_lane_target_invalid") for row in audience}
    addressees = {_text(row, "we_lane_addressee_invalid") for row in requested}
    if not addressees:
        raise WeLaneError("we_lane_addressee_empty")
    if len(addressees) != len(requested):
        raise WeLaneError("we_lane_addressee_duplicated")
    if not addressees <= known:
        raise WeLaneError("we_lane_addressee_not_in_audience")
    if len(addressees) > MAX_ADDRESSEES:
        raise WeLaneError("we_lane_addressee_too_large")
    return tuple(sorted(addressees))


def we_message_body(text: str, addressees: Sequence[str]) -> dict[str, Any]:
    """One closed message body carrying content and its explicit addressees."""
    content = _text(text, "we_lane_text_invalid", maximum=MAX_TEXT_BYTES)
    if not isinstance(addressees, Sequence) or isinstance(addressees, (str, bytes)):
        raise WeLaneError("we_lane_addressee_invalid")
    return {"addressee": list(addressees), "text": content}


def we_recipient_targets(
    authority: RootAuthority, audience: Sequence[Mapping[str, Any]]
) -> tuple[RecipientTarget, ...]:
    """Resolve each audience embodiment to its own root-authorized credential."""
    targets: list[RecipientTarget] = []
    for row in audience:
        embodiment_id = _text(row["recipient_id"], "we_lane_target_invalid")
        active = [
            member
            for member in authority.manifest.value["embodiments"]
            if member["embodiment_id"] == embodiment_id and member["status"] == "active"
        ]
        if len(active) != 1:
            raise WeLaneError("we_lane_embodiment_not_active")
        credential_id = _text(
            active[0]["embodiment_credential_id"], "we_lane_credential_invalid"
        )
        if credential_id not in authority.credentials:
            raise WeLaneError("we_lane_credential_unknown")
        targets.append(RecipientTarget(authority, credential_id))
    if not targets:
        raise WeLaneError("we_lane_audience_empty")
    return tuple(targets)


def seal_we_message(
    message: Mapping[str, Any],
    resolution: Mapping[str, Any],
    *,
    authority: RootAuthority,
    recipient_targets: Sequence[RecipientTarget],
    custody: DeliveryCustody,
    issued_at_ms: int,
    expires_at_ms: int,
    authorization_id: str | None = None,
) -> bytes:
    """Seal one intra-being message to every audience embodiment in one envelope."""
    authorization = DisclosureAuthorization.from_resolution_event(
        event=message,
        resolution_event=resolution,
        authority=authority,
        expires_at_ms=expires_at_ms,
        authorization_id=authorization_id,
    )
    return seal_event(
        message,
        sender_authority=authority,
        recipients=list(recipient_targets),
        authorization=authorization,
        custody=custody,
        issued_at_ms=issued_at_ms,
        expires_at_ms=expires_at_ms,
    )


def _local_embodiment(authority: RootAuthority, credential_id: str) -> str:
    text = _text(credential_id, "we_lane_credential_invalid")
    for member in authority.manifest.value["embodiments"]:
        if member["embodiment_credential_id"] == text and member["status"] == "active":
            return str(member["embodiment_id"])
    raise WeLaneError("we_lane_credential_unknown")
