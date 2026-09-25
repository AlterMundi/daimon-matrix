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

import copy
import hashlib
import uuid
from collections.abc import Mapping, Sequence
from typing import Any, Final

from .canonical import b64url, canonical_bytes, unb64url
from .communication import _message_payload, _resolution_payload
from .ledger import Clock, Ledger, LedgerError
from .sealed import (
    DeliveryCustody,
    DisclosureAuthorization,
    RecipientTarget,
    SealedDeliveryError,
    _parse,
    open_event,
    recipient_descriptor,
    seal_event,
    sender_descriptor,
)
from .weave import EventSigner, RootAuthority, WeaveProtocolError, verify_event

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


def _uint(value: Any, code: str) -> int:
    if type(value) is not int or value < 0:
        raise WeLaneError(code)
    return value


def _recipient_sort_key(row: Mapping[str, Any]) -> tuple[str, str, str]:
    return (
        str(row["being_ref"]),
        str(row["embodiment_id"]),
        str(row["encryption_kid"]),
    )


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


WE_CONVERSATION_SCHEMA: Final = "dm.we.conversation/v1"
WE_RECEIPT_SCHEMA: Final = "dm.communication.receipt/v2"
_ENVELOPE_FIELDS: Final = frozenset(
    {
        "schema",
        "profile",
        "delivery_id",
        "event_id",
        "event_hash",
        "sensitivity",
        "authorization_id",
        "evidence_hash",
        "sender",
        "recipients",
        "issued_at_ms",
        "expires_at_ms",
        "signature",
    }
)


def we_conversation_payload(
    *, envelope: bytes, resolution: Mapping[str, Any]
) -> dict[str, Any]:
    """One peer payload: the sealed message plus the audience it was frozen for.

    The resolution travels outside the envelope on purpose. It is a signed event,
    so the receiver authenticates the frozen audience before decrypting anything,
    and the envelope's evidence hash must equal its content hash.
    """
    return {
        "envelope": b64url(envelope),
        "resolution": copy.deepcopy(dict(resolution)),
        "schema": WE_CONVERSATION_SCHEMA,
    }


def open_we_conversation(
    payload: Mapping[str, Any],
    *,
    authority: RootAuthority,
    local_credential_id: str,
    custody: DeliveryCustody,
    at_ms: int,
) -> dict[str, Any]:
    """Authenticate, authorize and decrypt one intra-being message.

    The receiver re-derives the disclosure authorization itself. Sender and the
    whole audience come from the signed resolution and this being's own root
    manifest, never from the wire, so a tampered recipient list cannot redirect
    or widen who hears; only the identity of the still-encrypted message event is
    read from the envelope header, and the opened event must verify against the
    root and match that identity. A resolution that does not verify, an evidence
    hash that does not bind it, an audience that excludes the local embodiment, a
    message addressed to nobody inside that audience, or a sender that is not an
    active sibling all fail closed.
    """
    if not isinstance(payload, Mapping) or set(payload) != {
        "envelope",
        "resolution",
        "schema",
    }:
        raise WeLaneError("we_lane_payload_invalid")
    if payload["schema"] != WE_CONVERSATION_SCHEMA:
        raise WeLaneError("we_lane_payload_invalid")
    raw = unb64url(
        _text(payload["envelope"], "we_lane_envelope_invalid", maximum=1 << 22)
    )
    envelope = _closed_envelope(_parse(raw))
    resolution = verify_event(payload["resolution"], authority)
    message_id = _text(envelope["event_id"], "we_lane_message_invalid", maximum=64)
    _resolution_payload(resolution, message_id=message_id, scope=WE_LANE_SCOPE)
    if envelope["evidence_hash"] != resolution["content_hash"]:
        raise WeLaneError("we_lane_evidence_unbound")
    sender_embodiment = _text(
        resolution["origin"]["embodiment_id"], "we_lane_origin_invalid"
    )
    audience = we_audience(
        resolution, message_id=message_id, local_embodiment_id=sender_embodiment
    )
    local_embodiment = _local_embodiment(authority, local_credential_id)
    if local_embodiment == sender_embodiment:
        raise WeLaneError("we_lane_sender_is_local")
    targets = we_recipient_targets(authority, audience)
    authorized_at_ms = _uint(resolution["occurred_at_ms"], "we_lane_resolution_invalid")
    try:
        authorization = DisclosureAuthorization.synthetic(
            event={
                "content_hash": envelope["event_hash"],
                "event_id": envelope["event_id"],
                "sensitivity": envelope["sensitivity"],
            },
            sender=sender_descriptor(resolution, authority, at_ms=authorized_at_ms),
            recipients=sorted(
                (
                    recipient_descriptor(target, at_ms=authorized_at_ms)
                    for target in targets
                ),
                key=_recipient_sort_key,
            ),
            evidence_hash=resolution["content_hash"],
            authorized_at_ms=authorized_at_ms,
            expires_at_ms=envelope["expires_at_ms"],
            authorization_id=envelope["authorization_id"],
        )
    except SealedDeliveryError as exception:
        raise WeLaneError("we_lane_authorization_rejected") from exception
    message = open_event(
        raw,
        sender_authority=authority,
        local_target=RecipientTarget(authority, local_credential_id),
        recipient_targets=targets,
        authorization=authorization,
        custody=custody,
        at_ms=at_ms,
    )
    body = _message_payload(message)["body"]
    addressees = body.get("addressee")
    if not isinstance(addressees, list) or not addressees:
        raise WeLaneError("we_lane_addressee_empty")
    known = {row["recipient_id"] for row in audience}
    if local_embodiment not in known:
        raise WeLaneError("we_lane_not_in_audience")
    validated = we_addressees(audience, [str(row) for row in addressees])
    if message["origin"]["embodiment_id"] != sender_embodiment:
        raise WeLaneError("we_lane_origin_invalid")
    return {
        "addressees": validated,
        "audience": audience,
        "authorization": authorization,
        "message": message,
        "resolution": resolution,
    }


def we_receipt_payload(
    *,
    message: Mapping[str, Any],
    resolution: Mapping[str, Any],
    local_embodiment_id: str,
    observed_at_ms: int,
) -> dict[str, Any]:
    """One recipient-authored intake receipt for the embodiment that heard it."""
    thread_id = _message_payload(message)["intent"]["thread_id"]
    return {
        "message_being_ref": message["being_ref"],
        "message_ref": {
            "event_hash": message["content_hash"],
            "event_id": message["event_id"],
        },
        "observed_at_ms": observed_at_ms,
        "outcome": "delivered",
        "recipient_id": _text(local_embodiment_id, "we_lane_origin_invalid"),
        "recipient_type": "embodiment",
        "resolution_ref": {
            "event_hash": resolution["content_hash"],
            "event_id": resolution["event_id"],
        },
        "schema": WE_RECEIPT_SCHEMA,
        "thread_id": _text(thread_id, "we_lane_thread_invalid", maximum=64),
    }


def _closed_envelope(envelope: Mapping[str, Any]) -> Mapping[str, Any]:
    if not isinstance(envelope, Mapping) or not set(envelope) >= _ENVELOPE_FIELDS:
        raise WeLaneError("we_lane_envelope_invalid")
    for name in (
        "event_id",
        "event_hash",
        "sensitivity",
        "authorization_id",
        "evidence_hash",
    ):
        _text(envelope[name], "we_lane_envelope_invalid", maximum=256)
    for name in ("issued_at_ms", "expires_at_ms"):
        if type(envelope[name]) is not int or envelope[name] < 0:
            raise WeLaneError("we_lane_envelope_invalid")
    if not isinstance(envelope["sender"], Mapping) or not isinstance(
        envelope["recipients"], list
    ):
        raise WeLaneError("we_lane_envelope_invalid")
    return envelope


WE_RECEIPT_CLIENT_ID: Final = "dm.we.receipt/v1"
WE_INTAKE_SCHEMA: Final = "dm.we.intake-result/v1"


class WeConversation:
    """One being's intra-being conversation over its own ledger.

    Authority is root-validated same-being membership, so intake never consults a
    relationship, a tribe or a grant. Nothing here runs by itself: the lane
    installs no timer, poll or wakeup, and hearing a message never authorizes
    answering it.
    """

    def __init__(
        self,
        ledger: Ledger,
        *,
        signer: EventSigner,
        custody: DeliveryCustody,
        clock: Clock,
    ) -> None:
        authority = ledger.authority
        if (
            not isinstance(authority, RootAuthority)
            or authority.manifest.trust_mode != "root-bound"
        ):
            raise WeLaneError("we_lane_requires_root_authority")
        self.ledger = ledger
        self.authority = authority
        self.signer = signer
        self.custody = custody
        self.clock = clock
        self.local_embodiment_id = _text(
            ledger.local_origin["embodiment_id"], "we_lane_origin_invalid"
        )
        rows = [
            row
            for row in authority.manifest.value["embodiments"]
            if row["embodiment_id"] == self.local_embodiment_id
            and row["status"] == "active"
        ]
        if len(rows) != 1:
            raise WeLaneError("we_lane_embodiment_not_active")
        self.local_credential_id = _text(
            rows[0]["embodiment_credential_id"], "we_lane_credential_invalid"
        )
        ledger.initialize()

    def intake(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        """Open one delivered message, keep it, and author this body's receipt."""
        now = _uint(self.clock(), "we_lane_clock_invalid")
        opened = open_we_conversation(
            payload,
            authority=self.authority,
            local_credential_id=self.local_credential_id,
            custody=self.custody,
            at_ms=now,
        )
        message = opened["message"]
        sender = _text(message["origin"]["embodiment_id"], "we_lane_origin_invalid")
        if sender == self.local_embodiment_id:
            raise WeLaneError("we_lane_sender_is_local")
        self._retain((message, opened["resolution"]), source=f"we:{sender}")
        receipt = self._author_receipt(
            message, opened["resolution"], observed_at_ms=now
        )
        return {
            "schema": WE_INTAKE_SCHEMA,
            "message_id": message["event_id"],
            "message_hash": message["content_hash"],
            "receipt": copy.deepcopy(dict(receipt)),
            "receipt_hash": hashlib.sha256(canonical_bytes(receipt)).hexdigest(),
            "recipient_embodiment_id": self.local_embodiment_id,
        }

    def _retain(self, events: Sequence[Mapping[str, Any]], *, source: str) -> None:
        """Keep the message and its signed audience, once, in dependency order."""
        pending = [
            event
            for event in events
            if self.ledger.event(_text(event["event_id"], "we_lane_message_invalid"))
            is None
        ]
        if not pending:
            return
        try:
            self.ledger.ingest(pending, source=source)
        except (LedgerError, WeaveProtocolError) as exception:
            raise WeLaneError("we_lane_intake_rejected") from exception

    def _author_receipt(
        self,
        message: Mapping[str, Any],
        resolution: Mapping[str, Any],
        *,
        observed_at_ms: int,
    ) -> Mapping[str, Any]:
        """Sign this body's own receipt, so an exact retry returns the same one."""
        occurred = _uint(message["occurred_at_ms"], "we_lane_message_invalid")
        if observed_at_ms < occurred:
            raise WeLaneError("we_lane_observation_time_invalid")
        core = we_receipt_payload(
            message=message,
            resolution=resolution,
            local_embodiment_id=self.local_embodiment_id,
            observed_at_ms=observed_at_ms,
        )
        # The identity of a receipt must not depend on when the retry happened,
        # so the operation id and request hash cover everything but the instant.
        core.pop("observed_at_ms")
        digest = hashlib.sha256(canonical_bytes(core)).hexdigest()
        operation_id = str(
            uuid.uuid5(uuid.NAMESPACE_URL, f"{WE_RECEIPT_CLIENT_ID}:{digest}")
        )
        try:
            return self.ledger.append_local_idempotent(
                client_id=WE_RECEIPT_CLIENT_ID,
                request_id=operation_id,
                request_hash=digest,
                kind="experience.observed",
                subject="communication-receipt",
                payload={**core, "observed_at_ms": observed_at_ms},
                signer=self.signer,
                sensitivity=_text(
                    message["sensitivity"], "we_lane_message_invalid", maximum=32
                ),
                occurred_at_ms=observed_at_ms,
                causal_parents=(_text(message["event_id"], "we_lane_message_invalid"),),
            )
        except (LedgerError, WeaveProtocolError) as exception:
            raise WeLaneError("we_lane_receipt_rejected") from exception
