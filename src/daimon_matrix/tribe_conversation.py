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

import copy
import hashlib
import re
import uuid
from collections.abc import Callable, Mapping, Sequence
from typing import Any, Final

from .authority_epochs import RootHistoryAuthority
from .canonical import b64url, canonical_bytes, unb64url
from .communication import (
    MESSAGE_PAYLOAD_SCHEMA,
    RESOLUTION_PAYLOAD_SCHEMA,
    _message_payload,
    _resolution_payload,
)
from .ledger import Clock, Ledger, LedgerError
from .relationship_store import RelationshipStore, RelationshipStoreError
from .sealed import (
    MAX_RECIPIENTS as MAX_TRIBE_RECIPIENTS,
)
from .sealed import (
    MAX_TTL_MS as MAX_TRIBE_TTL_MS,
)
from .sealed import (
    MEMBERSHIP_PROOF_SCHEMA,
    TRIBE_SCOPE,
    DeliveryCustody,
    DisclosureAuthorization,
    RecipientTarget,
    SealedDeliveryError,
    _parse,
    open_event,
    seal_event,
)
from .weave import (
    Event,
    EventSigner,
    RootAuthority,
    WeaveProtocolError,
    verify_event,
)

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


def _text(value: Any, code: str, *, maximum: int = 240) -> str:
    if not isinstance(value, str) or not value or len(value.encode()) > maximum:
        raise TribeConversationError(code)
    return value


def _uint(value: Any, code: str) -> int:
    if type(value) is not int or value < 0:
        raise TribeConversationError(code)
    return value


def _uuid_text(value: Any, code: str) -> str:
    text = _text(value, code, maximum=36)
    try:
        parsed = uuid.UUID(text)
    except (ValueError, AttributeError) as exception:
        raise TribeConversationError(code) from exception
    if str(parsed) != text:
        raise TribeConversationError(code)
    return text


def _evidence_cursor(tribe_ref: str, row: Mapping[str, str]) -> str:
    """One deterministic cursor per (tribe, membership, receiving body)."""
    return "dm:scope-evidence:v1:" + b64url(
        hashlib.sha256(
            canonical_bytes(
                {
                    "embodiment_id": row["embodiment_id"],
                    "membership_ref": row["membership_ref"],
                    "scope": TRIBE_SCOPE,
                    "tribe_ref": tribe_ref,
                }
            )
        ).digest()
    )


def _closed_envelope(envelope: Mapping[str, Any]) -> Mapping[str, Any]:
    """Framing only. Authenticity is `open_event`'s job, never this one's."""
    if not isinstance(envelope, Mapping) or not set(envelope) >= _ENVELOPE_FIELDS:
        raise TribeConversationError("tribe_lane_envelope_invalid")
    for name in (
        "event_id",
        "event_hash",
        "sensitivity",
        "authorization_id",
        "evidence_hash",
    ):
        _text(envelope[name], "tribe_lane_envelope_invalid", maximum=256)
    for name in ("issued_at_ms", "expires_at_ms"):
        if type(envelope[name]) is not int or envelope[name] < 0:
            raise TribeConversationError("tribe_lane_envelope_invalid")
    if not isinstance(envelope["sender"], Mapping) or not isinstance(
        envelope["recipients"], list
    ):
        raise TribeConversationError("tribe_lane_envelope_invalid")
    return envelope


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


TRIBE_MESSAGE_CONTENT_TYPE: Final = "application/vnd.daimon.tribe-message+json"
TRIBE_RECEIPT_CONTENT_TYPE: Final = "application/vnd.daimon.tribe-receipt+json"
TRIBE_CONVERSATION_SCHEMA: Final = "dm.tribe.conversation/v1"
TRIBE_CONVERSE_RESULT_SCHEMA: Final = "dm.tribe.converse-result/v1"
TRIBE_INTAKE_SCHEMA: Final = "dm.tribe.intake-result/v1"
TRIBE_RECEIPT_SCHEMA: Final = "dm.communication.receipt/v2"
TRIBE_CLIENT_ID: Final = "dm.tribe.converse"
TRIBE_MESSAGE_CLIENT_ID: Final = "dm.tribe.message/v1"
TRIBE_RESOLUTION_CLIENT_ID: Final = "dm.tribe.resolution/v1"
TRIBE_RECEIPT_CLIENT_ID: Final = "dm.tribe.receipt/v2"
TRIBE_CONVERSE_OPERATION: Final = "tribe.converse"
TRIBE_MESSAGE_SUBJECT: Final = "communication"
TRIBE_RESOLUTION_SUBJECT: Final = "communication-resolution"
TRIBE_RECEIPT_SUBJECT: Final = "communication-receipt"
MAX_TRIBE_TEXT_BYTES: Final = 64 * 1024
DEFAULT_TRIBE_TTL_MS: Final = 10 * 60 * 1000

DeliverTribeConversation = Callable[[str, Mapping[str, Any]], Mapping[str, Any]]
"""Hand one sealed tribe conversation to a member body, return its intake."""


class TribeConversation:
    """One tribe's members conversing, authorized by membership alone.

    Foreign material never enters a local ledger. A message sealed by another being
    cannot verify against this being's root, so the lane opens it, returns it, and
    leaves retention to the host's own inbox and communication stores, exactly as
    the inter-daimon lane does. What this lane writes locally is one thing only:
    the receipt this body signed for what it heard.

    Authority is active signed membership in one exact tribe at send time plus a
    root-authorized credential for the event time. No grant, resource or operation
    is consulted here or may be synthesized to fill a field, and nothing this lane
    does widens resource authority.

    The audience is resolved when the message is sent, from the current verified
    membership snapshot, and frozen into the signed resolution. A member admitted
    afterwards is therefore in the next message's audience without anybody
    configuring anything, and a removed member simply is not in it. Every active
    embodiment of every active member is a recipient in its own right and authors
    its own receipt, so authorship inside the tribe stays visible per body.

    Nothing here runs by itself: no timer, no poll, no wakeup. Reading, sending and
    replying happen only when a human asks, and hearing a message never authorizes
    answering it.
    """

    def __init__(
        self,
        ledger: Ledger,
        *,
        signer: EventSigner,
        custody: DeliveryCustody,
        clock: Clock,
        relationships: RelationshipStore,
        card_verifier: Any,
        authority_resolver: Callable[[str], Any],
    ) -> None:
        history = ledger.authority
        authority = (
            history.active if isinstance(history, RootHistoryAuthority) else history
        )
        if (
            not isinstance(authority, RootAuthority)
            or authority.manifest.trust_mode != "root-bound"
        ):
            raise TribeConversationError("tribe_lane_requires_root_authority")
        self.ledger = ledger
        self.authority = authority
        self.signer = signer
        self.custody = custody
        self.clock = clock
        self.relationships = relationships
        self.card_verifier = card_verifier
        self.authority_resolver = authority_resolver
        self.being_ref = authority.manifest.being_ref
        self.local_embodiment_id = _text(
            ledger.local_origin["embodiment_id"], "tribe_lane_origin_invalid"
        )
        rows = [
            row
            for row in authority.manifest.value["embodiments"]
            if row["embodiment_id"] == self.local_embodiment_id
            and row["status"] == "active"
        ]
        if len(rows) != 1:
            raise TribeConversationError("tribe_lane_embodiment_not_active")
        self.local_credential_id = _text(
            rows[0]["embodiment_credential_id"], "tribe_lane_credential_invalid"
        )
        ledger.initialize()

    def _active(self, being_ref: str) -> RootAuthority:
        """Current epoch for one member being, whether or not history is supplied."""
        resolved = self.authority_resolver(
            _text(being_ref, "tribe_lane_authority_invalid")
        )
        authority = (
            resolved.active if isinstance(resolved, RootHistoryAuthority) else resolved
        )
        if not isinstance(authority, RootAuthority):
            raise TribeConversationError("tribe_lane_authority_invalid")
        return authority

    def snapshot(self, tribe_ref: str, at_ms: int) -> Any:
        """The verified membership snapshot this lane is allowed to act on."""
        tribe = _text(tribe_ref, "tribe_lane_tribe_ref_invalid")
        try:
            with self.relationships.authorization_view(
                at_ms=at_ms, card_verifier=self.card_verifier
            ) as view:
                return view.snapshot(tribe)
        except RelationshipStoreError as exception:
            raise TribeConversationError(
                "tribe_lane_snapshot_unavailable"
            ) from exception

    def audience(self, snapshot: Any) -> tuple[dict[str, str], ...]:
        """One row per active embodiment of every active member of the tribe."""
        rows: list[dict[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for member in snapshot.value["members"]:
            if member["state"] != "active":
                continue
            being_ref = _text(member["principal_id"], "tribe_lane_member_invalid")
            membership_ref = _text(
                member["membership_ref"], "tribe_lane_member_invalid"
            )
            for row in self._active(being_ref).manifest.value["embodiments"]:
                if row["status"] != "active":
                    continue
                embodiment_id = _text(row["embodiment_id"], "tribe_lane_member_invalid")
                marker = (membership_ref, embodiment_id)
                if marker in seen:
                    raise TribeConversationError("tribe_lane_audience_duplicated")
                seen.add(marker)
                rows.append(
                    {
                        "being_ref": being_ref,
                        "credential_id": _text(
                            row["embodiment_credential_id"],
                            "tribe_lane_credential_invalid",
                        ),
                        "embodiment_id": embodiment_id,
                        "membership_ref": membership_ref,
                    }
                )
        if not rows:
            raise TribeConversationError("tribe_lane_audience_empty")
        if len(rows) > MAX_TRIBE_RECIPIENTS:
            raise TribeConversationError("tribe_lane_audience_too_large")
        return tuple(sorted(rows, key=lambda item: tuple(sorted(item.values()))))

    def converse(
        self,
        *,
        text: str,
        request_id: str,
        tribe_ref: str,
        thread_id: str | None = None,
        sensitivity: str = "personal",
        ttl_ms: int = DEFAULT_TRIBE_TTL_MS,
        deliver: DeliverTribeConversation | None = None,
    ) -> dict[str, Any]:
        """Author, seal and hand over one message to the whole tribe.

        One message is one signed event in one envelope with one wrapped key per
        member body. Authoring is idempotent under the caller's request id, so an
        exact retry says the same thing once; byte-exact transport retry belongs to
        the carrier's own outbox, not here.
        """
        now = _uint(self.clock(), "tribe_lane_clock_invalid")
        request = _uuid_text(request_id, "tribe_lane_request_invalid")
        ttl = _uint(ttl_ms, "tribe_lane_ttl_invalid")
        if not 0 < ttl <= MAX_TRIBE_TTL_MS:
            raise TribeConversationError("tribe_lane_ttl_invalid")
        tribe = _text(tribe_ref, "tribe_lane_tribe_ref_invalid")
        content = _text(text, "tribe_lane_text_invalid", maximum=MAX_TRIBE_TEXT_BYTES)
        classification = _text(
            sensitivity, "tribe_lane_sensitivity_invalid", maximum=32
        )
        if classification not in {"personal", "private", "shareable"}:
            raise TribeConversationError("tribe_lane_sensitivity_invalid")
        thread = (
            _uuid_text(thread_id, "tribe_lane_thread_invalid")
            if thread_id is not None
            else str(
                uuid.uuid5(uuid.NAMESPACE_URL, f"{TRIBE_CLIENT_ID}:thread:{request}")
            )
        )
        snapshot = self.snapshot(tribe, now)
        members = list(snapshot.value["members"])
        rows = self.audience(snapshot)
        own = [row for row in members if row["principal_id"] == self.being_ref]
        if len(own) != 1 or own[0]["state"] != "active":
            raise TribeConversationError("tribe_lane_not_a_member")
        authorizer = MembershipAuthorizer(self.relationships.events())
        proofs = authorizer.proofs(members=members, tribe_ref=tribe)
        sender_proof = authorizer.proof(
            membership_ref=_text(own[0]["membership_ref"], "tribe_lane_member_invalid"),
            tribe_ref=tribe,
            principal_id=self.being_ref,
        )
        targets = [
            {
                "evidence_cursor": _evidence_cursor(tribe, row),
                "receipt_origin_embodiment_id": row["embodiment_id"],
                "recipient_id": row["membership_ref"],
                "recipient_type": "relationship",
                "scope_kind": "relationship",
            }
            for row in rows
        ]
        message = self._author(
            client_id=TRIBE_MESSAGE_CLIENT_ID,
            request_id=request,
            subject=TRIBE_MESSAGE_SUBJECT,
            payload={
                "body": {"text": content},
                "intent": {
                    "operation": TRIBE_CONVERSE_OPERATION,
                    "scope": TRIBE_SCOPE,
                    "thread_id": thread,
                },
                "reply": None,
                "schema": MESSAGE_PAYLOAD_SCHEMA,
            },
            sensitivity=classification,
            occurred_at_ms=now,
            causal_parents=(),
        )
        message_id = _text(
            message["event_id"], "tribe_lane_message_invalid", maximum=64
        )
        resolution = self._author(
            client_id=TRIBE_RESOLUTION_CLIENT_ID,
            request_id=request,
            subject=TRIBE_RESOLUTION_SUBJECT,
            payload={
                "message_id": message_id,
                "schema": RESOLUTION_PAYLOAD_SCHEMA,
                "scope": TRIBE_SCOPE,
                "targets": targets,
            },
            sensitivity="shareable",
            occurred_at_ms=now,
            causal_parents=(message_id,),
        )
        recipient_targets = [
            RecipientTarget(self._active(row["being_ref"]), row["credential_id"])
            for row in rows
        ]
        authorization = self._authorize(
            message,
            resolution,
            tribe_ref=tribe,
            proofs=proofs,
            sender_proof=sender_proof,
            recipient_targets=recipient_targets,
            expires_at_ms=now + ttl,
        )
        envelope = seal_event(
            message,
            sender_authority=self.authority,
            recipients=recipient_targets,
            authorization=authorization,
            custody=self.custody,
            issued_at_ms=now,
            expires_at_ms=now + ttl,
        )
        payload = tribe_conversation_payload(
            envelope=envelope, resolution=resolution, tribe_ref=tribe
        )
        deliveries: list[dict[str, Any]] = []
        for row in rows:
            if row["being_ref"] == self.being_ref:
                # The author is inside the sealed carrier set and still does not
                # intake its own message: hearing only yourself is a ledger note.
                deliveries.append(
                    {"embodiment_id": row["embodiment_id"], "state": "author"}
                )
                continue
            if deliver is None:
                deliveries.append(
                    {"embodiment_id": row["embodiment_id"], "state": "sealed"}
                )
                continue
            receipt = self._accept_member_receipt(
                deliver(row["embodiment_id"], payload),
                row=row,
                message=message,
                resolution=resolution,
            )
            deliveries.append(
                {
                    "embodiment_id": row["embodiment_id"],
                    "membership_ref": row["membership_ref"],
                    "receipt": copy.deepcopy(dict(receipt)),
                    "receipt_event_id": receipt["event_id"],
                    "state": "delivered",
                }
            )
        return {
            "audience": [
                {
                    "embodiment_id": row["embodiment_id"],
                    "membership_ref": row["membership_ref"],
                }
                for row in rows
            ],
            "deliveries": deliveries,
            "message_hash": message["content_hash"],
            "message_id": message_id,
            "resolution_id": resolution["event_id"],
            "schema": TRIBE_CONVERSE_RESULT_SCHEMA,
            "thread_id": thread,
            "tribe_ref": tribe,
        }

    def _authorize(
        self,
        message: Mapping[str, Any],
        resolution: Mapping[str, Any],
        *,
        tribe_ref: str,
        proofs: Mapping[str, Mapping[str, Any]],
        sender_proof: Mapping[str, Any],
        recipient_targets: Sequence[RecipientTarget],
        expires_at_ms: int,
    ) -> DisclosureAuthorization:
        try:
            return DisclosureAuthorization.from_membership_resolution_event(
                event=message,
                resolution_event=resolution,
                sender_authority=self.authority,
                recipient_targets=recipient_targets,
                memberships=proofs,
                sender_membership=sender_proof,
                tribe_ref=tribe_ref,
                expires_at_ms=expires_at_ms,
            )
        except SealedDeliveryError as exception:
            raise TribeConversationError(
                "tribe_lane_authorization_rejected"
            ) from exception

    def _author(
        self,
        *,
        client_id: str,
        request_id: str,
        subject: str,
        payload: Mapping[str, Any],
        sensitivity: str,
        occurred_at_ms: int,
        causal_parents: Sequence[str],
    ) -> Event:
        """Author one ledger event, or return the one an earlier attempt made."""
        digest = hashlib.sha256(canonical_bytes(payload)).hexdigest()
        operation_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"{client_id}:{request_id}"))
        try:
            return self.ledger.append_local_idempotent(
                client_id=client_id,
                request_id=operation_id,
                request_hash=digest,
                kind="experience.observed",
                subject=subject,
                payload=payload,
                signer=self.signer,
                sensitivity=sensitivity,
                occurred_at_ms=occurred_at_ms,
                causal_parents=causal_parents,
            )
        except (LedgerError, WeaveProtocolError) as exception:
            raise TribeConversationError("tribe_lane_authoring_rejected") from exception

    def _accept_member_receipt(
        self,
        result: Any,
        *,
        row: Mapping[str, str],
        message: Mapping[str, Any],
        resolution: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        """Bind one returned intake result to this message and this member body."""
        if not isinstance(result, Mapping) or set(result) != {
            "membership_ref",
            "message_hash",
            "message_id",
            "receipt",
            "receipt_hash",
            "recipient_embodiment_id",
            "schema",
            "tribe_ref",
        }:
            raise TribeConversationError("tribe_lane_intake_result_invalid")
        receipt = result["receipt"]
        if (
            result["schema"] != TRIBE_INTAKE_SCHEMA
            or result["message_id"] != message["event_id"]
            or result["message_hash"] != message["content_hash"]
            or result["recipient_embodiment_id"] != row["embodiment_id"]
            or result["membership_ref"] != row["membership_ref"]
            or not isinstance(receipt, Mapping)
            or result["receipt_hash"]
            != hashlib.sha256(canonical_bytes(receipt)).hexdigest()
        ):
            raise TribeConversationError("tribe_lane_intake_result_invalid")
        origin = receipt.get("origin")
        payload = receipt.get("payload")
        if (
            receipt.get("kind") != "experience.observed"
            or receipt.get("subject") != TRIBE_RECEIPT_SUBJECT
            or not isinstance(origin, Mapping)
            or origin.get("embodiment_id") != row["embodiment_id"]
            or not isinstance(payload, Mapping)
            or payload.get("schema") != TRIBE_RECEIPT_SCHEMA
            or payload.get("recipient_type") != "relationship"
            or payload.get("recipient_id") != row["membership_ref"]
            or payload.get("outcome") != "delivered"
        ):
            raise TribeConversationError("tribe_lane_intake_result_invalid")
        # A foreign receipt must be signed by the member's own authority, so the
        # sender cannot accept a receipt nobody authored.
        try:
            verify_event(receipt, self._active(str(row["being_ref"])))
        except WeaveProtocolError as exception:
            raise TribeConversationError("tribe_lane_receipt_unverified") from exception
        return receipt

    def intake(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        """Open one delivered tribe message and author this body's own receipt.

        The authorization is re-derived here from this being's own verified snapshot
        and signed membership history, never copied from the wire, so an envelope
        cannot name an audience this member does not independently agree with.
        """
        if not isinstance(payload, Mapping) or set(payload) != {
            "envelope",
            "resolution",
            "schema",
            "tribe_ref",
        }:
            raise TribeConversationError("tribe_lane_payload_invalid")
        if payload["schema"] != TRIBE_CONVERSATION_SCHEMA:
            raise TribeConversationError("tribe_lane_payload_invalid")
        now = _uint(self.clock(), "tribe_lane_clock_invalid")
        tribe = _text(payload["tribe_ref"], "tribe_lane_tribe_ref_invalid")
        raw = unb64url(
            _text(payload["envelope"], "tribe_lane_envelope_invalid", maximum=1 << 22)
        )
        envelope = _closed_envelope(_parse(raw))
        sender_being = _text(
            envelope["sender"]["being_ref"], "tribe_lane_sender_invalid"
        )
        if sender_being == self.being_ref:
            raise TribeConversationError("tribe_lane_sender_is_local")
        sender_authority = self._active(sender_being)
        try:
            resolution = verify_event(payload["resolution"], sender_authority)
        except WeaveProtocolError as exception:
            raise TribeConversationError(
                "tribe_lane_resolution_unverified"
            ) from exception
        message_id = _text(
            envelope["event_id"], "tribe_lane_message_invalid", maximum=64
        )
        _resolution_payload(resolution, message_id=message_id, scope=TRIBE_SCOPE)
        snapshot = self.snapshot(tribe, now)
        members = list(snapshot.value["members"])
        rows = self.audience(snapshot)
        local = [
            row
            for row in rows
            if row["embodiment_id"] == self.local_embodiment_id
            and row["being_ref"] == self.being_ref
        ]
        if len(local) != 1:
            raise TribeConversationError("tribe_lane_not_in_audience")
        authorizer = MembershipAuthorizer(self.relationships.events())
        proofs = authorizer.proofs(members=members, tribe_ref=tribe)
        own = [row for row in members if row["principal_id"] == self.being_ref]
        if len(own) != 1 or own[0]["state"] != "active":
            raise TribeConversationError("tribe_lane_not_a_member")
        # The author's proof is the author's own membership, not this body's: a
        # receiver that substituted its membership for the sender's would be
        # reconstructing an authorization for a different conversation.
        sender_rows = [row for row in members if row["principal_id"] == sender_being]
        if len(sender_rows) != 1 or sender_rows[0]["state"] != "active":
            raise TribeConversationError("tribe_lane_sender_not_a_member")
        sender_proof = authorizer.proof(
            membership_ref=_text(
                sender_rows[0]["membership_ref"], "tribe_lane_member_invalid"
            ),
            tribe_ref=tribe,
            principal_id=sender_being,
        )
        recipient_targets = [
            RecipientTarget(self._active(row["being_ref"]), row["credential_id"])
            for row in rows
        ]
        authorization = DisclosureAuthorization.from_membership_resolution_identity(
            message_id=message_id,
            message_hash=str(envelope["event_hash"]),
            sensitivity=str(envelope["sensitivity"]),
            resolution_event=resolution,
            sender_authority=sender_authority,
            recipient_targets=recipient_targets,
            memberships=proofs,
            sender_membership=sender_proof,
            tribe_ref=tribe,
            expires_at_ms=_uint(
                envelope["expires_at_ms"], "tribe_lane_envelope_invalid"
            ),
            authorization_id=str(envelope["authorization_id"]),
        )
        try:
            message = open_event(
                raw,
                sender_authority=sender_authority,
                local_target=RecipientTarget(self.authority, self.local_credential_id),
                recipient_targets=recipient_targets,
                authorization=authorization,
                custody=self.custody,
                at_ms=now,
            )
        except SealedDeliveryError as exception:
            raise TribeConversationError("tribe_lane_delivery_rejected") from exception
        if _message_payload(message)["reply"] is not None:
            raise TribeConversationError("tribe_lane_reply_forbidden")
        sender_row = next(
            (
                row
                for row in rows
                if row["embodiment_id"] == message["origin"]["embodiment_id"]
            ),
            None,
        )
        if sender_row is None or sender_row["being_ref"] != sender_being:
            raise TribeConversationError("tribe_lane_origin_invalid")
        receipt = self._author_receipt(
            message, resolution, membership_ref=local[0]["membership_ref"], now=now
        )
        return {
            "membership_ref": local[0]["membership_ref"],
            "message_hash": message["content_hash"],
            "message_id": message["event_id"],
            "receipt": copy.deepcopy(dict(receipt)),
            "receipt_hash": hashlib.sha256(canonical_bytes(receipt)).hexdigest(),
            "recipient_embodiment_id": self.local_embodiment_id,
            "schema": TRIBE_INTAKE_SCHEMA,
            "tribe_ref": tribe,
        }

    def _author_receipt(
        self,
        message: Mapping[str, Any],
        resolution: Mapping[str, Any],
        *,
        membership_ref: str,
        now: int,
    ) -> Event:
        """Sign this body's own receipt for the message it just heard."""
        occurred = _uint(message["occurred_at_ms"], "tribe_lane_message_invalid")
        if now < occurred:
            raise TribeConversationError("tribe_lane_observation_time_invalid")
        core = tribe_receipt_payload(
            message=message,
            resolution=resolution,
            membership_ref=membership_ref,
            observed_at_ms=now,
        )
        # Identity must not depend on when a retry happened, so the operation id and
        # request hash cover everything but the instant observed.
        core.pop("observed_at_ms")
        digest = hashlib.sha256(canonical_bytes(core)).hexdigest()
        operation_id = str(
            uuid.uuid5(uuid.NAMESPACE_URL, f"{TRIBE_RECEIPT_CLIENT_ID}:{digest}")
        )
        try:
            return self.ledger.append_local_idempotent(
                client_id=TRIBE_RECEIPT_CLIENT_ID,
                request_id=operation_id,
                request_hash=digest,
                kind="experience.observed",
                subject=TRIBE_RECEIPT_SUBJECT,
                payload={**core, "observed_at_ms": now},
                signer=self.signer,
                sensitivity=_text(
                    message["sensitivity"], "tribe_lane_message_invalid", maximum=32
                ),
                occurred_at_ms=now,
                causal_parents=(),
            )
        except (LedgerError, WeaveProtocolError) as exception:
            raise TribeConversationError("tribe_lane_receipt_rejected") from exception


def tribe_conversation_payload(
    *, envelope: bytes, resolution: Mapping[str, Any], tribe_ref: str
) -> dict[str, Any]:
    """One carrier payload: the sealed message, its frozen audience, and the tribe.

    The resolution travels outside the envelope on purpose. It is a signed event, so
    the receiver authenticates the frozen audience before decrypting anything. The
    tribe ref travels with it and is bound, not trusted: it feeds the evidence hash
    the receiver recomputes and compares against the envelope's, so renaming the
    tribe in transit breaks that comparison instead of redirecting the message.
    """
    return {
        "envelope": b64url(envelope),
        "resolution": copy.deepcopy(dict(resolution)),
        "schema": TRIBE_CONVERSATION_SCHEMA,
        "tribe_ref": _text(tribe_ref, "tribe_lane_tribe_ref_invalid"),
    }


def tribe_receipt_payload(
    *,
    message: Mapping[str, Any],
    resolution: Mapping[str, Any],
    membership_ref: str,
    observed_at_ms: int,
) -> dict[str, Any]:
    """One member-authored receipt, in the foreign shape the sender can record."""
    return {
        "message_being_ref": _text(message["being_ref"], "tribe_lane_message_invalid"),
        "message_ref": {
            "event_hash": _text(
                message["content_hash"], "tribe_lane_message_invalid", maximum=64
            ),
            "event_id": _text(
                message["event_id"], "tribe_lane_message_invalid", maximum=64
            ),
        },
        "observed_at_ms": _uint(observed_at_ms, "tribe_lane_observation_time_invalid"),
        "outcome": "delivered",
        "recipient_id": _text(membership_ref, "tribe_lane_member_invalid"),
        "recipient_type": "relationship",
        "resolution_ref": {
            "event_hash": _text(
                resolution["content_hash"], "tribe_lane_resolution_invalid", maximum=64
            ),
            "event_id": _text(
                resolution["event_id"], "tribe_lane_resolution_invalid", maximum=64
            ),
        },
        "schema": TRIBE_RECEIPT_SCHEMA,
        "thread_id": _uuid_text(
            _message_payload(message)["intent"]["thread_id"],
            "tribe_lane_thread_invalid",
        ),
    }
