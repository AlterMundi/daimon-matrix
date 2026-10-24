"""Authenticated directed evidence and membership-based group messages.

Foreign events never enter a Ledger. Explicit application V2 replies author
recipient-local receipts and carry sparse signed proof to the original sender.
Configuration, authority resolution and custody are trusted owner-local inputs;
only canonical DM-051 envelope bytes enter the receive methods.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
import uuid
from collections.abc import Callable, Iterator, Mapping
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from contextlib import contextmanager, suppress
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING, Any, cast

if TYPE_CHECKING:
    from .service import LoadedStoreBinding

from .authority_epochs import RootHistoryAuthority
from .canonical import CanonicalError, b64url, canonical_bytes, unb64url
from .communication import (
    MESSAGE_PAYLOAD_SCHEMA,
    RESOLUTION_PAYLOAD_SCHEMA,
    CommunicationError,
    CommunicationStore,
    _foreign_receipt_payload,
    _message_payload,
    _resolution_payload,
)
from .identity import (
    VerificationError,
    validity_attenuates,
    verify_embodiment_credential,
    verify_incarnation_authorization,
)
from .labels import LabelError, LabelIndex
from .ledger import Ledger
from .mandatory_echo import read_diagnostic, write_diagnostic
from .messaging_store import (
    MessagingInboxError,
    MessagingInboxStore,
    MessagingOutboxStore,
    TribeControlCapacityError,
)
from .native_egress import (
    READER_VALIDITY_SCHEMA,
    MandatoryEgressController,
    OperationBinding,
)
from .relationship_store import (
    RelationshipStore,
    RelationshipStoreError,
    RelationshipView,
)
from .routes import (
    ROUTE_SUBMISSION_SCHEMA,
    AuthenticatedProvider,
    DurableIntakeTicket,
    RouteAmbiguous,
    RouteError,
)
from .sealed import (
    MAX_TTL_MS,
    DeliveryCustody,
    DisclosureAuthorization,
    RecipientTarget,
    SealedDeliveryError,
    _closed,
    _parse,
    _text,
    _uint,
    _uuid,
    inspect_delivery,
    open_event,
    recipient_descriptor,
    seal_event,
    sender_descriptor,
)
from .tribe_conversation import (
    TribeConversation,
    ValidatedTribeIntake,
    direct_destination,
)
from .weave import EventSigner, RootAuthority, verify_event

EVIDENCE_SCHEMA = "dm.communication.evidence-package/v1"
GROUP_OPERATION_WORKERS = 2


def _display_identity(being_ref: str, labels: LabelIndex | None) -> str:
    """Owner-approved human name for one being ref, or the ref itself.

    Presentation for the mandatory echo only: the name comes from the
    owner-local labels registry, never from message content, and a being
    without a registry name keeps its exact ref (the compact renderer
    shortens it deterministically). Labels authorize nothing.
    """
    if labels is None:
        return being_ref
    try:
        name = labels.being_name_of_ref(being_ref)
    except LabelError:
        return being_ref
    return being_ref if name is None else name


def _sender_display(
    labels: LabelIndex | None,
    local_origin: Mapping[str, Any],
    being_ref: str,
    *,
    body_fallback: bool = False,
) -> str:
    """Name the sending body by its owner-local label when one exists.

    The signing body's label (``being.harness@host``) is what lets humans
    distinguish two bodies of one being in the echo; without it the display
    falls back to the being registry name and then to the exact ref. The
    label comes from signed body facts plus the owner registry, never from
    message content, and authorizes nothing.
    """
    if labels is not None:
        embodiment_id = local_origin.get("embodiment_id")
        if isinstance(embodiment_id, str):
            try:
                target = labels.targets.get(embodiment_id)
                if target is not None and target.being_ref == being_ref:
                    return target.label
            except LabelError:
                pass
    name = _display_identity(being_ref, labels)
    embodiment_id = local_origin.get("embodiment_id")
    if body_fallback and isinstance(embodiment_id, str):
        if name == being_ref:
            name = "Daimon sin nombre · " + being_ref.removeprefix("dm:being:v1:")
        return name + " · cuerpo " + embodiment_id.removeprefix("embodiment:")
    return name


@dataclass(frozen=True)
class GrantReference:
    grant_id: str
    event_id: str
    event_hash: str


@dataclass(frozen=True)
class MessagingTribePolicy:
    """One tribe channel's authority: active membership, and nothing else.

    Deliberately not ``MessagingPeerPolicy`` with a longer member list. A tribe
    channel has N recipients named by the audience frozen into the signed
    resolution at send time rather than pinned here, its authority is membership
    rather than bilateral consent, and it carries no resource, no operation and
    no grant -- conversation never requires one and never creates one, and the
    ``dm.tribe.membership-proof/v1`` artifact is closed so a proof that tries to
    carry one is rejected rather than ignored.

    The closed field set *is* the control. A policy that cannot name a grant
    cannot smuggle one into a conversation envelope, which is why the pairwise
    fields are absent here rather than present and empty: an empty
    ``grant_refs`` that a later change could populate is exactly the opening
    that review is meant to find.
    """

    tribe_ref: str
    membership_ref: str
    classification: str
    max_ttl_ms: int = 60_000


@dataclass(frozen=True)
class MessagingPeerPolicy:
    """One explicit bilateral lane, separate from the membership-based group."""

    peer_being_ref: str
    peer_embodiment_id: str
    peer_credential_id: str
    relationship_id: str
    tribe_ref: str | None
    membership_ref: str | None
    resource_ref: str
    operation: str
    classification: str
    grant_refs: tuple[GrantReference, ...]
    max_ttl_ms: int = 60_000

    def __post_init__(self) -> None:
        if (self.tribe_ref is None) != (self.membership_ref is None):
            raise ValueError("messaging_membership_policy_mismatch")

    @property
    def recipient_id(self) -> str:
        return (
            self.relationship_id if self.membership_ref is None else self.membership_ref
        )


class MessagingSender:
    """Trusted owner-local /tribe authoring; prepare returns evidence, message bytes.

    The context holds only public recipient authority and signed relationship
    material. Its policy's peer is this sender; its local target is the receiver.
    No transport, foreign Ledger history or generic event-signing API is exposed.
    """

    def __init__(
        self,
        *,
        context: MessagingChannel,
        ledger: Ledger,
        signer: EventSigner,
        custody: DeliveryCustody,
        outbox: MessagingOutboxStore,
        clock: Callable[[], int],
        egress: MandatoryEgressController,
        egress_catalog_id: str,
    ) -> None:
        self.communication: CommunicationStore | None = None
        self.context = context
        self.ledger = ledger
        self.signer = signer
        self.custody = custody
        self.outbox = outbox
        self.clock = clock
        if not isinstance(egress, MandatoryEgressController):
            raise ValueError("messaging_egress_required")
        self.egress = egress
        outbox.bind_egress(
            egress,
            catalog_id=egress_catalog_id,
            owner=context.policy.peer_being_ref,
            authorize=self._authorize_egress,
        )

    def _authorize_egress(self, binding: OperationBinding) -> bool:
        try:
            owner, send_id, _phase = binding.locator.split("\0")
            now = self.clock()
            self._bind(now)
            self.outbox._check_time(owner, send_id, now)
            return binding.authority_head == self.context._sender().state.head
        except (ValueError, KeyError, TypeError):
            return False

    def _bind(self, now: int) -> None:
        policy, authority = self.context.policy, self.context._sender()
        try:
            member = authority.validate_origin(
                self.ledger.local_origin, require_active=True
            )
            recipient_descriptor(
                RecipientTarget(authority, policy.peer_credential_id), at_ms=now
            )
            signing = authority.credentials[policy.peer_credential_id]["body"][
                "signing_key"
            ]
            if (
                self.ledger.authority.manifest.being_ref != policy.peer_being_ref
                or self.ledger.authority.manifest.digest != authority.manifest.digest
                or authority.state.being_ref != policy.peer_being_ref
                or member["embodiment_id"] != policy.peer_embodiment_id
                or member["embodiment_credential_id"] != policy.peer_credential_id
                or self.signer.key_id != signing["key_id"]
                or b64url(self.signer.public_key) != signing["public"]
            ):
                raise ValueError("binding")
        except (ValueError, KeyError, TypeError):
            raise ValueError("messaging_sender_binding") from None

    def _receipt(
        self,
        channel: MessagingChannel,
        message: Mapping[str, Any],
        now: int,
        *,
        observed_at_ms: int,
        authority_view: RelationshipView,
    ) -> dict[str, Any]:
        # page/message reads do not invoke this purpose-limited authoring path.
        row = channel.inbox._message(
            message["event_id"], channel._policy_hash(now, authority_view)
        )
        channel._validate_rows([row], now, authority_view=authority_view)
        resolution = row["evidence"]["payload"]["resolution_event"]
        payload = {
            "schema": "dm.communication.receipt/v2",
            "message_being_ref": message["being_ref"],
            "message_ref": {
                "event_id": message["event_id"],
                "event_hash": message["content_hash"],
            },
            "resolution_ref": {
                "event_id": resolution["event_id"],
                "event_hash": resolution["content_hash"],
            },
            "thread_id": message["payload"]["intent"]["thread_id"],
            "recipient_type": "relationship",
            "recipient_id": channel.policy.recipient_id,
            "outcome": "delivered",
        }
        digest = hashlib.sha256(canonical_bytes(payload)).hexdigest()
        operation_id = str(
            uuid.uuid5(uuid.NAMESPACE_URL, "dm.communication.receipt/v2:" + digest)
        )
        plan = self.outbox._reserve(
            "dm.communication.receipt/v2:" + channel.local_being_ref,
            operation_id,
            {
                "client_id": "dm.communication.receipt/v2",
                "request_hash": digest,
                "policy_hash": channel._policy_hash(now, authority_view),
                "origin": dict(self.ledger.local_origin),
                "issued_at_ms": observed_at_ms,
            },
        )
        observed = plan["issued_at_ms"]
        if observed < message["occurred_at_ms"] or observed > now:
            raise ValueError("receipt_observation_time_invalid")
        payload["observed_at_ms"] = observed
        return self.ledger.append_local_idempotent(
            client_id="dm.communication.receipt/v2",
            request_id=operation_id,
            request_hash=hashlib.sha256(canonical_bytes(payload)).hexdigest(),
            kind="experience.observed",
            subject="communication-receipt",
            payload=payload,
            signer=self.signer,
            sensitivity=self.context.policy.classification,
            occurred_at_ms=observed,
            causal_parents=(),
        )

    def prepare(
        self,
        *,
        client_id: str,
        send_id: str,
        thread_id: str,
        text: str,
        response_to: tuple[MessagingChannel, str] | None = None,
        _authority_view: RelationshipView | None = None,
    ) -> tuple[bytes, bytes]:
        now = _uint(self.clock())
        context, policy = self.context, self.context.policy
        if _authority_view is None:
            # Preserve bounded request/transport error precedence before taking
            # current-authority writer exclusion; the checks repeat inside it.
            self._bind(now)
            if not isinstance(text, str):
                raise ValueError("messaging_text_required")
            if not 0 < _uint(policy.max_ttl_ms) <= MAX_TTL_MS:
                raise ValueError("messaging_ttl_invalid")
            # Lock order: relationship writer exclusion -> outbox -> Ledger ->
            # communication store. No provider/network I/O is performed here.
            with context.relationships.authorization_view(
                at_ms=now, card_verifier=context._card
            ) as view:
                return self.prepare(
                    client_id=client_id,
                    send_id=send_id,
                    thread_id=thread_id,
                    text=text,
                    response_to=response_to,
                    _authority_view=view,
                )
        self._bind(now)
        if not isinstance(text, str):
            raise ValueError("messaging_text_required")
        if not 0 < _uint(policy.max_ttl_ms) <= MAX_TTL_MS:
            raise ValueError("messaging_ttl_invalid")
        owner = policy.peer_being_ref
        policy_hash = context._policy_hash(now, _authority_view)
        payload: dict[str, Any] = {
            "schema": MESSAGE_PAYLOAD_SCHEMA,
            "body": {"text": text, "resource_ref": policy.resource_ref},
            "intent": {
                "operation": policy.operation,
                "scope": "/tribe",
                "thread_id": thread_id,
            },
            "reply": None,
        }
        if self.communication is not None:
            cached_pair = self.outbox._prepared(owner, send_id)
            if cached_pair is None:
                payload["body"]["recipient_being_ref"] = context.local_being_ref
            else:
                previous_message = self.ledger.event(_parse(cached_pair[1])["event_id"])
                if previous_message is None:
                    raise ValueError("messaging_outbox_missing")
                previous_body = verify_event(previous_message, self.ledger.authority)[
                    "payload"
                ]["body"]
                if "recipient_being_ref" in previous_body:
                    payload["body"]["recipient_being_ref"] = context.local_being_ref
        if response_to is not None:
            channel, message_id = response_to
            if channel.relationships is not context.relationships:
                raise ValueError("messaging_response_authority_mismatch")
            received = channel.message(message_id, _authority_view=_authority_view)
            if (
                channel.local_being_ref != owner
                or channel.local_credential_id != policy.peer_credential_id
                or channel.policy.peer_being_ref != context.local_being_ref
                or channel.policy.peer_credential_id != context.local_credential_id
                or channel.policy.tribe_ref != policy.tribe_ref
                or channel.policy.relationship_id != policy.relationship_id
                or received["payload"]["intent"]["thread_id"] != thread_id
            ):
                raise ValueError("messaging_response_context_mismatch")
            payload["body"]["response_context"] = {
                "schema": "dm.messaging.application-response/v1",
                "message_id": received["event_id"],
                "message_hash": received["content_hash"],
                "sender_being_ref": received["being_ref"],
                "sender_embodiment_id": received["origin"]["embodiment_id"],
                "thread_id": thread_id,
            }
        semantic_reply = (
            response_to is not None
            and self.communication is not None
            and "recipient_being_ref" in payload["body"]
            and received["payload"]["body"].get("recipient_being_ref") == owner
        )
        _message_payload(
            {
                "kind": "experience.observed",
                "subject": "communication",
                "payload": payload,
            }
        )
        request_document = (
            {"payload": payload, "receipt_schema": "dm.communication.receipt/v2"}
            if semantic_reply
            else payload
        )
        request_hash = hashlib.sha256(canonical_bytes(request_document)).hexdigest()
        _text(client_id, maximum=128)
        _uuid(send_id)
        plan = self.outbox._reserve(
            owner,
            send_id,
            {
                "client_id": client_id,
                "request_hash": request_hash,
                "origin": dict(self.ledger.local_origin),
                "policy_hash": policy_hash,
                "logical_send_id": send_id,
                "carrier_generation": 1,
                "issued_at_ms": now,
                "expires_at_ms": now + policy.max_ttl_ms,
                "message_authorization_id": str(uuid.uuid4()),
                "evidence_authorization_id": str(uuid.uuid4()),
            },
        )
        carrier_send_id, plan = self.outbox._carrier(
            owner,
            send_id,
            plan,
            now=now,
            max_ttl_ms=policy.max_ttl_ms,
        )
        issued, expires = plan["issued_at_ms"], plan["expires_at_ms"]
        if now >= expires and not self.outbox._intake_recorded(owner, carrier_send_id):
            raise ValueError("messaging_authorization_expired")
        if now < issued:
            raise ValueError("messaging_authorization_not_yet_valid")
        cached = self.outbox._prepared(owner, carrier_send_id)
        if cached is not None:
            return cached
        logical_cached = self.outbox._prepared(owner, send_id)
        reuse_logical_events = carrier_send_id != send_id and logical_cached is not None
        message: dict[str, Any] | None = None
        resolution: dict[str, Any] | None = None
        if reuse_logical_events:
            if logical_cached is None:
                raise ValueError("messaging_outbox_missing")
            prior_message = self.ledger.event(_parse(logical_cached[1])["event_id"])
            prior_evidence = self.ledger.event(_parse(logical_cached[0])["event_id"])
            if prior_message is None or prior_evidence is None:
                raise ValueError("messaging_outbox_missing")
            message = verify_event(prior_message, self.ledger.authority)
            verified_prior_evidence = verify_event(
                prior_evidence, self.ledger.authority
            )
            resolution = verify_event(
                verified_prior_evidence["payload"]["resolution_event"],
                self.ledger.authority,
            )
            payload = dict(message["payload"])
        elif semantic_reply:
            payload["body"]["semantic_receipt"] = self._receipt(
                channel,
                received,
                now,
                observed_at_ms=issued,
                authority_view=_authority_view,
            )
            # A concurrent later reply may have established the one receipt first.
            # Keep the original expiry; only event chronology follows that proof.
            issued = max(issued, payload["body"]["semantic_receipt"]["occurred_at_ms"])

        def append(
            subject: str, body: Mapping[str, Any], parents: tuple[str, ...] = ()
        ) -> dict[str, Any]:
            operation_id = str(
                uuid.uuid5(uuid.UUID(plan["message_authorization_id"]), subject)
            )
            phase_hash = hashlib.sha256(
                canonical_bytes(
                    {
                        "subject": subject,
                        "payload": body,
                        "parents": list(parents),
                        "issued_at_ms": issued,
                        "sensitivity": policy.classification,
                    }
                )
            ).hexdigest()
            return self.ledger.append_local_idempotent(
                client_id="dm.messaging.prepare/v1",
                request_id=operation_id,
                request_hash=phase_hash,
                kind="experience.observed",
                subject=subject,
                payload=body,
                signer=self.signer,
                sensitivity=policy.classification,
                occurred_at_ms=issued,
                causal_parents=parents,
            )

        target = context._local()
        if not reuse_logical_events:
            message = append("communication", payload)
            resolution = append(
                "communication-resolution",
                {
                    "schema": RESOLUTION_PAYLOAD_SCHEMA,
                    "message_id": message["event_id"],
                    "scope": "/tribe",
                    "targets": [
                        {
                            "evidence_cursor": policy_hash,
                            "receipt_origin_embodiment_id": recipient_descriptor(
                                target, at_ms=now
                            )["embodiment_id"],
                            "recipient_id": policy.recipient_id,
                            "recipient_type": "relationship",
                            "scope_kind": "relationship",
                        }
                    ],
                },
                (message["event_id"],),
            )
            if self.communication is not None:
                self.communication.accept(
                    message_event_id=message["event_id"],
                    resolution_event_id=resolution["event_id"],
                )
        if message is None or resolution is None:
            raise ValueError("messaging_outbox_missing")
        authorization = DisclosureAuthorization.from_relationship_resolution_event(
            event=message,
            resolution_event=resolution,
            sender_authority=context._sender(),
            recipient_targets=[target],
            disclosures={
                policy.recipient_id: context._disclosure_from_view(
                    _authority_view, at_ms=now
                )
            },
            expires_at_ms=expires,
            authorization_id=plan["message_authorization_id"],
        )
        evidence = append(
            "communication-evidence",
            {
                "schema": EVIDENCE_SCHEMA,
                "message_id": message["event_id"],
                "message_hash": message["content_hash"],
                "resolution_event": resolution,
                "message_authorization_id": plan["message_authorization_id"],
                "message_authorized_at_ms": resolution["occurred_at_ms"],
                "message_expires_at_ms": expires,
            },
            (resolution["event_id"],),
        )
        bootstrap = context._authorization(
            evidence,
            sender=sender_descriptor(evidence, context._sender(), at_ms=now),
            evidence_hash=policy_hash,
            authorized_at_ms=issued,
            expires_at_ms=expires,
            authorization_id=plan["evidence_authorization_id"],
            at_ms=now,
        )
        envelopes = tuple(
            seal_event(
                event,
                sender_authority=context._sender(),
                recipients=[target],
                authorization=auth,
                custody=self.custody,
                issued_at_ms=issued,
                expires_at_ms=expires,
            )
            for event, auth in ((evidence, bootstrap), (message, authorization))
        )
        return self.outbox._commit(owner, carrier_send_id, (envelopes[0], envelopes[1]))


class MessagingDelivery:
    """Trusted owner-local evidence/message transport, not semantic delivery.

    The future owner config loader must derive config_digest from the validated
    endpoints, key references and channel selection. Neither that digest nor
    providers are model inputs. Results describe recipient intake only: never
    consumer acknowledgment, reply, task completion or a signed Matrix receipt.
    """

    def __init__(
        self,
        *,
        sender: MessagingSender,
        evidence_provider: AuthenticatedProvider,
        message_provider: AuthenticatedProvider,
        config_digest: str,
        historical_inspection: Callable[[str], None] | None = None,
    ) -> None:
        if (
            not isinstance(config_digest, str)
            or len(config_digest) != 64
            or any(character not in "0123456789abcdef" for character in config_digest)
        ):
            raise ValueError("messaging_config_digest_invalid")
        self.sender = sender
        self.providers = (evidence_provider, message_provider)
        self.config_digest = config_digest
        self.historical_inspection = historical_inspection

    def _semantic(self, message_id: str) -> dict[str, Any]:
        event = self.sender.ledger.event(message_id)
        if event is None:
            raise ValueError("messaging_outbox_missing")
        if (
            "recipient_being_ref"
            not in _message_payload(verify_event(event, self.sender.ledger.authority))[
                "body"
            ]
        ):
            return {
                "status": "legacy-untracked",
                "terminal": False,
                "message_id": message_id,
            }
        assert self.sender.communication is not None
        return self.sender.communication.result(message_id)

    def inspect(
        self,
        *,
        client_id: str,
        send_id: str,
        response_channels: tuple[MessagingChannel, ...] = (),
    ) -> dict[str, Any]:
        """Current-authorized transport proof inspection; never transmits or authors."""
        self.sender._bind(self.sender.clock())
        owner = self.sender.context.policy.peer_being_ref
        self.sender.outbox._check_client(owner, _uuid(send_id), client_id)
        envelopes = self.sender.outbox._prepared(owner, send_id)
        if envelopes is None:
            raise ValueError("messaging_outbox_missing")
        event = self.sender.ledger.event(_parse(envelopes[1])["event_id"])
        if event is None:
            raise ValueError("messaging_outbox_missing")
        payload = _message_payload(verify_event(event, self.sender.ledger.authority))
        request_payload = {**payload, "body": dict(payload["body"])}
        semantic_reply = request_payload["body"].pop("semantic_receipt", None)
        request_document = (
            {
                "payload": request_payload,
                "receipt_schema": "dm.communication.receipt/v2",
            }
            if semantic_reply is not None
            else request_payload
        )
        policy_hash = self.sender.context._policy_hash(self.sender.clock())
        envelopes = self.sender.outbox._inspection_pair(
            owner,
            send_id,
            expected={
                "client_id": client_id,
                "request_hash": hashlib.sha256(
                    canonical_bytes(request_document)
                ).hexdigest(),
                "policy_hash": policy_hash,
                "origin": dict(self.sender.ledger.local_origin),
            },
            now=self.sender.clock(),
        )
        if _parse(envelopes[1])["event_id"] != event["event_id"]:
            raise ValueError("messaging_carrier_conflict")
        carrier_send_id = self.sender.outbox._carrier_for_envelopes(
            owner, send_id, envelopes
        )
        retained_digest = self.sender.outbox._inspection_config_digest(
            owner, carrier_send_id
        )
        historical = retained_digest != self.config_digest
        if historical and self.historical_inspection is None:
            raise ValueError("messaging_transport_conflict")
        response_to = None
        if "response_context" in payload["body"]:
            reference = payload["body"]["response_context"]
            for channel in response_channels:
                try:
                    received = channel.message(reference["message_id"])
                except ValueError:
                    continue
                if received["content_hash"] == reference["message_hash"]:
                    response_to = (channel, reference["message_id"])
                    break
            if response_to is None:
                raise ValueError("messaging_response_context_missing")

        def authorize() -> None:
            now = self.sender.clock()
            self.sender._bind(now)
            if self.sender.context._policy_hash(now) != policy_hash:
                raise ValueError("messaging_send_conflict")
            if historical:
                assert self.historical_inspection is not None
                self.historical_inspection(retained_digest)

        result = self._run(
            client_id=client_id,
            send_id=send_id,
            thread_id=payload["intent"]["thread_id"],
            text=payload["body"]["text"],
            transmit=False,
            response_to=response_to,
            retained_envelopes=envelopes,
            inspection_config_digest=retained_digest,
            authorize=authorize,
        )
        if historical:
            # Past intake proof does not authorize a fresh retry under its old
            # application selection, even while a retained carrier is pending.
            result["retryable"] = False
            result["recovery"] = {
                **result["recovery"],
                "action": "historical-inspection-only",
                "not_before_ms": None,
            }
        return result

    def send(
        self,
        *,
        client_id: str,
        send_id: str,
        thread_id: str,
        text: str,
        response_to: tuple[MessagingChannel, str] | None = None,
        authorize: Callable[[], None] | None = None,
    ) -> dict[str, Any]:
        return self._run(
            client_id=client_id,
            send_id=send_id,
            thread_id=thread_id,
            text=text,
            transmit=True,
            response_to=response_to,
            authorize=authorize,
        )

    def _run(
        self,
        *,
        client_id: str,
        send_id: str,
        thread_id: str,
        text: str,
        transmit: bool,
        response_to: tuple[MessagingChannel, str] | None = None,
        authorize: Callable[[], None] | None = None,
        retained_envelopes: tuple[bytes, bytes] | None = None,
        inspection_config_digest: str | None = None,
    ) -> dict[str, Any]:
        if transmit and inspection_config_digest is not None:
            raise ValueError("messaging_transport_conflict")
        if authorize is not None:
            authorize()
        # Always authorize the original request before consulting private progress.
        envelopes = (
            self.sender.prepare(
                client_id=client_id,
                send_id=send_id,
                thread_id=thread_id,
                text=text,
                response_to=response_to,
            )
            if transmit
            else retained_envelopes
        )
        if envelopes is None:
            raise ValueError("messaging_transport_missing")
        owner = self.sender.context.policy.peer_being_ref
        labels = getattr(self.sender.context, "labels", None)
        readable = self.sender.egress.representation == "compact-text/v1"
        carrier_send_id = self.sender.outbox._carrier_for_envelopes(
            owner, send_id, envelopes
        )
        # An exact completed retry inspects the original authenticated pair.
        # Expiry forbids another transmission, not verification of past intake.
        # The local status is only a hint: BOTH response proofs are checked below.
        completed_retry = transmit and self.sender.outbox._intake_recorded(
            owner, carrier_send_id
        )
        if completed_retry:
            transmit = False
        phases = ("evidence", "message")
        submissions = {}
        bindings = {}
        projections = {}
        for phase, provider, envelope in zip(
            phases, self.providers, envelopes, strict=True
        ):
            metadata = _parse(envelope)
            attempt_id = str(
                uuid.uuid5(
                    uuid.UUID(carrier_send_id),
                    f"dm.messaging.transport/v1:{owner}:{phase}",
                )
            )
            submissions[phase] = {
                "schema": ROUTE_SUBMISSION_SCHEMA,
                "attempt_id": attempt_id,
                # Application stage label, not a fabricated DM-052 semantic leg.
                "leg_id": "application-stage:" + phase,
                "message_id": metadata["event_id"],
                "recipient_id": self.sender.context.policy.recipient_id,
                "delivery_id": metadata["delivery_id"],
                "envelope": b64url(envelope),
                "envelope_sha256": hashlib.sha256(envelope).hexdigest(),
                "deadline_ms": metadata["expires_at_ms"],
            }
            bindings[phase] = {
                "config_digest": inspection_config_digest or self.config_digest,
                "provider_ref": provider.provider_ref,
                "route_ref": provider.route_ref,
                "route_class": provider.route_class,
                "attempt_id": attempt_id,
                "submission_sha256": hashlib.sha256(
                    canonical_bytes(submissions[phase])
                ).hexdigest(),
            }
            event = self.sender.ledger.event(metadata["event_id"])
            if event is None:
                raise ValueError("messaging_outbox_missing")
            projections[phase] = {
                "event_id": metadata["event_id"],
                "event_digest": event["content_hash"],
                "sender": _sender_display(
                    labels,
                    self.sender.ledger.local_origin,
                    owner,
                    body_fallback=readable,
                ),
                "recipients": [
                    _display_identity(self.sender.context.local_being_ref, labels)
                ],
                "thread_id": thread_id,
                "reply_to": None,
                "kind": "message" if phase == "message" else "authorization-control",
                "content": {"text": text}
                if phase == "message"
                else {"stage": "evidence-before-message"},
            }
            if readable:
                target = self.sender.context._local()
                credential = target.authority.credentials[
                    self.sender.context.local_credential_id
                ]["body"]
                projections[phase]["recipients"] = [
                    _sender_display(
                        labels,
                        {"embodiment_id": credential["embodiment_id"]},
                        self.sender.context.local_being_ref,
                        body_fallback=True,
                    )
                ]
                reference = (
                    event["payload"]["body"].get("response_context")
                    if phase == "message"
                    else None
                )
                if reference is not None:
                    parent: dict[str, Any] = {
                        "event_id": reference["message_id"],
                        "event_digest": reference["message_hash"],
                    }
                    receipt = event["payload"]["body"].get("semantic_receipt")
                    if receipt is not None:
                        verified_receipt = verify_event(
                            receipt, self.sender.ledger.authority
                        )
                        receipt_payload = _foreign_receipt_payload(verified_receipt)
                        retained = self.sender.ledger.event(
                            verified_receipt["event_id"]
                        )
                        if (
                            retained is None
                            or canonical_bytes(retained)
                            != canonical_bytes(verified_receipt)
                            or verified_receipt["origin"] != event["origin"]
                            or receipt_payload["message_ref"]
                            != {
                                "event_id": parent["event_id"],
                                "event_hash": parent["event_digest"],
                            }
                            or receipt_payload["outcome"] != "delivered"
                        ):
                            raise ValueError("messaging_semantic_receipt_mismatch")
                        # This receipt confirms the PARENT's native intake, never
                        # the current reply, a human read or subsequent work.
                        parent["receipt"] = {
                            "event_id": verified_receipt["event_id"],
                            "event_digest": verified_receipt["content_hash"],
                            "outcome": receipt_payload["outcome"],
                        }
                    if response_to is not None:
                        received = response_to[0].message(reference["message_id"])
                        parent.update(
                            sender=_sender_display(
                                labels,
                                received["origin"],
                                received["being_ref"],
                                body_fallback=True,
                            ),
                            text=received["payload"]["body"]["text"][:160],
                        )
                    projections[phase].update(kind="reply", reply_to=parent)
        providers = dict(zip(phases, self.providers, strict=True))
        stages = self.sender.outbox._transport_stages(
            owner,
            carrier_send_id,
            bindings,
            lambda phase: providers[phase].prepare_submission(submissions[phase]),
            projections=projections,
            deadline_ms=max(item["deadline_ms"] for item in submissions.values()),
            authority_head=self.sender.context._sender().state.head,
            create=transmit,
        )
        # Validate BOTH retained requests before any network I/O, including when
        # evidence succeeded already. This checks current transport keys without
        # regenerating timestamps or retaining those keys in the outbox.
        for phase in phases:
            prepared, _, _ = providers[phase]._prepared_submission(
                stages[phase]["request"], check_time=transmit
            )
            if canonical_bytes(prepared) != canonical_bytes(submissions[phase]):
                raise ValueError("messaging_transport_conflict")
            stage = stages[phase]
            if stage["transport_status"] in {
                "recipient-intake",
                "refused",
                "hub-accepted",
            }:
                if not isinstance(stage["response"], bytes):
                    raise ValueError("messaging_transport_response_missing")
                verified = providers[phase].validate_prepared_response(
                    stage["request"], stage["response"]
                )
                if (
                    verified["outcome"] != stage["transport_status"]
                    or hashlib.sha256(canonical_bytes(verified)).hexdigest()
                    != stage["result_sha256"]
                ):
                    raise ValueError("messaging_transport_response_conflict")
            elif stage["response"] is not None or stage["result_sha256"] is not None:
                raise ValueError("messaging_transport_response_conflict")
        for phase in phases:
            if authorize is not None:
                authorize()
            # Evidence I/O may take us beyond expiry or a newly observed revocation.
            # Recheck before releasing the next stage, without renewing the pair.
            if transmit or completed_retry:
                self.sender.prepare(
                    client_id=client_id,
                    send_id=send_id,
                    thread_id=thread_id,
                    text=text,
                    response_to=response_to,
                )
            else:
                self.sender._bind(self.sender.clock())
            stage = stages[phase]
            status = stage["transport_status"]
            if transmit and status in {"prepared", "pending"}:
                now = self.sender.clock()
                self.sender.outbox._check_time(owner, carrier_send_id, now)
                with self.sender.context.relationships.authorization_view(
                    at_ms=now, card_verifier=self.sender.context._card
                ) as view:
                    self.sender.context._disclosure_from_view(view, at_ms=now)
                    if authorize is not None:
                        authorize()
                    status = self.sender.outbox._transport_status(
                        owner, carrier_send_id, phase
                    )
                if status == "pending":
                    proofs: list[bytes] = []
                    try:
                        # Deliberately outside the relationship writer exclusion.
                        result = providers[phase].send_prepared(
                            stage["request"], response_sink=proofs.append
                        )
                    except (RouteError, CanonicalError) as exception:
                        # No authenticated outcome: recipient may already have admitted
                        # the request. Keep the committed pending state across restart.
                        result = None
                        self.sender.outbox._record_failure(
                            owner,
                            carrier_send_id,
                            phase,
                            exception.code
                            if isinstance(exception, RouteError)
                            else "canonical_rejected",
                            self.sender.clock(),
                        )
                    now = self.sender.clock()
                    self.sender.outbox._check_time(owner, carrier_send_id, now)
                    with self.sender.context.relationships.authorization_view(
                        at_ms=now, card_verifier=self.sender.context._card
                    ) as view:
                        # Network I/O can race a signed revocation. Recheck current
                        # authority and serialize any local result commit after it.
                        self.sender.context._disclosure_from_view(view, at_ms=now)
                        if authorize is not None:
                            authorize()
                        if result is not None and result["status"] in {
                            "accepted",
                            "refused",
                        }:
                            status = self.sender.outbox._transport_status(
                                owner,
                                carrier_send_id,
                                phase,
                                result=result,
                                response=proofs[0],
                            )
            stage["transport_status"] = status
            if status != "recipient-intake":
                break
        if authorize is not None:
            authorize()
        diagnostics = {}
        for label in phases:
            operation = self.sender.egress.binding_for_native(
                stages[label]["request"],
                allowed_paths=frozenset({f"messaging-{label}-request"}),
            )
            diagnostics[label] = {
                **self.sender.egress.inspect_retained(operation),
                "last_failure": self.sender.outbox._failure(
                    owner, carrier_send_id, label
                ),
            }
        # History is inspectable after expiry; an explicit exact retry renews
        # only the immutable carrier, preserving the authored logical message.
        current = diagnostics[phase]
        expires = current["expires_at_ms"]
        unfinished = status in {"pending", "prepared"}
        action = (
            "none"
            if not unfinished
            else "renew-carrier"
            if self.sender.clock() >= expires
            else "wait-until-expiry"
            if current["echo_state"] == "ambiguous"
            else "retry-exact"
        )
        if authorize is not None:
            authorize()
        return {
            **(
                {"semantic": self._semantic(_parse(envelopes[1])["event_id"])}
                if self.sender.communication is not None
                else {}
            ),
            "send_id": send_id,
            "phase": phase,
            "transport_status": status,
            "retryable": unfinished and action != "wait-until-expiry",
            "ambiguous": status == "pending",
            "carrier_send_id": carrier_send_id,
            "recovery": {
                "action": action,
                "not_before_ms": expires if action == "wait-until-expiry" else None,
                "may_duplicate_tribu_post": unfinished
                and action in {"renew-carrier", "wait-until-expiry"}
                and any(
                    item["confirmed_parts"] > 0
                    or (item["part_count"] > 0 and item["echo_state"] == "ambiguous")
                    for item in diagnostics.values()
                ),
            },
            "stages": [
                {
                    "phase": label,
                    "attempt_id": bindings[label]["attempt_id"],
                    "transport_status": stages[label]["transport_status"],
                    "diagnostic": diagnostics[label],
                }
                for label in phases
            ],
        }


class MessagingChannel:
    """Owner-local receiver; no model-supplied verified objects or grant inputs."""

    def __init__(
        self,
        *,
        policy: MessagingPeerPolicy,
        local_being_ref: str,
        local_credential_id: str,
        authority_resolver: Callable[[str], RootAuthority | RootHistoryAuthority],
        relationships: RelationshipStore,
        custody: DeliveryCustody,
        inbox: MessagingInboxStore,
        clock: Callable[[], int],
    ) -> None:
        self.communication: CommunicationStore | None = None
        self.policy = policy
        self.labels: LabelIndex | None = None
        self.local_being_ref = local_being_ref
        self.local_credential_id = local_credential_id
        self.authority_resolver = authority_resolver
        self.relationships = relationships
        self.custody = custody
        self.inbox = inbox
        self.clock = clock

    def _active(self, being_ref: str) -> RootAuthority:
        """Current epoch for one being, whether or not history is supplied."""
        authority = self.authority_resolver(being_ref)
        return (
            authority.active
            if isinstance(authority, RootHistoryAuthority)
            else authority
        )

    def _local(self) -> RecipientTarget:
        return RecipientTarget(
            self._active(self.local_being_ref), self.local_credential_id
        )

    def _sender(self) -> RootAuthority:
        return self._active(self.policy.peer_being_ref)

    def _card(self, card: Mapping[str, Any], at_ms: int) -> None:
        """Verify one card against the epoch it pins, not against the newest one.

        Enrolling another embodiment advances the being manifest. A card issued
        before that advance pins the manifest it was issued under, and demanding
        the current digest there would silently drop every member whose card
        predates the advance, emptying tribe snapshots and refusing disclosure.
        The pinned epoch is selected from verified history, the member is checked
        in that epoch at the verification time, and the embodiment must still be
        active now under the same body. Anything else fails closed.
        """
        authority = self.authority_resolver(card["being_ref"])
        position = card["control_position"]
        pinned = position["manifest_hash"]
        epoch: RootAuthority
        if isinstance(authority, RootHistoryAuthority):
            try:
                epoch = authority.select({"manifest_hash": pinned})
            except Exception:
                raise SealedDeliveryError() from None
        else:
            epoch = authority
        if epoch.manifest.digest != pinned:
            raise SealedDeliveryError()
        try:
            member = epoch.manifest.member(
                position["embodiment_id"], position["incarnation_id"]
            )
        except Exception:
            raise SealedDeliveryError() from None
        target = RecipientTarget(epoch, member["embodiment_credential_id"])
        descriptor = recipient_descriptor(target, at_ms=at_ms)
        active = (
            authority.active if isinstance(authority, RootHistoryAuthority) else epoch
        )
        current = [
            row
            for row in active.manifest.value["embodiments"]
            if row["embodiment_id"] == position["embodiment_id"]
            and row["status"] == "active"
        ]
        if (
            len(current) != 1
            or current[0]["body_ref"] != member["body_ref"]
            or descriptor["encryption_kid"] != card["encryption_key"]["key_id"]
            or epoch.credentials[target.credential_id]["body"]["encryption_key"]
            != card["encryption_key"]
        ):
            raise SealedDeliveryError()

    def _disclosure_from_view(
        self, view: RelationshipView, *, at_ms: int
    ) -> dict[str, Any]:
        policy = self.policy
        # Membership and grants name the being; its card may advertise another
        # active body. Independently validate this channel's exact receiving
        # credential before using that being's signed membership.
        recipient_descriptor(self._local(), at_ms=at_ms)
        if policy.tribe_ref is not None:
            snapshot = view.snapshot(policy.tribe_ref)
            if not any(
                member["principal_id"] == self.local_being_ref
                and member["membership_ref"] == policy.membership_ref
                for member in snapshot.value["members"]
            ):
                raise SealedDeliveryError()
        disclosure = view.disclosure(
            requester_being_ref=self.local_being_ref,
            resource_ref=policy.resource_ref,
            operation=policy.operation,
            classification=policy.classification,
        )
        if not disclosure["authorized"] or not policy.grant_refs:
            raise SealedDeliveryError()
        selected = [asdict(reference) for reference in policy.grant_refs]
        if selected != sorted(selected, key=lambda row: row["grant_id"]) or len(
            {row["grant_id"] for row in selected}
        ) != len(selected):
            raise SealedDeliveryError()
        for reference in selected:
            state = view.grants.get(reference["grant_id"])
            if state is None or state["state"] != "active":
                raise SealedDeliveryError()
            grant = state["grant"]
            payload = grant["payload"]
            if (
                reference not in disclosure["authorization"]["grant_refs"]
                or grant["being_ref"] != policy.peer_being_ref
                or payload["grantor_being_ref"] != policy.peer_being_ref
                or payload["subject_being_ref"] != self.local_being_ref
                or payload["relationship_id"] != policy.relationship_id
                or payload["tribe_ref"] != policy.tribe_ref
            ):
                raise SealedDeliveryError()
        disclosure["authorization"]["grant_refs"] = selected
        return disclosure

    def _disclosure(self, at_ms: int) -> dict[str, Any]:
        with self.relationships.authorization_view(
            at_ms=at_ms, card_verifier=self._card
        ) as view:
            return self._disclosure_from_view(view, at_ms=at_ms)

    def disclosure(self) -> dict[str, Any]:
        """Recompute the selected disclosure, also usable by the sender context."""
        return self._disclosure(self.clock())

    def _policy_hash(
        self, at_ms: int, authority_view: RelationshipView | None = None
    ) -> str:
        if authority_view is None:
            with self.relationships.authorization_view(
                at_ms=at_ms, card_verifier=self._card
            ) as view:
                return self._policy_hash(at_ms, view)
        return hashlib.sha256(
            canonical_bytes(
                {
                    "schema": "dm.communication.bootstrap-policy/v1",
                    "policy": asdict(self.policy),
                    "recipient": recipient_descriptor(self._local(), at_ms=at_ms),
                    "disclosure": self._disclosure_from_view(
                        authority_view, at_ms=at_ms
                    ),
                }
            )
        ).hexdigest()

    def _authorization(
        self,
        commitment: Mapping[str, Any],
        *,
        sender: Mapping[str, Any],
        evidence_hash: str,
        authorized_at_ms: int,
        expires_at_ms: int,
        authorization_id: str,
        at_ms: int,
    ) -> DisclosureAuthorization:
        policy = self.policy
        if (
            sender["being_ref"] != policy.peer_being_ref
            or sender["embodiment_id"] != policy.peer_embodiment_id
            or sender["credential_id"] != policy.peer_credential_id
            or commitment["sensitivity"] != policy.classification
        ):
            raise SealedDeliveryError()
        return DisclosureAuthorization.synthetic(
            event=commitment,
            sender=sender,
            recipients=[recipient_descriptor(self._local(), at_ms=at_ms)],
            evidence_hash=evidence_hash,
            authorized_at_ms=authorized_at_ms,
            expires_at_ms=expires_at_ms,
            authorization_id=authorization_id,
        )

    def evidence_authorization(
        self,
        event: Mapping[str, Any],
        *,
        authorized_at_ms: int,
        expires_at_ms: int,
        authorization_id: str,
    ) -> DisclosureAuthorization:
        """Sender-side bootstrap decision from the same independently held policy."""
        now = self.clock()
        return self._authorization(
            event,
            sender=sender_descriptor(event, self._sender(), at_ms=now),
            evidence_hash=self._policy_hash(now),
            authorized_at_ms=authorized_at_ms,
            expires_at_ms=expires_at_ms,
            authorization_id=authorization_id,
            at_ms=now,
        )

    def _envelope(self, raw: bytes, at_ms: int) -> Mapping[str, Any]:
        inspect_delivery(raw, at_ms=at_ms)  # Framing only, never authenticity.
        envelope = _parse(raw)
        if (
            envelope["expires_at_ms"] - envelope["issued_at_ms"]
            > self.policy.max_ttl_ms
        ):
            raise SealedDeliveryError()
        return envelope

    def _open(
        self, raw: bytes, authorization: DisclosureAuthorization, at_ms: int
    ) -> Mapping[str, Any]:
        self.inbox._check_delivery(raw)
        local = self._local()
        # open_event verifies the signature AND reconstructed policy before unwrap.
        return open_event(
            raw,
            sender_authority=self._sender(),
            local_target=local,
            recipient_targets=[local],
            authorization=authorization,
            custody=self.custody,
            at_ms=at_ms,
        )

    def _message_authorization(
        self,
        evidence: Mapping[str, Any],
        at_ms: int,
        authority_view: RelationshipView | None = None,
    ) -> DisclosureAuthorization:
        if authority_view is None:
            with self.relationships.authorization_view(
                at_ms=at_ms, card_verifier=self._card
            ) as view:
                return self._message_authorization(evidence, at_ms, view)
        if (
            evidence["kind"] != "experience.observed"
            or evidence["subject"] != "communication-evidence"
        ):
            raise SealedDeliveryError()
        payload = _closed(
            evidence["payload"],
            {
                "schema",
                "message_id",
                "message_hash",
                "resolution_event",
                "message_authorization_id",
                "message_authorized_at_ms",
                "message_expires_at_ms",
            },
        )
        if payload["schema"] != EVIDENCE_SCHEMA:
            raise SealedDeliveryError()
        resolution = verify_event(payload["resolution_event"], self._sender())
        _, targets = _resolution_payload(
            resolution, message_id=payload["message_id"], scope="/tribe"
        )
        local = recipient_descriptor(self._local(), at_ms=at_ms)
        if (
            resolution["origin"] != evidence["origin"]
            or resolution["occurred_at_ms"]
            != _uint(payload["message_authorized_at_ms"])
            or resolution["occurred_at_ms"] > evidence["occurred_at_ms"]
            or len(targets) != 1
            or targets[0]["recipient_type"] != "relationship"
            or targets[0]["scope_kind"] != "relationship"
            or targets[0]["recipient_id"] != self.policy.recipient_id
            or targets[0]["receipt_origin_embodiment_id"] != local["embodiment_id"]
        ):
            raise SealedDeliveryError()
        proof = {
            self.policy.recipient_id: self._disclosure_from_view(
                authority_view, at_ms=at_ms
            )
        }
        evidence_hash = hashlib.sha256(
            canonical_bytes(
                {
                    "schema": "dm.relationship-delivery-evidence/v1",
                    "resolution_event_hash": resolution["content_hash"],
                    "disclosures": proof,
                }
            )
        ).hexdigest()
        return self._authorization(
            {
                "event_id": payload["message_id"],
                "content_hash": payload["message_hash"],
                "sensitivity": self.policy.classification,
            },
            sender=sender_descriptor(resolution, self._sender(), at_ms=at_ms),
            evidence_hash=evidence_hash,
            authorized_at_ms=payload["message_authorized_at_ms"],
            expires_at_ms=payload["message_expires_at_ms"],
            authorization_id=payload["message_authorization_id"],
            at_ms=at_ms,
        )

    def receive_evidence(self, raw: bytes) -> None:
        now = self.clock()
        envelope = self._envelope(raw, now)
        # Lock order: relationship writer exclusion -> inbox admission. The raw
        # transport bytes have already arrived; no network I/O occurs in this block.
        with self.relationships.authorization_view(
            at_ms=now, card_verifier=self._card
        ) as view:
            policy_hash = self._policy_hash(
                now, view
            )  # Never copy envelope evidence_hash.
            authorization = self._authorization(
                {
                    "event_id": envelope["event_id"],
                    "content_hash": envelope["event_hash"],
                    "sensitivity": envelope["sensitivity"],
                },
                sender=envelope["sender"],
                evidence_hash=policy_hash,
                authorized_at_ms=envelope["issued_at_ms"],
                expires_at_ms=envelope["expires_at_ms"],
                authorization_id=envelope["authorization_id"],
                at_ms=now,
            )
            evidence = self._open(raw, authorization, now)
            self._message_authorization(evidence, now, view)
            self.inbox._retain_evidence(evidence, raw, policy_hash)

    def receive_message(self, raw: bytes) -> dict[str, Any]:
        now = self.clock()
        envelope = self._envelope(raw, now)
        with self.relationships.authorization_view(
            at_ms=now, card_verifier=self._card
        ) as view:
            policy_hash = self._policy_hash(now, view)
            evidence = self.inbox._evidence(
                envelope["event_id"], envelope["authorization_id"], policy_hash
            )
            if evidence is None:
                raise CommunicationError("messaging_evidence_missing", retryable=True)
            evidence = self._verify_retained(evidence)
            authorization = self._message_authorization(evidence, now, view)
            message = self._open(raw, authorization, now)
            admission_version = self.inbox._admission_version(
                message["event_id"], 2 if self.communication is not None else 1
            )
            self._validate_message(
                message,
                evidence,
                authorization,
                now,
                admission_version=admission_version,
                authority_view=view,
            )
            result = self.inbox._retain_message(
                message,
                evidence,
                raw,
                policy_hash,
                admission_version=admission_version,
            )
            self._reduce_receipt(message, admission_version=admission_version)
            return result

    def _semantic_receipt(
        self, message: Mapping[str, Any], *, admission_version: int | None = None
    ) -> dict[str, Any] | None:
        body = message["payload"]["body"]
        if admission_version is None:
            version = 2 if self.communication is not None else 1
        else:
            version = admission_version
        if "semantic_receipt" not in body or self.communication is None or version != 2:
            return None
        receipt = self._verify_retained(body["semantic_receipt"])
        payload = _foreign_receipt_payload(receipt)
        original = self.communication.ledger.event(payload["message_ref"]["event_id"])
        expected = {
            "schema": "dm.messaging.application-response/v1",
            "message_id": payload["message_ref"]["event_id"],
            "message_hash": payload["message_ref"]["event_hash"],
            "sender_being_ref": payload["message_being_ref"],
            "sender_embodiment_id": None
            if original is None
            else original["origin"]["embodiment_id"],
            "thread_id": payload["thread_id"],
        }
        if (
            body.get("response_context") != expected
            or receipt["being_ref"] != message["being_ref"]
            or receipt["origin"] != message["origin"]
            or payload["thread_id"] != message["payload"]["intent"]["thread_id"]
            or receipt["occurred_at_ms"] > message["occurred_at_ms"]
        ):
            raise MessagingInboxError("messaging_semantic_receipt_mismatch")
        with self.communication._database() as database:
            self.communication._validate_foreign_receipt(
                database, receipt, self.policy.peer_being_ref
            )
        return receipt

    def _reduce_receipt(
        self, message: Mapping[str, Any], *, admission_version: int | None = None
    ) -> None:
        receipt = self._semantic_receipt(message, admission_version=admission_version)
        if receipt is not None:
            assert self.communication is not None
            self.communication.record_foreign_receipt(
                receipt, recipient_being_ref=self.policy.peer_being_ref
            )

    def reconcile_receipts(self) -> None:
        """Explicit current-authorized cross-store recovery; no signing or I/O.

        Startup/repeated intake, not page/inspection, reduces retained carriers.
        """
        after = 0
        while True:
            rows = self.inbox._page(
                after=after, limit=100, policy_hash=self._policy_hash(self.clock())
            )
            if not rows:
                return
            self._validate_rows(rows, self.clock())
            for row in rows:
                self._reduce_receipt(
                    row["message"], admission_version=row["admission_version"]
                )
                after = row["inbox_sequence"]

    def _validate_message(
        self,
        message: Mapping[str, Any],
        evidence: Mapping[str, Any],
        authorization: DisclosureAuthorization,
        now: int,
        *,
        admission_version: int | None = None,
        authority_view: RelationshipView | None = None,
    ) -> None:
        if authority_view is None:
            with self.relationships.authorization_view(
                at_ms=now, card_verifier=self._card
            ) as view:
                self._validate_message(
                    message,
                    evidence,
                    authorization,
                    now,
                    admission_version=admission_version,
                    authority_view=view,
                )
                return
        payload = _message_payload(message)
        if (
            payload["intent"]["operation"] != self.policy.operation
            or payload["intent"]["scope"] != "/tribe"
            or payload["body"].get("resource_ref") != self.policy.resource_ref
            or (
                "recipient_being_ref" in payload["body"]
                and payload["body"]["recipient_being_ref"] != self.local_being_ref
            )
        ):
            raise SealedDeliveryError()
        expected = DisclosureAuthorization.from_relationship_resolution_event(
            event=message,
            resolution_event=evidence["payload"]["resolution_event"],
            sender_authority=self._sender(),
            recipient_targets=[self._local()],
            disclosures={
                self.policy.recipient_id: self._disclosure_from_view(
                    authority_view, at_ms=now
                )
            },
            expires_at_ms=authorization.value["expires_at_ms"],
            authorization_id=authorization.value["authorization_id"],
        )
        if expected.value != authorization.value:
            raise SealedDeliveryError()
        self._semantic_receipt(message, admission_version=admission_version)

    def _verify_retained(self, event: Any) -> dict[str, Any]:
        try:
            return dict(verify_event(event, self._sender()))
        except (ValueError, KeyError, TypeError):
            raise MessagingInboxError("messaging_stored_evidence_invalid") from None

    def message(
        self,
        message_id: str,
        *,
        _authority_view: RelationshipView | None = None,
    ) -> dict[str, Any]:
        """Look up exact locally admitted evidence under current authorization."""
        now = self.clock()
        if _authority_view is None:
            with self.relationships.authorization_view(
                at_ms=now, card_verifier=self._card
            ) as view:
                return self.message(message_id, _authority_view=view)
        row = self.inbox._message(
            _uuid(message_id), self._policy_hash(now, _authority_view)
        )
        self._validate_rows([row], now, authority_view=_authority_view)
        return dict(row["message"])

    def page(self, *, after: int, limit: int) -> list[dict[str, Any]]:
        """Manual current-policy read, not a delivered/consumed semantic receipt."""
        now = self.clock()
        # Lock order: relationship writer exclusion -> inbox read. Never hold this
        # context over network I/O and never call a relationship writer from it.
        with self.relationships.authorization_view(
            at_ms=now, card_verifier=self._card
        ) as view:
            rows = self.inbox._page(
                after=after, limit=limit, policy_hash=self._policy_hash(now, view)
            )
            self._validate_rows(rows, now, authority_view=view)
            return [
                {key: value for key, value in row.items() if key != "admission_version"}
                for row in rows
            ]

    def _validate_rows(
        self,
        rows: list[dict[str, Any]],
        now: int,
        authority_view: RelationshipView | None = None,
    ) -> None:
        for row in rows:
            row["message"] = self._verify_retained(row["message"])
            row["evidence"] = self._verify_retained(row["evidence"])
            try:
                authorization = self._message_authorization(
                    row["evidence"], now, authority_view
                )
                self._validate_message(
                    row["message"],
                    row["evidence"],
                    authorization,
                    now,
                    admission_version=row["admission_version"],
                    authority_view=authority_view,
                )
            except (ValueError, KeyError, TypeError):
                raise MessagingInboxError("messaging_stored_evidence_invalid") from None


class GroupMessaging:
    """One membership channel over existing authenticated opaque route providers.

    A single durable carrier obligation gates every copy of the exact frame. Its
    human projection is admitted once, independently of the number of transports.
    Transport ACKs never close semantic legs; only verified member receipts do.
    All work is synchronous with an explicit send/intake, with no model wakeup.
    """

    def __init__(
        self,
        *,
        lane: TribeConversation,
        policy: MessagingTribePolicy,
        communication: CommunicationStore,
        providers: Mapping[tuple[str, str], Any],
        config_digest: str,
        egress: MandatoryEgressController,
        labels: LabelIndex | None = None,
        direct_reader_ready: Callable[[Mapping[str, Any]], bool] | None = None,
        controlled_readers: bool = False,
        loaded_store_bindings: tuple[LoadedStoreBinding, ...] = (),
    ) -> None:
        if type(controlled_readers) is not bool or (
            controlled_readers and direct_reader_ready is not None
        ):
            raise ValueError("tribe_reader_composition_invalid")
        self._controlled_readers = controlled_readers
        self._loaded_store_bindings = tuple(loaded_store_bindings)
        self.lane, self.policy = lane, policy
        self.ledger, self.signer = lane.ledger, lane.signer
        self.inbox = self.records = lane.records
        self.communication, self.providers = communication, dict(providers)
        self.config_digest, self.egress, self.labels = config_digest, egress, labels
        egress.register_reader_channel(
            "tribe", config_digest, controlled=controlled_readers
        )
        self._default_reader_guard = lambda row: egress.reader_ready("tribe", row)
        self.direct_reader_ready = (
            self._default_reader_guard
            if direct_reader_ready is None
            else direct_reader_ready
        )
        self.intake_ingresses: dict[str, Any] = {}
        self._receipt_lock = threading.Lock()
        self._receipt_inflight: set[str] = set()
        self._speech_slots = egress._group_speech_slots
        self._control_slots = egress._group_control_slots
        self._send_slots = egress._group_send_slots
        self._transport_lock = egress._group_transport_lock
        self._transport_inflight = egress._group_transport_inflight
        self.records.bind_egress(
            egress,
            catalog_id="tribe-carriers",
            authorize=self._authorize,
        )

    @property
    def controlled_readers(self) -> bool:
        """Verified owner startup selects this mode; requests cannot change it."""
        return self._controlled_readers

    def validate(self, service: Any) -> None:
        for binding in self._loaded_store_bindings:
            binding.verify()
        if self.ledger is not service.ledger or self.signer is not service.signer:
            raise ValueError("tribe_runtime_binding")
        self.lane._operational(
            self.lane.being_ref,
            self.lane.local_credential_id,
            self.lane.local_embodiment_id,
            self.lane.clock(),
        )

    def initialize_reader_recovery(self, service: Any) -> None:
        """Attach durable owner controls only at a fully qualified serving boot."""
        if not self.controlled_readers:
            return
        base = json.loads(service.loaded_runtime or b"null")
        app = json.loads(service.loaded_application or b"null")
        base_fields = {
            "schema",
            "runtime_id",
            "local_origin",
            "runtime_bundle_sha256",
            "startup",
            "qualified_startup",
            "authority_epoch",
            "state_root_identity",
            "stores",
            "process_id",
            "process_instance_id",
        }
        app_fields = {
            "schema",
            "loaded_base_sha256",
            "loaded_view_sha256",
            "reader_gates",
            "application_sha256",
            "config_sha256",
            "publication",
            "publication_sha256",
            "stores",
            "shared_stores",
            "shared_relationships",
            "communication_store_role",
            "tribe",
            "visibility",
            "authorities",
        }
        startup_fields = {
            "schema",
            "code_digest",
            "sdk_digest",
            "matrix_commit",
            "matrix_wheel_sha256",
            "import_context_sha256",
            "import_files_sha256",
            "interpreter",
            "reader",
            "isolated",
            "no_site",
            "no_bytecode",
            "process_id",
            "startup_instance_id",
        }
        if (
            not isinstance(base, dict)
            or set(base) != base_fields
            or not isinstance(app, dict)
            or set(app) != app_fields
            or base["schema"] != "dm.runtime.loaded-base/v1"
            or app["schema"] != "dm.runtime.loaded-application/v1"
            or not isinstance(base["qualified_startup"], dict)
            or set(base["qualified_startup"]) != startup_fields
        ):
            # Bare fixtures and historical loaders cannot advertise this feature.
            return
        self.validate(service)
        stable_base = {
            key: value
            for key, value in base.items()
            if key not in {"process_id", "process_instance_id"}
        }
        stable_base["qualified_startup"] = {
            key: value
            for key, value in base["qualified_startup"].items()
            if key not in {"process_id", "startup_instance_id"}
        }
        capability = service.capabilities[service.receiving.capability_id]
        binding = {
            "base": stable_base,
            "application": {
                key: value
                for key, value in app.items()
                if key
                not in {"loaded_base_sha256", "loaded_view_sha256", "reader_gates"}
            },
            "controller": capability.descriptor,
            "credential_id": self.lane.local_credential_id,
        }
        self.egress.initialize_reader_recovery(
            "tribe",
            binding=binding,
            boot={"base": base, "application": app},
            load=self.records.reader_control_head,
            append=self.records.append_reader_control,
            authorization=self.selection_authorization,
        )

    def _verify_loaded_stores(self) -> None:
        """A changed physical store is uncertain storage, not a peer refusal."""
        try:
            for binding in self._loaded_store_bindings:
                binding.verify()
        except (ValueError, OSError) as failure:
            raise RouteAmbiguous("tribe_loaded_store_uncertain") from failure

    def _authorize(self, binding: OperationBinding) -> bool:
        try:
            for store in self._loaded_store_bindings:
                store.verify()
            self.lane._operational(
                self.lane.being_ref,
                self.lane.local_credential_id,
                self.lane.local_embodiment_id,
                self.lane.clock(),
            )
            if binding.authority_head != self.ledger.local_origin["body_ref"]:
                return False
            if binding.catalog_id != self.records.catalog_id:
                # Incoming transport ACKs are owned by their opaque-response
                # catalogs. They share current body/authority checks, but are
                # not Tribe carriers and have no Tribe-native/recovery record.
                return (binding.catalog_id, binding.path_id) in {
                    ("messaging-message-responses", "messaging-message-result"),
                    ("messaging-evidence-responses", "messaging-evidence-result"),
                }
            native = self.records.get("native", binding.locator)
            if native is None:
                return False
            carrier = _parse(unb64url(native["native"]))
            recovery = self.records.get("recovery", binding.operation_id)
            if carrier.get("schema") == "dm.tribe.recovery-conversation/v1":
                if (
                    recovery is None
                    or recovery["recovery_id"] != binding.operation_id
                    or carrier.get("recovery") != recovery["event"]
                ):
                    return False
                self._validate_recovery_parent(recovery)
            elif recovery is not None:
                return False
            return True
        except ValueError:
            return False

    def _policy_hash(self, _at_ms: int) -> str:
        # Historical reads do not acquire today's membership or resource grants.
        return self.config_digest

    def message(self, message_id: str) -> Mapping[str, Any]:
        record = self.records.get("inbox", _uuid(message_id))
        if record is None:
            raise ValueError("tribe_message_missing")
        message = record["message"]
        return verify_event(
            message, self.lane._epoch(message["being_ref"], message["manifest_hash"])
        )

    def page(self, *, after: int, limit: int) -> list[dict[str, Any]]:
        result = self.records.page(after=after, limit=limit)
        for item in result["items"]:
            self.message(item["message"]["event_id"])
        return cast(list[dict[str, Any]], result["items"])

    def inspect(
        self, *, client_id: str, send_id: str, response_channels: tuple[Any, ...] = ()
    ) -> dict[str, Any]:
        request = self.records.get("request", _uuid(send_id))
        if request is None or request["client_id"] != client_id:
            raise ValueError("tribe_send_missing")
        retained = self.records.get("result", send_id)
        if retained is None:
            raise ValueError("tribe_send_missing")
        message = self.ledger.event(retained["message_id"])
        if message is None:
            raise ValueError("tribe_send_missing")
        return self._result(message, send_id)

    def _result(self, message: Any, send_id: str) -> dict[str, Any]:
        semantic = self.communication.result(message["event_id"])
        plan = self.records.get("send", send_id)
        if plan is None:
            raise ValueError("tribe_send_missing")
        transport = []
        members: dict[str, dict[str, Any]] = {}
        legs = {
            (leg["recipient_id"], leg["receipt_origin_embodiment_id"]): leg
            for leg in semantic["legs"]
        }
        for row in message["payload"]["body"]["audience"]:
            target = (row["being_ref"], row["embodiment_id"])
            leg = legs[(row["membership_ref"], row["embodiment_id"])]
            author = target == (
                message["being_ref"],
                message["origin"]["embodiment_id"],
            )
            member = members.setdefault(
                row["being_ref"],
                {
                    "being_ref": row["being_ref"],
                    "membership_ref": row["membership_ref"],
                    "body_count": 0,
                    "receiving_copy": "unknown",
                    "receiving_leg_ids": [],
                    "author_retained_leg_ids": [],
                },
            )
            member["body_count"] += 1
            # CommunicationStore has reverified each terminal receipt. The
            # author's local retention is not receiving uptake, even though its
            # existing semantic leg also uses the delivered outcome.
            if leg["state"] == "delivered":
                if author:
                    member["author_retained_leg_ids"].append(leg["leg_id"])
                else:
                    member["receiving_copy"] = "proved"
                    member["receiving_leg_ids"].append(leg["leg_id"])
            state, proof_hash = "pending", None
            failure = None
            route = "available" if target in self.providers else "unavailable"
            attempt = "not-attempted"
            if author:
                state = "author-retained"
                route, attempt = "not-required", "author-retained"
            else:
                request_id = str(
                    uuid.uuid5(
                        uuid.UUID(send_id),
                        f"tribe-transport/v1:{target[0]}:{target[1]}",
                    )
                )
                proof = self.records.transport_result(request_id)
                if proof is not None:
                    state = proof["result"]["outcome"]
                    attempt = state
                    proof_hash = hashlib.sha256(unb64url(proof["response"])).hexdigest()
                else:
                    # A readiness refusal occurs before transport preparation;
                    # it still has a retained diagnostic. Current readiness is
                    # evaluated separately below, never used to rewrite history.
                    with (
                        suppress(OSError, sqlite3.Error, ValueError),
                        self.egress.local_storage(),
                    ):
                        failure = read_diagnostic(
                            self.records.path, "route", request_id
                        )
                    if self.records.get("transport", request_id) is not None:
                        attempt = "unconfirmed"
                    elif route == "unavailable":
                        state = "unroutable"
                    elif self.lane.clock() >= plan["expires_at_ms"]:
                        state = "expired"
                    elif (
                        failure is not None
                        and failure["code"] == "tribe_reader_unconfirmed"
                    ):
                        state = "blocked"
            transport.append(
                {
                    "being_ref": target[0],
                    "embodiment_id": target[1],
                    "state": state,
                    "response_sha256": proof_hash,
                    "attempt_state": attempt,
                    "current_route": route,
                    **({"last_failure": failure} if failure is not None else {}),
                    **(
                        {"reason_code": "carrier_expired_before_attempt"}
                        if not author
                        and attempt == "not-attempted"
                        and self.lane.clock() >= plan["expires_at_ms"]
                        else {}
                    ),
                }
            )
        result = {
            "schema": "dm.tribe.delivery/v1",
            "send_id": send_id,
            "message_id": message["event_id"],
            "message_hash": message["content_hash"],
            "author": {
                "being_ref": message["being_ref"],
                "embodiment_id": message["origin"]["embodiment_id"],
            },
            "response_context": message["payload"]["body"].get("response_context"),
            "thread_id": message["payload"]["intent"]["thread_id"],
            "tribe_ref": self.policy.tribe_ref,
            "audience": message["payload"]["body"]["audience"],
            "semantic": semantic,
            "members": [members[ref] for ref in sorted(members)],
            "transport": transport,
            "carrier": {
                "expires_at_ms": plan["expires_at_ms"],
                "expired": self.lane.clock() >= plan["expires_at_ms"],
            },
            # Inspect the existing obligation without preparing visibility or
            # releasing native bytes. An authored event alone is not echo proof.
            "visibility": (
                self.egress.inspect_retained(
                    self.egress.binding("tribe-carriers", send_id)
                )
                if self.records.get("native", send_id) is not None
                else None
            ),
        }
        recovery_selection = self.records.get("recovery-selection", send_id)
        if recovery_selection is not None:
            recovery_id = recovery_selection["recovery_id"]
            recovery = self.records.get("recovery", recovery_id)
            if recovery is None:
                result["recovery"] = {
                    "recovery_id": recovery_id,
                    "state": "unavailable",
                    "reason_code": "recovery_record_missing",
                }
            else:
                recovered_transport = []
                for row in message["payload"]["body"]["audience"]:
                    if (row["being_ref"], row["embodiment_id"]) == (
                        message["being_ref"],
                        message["origin"]["embodiment_id"],
                    ):
                        continue
                    request_id = str(
                        uuid.uuid5(
                            uuid.UUID(recovery_id),
                            f"tribe-transport/v1:{row['being_ref']}:{row['embodiment_id']}",
                        )
                    )
                    proof = self.records.transport_result(request_id)
                    carrier_attempt = self.records.get("transport", request_id)
                    recovered_transport.append(
                        {
                            "being_ref": row["being_ref"],
                            "embodiment_id": row["embodiment_id"],
                            "state": proof["result"]["outcome"]
                            if proof is not None
                            else "unconfirmed"
                            if carrier_attempt is not None
                            else "expired"
                            if self.lane.clock() >= recovery["expires_at_ms"]
                            else "not-attempted",
                            "response_sha256": None
                            if proof is None
                            else hashlib.sha256(
                                unb64url(proof["response"])
                            ).hexdigest(),
                        }
                    )
                result["recovery"] = {
                    "recovery_id": recovery_id,
                    "expires_at_ms": recovery["expires_at_ms"],
                    "expired": self.lane.clock() >= recovery["expires_at_ms"],
                    "original_publication": "confirmed-by-reference"
                    if result["visibility"] is not None
                    and result["visibility"]["echo_state"] == "confirmed"
                    else "unconfirmed",
                    "transport": recovered_transport,
                    "native_visibility": self.egress.inspect_retained(
                        self.egress.binding("tribe-carriers", recovery_id)
                    )
                    if self.records.get("native", recovery_id) is not None
                    else None,
                }
        destination = message["payload"]["body"].get("destination")
        if destination is not None:
            result.update(
                schema="dm.tribe.direct-delivery/v1",
                destination=destination,
                author_retention={
                    "being_ref": message["being_ref"],
                    "embodiment_id": message["origin"]["embodiment_id"],
                    "message_id": message["event_id"],
                    "state": "authored-local",
                },
            )
        if destination is not None or self.controlled_readers:
            requirements = self._reader_requirements(plan, message["manifest_hash"])
            for row, outcome in zip(
                message["payload"]["body"]["audience"], transport, strict=True
            ):
                outcome["reader_readiness"] = self._direct_ready(
                    row,
                    requirements=requirements,
                )
        return result

    def _reader_requirements(
        self,
        plan: Mapping[str, Any] | None,
        sender_manifest_hash: str,
        *,
        events: list[dict[str, Any]] | None = None,
    ) -> tuple[str, tuple[str, ...]]:
        # Send lookup uses the retained plan before the physical-write fence.
        # The controller also reuses this proof verification while holding its
        # local roster authorization view and selection fence (no network I/O).
        if plan is None:
            raise ValueError("tribe_readiness_evidence_missing")
        epochs = {sender_manifest_hash, *plan["epochs"].values()}
        events = self.lane.relationships.events() if events is None else events
        for proof in [plan["sender_proof"], *plan["proofs"].values()]:
            matching = [
                event
                for event in events
                if (event["event_id"], event["content_hash"])
                == (proof["membership_event_id"], proof["membership_event_hash"])
            ]
            if len(matching) != 1:
                raise ValueError("tribe_readiness_evidence_missing")
            try:
                event = self.lane.relationships._validated_event(matching[0])
            except RelationshipStoreError:
                raise ValueError("tribe_readiness_evidence_invalid") from None
            epochs.add(event["manifest_hash"])
        return (
            "dm.tribe.direct-conversation/v1"
            if "destination" in plan
            else "dm.tribe.conversation/v1",
            tuple(sorted(epochs)),
        )

    def _receiving_roster(self, view: RelationshipView, now: int) -> dict[str, Any]:
        """Derive only public audience/proof facts from the held verified view."""
        from .tribe_conversation import MembershipAuthorizer

        snapshot = view.snapshot(self.policy.tribe_ref)
        members = snapshot.value["members"]
        rows = list(self.lane.audience(snapshot))
        if not 1 <= len(rows) <= 256:
            raise ValueError("tribe_readiness_roster_invalid")
        own = [
            row
            for row in members
            if row["principal_id"] == self.lane.being_ref and row["state"] == "active"
        ]
        if len(own) != 1:
            raise ValueError("tribe_readiness_roster_invalid")
        authorizer = MembershipAuthorizer(view.all_events)
        proofs = authorizer.proofs(members=members, tribe_ref=self.policy.tribe_ref)
        sender = authorizer.proof(
            membership_ref=own[0]["membership_ref"],
            tribe_ref=self.policy.tribe_ref,
            principal_id=self.lane.being_ref,
        )
        epochs = {
            row["being_ref"]: self.lane._active(row["being_ref"]).manifest.digest
            for row in rows
        }
        plan = dict(epochs=epochs, proofs=proofs, sender_proof=sender)
        _, required = self._reader_requirements(
            plan, self.lane.authority.manifest.digest, events=view.all_events
        )
        if len(required) > 256 or len(proofs) > 256:
            raise ValueError("tribe_readiness_roster_invalid")
        proof_rows = []
        for proof in proofs.values():
            event = next(
                event
                for event in view.all_events
                if (event["event_id"], event["content_hash"])
                == (proof["membership_event_id"], proof["membership_event_hash"])
            )
            proof_rows.append(
                {
                    **proof,
                    "signer_being_ref": event["being_ref"],
                    "signer_manifest_hash": event["manifest_hash"],
                }
            )
        body = dict(
            schema="dm.runtime.tribe-roster/v1",
            tribe_ref=self.policy.tribe_ref,
            lineage_head_ref=snapshot.value["lineage_head_ref"],
            audience=sorted(
                [
                    {**row, "authority_manifest_hash": epochs[row["being_ref"]]}
                    for row in rows
                ],
                key=lambda row: (row["being_ref"], row["embodiment_id"]),
            ),
            membership_proofs=sorted(proof_rows, key=lambda row: row["membership_ref"]),
            required_authority_epochs=list(required),
        )
        return {
            **body,
            "roster_sha256": hashlib.sha256(canonical_bytes(body)).hexdigest(),
            "evaluated_at_ms": now,
        }

    def receiving_roster(self) -> dict[str, Any]:
        """Current verified roster, separate from immutable boot/gate evidence."""
        self._verify_loaded_stores()
        now = self.lane.clock()
        with self.lane.relationships.authorization_view(
            at_ms=now, card_verifier=self.lane.card_verifier, busy_timeout_ms=0
        ) as view:
            roster = self._receiving_roster(view, now)
            self._verify_loaded_stores()
            return roster

    @contextmanager
    def selection_authorization(
        self,
        expected_roster_sha256: str,
        *,
        readers: list[dict[str, Any]] | None = None,
    ) -> Iterator[None]:
        """Called under physical fence; hold the local roster through selection.

        Lock order is physical fence -> relationship transaction, matching
        release authorization. Do no network calls or owner RPC in this scope.
        Contended history fails immediately rather than extending the budget.
        """
        self._verify_loaded_stores()
        now = self.lane.clock()
        with self.lane.relationships.authorization_view(
            at_ms=now, card_verifier=self.lane.card_verifier, busy_timeout_ms=0
        ) as view:
            roster = self._receiving_roster(view, now)
            if roster["roster_sha256"] != expected_roster_sha256:
                raise ValueError("reader_roster_conflict")
            for row in readers or []:
                if row.get("schema") != READER_VALIDITY_SCHEMA:
                    continue
                try:
                    if not any(
                        all(
                            candidate[key] == row[key]
                            for key in (
                                "being_ref",
                                "embodiment_id",
                                "credential_id",
                                "authority_manifest_hash",
                            )
                        )
                        for candidate in roster["audience"]
                    ):
                        raise ValueError("reader_validity_conflict")
                    authority = self.lane._active(row["being_ref"])
                    member = authority.manifest.member(
                        row["embodiment_id"], row["incarnation_id"]
                    )
                    if (
                        member["status"] != "active"
                        or member["embodiment_credential_id"] != row["credential_id"]
                    ):
                        raise ValueError("reader_validity_conflict")
                    credential = authority.credentials[row["credential_id"]]
                    body = verify_embodiment_credential(
                        credential, authority.state, at_ms=now
                    )
                    verify_incarnation_authorization(
                        authority.incarnations[member["incarnation_authorization_id"]],
                        credential,
                        authority.state,
                        at_ms=now,
                    )
                    actual = body.get(
                        "validity",
                        {
                            "mode": "finite",
                            "not_before_ms": body.get("valid_from_ms"),
                            "not_after_ms": body.get("valid_until_ms"),
                        },
                    )
                    if not validity_attenuates(row["validity"], actual):
                        raise ValueError("reader_validity_conflict")
                except (KeyError, VerificationError):
                    raise ValueError("reader_validity_conflict") from None
            self._verify_loaded_stores()
            yield

    def _direct_ready(
        self,
        row: Mapping[str, Any],
        *,
        requirements: tuple[str, tuple[str, ...]] | None = None,
    ) -> bool:
        # A route or prepared wheel never establishes a loaded compatible reader.
        # This owner-local guard is supplied by the receiving cohort controller;
        # refreshable evidence is not part of immutable retry/config bindings.
        try:
            if (
                self.controlled_readers
                or self.direct_reader_ready is self._default_reader_guard
            ):
                return requirements is not None and self.egress.reader_ready(
                    "tribe",
                    row,
                    required_wire=requirements[0],
                    required_authority_epochs=requirements[1],
                )
            return (
                self.direct_reader_ready is not None
                and self.direct_reader_ready(row) is True
            )
        except (OSError, ValueError):
            return False

    def send(
        self,
        *,
        client_id: str,
        send_id: str,
        thread_id: str,
        text: str,
        response_to: tuple[Any, str] | None = None,
        authorize: Callable[[], None] | None = None,
        destination: Mapping[str, str] | None = None,
    ) -> dict[str, Any]:
        if authorize is not None:
            authorize()
        response = None
        if response_to is not None:
            if response_to[0] is not self:
                raise ValueError("tribe_reply_channel_mismatch")
            parent = self.message(response_to[1])
            if parent["payload"]["intent"]["thread_id"] != thread_id:
                raise ValueError("tribe_reply_thread_mismatch")
            response = {
                "message_id": parent["event_id"],
                "message_hash": parent["content_hash"],
                "sender_being_ref": parent["being_ref"],
                "sender_embodiment_id": parent["origin"]["embodiment_id"],
            }
            parent_destination = parent["payload"]["body"].get("destination")
            reply_destination = None
            if parent_destination is not None:
                reply_destination = {
                    "kind": parent_destination["kind"],
                    "being_ref": parent["being_ref"],
                }
                if parent_destination["kind"] == "body":
                    reply_destination["embodiment_id"] = parent["origin"][
                        "embodiment_id"
                    ]
            if (
                destination is not None
                and direct_destination(destination) != reply_destination
            ):
                raise ValueError("tribe_reply_destination_mismatch")
            destination = reply_destination
        if destination is not None:
            destination = direct_destination(destination)
        parameters = {
            "client_id": client_id,
            "thread_id": thread_id,
            "text": text,
            "response_to": None if response_to is None else response_to[1],
            **({"destination": dict(destination)} if destination is not None else {}),
        }
        self.records.reserve("request", send_id, parameters, lambda: parameters)
        if self.records.get("send", send_id) is None:
            snapshot = self.lane.snapshot(self.policy.tribe_ref, self.lane.clock())
            if not any(
                member["principal_id"] == self.lane.being_ref
                and member["membership_ref"] == self.policy.membership_ref
                and member["state"] == "active"
                for member in snapshot.value["members"]
            ):
                raise ValueError("tribe_membership_binding")
        prepared = self.lane.prepare(
            text=text,
            request_id=send_id,
            tribe_ref=self.policy.tribe_ref,
            thread_id=thread_id,
            ttl_ms=self.policy.max_ttl_ms,
            sensitivity={
                "public": "shareable",
                "shareable": "shareable",
                "private": "private",
            }[self.policy.classification],
            response_context=response,
            destination=destination,
        )
        message, resolution = prepared["message"], prepared["resolution"]
        identifiers = {
            "message_id": message["event_id"],
            "resolution_id": resolution["event_id"],
        }
        self.records.reserve("result", send_id, identifiers, lambda: identifiers)
        self.communication.accept(
            message_event_id=message["event_id"],
            resolution_event_id=resolution["event_id"],
        )
        if destination is None:
            own_receipt = self.lane._author_receipt(
                message,
                resolution,
                membership_ref=self.policy.membership_ref,
                now=self.lane.clock(),
                authored_local=True,
            )
            self.communication.record_receipt(own_receipt["event_id"])
        if self.lane.clock() >= prepared["expires_at_ms"]:
            return self._result(message, send_id)
        native = canonical_bytes(prepared["payload"])
        sender = _sender_display(
            self.labels, message["origin"], message["being_ref"], body_fallback=True
        )
        # This producer has already authenticated the membership group and
        # frozen its full body audience. Present its logical destination, not
        # its physical fanout; mentions in the text do not narrow that audience.
        # Retained native projections below preserve historical publication.
        recipients = ["Tribu"]
        if destination is not None:
            recipients = [
                "Direct · "
                + _sender_display(
                    self.labels,
                    destination,
                    destination["being_ref"],
                    body_fallback=destination["kind"] == "body",
                )
            ]
        projection: dict[str, Any] = {
            "event_id": message["event_id"],
            "event_digest": message["content_hash"],
            "sender": sender,
            "recipients": recipients,
            "thread_id": thread_id,
            "kind": "message",
            "reply_to": None,
            "content": {"text": text},
        }
        if response_to is not None:
            projection.update(
                kind="reply",
                reply_to={
                    "event_id": parent["event_id"],
                    "event_digest": parent["content_hash"],
                    "sender": _sender_display(
                        self.labels,
                        parent["origin"],
                        parent["being_ref"],
                        body_fallback=True,
                    ),
                    "text": parent["payload"]["body"]["text"][:160],
                },
            )
            parent_audience = {
                (row["being_ref"], row["membership_ref"], row["embodiment_id"])
                for row in parent["payload"]["body"]["audience"]
            }
            audience = {
                (row["being_ref"], row["membership_ref"], row["embodiment_id"])
                for row in message["payload"]["body"]["audience"]
            }
            if destination is not None or not audience <= parent_audience:
                # Correlation is authorized by the verified parent; copying
                # parent plaintext requires its separate disclosure provenance.
                # A later group audience may include newly admitted members or
                # bodies that were never recipients of that original message.
                projection["reply_to"].pop("text")
                projection["reply_to"].pop("sender")
        retained_native = self.records.get("native", send_id)
        if retained_native is not None:
            projection = retained_native["projection"]
        operation = self.records.admit(
            send_id,
            native,
            path_id="tribe-message-request",
            projection=projection,
            deadline_ms=prepared["expires_at_ms"],
            authority_head=self.ledger.local_origin["body_ref"],
        )
        # Even an unreachable first route must not let later copies bypass the
        # one logical message's mandatory confirmed visibility.
        self.egress.prepare_visibility(operation)
        completed = {
            (leg["recipient_id"], leg["receipt_origin_embodiment_id"])
            for leg in self.communication.result(message["event_id"])["legs"]
            if leg["state"] == "delivered"
        }
        eligible = []
        requirements = (
            self._reader_requirements(
                self.records.get("send", send_id), message["manifest_hash"]
            )
            if destination is not None or self.controlled_readers
            else None
        )
        for row in prepared["rows"]:
            if (row["being_ref"], row["embodiment_id"]) == (
                self.lane.being_ref,
                self.lane.local_embodiment_id,
            ):
                continue
            if (row["membership_ref"], row["embodiment_id"]) in completed:
                continue
            if (
                destination is not None or self.controlled_readers
            ) and not self._direct_ready(row, requirements=requirements):
                self._record_reader_block(send_id, row)
                continue
            eligible.append(row)
        self._fanout(native, eligible, operation, authorize=authorize)
        return self._result(message, send_id)

    def _validate_recovery_parent(
        self, recovery: Mapping[str, Any]
    ) -> OperationBinding:
        """Recheck the exact original publication at every physical release."""
        original_id = recovery["original_send_id"]
        parent = self.egress.binding("tribe-carriers", original_id)
        publication_hash = hashlib.sha256(canonical_bytes(asdict(parent))).hexdigest()
        if publication_hash != recovery["original_publication_sha256"]:
            raise ValueError("tribe_recovery_publication_changed")
        publication = self.egress.inspect_retained(parent)
        if (
            publication["echo_state"] != "confirmed"
            or publication["completed_releases"]
        ):
            raise ValueError("tribe_recovery_original_not_unattempted")
        native = self.records.get("native", original_id)
        plan = self.records.get("send", original_id)
        if native is None or plan is None:
            raise ValueError("tribe_recovery_original_missing")
        raw = unb64url(native["native"])
        if hashlib.sha256(raw).hexdigest() != recovery["original_carrier_sha256"]:
            raise ValueError("tribe_recovery_original_changed")
        result = self.records.get("result", original_id)
        if result is None:
            raise ValueError("tribe_recovery_original_missing")
        message = self.ledger.event(result["message_id"])
        if (
            message is None
            or message["content_hash"] != recovery["message_hash"]
            or native["projection"]["event_id"] != message["event_id"]
            or native["projection"]["event_digest"] != message["content_hash"]
        ):
            raise ValueError("tribe_recovery_original_changed")
        for row in plan["rows"]:
            transport_id = str(
                uuid.uuid5(
                    uuid.UUID(original_id),
                    f"tribe-transport/v1:{row['being_ref']}:{row['embodiment_id']}",
                )
            )
            if self.records.get("transport", transport_id) is not None:
                raise ValueError("tribe_recovery_original_attempt_uncertain")
        # Verify this technical authorization, never a caller-authored parent pointer.
        event = verify_event(
            recovery["event"],
            self.lane._epoch(message["being_ref"], message["manifest_hash"]),
        )
        body = event["payload"]
        for key in (
            "original_send_id",
            "message_hash",
            "original_carrier_sha256",
            "original_publication_sha256",
        ):
            if body[key] != recovery[key]:
                raise ValueError("tribe_recovery_proof_conflict")
        if event["origin"] != message["origin"]:
            raise ValueError("tribe_recovery_original_author_required")
        current = self.lane.snapshot(self.policy.tribe_ref, self.lane.clock())
        active = {
            m["principal_id"]
            for m in current.value["members"]
            if m["state"] == "active"
        }
        if not {self.lane.being_ref, *[r["being_ref"] for r in plan["rows"]]} <= active:
            raise ValueError("tribe_recovery_membership_changed")
        return parent

    def recover(
        self,
        *,
        client_id: str,
        original_send_id: str,
        recovery_id: str,
        authorize: Callable[[], None] | None = None,
    ) -> dict[str, Any]:
        """Explicit one-carrier recovery, retaining original speech and audience.

        First slice accepts only an expired, confirmed, provably never-attempted
        original. Unknown attempts are never permission to remint a carrier.
        """
        from .tribe_conversation import TRIBE_RECOVERY_SCHEMA

        if authorize is not None:
            authorize()
        original_send_id, recovery_id = _uuid(original_send_id), _uuid(recovery_id)
        if original_send_id == recovery_id:
            raise ValueError("tribe_recovery_distinct_control_required")
        request = self.records.get("request", original_send_id)
        result = self.records.get("result", original_send_id)
        plan = self.records.get("send", original_send_id)
        if (
            request is None
            or request["client_id"] != client_id
            or result is None
            or plan is None
        ):
            raise ValueError("tribe_send_missing")
        if self.lane.clock() < plan["expires_at_ms"]:
            raise ValueError("tribe_recovery_original_not_expired")
        retained_recovery = self.records.get("recovery", recovery_id)
        if (
            retained_recovery is not None
            and retained_recovery["original_send_id"] != original_send_id
        ):
            raise ValueError("tribe_record_request_conflict")
        if (
            retained_recovery is not None
            and self.lane.clock() >= retained_recovery["expires_at_ms"]
        ):
            message = self.ledger.event(result["message_id"])
            if message is None:
                raise ValueError("tribe_send_missing")
            return self._result(message, original_send_id)
        # Plain JSON intentionally publishes technical controls; that receiving
        # profile cannot satisfy reuse of the original single visible speech.
        if self.egress.representation == "plain-json/v2":
            raise ValueError("tribe_recovery_visibility_profile_unsupported")
        message = self.ledger.event(result["message_id"])
        resolution = self.ledger.event(result["resolution_id"])
        if message is None or resolution is None:
            raise ValueError("tribe_send_missing")
        parent = self.egress.binding("tribe-carriers", original_send_id)
        native = self.records.get("native", original_send_id)
        if native is None:
            raise ValueError("tribe_recovery_original_missing")
        parent_reference = {
            "original_send_id": original_send_id,
            "message_hash": message["content_hash"],
            "original_carrier_sha256": hashlib.sha256(
                unb64url(native["native"])
            ).hexdigest(),
            "original_publication_sha256": hashlib.sha256(
                canonical_bytes(asdict(parent))
            ).hexdigest(),
        }
        # Check original uncertainty before creating any technical authorization.
        publication = self.egress.inspect_retained(parent)
        if (
            publication["echo_state"] != "confirmed"
            or publication["completed_releases"]
        ):
            raise ValueError("tribe_recovery_original_not_unattempted")
        for row in plan["rows"]:
            transport_id = str(
                uuid.uuid5(
                    uuid.UUID(original_send_id),
                    f"tribe-transport/v1:{row['being_ref']}:{row['embodiment_id']}",
                )
            )
            if self.records.get("transport", transport_id) is not None:
                raise ValueError("tribe_recovery_original_attempt_uncertain")
        self.records.reserve(
            "recovery-selection",
            original_send_id,
            {"recovery_id": recovery_id},
            lambda: {"recovery_id": recovery_id},
        )
        prepared = self.lane.prepare_recovery(
            original_send_id=original_send_id,
            recovery_id=recovery_id,
            message=message,
            resolution=resolution,
            original_publication_sha256=parent_reference["original_publication_sha256"],
            ttl_ms=self.policy.max_ttl_ms,
        )
        recovery = {
            **parent_reference,
            "event": prepared["recovery"],
            "recovery_id": recovery_id,
            "expires_at_ms": prepared["expires_at_ms"],
        }
        self.records.reserve("recovery", recovery_id, recovery, lambda: recovery)
        self._validate_recovery_parent(recovery)
        if self.lane.clock() < prepared["expires_at_ms"]:
            projection = {
                **native["projection"],
                "event_id": prepared["recovery"]["event_id"],
                "event_digest": prepared["recovery"]["content_hash"],
                "kind": "authorization-control",
                "content": {"stage": "converse"},
                "reply_to": {
                    "event_id": message["event_id"],
                    "event_digest": message["content_hash"],
                },
            }
            operation = self.records.admit(
                recovery_id,
                canonical_bytes(prepared["payload"]),
                path_id="tribe-message-request",
                projection=projection,
                deadline_ms=prepared["expires_at_ms"],
                authority_head=self.ledger.local_origin["body_ref"],
            )
            self.egress.prepare_visibility(operation)
            epochs = self._reader_requirements(plan, message["manifest_hash"])[1]
            completed = {
                (leg["recipient_id"], leg["receipt_origin_embodiment_id"])
                for leg in self.communication.result(message["event_id"])["legs"]
                if leg["state"] == "delivered"
            }
            rows = []
            for row in prepared["rows"]:
                if (row["being_ref"], row["embodiment_id"]) == (
                    self.lane.being_ref,
                    self.lane.local_embodiment_id,
                ):
                    continue
                if (row["membership_ref"], row["embodiment_id"]) in completed:
                    continue
                if not self._direct_ready(
                    row, requirements=(TRIBE_RECOVERY_SCHEMA, epochs)
                ):
                    self._record_reader_block(recovery_id, row)
                    continue
                rows.append(row)
            self._fanout(
                canonical_bytes(prepared["payload"]),
                rows,
                operation,
                authorize=authorize,
            )
        return self._result(message, original_send_id)

    def _record_reader_block(
        self,
        operation_id: str,
        row: Mapping[str, Any],
        *,
        deadline_ns: int | None = None,
    ) -> None:
        request_id = str(
            uuid.uuid5(
                uuid.UUID(operation_id),
                f"tribe-transport/v1:{row['being_ref']}:{row['embodiment_id']}",
            )
        )
        # This is a safe diagnostic, not a transport attempt or receiver proof.
        # A contended/corrupt sidecar cannot change the message's native outcome.
        with (
            suppress(OSError, sqlite3.Error, ValueError),
            self.egress.local_storage(deadline_ns=deadline_ns),
        ):
            write_diagnostic(
                self.records.path,
                "route",
                request_id,
                "tribe_reader_unconfirmed",
                self.lane.clock(),
                timeout=0,
            )

    def _claim_transport(
        self, row: Mapping[str, Any], operation: OperationBinding, *, receipt: bool
    ) -> bool:
        marker = (operation.operation_id, row["being_ref"], row["embodiment_id"])
        slots = self._control_slots if receipt else self._speech_slots
        with self._transport_lock:
            if marker in self._transport_inflight or not slots.acquire(blocking=False):
                return False
            self._transport_inflight.add(marker)
            return True

    def _finish_transport(
        self, row: Mapping[str, Any], operation: OperationBinding, *, receipt: bool
    ) -> None:
        marker = (operation.operation_id, row["being_ref"], row["embodiment_id"])
        with self._transport_lock:
            self._transport_inflight.remove(marker)
            (self._control_slots if receipt else self._speech_slots).release()

    def _fanout(
        self,
        native: bytes,
        rows: list[Mapping[str, Any]],
        operation: OperationBinding,
        *,
        authorize: Callable[[], None] | None,
    ) -> None:
        """One owned rolling window; no task exists before global admission."""
        if not self._send_slots.acquire(blocking=False):
            return  # Full audience remains inspectable, with unstarted rows.
        deadline_ns = (
            time.monotonic_ns()
            + max(0, operation.deadline_ms - self.lane.clock()) * 1_000_000
        )
        futures: set[Future[None]] = set()
        failures: list[BaseException] = []

        def run(row: Mapping[str, Any]) -> None:
            try:
                if authorize is not None:
                    authorize()
                for attempt in range(3):
                    outcome = self._transmit(
                        native,
                        row,
                        operation,
                        receipt=False,
                        deadline_ns=deadline_ns,
                        authorize=authorize,
                    )
                    if (
                        outcome not in {"route_connection_failed", "route_timeout"}
                        or attempt == 2
                    ):
                        break
                    remaining = min(
                        (deadline_ns - time.monotonic_ns()) / 1_000_000_000,
                        (operation.deadline_ms - self.lane.clock()) / 1000,
                    )
                    if remaining <= 0:
                        break
                    time.sleep(min(0.05 * 2**attempt, remaining))
                    # Recheck authority/readers at each original-byte release.
                    if authorize is not None:
                        authorize()
            finally:
                self._finish_transport(row, operation, receipt=False)

        def collect(done: set[Future[None]]) -> None:
            for future in done:
                try:
                    future.result()
                except BaseException as failure:
                    failures.append(failure)

        try:
            with ThreadPoolExecutor(max_workers=GROUP_OPERATION_WORKERS) as workers:
                for row in rows:
                    if self.lane.clock() >= operation.deadline_ms:
                        break
                    if time.monotonic_ns() >= deadline_ns:
                        break
                    if (row["being_ref"], row["embodiment_id"]) not in self.providers:
                        continue
                    if len(futures) >= GROUP_OPERATION_WORKERS:
                        done, futures = wait(futures, return_when=FIRST_COMPLETED)
                        collect(done)
                    if failures or time.monotonic_ns() >= deadline_ns:
                        break
                    if not self._claim_transport(row, operation, receipt=False):
                        continue
                    try:
                        futures.add(workers.submit(run, row))
                    except BaseException:
                        self._finish_transport(row, operation, receipt=False)
                        raise
                # Every submitted writer stays owned until completion. A stuck
                # local storage operation is degraded ownership, not permission
                # to abandon a writer and release the runtime lock.
                collect(futures)
            if failures:
                raise failures[0]
        finally:
            self._send_slots.release()

    def _transmit(
        self,
        native: bytes,
        row: Mapping[str, Any],
        operation: OperationBinding,
        *,
        receipt: bool,
        deadline_ns: int | None = None,
        authorize: Callable[[], None] | None = None,
    ) -> str | None:
        if receipt:
            if not self._claim_transport(row, operation, receipt=True):
                return None
            try:
                if deadline_ns is not None and time.monotonic_ns() >= deadline_ns:
                    return None
                self.egress.prepare_visibility(operation)
                return self._transmit_one(
                    native,
                    row,
                    operation,
                    receipt=receipt,
                    deadline_ns=deadline_ns,
                    authorize=authorize,
                )
            finally:
                self._finish_transport(row, operation, receipt=True)
        else:
            return self._transmit_one(
                native,
                row,
                operation,
                receipt=receipt,
                deadline_ns=deadline_ns,
                authorize=authorize,
            )

    def _transmit_one(
        self,
        native: bytes,
        row: Mapping[str, Any],
        operation: OperationBinding,
        *,
        receipt: bool,
        deadline_ns: int | None,
        authorize: Callable[[], None] | None,
    ) -> str | None:
        from .routes import RouteError
        from .sealed import inspect_delivery

        providers = self.providers.get((row["being_ref"], row["embodiment_id"]))
        if providers is None:
            return None  # The full signed audience remains present and pending.
        if self.lane.clock() >= operation.deadline_ms:
            return None
        provider = providers["evidence" if receipt else "message"]
        document = _parse(native)
        recovering = (
            not receipt
            and document.get("schema") == "dm.tribe.recovery-conversation/v1"
        )
        directed = (
            not receipt and document.get("schema") == "dm.tribe.direct-conversation/v1"
        )
        controlled_data = (
            recovering or directed or (self.controlled_readers and not receipt)
        )
        requirements = (
            self._reader_requirements(
                self.records.get(
                    "send",
                    document["recovery"]["payload"]["original_send_id"]
                    if recovering
                    else operation.operation_id,
                    deadline_ns=deadline_ns,
                ),
                document["resolution"]["manifest_hash"],
            )
            if controlled_data
            else None
        )
        if recovering and requirements is not None:
            requirements = ("dm.tribe.recovery-conversation/v1", requirements[1])
        if controlled_data and not self._direct_ready(row, requirements=requirements):
            self._record_reader_block(
                operation.operation_id, row, deadline_ns=deadline_ns
            )
            return None
        if receipt:
            identifier = document["receipt"]["event_id"]
            delivery_id = str(uuid.uuid5(uuid.UUID(identifier), "tribe-receipt/v1"))
        else:
            metadata = inspect_delivery(
                unb64url(document["envelope"]), at_ms=self.lane.clock()
            )
            identifier, delivery_id = metadata["event_id"], metadata["delivery_id"]
        request_id = str(
            uuid.uuid5(
                uuid.UUID(operation.operation_id),
                f"tribe-transport/v1:{row['being_ref']}:{row['embodiment_id']}",
            )
        )
        submission = {
            "schema": ROUTE_SUBMISSION_SCHEMA,
            "attempt_id": request_id,
            "leg_id": "application-stage:" + ("evidence" if receipt else "message"),
            "message_id": identifier,
            "recipient_id": row["embodiment_id"],
            "delivery_id": delivery_id,
            "envelope": b64url(native),
            "envelope_sha256": hashlib.sha256(native).hexdigest(),
            "deadline_ms": operation.deadline_ms,
        }
        fingerprint = {
            "submission": submission,
            "config_digest": self.config_digest,
            "provider_ref": provider.provider_ref,
            "route_ref": provider.route_ref,
        }
        retained = self.records.reserve(
            "transport",
            request_id,
            fingerprint,
            lambda: {"request": b64url(provider.prepare_submission(submission))},
            deadline_ns=deadline_ns,
        )
        raw = unb64url(retained["request"])
        proof = self.records.transport_result(request_id, deadline_ns=deadline_ns)
        if proof is not None:
            result = provider.validate_prepared_response(
                raw, unb64url(proof["response"])
            )
            if dict(result) != proof["result"]:
                raise ValueError("tribe_receipt_return_proof_conflict")
            return None

        def retain_response(response: bytes) -> None:
            observed = {
                "request_id": request_id,
                "response": b64url(response),
                "result": dict(provider.validate_prepared_response(raw, response)),
                "request_sha256": hashlib.sha256(raw).hexdigest(),
            }
            proof_id = str(
                uuid.uuid5(uuid.UUID(request_id), hashlib.sha256(response).hexdigest())
            )
            self.records.reserve(
                "transport-result",
                proof_id,
                observed,
                lambda: observed,
                deadline_ns=deadline_ns,
            )

        def authorize_write() -> None:
            if authorize is not None:
                authorize()
            if controlled_data and not self._direct_ready(
                row, requirements=requirements
            ):
                raise RouteError("tribe_reader_unconfirmed")

        try:
            provider.send_prepared(
                raw,
                carrier_binding=operation,
                response_sink=retain_response,
                attempt_deadline_ns=deadline_ns,
                authorize=authorize_write,
                require_bounded_write=controlled_data,
            )
        except RouteError as failure:
            # An unknown outcome stays pending. Retrying uses the same bytes and
            # receipt identity; never substitute a new logical message. Preserve
            # only the existing closed diagnostic code, never exception text or
            # peer responses. A failed observer cannot change native outcomes.
            with (
                suppress(OSError, sqlite3.Error, ValueError),
                self.egress.local_storage(deadline_ns=deadline_ns),
            ):
                write_diagnostic(
                    self.records.path,
                    "route",
                    request_id,
                    failure.code,
                    self.lane.clock(),
                )
            return failure.code
        return None

    def inspect_carrier(self, raw: bytes, *, at_ms: int) -> Mapping[str, Any]:
        from .sealed import inspect_delivery
        from .tribe_conversation import (
            TRIBE_CONVERSATION_SCHEMA,
            TRIBE_DIRECT_SCHEMA,
            TRIBE_INTAKE_SCHEMA,
            TRIBE_RECOVERY_SCHEMA,
        )

        document = _parse(raw)
        if document.get("schema") in {
            TRIBE_CONVERSATION_SCHEMA,
            TRIBE_DIRECT_SCHEMA,
            TRIBE_RECOVERY_SCHEMA,
        }:
            fields = {"schema", "envelope", "resolution", "tribe_ref"}
            if document["schema"] == TRIBE_RECOVERY_SCHEMA:
                fields.add("recovery")
            if (
                set(document) != fields
                or not isinstance(document["envelope"], str)
                or not isinstance(document["resolution"], Mapping)
            ):
                raise ValueError("tribe_carrier_invalid")
            return inspect_delivery(unb64url(document["envelope"]), at_ms=at_ms)
        if document.get("schema") == TRIBE_INTAKE_SCHEMA:
            if set(document) != {
                "schema",
                "membership_ref",
                "message_hash",
                "message_id",
                "receipt",
                "receipt_hash",
                "recipient_embodiment_id",
                "tribe_ref",
            } or not isinstance(document["receipt"], Mapping):
                raise ValueError("tribe_carrier_invalid")
            _uuid(document["message_id"])
            identifier = _uuid(document["receipt"].get("event_id"))
            return {
                "event_id": identifier,
                "delivery_id": str(
                    uuid.uuid5(uuid.UUID(identifier), "tribe-receipt/v1")
                ),
                "recipient_embodiment_ids": [self.lane.local_embodiment_id],
            }
        raise ValueError("tribe_carrier_invalid")

    def _return_context(self, sender: Mapping[str, Any]) -> dict[str, Any]:
        routes = self.providers.get((sender["being_ref"], sender["embodiment_id"]))
        provider = None if routes is None else routes["evidence"]
        return {
            "config_digest": self.config_digest,
            "policy": asdict(self.policy),
            "provider": None if provider is None else provider.retained_binding(),
            "local_body_ref": self.ledger.local_origin["body_ref"],
        }

    def _known_admission(self, request_id: str) -> dict[str, Any] | None:
        self._verify_loaded_stores()
        try:
            return self.records.get("intake-admission", request_id)
        except (ValueError, OSError, sqlite3.Error) as failure:
            raise RouteAmbiguous("tribe_intake_state_unavailable") from failure

    def admit_message(self, context: Mapping[str, Any]) -> DurableIntakeTicket:
        """Authenticated owner callback: atomically retain intake before ACK work."""
        request = context["request"]
        request_id = request["request_id"]
        existing = self._known_admission(request_id)
        if existing is not None:
            return self.retained_message_ticket(context)
        raw = unb64url(request["submission"]["envelope"])
        validated = self.lane.validate_intake(_parse(raw))
        message, resolution = validated.message, validated.resolution
        sender = {
            "being_ref": message["being_ref"],
            "embodiment_id": message["origin"]["embodiment_id"],
        }
        if (
            request["sender_principal"] != sender["being_ref"]
            or request["sender_body_ref"] != message["origin"]["body_ref"]
            or context["metadata"]["event_id"] != message["event_id"]
        ):
            raise ValueError("tribe_intake_sender_conflict")
        admission = {
            "schema": "dm.tribe.intake-admission/v1",
            "phase": "message",
            "context": dict(context),
            "message_id": message["event_id"],
            "message_hash": message["content_hash"],
            "resolution_hash": resolution["content_hash"],
        }

        def acceptance(now: int) -> None:
            if (
                not validated.validated_at_ms
                <= now
                < min(validated.expires_at_ms, request["expires_at_ms"])
            ):
                raise ValueError("tribe_intake_time_invalid")
            self.lane._operational(
                self.lane.being_ref,
                self.lane.local_credential_id,
                self.lane.local_embodiment_id,
                now,
            )
            descriptor = context["metadata"]["sender"]
            self.lane._operational(
                sender["being_ref"],
                descriptor["credential_id"],
                sender["embodiment_id"],
                now,
            )

        def obligation(first: int, legacy: bool) -> dict[str, Any]:
            observed, deadline = first, first + self.policy.max_ttl_ms
            if legacy:
                retained = self.records.get("receipt", message["event_id"])
                native = (
                    None
                    if retained is None
                    else self.records.get("native", retained["receipt"]["event_id"])
                )
                if retained is None or native is None:
                    raise ValueError("tribe_legacy_deadline_provenance_missing")
                observed = retained["receipt"]["payload"]["observed_at_ms"]
                deadline = native["deadline_ms"]
            return {
                "schema": "dm.tribe.receipt-obligation/v1",
                "message_id": message["event_id"],
                "message_hash": message["content_hash"],
                "resolution_hash": resolution["content_hash"],
                "membership_ref": validated.membership_ref,
                "tribe_ref": validated.tribe_ref,
                "recipient_embodiment_id": self.lane.local_embodiment_id,
                "observed_at_ms": observed,
                "deadline_ms": deadline,
                "first_request_id": request_id,
                "request_hash": context["request_hash"],
                "carrier_sha256": request["submission"]["envelope_sha256"],
                "return_target": sender,
                "return_context": self._return_context(sender),
            }

        try:
            self.records.commit_intake(
                request_id=request_id,
                admission=admission,
                message=message,
                resolution=resolution,
                acceptance=acceptance,
                obligation=obligation,
            )
        except (OSError, sqlite3.Error, ValueError) as failure:
            # A failed COMMIT observation cannot classify a real committed intake
            # as absent. Resolve its exact signed row before selecting recovery.
            try:
                retained = self.records.get("intake-admission", request_id)
            except (OSError, sqlite3.Error, ValueError):
                retained = None
            if retained is None:
                code = (
                    "tribe_control_capacity"
                    if isinstance(failure, TribeControlCapacityError)
                    else "tribe_intake_commit_uncertain"
                )
                raise RouteAmbiguous(code) from failure
        return self.retained_message_ticket(context)

    def _retained_intake(
        self, context: Mapping[str, Any]
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
        admission = self.records.get(
            "intake-admission", context["request"]["request_id"]
        )
        if admission is None or admission["context"] != context:
            raise RouteAmbiguous("tribe_intake_recovery_binding_conflict")
        identifier = admission["message_id"]
        inbox = self.records.get("inbox", identifier)
        obligation = self.records.get("receipt-obligation", identifier)
        if inbox is None or obligation is None:
            raise RouteAmbiguous("tribe_intake_commit_incomplete")
        message, resolution = inbox["message"], inbox["resolution"]
        verify_event(
            message, self.lane._epoch(message["being_ref"], message["manifest_hash"])
        )
        verify_event(
            resolution,
            self.lane._epoch(resolution["being_ref"], resolution["manifest_hash"]),
        )
        expected = {
            "message_id": message["event_id"],
            "message_hash": message["content_hash"],
            "resolution_hash": resolution["content_hash"],
        }
        if (
            any(
                admission[key] != value or obligation[key] != value
                for key, value in expected.items()
            )
            or obligation["recipient_embodiment_id"] != self.lane.local_embodiment_id
            or obligation["tribe_ref"] != self.policy.tribe_ref
            or obligation["return_target"]
            != {
                "being_ref": message["being_ref"],
                "embodiment_id": message["origin"]["embodiment_id"],
            }
        ):
            raise RouteAmbiguous("tribe_intake_recovery_binding_conflict")
        first = self.records.get("intake-admission", obligation["first_request_id"])
        if (
            first is None
            or first["message_id"] != identifier
            or first["context"]["request_hash"] != obligation["request_hash"]
            or first["context"]["request"]["submission"]["envelope_sha256"]
            != obligation["carrier_sha256"]
        ):
            raise RouteAmbiguous("tribe_intake_recovery_binding_conflict")
        return admission, inbox, obligation

    def retained_message_ticket(
        self, context: Mapping[str, Any]
    ) -> DurableIntakeTicket:
        self._verify_loaded_stores()
        try:
            return self._retained_message_ticket(context)
        except (ValueError, OSError, sqlite3.Error) as failure:
            raise RouteAmbiguous(
                "tribe_retained_intake_verification_uncertain"
            ) from failure

    def _retained_message_ticket(
        self, context: Mapping[str, Any]
    ) -> DurableIntakeTicket:
        admission, inbox, obligation = self._retained_intake(context)
        identifier = inbox["message"]["event_id"]

        def after_response() -> None:
            self.complete_receipt(identifier)

        def after_response_bounded(deadline: int) -> Mapping[str, Any]:
            with self.egress.attempt_budget(deadline):
                return self.complete_receipt(identifier, deadline_ns=deadline)

        return DurableIntakeTicket(
            received_at_ms=admission["received_at_ms"],
            metadata=context["metadata"],
            acknowledge=lambda response: self._acknowledge_intake(
                admission, context, response
            ),
            after_response=after_response,
            after_response_bounded=after_response_bounded,
            completion_expires_at_ms=obligation["deadline_ms"],
        )

    def _acknowledge_intake(
        self, admission: Mapping[str, Any], context: Mapping[str, Any], response: bytes
    ) -> None:
        self._verify_loaded_stores()
        value = _parse(response)
        if (
            value["status"] != "accepted"
            or value["outcome"] != "recipient-intake"
            or value["request_id"] != context["request"]["request_id"]
            or value["request_sha256"] != context["request_hash"]
            or value["intake"]["envelope_sha256"]
            != context["request"]["submission"]["envelope_sha256"]
            or not context["metadata"].get("issued_at_ms", 0)
            <= _uint(value["intake"]["accepted_at_ms"])
            <= admission["received_at_ms"]
            or value["intake"]["delivery_id"] != context["metadata"]["delivery_id"]
            or value["intake"]["recipient_id"] != self.lane.local_embodiment_id
            or value["intake"]["recipient_body_ref"]
            != self.ledger.local_origin["body_ref"]
        ):
            raise RouteAmbiguous("tribe_intake_ack_conflict")
        proof = {
            "admission_sha256": hashlib.sha256(canonical_bytes(admission)).hexdigest(),
            "response": b64url(response),
        }
        self.records.reserve("intake-ack", value["request_id"], proof, lambda: proof)

    def complete_receipt(
        self, message_id: str, *, deadline_ns: int | None = None
    ) -> dict[str, Any]:
        """One finite retained technical attempt under the runtime owner."""
        self._verify_loaded_stores()
        if deadline_ns is not None and time.monotonic_ns() >= deadline_ns:
            return {"state": "pending", "code": "attempt_budget_exhausted"}
        with self._receipt_lock:
            if message_id in self._receipt_inflight:
                return {"state": "in-flight"}
            self._receipt_inflight.add(message_id)
        try:
            with self.ledger.storage_budget(deadline_ns):
                return self._complete_receipt(message_id, deadline_ns=deadline_ns)
        finally:
            with self._receipt_lock:
                self._receipt_inflight.remove(message_id)

    def _retained_return_state(
        self, result: Mapping[str, Any], obligation: Mapping[str, Any]
    ) -> str | None:
        """Read the signed observation of a verified ACK, not today's route."""
        receipt_id = result["receipt"]["event_id"]
        target = obligation["return_target"]
        identifier = str(
            uuid.uuid5(
                uuid.UUID(receipt_id),
                f"tribe-transport/v1:{target['being_ref']}:{target['embodiment_id']}",
            )
        )
        proof = self.records.transport_result(identifier)
        if proof is None:
            return None
        transport = self.records.get("transport", identifier)
        if transport is None:
            raise ValueError("tribe_receipt_return_proof_conflict")
        raw = unb64url(transport["request"])
        request = _parse(raw)
        response = _parse(unb64url(proof["response"]))
        provider = obligation["return_context"]["provider"]
        if (
            provider is None
            or proof["request_sha256"] != hashlib.sha256(raw).hexdigest()
            or request["submission"]["envelope"] != b64url(canonical_bytes(result))
            or request["submission"]["recipient_id"] != target["embodiment_id"]
            or request["expires_at_ms"] != obligation["deadline_ms"]
            or request["provider_ref"] != provider["provider_ref"]
            or request["route_ref"] != provider["route_ref"]
            or request["auth"]["key_ref"] != provider["key_ref"]
            or response["request_id"] != request["request_id"]
            or response["request_sha256"]
            != hashlib.sha256(
                canonical_bytes(
                    {key: value for key, value in request.items() if key != "auth"}
                )
            ).hexdigest()
            or response["outcome"] != proof["result"]["outcome"]
            or response["intake"] != proof["result"]["intake"]
        ):
            raise ValueError("tribe_receipt_return_proof_conflict")
        # Production _checked verifies the owner-signed record that retained the
        # provider's authenticated result. No new HMAC key, route or I/O is used.
        return str(proof["result"]["outcome"])

    def _complete_receipt(
        self, message_id: str, *, deadline_ns: int | None = None
    ) -> dict[str, Any]:
        obligation = self.records.get("receipt-obligation", message_id)
        if obligation is None:
            raise ValueError("tribe_receipt_obligation_missing")
        first = self.records.get("intake-admission", obligation["first_request_id"])
        if first is None:
            raise ValueError("tribe_intake_commit_incomplete")
        _, inbox, obligation = self._retained_intake(first["context"])
        terminal = self.records.get("receipt-terminal", message_id)
        if terminal is not None:
            retained_receipt = self.records.get("receipt", message_id)
            if (
                terminal.get("state") not in {"recipient-intake", "refused", "expired"}
                or terminal.get("obligation_sha256")
                != hashlib.sha256(canonical_bytes(obligation)).hexdigest()
                or retained_receipt is None
                or terminal.get("receipt_sha256")
                != hashlib.sha256(canonical_bytes(retained_receipt)).hexdigest()
            ):
                raise ValueError("tribe_receipt_completion_conflict")
            return terminal
        now = self.lane.clock()
        if now < obligation["observed_at_ms"]:
            return {"state": "blocked-clock"}
        message, resolution = inbox["message"], inbox["resolution"]
        result = self.records.get("receipt", message_id)
        if result is None:
            self.lane._operational(
                self.lane.being_ref,
                self.lane.local_credential_id,
                self.lane.local_embodiment_id,
                now,
            )
            receipt = self.lane._author_receipt(
                message,
                resolution,
                membership_ref=obligation["membership_ref"],
                now=now,
                observed_at_ms=obligation["observed_at_ms"],
            )
            if receipt["payload"]["observed_at_ms"] != obligation["observed_at_ms"]:
                raise ValueError("tribe_receipt_observation_conflict")
            validated = ValidatedTribeIntake(
                message=message,
                resolution=resolution,
                membership_ref=obligation["membership_ref"],
                tribe_ref=obligation["tribe_ref"],
                validated_at_ms=obligation["observed_at_ms"],
                expires_at_ms=first["context"]["request"]["expires_at_ms"],
            )
            result = self.lane.intake_result(validated, receipt)
            self.records.reserve("receipt", message_id, result, lambda: result)
        native = canonical_bytes(result)
        known = self._retained_return_state(result, obligation)
        state = known or ("expired" if now >= obligation["deadline_ms"] else "pending")
        if state == "pending":
            if (
                self._return_context(obligation["return_target"])
                != obligation["return_context"]
            ):
                return {"state": "blocked-selection"}
            if obligation["return_context"]["provider"] is None:
                return {"state": "unroutable"}
            operation_id = result["receipt"]["event_id"]
            operation = self.records.admit(
                operation_id,
                native,
                path_id="tribe-receipt-request",
                projection={
                    "event_id": operation_id,
                    "event_digest": result["receipt"]["content_hash"],
                    "sender": self.lane.being_ref,
                    "recipients": [message["being_ref"]],
                    "thread_id": message["payload"]["intent"]["thread_id"],
                    "kind": "authorization-control",
                    "reply_to": None,
                    "content": {"stage": "semantic-receipt"},
                },
                deadline_ms=obligation["deadline_ms"],
                authority_head=self.ledger.local_origin["body_ref"],
            )
            failure_code = self._transmit(
                native,
                obligation["return_target"],
                operation,
                receipt=True,
                deadline_ns=deadline_ns,
            )
            if failure_code in {
                "route_authority_blocked",
                "route_echo_unconfirmed",
                "route_egress_blocked",
                "transport_response_rejected",
            }:
                return {"state": "blocked-return"}
            state = self._retained_return_state(result, obligation) or "pending"
        if state == "pending":
            return {"state": state}
        terminal = {
            "state": state,
            "obligation_sha256": hashlib.sha256(
                canonical_bytes(obligation)
            ).hexdigest(),
            "receipt_sha256": hashlib.sha256(native).hexdigest(),
        }
        return self.records.reserve(
            "receipt-terminal", message_id, terminal, lambda: terminal
        )

    def reconcile_intake(
        self,
        *,
        after: int = 0,
        limit: int = 32,
        max_bytes: int = 8 * 1024 * 1024,
        max_elapsed_ms: int = 10_000,
    ) -> dict[str, Any]:
        """Finite technical recovery; the caller must own the native runtime lock.

        The same elapsed budget limits in-flight network attempts and stops
        starting further items. Local storage completion retains ownership;
        this method never abandons an active writer.
        """
        self._verify_loaded_stores()
        if (
            type(max_bytes) is not int
            or not 1 <= max_bytes <= 32 * 1024 * 1024
            or type(max_elapsed_ms) is not int
            or not 1 <= max_elapsed_ms <= 60_000
        ):
            raise ValueError("tribe_intake_budget_invalid")
        started = time.monotonic_ns()
        deadline_ns = started + max_elapsed_ms * 1_000_000
        page = self.records.intake_page(
            after=after,
            limit=limit,
            max_bytes=max_bytes,
            deadline_ns=deadline_ns,
        )
        consumed, cursor = 0, after
        results = []
        for item in page["items"]:
            admission = item["admission"]
            size = len(canonical_bytes(admission))
            if (
                consumed + size > max_bytes
                or (time.monotonic_ns() - started) // 1_000_000 >= max_elapsed_ms
            ):
                break
            context = admission["context"]
            identifier = context["request"]["request_id"]
            try:
                phase = admission.get("phase", "message")
                ticket = (
                    self.retained_message_ticket(context)
                    if phase == "message"
                    else self.retained_evidence_ticket(context)
                )
                ingress = self.intake_ingresses[phase]
                ingress.finalize_retained_intake(context, ticket)
                state = (
                    self.complete_receipt(
                        admission["message_id"], deadline_ns=deadline_ns
                    )
                    if phase == "message"
                    else self.complete_control(identifier, deadline_ns=deadline_ns)
                )
                results.append({"request_id": identifier, "ack": "retained", **state})
            except (ValueError, OSError, sqlite3.Error, RouteError) as failure:
                # Only fixed local codes are exposed, never requests or routes.
                code = (
                    failure.code
                    if isinstance(failure, RouteError)
                    else "recovery-pending"
                )
                results.append(
                    {"request_id": identifier, "state": "pending", "code": code}
                )
            consumed += size
            cursor = item["sequence"]
        return {
            "schema": "dm.tribe.intake-reconciliation/v1",
            "items": results,
            "next_after": cursor,
            "has_more": page["has_more"] or len(results) < len(page["items"]),
            "inference_started": 0,
        }

    def admit_evidence(self, context: Mapping[str, Any]) -> DurableIntakeTicket:
        request = context["request"]
        request_id = request["request_id"]
        if self._known_admission(request_id) is not None:
            return self.retained_evidence_ticket(context)
        raw = unb64url(request["submission"]["envelope"])
        verified, being = self._validated_evidence(raw)
        if (
            request["sender_principal"] != verified["being_ref"]
            or request["sender_body_ref"] != verified["origin"]["body_ref"]
        ):
            raise ValueError("tribe_intake_sender_conflict")
        proof = {"wire": _parse(raw), "receipt": verified, "recipient_being_ref": being}
        admission = {
            "schema": "dm.tribe.intake-admission/v1",
            "phase": "evidence",
            "context": dict(context),
            "control_sha256": hashlib.sha256(canonical_bytes(proof)).hexdigest(),
        }
        validated_at = self.lane.clock()

        def acceptance(now: int) -> None:
            if not validated_at <= now < request["expires_at_ms"]:
                raise ValueError("tribe_intake_time_invalid")
            self.lane._operational(
                self.lane.being_ref,
                self.lane.local_credential_id,
                self.lane.local_embodiment_id,
                now,
            )

        try:
            self.records.commit_control(
                request_id=request_id,
                admission=admission,
                proof=proof,
                acceptance=acceptance,
            )
        except (ValueError, OSError, sqlite3.Error) as failure:
            try:
                retained = self.records.get("intake-admission", request_id)
            except (ValueError, OSError, sqlite3.Error):
                retained = None
            if retained is None:
                raise RouteAmbiguous("tribe_control_commit_uncertain") from failure
        return self.retained_evidence_ticket(context)

    def retained_evidence_ticket(
        self, context: Mapping[str, Any]
    ) -> DurableIntakeTicket:
        self._verify_loaded_stores()
        try:
            return self._retained_evidence_ticket(context)
        except (ValueError, OSError, sqlite3.Error) as failure:
            raise RouteAmbiguous(
                "tribe_retained_intake_verification_uncertain"
            ) from failure

    def _retained_evidence_ticket(
        self, context: Mapping[str, Any]
    ) -> DurableIntakeTicket:
        request_id = context["request"]["request_id"]
        admission = self.records.get("intake-admission", request_id)
        proof = self.records.get("control-proof", request_id)
        if (
            admission is None
            or admission.get("phase") != "evidence"
            or admission["context"] != context
            or proof is None
            or hashlib.sha256(canonical_bytes(proof)).hexdigest()
            != admission["control_sha256"]
            or canonical_bytes(proof["wire"])
            != unb64url(context["request"]["submission"]["envelope"])
        ):
            raise RouteAmbiguous("tribe_control_recovery_binding_conflict")
        receipt, being = self._validated_evidence(canonical_bytes(proof["wire"]))
        if proof["receipt"] != receipt or proof["recipient_being_ref"] != being:
            raise RouteAmbiguous("tribe_control_recovery_binding_conflict")

        def after_response() -> None:
            self.complete_control(request_id)

        def after_response_bounded(deadline: int) -> Mapping[str, Any]:
            with self.egress.attempt_budget(deadline):
                return self.complete_control(request_id, deadline_ns=deadline)

        return DurableIntakeTicket(
            received_at_ms=admission["received_at_ms"],
            metadata=context["metadata"],
            acknowledge=lambda response: self._acknowledge_intake(
                admission, context, response
            ),
            after_response=after_response,
            after_response_bounded=after_response_bounded,
            completion_expires_at_ms=context["request"]["expires_at_ms"],
        )

    def complete_control(
        self, request_id: str, *, deadline_ns: int | None = None
    ) -> dict[str, Any]:
        self._verify_loaded_stores()
        if deadline_ns is not None and time.monotonic_ns() >= deadline_ns:
            return {"state": "pending", "code": "attempt_budget_exhausted"}
        key = "control:" + request_id
        with self._receipt_lock:
            if key in self._receipt_inflight:
                return {"state": "in-flight"}
            self._receipt_inflight.add(key)
        try:
            with self.ledger.storage_budget(deadline_ns):
                admission = self.records.get("intake-admission", request_id)
                if admission is None:
                    raise ValueError("tribe_control_recovery_missing")
                self.retained_evidence_ticket(admission["context"])
                terminal = self.records.get("control-terminal", request_id)
                if terminal is not None:
                    if terminal["control_sha256"] != admission["control_sha256"]:
                        raise ValueError("tribe_control_recovery_binding_conflict")
                    return terminal
                proof = self.records.get("control-proof", request_id)
                assert proof is not None
                self.communication.record_foreign_receipt(
                    proof["receipt"],
                    recipient_being_ref=proof["recipient_being_ref"],
                    deadline_ns=deadline_ns,
                )
                terminal = {
                    "state": "receipt-projected",
                    "control_sha256": admission["control_sha256"],
                }
                return self.records.reserve(
                    "control-terminal", request_id, terminal, lambda: terminal
                )
        finally:
            with self._receipt_lock:
                self._receipt_inflight.remove(key)

    def receive_message(self, raw: bytes) -> None:
        self._verify_loaded_stores()
        result = self.lane.intake(_parse(raw))
        self.records.reserve("receipt", result["message_id"], result, lambda: result)
        message = self.message(result["message_id"])
        sender = {
            "being_ref": message["being_ref"],
            "embodiment_id": message["origin"]["embodiment_id"],
        }
        native = canonical_bytes(result)
        operation_id = result["receipt"]["event_id"]
        existing = self.records.get("native", operation_id)
        deadline = (
            existing["deadline_ms"]
            if existing is not None
            else result["receipt"]["payload"]["observed_at_ms"] + self.policy.max_ttl_ms
        )
        operation = self.records.admit(
            operation_id,
            native,
            path_id="tribe-receipt-request",
            projection={
                "event_id": operation_id,
                "event_digest": result["receipt"]["content_hash"],
                "sender": self.lane.being_ref,
                "recipients": [message["being_ref"]],
                "thread_id": message["payload"]["intent"]["thread_id"],
                "kind": "authorization-control",
                "reply_to": None,
                "content": {"stage": "semantic-receipt"},
            },
            deadline_ms=deadline,
            authority_head=self.ledger.local_origin["body_ref"],
        )
        self._transmit(native, sender, operation, receipt=True)

    def _validated_evidence(self, raw: bytes) -> tuple[dict[str, Any], str]:
        result = _parse(raw)
        message = self.ledger.event(result["message_id"])
        if message is None:
            raise ValueError("tribe_receipt_message_missing")
        receipt = result["receipt"]
        resolution = self.ledger.event(receipt["payload"]["resolution_ref"]["event_id"])
        row = next(
            (
                row
                for row in message["payload"]["body"]["audience"]
                if row["being_ref"] == receipt["being_ref"]
                and row["embodiment_id"] == receipt["origin"]["embodiment_id"]
            ),
            None,
        )
        if resolution is None or row is None:
            raise ValueError("tribe_receipt_target_missing")
        verified = self.lane._accept_member_receipt(
            result,
            row=row,
            message=message,
            resolution=resolution,
            tribe_ref=self.policy.tribe_ref,
        )
        _foreign_receipt_payload(verified)
        return dict(verified), str(row["being_ref"])

    def receive_evidence(self, raw: bytes) -> None:
        self._verify_loaded_stores()
        verified, being = self._validated_evidence(raw)
        self.communication.record_foreign_receipt(verified, recipient_being_ref=being)
