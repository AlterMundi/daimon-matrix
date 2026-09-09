"""Grant-gated encrypted evidence and sparse foreign inbox admission.

This application seam does not import events into a Ledger or issue receipts.
Configuration, authority resolution and custody are trusted owner-local inputs;
only canonical DM-051 envelope bytes enter the receive methods.
"""

from __future__ import annotations

import hashlib
import uuid
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass
from typing import Any

from .canonical import CanonicalError, b64url, canonical_bytes
from .communication import (
    MESSAGE_PAYLOAD_SCHEMA,
    RESOLUTION_PAYLOAD_SCHEMA,
    CommunicationError,
    _message_payload,
    _resolution_payload,
)
from .ledger import Ledger
from .messaging_store import (
    MessagingInboxError,
    MessagingInboxStore,
    MessagingOutboxStore,
)
from .relationship_store import RelationshipStore, RelationshipView
from .routes import ROUTE_SUBMISSION_SCHEMA, AuthenticatedProvider, RouteError
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
from .weave import EventSigner, RootAuthority, verify_event

EVIDENCE_SCHEMA = "dm.communication.evidence-package/v1"


@dataclass(frozen=True)
class GrantReference:
    grant_id: str
    event_id: str
    event_hash: str


@dataclass(frozen=True)
class MessagingPeerPolicy:
    """One explicitly configured directional /tribe channel, not a wire claim."""

    peer_being_ref: str
    peer_embodiment_id: str
    peer_credential_id: str
    relationship_id: str
    tribe_ref: str
    membership_ref: str
    resource_ref: str
    operation: str
    classification: str
    grant_refs: tuple[GrantReference, ...]
    max_ttl_ms: int = 60_000


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
    ) -> None:
        self.context = context
        self.ledger = ledger
        self.signer = signer
        self.custody = custody
        self.outbox = outbox
        self.clock = clock

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

    def prepare(
        self,
        *,
        client_id: str,
        send_id: str,
        thread_id: str,
        text: str,
        response_to: tuple[MessagingChannel, str] | None = None,
    ) -> tuple[bytes, bytes]:
        now = _uint(self.clock())
        context, policy = self.context, self.context.policy
        self._bind(now)
        if not isinstance(text, str):
            raise ValueError("messaging_text_required")
        if not 0 < _uint(policy.max_ttl_ms) <= MAX_TTL_MS:
            raise ValueError("messaging_ttl_invalid")
        owner = policy.peer_being_ref
        self.outbox._check_time(owner, send_id, now)
        policy_hash = context._policy_hash(now)
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
        if response_to is not None:
            channel, message_id = response_to
            received = channel.message(message_id)
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
        _message_payload(
            {
                "kind": "experience.observed",
                "subject": "communication",
                "payload": payload,
            }
        )
        request_hash = hashlib.sha256(canonical_bytes(payload)).hexdigest()
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
                "issued_at_ms": now,
                "expires_at_ms": now + policy.max_ttl_ms,
                "message_authorization_id": str(uuid.uuid4()),
                "evidence_authorization_id": str(uuid.uuid4()),
            },
        )
        issued, expires = plan["issued_at_ms"], plan["expires_at_ms"]
        if now >= expires:
            raise ValueError("messaging_authorization_expired")
        if now < issued:
            raise ValueError("messaging_authorization_not_yet_valid")
        cached = self.outbox._prepared(owner, send_id)
        if cached is not None:
            return cached

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

        message = append("communication", payload)
        target = context._local()
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
                        "recipient_id": policy.membership_ref,
                        "recipient_type": "relationship",
                        "scope_kind": "relationship",
                    }
                ],
            },
            (message["event_id"],),
        )
        authorization = DisclosureAuthorization.from_relationship_resolution_event(
            event=message,
            resolution_event=resolution,
            sender_authority=context._sender(),
            recipient_targets=[target],
            disclosures={policy.membership_ref: context._disclosure(now)},
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
                "message_authorized_at_ms": issued,
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
        return self.outbox._commit(owner, send_id, (envelopes[0], envelopes[1]))


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
        payload = _message_payload(event)
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
        return self._run(
            client_id=client_id,
            send_id=send_id,
            thread_id=payload["intent"]["thread_id"],
            text=payload["body"]["text"],
            transmit=False,
            response_to=response_to,
        )

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
    ) -> dict[str, Any]:
        if authorize is not None:
            authorize()
        # Always authorize the original request before consulting private progress.
        envelopes = self.sender.prepare(
            client_id=client_id,
            send_id=send_id,
            thread_id=thread_id,
            text=text,
            response_to=response_to,
        )
        owner = self.sender.context.policy.peer_being_ref
        phases = ("evidence", "message")
        submissions = {}
        bindings = {}
        for phase, provider, envelope in zip(
            phases, self.providers, envelopes, strict=True
        ):
            metadata = _parse(envelope)
            attempt_id = str(
                uuid.uuid5(
                    uuid.UUID(send_id), f"dm.messaging.transport/v1:{owner}:{phase}"
                )
            )
            submissions[phase] = {
                "schema": ROUTE_SUBMISSION_SCHEMA,
                "attempt_id": attempt_id,
                # Application stage label, not a fabricated DM-052 semantic leg.
                "leg_id": "application-stage:" + phase,
                "message_id": metadata["event_id"],
                "recipient_id": self.sender.context.policy.membership_ref,
                "delivery_id": metadata["delivery_id"],
                "envelope": b64url(envelope),
                "envelope_sha256": hashlib.sha256(envelope).hexdigest(),
                "deadline_ms": metadata["expires_at_ms"],
            }
            bindings[phase] = {
                "config_digest": self.config_digest,
                "provider_ref": provider.provider_ref,
                "route_ref": provider.route_ref,
                "route_class": provider.route_class,
                "attempt_id": attempt_id,
                "submission_sha256": hashlib.sha256(
                    canonical_bytes(submissions[phase])
                ).hexdigest(),
            }
        providers = dict(zip(phases, self.providers, strict=True))
        stages = self.sender.outbox._transport_stages(
            owner,
            send_id,
            bindings,
            lambda phase: providers[phase].prepare_submission(submissions[phase]),
            create=transmit,
        )
        # Validate BOTH retained requests before any network I/O, including when
        # evidence succeeded already. This checks current transport keys without
        # regenerating timestamps or retaining those keys in the outbox.
        for phase in phases:
            prepared, _, _ = providers[phase]._prepared_submission(
                stages[phase]["request"]
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
            self.sender.prepare(
                client_id=client_id,
                send_id=send_id,
                thread_id=thread_id,
                text=text,
                response_to=response_to,
            )
            stage = stages[phase]
            status = stage["transport_status"]
            if transmit and status in {"prepared", "pending"}:
                status = self.sender.outbox._transport_status(owner, send_id, phase)
                if status == "pending":
                    proofs: list[bytes] = []
                    try:
                        result = providers[phase].send_prepared(
                            stage["request"], response_sink=proofs.append
                        )
                    except (RouteError, CanonicalError):
                        # No authenticated outcome: recipient may already have admitted
                        # the request. Keep the committed pending state across restart.
                        result = None
                    if result is not None and result["status"] in {
                        "accepted",
                        "refused",
                    }:
                        status = self.sender.outbox._transport_status(
                            owner, send_id, phase, result=result, response=proofs[0]
                        )
            stage["transport_status"] = status
            if status != "recipient-intake":
                break
        if authorize is not None:
            authorize()
        return {
            "send_id": send_id,
            "phase": phase,
            "transport_status": status,
            "retryable": status == "pending",
            "ambiguous": status == "pending",
            "stages": [
                {
                    "phase": label,
                    "attempt_id": bindings[label]["attempt_id"],
                    "transport_status": stages[label]["transport_status"],
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
        authority_resolver: Callable[[str], RootAuthority],
        relationships: RelationshipStore,
        custody: DeliveryCustody,
        inbox: MessagingInboxStore,
        clock: Callable[[], int],
    ) -> None:
        self.policy = policy
        self.local_being_ref = local_being_ref
        self.local_credential_id = local_credential_id
        self.authority_resolver = authority_resolver
        self.relationships = relationships
        self.custody = custody
        self.inbox = inbox
        self.clock = clock

    def _local(self) -> RecipientTarget:
        return RecipientTarget(
            self.authority_resolver(self.local_being_ref), self.local_credential_id
        )

    def _sender(self) -> RootAuthority:
        return self.authority_resolver(self.policy.peer_being_ref)

    def _card(self, card: Mapping[str, Any], at_ms: int) -> None:
        authority = self.authority_resolver(card["being_ref"])
        position = card["control_position"]
        member = authority.manifest.member(
            position["embodiment_id"], position["incarnation_id"]
        )
        target = RecipientTarget(authority, member["embodiment_credential_id"])
        descriptor = recipient_descriptor(target, at_ms=at_ms)
        if (
            authority.manifest.digest != position["manifest_hash"]
            or descriptor["encryption_kid"] != card["encryption_key"]["key_id"]
            or authority.credentials[target.credential_id]["body"]["encryption_key"]
            != card["encryption_key"]
        ):
            raise SealedDeliveryError()

    def _disclosure(self, at_ms: int) -> dict[str, Any]:
        # Revalidate retained signatures; RelationshipView itself is only a reducer.
        events = [
            self.relationships._validated_event(e) for e in self.relationships.events()
        ]
        view = RelationshipView(events, at_ms=at_ms, card_verifier=self._card)
        policy = self.policy
        local = recipient_descriptor(self._local(), at_ms=at_ms)
        snapshot = view.snapshot(policy.tribe_ref)
        if not any(
            member["principal_id"] == self.local_being_ref
            and member["embodiment_id"] == local["embodiment_id"]
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

    def disclosure(self) -> dict[str, Any]:
        """Recompute the selected disclosure, also usable by the sender context."""
        return self._disclosure(self.clock())

    def _policy_hash(self, at_ms: int) -> str:
        return hashlib.sha256(
            canonical_bytes(
                {
                    "schema": "dm.communication.bootstrap-policy/v1",
                    "policy": asdict(self.policy),
                    "recipient": recipient_descriptor(self._local(), at_ms=at_ms),
                    "disclosure": self._disclosure(at_ms),
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
    ) -> DisclosureAuthorization:
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
            or targets[0]["recipient_id"] != self.policy.membership_ref
            or targets[0]["receipt_origin_embodiment_id"] != local["embodiment_id"]
        ):
            raise SealedDeliveryError()
        proof = {self.policy.membership_ref: self._disclosure(at_ms)}
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
        policy_hash = self._policy_hash(now)  # Never copy envelope evidence_hash.
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
        self._message_authorization(evidence, now)
        self.inbox._retain_evidence(evidence, raw, policy_hash)

    def receive_message(self, raw: bytes) -> dict[str, Any]:
        now = self.clock()
        envelope = self._envelope(raw, now)
        evidence = self.inbox._evidence(
            envelope["event_id"], envelope["authorization_id"], self._policy_hash(now)
        )
        if evidence is None:
            raise CommunicationError("messaging_evidence_missing", retryable=True)
        evidence = self._verify_retained(evidence)
        authorization = self._message_authorization(evidence, now)
        message = self._open(raw, authorization, now)
        self._validate_message(message, evidence, authorization, now)
        return self.inbox._retain_message(
            message, evidence, raw, self._policy_hash(now)
        )

    def _validate_message(
        self,
        message: Mapping[str, Any],
        evidence: Mapping[str, Any],
        authorization: DisclosureAuthorization,
        now: int,
    ) -> None:
        payload = _message_payload(message)
        if (
            payload["intent"]["operation"] != self.policy.operation
            or payload["intent"]["scope"] != "/tribe"
            or payload["body"].get("resource_ref") != self.policy.resource_ref
        ):
            raise SealedDeliveryError()
        expected = DisclosureAuthorization.from_relationship_resolution_event(
            event=message,
            resolution_event=evidence["payload"]["resolution_event"],
            sender_authority=self._sender(),
            recipient_targets=[self._local()],
            disclosures={self.policy.membership_ref: self._disclosure(now)},
            expires_at_ms=authorization.value["expires_at_ms"],
            authorization_id=authorization.value["authorization_id"],
        )
        if expected.value != authorization.value:
            raise SealedDeliveryError()

    def _verify_retained(self, event: Any) -> dict[str, Any]:
        try:
            return dict(verify_event(event, self._sender()))
        except (ValueError, KeyError, TypeError):
            raise MessagingInboxError("messaging_stored_evidence_invalid") from None

    def message(self, message_id: str) -> dict[str, Any]:
        """Look up exact locally admitted evidence under current authorization."""
        now = self.clock()
        row = self.inbox._message(_uuid(message_id), self._policy_hash(now))
        self._validate_rows([row], now)
        return dict(row["message"])

    def page(self, *, after: int, limit: int) -> list[dict[str, Any]]:
        """Manual current-policy read, not a delivered/consumed semantic receipt."""
        now = self.clock()
        rows = self.inbox._page(
            after=after, limit=limit, policy_hash=self._policy_hash(now)
        )
        self._validate_rows(rows, now)
        return rows

    def _validate_rows(self, rows: list[dict[str, Any]], now: int) -> None:
        for row in rows:
            row["message"] = self._verify_retained(row["message"])
            row["evidence"] = self._verify_retained(row["evidence"])
            try:
                authorization = self._message_authorization(row["evidence"], now)
                self._validate_message(
                    row["message"], row["evidence"], authorization, now
                )
            except (ValueError, KeyError, TypeError):
                raise MessagingInboxError("messaging_stored_evidence_invalid") from None
