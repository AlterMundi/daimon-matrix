"""Grant-gated encrypted evidence and sparse foreign inbox admission.

This application seam does not import events into a Ledger or issue receipts.
Configuration, authority resolution and custody are trusted owner-local inputs;
only canonical DM-051 envelope bytes enter the receive methods.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass
from typing import Any

from .canonical import canonical_bytes
from .communication import CommunicationError, _message_payload, _resolution_payload
from .messaging_store import MessagingInboxError, MessagingInboxStore
from .relationship_store import RelationshipStore, RelationshipView
from .sealed import (
    DisclosureAuthorization,
    KeystoreDeliveryCustody,
    RecipientTarget,
    SealedDeliveryError,
    _closed,
    _parse,
    _uint,
    inspect_delivery,
    open_event,
    recipient_descriptor,
    sender_descriptor,
)
from .weave import RootAuthority, verify_event

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
        custody: KeystoreDeliveryCustody,
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

    def page(self, *, after: int, limit: int) -> list[dict[str, Any]]:
        """Manual current-policy read, not a delivered/consumed semantic receipt."""
        now = self.clock()
        rows = self.inbox._page(
            after=after, limit=limit, policy_hash=self._policy_hash(now)
        )
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
        return rows
