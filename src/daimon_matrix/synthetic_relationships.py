"""Deterministic isolated DM-082 relationship, Tribe and grant journey."""

from __future__ import annotations

import argparse
import hashlib
import os
import stat
import threading
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Final, cast

from .canonical import b64url, canonical_bytes
from .communication import (
    MESSAGE_PAYLOAD_SCHEMA,
    RECEIPT_PAYLOAD_SCHEMA,
    RESOLUTION_PAYLOAD_SCHEMA,
    CommunicationStore,
)
from .identity import (
    ControlState,
    create_embodiment_credential,
    create_genesis,
    create_incarnation_authorization,
    ed25519_public,
    key_descriptor,
    signing_descriptor,
    verify_embodiment_credential,
    verify_genesis,
    x25519_public,
)
from .keystore import EncryptedKeystore
from .ledger import Ledger
from .relationship_store import RelationshipStore, RelationshipStoreError
from .relationships import (
    ACCEPTANCE_SCHEMA,
    CARD_SCHEMA,
    DECLARATION_SCHEMA,
    FOUNDER_ACCEPTANCE_SCHEMA,
    FOUNDER_TRANSFER_SCHEMA,
    GRANT_ACCEPTANCE_SCHEMA,
    GRANT_REVOCATION_SCHEMA,
    GRANT_SCHEMA,
    INVITATION_SCHEMA,
    MEMBERSHIP_ACCEPTANCE_SCHEMA,
    OFFER_SCHEMA,
    RESOURCE_SCHEMA,
    card_series_id,
    founder_transfer_id,
    grant_id,
    invitation_id,
    relationship_event_subject,
    relationship_id,
    resource_ref,
    tribe_ref,
    validate_relationship_event_payload,
)
from .routes import (
    ROUTE_BINDING_SCHEMA,
    ROUTE_PROFILE_SCHEMA,
    AuthenticatedProvider,
    DirectHTTPProvider,
    OpaqueInbox,
    RouteCoordinator,
    RouteProfile,
    TransportIngress,
)
from .scopes import ScopeResolver
from .sealed import (
    DisclosureAuthorization,
    KeystoreDeliveryCustody,
    RecipientTarget,
    inspect_delivery,
    open_event,
    seal_event,
)
from .weave import (
    BeingManifest,
    EventSigner,
    RootAuthority,
    RootAuthorityInventory,
    create_event,
)

NOW: Final = 1_800_000_000_000
MAX_TIME: Final = 2**53 - 1
REPORT_SCHEMA: Final = "dm.synthetic-relationship-report/v1"
_UUID_NAMESPACE: Final = uuid.UUID("82000000-0000-4000-8000-000000000000")


class SyntheticRelationshipError(RuntimeError):
    """The isolated journey failed one of its required invariants."""


def _seed(label: str) -> bytes:
    return hashlib.sha256(f"dm082:synthetic:{label}".encode()).digest()


def _uuid(label: str) -> str:
    return str(uuid.uuid5(_UUID_NAMESPACE, label))


def _owner_root(path: Path) -> Path:
    root = Path(os.path.abspath(path))
    if root.exists():
        info = root.lstat()
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid()
            or next(root.iterdir(), None) is not None
        ):
            raise SyntheticRelationshipError("synthetic_relationship_root_rejected")
    else:
        root.mkdir(parents=True, mode=0o700)
    root.chmod(0o700)
    return root


def _transport(label: str, principal_id: str) -> dict[str, Any]:
    return {
        "key": key_descriptor("Ed25519", ed25519_public(_seed(f"{label}:transport"))),
        "principal_id": principal_id,
        "scheme": "synthetic-loopback",
    }


@dataclass(frozen=True)
class _Identity:
    state: ControlState
    authority: RootAuthority
    origin: Mapping[str, str]
    signer: EventSigner
    credential: Mapping[str, Any]


def _identity(label: str) -> _Identity:
    root_seeds = tuple(_seed(f"{label}:root:{index}") for index in range(3))
    recovery_seeds = tuple(_seed(f"{label}:recovery:{index}") for index in range(3))
    genesis = create_genesis(
        root_seeds,
        2,
        recovery_seeds,
        2,
        created_at_ms=0,
        nonce=_seed(f"{label}:being"),
    )
    state = verify_genesis(genesis)
    signing_seed = _seed(f"{label}:signing")
    origin = {
        "body_ref": f"cluster:synthetic:{label}",
        "embodiment_id": f"embodiment:synthetic:{label}",
        "incarnation_id": f"incarnation:synthetic:{label}:0",
        "principal_id": f"synthetic-{label}@loopback",
    }
    credential = create_embodiment_credential(
        state,
        root_seeds,
        signing_seed,
        x25519_public(_seed(f"{label}:encryption")),
        embodiment_id=origin["embodiment_id"],
        body_ref=origin["body_ref"],
        purposes=["dm.we", "messages"],
        valid_from_ms=0,
        valid_until_ms=MAX_TIME,
        transport_principals=[_transport(label, origin["principal_id"])],
    )
    incarnation = create_incarnation_authorization(
        credential,
        signing_seed,
        incarnation_id=origin["incarnation_id"],
        incarnation_sequence=0,
        started_at_ms=0,
    )
    manifest = BeingManifest.from_value(
        {
            "being_ref": state.being_ref,
            "control_head": state.head,
            "embodiments": [
                {
                    "body_ref": origin["body_ref"],
                    "embodiment_credential_id": credential["artifact_id"],
                    "embodiment_id": origin["embodiment_id"],
                    "incarnation_authorization_id": incarnation["artifact_id"],
                    "incarnation_id": origin["incarnation_id"],
                    "status": "active",
                }
            ],
            "history_binding_id": None,
            "revision": 1,
            "schema": "being-manifest/v2",
        }
    )
    authority = RootAuthority(
        manifest,
        state,
        {credential["artifact_id"]: credential},
        {incarnation["artifact_id"]: incarnation},
    )
    signer = EventSigner(signing_descriptor(signing_seed)["key_id"], signing_seed)
    return _Identity(state, authority, origin, signer, credential)


def _event_ref(event: Mapping[str, Any]) -> dict[str, str]:
    return {"event_id": event["event_id"], "event_hash": event["content_hash"]}


class _Journey:
    def __init__(self, root: Path) -> None:
        self.root = _owner_root(root)
        self.identities = {
            "founder": _identity("founder"),
            "member": _identity("member"),
            "delegate": _identity("delegate"),
        }
        if len({item.state.being_ref for item in self.identities.values()}) != len(
            self.identities
        ):
            raise SyntheticRelationshipError("synthetic_relationship_identity_alias")
        self.sequence = {label: 0 for label in self.identities}
        self.previous: dict[str, str | None] = {
            label: None for label in self.identities
        }
        self.authorities = {
            item.state.being_ref: item.authority for item in self.identities.values()
        }
        self.authority_inventory = RootAuthorityInventory(
            self.identities["founder"].authority, self.authorities
        )
        self.now = NOW
        self.store = RelationshipStore(
            self.root / "relationships.sqlite3",
            authority_resolver=lambda being: self.authorities[being],
        )
        self.peer_store = RelationshipStore(
            self.root / "relationships-member.sqlite3",
            authority_resolver=lambda being: self.authorities[being],
        )
        self.ledger = Ledger(
            self.root / "founder-ledger.sqlite3",
            authority=self.authority_inventory,
            local_origin=self.identities["founder"].origin,
            clock=lambda: self.now,
        )
        self.communication = CommunicationStore(self.ledger, clock=lambda: self.now)
        self.communication.initialize()
        self.custodies: dict[str, KeystoreDeliveryCustody] = {}
        self.events: dict[str, dict[str, Any]] = {}

    def custody(self, label: str) -> KeystoreDeliveryCustody:
        cached = self.custodies.get(label)
        if cached is not None:
            return cached
        identity = self.identities[label]
        signing_seed = _seed(f"{label}:signing")
        encryption_seed = _seed(f"{label}:encryption")
        signing_id = identity.credential["body"]["signing_key"]["key_id"]
        encryption_id = identity.credential["body"]["encryption_key"]["key_id"]
        signing_slot = f"sealed.signing.v1:{label}"
        encryption_slot = f"sealed.encryption.v1:{label}"
        directory = self.root / f"custody-{label}"
        directory.mkdir(mode=0o700)

        def password_reader() -> bytearray:
            return bytearray(_seed("custody-password"))

        store = EncryptedKeystore.create(
            directory / "keys.json",
            password_reader,
            control_head=identity.state.head,
            secrets={
                signing_slot: signing_seed,
                encryption_slot: encryption_seed,
            },
        )
        custody = KeystoreDeliveryCustody(
            store,
            password_reader,
            control_head=identity.state.head,
            counter=1,
            signing_slots={signing_id: signing_slot},
            encryption_slots={encryption_id: encryption_slot},
        )
        self.custodies[label] = custody
        return custody

    def append(
        self,
        label: str,
        kind: str,
        payload: Mapping[str, Any],
        *,
        at_ms: int,
    ) -> dict[str, Any]:
        identity = self.identities[label]
        normalized = validate_relationship_event_payload(
            kind,
            payload,
            author_being_ref=identity.state.being_ref,
            causal_parents=(),
        )
        self.sequence[label] += 1
        event = create_event(
            identity.authority,
            identity.origin,
            identity.signer,
            event_id=_uuid(f"{label}:{self.sequence[label]}:{kind}"),
            sequence=self.sequence[label],
            previous_event_id=self.previous[label],
            occurred_at_ms=at_ms,
            causal_parents=(),
            kind=kind,
            subject=relationship_event_subject(kind, normalized),
            payload=normalized,
            supersedes=None,
            sensitivity="shareable",
        )
        self.previous[label] = event["event_id"]
        self.store.ingest(event)
        self.peer_store.ingest(event)
        self.ledger.ingest([event], source=f"synthetic:{label}")
        self.events[f"{label}:{kind}:{self.sequence[label]}"] = event
        return event

    def card_verifier(self, card: Mapping[str, Any], at_ms: int) -> None:
        identities = [
            identity
            for identity in self.identities.values()
            if identity.state.being_ref == card["being_ref"]
        ]
        if len(identities) != 1:
            raise ValueError("unknown_card_being")
        identity = identities[0]
        credential = verify_embodiment_credential(
            identity.credential, identity.state, at_ms=at_ms
        )
        if (
            card["control_position"]["manifest_hash"]
            != identity.authority.manifest.digest
            or card["control_position"]["embodiment_id"]
            != identity.origin["embodiment_id"]
            or card["control_position"]["incarnation_id"]
            != identity.origin["incarnation_id"]
            or card["encryption_key"] != credential["encryption_key"]
            or "messages" not in credential["purposes"]
        ):
            raise ValueError("card_control_mismatch")

    def run(self) -> dict[str, Any]:
        founder = self.identities["founder"]
        member = self.identities["member"]
        delegate = self.identities["delegate"]
        resource = {
            "schema": RESOURCE_SCHEMA,
            "resource_nonce": b64url(_seed("resource")),
            "controller_being_ref": founder.state.being_ref,
            "kind": "knowledge",
            "classification": "shareable",
            "operations": ["read"],
            "descriptor_ref": "dm:content:v1:synthetic-knowledge",
        }
        resource_identifier = resource_ref(resource)

        cards: dict[str, dict[str, Any]] = {}
        for label, identity in self.identities.items():
            card_payload = {
                "schema": CARD_SCHEMA,
                "card_series_id": card_series_id(identity.state.being_ref),
                "sequence": 0,
                "previous_card_event_id": None,
                "being_ref": identity.state.being_ref,
                "control_position": {
                    "manifest_hash": identity.authority.manifest.digest,
                    "embodiment_id": identity.origin["embodiment_id"],
                    "incarnation_id": identity.origin["incarnation_id"],
                },
                "encryption_key": identity.credential["body"]["encryption_key"],
                "route_refs": [f"dm:route:v1:{label}"],
                "capability_refs": ["dm:capability:v1:relationship-v1"],
                "resources": (
                    [
                        {
                            "resource_ref": resource_identifier,
                            "descriptor": resource,
                        }
                    ]
                    if label == "founder"
                    else []
                ),
                "issued_at_ms": NOW,
                "expires_at_ms": NOW + 60_000,
            }
            cards[label] = self.append(
                label, "matrix/relationship-card", card_payload, at_ms=NOW
            )

        nonce = b64url(_seed("relationship"))
        relationship = relationship_id(
            nonce=nonce,
            initiator_being_ref=founder.state.being_ref,
            responder_being_ref=member.state.being_ref,
        )
        permission = {
            "resource_ref": resource_identifier,
            "operations": ["read"],
            "classification": "shareable",
            "delegable": True,
            "remaining_delegation_depth": 1,
        }
        offer_payload = {
            "schema": OFFER_SCHEMA,
            "relationship_id": relationship,
            "nonce": nonce,
            "initiator_being_ref": founder.state.being_ref,
            "responder_being_ref": member.state.being_ref,
            "initiator_card_ref": _event_ref(cards["founder"]),
            "responder_card_ref": _event_ref(cards["member"]),
            "terms_ref": "dm:terms:v1:synthetic-mutual-consent",
            "roles": ["peer"],
            "proposed_grants": [
                {
                    "grantor_being_ref": founder.state.being_ref,
                    "subject_being_ref": member.state.being_ref,
                    "permissions": [permission],
                    "not_before_ms": NOW,
                    "expires_at_ms": NOW + 40_000,
                }
            ],
            "issued_at_ms": NOW + 1,
            "expires_at_ms": NOW + 10_000,
        }
        offer = self.append(
            "founder", "matrix/relationship-offer", offer_payload, at_ms=NOW + 1
        )
        acceptance_payload = {
            "schema": ACCEPTANCE_SCHEMA,
            "relationship_id": relationship,
            "offer_ref": _event_ref(offer),
            "initiator_being_ref": founder.state.being_ref,
            "responder_being_ref": member.state.being_ref,
            "initiator_card_ref": _event_ref(cards["founder"]),
            "responder_card_ref": _event_ref(cards["member"]),
            "accepted_at_ms": NOW + 2,
        }
        acceptance = self.append(
            "member",
            "matrix/relationship-acceptance",
            acceptance_payload,
            at_ms=NOW + 2,
        )

        declaration_core = {
            "created_at_ms": NOW + 3,
            "founder_principal_id": founder.state.being_ref,
            "nonce": b64url(_seed("tribe")),
            "policy_ref": "dm:tribe-policy:v1:synthetic",
        }
        tribe = tribe_ref(declaration_core)
        declaration = self.append(
            "founder",
            "matrix/tribe-declaration",
            {
                "schema": DECLARATION_SCHEMA,
                "tribe_ref": tribe,
                "declaration": declaration_core,
            },
            at_ms=NOW + 3,
        )
        invite_nonce = b64url(_seed("invitation"))
        invitation_identifier = invitation_id(
            tribe=tribe,
            founder_epoch=0,
            invitee_being_ref=member.state.being_ref,
            nonce=invite_nonce,
        )
        invitation = self.append(
            "founder",
            "matrix/tribe-invitation",
            {
                "schema": INVITATION_SCHEMA,
                "tribe_ref": tribe,
                "founder_epoch": 0,
                "founder_being_ref": founder.state.being_ref,
                "invitation_id": invitation_identifier,
                "invitee_being_ref": member.state.being_ref,
                "nonce": invite_nonce,
                "issued_at_ms": NOW + 4,
                "expires_at_ms": NOW + 10_000,
            },
            at_ms=NOW + 4,
        )
        membership = self.append(
            "member",
            "matrix/tribe-membership-acceptance",
            {
                "schema": MEMBERSHIP_ACCEPTANCE_SCHEMA,
                "tribe_ref": tribe,
                "founder_epoch": 0,
                "invitation_ref": _event_ref(invitation),
                "invitee_being_ref": member.state.being_ref,
                "membership_sequence": 0,
                "previous_membership_terminal_ref": None,
                "accepted_at_ms": NOW + 5,
            },
            at_ms=NOW + 5,
        )

        grant_nonce = b64url(_seed("grant"))
        grant_identifier = grant_id(
            nonce=grant_nonce,
            relationship=relationship,
            grantor_being_ref=founder.state.being_ref,
            subject_being_ref=member.state.being_ref,
        )
        grant = self.append(
            "founder",
            "matrix/relationship-grant",
            {
                "schema": GRANT_SCHEMA,
                "grant_id": grant_identifier,
                "nonce": grant_nonce,
                "relationship_id": relationship,
                "tribe_ref": tribe,
                "grantor_being_ref": founder.state.being_ref,
                "subject_being_ref": member.state.being_ref,
                "permissions": [permission],
                "not_before_ms": NOW,
                "expires_at_ms": NOW + 40_000,
                "issued_at_ms": NOW + 6,
                "parent_grant_ref": None,
                "delegation_sequence": 0,
                "previous_delegation_event_id": None,
            },
            at_ms=NOW + 6,
        )
        grant_acceptance = self.append(
            "member",
            "matrix/relationship-grant-acceptance",
            {
                "schema": GRANT_ACCEPTANCE_SCHEMA,
                "grant_id": grant_identifier,
                "grant_ref": _event_ref(grant),
                "relationship_id": relationship,
                "grantor_being_ref": founder.state.being_ref,
                "subject_being_ref": member.state.being_ref,
                "accepted_at_ms": NOW + 7,
            },
            at_ms=NOW + 7,
        )
        active_view = self.store.view(at_ms=NOW + 8, card_verifier=self.card_verifier)
        active_snapshot = active_view.snapshot(tribe)
        if (
            active_view.relationships[relationship]["state"] != "active"
            or active_view.grants[grant_identifier]["state"] != "active"
            or len(active_snapshot.value["members"]) != 2
            or len(active_snapshot.value["grants"]) != 1
        ):
            raise SyntheticRelationshipError("synthetic_relationship_not_active")

        disclosure = active_view.disclosure(
            requester_being_ref=member.state.being_ref,
            resource_ref=resource_identifier,
            operation="read",
            classification="shareable",
        )
        if not disclosure["authorized"]:
            raise SyntheticRelationshipError("synthetic_disclosure_not_authorized")
        self.sequence["founder"] += 1
        message = create_event(
            founder.authority,
            founder.origin,
            founder.signer,
            event_id=_uuid("relationship-authorized-message"),
            sequence=self.sequence["founder"],
            previous_event_id=self.previous["founder"],
            occurred_at_ms=NOW + 8,
            causal_parents=(),
            kind="experience.observed",
            subject="communication",
            payload={
                "schema": MESSAGE_PAYLOAD_SCHEMA,
                "body": {
                    "operation": "read",
                    "resource_ref": resource_identifier,
                    "text": "synthetic authorized relationship delivery",
                },
                "intent": {
                    "operation": "read",
                    "scope": "/tribe",
                    "thread_id": _uuid("relationship-authorized-thread"),
                },
                "reply": None,
            },
            supersedes=None,
            sensitivity="shareable",
        )
        self.previous["founder"] = message["event_id"]
        self.ledger.ingest([message], source="synthetic:founder")
        dm054_resolution = ScopeResolver(
            self.ledger,
            clock=lambda: self.now,
            tribes={tribe: active_snapshot},
        ).resolution(
            scope="/tribe",
            request_id=_uuid("relationship-scope-resolution"),
            tribe_ref=tribe,
        )
        member_scope_targets = [
            row
            for row in dm054_resolution["targets"]
            if row["receipt_origin_embodiment_id"] == member.origin["embodiment_id"]
        ]
        if len(member_scope_targets) != 1:
            raise SyntheticRelationshipError("synthetic_relationship_scope_ambiguous")
        self.sequence["founder"] += 1
        resolution = create_event(
            founder.authority,
            founder.origin,
            founder.signer,
            event_id=_uuid("relationship-message-resolution"),
            sequence=self.sequence["founder"],
            previous_event_id=self.previous["founder"],
            occurred_at_ms=NOW + 8,
            causal_parents=(message["event_id"],),
            kind="experience.observed",
            subject="communication-resolution",
            payload={
                "schema": RESOLUTION_PAYLOAD_SCHEMA,
                "message_id": message["event_id"],
                "scope": "/tribe",
                "targets": member_scope_targets,
            },
            supersedes=None,
            sensitivity="shareable",
        )
        self.previous["founder"] = resolution["event_id"]
        self.ledger.ingest([resolution], source="synthetic:founder")
        communication_result = self.communication.accept(
            message_event_id=message["event_id"],
            resolution_event_id=resolution["event_id"],
        )
        if len(communication_result["legs"]) != 1:
            raise SyntheticRelationshipError("synthetic_relationship_leg_ambiguous")
        semantic_leg = communication_result["legs"][0]
        relationship_recipient_id = cast(str, member_scope_targets[0]["recipient_id"])
        if (
            semantic_leg["recipient_type"] != "relationship"
            or semantic_leg["recipient_id"] != relationship_recipient_id
        ):
            raise SyntheticRelationshipError("synthetic_relationship_leg_mismatch")
        member_target = RecipientTarget(
            member.authority, member.credential["artifact_id"]
        )
        authorization = DisclosureAuthorization.from_relationship_resolution_event(
            event=message,
            resolution_event=resolution,
            sender_authority=founder.authority,
            recipient_targets=[member_target],
            disclosures={relationship_recipient_id: disclosure},
            expires_at_ms=NOW + 30_000,
            authorization_id=_uuid("relationship-delivery-authorization"),
        )
        sealed = seal_event(
            message,
            sender_authority=founder.authority,
            recipients=[member_target],
            authorization=authorization,
            custody=self.custody("founder"),
            issued_at_ms=NOW + 8,
            expires_at_ms=NOW + 20_000,
        )
        route_secret = _seed("relationship-route-secret")
        route_directory = self.root / "relationship-route"
        route_directory.mkdir(mode=0o700)
        inbox = OpaqueInbox(route_directory / "inbox.sqlite3", clock=lambda: self.now)
        opened_events: list[Mapping[str, Any]] = []

        def validate_intake(raw: bytes) -> None:
            current_disclosure = self.peer_store.view(
                at_ms=self.now, card_verifier=self.card_verifier
            ).disclosure(
                requester_being_ref=member.state.being_ref,
                resource_ref=resource_identifier,
                operation="read",
                classification="shareable",
            )
            current_authorization = (
                DisclosureAuthorization.from_relationship_resolution_event(
                    event=message,
                    resolution_event=resolution,
                    sender_authority=founder.authority,
                    recipient_targets=[member_target],
                    disclosures={relationship_recipient_id: current_disclosure},
                    expires_at_ms=NOW + 30_000,
                    authorization_id=_uuid("relationship-delivery-authorization"),
                )
            )
            opened_events.append(
                open_event(
                    raw,
                    sender_authority=founder.authority,
                    local_target=member_target,
                    recipient_targets=[member_target],
                    authorization=current_authorization,
                    custody=self.custody("member"),
                    at_ms=self.now,
                )
            )

        ingress = TransportIngress(
            provider_ref="provider:synthetic-relationship",
            route_ref="route:synthetic-relationship",
            key_ref="credential:synthetic-relationship",
            secret=route_secret,
            recipient_id=relationship_recipient_id,
            recipient_embodiment_id=member.origin["embodiment_id"],
            recipient_body_ref=member.origin["body_ref"],
            inbox=inbox,
            clock=lambda: self.now,
            intake_validator=validate_intake,
        )

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                size = int(self.headers["Content-Length"])
                response = ingress.handle(self.rfile.read(size))
                self.send_response(200)
                self.send_header("Content-Type", "application/daimon+jcs")
                self.send_header("Content-Length", str(len(response)))
                self.end_headers()
                self.wfile.write(response)

            def log_message(self, _format: str, *args: object) -> None:
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.now = NOW + 9
        try:
            host, port = cast(tuple[str, int], server.server_address)
            provider = DirectHTTPProvider(
                provider_ref="provider:synthetic-relationship",
                route_ref="route:synthetic-relationship",
                route_class="direct-anyvpn",
                key_ref="credential:synthetic-relationship",
                secret=route_secret,
                sender_principal=founder.origin["principal_id"],
                sender_body_ref=founder.origin["body_ref"],
                endpoint=f"http://{host}:{port}/dm-route",
                clock=lambda: self.now,
            )
            profile = RouteProfile.from_value(
                {
                    "schema": ROUTE_PROFILE_SCHEMA,
                    "profile_id": "route-profile:synthetic-founder",
                    "body_ref": founder.origin["body_ref"],
                    "principal_id": founder.origin["principal_id"],
                    "policy_version": "dm.route-policy/v1",
                    "enabled": True,
                    "local_recipient_ids": [],
                    "routes": [
                        {
                            "schema": ROUTE_BINDING_SCHEMA,
                            "adapter_id": "adapter:synthetic-relationship",
                            "provider_ref": "provider:synthetic-relationship",
                            "route_ref": "route:synthetic-relationship",
                            "route_class": "direct-anyvpn",
                            "priority": 0,
                            "recipient_id": relationship_recipient_id,
                            "recipient_body_ref": member.origin["body_ref"],
                            "credential_ref": "credential:synthetic-relationship",
                            "enabled": True,
                        }
                    ],
                }
            )
            coordinator = RouteCoordinator(
                self.communication,
                profile,
                {provider.provider_ref: provider},
                clock=lambda: self.now,
            )
            dispatched = coordinator.dispatch(
                leg_id=semantic_leg["leg_id"],
                envelope=sealed,
                deadline_ms=NOW + 19_000,
            )
            replayed_dispatch = coordinator.dispatch(
                leg_id=semantic_leg["leg_id"],
                envelope=sealed,
                deadline_ms=NOW + 19_000,
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
        if (
            dispatched["selected"]["outcome"] != "recipient-intake"
            or canonical_bytes(dispatched) != canonical_bytes(replayed_dispatch)
            or len(opened_events) != 2
            or any(
                canonical_bytes(opened) != canonical_bytes(message)
                for opened in opened_events
            )
            or b"synthetic authorized relationship delivery" in sealed
            or self.communication.leg(semantic_leg["leg_id"])["state"] != "accepted"
        ):
            raise SyntheticRelationshipError("synthetic_encrypted_intake_failed")
        intake_evidence_ref = "dm:intake:v1:" + b64url(
            hashlib.sha256(
                canonical_bytes(
                    {
                        "authorization_id": authorization.value["authorization_id"],
                        "message_hash": message["content_hash"],
                        "recipient_id": relationship_recipient_id,
                    }
                )
            ).digest()
        )
        self.sequence["member"] += 1
        receipt = create_event(
            member.authority,
            member.origin,
            member.signer,
            event_id=_uuid("relationship-message-receipt"),
            sequence=self.sequence["member"],
            previous_event_id=self.previous["member"],
            occurred_at_ms=NOW + 9,
            causal_parents=(message["event_id"],),
            kind="experience.observed",
            subject="communication-receipt",
            payload={
                "schema": RECEIPT_PAYLOAD_SCHEMA,
                "message_id": message["event_id"],
                "thread_id": message["payload"]["intent"]["thread_id"],
                "recipient_type": "relationship",
                "recipient_id": relationship_recipient_id,
                "outcome": "delivered",
                "observed_at_ms": NOW + 9,
                "evidence_ref": intake_evidence_ref,
            },
            supersedes=None,
            sensitivity="shareable",
        )
        self.previous["member"] = receipt["event_id"]
        self.ledger.ingest([receipt], source="synthetic:member")
        delivered = self.communication.record_receipt(receipt["event_id"])
        if not delivered["terminal"] or delivered["legs"][0]["state"] != "delivered":
            raise SyntheticRelationshipError("synthetic_semantic_receipt_failed")

        delegate_nonce = b64url(_seed("delegate-relationship"))
        delegate_relationship = relationship_id(
            nonce=delegate_nonce,
            initiator_being_ref=member.state.being_ref,
            responder_being_ref=delegate.state.being_ref,
        )
        delegate_offer = self.append(
            "member",
            "matrix/relationship-offer",
            {
                "schema": OFFER_SCHEMA,
                "relationship_id": delegate_relationship,
                "nonce": delegate_nonce,
                "initiator_being_ref": member.state.being_ref,
                "responder_being_ref": delegate.state.being_ref,
                "initiator_card_ref": _event_ref(cards["member"]),
                "responder_card_ref": _event_ref(cards["delegate"]),
                "terms_ref": "dm:terms:v1:synthetic-delegation",
                "roles": ["peer"],
                "proposed_grants": [],
                "issued_at_ms": NOW + 9,
                "expires_at_ms": NOW + 10_000,
            },
            at_ms=NOW + 9,
        )
        self.append(
            "delegate",
            "matrix/relationship-acceptance",
            {
                "schema": ACCEPTANCE_SCHEMA,
                "relationship_id": delegate_relationship,
                "offer_ref": _event_ref(delegate_offer),
                "initiator_being_ref": member.state.being_ref,
                "responder_being_ref": delegate.state.being_ref,
                "initiator_card_ref": _event_ref(cards["member"]),
                "responder_card_ref": _event_ref(cards["delegate"]),
                "accepted_at_ms": NOW + 10,
            },
            at_ms=NOW + 10,
        )
        child_permission = {
            **permission,
            "delegable": False,
            "remaining_delegation_depth": 0,
        }
        child_nonce = b64url(_seed("child-grant"))
        child_grant_identifier = grant_id(
            nonce=child_nonce,
            relationship=delegate_relationship,
            grantor_being_ref=member.state.being_ref,
            subject_being_ref=delegate.state.being_ref,
        )
        child_grant = self.append(
            "member",
            "matrix/relationship-grant",
            {
                "schema": GRANT_SCHEMA,
                "grant_id": child_grant_identifier,
                "nonce": child_nonce,
                "relationship_id": delegate_relationship,
                "tribe_ref": None,
                "grantor_being_ref": member.state.being_ref,
                "subject_being_ref": delegate.state.being_ref,
                "permissions": [child_permission],
                "not_before_ms": NOW,
                "expires_at_ms": NOW + 30_000,
                "issued_at_ms": NOW + 11,
                "parent_grant_ref": _event_ref(grant),
                "delegation_sequence": 0,
                "previous_delegation_event_id": None,
            },
            at_ms=NOW + 11,
        )
        child_acceptance = self.append(
            "delegate",
            "matrix/relationship-grant-acceptance",
            {
                "schema": GRANT_ACCEPTANCE_SCHEMA,
                "grant_id": child_grant_identifier,
                "grant_ref": _event_ref(child_grant),
                "relationship_id": delegate_relationship,
                "grantor_being_ref": member.state.being_ref,
                "subject_being_ref": delegate.state.being_ref,
                "accepted_at_ms": NOW + 12,
            },
            at_ms=NOW + 12,
        )
        delegated_view = self.store.view(
            at_ms=NOW + 13, card_verifier=self.card_verifier
        )
        if delegated_view.grants[child_grant_identifier]["state"] != "active":
            raise SyntheticRelationshipError("synthetic_attenuation_not_active")

        transfer_nonce = b64url(_seed("founder-transfer"))
        transfer_identifier = founder_transfer_id(
            tribe=tribe,
            from_epoch=0,
            successor_being_ref=member.state.being_ref,
            nonce=transfer_nonce,
        )
        transfer = self.append(
            "founder",
            "matrix/tribe-founder-transfer",
            {
                "schema": FOUNDER_TRANSFER_SCHEMA,
                "tribe_ref": tribe,
                "transfer_id": transfer_identifier,
                "from_epoch": 0,
                "to_epoch": 1,
                "old_founder_being_ref": founder.state.being_ref,
                "successor_being_ref": member.state.being_ref,
                "nonce": transfer_nonce,
                "issued_at_ms": NOW + 14,
            },
            at_ms=NOW + 14,
        )
        transfer_acceptance = self.append(
            "member",
            "matrix/tribe-founder-acceptance",
            {
                "schema": FOUNDER_ACCEPTANCE_SCHEMA,
                "tribe_ref": tribe,
                "transfer_id": transfer_identifier,
                "transfer_ref": _event_ref(transfer),
                "from_epoch": 0,
                "to_epoch": 1,
                "successor_being_ref": member.state.being_ref,
                "accepted_at_ms": NOW + 15,
            },
            at_ms=NOW + 15,
        )
        revocation = self.append(
            "founder",
            "matrix/relationship-grant-revocation",
            {
                "schema": GRANT_REVOCATION_SCHEMA,
                "grant_id": grant_identifier,
                "grant_ref": _event_ref(grant),
                "acceptance_ref": _event_ref(grant_acceptance),
                "actor_being_ref": founder.state.being_ref,
                "action": "revoke",
                "reason": "synthetic-complete",
                "revoked_at_ms": NOW + 16,
            },
            at_ms=NOW + 16,
        )
        final_view = self.store.view(at_ms=NOW + 17, card_verifier=self.card_verifier)
        final_snapshot = final_view.snapshot(tribe)
        if (
            final_view.tribes[tribe]["founder_epoch"] != 1
            or final_view.tribes[tribe]["founder_being_ref"] != member.state.being_ref
            or final_view.grants[grant_identifier]["state"] != "revoked"
            or final_view.grants[child_grant_identifier]["state"] != "revoked"
            or final_snapshot.value["grants"]
        ):
            raise SyntheticRelationshipError("synthetic_relationship_revocation_failed")
        denied_disclosure = final_view.disclosure(
            requester_being_ref=member.state.being_ref,
            resource_ref=resource_identifier,
            operation="read",
            classification="shareable",
        )
        if denied_disclosure != {
            "schema": "dm.relationship.disclosure/v1",
            "authorized": False,
            "authorization": None,
        }:
            raise SyntheticRelationshipError("synthetic_revocation_disclosure_open")

        self.now = NOW + 17
        delivery_metadata = inspect_delivery(sealed, at_ms=self.now)
        stale_submission = {
            "schema": "dm.route-submission/v1",
            "attempt_id": _uuid("stale-direct-attempt"),
            "leg_id": semantic_leg["leg_id"],
            "message_id": message["event_id"],
            "recipient_id": relationship_recipient_id,
            "delivery_id": delivery_metadata["delivery_id"],
            "envelope_sha256": delivery_metadata["envelope_sha256"],
            "envelope": b64url(sealed),
            "deadline_ms": NOW + 19_000,
        }
        opened_before_stale_attempts = len(opened_events)
        stale_direct = AuthenticatedProvider(
            provider_ref="provider:synthetic-relationship",
            route_ref="route:synthetic-relationship",
            route_class="direct-anyvpn",
            key_ref="credential:synthetic-relationship",
            secret=route_secret,
            sender_principal=founder.origin["principal_id"],
            sender_body_ref=founder.origin["body_ref"],
            round_trip=ingress.handle,
            clock=lambda: self.now,
        ).deliver(stale_submission)

        hub_directory = self.root / "relationship-hub"
        hub_directory.mkdir(mode=0o700)
        hub_inbox = OpaqueInbox(hub_directory / "inbox.sqlite3", clock=lambda: self.now)
        hub_ingress = TransportIngress(
            provider_ref="provider:synthetic-hub",
            route_ref="route:synthetic-hub",
            key_ref="credential:synthetic-hub",
            secret=route_secret,
            recipient_id=relationship_recipient_id,
            recipient_embodiment_id=member.origin["embodiment_id"],
            recipient_body_ref=member.origin["body_ref"],
            inbox=hub_inbox,
            clock=lambda: self.now,
            hub=True,
        )
        hub_submission = {
            **stale_submission,
            "attempt_id": _uuid("stale-hub-attempt"),
        }
        stale_hub = AuthenticatedProvider(
            provider_ref="provider:synthetic-hub",
            route_ref="route:synthetic-hub",
            route_class="hub",
            key_ref="credential:synthetic-hub",
            secret=route_secret,
            sender_principal=founder.origin["principal_id"],
            sender_body_ref=founder.origin["body_ref"],
            round_trip=hub_ingress.handle,
            clock=lambda: self.now,
        ).deliver(hub_submission)
        hub_claim = hub_inbox.claim(
            recipient_id=relationship_recipient_id,
            consumer_id="consumer:synthetic-hub-forwarder",
            claim_id=_uuid("stale-hub-claim"),
            limit=1,
            lease_until_ms=NOW + 18_000,
        )
        forwarded_stale = AuthenticatedProvider(
            provider_ref="provider:synthetic-relationship",
            route_ref="route:synthetic-relationship",
            route_class="direct-anyvpn",
            key_ref="credential:synthetic-relationship",
            secret=route_secret,
            sender_principal="synthetic-hub-forwarder@loopback",
            sender_body_ref="cluster:synthetic:hub-forwarder",
            round_trip=ingress.handle,
            clock=lambda: self.now,
        ).deliver(
            {
                **stale_submission,
                "attempt_id": _uuid("stale-hub-forward-attempt"),
            }
        )
        if (
            stale_direct["outcome"] != "refused"
            or stale_hub["outcome"] != "hub-accepted"
            or len(hub_claim["items"]) != 1
            or forwarded_stale["outcome"] != "refused"
            or len(opened_events) != opened_before_stale_attempts
        ):
            raise SyntheticRelationshipError("synthetic_stale_delivery_not_refused")

        restarted = RelationshipStore(
            self.store.path,
            authority_resolver=self.store.authority_resolver,
        )
        restarted_view = restarted.view(
            at_ms=NOW + 17, card_verifier=self.card_verifier
        )
        if restarted_view.report() != final_view.report():
            raise SyntheticRelationshipError("synthetic_relationship_restart_drift")
        restarted_peer = RelationshipStore(
            self.peer_store.path,
            authority_resolver=self.peer_store.authority_resolver,
        )
        if (
            restarted_peer.view(
                at_ms=NOW + 17, card_verifier=self.card_verifier
            ).report()
            != final_view.report()
            or restarted_peer.cursor() != restarted.cursor()
        ):
            raise SyntheticRelationshipError("synthetic_peer_restart_drift")
        retry = restarted.ingest(revocation)
        if retry != revocation or restarted.cursor() != self.store.cursor():
            raise SyntheticRelationshipError("synthetic_relationship_replay_drift")

        report = {
            "schema": REPORT_SCHEMA,
            "being_refs": sorted(
                identity.state.being_ref for identity in self.identities.values()
            ),
            "relationship_id": relationship,
            "tribe_ref": tribe,
            "grant_id": grant_identifier,
            "child_grant_id": child_grant_identifier,
            "active_snapshot_hash": hashlib.sha256(
                canonical_bytes(active_snapshot.value)
            ).hexdigest(),
            "final_snapshot_hash": hashlib.sha256(
                canonical_bytes(final_snapshot.value)
            ).hexdigest(),
            "cursor_hash": restarted.cursor()["cursor_hash"],
            "final_history": final_view.report(),
            "evidence": {
                "offer_event_id": offer["event_id"],
                "acceptance_event_id": acceptance["event_id"],
                "declaration_event_id": declaration["event_id"],
                "membership_event_id": membership["event_id"],
                "message_event_id": message["event_id"],
                "resolution_event_id": resolution["event_id"],
                "receipt_event_id": receipt["event_id"],
                "grant_event_id": grant["event_id"],
                "grant_acceptance_event_id": grant_acceptance["event_id"],
                "child_grant_event_id": child_grant["event_id"],
                "child_acceptance_event_id": child_acceptance["event_id"],
                "transfer_event_id": transfer["event_id"],
                "transfer_acceptance_event_id": transfer_acceptance["event_id"],
                "revocation_event_id": revocation["event_id"],
            },
            "invariants": {
                "distinct_beings": True,
                "bilateral_consent_before_relationship": True,
                "membership_separate_from_grant": True,
                "grant_requires_subject_acceptance": True,
                "delegation_is_strictly_attenuated": True,
                "ancestor_revocation_cascades": True,
                "route_ack_is_not_consent": True,
                "route_ack_is_not_semantic_delivery": True,
                "authenticated_intake_creates_signed_delivery": True,
                "recipient_encrypted_delivery_opens_only_after_grant": True,
                "revocation_blocks_disclosure_before_sealing": True,
                "revocation_refuses_stale_direct_and_hub_forward": True,
                "independent_observer_cursors_converge": True,
                "founder_transfer_is_two_party": True,
                "revocation_survives_restart": True,
                "exact_replay_is_idempotent": True,
                "no_external_contact": True,
            },
        }
        return report


def run_synthetic_relationships(root: Path) -> dict[str, Any]:
    return cast(dict[str, Any], synthetic_relationship_evidence(root)["report"])


def synthetic_relationship_evidence(root: Path) -> dict[str, Any]:
    """Return the report and complete signed event set for published vectors."""

    journey = _Journey(root)
    report = journey.run()
    return {"events": journey.store.events(), "report": report}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", "--state-root", dest="root", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        report = run_synthetic_relationships(args.root)
    except (
        RelationshipStoreError,
        SyntheticRelationshipError,
        ValueError,
    ) as exception:
        print(str(exception))
        return 1
    raw = canonical_bytes(report) + b"\n"
    if args.output is None:
        import sys

        sys.stdout.buffer.write(raw)
    else:
        args.output.write_bytes(raw)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "REPORT_SCHEMA",
    "SyntheticRelationshipError",
    "run_synthetic_relationships",
    "synthetic_relationship_evidence",
]
