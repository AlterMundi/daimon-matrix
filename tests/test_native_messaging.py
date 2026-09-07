"""Independent foreign intake: synthetic keys, real signed grants and HPKE."""

from __future__ import annotations

import copy
import json
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from typing import Any

from daimon_matrix.canonical import canonical_bytes
from daimon_matrix.communication import (
    MESSAGE_PAYLOAD_SCHEMA,
    RESOLUTION_PAYLOAD_SCHEMA,
)
from daimon_matrix.keystore import EncryptedKeystore
from daimon_matrix.ledger import Ledger
from daimon_matrix.relationship_store import RelationshipStore
from daimon_matrix.sealed import (
    DisclosureAuthorization,
    KeystoreDeliveryCustody,
    RecipientTarget,
    seal_event,
)
from daimon_matrix.synthetic_relationships import NOW, _identity, _seed, _uuid
from daimon_matrix.weave import create_event

ROOT = Path(__file__).resolve().parents[1]
TEXT = "Only the independently authorized recipient may read this native message."


def custody(root: Path, label: str) -> KeystoreDeliveryCustody:
    identity = _identity(label)
    root.mkdir(mode=0o700)
    store = EncryptedKeystore.create(
        root / "keys.json",
        lambda: bytearray(b"synthetic-native-messaging"),
        control_head=identity.state.head,
        secrets={
            "sealed.signing.v1:test": _seed(f"{label}:signing"),
            "sealed.encryption.v1:test": _seed(f"{label}:encryption"),
        },
    )
    return KeystoreDeliveryCustody(
        store,
        lambda: bytearray(b"synthetic-native-messaging"),
        control_head=identity.state.head,
        counter=1,
        signing_slots={
            identity.credential["body"]["signing_key"][
                "key_id"
            ]: "sealed.signing.v1:test"
        },
        encryption_slots={
            identity.credential["body"]["encryption_key"][
                "key_id"
            ]: "sealed.encryption.v1:test"
        },
    )


class Pair:
    def __init__(self, root: Path) -> None:
        from daimon_matrix.messaging import (
            GrantReference,
            MessagingChannel,
            MessagingPeerPolicy,
        )
        from daimon_matrix.messaging_store import MessagingInboxStore

        self.sender = _identity("founder")
        self.recipient = _identity("member")
        # Only public RootAuthority objects are injected into the receiver resolver.
        public = {
            identity.state.being_ref: copy.deepcopy(identity.authority)
            for identity in (self.sender, self.recipient, _identity("delegate"))
        }
        self.public = public
        self.sender_relationships = RelationshipStore(
            root / "sender" / "relationships.sqlite3",
            authority_resolver=lambda being_ref: public[being_ref],
        )
        self.receiver_relationships = RelationshipStore(
            root / "receiver" / "relationships.sqlite3",
            authority_resolver=lambda being_ref: public[being_ref],
        )
        self.history = [
            json.loads(path.read_bytes())
            for path in sorted((ROOT / "vectors/relationships/v1/valid").glob("*.json"))
        ]
        for event in self.history:
            if event["occurred_at_ms"] <= NOW + 7:
                self.sender_relationships.ingest(event)
                self.receiver_relationships.ingest(copy.deepcopy(event))
        self.grant = next(
            event
            for event in self.history
            if event["kind"] == "matrix/relationship-grant"
            and event["being_ref"] == self.sender.state.being_ref
        )
        membership = next(
            event
            for event in self.history
            if event["kind"] == "matrix/tribe-membership-acceptance"
            and event["being_ref"] == self.recipient.state.being_ref
        )
        self.policy = MessagingPeerPolicy(
            peer_being_ref=self.sender.state.being_ref,
            peer_embodiment_id=self.sender.origin["embodiment_id"],
            peer_credential_id=self.sender.credential["artifact_id"],
            relationship_id=self.grant["payload"]["relationship_id"],
            tribe_ref=self.grant["payload"]["tribe_ref"],
            membership_ref=membership["event_id"],
            resource_ref=self.grant["payload"]["permissions"][0]["resource_ref"],
            operation="read",
            classification="shareable",
            grant_refs=(
                GrantReference(
                    self.grant["payload"]["grant_id"],
                    self.grant["event_id"],
                    self.grant["content_hash"],
                ),
            ),
        )
        self.sender_custody = custody(root / "sender" / "custody", "founder")
        self.receiver_custody = custody(root / "receiver" / "custody", "member")
        self.now = NOW + 10
        self.store_path = root / "receiver" / "foreign-inbox.sqlite3"
        self.store = MessagingInboxStore(self.store_path)
        self.channel_options = dict(
            policy=self.policy,
            local_being_ref=self.recipient.state.being_ref,
            local_credential_id=self.recipient.credential["artifact_id"],
            authority_resolver=lambda being_ref: public[being_ref],
            custody=self.receiver_custody,
        )
        self.receiver = MessagingChannel(
            **self.channel_options,
            relationships=self.receiver_relationships,
            inbox=self.store,
            clock=lambda: self.now,
        )
        self.sender_context = MessagingChannel(
            **{**self.channel_options, "custody": self.sender_custody},
            relationships=self.sender_relationships,
            inbox=MessagingInboxStore(root / "sender" / "unused-inbox.sqlite3"),
            clock=lambda: NOW + 10,
        )
        self.local_ledger = Ledger(
            root / "receiver" / "local.sqlite3",
            authority=self.recipient.authority,
            local_origin=self.recipient.origin,
            clock=lambda: NOW + 10,
        )
        self.local_ledger.initialize()

    def event(
        self,
        subject: str,
        payload: dict[str, Any],
        sequence: int,
        parents: tuple[str, ...] = (),
    ) -> dict[str, Any]:
        return create_event(
            self.sender.authority,
            self.sender.origin,
            self.sender.signer,
            event_id=_uuid(f"native:{subject}:{sequence}"),
            sequence=sequence,
            previous_event_id=_uuid(f"native:previous:{sequence}"),
            occurred_at_ms=NOW + 8,
            causal_parents=parents,
            kind="experience.observed",
            subject=subject,
            payload=payload,
            sensitivity="shareable",
        )

    def wire(
        self, sequence: int = 100
    ) -> tuple[bytes, bytes, dict[str, Any], dict[str, Any]]:
        message = self.event(
            "communication",
            {
                "schema": MESSAGE_PAYLOAD_SCHEMA,
                "body": {"text": TEXT, "resource_ref": self.policy.resource_ref},
                "intent": {
                    "operation": "read",
                    "scope": "/tribe",
                    "thread_id": _uuid("native-thread"),
                },
                "reply": None,
            },
            sequence,
        )
        resolution = self.event(
            "communication-resolution",
            {
                "schema": RESOLUTION_PAYLOAD_SCHEMA,
                "message_id": message["event_id"],
                "scope": "/tribe",
                "targets": [
                    {
                        "evidence_cursor": "signed-selection-not-grant-authority",
                        "receipt_origin_embodiment_id": self.recipient.origin[
                            "embodiment_id"
                        ],
                        "recipient_id": self.policy.membership_ref,
                        "recipient_type": "relationship",
                        "scope_kind": "relationship",
                    }
                ],
            },
            sequence + 1,
            (message["event_id"],),
        )
        target = RecipientTarget(
            self.recipient.authority, self.recipient.credential["artifact_id"]
        )
        authorization = DisclosureAuthorization.from_relationship_resolution_event(
            event=message,
            resolution_event=resolution,
            sender_authority=self.sender.authority,
            recipient_targets=[target],
            disclosures={self.policy.membership_ref: self.sender_context.disclosure()},
            expires_at_ms=NOW + 30_000,
            authorization_id=_uuid(f"native-auth:{sequence}"),
        )
        evidence = self.event(
            "communication-evidence",
            {
                "schema": "dm.communication.evidence-package/v1",
                "message_id": message["event_id"],
                "message_hash": message["content_hash"],
                "resolution_event": resolution,
                "message_authorization_id": authorization.value["authorization_id"],
                "message_authorized_at_ms": authorization.value["authorized_at_ms"],
                "message_expires_at_ms": authorization.value["expires_at_ms"],
            },
            sequence + 2,
        )
        bootstrap = self.sender_context.evidence_authorization(
            evidence,
            authorized_at_ms=NOW + 10,
            expires_at_ms=NOW + 20_000,
            authorization_id=_uuid(f"native-bootstrap:{sequence}"),
        )
        options: dict[str, Any] = dict(
            sender_authority=self.sender.authority,
            recipients=[target],
            custody=self.sender_custody,
            issued_at_ms=NOW + 10,
            expires_at_ms=NOW + 20_000,
        )
        return (
            seal_event(evidence, authorization=bootstrap, **options),
            seal_event(message, authorization=authorization, **options),
            message,
            evidence,
        )


class NativeMessagingTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="dm132-native-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def make_sender(self, pair: Pair) -> Any:
        from daimon_matrix.messaging import MessagingSender
        from daimon_matrix.messaging_store import MessagingOutboxStore

        ledger = Ledger(
            self.root / "sender/local.sqlite3",
            authority=pair.sender.authority,
            local_origin=pair.sender.origin,
            clock=lambda: pair.now,
        )
        ledger.initialize()
        return MessagingSender(
            context=pair.sender_context,
            ledger=ledger,
            signer=pair.sender.signer,
            custody=pair.sender_custody,
            outbox=MessagingOutboxStore(self.root / "sender/outbox.sqlite3"),
            clock=lambda: pair.now,
        )

    def test_sender_recovers_interrupted_authoring_without_duplicate_events(
        self,
    ) -> None:
        from unittest.mock import patch

        from daimon_matrix.weave import EventSigner

        pair = Pair(self.root)
        sender = self.make_sender(pair)
        request = dict(
            client_id="owner-ui",
            send_id=_uuid("interrupted-send"),
            thread_id=_uuid("thread"),
            text=TEXT,
        )
        original = EventSigner.signature
        calls = 0

        def interrupted(signer: EventSigner, content_hash: str) -> dict[str, str]:
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("synthetic signing device interrupted")
            return dict(original(signer, content_hash))

        with (
            patch.object(EventSigner, "signature", new=interrupted),
            self.assertRaises(OSError),
        ):
            sender.prepare(**request)
        partial = sender.ledger.events()
        self.assertEqual(len(partial), 1)
        self.assertIsNone(
            sender.outbox._prepared(pair.sender.state.being_ref, request["send_id"])
        )
        pair.now += 1
        restarted = self.make_sender(pair)
        evidence, message = restarted.prepare(**request)
        recovered = restarted.ledger.events()
        self.assertEqual(len(recovered), 3)
        self.assertEqual(recovered[0], partial[0])
        pair.receiver.receive_evidence(evidence)
        pair.receiver.receive_message(message)
        self.assertEqual(
            pair.receiver.page(after=0, limit=10)[0]["message"], partial[0]
        )
        self.assertEqual(restarted.prepare(**request), (evidence, message))
        self.assertEqual(pair.local_ledger.events(), [])

    def test_sender_prepares_real_local_events_for_independent_receiver(self) -> None:
        pair = Pair(self.root)
        sender = self.make_sender(pair)
        evidence, message = sender.prepare(
            client_id="owner-ui",
            send_id=_uuid("send"),
            thread_id=_uuid("thread"),
            text=TEXT,
        )
        events = sender.ledger.events()
        self.assertEqual(
            [event["subject"] for event in events],
            ["communication", "communication-resolution", "communication-evidence"],
        )
        self.assertEqual([event["sequence"] for event in events], [1, 2, 3])
        self.assertTrue(
            all(event["being_ref"] == pair.sender.state.being_ref for event in events)
        )
        self.assertTrue(all(TEXT.encode() not in raw for raw in (evidence, message)))
        pair.receiver.receive_evidence(evidence)
        pair.receiver.receive_message(message)
        page = pair.receiver.page(after=0, limit=10)
        self.assertEqual(page[0]["message"]["payload"]["body"]["text"], TEXT)
        self.assertIsNone(page[0]["message"]["payload"]["reply"])
        self.assertEqual(page[0]["message"], events[0])
        self.assertEqual(page[0]["evidence"], events[2])
        self.assertEqual(pair.local_ledger.events(), [])

    def test_sender_retry_restart_preserves_envelopes_and_checks_fresh_authority(
        self,
    ) -> None:
        import sqlite3

        pair = Pair(self.root)
        sender = self.make_sender(pair)
        request = dict(
            client_id="owner-ui",
            send_id=_uuid("retry-send"),
            thread_id=_uuid("thread"),
            text=TEXT,
        )
        first = sender.prepare(**request)
        events = sender.ledger.events()
        pair.now += 1
        self.assertEqual(sender.prepare(**request), first)
        restarted = self.make_sender(pair)
        self.assertEqual(restarted.prepare(**request), first)
        self.assertEqual(restarted.ledger.events(), events)
        with closing(sqlite3.connect(restarted.outbox.path)) as database:
            row = database.execute(
                "SELECT evidence, message FROM messaging_outbox"
            ).fetchone()
        self.assertEqual(tuple(row), first)
        before = restarted.outbox.path.read_bytes()
        pair.now = json.loads(first[0])["expires_at_ms"]
        with self.assertRaisesRegex(ValueError, "messaging_authorization_expired"):
            restarted.prepare(**request)
        self.assertEqual(restarted.outbox.path.read_bytes(), before)
        self.assertEqual(restarted.ledger.events(), events)
        revocation = next(
            event
            for event in pair.history
            if event["kind"] == "matrix/relationship-grant-revocation"
        )
        pair.sender_relationships.ingest(revocation)
        pair.now = NOW + 17
        with self.assertRaises(ValueError):
            restarted.prepare(**request)
        self.assertEqual(restarted.outbox.path.read_bytes(), before)
        self.assertEqual(restarted.ledger.events(), events)

    def test_sender_rejects_changed_request_policy_or_owner_without_mutation(
        self,
    ) -> None:
        from dataclasses import replace

        pair = Pair(self.root)
        sender = self.make_sender(pair)
        request = dict(
            client_id="owner-ui",
            send_id=_uuid("bound-send"),
            thread_id=_uuid("thread"),
            text=TEXT,
        )
        first = sender.prepare(**request)
        before = sender.outbox.path.read_bytes()
        events = sender.ledger.events()
        for changed in (
            {"text": "changed"},
            {"thread_id": _uuid("other-thread")},
            {"client_id": "other-client"},
        ):
            with (
                self.subTest(changed=changed),
                self.assertRaisesRegex(ValueError, "messaging_send_conflict"),
            ):
                sender.prepare(**{**request, **changed})
        sender.context.policy = replace(pair.policy, max_ttl_ms=20_000)
        with self.assertRaisesRegex(ValueError, "messaging_send_conflict"):
            sender.prepare(**request)
        sender.context.policy = pair.policy
        for field, value in (
            ("local_being_ref", pair.sender.state.being_ref),
            ("local_credential_id", pair.sender.credential["artifact_id"]),
        ):
            original = getattr(sender.context, field)
            setattr(sender.context, field, value)
            with self.subTest(field=field), self.assertRaises(ValueError):
                sender.prepare(**request)
            setattr(sender.context, field, original)
        self.assertEqual(sender.outbox.path.read_bytes(), before)
        self.assertEqual(sender.ledger.events(), events)
        self.assertEqual(sender.prepare(**request), first)
        sender.ledger = pair.local_ledger
        for send_id in (request["send_id"], _uuid("wrong-owner")):
            with self.assertRaisesRegex(ValueError, "messaging_sender_binding"):
                sender.prepare(**{**request, "send_id": send_id})
        self.assertEqual(pair.local_ledger.events(), [])
        sender = self.make_sender(pair)
        for field in ("embodiment_id", "incarnation_id", "body_ref", "principal_id"):
            original = sender.ledger.local_origin[field]
            sender.ledger.local_origin[field] = "unconfigured"
            with (
                self.subTest(field=field),
                self.assertRaisesRegex(ValueError, "messaging_sender_binding"),
            ):
                sender.prepare(**request)
            sender.ledger.local_origin[field] = original
        sender.signer = pair.recipient.signer
        with self.assertRaisesRegex(ValueError, "messaging_sender_binding"):
            sender.prepare(**request)
        sender.signer = pair.sender.signer
        invalid_requests: list[dict[str, Any]] = [
            {"text": 123},
            {"send_id": "not-a-uuid"},
            {"client_id": ""},
            {"thread_id": "not-a-uuid"},
        ]
        for invalid_request in invalid_requests:
            with self.subTest(changed=invalid_request), self.assertRaises(ValueError):
                sender.prepare(**{**request, **invalid_request})
        self.assertEqual(sender.outbox.path.read_bytes(), before)
        self.assertEqual(sender.ledger.events(), events)

    def test_independent_encrypted_evidence_materializes_actual_foreign_body(
        self,
    ) -> None:
        pair = Pair(self.root)
        evidence_wire, message_wire, message, evidence = pair.wire()
        assert pair.local_ledger.authority is pair.recipient.authority
        before = (self.root / "receiver/local.sqlite3").read_bytes()
        for raw in (evidence_wire, message_wire):
            assert TEXT.encode() not in raw
            assert canonical_bytes(evidence["payload"]["resolution_event"]) not in raw
        assert TEXT.encode() not in canonical_bytes(evidence)
        pair.receiver.receive_evidence(evidence_wire)
        result = pair.receiver.receive_message(message_wire)
        page = pair.receiver.page(after=0, limit=10)
        assert len(page) == 1
        assert page[0]["inbox_sequence"] == result["inbox_sequence"]
        assert page[0]["message"] == message
        assert page[0]["evidence"] == evidence
        assert page[0]["message"]["payload"]["body"]["text"] == TEXT
        assert (self.root / "receiver/local.sqlite3").read_bytes() == before

    def test_duplicate_reseal_and_restart_keep_one_immutable_item(self) -> None:
        from daimon_matrix.messaging import MessagingChannel
        from daimon_matrix.messaging_store import MessagingInboxStore

        pair = Pair(self.root)
        evidence, message, _, _ = pair.wire()
        pair.receiver.receive_evidence(evidence)
        first = pair.receiver.receive_message(message)
        pair.receiver.receive_evidence(evidence)
        assert pair.receiver.receive_message(message) == first
        resealed_evidence, resealed_message, _, _ = pair.wire()
        assert resealed_evidence != evidence and resealed_message != message
        pair.receiver.receive_evidence(resealed_evidence)
        assert pair.receiver.receive_message(resealed_message) == first
        expected = pair.receiver.page(after=0, limit=10)
        restarted = MessagingChannel(
            **pair.channel_options,
            relationships=pair.receiver_relationships,
            inbox=MessagingInboxStore(pair.store_path),
            clock=lambda: NOW + 25_000,
        )
        # Delivery envelopes expired; historical access does not unwrap again.
        assert restarted.page(after=0, limit=10) == expected
        assert len(expected) == 1

    def test_manual_pages_are_bounded_ordered_and_do_not_consume(self) -> None:
        from daimon_matrix.messaging_store import MessagingInboxError

        pair = Pair(self.root)
        for sequence in (200, 100):
            evidence, message, _, _ = pair.wire(sequence)
            pair.receiver.receive_evidence(evidence)
            pair.receiver.receive_message(message)
        first = pair.receiver.page(after=0, limit=1)
        assert pair.receiver.page(after=0, limit=1) == first
        second = pair.receiver.page(after=first[0]["inbox_sequence"], limit=1)
        assert first[0]["message"]["sequence"] == 200
        assert second[0]["message"]["sequence"] == 100
        assert pair.receiver.page(after=second[0]["inbox_sequence"], limit=1) == []
        for after, limit in ((-1, 1), (True, 1), (0, 0), (0, -1), (0, 101), (0, True)):
            with (
                self.subTest(after=after, limit=limit),
                self.assertRaises(MessagingInboxError),
            ):
                pair.receiver.page(after=after, limit=limit)

    def test_foreign_origin_position_conflict_does_not_mutate_inbox(self) -> None:
        from daimon_matrix.messaging_store import MessagingInboxError

        pair = Pair(self.root)
        evidence, message, _, _ = pair.wire(100)
        pair.receiver.receive_evidence(evidence)
        pair.receiver.receive_message(message)
        before = pair.receiver.page(after=0, limit=10)
        # The second resolution occupies the first evidence event's origin position.
        conflicting, _, _, _ = pair.wire(101)
        with self.assertRaisesRegex(MessagingInboxError, "conflict"):
            pair.receiver.receive_evidence(conflicting)
        assert pair.receiver.page(after=0, limit=10) == before

    def test_reusing_delivery_identity_for_new_ciphertext_fails_closed(self) -> None:
        import uuid
        from unittest.mock import patch

        from daimon_matrix.messaging_store import MessagingInboxError

        pair = Pair(self.root)
        evidence, message, _, _ = pair.wire()
        pair.receiver.receive_evidence(evidence)
        pair.receiver.receive_message(message)
        delivery_ids = [
            uuid.UUID(json.loads(raw)["delivery_id"]) for raw in (evidence, message)
        ]
        # Control UUID generation only; both envelopes are genuinely signed.
        with patch("daimon_matrix.sealed.uuid.uuid4", side_effect=delivery_ids):
            conflicting_evidence, conflicting_message, _, _ = pair.wire()
        assert evidence != conflicting_evidence and message != conflicting_message
        with self.assertRaisesRegex(MessagingInboxError, "delivery_conflict"):
            pair.receiver.receive_evidence(conflicting_evidence)
        with self.assertRaisesRegex(MessagingInboxError, "delivery_conflict"):
            pair.receiver.receive_message(conflicting_message)

    def test_retained_bytes_are_checked_on_read_and_after_restart(self) -> None:
        import sqlite3
        from unittest.mock import patch

        from daimon_matrix.messaging_store import (
            MessagingInboxError,
            MessagingInboxStore,
        )

        pair = Pair(self.root)
        evidence_wire, message_wire, message, evidence = pair.wire()
        pair.receiver.receive_evidence(evidence_wire)
        pair.receiver.receive_message(message_wire)
        changed = copy.deepcopy(message)
        changed["payload"]["body"]["text"] = "unsigned substituted body"
        with closing(sqlite3.connect(pair.store_path)) as database, database:
            database.execute("UPDATE inbox SET message=?", (canonical_bytes(changed),))
        pair.receiver.inbox = MessagingInboxStore(pair.store_path)
        with self.assertRaises(MessagingInboxError):
            pair.receiver.page(after=0, limit=10)
        with closing(sqlite3.connect(pair.store_path)) as database, database:
            database.execute("UPDATE inbox SET message=?", (canonical_bytes(message),))
            changed_evidence = copy.deepcopy(evidence)
            changed_evidence["signature"]["value"] = "A" * 86
            database.execute(
                "UPDATE evidence SET event=?", (canonical_bytes(changed_evidence),)
            )
        with patch.object(
            pair.receiver_custody, "unwrap", wraps=pair.receiver_custody.unwrap
        ) as unwrap:
            with self.assertRaises(MessagingInboxError):
                pair.receiver.receive_message(message_wire)
            unwrap.assert_not_called()

    def test_missing_evidence_is_retryable_without_decryption(self) -> None:
        from unittest.mock import patch

        from daimon_matrix.communication import CommunicationError

        pair = Pair(self.root)
        evidence, message, _, _ = pair.wire()
        before = pair.store_path.read_bytes()
        with patch.object(
            pair.receiver_custody, "unwrap", wraps=pair.receiver_custody.unwrap
        ) as unwrap:
            with self.assertRaises(CommunicationError) as caught:
                pair.receiver.receive_message(message)
            self.assertTrue(caught.exception.retryable)
            unwrap.assert_not_called()
        self.assertEqual(pair.store_path.read_bytes(), before)
        pair.receiver.receive_evidence(evidence)
        pair.receiver.receive_message(message)
        self.assertEqual(len(pair.receiver.page(after=0, limit=10)), 1)

    def test_signature_policy_and_expiry_fail_before_unwrap(self) -> None:
        from dataclasses import replace
        from unittest.mock import patch

        pair = Pair(self.root)
        evidence, _, _, _ = pair.wire()
        mutated = json.loads(evidence)
        mutated["signature"]["value"] = "A" * 86
        before = pair.store_path.read_bytes()
        policies = [
            pair.policy,
            replace(pair.policy, resource_ref="unapproved-resource"),
            replace(pair.policy, operation="write"),
            replace(pair.policy, classification="private"),
            replace(
                pair.policy, peer_credential_id=pair.recipient.credential["artifact_id"]
            ),
        ]
        for index, policy in enumerate(policies):
            with self.subTest(index=index):
                pair.receiver.policy = policy
                raw = canonical_bytes(mutated) if index == 0 else evidence
                with patch.object(
                    pair.receiver_custody, "unwrap", wraps=pair.receiver_custody.unwrap
                ) as unwrap:
                    with self.assertRaises(ValueError):
                        pair.receiver.receive_evidence(raw)
                    unwrap.assert_not_called()
                self.assertEqual(pair.store_path.read_bytes(), before)
        pair.receiver.policy = pair.policy
        pair.now = NOW + 20_001
        with patch.object(
            pair.receiver_custody, "unwrap", wraps=pair.receiver_custody.unwrap
        ) as unwrap:
            with self.assertRaises(ValueError):
                pair.receiver.receive_evidence(evidence)
            unwrap.assert_not_called()
        self.assertEqual(pair.store_path.read_bytes(), before)
        pair.now = NOW + 10
        pair.receiver.receive_evidence(evidence)

    def test_grant_requires_acceptance_and_current_nonrevocation(self) -> None:
        from unittest.mock import patch

        pair = Pair(self.root)
        evidence, message, _, _ = pair.wire()
        unaccepted = RelationshipStore(
            self.root / "unaccepted.sqlite3",
            authority_resolver=lambda being_ref: pair.public[being_ref],
        )
        for event in pair.history:
            if (
                event["occurred_at_ms"] <= NOW + 7
                and event["kind"] != "matrix/relationship-grant-acceptance"
            ):
                unaccepted.ingest(event)
        pair.receiver.relationships = unaccepted
        before = pair.store_path.read_bytes()
        with patch.object(
            pair.receiver_custody, "unwrap", wraps=pair.receiver_custody.unwrap
        ) as unwrap:
            with self.assertRaises(ValueError):
                pair.receiver.receive_evidence(evidence)
            unwrap.assert_not_called()
        self.assertEqual(pair.store_path.read_bytes(), before)
        pair.receiver.relationships = pair.receiver_relationships
        pair.receiver.receive_evidence(evidence)
        pair.receiver.receive_message(message)
        self.assertEqual(len(pair.receiver.page(after=0, limit=10)), 1)
        revocation = next(
            event
            for event in pair.history
            if event["kind"] == "matrix/relationship-grant-revocation"
        )
        pair.receiver_relationships.ingest(revocation)
        pair.now = NOW + 17
        before = pair.store_path.read_bytes()
        with patch.object(
            pair.receiver_custody, "unwrap", wraps=pair.receiver_custody.unwrap
        ) as unwrap:
            with self.assertRaises(ValueError):
                pair.receiver.receive_evidence(evidence)
            with self.assertRaises(ValueError):
                pair.receiver.receive_message(message)
            with self.assertRaises(ValueError):
                pair.receiver.page(after=0, limit=10)
            unwrap.assert_not_called()
        self.assertEqual(pair.store_path.read_bytes(), before)

    def test_manual_read_rejects_mismatched_signed_evidence(self) -> None:
        import sqlite3

        from daimon_matrix.messaging_store import MessagingInboxError

        pair = Pair(self.root)
        wire, message_wire, _, _ = pair.wire()
        pair.receiver.receive_evidence(wire)
        pair.receiver.receive_message(message_wire)
        _, _, _, unrelated = pair.wire(200)
        with closing(sqlite3.connect(pair.store_path)) as database, database:
            database.execute(
                "UPDATE inbox SET evidence=?", (canonical_bytes(unrelated),)
            )
        with self.assertRaises(MessagingInboxError):
            pair.receiver.page(after=0, limit=10)
