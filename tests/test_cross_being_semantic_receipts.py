"""V2 receipts: independent synthetic beings, never shared canonical history."""

import copy
import tempfile
import unittest
from pathlib import Path

from daimon_matrix.communication import CommunicationStore
from daimon_matrix.synthetic_relationships import _uuid
from daimon_matrix.weave import create_event
from tests import test_native_messaging as native


class ForeignReceiptTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.pair = native.Pair(self.root)
        self.sender = native.NativeMessagingTests.make_sender(self, self.pair)
        self.semantic_store = CommunicationStore(
            self.sender.ledger,
            foreign_authority_resolver=lambda ref: self.pair.public[ref],
            clock=lambda: self.pair.now,
        )
        self.semantic_store.upgrade_receipts_v2()
        self.sender.communication = self.semantic_store
        self.sender.prepare(
            client_id="owner",
            send_id=_uuid("semantic-send"),
            thread_id=_uuid("semantic-thread"),
            text="hello",
        )
        self.message, self.resolution, _ = self.sender.ledger.events()

    def receipt(self, *, payload=None, sequence=1):
        body = {
            "schema": "dm.communication.receipt/v2",
            "message_being_ref": self.message["being_ref"],
            "message_ref": {
                "event_id": self.message["event_id"],
                "event_hash": self.message["content_hash"],
            },
            "resolution_ref": {
                "event_id": self.resolution["event_id"],
                "event_hash": self.resolution["content_hash"],
            },
            "thread_id": self.message["payload"]["intent"]["thread_id"],
            "recipient_type": "relationship",
            "recipient_id": self.pair.policy.membership_ref,
            "outcome": "delivered",
            "observed_at_ms": self.pair.now,
        }
        body.update(payload or {})
        return create_event(
            authority=self.pair.recipient.authority,
            origin=self.pair.recipient.origin,
            sequence=sequence,
            previous_event_id=None,
            causal_parents=[],
            event_id=_uuid("receipt-" + str(sequence)),
            kind="experience.observed",
            subject="communication-receipt",
            payload=body,
            signer=self.pair.recipient.signer,
            sensitivity="shareable",
            occurred_at_ms=self.pair.now,
        )

    def store(self):
        return self.semantic_store

    def test_original_message_signs_expected_recipient_being(self):
        self.assertEqual(
            self.message["payload"]["body"]["recipient_being_ref"],
            self.pair.recipient.state.being_ref,
        )

    def test_reply_authors_stable_receipt_and_reduces_retained_carrier(self):
        from daimon_matrix.messaging import MessagingChannel, MessagingSender
        from daimon_matrix.messaging_store import (
            MessagingInboxStore,
            MessagingOutboxStore,
        )
        from tests.test_native_messaging import NativeSendRpcTests

        store = self.store()
        self.sender.communication = store
        reverse = NativeSendRpcTests.reverse_channel(self, self.pair)
        reverse.communication = store
        evidence, message = self.sender.prepare(
            client_id="owner",
            send_id=_uuid("semantic-send"),
            thread_id=_uuid("semantic-thread"),
            text="hello",
        )
        self.pair.receiver.receive_evidence(evidence)
        self.pair.receiver.receive_message(message)
        context = MessagingChannel(
            policy=reverse.policy,
            local_being_ref=reverse.local_being_ref,
            local_credential_id=reverse.local_credential_id,
            authority_resolver=reverse.authority_resolver,
            relationships=self.pair.receiver_relationships,
            custody=self.pair.receiver_custody,
            inbox=MessagingInboxStore(self.root / "receiver/context.sqlite3"),
            clock=lambda: self.pair.now,
        )
        back_store = CommunicationStore(
            self.pair.local_ledger,
            foreign_authority_resolver=lambda ref: self.pair.public[ref],
            clock=lambda: self.pair.now,
        )
        back_store.upgrade_receipts_v2()
        back = MessagingSender(
            context=context,
            ledger=self.pair.local_ledger,
            signer=self.pair.recipient.signer,
            custody=self.pair.receiver_custody,
            outbox=MessagingOutboxStore(self.root / "receiver/outbox.sqlite3"),
            clock=lambda: self.pair.now,
        )
        back.communication = back_store
        request = dict(
            client_id="owner-b",
            send_id=_uuid("reply-one"),
            thread_id=_uuid("semantic-thread"),
            text="reply",
            response_to=(self.pair.receiver, self.message["event_id"]),
        )
        from unittest.mock import patch

        with (
            patch.object(
                back, "_receipt", side_effect=OSError("private operation interrupted")
            ),
            self.assertRaises(OSError),
        ):
            back.prepare(**request)
        back.outbox._check_client(
            self.pair.recipient.state.being_ref,
            request["send_id"],
            request["client_id"],
        )
        with (
            patch.object(back, "_receipt") as private,
            self.assertRaisesRegex(ValueError, "messaging_send_conflict"),
        ):
            back.prepare(**{**request, "text": "changed retry"})
        private.assert_not_called()
        append = back.ledger.append_local_idempotent

        def lost_return(**kwargs):
            result = append(**kwargs)
            if kwargs["subject"] == "communication-receipt":
                raise OSError("receipt commit return lost")
            return result

        with (
            patch.object(
                back.ledger, "append_local_idempotent", side_effect=lost_return
            ),
            self.assertRaises(OSError),
        ):
            back.prepare(**request)
        first_receipt = back.ledger.events()[0]
        self.pair.now += 1
        envelopes = back.prepare(**request)
        self.assertEqual(first_receipt, back.ledger.events()[0])
        self.assertEqual(envelopes, back.prepare(**request))
        reverse.receive_evidence(envelopes[0])
        with (
            patch.object(
                reverse, "_reduce_receipt", side_effect=OSError("post-inbox crash")
            ),
            self.assertRaises(OSError),
        ):
            reverse.receive_message(envelopes[1])
        self.assertFalse(store.result(self.message["event_id"])["terminal"])
        self.assertEqual(1, len(reverse.page(after=0, limit=10)))
        reverse.reconcile_receipts()
        reverse.receive_message(envelopes[1])
        self.assertTrue(store.result(self.message["event_id"])["terminal"])
        received = reverse.page(after=0, limit=10)[0]["message"]
        receipt = received["payload"]["body"]["semantic_receipt"]
        self.assertIsNone(received["payload"]["reply"])
        self.assertNotIn(self.message["event_id"], receipt["causal_parents"])
        self.assertIsNone(self.sender.ledger.event(receipt["event_id"]))
        self.assertIsNone(self.pair.local_ledger.event(self.message["event_id"]))
        back.prepare(**{**request, "send_id": _uuid("reply-two")})
        self.assertEqual(
            1,
            len(
                [
                    e
                    for e in back.ledger.events()
                    if e["subject"] == "communication-receipt"
                ]
            ),
        )

    def test_v1_then_v2_terminal_conflict(self):
        self._cross_version_conflict(local_first=True)

    def test_v2_then_v1_terminal_conflict(self):
        self._cross_version_conflict(local_first=False)

    def _cross_version_conflict(self, *, local_first):
        store = self.store()
        local = self.sender.ledger.append_local(
            kind="experience.observed",
            subject="communication-receipt",
            signer=self.pair.sender.signer,
            sensitivity="shareable",
            occurred_at_ms=self.pair.now,
            causal_parents=(self.message["event_id"],),
            payload={
                "schema": "dm.communication.receipt/v1",
                "message_id": self.message["event_id"],
                "thread_id": self.message["payload"]["intent"]["thread_id"],
                "recipient_type": "relationship",
                "recipient_id": self.pair.policy.membership_ref,
                "outcome": "failed:transport",
                "observed_at_ms": self.pair.now,
                "evidence_ref": None,
            },
        )
        operations = [
            lambda: store.record_receipt(local["event_id"]),
            lambda: store.record_foreign_receipt(
                self.receipt(), recipient_being_ref=self.pair.recipient.state.being_ref
            ),
        ]
        if not local_first:
            operations.reverse()
        operations[0]()
        with self.assertRaisesRegex(ValueError, "terminal_receipt_conflict"):
            operations[1]()
        self.assertEqual(
            store.result(self.message["event_id"])["legs"][0]["state"], "quarantined"
        )

    def test_signed_payload_mutations_never_terminate(self):
        store = self.store()
        mutations = [
            {"schema": "dm.communication.receipt/v1"},
            {"schema": "dm.communication.receipt/v999"},
            {"outcome": "failed:transport"},
            {"outcome": "refused:policy"},
            {"observed_at_ms": True},
            {"observed_at_ms": self.pair.now - 1},
            {"recipient_id": "wrong-membership"},
            {"recipient_type": "embodiment"},
            {"thread_id": _uuid("wrong-thread")},
            {"message_being_ref": self.pair.recipient.state.being_ref},
            {
                "message_ref": {
                    "event_id": self.message["event_id"],
                    "event_hash": "0" * 64,
                }
            },
            {
                "resolution_ref": {
                    "event_id": self.resolution["event_id"],
                    "event_hash": "0" * 64,
                }
            },
            {"unknown": True},
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                store.record_foreign_receipt(
                    self.receipt(payload=mutation),
                    recipient_being_ref=self.pair.recipient.state.being_ref,
                )
            self.assertFalse(store.result(self.message["event_id"])["terminal"])
        self.assertTrue(
            store.record_foreign_receipt(
                self.receipt(), recipient_being_ref=self.pair.recipient.state.being_ref
            )["terminal"]
        )

    def test_independent_wrong_being_with_same_embodiment_is_rejected(self):
        from daimon_matrix.identity import (
            create_embodiment_credential,
            create_incarnation_authorization,
            x25519_public,
        )
        from daimon_matrix.synthetic_relationships import (
            MAX_TIME,
            _identity,
            _seed,
            _transport,
        )
        from daimon_matrix.weave import BeingManifest, RootAuthority, verify_event

        other = _identity("delegate")
        origin = {
            **other.origin,
            "embodiment_id": self.pair.recipient.origin["embodiment_id"],
        }
        credential = create_embodiment_credential(
            other.state,
            tuple(_seed(f"delegate:root:{i}") for i in range(3)),
            other.signer.seed,
            x25519_public(_seed("delegate:encryption")),
            embodiment_id=origin["embodiment_id"],
            body_ref=origin["body_ref"],
            purposes=["dm.we", "messages"],
            valid_from_ms=0,
            valid_until_ms=MAX_TIME,
            transport_principals=[_transport("delegate", origin["principal_id"])],
        )
        incarnation = create_incarnation_authorization(
            credential,
            other.signer.seed,
            incarnation_id=origin["incarnation_id"],
            incarnation_sequence=0,
            started_at_ms=0,
        )
        manifest = copy.deepcopy(other.authority.manifest.value)
        manifest["embodiments"][0].update(
            embodiment_id=origin["embodiment_id"],
            embodiment_credential_id=credential["artifact_id"],
            incarnation_authorization_id=incarnation["artifact_id"],
        )
        authority = RootAuthority(
            BeingManifest.from_value(manifest),
            other.state,
            {credential["artifact_id"]: credential},
            {incarnation["artifact_id"]: incarnation},
        )
        self.pair.public[other.state.being_ref] = authority
        event = create_event(
            authority=authority,
            origin=origin,
            sequence=1,
            previous_event_id=None,
            causal_parents=[],
            event_id=_uuid("wrong-being-receipt"),
            kind="experience.observed",
            subject="communication-receipt",
            payload=self.receipt()["payload"],
            signer=other.signer,
            sensitivity="shareable",
            occurred_at_ms=self.pair.now,
        )
        verify_event(
            event, authority
        )  # genuine independent signature, same selected embodiment ID
        with self.assertRaisesRegex(ValueError, "foreign_receipt_binding_mismatch"):
            self.store().record_foreign_receipt(
                event, recipient_being_ref=other.state.being_ref
            )
        self.assertFalse(self.store().result(self.message["event_id"])["terminal"])
        self.assertTrue(
            self.store().record_foreign_receipt(
                self.receipt(), recipient_being_ref=self.pair.recipient.state.being_ref
            )["terminal"]
        )

    def test_foreign_reducer_recovers_anchor_before_database_commit(self):
        from unittest.mock import patch

        store = self.store()
        original = store._write_anchor

        def crash(generation, counter):
            original(generation, counter)
            raise OSError("crash after anchor persistence")

        with (
            patch.object(store, "_write_anchor", side_effect=crash),
            self.assertRaises(OSError),
        ):
            store.record_foreign_receipt(
                self.receipt(), recipient_being_ref=self.pair.recipient.state.being_ref
            )
        restarted = CommunicationStore(
            self.sender.ledger,
            receipts_v2=True,
            foreign_authority_resolver=lambda ref: self.pair.public[ref],
            clock=lambda: self.pair.now,
        )
        restarted.initialize()
        self.assertFalse(restarted.result(self.message["event_id"])["terminal"])
        self.assertTrue(
            restarted.record_foreign_receipt(
                self.receipt(), recipient_being_ref=self.pair.recipient.state.being_ref
            )["terminal"]
        )

    def test_foreign_reducer_recovers_committed_pending_journal(self):
        from unittest.mock import patch

        store = self.store()
        receipt = self.receipt()
        with (
            patch.object(store, "_pending_remove", side_effect=OSError("lost return")),
            self.assertRaises(OSError),
        ):
            store.record_foreign_receipt(
                receipt, recipient_being_ref=self.pair.recipient.state.being_ref
            )
        restarted = CommunicationStore(
            self.sender.ledger,
            receipts_v2=True,
            foreign_authority_resolver=lambda ref: self.pair.public[ref],
            clock=lambda: self.pair.now,
        )
        self.assertTrue(restarted.result(self.message["event_id"])["terminal"])
        self.assertFalse(restarted._pending_path().exists())
        self.assertTrue(
            restarted.record_foreign_receipt(
                receipt, recipient_being_ref=self.pair.recipient.state.being_ref
            )["terminal"]
        )

    def test_journal_does_not_repair_unbound_database_tampering(self):
        from unittest.mock import patch

        store = self.store()
        with (
            patch.object(store, "_pending_remove", side_effect=OSError("lost return")),
            self.assertRaises(OSError),
        ):
            store.record_foreign_receipt(
                self.receipt(), recipient_being_ref=self.pair.recipient.state.being_ref
            )
        with store._database() as db:
            db.execute(
                "UPDATE communication_foreign_receipts SET receipt_hash=?", ("0" * 64,)
            )
        with self.assertRaisesRegex(ValueError, "communication_state_rollback"):
            store.initialize()

    def test_missing_foreign_table_fails_before_any_projection_write(self):
        store = self.store()
        with store._database() as db:
            db.execute("DROP TABLE communication_foreign_receipts")
        with self.assertRaisesRegex(ValueError, "foreign_receipt_store_missing"):
            store.initialize()

    def test_terminal_projection_revalidates_resolution_evidence_cursor(self):
        store = self.store()
        store.record_foreign_receipt(
            self.receipt(), recipient_being_ref=self.pair.recipient.state.being_ref
        )
        with store._database() as db:
            db.execute("UPDATE communication_legs SET evidence_cursor='forged'")
        with self.assertRaisesRegex(ValueError, "foreign_receipt_binding_mismatch"):
            store.result(self.message["event_id"], require_terminal=True)

    def test_corrupt_foreign_proof_cannot_advance_consumer_or_rebuild(self):
        store = self.store()
        store.record_foreign_receipt(
            self.receipt(), recipient_being_ref=self.pair.recipient.state.being_ref
        )
        with store._database() as db:
            db.execute(
                "UPDATE communication_foreign_receipts SET receipt_hash=?", ("0" * 64,)
            )
        with self.assertRaisesRegex(ValueError, "foreign_receipt_store_corrupt"):
            store.advance_consumer(
                recipient_id=self.pair.policy.membership_ref,
                consumer_id="probe",
                sequence=1,
            )
        with store._database() as db:
            self.assertEqual(
                db.execute("SELECT COUNT(*) FROM communication_consumers").fetchone()[
                    0
                ],
                0,
            )
        with self.assertRaisesRegex(ValueError, "foreign_receipt_store_corrupt"):
            store.rebuild_plan(self.message["event_id"])

    def test_retained_proof_is_required_and_reverified(self):
        store = self.store()
        receipt = self.receipt()
        store.record_foreign_receipt(
            receipt, recipient_being_ref=self.pair.recipient.state.being_ref
        )
        with store._database() as db:
            db.execute(
                "UPDATE communication_foreign_receipts SET receipt_hash=?", ("0" * 64,)
            )
        with self.assertRaises(ValueError):
            store.result(self.message["event_id"], require_terminal=True)

    def test_conflicting_terminal_evidence_is_retained_and_quarantined(self):
        store = self.store()
        first = self.receipt()
        store.record_foreign_receipt(
            first, recipient_being_ref=self.pair.recipient.state.being_ref
        )
        # A different valid signed event at the SAME sparse origin position.
        second = copy.deepcopy(first)
        from daimon_matrix.weave import create_event

        second = create_event(
            authority=self.pair.recipient.authority,
            origin=self.pair.recipient.origin,
            sequence=1,
            previous_event_id=None,
            causal_parents=[],
            event_id=_uuid("conflicting-receipt"),
            kind="experience.observed",
            subject="communication-receipt",
            payload=first["payload"],
            signer=self.pair.recipient.signer,
            sensitivity="shareable",
            occurred_at_ms=self.pair.now,
        )
        with self.assertRaisesRegex(ValueError, "terminal_receipt_conflict"):
            store.record_foreign_receipt(
                second, recipient_being_ref=self.pair.recipient.state.being_ref
            )
        self.assertFalse(store.result(self.message["event_id"])["terminal"])
        with store._database() as db:
            self.assertIn(
                second["content_hash"].encode(),
                db.execute(
                    "SELECT evidence_json FROM communication_conflicts"
                ).fetchone()[0],
            )

    def test_signed_foreign_receipt_terminates_without_import(self):
        store = self.store()
        receipt = self.receipt()
        result = store.record_foreign_receipt(
            receipt, recipient_being_ref=self.pair.recipient.state.being_ref
        )
        self.assertTrue(result["terminal"])
        self.assertEqual(
            result, store.result(self.message["event_id"], require_terminal=True)
        )
        self.assertIsNone(self.sender.ledger.event(receipt["event_id"]))
        self.assertEqual(len(self.sender.ledger.events()), 3)
        self.assertEqual(
            result,
            store.record_foreign_receipt(
                receipt, recipient_being_ref=self.pair.recipient.state.being_ref
            ),
        )
