"""V2 receipts: independent synthetic beings, never shared canonical history."""

import copy
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

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


# Original independent #132 regression probes, including positive controls.
class ReviewProbes(unittest.TestCase):
    def setUp(self):
        self.f = ForeignReceiptTests()
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.root = self.f.root
        self.s = self.f.store()
        self.mid = self.f.message["event_id"]
        self.rec = self.f.pair.recipient.state.being_ref
        self.rid = self.f.pair.policy.membership_ref

    def deliver(self):
        return self.s.record_foreign_receipt(
            self.f.receipt(), recipient_being_ref=self.rec
        )

    def test_v1_receipt_looking_inbox_rows_remain_inert_after_v2_admission(self):
        pair = native.Pair(self.root / "legacy-boundary")
        receipt_looking = pair.event(
            "communication-receipt",
            {
                "schema": "dm.communication.receipt/v2",
                "message_being_ref": pair.sender.state.being_ref,
                "message_ref": {"event_id": _uuid("legacy"), "event_hash": "0" * 64},
                "resolution_ref": {
                    "event_id": _uuid("legacy-resolution"),
                    "event_hash": "0" * 64,
                },
                "thread_id": _uuid("legacy-thread"),
                "recipient_type": "relationship",
                "recipient_id": pair.policy.membership_ref,
                "outcome": "delivered",
                "observed_at_ms": pair.now,
            },
            90,
        )
        expected = []
        for sequence, semantic_receipt in (
            (100, {"legacy": "extension-data"}),
            (200, receipt_looking),
        ):
            evidence, message, event, _ = pair.wire(
                sequence,
                text=f"legacy-{sequence}",
                body_extra={"semantic_receipt": semantic_receipt},
            )
            pair.receiver.receive_evidence(evidence)
            pair.receiver.receive_message(message)
            expected.append(event)

        store = CommunicationStore(
            pair.local_ledger,
            foreign_authority_resolver=lambda ref: pair.public[ref],
            clock=lambda: pair.now,
        )
        store.upgrade_receipts_v2()
        pair.receiver.communication = store

        pair.receiver.reconcile_receipts()
        rows = pair.receiver.page(after=0, limit=10)
        self.assertEqual([row["message"] for row in rows], expected)
        retained = pair.store._page(
            after=0, limit=10, policy_hash=pair.receiver._policy_hash(pair.now)
        )
        self.assertEqual([row["admission_version"] for row in retained], [1, 1])
        self.assertEqual(pair.receiver.message(expected[0]["event_id"]), expected[0])

    def test_positive_signature_and_restart(self):
        bad = copy.deepcopy(self.f.receipt())
        bad["payload"]["thread_id"] = _uuid("tampered-no-resign")
        with self.assertRaises(ValueError):
            self.s.record_foreign_receipt(bad, recipient_being_ref=self.rec)
        self.assertFalse(self.s.result(self.mid)["terminal"])
        self.assertTrue(self.deliver()["terminal"])
        restarted = CommunicationStore(
            self.f.sender.ledger,
            receipts_v2=True,
            foreign_authority_resolver=lambda ref: self.f.pair.public[ref],
        )
        self.assertTrue(restarted.result(self.mid)["terminal"])
        self.assertIsNone(self.f.sender.ledger.event(self.f.receipt()["event_id"]))

    def test_signed_carrier_context_mutations_rejected(self):
        from daimon_matrix.weave import create_event, verify_event
        from tests.test_native_messaging import NativeSendRpcTests

        channel = NativeSendRpcTests.reverse_channel(self, self.f.pair)
        channel.communication = self.s
        receipt = self.f.receipt()
        payload = {
            "schema": "dm.communication.message/v1",
            "intent": copy.deepcopy(self.f.message["payload"]["intent"]),
            "reply": None,
            "body": {
                "text": "review reply",
                "resource_ref": channel.policy.resource_ref,
                "recipient_being_ref": self.f.message["being_ref"],
                "semantic_receipt": receipt,
                "response_context": {
                    "schema": "dm.messaging.application-response/v1",
                    "message_id": self.mid,
                    "message_hash": self.f.message["content_hash"],
                    "sender_being_ref": self.f.message["being_ref"],
                    "sender_embodiment_id": self.f.message["origin"]["embodiment_id"],
                    "thread_id": receipt["payload"]["thread_id"],
                },
            },
        }

        def sign(body):
            return create_event(
                authority=self.f.pair.recipient.authority,
                origin=self.f.pair.recipient.origin,
                signer=self.f.pair.recipient.signer,
                event_id=_uuid("review-carrier"),
                sequence=2,
                previous_event_id=receipt["event_id"],
                causal_parents=[],
                kind="experience.observed",
                subject="communication",
                payload=body,
                sensitivity="shareable",
                occurred_at_ms=self.f.pair.now,
            )

        good = sign(payload)
        self.assertEqual(channel._semantic_receipt(good), receipt)
        for field, value in [
            ("message_id", _uuid("different-original")),
            ("message_hash", "0" * 64),
            ("sender_being_ref", self.rec),
            ("sender_embodiment_id", "other-embodiment"),
            ("thread_id", _uuid("different-thread")),
        ]:
            with self.subTest(field=field):
                changed = copy.deepcopy(payload)
                changed["body"]["response_context"][field] = value
                carrier = sign(changed)
                verify_event(carrier, self.f.pair.recipient.authority)
                with self.assertRaises(ValueError):
                    channel._reduce_receipt(carrier)
                self.assertFalse(self.s.result(self.mid)["terminal"])
        channel._reduce_receipt(good)
        channel._reduce_receipt(good)
        self.assertTrue(self.s.result(self.mid)["terminal"])
        self.assertIsNone(self.f.sender.ledger.event(receipt["event_id"]))

    def test_cached_page_and_leg_reject_corrupt_proof(self):
        self.deliver()
        args = dict(
            recipient_id=self.rid,
            consumer_id="review",
            request_id=_uuid("review-page"),
            cursor=None,
        )
        page = self.s.page(**args)
        leg_id = page["items"][0]["leg_id"]
        with self.s._database() as db:
            db.execute(
                "UPDATE communication_foreign_receipts SET receipt_hash=?", ("0" * 64,)
            )
        with self.assertRaises(ValueError):
            self.s.result(self.mid)
        with self.subTest(path="cached-page"), self.assertRaises(ValueError):
            self.s.page(**args)
        with self.subTest(path="leg"), self.assertRaises(ValueError):
            self.s.leg(leg_id)

    def test_pending_projection_binding_is_reverified(self):
        with self.s._database() as db:
            db.execute(
                "UPDATE communication_legs SET recipient_id='wrong-recipient', "
                "evidence_cursor='forged'"
            )
        with self.assertRaises(ValueError):
            self.s.result(self.mid)

    def test_missing_nonterminal_queue_row_fails_closed_on_all_v2_paths(self):
        sequence = self.s.result(self.mid)["legs"][0]["sequence"]
        with self.s._database() as db:
            db.execute("DELETE FROM communication_queue")

        def restarted_page():
            restarted = CommunicationStore(
                self.f.sender.ledger,
                receipts_v2=True,
                foreign_authority_resolver=lambda ref: self.f.pair.public[ref],
                clock=lambda: self.f.pair.now,
            )
            return restarted.page(
                recipient_id=self.rid,
                consumer_id="missing-restart",
                request_id=_uuid("missing-restart-page"),
                cursor=None,
            )

        calls = {
            "page": lambda: self.s.page(
                recipient_id=self.rid,
                consumer_id="missing-page",
                request_id=_uuid("missing-queue-page"),
                cursor=None,
            ),
            "claim": lambda: self.s.claim(
                recipient_id=self.rid,
                consumer_id="missing-claim",
                claim_id=_uuid("missing-queue-claim"),
                limit=1,
                lease_until_ms=self.f.pair.now + 10_000,
            ),
            "cursor": lambda: self.s.advance_consumer(
                recipient_id=self.rid,
                consumer_id="missing-cursor",
                sequence=sequence,
            ),
            "compaction": lambda: self.s.compact(
                recipient_id=self.rid, through_sequence=sequence
            ),
            "restart": restarted_page,
        }
        for path, call in calls.items():
            with (
                self.subTest(path=path),
                self.assertRaisesRegex(ValueError, "communication_queue_incomplete"),
            ):
                call()

    def test_equal_consumer_replay_revalidates_owned_terminal_prefix(self):
        sequence = self.s.result(self.mid)["legs"][0]["sequence"]
        with self.assertRaisesRegex(ValueError, "consumer_prefix_not_terminal"):
            self.s.advance_consumer(
                recipient_id=self.rid, consumer_id="corrupt", sequence=sequence
            )
        with self.s._database() as db:
            generation = db.execute(
                "SELECT value FROM communication_meta WHERE key='generation'"
            ).fetchone()[0]
            db.execute(
                "INSERT INTO communication_consumers VALUES (?, ?, ?, ?)",
                (self.rid, "corrupt", generation, sequence),
            )
        with self.assertRaisesRegex(ValueError, "consumer_prefix_not_terminal"):
            self.s.advance_consumer(
                recipient_id=self.rid, consumer_id="corrupt", sequence=sequence
            )
        with self.s._database() as db:
            self.assertEqual(
                tuple(
                    db.execute(
                        "SELECT recipient_id, consumer_id, generation, sequence "
                        "FROM communication_consumers"
                    ).fetchone()
                ),
                (self.rid, "corrupt", generation, sequence),
            )

    def test_reinserted_compacted_queue_row_is_not_legitimate_absence_evidence(self):
        leg = self.deliver()["legs"][0]
        sequence = leg["sequence"]
        self.s.advance_consumer(
            recipient_id=self.rid, consumer_id="extra", sequence=sequence
        )
        self.s.compact(recipient_id=self.rid, through_sequence=sequence)
        with self.s._database() as db:
            db.execute(
                "INSERT INTO communication_queue VALUES (?, ?, ?)",
                (sequence, leg["leg_id"], self.rid),
            )

        def restarted_page():
            restarted = CommunicationStore(
                self.f.sender.ledger,
                receipts_v2=True,
                foreign_authority_resolver=lambda ref: self.f.pair.public[ref],
                clock=lambda: self.f.pair.now,
            )
            return restarted.page(
                recipient_id=self.rid,
                consumer_id="extra-restart",
                request_id=_uuid("extra-restart-page"),
                cursor=None,
            )

        calls = {
            "page": lambda: self.s.page(
                recipient_id=self.rid,
                consumer_id="extra",
                request_id=_uuid("extra-queue-page"),
                cursor=None,
            ),
            "claim": lambda: self.s.claim(
                recipient_id=self.rid,
                consumer_id="extra",
                claim_id=_uuid("extra-queue-claim"),
                limit=1,
                lease_until_ms=self.f.pair.now + 10_000,
            ),
            "cursor": lambda: self.s.advance_consumer(
                recipient_id=self.rid, consumer_id="extra", sequence=sequence
            ),
            "compaction": lambda: self.s.compact(
                recipient_id=self.rid, through_sequence=sequence
            ),
            "restart": restarted_page,
        }
        for path, call in calls.items():
            with (
                self.subTest(path=path),
                self.assertRaisesRegex(
                    ValueError, "communication_compaction_evidence_corrupt"
                ),
            ):
                call()

    def test_swapped_queue_sequences_fail_every_v2_read_path(self):
        self.f.sender.prepare(
            client_id="owner",
            send_id=_uuid("swapped-queue-send"),
            thread_id=_uuid("swapped-queue-thread"),
            text="second",
        )
        with self.s._database() as db:
            rows = db.execute(
                "SELECT sequence, leg_id FROM communication_queue ORDER BY sequence"
            ).fetchall()
            self.assertEqual(len(rows), 2)
            first, second = rows
            db.execute(
                "UPDATE communication_queue SET sequence=-1 WHERE leg_id=?",
                (first["leg_id"],),
            )
            db.execute(
                "UPDATE communication_queue SET sequence=-2 WHERE leg_id=?",
                (second["leg_id"],),
            )
            db.execute(
                "UPDATE communication_queue SET sequence=? WHERE leg_id=?",
                (second["sequence"], first["leg_id"]),
            )
            db.execute(
                "UPDATE communication_queue SET sequence=? WHERE leg_id=?",
                (first["sequence"], second["leg_id"]),
            )

        def restarted_page():
            restarted = CommunicationStore(
                self.f.sender.ledger,
                receipts_v2=True,
                foreign_authority_resolver=lambda ref: self.f.pair.public[ref],
                clock=lambda: self.f.pair.now,
            )
            return restarted.page(
                recipient_id=self.rid,
                consumer_id="swapped-restart",
                request_id=_uuid("swapped-restart"),
                cursor=None,
            )

        for path, call in {
            "page": lambda: self.s.page(
                recipient_id=self.rid,
                consumer_id="swapped-page",
                request_id=_uuid("swapped-page"),
                cursor=None,
            ),
            "claim": lambda: self.s.claim(
                recipient_id=self.rid,
                consumer_id="swapped-claim",
                claim_id=_uuid("swapped-claim"),
                limit=1,
                lease_until_ms=self.f.pair.now + 10_000,
            ),
            "cursor": lambda: self.s.advance_consumer(
                recipient_id=self.rid,
                consumer_id="swapped-cursor",
                sequence=first["sequence"],
            ),
            "compaction": lambda: self.s.compact(
                recipient_id=self.rid, through_sequence=second["sequence"]
            ),
            "restart": restarted_page,
        }.items():
            with (
                self.subTest(path=path),
                self.assertRaisesRegex(
                    ValueError, "communication_queue_binding_mismatch"
                ),
            ):
                call()

    def test_missing_pending_leg_cannot_make_whole_vector_terminal(self):
        from daimon_matrix.weave import create_event

        ledger = self.f.sender.ledger
        message = ledger.append_local(
            kind="experience.observed",
            subject="communication",
            signer=self.f.pair.sender.signer,
            sensitivity="shareable",
            occurred_at_ms=self.f.pair.now,
            payload=copy.deepcopy(self.f.message["payload"]),
        )
        targets = copy.deepcopy(self.f.resolution["payload"]["targets"])
        targets.append({**targets[0], "recipient_id": "review-other-membership"})
        targets.sort(key=lambda t: (t["recipient_type"], t["recipient_id"]))
        resolution = ledger.append_local(
            kind="experience.observed",
            subject="communication-resolution",
            signer=self.f.pair.sender.signer,
            sensitivity="shareable",
            occurred_at_ms=self.f.pair.now,
            causal_parents=(message["event_id"],),
            payload={
                **self.f.resolution["payload"],
                "message_id": message["event_id"],
                "targets": targets,
            },
        )
        self.s.accept(
            message_event_id=message["event_id"],
            resolution_event_id=resolution["event_id"],
        )
        payload = copy.deepcopy(self.f.receipt()["payload"])
        payload["message_ref"] = {
            "event_id": message["event_id"],
            "event_hash": message["content_hash"],
        }
        payload["resolution_ref"] = {
            "event_id": resolution["event_id"],
            "event_hash": resolution["content_hash"],
        }
        receipt = create_event(
            authority=self.f.pair.recipient.authority,
            origin=self.f.pair.recipient.origin,
            signer=self.f.pair.recipient.signer,
            event_id=_uuid("review-multi-receipt"),
            sequence=1,
            previous_event_id=None,
            causal_parents=[],
            kind="experience.observed",
            subject="communication-receipt",
            payload=payload,
            sensitivity="shareable",
            occurred_at_ms=self.f.pair.now,
        )
        before = self.s.record_foreign_receipt(receipt, recipient_being_ref=self.rec)
        self.assertFalse(before["terminal"])
        self.assertEqual(len(before["legs"]), 2)
        with self.s._database() as db:
            leg = db.execute(
                "SELECT leg_id FROM communication_legs WHERE message_id=? "
                "AND state='accepted'",
                (message["event_id"],),
            ).fetchone()[0]
            db.execute("DELETE FROM communication_queue WHERE leg_id=?", (leg,))
            db.execute("DELETE FROM communication_legs WHERE leg_id=?", (leg,))
        with self.assertRaises(ValueError):
            self.s.result(message["event_id"], require_terminal=True)

    def test_foreign_proof_compaction_positive_and_negative(self):
        self.deliver()
        self.s.advance_consumer(recipient_id=self.rid, consumer_id="review", sequence=1)
        with self.s._database() as db:
            db.execute(
                "UPDATE communication_foreign_receipts SET receipt_hash=?", ("0" * 64,)
            )
        with self.assertRaises(ValueError):
            self.s.compact(recipient_id=self.rid, through_sequence=1)
        with self.s._database() as db:
            self.assertEqual(
                1, db.execute("SELECT COUNT(*) FROM communication_queue").fetchone()[0]
            )

    def test_local_receipt_transplant_does_not_close_unsent_leg(self):
        # Produce a genuine local failure receipt for an unrelated signed message.
        self.f.sender.prepare(
            client_id="owner",
            send_id=_uuid("other-send"),
            thread_id=_uuid("other-thread"),
            text="other",
        )
        other = next(
            e
            for e in self.f.sender.ledger.events()
            if e["subject"] == "communication" and e["event_id"] != self.mid
        )
        receipt = self.f.sender.ledger.append_local(
            kind="experience.observed",
            subject="communication-receipt",
            signer=self.f.pair.sender.signer,
            sensitivity="shareable",
            occurred_at_ms=self.f.pair.now,
            causal_parents=(other["event_id"],),
            payload={
                "schema": "dm.communication.receipt/v1",
                "message_id": other["event_id"],
                "thread_id": other["payload"]["intent"]["thread_id"],
                "recipient_type": "relationship",
                "recipient_id": self.rid,
                "outcome": "failed:transport",
                "observed_at_ms": self.f.pair.now,
                "evidence_ref": None,
            },
        )
        self.s.record_receipt(receipt["event_id"])
        with self.s._database() as db:
            target = db.execute(
                "SELECT leg_id FROM communication_legs WHERE message_id=?", (self.mid,)
            ).fetchone()[0]
            columns = [
                r[1] for r in db.execute("PRAGMA table_info(communication_receipts)")
            ]
            old = dict(db.execute("SELECT * FROM communication_receipts").fetchone())
            old["leg_id"] = target
            # Move the projection receipt, preserving its genuine signed event.
            db.execute("DELETE FROM communication_receipts")
            db.execute(
                "INSERT INTO communication_receipts VALUES ("
                + ",".join("?" for _ in columns)
                + ")",
                [old[k] for k in columns],
            )
            db.execute(
                "UPDATE communication_legs SET state='failed:transport', "
                "terminal_receipt_event_id=?,terminal_receipt_hash=? WHERE leg_id=?",
                (receipt["event_id"], receipt["content_hash"], target),
            )
        with self.assertRaises(ValueError):
            self.s.result(self.mid, require_terminal=True)

    def test_all_pending_immutable_fields_and_vector_cardinality(self):
        import hashlib

        from daimon_matrix.canonical import canonical_bytes

        leg = self.s.result(self.mid)["legs"][0]
        with self.s._database() as db:
            original = dict(db.execute("SELECT * FROM communication_legs").fetchone())
        fields = (
            "thread_id",
            "recipient_type",
            "recipient_id",
            "receipt_origin_embodiment_id",
            "resolution_event_id",
            "resolution_hash",
            "evidence_cursor",
            "leg_id",
        )
        for field in fields:
            with self.subTest(field=field):
                with self.s._database() as db:
                    db.execute("DELETE FROM communication_queue")
                    value = "embodiment" if field == "recipient_type" else "forged"
                    db.execute(f"UPDATE communication_legs SET {field}=?", (value,))
                with self.assertRaises(ValueError):
                    self.s.result(self.mid)
                with self.s._database() as db:
                    db.execute(
                        f"UPDATE communication_legs SET {field}=?", (original[field],)
                    )
        # Even a self-consistent extra row cannot add a signed recipient.
        extra = dict(original)
        extra["leg_id"] = "extra-leg"
        extra["recipient_id"] = "extra-recipient"
        extra["sequence"] += 1
        immutable = {
            key: extra[key]
            for key in (
                "message_id",
                "thread_id",
                "recipient_type",
                "recipient_id",
                "receipt_origin_embodiment_id",
                "resolution_event_id",
                "resolution_hash",
                "evidence_cursor",
            )
        }
        extra["immutable_hash"] = hashlib.sha256(canonical_bytes(immutable)).hexdigest()
        with self.s._database() as db:
            db.execute(
                "INSERT INTO communication_legs VALUES ("
                + ",".join("?" for _ in extra)
                + ")",
                list(extra.values()),
            )
        with self.assertRaises(ValueError):
            self.s.result(self.mid)
        with self.s._database() as db:
            db.execute("DELETE FROM communication_legs")
        for call in [
            lambda: self.s.result(self.mid),
            lambda: self.s.advance_consumer(
                recipient_id=self.rid, consumer_id="empty", sequence=0
            ),
        ]:
            with self.assertRaises(ValueError):
                call()
        with self.s._database() as db:
            db.execute(
                "INSERT INTO communication_legs VALUES ("
                + ",".join("?" for _ in original)
                + ")",
                list(original.values()),
            )
        self.assertEqual(leg, self.s.result(self.mid)["legs"][0])

    def test_local_receipt_projection_bytes_columns_and_origin_are_reverified(self):
        from daimon_matrix.canonical import canonical_bytes

        receipt = self.f.sender.ledger.append_local(
            kind="experience.observed",
            subject="communication-receipt",
            signer=self.f.pair.sender.signer,
            sensitivity="shareable",
            occurred_at_ms=self.f.pair.now,
            causal_parents=(self.mid,),
            payload={
                "schema": "dm.communication.receipt/v1",
                "message_id": self.mid,
                "thread_id": self.f.message["payload"]["intent"]["thread_id"],
                "recipient_type": "relationship",
                "recipient_id": self.rid,
                "outcome": "failed:transport",
                "observed_at_ms": self.f.pair.now,
                "evidence_ref": None,
            },
        )
        self.assertTrue(self.s.record_receipt(receipt["event_id"])["terminal"])
        with self.s._database() as db:
            original = dict(
                db.execute("SELECT * FROM communication_receipts").fetchone()
            )
        for field, value in [
            ("receipt_hash", "0" * 64),
            ("outcome", "delivered"),
            ("receipt_json", b"{}"),
        ]:
            with self.subTest(field=field):
                with self.s._database() as db:
                    db.execute(f"UPDATE communication_receipts SET {field}=?", (value,))
                with self.assertRaises(ValueError):
                    self.s.result(self.mid)
                with self.s._database() as db:
                    db.execute(
                        f"UPDATE communication_receipts SET {field}=?",
                        (original[field],),
                    )
        # A signed local delivered receipt from the sender is not recipient proof.
        bad = self.f.sender.ledger.append_local(
            kind="experience.observed",
            subject="communication-receipt",
            signer=self.f.pair.sender.signer,
            sensitivity="shareable",
            occurred_at_ms=self.f.pair.now,
            causal_parents=(self.mid,),
            payload={**receipt["payload"], "outcome": "delivered"},
        )
        with self.assertRaisesRegex(ValueError, "receipt_origin_mismatch"):
            self.s.record_receipt(bad["event_id"])
        projection = dict(
            schema="dm.semantic-receipt/v1",
            leg_id=original["leg_id"],
            receipt_event_id=bad["event_id"],
            receipt_hash=bad["content_hash"],
            outcome="delivered",
        )
        with self.s._database() as db:
            db.execute(
                "UPDATE communication_receipts SET receipt_event_id=?, "
                "receipt_hash=?, outcome=?, receipt_json=?",
                (
                    bad["event_id"],
                    bad["content_hash"],
                    "delivered",
                    canonical_bytes(projection),
                ),
            )
            db.execute(
                "UPDATE communication_legs SET state='delivered', "
                "terminal_receipt_event_id=?, terminal_receipt_hash=?",
                (bad["event_id"], bad["content_hash"]),
            )
        with self.assertRaisesRegex(ValueError, "receipt_origin_mismatch"):
            self.s.result(self.mid)

    def test_cached_neighbors_revalidate_proof_and_preserve_history(self):
        leg = self.s.result(self.mid)["legs"][0]
        page_args = dict(
            recipient_id=self.rid,
            consumer_id="history",
            request_id=_uuid("history-page"),
            cursor=None,
        )
        claim_args = dict(
            recipient_id=self.rid,
            consumer_id="history",
            claim_id=_uuid("history-claim"),
            limit=1,
            lease_until_ms=self.f.pair.now + 10000,
        )
        attempt = dict(
            schema="dm.route-attempt/v1",
            attempt_id=_uuid("history-attempt"),
            leg_id=leg["leg_id"],
            body_ref="body",
            credential_ref="credential",
            provider_ref="provider",
            route_ref="route",
            deadline_ms=self.f.pair.now + 10000,
        )
        # Both snapshots are genuinely accepted, not current terminal proof.
        page = self.s.page(**page_args)
        claim = self.s.claim(**claim_args)
        self.s.record_attempt(attempt)
        delivery_args = dict(
            attempt_id=attempt["attempt_id"],
            delivery_id=_uuid("history-delivery"),
            envelope_hash="1" * 64,
        )
        self.s.record_delivery(**delivery_args)
        ack_args = dict(attempt_id=attempt["attempt_id"], ack={"ack": True})
        ack = self.s.record_route_ack(**ack_args)
        self.deliver()
        cursor_args = dict(
            recipient_id=self.rid, consumer_id="history", sequence=leg["sequence"]
        )
        progress = self.s.advance_consumer(**cursor_args)
        self.assertEqual(
            1,
            self.s.compact(recipient_id=self.rid, through_sequence=leg["sequence"])[
                "removed"
            ],
        )
        self.assertEqual(page, self.s.page(**page_args))
        self.assertEqual(claim, self.s.claim(**claim_args))
        self.assertEqual(ack, self.s.record_route_ack(**ack_args))
        self.assertEqual(progress, self.s.advance_consumer(**cursor_args))
        self.assertEqual("route-acked", self.s.record_attempt(attempt)["state"])
        self.assertTrue(self.s.record_delivery(**delivery_args)["replayed"])
        with self.s._database() as db:
            raw_attempt = db.execute(
                "SELECT attempt_json FROM communication_attempts"
            ).fetchone()[0]
            db.execute("UPDATE communication_attempts SET attempt_json=?", (b"{}",))
        with self.assertRaises(ValueError):
            self.s.record_attempt(attempt)
        with self.s._database() as db:
            db.execute(
                "UPDATE communication_attempts SET attempt_json=?", (raw_attempt,)
            )
        with self.s._database() as db:
            db.execute(
                "UPDATE communication_foreign_receipts SET receipt_hash=?", ("0" * 64,)
            )
        for name, call in [
            ("page", lambda: self.s.page(**page_args)),
            ("claim", lambda: self.s.claim(**claim_args)),
            ("attempt", lambda: self.s.record_attempt(attempt)),
            ("delivery", lambda: self.s.record_delivery(**delivery_args)),
            ("ack", lambda: self.s.record_route_ack(**ack_args)),
            ("cursor", lambda: self.s.advance_consumer(**cursor_args)),
        ]:
            with self.subTest(path=name), self.assertRaises(ValueError):
                call()

    def test_cached_snapshot_fields_cannot_claim_unproved_terminal_state(self):
        from daimon_matrix.canonical import canonical_bytes

        args = dict(
            recipient_id=self.rid,
            consumer_id="snapshot",
            request_id=_uuid("snapshot"),
            cursor=None,
        )
        good = self.s.page(**args)
        for field, value in [
            ("recipient_id", "wrong"),
            ("state", "delivered"),
            ("terminal_receipt_hash", "0" * 64),
        ]:
            with self.subTest(field=field):
                bad = copy.deepcopy(good)
                bad["items"][0][field] = value
                with self.s._database() as db:
                    db.execute(
                        "UPDATE communication_page_requests SET response_json=?",
                        (canonical_bytes(bad),),
                    )
                with self.assertRaises(ValueError):
                    self.s.page(**args)
        with self.s._database() as db:
            db.execute(
                "UPDATE communication_page_requests SET response_json=?",
                (canonical_bytes(good),),
            )
        self.assertEqual(good, self.s.page(**args))

    def test_cached_claim_bindings_and_items_are_checked(self):
        from daimon_matrix.canonical import canonical_bytes

        args = dict(
            recipient_id=self.rid,
            consumer_id="cached-claim",
            claim_id=_uuid("cached-claim"),
            limit=1,
            lease_until_ms=self.f.pair.now + 10000,
        )
        good = self.s.claim(**args)
        for field, value in [
            ("consumer_id", "wrong"),
            ("claim_id", _uuid("wrong")),
            ("lease_until_ms", self.f.pair.now + 20000),
        ]:
            with self.subTest(field=field):
                bad = {**good, field: value}
                with self.s._database() as db:
                    db.execute(
                        "UPDATE communication_claim_batches SET response_json=?",
                        (canonical_bytes(bad),),
                    )
                with self.assertRaises(ValueError):
                    self.s.claim(**args)
        bad = copy.deepcopy(good)
        bad["items"][0]["state"] = "delivered"
        with self.s._database() as db:
            db.execute(
                "UPDATE communication_claim_batches SET response_json=?",
                (canonical_bytes(bad),),
            )
        with self.assertRaises(ValueError):
            self.s.claim(**args)
        with self.s._database() as db:
            db.execute(
                "UPDATE communication_claim_batches SET response_json=?",
                (canonical_bytes(good),),
            )
        self.assertEqual(good, self.s.claim(**args))

    def test_cached_pagination_and_terminal_history(self):
        self.f.sender.prepare(
            client_id="owner",
            send_id=_uuid("pagination-other"),
            thread_id=_uuid("pagination-thread"),
            text="other",
        )
        args = dict(
            recipient_id=self.rid,
            consumer_id="pagination",
            request_id=_uuid("pagination-first"),
            cursor=None,
            limit=1,
        )
        self.deliver()
        first = self.s.page(**args)
        self.assertIsNotNone(first["next_cursor"])
        next_args = {
            **args,
            "request_id": _uuid("pagination-next"),
            "cursor": first["next_cursor"],
        }
        second = self.s.page(**next_args)
        self.assertEqual("delivered", first["items"][0]["state"])
        self.assertEqual("accepted", second["items"][0]["state"])
        self.assertEqual(second, self.s.page(**next_args))
        with self.s._database() as db:
            db.execute("UPDATE communication_page_cursors SET consumer_id='wrong'")
        for call in [lambda: self.s.page(**args), lambda: self.s.page(**next_args)]:
            with self.assertRaises(ValueError):
                call()
        with self.s._database() as db:
            db.execute("UPDATE communication_page_cursors SET consumer_id='pagination'")
        conflicting = create_event(
            authority=self.f.pair.recipient.authority,
            origin=self.f.pair.recipient.origin,
            signer=self.f.pair.recipient.signer,
            sequence=1,
            previous_event_id=None,
            causal_parents=[],
            event_id=_uuid("pagination-conflict"),
            kind="experience.observed",
            subject="communication-receipt",
            payload=self.f.receipt()["payload"],
            sensitivity="shareable",
            occurred_at_ms=self.f.pair.now,
        )
        with self.assertRaisesRegex(ValueError, "terminal_receipt_conflict"):
            self.s.record_foreign_receipt(conflicting, recipient_being_ref=self.rec)
        self.assertEqual("quarantined", self.s.result(self.mid)["legs"][0]["state"])
        self.assertEqual(first, self.s.page(**args))
        self.assertEqual(second, self.s.page(**next_args))
        with self.s._database() as db:
            db.execute(
                "UPDATE communication_foreign_receipts SET receipt_hash=?", ("0" * 64,)
            )
        with self.assertRaises(ValueError):
            self.s.page(**next_args)


class MigrationReviewProbes(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def v1_store(self, name):
        root = self.root / name
        pair = native.Pair(root)
        case = native.NativeMessagingTests()
        case.root = root / "sender-case"
        sender = case.make_sender(pair)
        store = CommunicationStore(sender.ledger, clock=lambda: pair.now)
        sender.communication = store
        sender.prepare(
            client_id="migration",
            send_id=_uuid(name + "-send"),
            thread_id=_uuid(name + "-thread"),
            text="one",
        )
        return pair, sender, store

    def assert_v1_migration_rolled_back(self, store):
        self.assertFalse(store.receipts_v2)
        with store._database() as db:
            self.assertEqual(
                db.execute(
                    "SELECT value FROM communication_meta WHERE key='schema_version'"
                ).fetchone()[0],
                "1",
            )
            for table in (
                "communication_foreign_receipts",
                "communication_compactions",
            ):
                self.assertIsNone(
                    db.execute(
                        "SELECT 1 FROM sqlite_schema WHERE name=? AND type='table'",
                        (table,),
                    ).fetchone()
                )

    @staticmethod
    def terminalize_v1(pair, sender, store, message=None):
        if message is None:
            message = sender.ledger.events()[0]
        receipt = sender.ledger.append_local(
            kind="experience.observed",
            subject="communication-receipt",
            signer=pair.sender.signer,
            sensitivity="shareable",
            occurred_at_ms=pair.now,
            causal_parents=(message["event_id"],),
            payload={
                "schema": "dm.communication.receipt/v1",
                "message_id": message["event_id"],
                "thread_id": message["payload"]["intent"]["thread_id"],
                "recipient_type": "relationship",
                "recipient_id": pair.policy.membership_ref,
                "outcome": "failed:transport",
                "observed_at_ms": pair.now,
                "evidence_ref": None,
            },
        )
        return store.record_receipt(receipt["event_id"])

    def test_v1_consumer_wrong_generation_cannot_commit_v2_schema(self):
        pair, _sender, store = self.v1_store("consumer-wrong-generation")
        with store._database() as db:
            sequence = db.execute("SELECT sequence FROM communication_legs").fetchone()[
                0
            ]
            db.execute(
                "INSERT INTO communication_consumers VALUES (?, ?, ?, ?)",
                (pair.policy.membership_ref, "migration", "wrong-generation", sequence),
            )
        with self.assertRaisesRegex(ValueError, "consumer_generation_mismatch"):
            store.upgrade_receipts_v2()
        self.assert_v1_migration_rolled_back(store)

    def test_v1_consumer_beyond_highwater_cannot_commit_v2_schema(self):
        pair, _sender, store = self.v1_store("consumer-beyond-highwater")
        with store._database() as db:
            generation = db.execute(
                "SELECT value FROM communication_meta WHERE key='generation'"
            ).fetchone()[0]
            highwater = int(
                db.execute(
                    "SELECT value FROM communication_meta "
                    "WHERE key='sequence_highwater'"
                ).fetchone()[0]
            )
            db.execute(
                "INSERT INTO communication_consumers VALUES (?, ?, ?, ?)",
                (pair.policy.membership_ref, "migration", generation, highwater + 1),
            )
        with self.assertRaisesRegex(ValueError, "cursor_beyond_highwater"):
            store.upgrade_receipts_v2()
        self.assert_v1_migration_rolled_back(store)

    def test_v1_consumer_malformed_type_cannot_commit_v2_schema(self):
        pair, _sender, store = self.v1_store("consumer-malformed-type")
        with store._database() as db:
            generation = db.execute(
                "SELECT value FROM communication_meta WHERE key='generation'"
            ).fetchone()[0]
            sequence = db.execute("SELECT sequence FROM communication_legs").fetchone()[
                0
            ]
            db.execute(
                "INSERT INTO communication_consumers VALUES (?, ?, ?, ?)",
                (pair.policy.membership_ref, b"migration", generation, sequence),
            )
        with self.assertRaisesRegex(ValueError, "invalid_consumer_binding"):
            store.upgrade_receipts_v2()
        self.assert_v1_migration_rolled_back(store)

    def test_v1_consumer_unowned_target_cannot_commit_v2_schema(self):
        _pair, _sender, store = self.v1_store("consumer-unowned-target")
        with store._database() as db:
            generation = db.execute(
                "SELECT value FROM communication_meta WHERE key='generation'"
            ).fetchone()[0]
            sequence = db.execute("SELECT sequence FROM communication_legs").fetchone()[
                0
            ]
            db.execute(
                "INSERT INTO communication_consumers VALUES (?, ?, ?, ?)",
                ("unowned-recipient", "migration", generation, sequence),
            )
        with self.assertRaisesRegex(ValueError, "consumer_target_not_owned"):
            store.upgrade_receipts_v2()
        self.assert_v1_migration_rolled_back(store)

    def test_v1_compaction_participant_must_be_terminal_prefix(self):
        pair, sender, store = self.v1_store("compaction-participant")
        first = self.terminalize_v1(pair, sender, store)["legs"][0]["sequence"]
        store.advance_consumer(
            recipient_id=pair.policy.membership_ref,
            consumer_id="migration",
            sequence=first,
        )
        store.compact(recipient_id=pair.policy.membership_ref, through_sequence=first)
        sender.prepare(
            client_id="migration",
            send_id=_uuid("compaction-participant-second"),
            thread_id=_uuid("compaction-participant-second-thread"),
            text="pending",
        )
        with store._database() as db:
            second = db.execute(
                "SELECT max(sequence) FROM communication_legs"
            ).fetchone()[0]
            db.execute(
                "UPDATE communication_consumers SET sequence=?",
                (second,),
            )
        with self.assertRaisesRegex(ValueError, "consumer_prefix_not_terminal"):
            store.upgrade_receipts_v2()
        self.assert_v1_migration_rolled_back(store)

    def test_v1_consumer_nonterminal_prefix_cannot_commit_v2_schema(self):
        pair, sender, store = self.v1_store("consumer-nonterminal-prefix")
        sender.prepare(
            client_id="migration",
            send_id=_uuid("consumer-nonterminal-prefix-second"),
            thread_id=_uuid("consumer-nonterminal-prefix-second-thread"),
            text="terminal target",
        )
        with store._database() as db:
            target = db.execute(
                "SELECT message_id, sequence FROM communication_legs "
                "ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
        message = sender.ledger.event(target["message_id"])
        self.assertIsNotNone(message)
        self.terminalize_v1(pair, sender, store, message)
        with store._database() as db:
            generation = db.execute(
                "SELECT value FROM communication_meta WHERE key='generation'"
            ).fetchone()[0]
            db.execute(
                "INSERT INTO communication_consumers VALUES (?, ?, ?, ?)",
                (
                    pair.policy.membership_ref,
                    "migration",
                    generation,
                    target["sequence"],
                ),
            )
        with self.assertRaisesRegex(ValueError, "consumer_prefix_not_terminal"):
            store.upgrade_receipts_v2()
        self.assert_v1_migration_rolled_back(store)

    def test_clean_v1_store_migrates_to_v2(self):
        _pair, _sender, store = self.v1_store("clean-v1")
        store.upgrade_receipts_v2()
        self.assertTrue(store.receipts_v2)
        with store._database() as db:
            self.assertEqual(
                db.execute(
                    "SELECT value FROM communication_meta WHERE key='schema_version'"
                ).fetchone()[0],
                "2",
            )
            for table in (
                "communication_foreign_receipts",
                "communication_compactions",
            ):
                self.assertIsNotNone(
                    db.execute(
                        "SELECT 1 FROM sqlite_schema WHERE name=? AND type='table'",
                        (table,),
                    ).fetchone()
                )

    def test_v1_queue_corruption_cannot_commit_v2_schema(self):
        import sqlite3

        for mutation in ("missing", "extra", "swapped"):
            with self.subTest(mutation=mutation):
                root = self.root / ("queue-migration-" + mutation)
                pair = native.Pair(root)
                case = native.NativeMessagingTests()
                case.root = root / "sender-case"
                sender = case.make_sender(pair)
                store = CommunicationStore(
                    sender.ledger, clock=lambda pair=pair: pair.now
                )
                sender.communication = store
                sender.prepare(
                    client_id="migration",
                    send_id=_uuid(mutation + "-one"),
                    thread_id=_uuid(mutation + "-thread-one"),
                    text="one",
                )
                if mutation == "swapped":
                    sender.prepare(
                        client_id="migration",
                        send_id=_uuid(mutation + "-two"),
                        thread_id=_uuid(mutation + "-thread-two"),
                        text="two",
                    )
                if mutation == "missing":
                    with store._database() as db:
                        db.execute("DELETE FROM communication_queue")
                elif mutation == "extra":
                    with closing(sqlite3.connect(sender.ledger.path)) as db, db:
                        db.execute(
                            "INSERT INTO communication_queue VALUES (?, ?, ?)",
                            (999, "orphan-leg", pair.policy.membership_ref),
                        )
                else:
                    with store._database() as db:
                        rows = db.execute(
                            "SELECT sequence, leg_id FROM communication_queue "
                            "ORDER BY sequence"
                        ).fetchall()
                        first, second = rows
                        db.execute(
                            "UPDATE communication_queue SET sequence=-1 WHERE leg_id=?",
                            (first["leg_id"],),
                        )
                        db.execute(
                            "UPDATE communication_queue SET sequence=-2 WHERE leg_id=?",
                            (second["leg_id"],),
                        )
                        db.execute(
                            "UPDATE communication_queue SET sequence=? WHERE leg_id=?",
                            (second["sequence"], first["leg_id"]),
                        )
                        db.execute(
                            "UPDATE communication_queue SET sequence=? WHERE leg_id=?",
                            (first["sequence"], second["leg_id"]),
                        )
                expected = (
                    "communication_queue_incomplete"
                    if mutation == "missing"
                    else "communication_queue_binding_mismatch"
                )
                with self.assertRaisesRegex(ValueError, expected):
                    store.upgrade_receipts_v2()
                with store._database() as db:
                    self.assertEqual(
                        db.execute(
                            "SELECT value FROM communication_meta "
                            "WHERE key='schema_version'"
                        ).fetchone()[0],
                        "1",
                    )
                    self.assertIsNone(
                        db.execute(
                            "SELECT 1 FROM sqlite_schema "
                            "WHERE name='communication_compactions'"
                        ).fetchone()
                    )

    def test_v1_compacted_terminal_queue_migrates_with_durable_evidence(self):
        root = self.root / "queue-migration-compacted"
        pair = native.Pair(root)
        case = native.NativeMessagingTests()
        case.root = root / "sender-case"
        sender = case.make_sender(pair)
        store = CommunicationStore(sender.ledger, clock=lambda: pair.now)
        sender.communication = store
        sender.prepare(
            client_id="migration",
            send_id=_uuid("compacted-one"),
            thread_id=_uuid("compacted-thread"),
            text="one",
        )
        message, _resolution = sender.ledger.events()[:2]
        receipt = sender.ledger.append_local(
            kind="experience.observed",
            subject="communication-receipt",
            signer=pair.sender.signer,
            sensitivity="shareable",
            occurred_at_ms=pair.now,
            causal_parents=(message["event_id"],),
            payload={
                "schema": "dm.communication.receipt/v1",
                "message_id": message["event_id"],
                "thread_id": message["payload"]["intent"]["thread_id"],
                "recipient_type": "relationship",
                "recipient_id": pair.policy.membership_ref,
                "outcome": "failed:transport",
                "observed_at_ms": pair.now,
                "evidence_ref": None,
            },
        )
        result = store.record_receipt(receipt["event_id"])
        sequence = result["legs"][0]["sequence"]
        store.advance_consumer(
            recipient_id=pair.policy.membership_ref,
            consumer_id="migration",
            sequence=sequence,
        )
        store.compact(
            recipient_id=pair.policy.membership_ref, through_sequence=sequence
        )
        store.upgrade_receipts_v2()
        with store._database() as db:
            self.assertEqual(
                tuple(db.execute("SELECT * FROM communication_compactions").fetchone()),
                (
                    pair.policy.membership_ref,
                    db.execute(
                        "SELECT value FROM communication_meta WHERE key='generation'"
                    ).fetchone()[0],
                    sequence,
                ),
            )
        self.assertTrue(store.result(message["event_id"])["terminal"])

    def test_v2_migration_retry_never_recreates_missing_inbox(self):
        from daimon_matrix import operator_messaging as op
        from daimon_matrix.messaging_config import (
            config_digest,
            read_document,
        )
        from tests.test_messaging_runtime import application_fixture

        runtime, spec, sources, _ = application_fixture(self)
        target = self.root / "missing-v2-inbox"
        op.prepare(runtime, target, spec, secret_sources=sources)
        predecessor = config_digest(read_document(target / "application.json"))
        op.upgrade_semantic_receipts(
            runtime, target, expected_application_sha256=predecessor
        )
        inbox = target / spec["stores"]["inbox"]
        saved = inbox.with_suffix(".saved")
        inbox.rename(saved)
        with self.assertRaisesRegex(ValueError, "messaging_required_store_invalid"):
            op.upgrade_semantic_receipts(
                runtime, target, expected_application_sha256=predecessor
            )
        self.assertFalse(inbox.exists())

    def test_real_runtime_migration_crash_publication_boundaries_preserve_unsent(self):
        import json

        from daimon_matrix import operator_messaging as op
        from daimon_matrix.messaging_config import (
            config_digest,
            load_application,
            read_publication,
        )
        from daimon_matrix.runtime import load_runtime
        from tests.test_dm024_runtime import PASSWORD
        from tests.test_messaging_runtime import application_fixture

        for boundary in ("generation-published", "publication-selected"):
            with self.subTest(boundary=boundary):
                runtime, spec, sources, _ = application_fixture(self)
                target = self.root / "review-app"
                op.prepare(runtime, target, spec, secret_sources=sources)
                app = load_application(runtime, target)
                delivery = app.service.messaging.deliveries["peer-out"]
                args = dict(
                    client_id="client:operator-messaging",
                    send_id=_uuid("review-unsent"),
                    thread_id=_uuid("review-unsent-thread"),
                    text="never sent",
                )
                envelopes = delivery.sender.prepare(**args)
                message_id = json.loads(envelopes[1])["event_id"]
                previous, _ = read_publication(runtime, target)
                predecessor = config_digest(previous)
                if boundary == "generation-published":
                    original = op._publish

                    def crash(*args, original=original, **kwargs):
                        value = original(*args, **kwargs)
                        if args[1].name.startswith("generation-"):
                            raise OSError("after-generation-publish")
                        return value

                    fault = patch.object(op, "_publish", side_effect=crash)
                else:
                    original = op.os.replace

                    def crash(*args, original=original, **kwargs):
                        value = original(*args, **kwargs)
                        if args[1].name == "publication.json":
                            raise OSError("after-publication-select")
                        return value

                    fault = patch.object(op.os, "replace", side_effect=crash)
                with fault, self.assertRaises(OSError):
                    op.upgrade_semantic_receipts(
                        runtime, target, expected_application_sha256=predecessor
                    )
                restarted = load_runtime(
                    runtime.state_root,
                    "runtime.json",
                    lambda: bytearray(PASSWORD),
                    clock=lambda: self.pair.now,
                )
                result = op.upgrade_semantic_receipts(
                    restarted, target, expected_application_sha256=predecessor
                )
                self.assertEqual(result["status"], "semantic-v2")
                after = load_application(
                    restarted, target
                ).service.messaging.deliveries["peer-out"]
                self.assertEqual(envelopes, after.sender.prepare(**args))
                self.assertEqual(
                    after._semantic(message_id)["status"], "legacy-untracked"
                )
                self.assertFalse(after._semantic(message_id)["terminal"])
                fresh = after.sender.prepare(
                    **{**args, "send_id": _uuid("review-fresh-v2")}
                )
                new_id = json.loads(fresh[1])["event_id"]
                self.assertFalse(after._semantic(new_id)["terminal"])
                self.assertEqual(
                    after._semantic(new_id)["legs"][0]["state"], "accepted"
                )
                self.assertEqual(
                    result,
                    op.upgrade_semantic_receipts(
                        restarted, target, expected_application_sha256=predecessor
                    ),
                )
