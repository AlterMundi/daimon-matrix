"""Membership group integration over the existing authenticated HTTP transport."""

from __future__ import annotations

import threading
import unittest
import uuid
from contextlib import closing
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from daimon_matrix.canonical import canonical_bytes
from daimon_matrix.communication import CommunicationStore
from daimon_matrix.daemon import create_messaging_http_server
from daimon_matrix.messaging import GroupMessaging, MessagingTribePolicy
from daimon_matrix.native_egress import (
    VISIBILITY_SCHEMA_VERSION,
    MandatoryEgressController,
    synthetic_visibility,
)
from daimon_matrix.routes import DirectHTTPProvider, OpaqueInbox, TransportIngress
from tests import test_dm051_sealed as sealing_fixtures


class GroupRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.fixture = sealing_fixtures.TribeConversationLaneTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        fixture = self.fixture
        root = Path(fixture.journey.root)
        self.groups = []
        self.servers = []
        for index, lane in enumerate((fixture.sender_lane, fixture.receiver_lane)):
            # Match the receiving compositor's single operational clock.
            lane.records.clock = lane.clock
            template = synthetic_visibility(clock=lane.clock)
            controller = MandatoryEgressController(
                policy=template._policy,
                proof_key=template._proof_key,
                transport=template._transport,
                clock=lane.clock,
                catalog_mode="migrate",
            )
            communication = CommunicationStore(
                lane.ledger,
                clock=lane.clock,
                foreign_authority_resolver=lane.authority_resolver,
            )
            communication.initialize()
            communication.upgrade_receipts_v2()
            communication.upgrade_legs_v3()
            group = GroupMessaging(
                lane=lane,
                policy=MessagingTribePolicy(
                    tribe_ref=fixture.tribe_ref,
                    membership_ref=fixture._membership_of(lane.being_ref),
                    classification="shareable",
                    max_ttl_ms=60_000,
                ),
                communication=communication,
                providers={},
                config_digest="0" * 64,
                egress=controller,
            )
            ingresses = {}
            origin_body = lane.ledger.local_origin["body_ref"]
            for phase in ("evidence", "message"):
                ingresses[phase] = TransportIngress(
                    provider_ref=f"body-{index}",
                    route_ref=f"body-{index}",
                    key_ref=f"key-{index}",
                    secret=bytes([index + 1]) * 32,
                    recipient_id=lane.local_embodiment_id,
                    recipient_body_ref=lane.ledger.local_origin["body_ref"],
                    recipient_embodiment_id=lane.local_embodiment_id,
                    inbox=OpaqueInbox(
                        root / f"{index}-{phase}.sqlite", clock=lane.clock
                    ),
                    clock=lane.clock,
                    egress=group.egress,
                    egress_catalog_id=f"{phase}-responses",
                    egress_authority_head=origin_body,
                    egress_authorizer=lambda binding, origin=origin_body: (
                        binding.authority_head == origin
                    ),
                    intake_validator=None,
                    intake_admission=group.admit_message
                    if phase == "message"
                    else group.admit_evidence,
                    carrier_inspector=group.inspect_carrier,
                )
            group.intake_ingresses = ingresses
            server = create_messaging_http_server(
                ("127.0.0.1", 0),
                evidence_ingress=ingresses["evidence"],
                message_ingress=ingresses["message"],
            )
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            self.addCleanup(thread.join)
            self.addCleanup(server.server_close)
            self.addCleanup(server.shutdown)
            self.groups.append(group)
            self.servers.append(server)
        for group in self.groups:
            for index, receiver in enumerate(self.groups):
                group.providers[
                    (receiver.lane.being_ref, receiver.lane.local_embodiment_id)
                ] = {
                    phase: DirectHTTPProvider(
                        provider_ref=f"body-{index}",
                        route_ref=f"body-{index}",
                        key_ref=f"key-{index}",
                        secret=bytes([index + 1]) * 32,
                        route_class="direct",
                        sender_principal=group.lane.being_ref,
                        sender_body_ref=group.ledger.local_origin["body_ref"],
                        endpoint=f"http://127.0.0.1:{self.servers[index].server_port}"
                        f"/dm-messaging/v1/{phase}",
                        clock=group.lane.clock,
                        egress=group.egress,
                    )
                    for phase in ("evidence", "message")
                }

        for group in self.groups:
            group.egress.migrate_registered_catalogs(version=VISIBILITY_SCHEMA_VERSION)
            group.egress.validate_registered_catalogs()

    def send_and_settle(self, group, **arguments):
        result = group.send(**arguments)
        # A transport ACK can precede the receiver's technical return attempt.
        # Join only the real admitted HTTP handlers before asserting their proof.
        for server in [*self.servers, self.servers[0]]:
            server._threads.join()
        return group.inspect(
            client_id=arguments["client_id"], send_id=result["send_id"]
        )

    def test_http_ack_precedes_a_blocked_signed_receipt_attempt(self):
        sender, receiver = self.groups
        entered, release = threading.Event(), threading.Event()
        original = receiver.lane._author_receipt

        def blocked(*arguments, **keywords):
            entered.set()
            if not release.wait(timeout=5):
                raise AssertionError("synthetic receipt release missing")
            return original(*arguments, **keywords)

        with patch.object(receiver.lane, "_author_receipt", side_effect=blocked):
            try:
                first = sender.send(
                    client_id="test",
                    send_id=str(uuid.uuid4()),
                    thread_id=str(uuid.uuid4()),
                    text="ACK before receipt signing",
                )
                self.assertTrue(entered.wait(timeout=1))
                remote = next(
                    row
                    for row in first["transport"]
                    if row["being_ref"] == receiver.lane.being_ref
                )
                self.assertEqual(remote["state"], "recipient-intake")
                self.assertFalse(first["semantic"]["terminal"])
                self.assertEqual(len(receiver.page(after=0, limit=10)), 1)
            finally:
                release.set()
                for server in [*self.servers, self.servers[0]]:
                    server._threads.join()
        self.assertTrue(
            sender.inspect(client_id="test", send_id=first["send_id"])["semantic"][
                "terminal"
            ]
        )

    def _fail_ack_after_durable_intake(self, sender, receiver):
        with patch.object(
            receiver.intake_ingresses["message"].inbox,
            "_finalize_retained_intake",
            side_effect=OSError("synthetic ACK disk failure"),
        ):
            first = self.send_and_settle(
                sender,
                client_id="test",
                send_id=str(uuid.uuid4()),
                thread_id=str(uuid.uuid4()),
                text="recover the committed readable intake",
            )
        self.assertFalse(first["semantic"]["terminal"])
        self.assertEqual(len(receiver.page(after=0, limit=10)), 1)
        admission = receiver.records.intake_page()["items"][0]["admission"]
        self.assertIsNone(receiver.records.get("receipt", first["message_id"]))
        return first, admission

    def test_known_intake_ack_failure_recovers_without_false_refusal(self):
        sender, receiver = self.groups
        first, admission = self._fail_ack_after_durable_intake(sender, receiver)
        obligation = receiver.records.get("receipt-obligation", first["message_id"])
        recovered = receiver.reconcile_intake()
        self.assertEqual(recovered["items"][0]["state"], "recipient-intake")
        self.assertEqual(recovered["inference_started"], 0)
        ack = receiver.records.get(
            "intake-ack", admission["context"]["request"]["request_id"]
        )
        self.assertIsNotNone(ack)
        self.assertEqual(
            receiver.records.get("receipt-obligation", first["message_id"]), obligation
        )
        self.assertEqual(len(receiver.page(after=0, limit=10)), 1)
        inspected = sender.inspect(client_id="test", send_id=first["send_id"])
        self.assertTrue(inspected["semantic"]["terminal"])
        self.assertEqual(
            sum(
                event["subject"] == "communication-receipt"
                for event in receiver.ledger.events()
            ),
            1,
        )

    def test_expired_committed_intake_recovers_history_without_decrypt_or_egress(self):
        sender, receiver = self.groups
        first, admission = self._fail_ack_after_durable_intake(sender, receiver)
        obligation = receiver.records.get("receipt-obligation", first["message_id"])
        self.fixture.now = obligation["deadline_ms"]
        with (
            patch.object(
                receiver.lane,
                "validate_intake",
                side_effect=AssertionError("expired frame open"),
            ),
            patch.object(
                receiver,
                "inspect_carrier",
                side_effect=AssertionError("expired inspection"),
            ),
            patch.object(
                receiver, "_transmit", side_effect=AssertionError("expired I/O")
            ),
        ):
            recovered = receiver.reconcile_intake()
        self.assertEqual(recovered["items"][0]["state"], "expired")
        receipt = receiver.records.get("receipt", first["message_id"])["receipt"]
        self.assertEqual(
            receipt["payload"]["observed_at_ms"], obligation["observed_at_ms"]
        )
        self.assertEqual(receipt["occurred_at_ms"], self.fixture.now)
        self.assertEqual(
            receiver.records.get("receipt-obligation", first["message_id"]), obligation
        )
        self.assertIsNotNone(
            receiver.records.get(
                "intake-ack", admission["context"]["request"]["request_id"]
            )
        )
        self.assertEqual(len(receiver.page(after=0, limit=10)), 1)
        receiver.egress.validate_registered_catalogs()

    def test_receipt_ledger_commit_survives_result_storage_failure(self):
        sender, receiver = self.groups
        original = receiver.records.reserve

        def fail_result(kind, *arguments, **keywords):
            if kind == "receipt":
                raise OSError("synthetic receipt result failure")
            return original(kind, *arguments, **keywords)

        with patch.object(receiver.records, "reserve", side_effect=fail_result):
            first = self.send_and_settle(
                sender,
                client_id="test",
                send_id=str(uuid.uuid4()),
                thread_id=str(uuid.uuid4()),
                text="recover stable receipt identity",
            )
        self.assertFalse(first["semantic"]["terminal"])
        before = [
            event
            for event in receiver.ledger.events()
            if event["subject"] == "communication-receipt"
        ]
        self.assertEqual(len(before), 1)
        self.fixture.now += 1
        recovered = receiver.reconcile_intake()
        self.assertEqual(recovered["items"][0]["state"], "recipient-intake")
        after = [
            event
            for event in receiver.ledger.events()
            if event["subject"] == "communication-receipt"
        ]
        self.assertEqual(before, after)
        self.assertEqual(len(receiver.page(after=0, limit=10)), 1)

    def test_control_ack_survives_foreign_projection_failure(self):
        sender, receiver = self.groups
        with patch.object(
            sender.communication,
            "record_foreign_receipt",
            side_effect=OSError("synthetic foreign projection failure"),
        ):
            first = self.send_and_settle(
                sender,
                client_id="test",
                send_id=str(uuid.uuid4()),
                thread_id=str(uuid.uuid4()),
                text="receipt proof is durably retained",
            )
        self.assertFalse(first["semantic"]["terminal"])
        controls = sender.records.intake_page()["items"]
        self.assertEqual(len(controls), 1)
        admission = controls[0]["admission"]
        self.assertEqual(admission["phase"], "evidence")
        request_id = admission["context"]["request"]["request_id"]
        self.assertIsNotNone(sender.records.get("control-proof", request_id))
        self.assertIsNotNone(sender.records.get("intake-ack", request_id))
        self.assertIsNone(sender.records.get("control-terminal", request_id))
        self.assertEqual(
            receiver.records.get("receipt-terminal", first["message_id"])["state"],
            "recipient-intake",
        )
        recovered = sender.reconcile_intake()
        self.assertEqual(recovered["items"][0]["state"], "receipt-projected")
        self.assertEqual(recovered["inference_started"], 0)
        self.assertTrue(
            sender.inspect(client_id="test", send_id=first["send_id"])["semantic"][
                "terminal"
            ]
        )
        self.assertEqual(len(receiver.page(after=0, limit=10)), 1)
        self.assertEqual(sender.page(after=0, limit=10), [])

    def test_lost_control_ack_retries_exact_receipt_without_duplicate_projection(self):
        sender, receiver = self.groups
        with patch.object(
            sender.intake_ingresses["evidence"].inbox,
            "_finalize_retained_intake",
            side_effect=OSError("synthetic control ACK failure"),
        ):
            first = self.send_and_settle(
                sender,
                client_id="test",
                send_id=str(uuid.uuid4()),
                thread_id=str(uuid.uuid4()),
                text="retry the same control carrier",
            )
        self.assertFalse(first["semantic"]["terminal"])
        controls = sender.records.intake_page()["items"]
        self.assertEqual(len(controls), 1)
        control = controls[0]["admission"]
        receipt = receiver.records.get("receipt", first["message_id"])
        returned = receiver.reconcile_intake()
        self.assertEqual(returned["items"][0]["state"], "recipient-intake")
        for server in [*self.servers, self.servers[0]]:
            server._threads.join()
        self.assertTrue(
            sender.inspect(client_id="test", send_id=first["send_id"])["semantic"][
                "terminal"
            ]
        )
        self.assertEqual(sender.records.intake_page()["items"][0]["admission"], control)
        self.assertEqual(len(sender.records.intake_page()["items"]), 1)
        self.assertEqual(receiver.records.get("receipt", first["message_id"]), receipt)
        self.assertEqual(
            receiver.reconcile_intake()["items"][0]["state"], "recipient-intake"
        )

    def test_postcommit_ticket_verification_failure_is_uncertain_not_refused(self):
        sender, receiver = self.groups
        with patch.object(
            receiver,
            "_retained_message_ticket",
            side_effect=ValueError("synthetic retained verification failure"),
        ):
            first = self.send_and_settle(
                sender,
                client_id="test",
                send_id=str(uuid.uuid4()),
                thread_id=str(uuid.uuid4()),
                text="committed before ticket verification",
            )
        remote = next(
            row
            for row in first["transport"]
            if row["being_ref"] == receiver.lane.being_ref
        )
        self.assertEqual(remote["state"], "pending")
        self.assertEqual(len(receiver.page(after=0, limit=10)), 1)
        admission = receiver.records.intake_page()["items"][0]["admission"]
        self.assertIsNone(
            receiver.records.get(
                "intake-ack", admission["context"]["request"]["request_id"]
            )
        )
        self.assertEqual(
            receiver.reconcile_intake()["items"][0]["state"], "recipient-intake"
        )

    def test_another_request_for_same_carrier_preserves_first_ack_time(self):
        from daimon_matrix.sealed import _parse

        sender, receiver = self.groups
        first = self.send_and_settle(
            sender,
            client_id="test",
            send_id=str(uuid.uuid4()),
            thread_id=str(uuid.uuid4()),
            text="same carrier, another authenticated request",
        )
        admission = receiver.records.intake_page()["items"][0]["admission"]
        obligation = receiver.records.get("receipt-obligation", first["message_id"])
        self.fixture.now += 1
        provider = sender.providers[
            (receiver.lane.being_ref, receiver.lane.local_embodiment_id)
        ]["message"]
        submission = {
            **admission["context"]["request"]["submission"],
            "attempt_id": str(uuid.uuid4()),
        }
        raw = provider.prepare_submission(submission)
        result = provider.send_prepared(
            raw,
            carrier_binding=sender.egress.binding(
                sender.records.catalog_id, first["send_id"]
            ),
        )
        for server in [*self.servers, self.servers[0]]:
            server._threads.join()
        self.assertEqual(result["outcome"], "recipient-intake")
        self.assertEqual(
            result["intake"]["accepted_at_ms"], admission["received_at_ms"]
        )
        new_id = _parse(raw)["request_id"]
        other = receiver.records.get("intake-admission", new_id)
        self.assertEqual(other["received_at_ms"], self.fixture.now)
        self.assertIsNotNone(receiver.records.get("intake-ack", new_id))
        self.assertEqual(
            receiver.records.get("receipt-obligation", first["message_id"]), obligation
        )
        self.assertEqual(len(receiver.page(after=0, limit=10)), 1)

    def test_known_return_ack_survives_terminal_failure_expiry_and_route_removal(self):
        sender, receiver = self.groups
        original = receiver.records.reserve

        def fail_terminal(kind, *arguments, **keywords):
            if kind == "receipt-terminal":
                raise OSError("synthetic completion storage failure")
            return original(kind, *arguments, **keywords)

        with patch.object(receiver.records, "reserve", side_effect=fail_terminal):
            first = self.send_and_settle(
                sender,
                client_id="test",
                send_id=str(uuid.uuid4()),
                thread_id=str(uuid.uuid4()),
                text="observed return survives expiry",
            )
        self.assertTrue(first["semantic"]["terminal"])
        self.assertIsNone(receiver.records.get("receipt-terminal", first["message_id"]))
        obligation = receiver.records.get("receipt-obligation", first["message_id"])
        self.fixture.now = obligation["deadline_ms"]
        receiver.providers.clear()
        with patch.object(
            receiver, "_transmit", side_effect=AssertionError("historical I/O")
        ):
            recovered = receiver.reconcile_intake()
        self.assertEqual(recovered["items"][0]["state"], "recipient-intake")
        self.assertEqual(
            receiver.records.get("receipt-terminal", first["message_id"])["state"],
            "recipient-intake",
        )

    def test_staged_http_rejects_invalid_signed_receipt_before_control_commit(self):
        import hashlib

        from daimon_matrix.weave import create_event

        sender, receiver = self.groups
        first = self.send_and_settle(
            sender,
            client_id="test",
            send_id=str(uuid.uuid4()),
            thread_id=str(uuid.uuid4()),
            text="closed receipt format before admission",
        )
        original = receiver.records.get("receipt", first["message_id"])
        baseline = sender.records.intake_page()["items"]
        for index, (extra, parents) in enumerate(
            (
                ({"unexpected": True}, []),
                ({}, [first["message_id"]]),
            ),
            start=1,
        ):
            with self.subTest(extra=bool(extra), foreign_parent=bool(parents)):
                old = original["receipt"]
                receipt = create_event(
                    authority=receiver.lane._active(receiver.lane.being_ref),
                    origin=receiver.ledger.local_origin,
                    sequence=old["sequence"] + index,
                    previous_event_id=old["event_id"],
                    causal_parents=parents,
                    event_id=str(uuid.uuid4()),
                    kind=old["kind"],
                    subject=old["subject"],
                    payload={**old["payload"], **extra},
                    signer=receiver.signer,
                    sensitivity=old["sensitivity"],
                    occurred_at_ms=old["occurred_at_ms"],
                )
                document = {
                    **original,
                    "receipt": receipt,
                    "receipt_hash": hashlib.sha256(
                        canonical_bytes(receipt)
                    ).hexdigest(),
                }
                raw = canonical_bytes(document)
                identifier = receipt["event_id"]
                operation = receiver.records.admit(
                    identifier,
                    raw,
                    path_id="tribe-receipt-request",
                    projection={
                        "event_id": identifier,
                        "event_digest": receipt["content_hash"],
                        "sender": receiver.lane.being_ref,
                        "recipients": [sender.lane.being_ref],
                        "thread_id": first["thread_id"],
                        "kind": "authorization-control",
                        "reply_to": None,
                        "content": {"stage": "semantic-receipt"},
                    },
                    deadline_ms=self.fixture.now + 60_000,
                    authority_head=receiver.ledger.local_origin["body_ref"],
                )
                receiver._transmit(
                    raw,
                    {
                        "being_ref": sender.lane.being_ref,
                        "embodiment_id": sender.lane.local_embodiment_id,
                    },
                    operation,
                    receipt=True,
                )
                for server in [*self.servers, self.servers[0]]:
                    server._threads.join()
                self.assertEqual(sender.records.intake_page()["items"], baseline)
                request_id = str(
                    uuid.uuid5(
                        uuid.UUID(identifier),
                        f"tribe-transport/v1:{sender.lane.being_ref}:{sender.lane.local_embodiment_id}",
                    )
                )
                proof = receiver.records.transport_result(request_id)
                self.assertEqual(proof["result"]["outcome"], "refused")
                self.assertEqual(len(receiver.page(after=0, limit=10)), 1)

    def test_real_http_intake_receipts_reply_and_exact_retry(self):
        sender, receiver = self.groups
        send_id, thread_id = str(uuid.uuid4()), str(uuid.uuid4())
        first = self.send_and_settle(
            sender,
            client_id="test",
            send_id=send_id,
            thread_id=thread_id,
            text="one group message",
        )
        self.assertTrue(first["semantic"]["terminal"])
        members = {row["being_ref"]: row for row in first["members"]}
        own = members[sender.lane.being_ref]
        remote = members[receiver.lane.being_ref]
        self.assertEqual(own["receiving_copy"], "unknown")
        self.assertEqual(len(own["author_retained_leg_ids"]), 1)
        self.assertEqual(remote["receiving_copy"], "proved")
        self.assertEqual(len(remote["receiving_leg_ids"]), 1)
        self.assertEqual(remote["author_retained_leg_ids"], [])
        remote_transport = [
            leg for leg in first["transport"] if leg["state"] != "author-retained"
        ]
        self.assertEqual(
            [leg["state"] for leg in remote_transport], ["recipient-intake"]
        )
        self.assertTrue(remote_transport[0]["response_sha256"])
        for group in self.groups:
            self.assertFalse(
                any(
                    "El transporte rechazó" in request["text"]
                    for request in group.egress._transport.requests
                )
            )
        items = receiver.page(after=0, limit=10)
        self.assertEqual(len(items), 1)
        self.assertEqual(
            items[0]["message"]["payload"]["body"]["text"], "one group message"
        )
        self.fixture.now += 1
        with patch.object(
            sender.lane, "snapshot", side_effect=AssertionError("resolved")
        ):
            retry = self.send_and_settle(
                sender,
                client_id="test",
                send_id=send_id,
                thread_id=thread_id,
                text="one group message",
            )
        self.assertEqual(retry, first)
        self.assertEqual(len(receiver.page(after=0, limit=10)), 1)
        inspected = sender.inspect(client_id="test", send_id=send_id)
        self.assertEqual(inspected, first)
        reply = self.send_and_settle(
            receiver,
            client_id="reply",
            send_id=str(uuid.uuid4()),
            thread_id=thread_id,
            text="connected reply",
            response_to=(receiver, first["message_id"]),
        )
        self.assertTrue(reply["semantic"]["terminal"])
        self.assertEqual(
            [
                leg["state"]
                for leg in reply["transport"]
                if leg["state"] != "author-retained"
            ],
            ["recipient-intake"],
        )
        for group in self.groups:
            self.assertFalse(
                any(
                    "El transporte rechazó" in request["text"]
                    for request in group.egress._transport.requests
                )
            )
        received = sender.page(after=0, limit=10)[0]["message"]
        self.assertEqual(
            received["payload"]["body"]["response_context"]["message_id"],
            first["message_id"],
        )
        # One visible speech obligation, irrespective of repeated HTTP copies.
        messages = [
            request
            for request in sender.egress._transport.requests
            if "one group message" in request["text"]
        ]
        self.assertEqual(len(messages), 1)
        sender.egress.validate_registered_catalogs()
        receiver.egress.validate_registered_catalogs()
        self.fixture.now += 60_000
        with patch.object(
            sender, "_transmit", side_effect=AssertionError("expired I/O")
        ):
            expired = self.send_and_settle(
                sender,
                client_id="test",
                send_id=send_id,
                thread_id=thread_id,
                text="one group message",
            )
        self.assertTrue(expired["carrier"]["expired"])
        self.assertEqual(expired["semantic"], first["semantic"])
        self.assertEqual(sender.inspect(client_id="test", send_id=send_id), expired)

    def test_route_removal_preserves_recorded_ack_and_signed_receipt(self):
        sender, receiver = self.groups
        send_id = str(uuid.uuid4())
        first = self.send_and_settle(
            sender,
            client_id="test",
            send_id=send_id,
            thread_id=str(uuid.uuid4()),
            text="recorded receiving proof",
        )
        sender.providers.clear()
        with patch.object(sender, "_transmit", side_effect=AssertionError("read I/O")):
            retained = sender.inspect(client_id="test", send_id=send_id)
        remote = next(
            row
            for row in retained["transport"]
            if row["being_ref"] == receiver.lane.being_ref
        )
        self.assertEqual(remote["state"], "recipient-intake")
        self.assertEqual(remote["attempt_state"], "recipient-intake")
        self.assertEqual(remote["current_route"], "unavailable")
        self.assertTrue(remote["response_sha256"])
        self.assertEqual(retained["semantic"], first["semantic"])
        self.assertEqual(retained["members"], first["members"])

    def test_late_receipt_improves_unknown_after_expiry_without_retransmission(self):
        sender, receiver = self.groups
        request = dict(
            client_id="test",
            send_id=str(uuid.uuid4()),
            thread_id=str(uuid.uuid4()),
            text="receipt return is unavailable",
        )
        with patch.object(receiver, "_transmit"):
            first = self.send_and_settle(sender, **request)
        remote = next(
            row
            for row in first["transport"]
            if row["being_ref"] == receiver.lane.being_ref
        )
        self.assertEqual(remote["state"], "recipient-intake")
        self.assertFalse(first["semantic"]["terminal"])
        self.assertTrue(all(m["receiving_copy"] == "unknown" for m in first["members"]))
        self.fixture.now += 60_000
        with patch.object(
            sender, "_transmit", side_effect=AssertionError("expired I/O")
        ):
            expired = self.send_and_settle(sender, **request)
            self.assertTrue(expired["carrier"]["expired"])
            self.assertEqual(expired["semantic"], first["semantic"])
            receipt = receiver.records.get("receipt", first["message_id"])
            sender.receive_evidence(canonical_bytes(receipt))
            late = self.send_and_settle(sender, **request)
        self.assertTrue(late["semantic"]["terminal"])
        self.assertTrue(late["carrier"]["expired"])
        self.assertEqual(late["audience"], first["audience"])
        self.assertEqual(late["message_id"], first["message_id"])
        member = next(
            m for m in late["members"] if m["being_ref"] == receiver.lane.being_ref
        )
        self.assertEqual(member["receiving_copy"], "proved")
        self.assertEqual(len(receiver.page(after=0, limit=10)), 1)

    def test_expired_unroutable_leg_is_not_a_semantic_nondelivery_receipt(self):
        sender, receiver = self.groups
        sender.providers.clear()
        request = dict(
            client_id="test",
            send_id=str(uuid.uuid4()),
            thread_id=str(uuid.uuid4()),
            text="offline route",
        )
        first = self.send_and_settle(sender, **request)
        self.fixture.now += 60_000
        with patch.object(
            sender, "_transmit", side_effect=AssertionError("expired I/O")
        ):
            expired = self.send_and_settle(sender, **request)
        self.assertEqual(expired["semantic"], first["semantic"])
        self.assertFalse(expired["semantic"]["terminal"])
        member = next(
            m for m in expired["members"] if m["being_ref"] == receiver.lane.being_ref
        )
        self.assertEqual(member["receiving_copy"], "unknown")
        remote = next(
            t for t in expired["transport"] if t["being_ref"] == receiver.lane.being_ref
        )
        self.assertEqual(remote["attempt_state"], "not-attempted")
        self.assertEqual(remote["current_route"], "unavailable")
        self.assertEqual(receiver.page(after=0, limit=10), [])

    def test_persistence_failure_cannot_sign_receipt(self):
        prepared = self.fixture.sender_lane.prepare(
            text="not stored",
            request_id=str(uuid.uuid4()),
            tribe_ref=self.fixture.tribe_ref,
        )
        receiver = self.fixture.receiver_lane
        with (
            patch.object(receiver.records, "received", side_effect=OSError("disk")),
            patch.object(receiver, "_author_receipt") as author,
            self.assertRaises(OSError),
        ):
            receiver.intake(prepared["payload"])
        author.assert_not_called()

    def test_interrupted_visibility_admission_does_not_strand_native_carrier(self):
        sender = self.groups[0]
        request = {
            "client_id": "test",
            "send_id": str(uuid.uuid4()),
            "thread_id": str(uuid.uuid4()),
            "text": "recover the exact group operation",
        }
        with (
            patch.object(sender.egress, "admit_in_transaction", side_effect=OSError),
            self.assertRaises(OSError),
        ):
            self.send_and_settle(sender, **request)
        self.assertIsNone(sender.records.get("native", request["send_id"]))
        sender.egress.validate_registered_catalogs()
        result = self.send_and_settle(sender, **request)
        self.assertTrue(result["semantic"]["terminal"])
        sender.egress.validate_registered_catalogs()

    def test_restart_uses_byte_identical_frozen_envelope(self):
        lane = self.fixture.sender_lane
        params = dict(
            text="durable",
            request_id=str(uuid.uuid4()),
            tribe_ref=self.fixture.tribe_ref,
        )
        original = lane.prepare(**params)
        restarted = self.fixture.lane_for(
            "founder",
            self.fixture.founder_ledger,
            self.fixture.sender_custody,
            self.fixture.journey.store,
        )
        self.fixture.now += 100
        with patch.object(
            restarted, "snapshot", side_effect=AssertionError("resolved")
        ):
            self.assertEqual(
                canonical_bytes(restarted.prepare(**params)), canonical_bytes(original)
            )

    def test_group_only_application_uses_supported_signed_provisioning(self):
        import hashlib

        from daimon_matrix.messaging_config import (
            APPLICATION_SCHEMA_V3,
            GROUP_STORE_NAMES,
            load_application,
            validate_shape,
        )
        from daimon_matrix.operator_messaging import prepare
        from daimon_matrix.relationship_store import (
            RelationshipServiceContext,
            RelationshipStore,
        )
        from tests.test_messaging_runtime import loaded, public_document

        fixture = self.fixture
        _runtime_fixture, runtime, _reads = loaded(
            self, fixture.founder, clock=lambda: fixture.now
        )
        relationships = RelationshipStore(
            runtime.state_root / "relationships.sqlite",
            authority_resolver=fixture.sender_lane.authority_resolver,
        )
        for event in fixture.events:
            relationships.ingest(event)
        runtime.service.communication.upgrade_receipts_v2()
        runtime.service.communication.upgrade_legs_v3()
        runtime = replace(
            runtime,
            service=replace(
                runtime.service,
                relationships=RelationshipServiceContext(
                    relationships,
                    fixture.journey.card_verifier,
                    fixture.sender_lane.authority_resolver,
                ),
            ),
        )
        port = 48765
        sources, roster = {}, []
        directory = runtime.state_root.parent
        for index, identity in enumerate((fixture.founder, fixture.member)):
            path = directory / f"group-body-{index}.key"
            path.write_bytes(bytes([index + 1]) * 32)
            path.chmod(0o600)
            sources[path.name] = path
            roster.append(
                {
                    "being_ref": identity.state.being_ref,
                    "embodiment_id": identity.origin["embodiment_id"],
                    "body_ref": identity.origin["body_ref"],
                    "route": {
                        "provider_ref": f"body-{index}",
                        "route_ref": f"body-{index}",
                        "key_ref": f"body-{index}",
                        "endpoint": (
                            f"http://127.0.0.1:{port + index}/dm-messaging/v1/message"
                        ),
                        "secret_file": path.name,
                        "secret_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                    },
                }
            )
        spec = {
            "schema": APPLICATION_SCHEMA_V3,
            "listen": {"host": "127.0.0.1", "port": port},
            "authorities": [
                public_document(fixture.founder, "founder"),
                public_document(fixture.member, "member"),
            ],
            "relationship_events": fixture.events,
            "relationship_mode": {
                "mode": "shared",
                "runtime_id": runtime.service.runtime_id,
                "state_root": str(runtime.state_root),
                "store_filename": relationships.path.name,
            },
            "tribe": {
                "channel_id": "tribe",
                "policy": {
                    "tribe_ref": fixture.tribe_ref,
                    "membership_ref": fixture.declaration["event_id"],
                    "classification": "shareable",
                    "max_ttl_ms": 60000,
                },
            },
            "intake": roster[0]["route"],
            "roster": roster,
            "stores": {name: name + ".sqlite" for name in GROUP_STORE_NAMES},
        }
        validate_shape(spec, specification=True)
        app = directory / "group-application"
        prepare(runtime, app, spec, secret_sources=sources)
        view = load_application(runtime, app)
        self.assertEqual(set(view.service.messaging.channels), {"tribe"})
        self.assertIsInstance(view.service.messaging.channels["tribe"], GroupMessaging)
        self.assertIs(
            view.service._messaging_context(startup=True), view.service.messaging
        )
        self.assertNotIn("incoming", spec)
        self.assertNotIn("outgoing", spec)
        import sqlite3

        group = view.service.messaging.channels["tribe"]
        request_id, moved_id = str(uuid.uuid4()), str(uuid.uuid4())
        document = {"client_id": "test", "text": "signed record"}
        group.records.reserve("request", request_id, document, lambda: document)
        with closing(sqlite3.connect(group.records.path)) as database, database:
            database.execute(
                "UPDATE tribe_records SET record_id=? WHERE record_id=?",
                (moved_id, request_id),
            )
        with self.assertRaisesRegex(ValueError, "messaging_binding_rejected"):
            group.records.get("request", moved_id)


class DurableIntakeStoreTests(unittest.TestCase):
    """Exercise local transaction boundaries without a live body or transport."""

    def setUp(self):
        import tempfile

        from daimon_matrix.messaging_store import TribeRecordStore

        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.now = 1000
        self.records = TribeRecordStore(
            Path(temporary.name) / "intake.sqlite", clock=lambda: self.now
        )
        self.message = {"event_id": str(uuid.uuid4()), "content_hash": "1" * 64}
        self.resolution = {"event_id": str(uuid.uuid4()), "content_hash": "2" * 64}
        self.request_id = str(uuid.uuid4())
        self.admission = {"request": {"expires_at_ms": 2000}, "request_hash": "3" * 64}

    def commit(self, **changes):
        def obligation(first, legacy):
            self.assertFalse(legacy)
            return {"observed_at_ms": first, "deadline_ms": first + 60_000}

        arguments = {
            "request_id": self.request_id,
            "admission": self.admission,
            "message": self.message,
            "resolution": self.resolution,
            "acceptance": lambda now: None,
            "obligation": obligation,
            "max_pending": 1,
        }
        arguments.update(changes)
        return self.records.commit_intake(**arguments)

    def test_exact_retry_preserves_first_commit_and_obligation(self):
        first = self.commit()
        obligation = self.records.get("receipt-obligation", self.message["event_id"])
        self.now = 90_000
        with patch.object(
            self.records, "_reserve_in_transaction", side_effect=AssertionError
        ):
            replay = self.commit()
        self.assertEqual(first, replay)
        self.assertEqual(first["received_at_ms"], 1000)
        self.assertEqual(
            self.records.get("receipt-obligation", self.message["event_id"]), obligation
        )
        self.assertEqual(obligation["deadline_ms"], 61_000)

    def test_expiry_without_retained_terminal_does_not_release_capacity(self):
        from daimon_matrix.messaging_store import TribeControlCapacityError

        self.commit()
        self.now = 90_000
        other = {"event_id": str(uuid.uuid4()), "content_hash": "4" * 64}
        request = str(uuid.uuid4())
        with self.assertRaises(TribeControlCapacityError):
            self.commit(request_id=request, message=other)
        self.assertIsNone(self.records.get("inbox", other["event_id"]))
        self.assertIsNone(self.records.get("intake-admission", request))

    def test_failure_after_readable_insert_rolls_back_all_three_records(self):
        reserve = self.records._reserve_in_transaction

        def fail_admission(database, kind, identifier, digest, factory):
            if kind == "intake-admission":
                raise OSError("synthetic storage failure")
            return reserve(database, kind, identifier, digest, factory)

        with (
            patch.object(
                self.records, "_reserve_in_transaction", side_effect=fail_admission
            ),
            self.assertRaises(OSError),
        ):
            self.commit()
        for kind, identifier in (
            ("inbox", self.message["event_id"]),
            ("receipt-obligation", self.message["event_id"]),
            ("intake-admission", self.request_id),
        ):
            self.assertIsNone(self.records.get(kind, identifier))
        self.assertEqual(self.commit()["received_at_ms"], self.now)

    def test_commit_boundary_rechecks_authorization_before_any_record(self):
        def revoked(now):
            self.assertEqual(now, self.now)
            raise ValueError("synthetic revoked authority")

        with self.assertRaisesRegex(ValueError, "revoked authority"):
            self.commit(acceptance=revoked)
        self.assertIsNone(self.records.get("inbox", self.message["event_id"]))
        self.assertIsNone(
            self.records.get("receipt-obligation", self.message["event_id"])
        )
        self.assertIsNone(self.records.get("intake-admission", self.request_id))

    def test_changed_request_bytes_do_not_replace_committed_intake(self):
        first = self.commit()
        with self.assertRaisesRegex(ValueError, "tribe_record_request_conflict"):
            self.commit(admission={**self.admission, "request_hash": "5" * 64})
        self.assertEqual(self.records.get("intake-admission", self.request_id), first)

    def test_control_reserve_is_available_when_message_pool_is_full(self):
        from daimon_matrix.messaging_store import TribeControlCapacityError

        self.commit()
        identifier = str(uuid.uuid4())
        proof = {"receipt": "synthetic"}
        admission = {"phase": "evidence", "control_sha256": "4" * 64}
        accepted = self.records.commit_control(
            request_id=identifier,
            admission=admission,
            proof=proof,
            acceptance=lambda now: None,
            max_pending=1,
        )
        self.assertEqual(accepted["received_at_ms"], self.now)
        with self.assertRaises(TribeControlCapacityError):
            self.records.commit_control(
                request_id=str(uuid.uuid4()),
                admission=admission,
                proof=proof,
                acceptance=lambda now: None,
                max_pending=1,
            )

    def test_unrelated_completion_cannot_release_capacity(self):
        from daimon_matrix.canonical import b64url
        from daimon_matrix.messaging_store import TribeControlCapacityError

        self.commit()
        false_ack = {
            "admission_sha256": "0" * 64,
            "response": b64url(
                canonical_bytes({"status": "accepted", "outcome": "recipient-intake"})
            ),
        }
        self.records.reserve(
            "intake-ack", self.request_id, false_ack, lambda: false_ack
        )
        with self.assertRaises(TribeControlCapacityError):
            self.commit(
                request_id=str(uuid.uuid4()), message={"event_id": str(uuid.uuid4())}
            )

    def test_forged_completion_with_matching_hash_cannot_release_capacity(self):
        import hashlib
        import hmac
        import sqlite3

        from daimon_matrix.canonical import b64url

        key = b"synthetic completion verification key"

        def sign(value):
            return {"mac": hmac.digest(key, canonical_bytes(value), "sha256").hex()}

        def verify(value, signature):
            if not hmac.compare_digest(sign(value)["mac"], signature["mac"]):
                raise ValueError("synthetic completion signature invalid")

        self.records.sign, self.records.verify = sign, verify
        admission = self.commit()
        document = {
            "admission_sha256": hashlib.sha256(canonical_bytes(admission)).hexdigest(),
            "response": b64url(
                canonical_bytes({"status": "accepted", "outcome": "recipient-intake"})
            ),
        }
        self.records.reserve("intake-ack", self.request_id, document, lambda: document)
        # Preserve the signed binding while replacing both plaintext and its
        # untrusted checksum. Only signature validation detects this substitution.
        changed = {**document, "extra": True}
        raw = canonical_bytes(changed)
        with closing(sqlite3.connect(self.records.path)) as database, database:
            database.execute(
                "UPDATE tribe_records SET document=?,document_hash=? "
                "WHERE kind='intake-ack' AND record_id=?",
                (raw, hashlib.sha256(raw).hexdigest(), self.request_id),
            )
        with self.assertRaisesRegex(ValueError, "completion signature invalid"):
            self.commit(
                request_id=str(uuid.uuid4()), message={"event_id": str(uuid.uuid4())}
            )

    def test_scan_budget_precedes_large_admission_decode(self):
        import time

        self.commit()
        with patch.object(
            self.records, "_checked", side_effect=AssertionError("unbudgeted decode")
        ):
            limited = self.records.intake_page(max_bytes=1)
            expired = self.records.intake_page(deadline_ns=time.monotonic_ns() - 1)
        for page in (limited, expired):
            self.assertEqual(page["items"], [])
            self.assertTrue(page["has_more"])
            self.assertEqual(page["next_after"], 0)

    def test_concurrent_duplicates_share_one_durable_first_observation(self):
        import sqlite3
        from concurrent.futures import ThreadPoolExecutor

        with ThreadPoolExecutor(max_workers=3) as workers:
            values = list(workers.map(lambda _: self.commit(), range(3)))
        self.assertTrue(all(value == values[0] for value in values))
        with closing(sqlite3.connect(self.records.path)) as database:
            self.assertEqual(
                database.execute("SELECT count(*) FROM tribe_records").fetchone()[0], 3
            )


if __name__ == "__main__":
    unittest.main()
