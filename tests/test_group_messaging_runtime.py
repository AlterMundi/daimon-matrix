"""Membership group integration over the existing authenticated HTTP transport."""

from __future__ import annotations

import threading
import time
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
    NativeEgressError,
    synthetic_visibility,
)
from daimon_matrix.routes import DirectHTTPProvider, OpaqueInbox, TransportIngress
from tests import test_dm051_sealed as sealing_fixtures


class DirectLaneTests(unittest.TestCase):
    def setUp(self):
        self.fixture = sealing_fixtures.TribeConversationLaneTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def prepare(self, **changes):
        f = self.fixture
        return f.sender_lane.prepare(
            text="explicit member direct",
            request_id=str(uuid.uuid4()),
            tribe_ref=f.tribe_ref,
            destination={"kind": "being", "being_ref": f.member.state.being_ref},
            **changes,
        )

    def test_direct_has_only_recipient_keys_and_author_retains_its_ledger_event(self):
        from daimon_matrix.tribe_conversation import TRIBE_DIRECT_SCHEMA

        f = self.fixture
        prepared = self.prepare()
        self.assertEqual(prepared["payload"]["schema"], TRIBE_DIRECT_SCHEMA)
        self.assertEqual(
            [row["being_ref"] for row in prepared["rows"]], [f.member.state.being_ref]
        )
        self.assertIsNotNone(f.founder_ledger.event(prepared["message"]["event_id"]))
        validated = f.receiver_lane.validate_intake(prepared["payload"])
        self.assertEqual(validated.message, prepared["message"])
        self.assertEqual(
            prepared["message"]["payload"]["body"]["destination"][
                "authority_manifest_hash"
            ],
            f.member.authority.manifest.digest,
        )

    def test_explicit_body_direct_receives_signed_receipt_without_author_semantic_copy(
        self,
    ):
        f = self.fixture
        result = f.sender_lane.converse(
            text="one selected body",
            request_id=str(uuid.uuid4()),
            tribe_ref=f.tribe_ref,
            destination={
                "kind": "body",
                "being_ref": f.member.state.being_ref,
                "embodiment_id": f.member.origin["embodiment_id"],
            },
            deliver=lambda _body, payload: f.receiver_lane.intake(payload),
        )
        self.assertEqual(len(result["deliveries"]), 1)
        self.assertEqual(result["deliveries"][0]["state"], "delivered")

    def test_direct_cannot_be_relabelled_as_old_group_wire(self):
        from daimon_matrix.tribe_conversation import (
            TRIBE_CONVERSATION_SCHEMA,
            open_event,
        )

        prepared = self.prepare()
        prepared["payload"]["schema"] = TRIBE_CONVERSATION_SCHEMA
        with patch(
            "daimon_matrix.tribe_conversation.open_event", wraps=open_event
        ) as decrypted:
            with self.assertRaises(ValueError):
                self.fixture.receiver_lane.validate_intake(prepared["payload"])
            # The old complete-membership proof map must reject the omitted
            # author before touching recipient keys, not after decryption.
            decrypted.assert_not_called()

    def enroll_second_member_body(self, label="member"):
        import copy

        from daimon_matrix.authority_epochs import (
            RootHistoryAuthority,
            create_embodiment_enrollment,
        )
        from daimon_matrix.identity import (
            create_embodiment_credential,
            create_incarnation_authorization,
            x25519_public,
        )
        from daimon_matrix.synthetic_relationships import _seed, _transport
        from daimon_matrix.weave import BeingManifest, RootAuthority

        f = self.fixture
        old = f.journey.identities[label].authority
        roots = tuple(_seed(f"{label}:root:{index}") for index in range(3))
        signing = _seed(f"{label}-second:signing")
        origin = dict(
            body_ref=f"codex:synthetic:{label}-second",
            embodiment_id=f"embodiment:{label}-second",
            incarnation_id=f"incarnation:{label}-second:0",
            principal_id=f"{label}-second@loopback",
        )
        credential = create_embodiment_credential(
            old.state,
            roots,
            signing,
            x25519_public(_seed(f"{label}-second:encryption")),
            embodiment_id=origin["embodiment_id"],
            body_ref=origin["body_ref"],
            purposes=["dm.we", "messages"],
            valid_from_ms=0,
            valid_until_ms=2**53 - 1,
            transport_principals=[
                {
                    **_transport(f"{label}-second", origin["principal_id"]),
                    "scheme": "dm-peer-v1",
                }
            ],
        )
        incarnation = create_incarnation_authorization(
            credential,
            signing,
            incarnation_id=origin["incarnation_id"],
            incarnation_sequence=0,
            started_at_ms=0,
        )
        manifest = copy.deepcopy(old.manifest.value)
        manifest["revision"] += 1
        manifest["embodiments"].append(
            dict(
                body_ref=origin["body_ref"],
                embodiment_id=origin["embodiment_id"],
                incarnation_id=origin["incarnation_id"],
                status="active",
                embodiment_credential_id=credential["artifact_id"],
                incarnation_authorization_id=incarnation["artifact_id"],
            )
        )
        manifest["embodiments"].sort(
            key=lambda row: (row["embodiment_id"], row["incarnation_id"])
        )
        current = RootAuthority(
            BeingManifest.from_value(manifest),
            old.state,
            {**old.credentials, credential["artifact_id"]: credential},
            {**old.incarnations, incarnation["artifact_id"]: incarnation},
        )
        enrollment = create_embodiment_enrollment(
            old.manifest,
            current.manifest,
            root_seeds=roots,
            request_id=str(uuid.uuid4()),
            body_ref=origin["body_ref"],
            embodiment_id=origin["embodiment_id"],
            incarnation_id=origin["incarnation_id"],
            embodiment_credential_id=credential["artifact_id"],
            incarnation_authorization_id=incarnation["artifact_id"],
            principal_id=origin["principal_id"],
            issued_at_ms=f.now,
        )
        f.journey.authorities[old.state.being_ref] = RootHistoryAuthority(
            current, [old], [enrollment]
        )
        return current, origin

    def test_group_with_bodyless_active_member_retains_complete_membership_proofs(self):
        import copy

        from daimon_matrix.authority_epochs import (
            RootHistoryAuthority,
            create_embodiment_retirement,
        )
        from daimon_matrix.identity import create_revocation, verify_successor
        from daimon_matrix.synthetic_relationships import _seed
        from daimon_matrix.weave import BeingManifest, RootAuthority

        f = self.fixture
        # A sibling permits group preparation even when the other being has
        # retired its last body. Signed membership itself remains active.
        self.enroll_second_member_body("founder")
        old = f.member.authority
        roots = tuple(_seed(f"member:root:{index}") for index in range(3))
        control = create_revocation(
            old.state,
            roots,
            embodiment_id=f.member.origin["embodiment_id"],
            cutoff_incarnation_sequence=0,
            revocation_generation=1,
        )
        state = verify_successor(control, old.state)
        manifest = copy.deepcopy(old.manifest.value)
        manifest.update(control_head=state.head, revision=manifest["revision"] + 1)
        for row in manifest["embodiments"]:
            row["status"] = "retired"
        current = RootAuthority(
            BeingManifest.from_value(manifest), state, old.credentials, old.incarnations
        )
        transition = create_embodiment_retirement(
            old.manifest,
            current.manifest,
            revocations=[control],
            root_seeds=roots,
            issued_at_ms=f.now,
        )
        f.journey.authorities[old.state.being_ref] = RootHistoryAuthority(
            current, [old], [transition]
        )
        # Preserve the v1 sealing contract: a proof without any recipient body
        # rejects preparation, rather than emitting a frame its reader rejects.
        request_id = str(uuid.uuid4())
        with self.assertRaises(ValueError):
            f.sender_lane.prepare(
                text="bodyless member cannot be silently omitted",
                request_id=request_id,
                tribe_ref=f.tribe_ref,
            )
        self.assertIsNone(f.sender_lane.records.get("native", request_id))

    def test_retry_retains_original_root_audience_and_next_direct_selects_new_bodies(
        self,
    ):
        f = self.fixture
        arguments = dict(
            text="freeze before extra body",
            request_id=str(uuid.uuid4()),
            tribe_ref=f.tribe_ref,
            destination={"kind": "being", "being_ref": f.member.state.being_ref},
        )
        previous = f.sender_lane.prepare(**arguments)
        current, origin = self.enroll_second_member_body()
        f.now += 1
        retried = f.sender_lane.prepare(**arguments)
        self.assertEqual(retried, previous)
        self.assertEqual(
            f.receiver_lane.validate_intake(retried["payload"]).message,
            previous["message"],
        )
        next_message = f.sender_lane.prepare(
            **{**arguments, "request_id": str(uuid.uuid4())}
        )
        self.assertEqual(
            {row["embodiment_id"] for row in next_message["rows"]},
            {f.member.origin["embodiment_id"], origin["embodiment_id"]},
        )
        self.assertEqual(
            next_message["message"]["payload"]["body"]["destination"][
                "authority_manifest_hash"
            ],
            current.manifest.digest,
        )
        self.assertEqual(
            f.receiver_lane.validate_intake(next_message["payload"]).message,
            next_message["message"],
        )
        selected = f.sender_lane.prepare(
            **{
                **arguments,
                "request_id": str(uuid.uuid4()),
                "destination": {
                    "kind": "body",
                    "being_ref": f.member.state.being_ref,
                    "embodiment_id": origin["embodiment_id"],
                },
            }
        )
        self.assertEqual(
            [row["embodiment_id"] for row in selected["rows"]],
            [origin["embodiment_id"]],
        )


class GroupRuntimeTests(unittest.TestCase):
    def test_group_mention_and_connected_reply_show_one_logical_destination(self):
        from daimon_matrix.telegram_mirror import render_readable_parts

        sender, receiver = self.groups
        arguments = dict(
            client_id="test",
            send_id=str(uuid.uuid4()),
            thread_id=str(uuid.uuid4()),
            text="hello @member, this is visible to the group",
        )
        first = self.send_and_settle(sender, **arguments)
        native = sender.records.get("native", arguments["send_id"])
        self.assertEqual(native["projection"]["recipients"], ["Tribu"])
        self.assertTrue(
            render_readable_parts(native["projection"])[0]
            .splitlines()[0]
            .endswith(" → Tribu")
        )
        expected = {sender.lane.being_ref, receiver.lane.being_ref}
        self.assertEqual({row["being_ref"] for row in first["audience"]}, expected)
        self.assertTrue(first["semantic"]["terminal"])
        reply_id = str(uuid.uuid4())
        response = self.send_and_settle(
            receiver,
            client_id="test",
            send_id=reply_id,
            thread_id=arguments["thread_id"],
            text="connected group response",
            response_to=(receiver, first["message_id"]),
        )
        reply_projection = receiver.records.get("native", reply_id)["projection"]
        self.assertEqual(reply_projection["recipients"], ["Tribu"])
        self.assertEqual(reply_projection["reply_to"]["event_id"], first["message_id"])
        self.assertEqual({row["being_ref"] for row in response["audience"]}, expected)
        self.assertTrue(response["semantic"]["terminal"])

    def test_exact_group_retry_preserves_predecessor_projection_and_frozen_audience(
        self,
    ):
        sender = self.groups[0]
        arguments = dict(
            client_id="test",
            send_id=str(uuid.uuid4()),
            thread_id=str(uuid.uuid4()),
            text="retained predecessor group publication",
        )
        original_admit = sender.records.admit
        old_recipients = ["historical founder body", "historical member body"]

        def predecessor_admit(*args, **kwargs):
            # Owner-local fixture: mint the old producer's projection through
            # the real native/echo transaction before running the new retry.
            if kwargs.get("path_id") == "tribe-message-request":
                kwargs["projection"] = {
                    **kwargs["projection"],
                    "recipients": old_recipients,
                }
            return original_admit(*args, **kwargs)

        with patch.object(sender.records, "admit", side_effect=predecessor_admit):
            first = self.send_and_settle(sender, **arguments)
        native = sender.records.get("native", arguments["send_id"])
        self.assertEqual(native["projection"]["recipients"], old_recipients)
        pages = [group.page(after=0, limit=10) for group in self.groups]
        retried = self.send_and_settle(sender, **arguments)
        self.assertEqual(retried["message_id"], first["message_id"])
        self.assertEqual(retried["audience"], first["audience"])
        self.assertTrue(retried["semantic"]["terminal"])
        self.assertEqual(sender.records.get("native", arguments["send_id"]), native)
        self.assertEqual(
            [group.page(after=0, limit=10) for group in self.groups], pages
        )

    def test_direct_catalog_reopen_and_migration_preserve_native_echo_and_ack(self):
        sender, receiver = self.groups
        sender.direct_reader_ready = lambda row: True
        delivered = self.direct_arguments(sender, receiver)
        result = self.send_and_settle(sender, **delivered)
        self.assertTrue(result["semantic"]["terminal"])
        sender.direct_reader_ready = None
        blocked = self.direct_arguments(sender, receiver)
        denied = self.send_and_settle(sender, **blocked)
        self.assertEqual(denied["transport"][0]["attempt_state"], "not-attempted")
        retained = {
            arguments["send_id"]: (
                sender.records.get("native", arguments["send_id"]),
                sender.inspect(client_id="test", send_id=arguments["send_id"]),
            )
            for arguments in (delivered, blocked)
        }
        for mode in ("validate", "migrate"):
            with self.subTest(mode=mode):
                lane = self.fixture.lane_for(
                    "founder",
                    self.fixture.founder_ledger,
                    self.fixture.sender_custody,
                    self.fixture.journey.store,
                )
                lane.records.clock = lane.clock
                controller = MandatoryEgressController(
                    policy=sender.egress._policy,
                    proof_key=sender.egress._proof_key,
                    transport=sender.egress._transport,
                    clock=lane.clock,
                    catalog_mode=mode,
                )
                reopened = GroupMessaging(
                    lane=lane,
                    policy=sender.policy,
                    communication=sender.communication,
                    providers=sender.providers,
                    config_digest=sender.config_digest,
                    egress=controller,
                )
                if mode == "migrate":
                    controller.migrate_registered_catalogs(
                        version=VISIBILITY_SCHEMA_VERSION
                    )
                controller.validate_registered_catalogs()
                controller.validate_registry(
                    {"tribe-message-request", "tribe-receipt-request"}
                )
                for send_id, (native, evidence) in retained.items():
                    self.assertEqual(reopened.records.get("native", send_id), native)
                    self.assertEqual(
                        reopened.inspect(client_id="test", send_id=send_id), evidence
                    )

    def test_owner_service_forwards_typed_direct_and_rejects_null_or_nongroup_lane(
        self,
    ):
        from types import SimpleNamespace
        from unittest.mock import Mock

        from daimon_matrix.service import HostedWeave, ServiceError

        sender, receiver = self.groups
        sender.direct_reader_ready = lambda row: True
        context = SimpleNamespace(
            client_channels={"test": frozenset({"tribe"})}, deliveries={"tribe": sender}
        )
        service = SimpleNamespace(
            _messaging_context=lambda: context,
            _messaging_guard=lambda *args: lambda: None,
        )
        arguments = {**self.direct_arguments(sender, receiver), "channel_id": "tribe"}
        arguments.pop("client_id")
        result = HostedWeave._messaging_send(service, arguments, client_id="test")
        for server in [*self.servers, self.servers[0]]:
            server._threads.join()
        result = sender.inspect(client_id="test", send_id=result["send_id"])
        self.assertTrue(result["semantic"]["terminal"])
        self.assertEqual(
            [row["being_ref"] for row in result["audience"]], [receiver.lane.being_ref]
        )
        count = len(sender.ledger.events())
        with self.assertRaises(ServiceError):
            HostedWeave._messaging_send(
                service,
                {**arguments, "send_id": str(uuid.uuid4()), "destination": None},
                client_id="test",
            )
        self.assertEqual(len(sender.ledger.events()), count)
        other = SimpleNamespace(send=Mock())
        context.deliveries["tribe"] = other
        with self.assertRaises(ServiceError):
            HostedWeave._messaging_send(service, arguments, client_id="test")
        other.send.assert_not_called()

    def direct_arguments(self, sender, receiver, *, kind="being", **changes):
        destination = {"kind": kind, "being_ref": receiver.lane.being_ref}
        if kind == "body":
            destination["embodiment_id"] = receiver.lane.local_embodiment_id
        return dict(
            client_id="test",
            send_id=str(uuid.uuid4()),
            thread_id=str(uuid.uuid4()),
            text="explicit direct over the enrolled shared carrier",
            destination=destination,
            **changes,
        )

    def test_direct_default_denies_unknown_reader_without_losing_frozen_leg_or_echo(
        self,
    ):
        sender, receiver = self.groups
        arguments = self.direct_arguments(sender, receiver)
        blocked = self.send_and_settle(sender, **arguments)
        self.assertEqual(blocked["schema"], "dm.tribe.direct-delivery/v1")
        self.assertEqual(len(blocked["audience"]), 1)
        self.assertEqual(blocked["transport"][0]["attempt_state"], "not-attempted")
        self.assertFalse(blocked["transport"][0]["reader_readiness"])
        self.assertEqual(receiver.page(after=0, limit=10), [])
        native = sender.records.get("native", arguments["send_id"])
        self.assertEqual(
            native["projection"]["recipients"], ["Direct · " + receiver.lane.being_ref]
        )
        sender.direct_reader_ready = lambda row: (
            row["being_ref"] == receiver.lane.being_ref
        )
        delivered = self.send_and_settle(sender, **arguments)
        self.assertEqual(delivered["message_id"], blocked["message_id"])
        self.assertEqual(delivered["audience"], blocked["audience"])
        self.assertEqual(sender.records.get("native", arguments["send_id"]), native)
        self.assertTrue(delivered["semantic"]["terminal"])
        self.assertEqual(delivered["semantic"]["legs"][0]["state"], "delivered")
        self.assertEqual(delivered["author_retention"]["state"], "authored-local")
        self.assertEqual(sender.page(after=0, limit=10), [])
        sender.direct_reader_ready = None
        historical = self.send_and_settle(sender, **arguments)
        self.assertEqual(
            historical["transport"][0]["attempt_state"], "recipient-intake"
        )
        self.assertFalse(historical["transport"][0]["reader_readiness"])
        self.assertEqual(len(receiver.page(after=0, limit=10)), 1)

    def test_direct_reader_invalidation_at_actual_write_retains_uncertain_attempt(self):
        sender, receiver = self.groups
        sender.direct_reader_ready = lambda row: True
        provider = sender.providers[
            (receiver.lane.being_ref, receiver.lane.local_embodiment_id)
        ]["message"]
        round_trip = provider._round_trip
        original = round_trip.bounded_open

        def withdraw_after_connect(deadline):
            exchange = original(deadline)
            sender.direct_reader_ready = None
            return exchange

        provider._round_trip = replace(round_trip, bounded_open=withdraw_after_connect)
        arguments = self.direct_arguments(sender, receiver)
        result = self.send_and_settle(sender, **arguments)
        self.assertEqual(receiver.page(after=0, limit=10), [])
        self.assertEqual(result["transport"][0]["attempt_state"], "unconfirmed")
        self.assertFalse(result["transport"][0]["reader_readiness"])
        provider._round_trip = round_trip
        sender.direct_reader_ready = lambda row: True
        retried = self.send_and_settle(sender, **arguments)
        self.assertEqual(retried["message_id"], result["message_id"])
        self.assertTrue(retried["semantic"]["terminal"])

    def test_direct_cannot_use_legacy_opaque_provider_to_bypass_the_write_guard(self):
        sender, receiver = self.groups
        sender.direct_reader_ready = lambda row: True
        provider = sender.providers[
            (receiver.lane.being_ref, receiver.lane.local_embodiment_id)
        ]["message"]
        with patch.object(provider, "_round_trip") as opaque:
            result = self.send_and_settle(
                sender, **self.direct_arguments(sender, receiver)
            )
            opaque.assert_not_called()
        self.assertEqual(receiver.page(after=0, limit=10), [])
        self.assertEqual(result["transport"][0]["attempt_state"], "unconfirmed")
        self.assertFalse(result["semantic"]["terminal"])

    def test_body_direct_reply_targets_parent_author_without_quote_or_broadcast(self):
        sender, receiver = self.groups
        sender.direct_reader_ready = receiver.direct_reader_ready = lambda row: True
        arguments = self.direct_arguments(sender, receiver, kind="body")
        first = self.send_and_settle(sender, **arguments)
        reply_id = str(uuid.uuid4())
        reply = self.send_and_settle(
            receiver,
            client_id="test",
            send_id=reply_id,
            thread_id=arguments["thread_id"],
            text="direct response",
            response_to=(receiver, first["message_id"]),
        )
        self.assertTrue(reply["semantic"]["terminal"])
        self.assertEqual(reply["destination"]["kind"], "body")
        self.assertEqual(
            reply["destination"]["embodiment_id"], sender.lane.local_embodiment_id
        )
        self.assertEqual(
            [row["being_ref"] for row in reply["audience"]], [sender.lane.being_ref]
        )
        projection = receiver.records.get("native", reply_id)["projection"]
        self.assertNotIn("text", projection["reply_to"])
        self.assertEqual(projection["reply_to"]["event_id"], first["message_id"])

    def test_owned_ack_and_refusal_recheck_authority_before_actual_http_writer(self):
        sender, receiver = self.groups
        ingress = receiver.intake_ingresses["message"]
        original_reply = ingress._owned_reply
        original_authorizer = ingress.egress_authorizer
        handler = self.servers[1].RequestHandlerClass
        completed = []

        def revoke_after_preparation(*arguments, **keywords):
            reply = original_reply(*arguments, **keywords)
            ingress.egress_authorizer = lambda _binding: False

            def completion(deadline):
                completed.append(True)
                if reply.after_response_bounded is not None:
                    reply.after_response_bounded(deadline)
                else:
                    reply.after_response()

            return replace(reply, after_response_bounded=completion)

        for refused in (False, True):
            with self.subTest(refused=refused):
                before = len(receiver.page(after=0, limit=10))
                try:
                    with (
                        patch.object(ingress, "_owned_reply", revoke_after_preparation),
                        patch.object(handler, "_write_response") as actual_writer,
                        patch.object(
                            ingress,
                            "intake_admission",
                            side_effect=ValueError("synthetic pre-effect refusal")
                            if refused
                            else None,
                            wraps=None if refused else ingress.intake_admission,
                        ),
                    ):
                        sender.send(
                            client_id="test",
                            send_id=str(uuid.uuid4()),
                            thread_id=str(uuid.uuid4()),
                            text="actual owned reply authority boundary",
                        )
                        for server in [*self.servers, self.servers[0]]:
                            server._threads.join()
                        actual_writer.assert_not_called()
                finally:
                    ingress.egress_authorizer = original_authorizer
                self.assertEqual(
                    len(receiver.page(after=0, limit=10)),
                    before + (0 if refused else 1),
                )
        self.assertEqual(completed, [True, True])

    def test_authorize_callback_expiry_at_the_fence_emits_no_matrix_bytes(self):
        sender, receiver = self.groups
        checked = []

        def authorize():
            if sender.egress._fence.locked():
                self.fixture.now += 60_000
                checked.append(True)

        result = sender.send(
            client_id="test",
            send_id=str(uuid.uuid4()),
            thread_id=str(uuid.uuid4()),
            text="recheck immutable lifetime after owner authorization",
            authorize=authorize,
        )
        self.assertEqual(checked, [True])
        self.assertTrue(result["carrier"]["expired"])
        for server in self.servers:
            server._threads.join()
        self.assertEqual(receiver.page(after=0, limit=10), [])

    def test_expiry_after_connection_setup_emits_no_matrix_request(self):
        sender, receiver = self.groups
        provider = sender.providers[
            (receiver.lane.being_ref, receiver.lane.local_embodiment_id)
        ]["message"]
        round_trip = provider._round_trip
        original = round_trip.bounded_open
        connected = []

        def connect_then_expire(deadline):
            exchange = original(deadline)
            connected.append(True)
            self.fixture.now += 60_000
            return exchange

        provider._round_trip = replace(round_trip, bounded_open=connect_then_expire)
        result = sender.send(
            client_id="test",
            send_id=str(uuid.uuid4()),
            thread_id=str(uuid.uuid4()),
            text="check authority at the actual write after setup",
        )
        self.assertEqual(connected, [True])
        self.assertTrue(result["carrier"]["expired"])
        for server in self.servers:
            server._threads.join()
        self.assertEqual(receiver.page(after=0, limit=10), [])

    def test_fanout_slow_row_does_not_serialize_healthy_row_and_joins_writers(self):
        _controller, operation, native = self._bounded_write_operation()
        group = self.groups[0]
        rows = [
            {"being_ref": "synthetic:slow", "embodiment_id": "synthetic:slow-body"},
            {"being_ref": "synthetic:fast", "embodiment_id": "synthetic:fast-body"},
        ]
        for row in rows:
            group.providers[(row["being_ref"], row["embodiment_id"])] = {}
        entered, healthy, release, returned = (threading.Event() for _ in range(4))
        seen, errors = [], []

        def transmit(raw, row, binding, **arguments):
            self.assertEqual(raw, native)
            self.assertEqual(binding, operation)
            self.assertFalse(arguments["receipt"])
            seen.append(row["embodiment_id"])
            if row["being_ref"] == "synthetic:slow":
                entered.set()
                if not release.wait(5):
                    raise AssertionError("slow writer release missing")
            else:
                healthy.set()

        def fanout():
            try:
                group._fanout(native, rows, operation, authorize=None)
            except BaseException as failure:
                errors.append(failure)
            finally:
                returned.set()

        with patch.object(group, "_transmit", side_effect=transmit):
            worker = threading.Thread(target=fanout)
            try:
                worker.start()
                self.assertTrue(entered.wait(5))
                self.assertTrue(healthy.wait(5))
                self.assertFalse(returned.is_set())
                # Another exact concurrent call coalesces its active slow row.
                group._fanout(native, rows[:1], operation, authorize=None)
                self.assertEqual(seen.count("synthetic:slow-body"), 1)
            finally:
                release.set()
                worker.join(5)
        self.assertTrue(returned.is_set())
        self.assertFalse(worker.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(group._transport_inflight, set())

    def test_saturated_speech_has_independent_control_admission(self):
        _, operation, _native = self._bounded_write_operation()
        group = self.groups[0]
        rows = [
            {"being_ref": f"synthetic:{i}", "embodiment_id": f"synthetic:body-{i}"}
            for i in range(5)
        ]
        claimed = []
        try:
            for row in rows[:4]:
                self.assertTrue(group._claim_transport(row, operation, receipt=False))
                claimed.append(row)
            self.assertFalse(group._claim_transport(rows[4], operation, receipt=False))
            self.assertTrue(group._claim_transport(rows[4], operation, receipt=True))
            group._finish_transport(rows[4], operation, receipt=True)
        finally:
            for row in claimed:
                group._finish_transport(row, operation, receipt=False)
        self.assertEqual(group._transport_inflight, set())

    def test_expired_completion_budget_preserves_receipt_obligation(self):
        sender, receiver = self.groups
        first, _admission = self._fail_ack_after_durable_intake(sender, receiver)
        before = receiver.records.get("receipt-obligation", first["message_id"])
        deadline = time.monotonic_ns() - 1
        with patch.object(
            receiver, "_transmit", side_effect=AssertionError("late I/O")
        ):
            result = receiver.complete_receipt(
                first["message_id"], deadline_ns=deadline
            )
            self.assertEqual(result["state"], "pending")
        self.assertEqual(
            receiver.records.get("receipt-obligation", first["message_id"]), before
        )
        self.assertIsNone(receiver.records.get("receipt-terminal", first["message_id"]))

    def test_large_echo_is_fully_confirmed_before_bounded_fanout(self):
        sender, _ = self.groups
        seen = []

        def transmit(_native, _row, operation, **_arguments):
            state = sender.egress.inspect(operation)
            self.assertGreater(state["part_count"], 1)
            self.assertEqual(state["state"], "confirmed")
            seen.append(state["confirmed_parts"])

        with patch.object(sender, "_transmit", side_effect=transmit):
            sender.send(
                client_id="test",
                send_id=str(uuid.uuid4()),
                thread_id=str(uuid.uuid4()),
                text="large synthetic full echo " * 500,
            )
        self.assertTrue(seen)

    def _bounded_write_operation(self):
        group = self.groups[0]
        identifier = str(uuid.uuid4())
        raw = b"synthetic bounded native writer"
        projection = {
            "event_id": identifier,
            "event_digest": "a" * 64,
            "sender": group.lane.being_ref,
            "recipients": [self.groups[1].lane.being_ref],
            "thread_id": identifier,
            "kind": "message",
            "reply_to": None,
            "content": {"text": "synthetic bounded writer"},
        }
        binding = group.records.admit(
            identifier,
            raw,
            path_id="tribe-message-request",
            projection=projection,
            deadline_ms=self.fixture.now + 60_000,
            authority_head=group.ledger.local_origin["body_ref"],
        )
        return group.egress, binding, raw

    def test_bounded_release_never_advances_visibility_under_the_fence(self):
        controller, binding, raw = self._bounded_write_operation()
        effects = []
        with (
            patch.object(
                controller._transport,
                "send",
                side_effect=AssertionError("hidden echo I/O"),
            ),
            self.assertRaisesRegex(NativeEgressError, "egress_echo_not_confirmed"),
        ):
            controller.release_bounded(
                binding,
                raw,
                effects.append,
                deadline_ns=time.monotonic_ns() + 1_000_000_000,
            )
        self.assertEqual(effects, [])
        controller.advance_one(binding)
        controller.release_bounded(
            binding,
            raw,
            effects.append,
            deadline_ns=time.monotonic_ns() + 1_000_000_000,
        )
        self.assertEqual(effects, [raw])
        self.assertEqual(controller.inspect_retained(binding)["completed_releases"], 1)

    def test_bounded_release_deadline_includes_existing_fence_wait(self):
        controller, binding, raw = self._bounded_write_operation()
        controller.advance_one(binding)
        controller._fence.acquire()
        effects = []
        try:
            with self.assertRaisesRegex(NativeEgressError, "egress_attempt_deadline"):
                controller.release_bounded(
                    binding,
                    raw,
                    effects.append,
                    deadline_ns=time.monotonic_ns() + 20_000_000,
                )
        finally:
            controller._fence.release()
        self.assertEqual(effects, [])
        self.assertEqual(controller._live_permits, set())
        self.assertIsNone(controller._attempt_deadline.get())

    def test_bounded_release_rechecks_time_after_local_verification(self):
        controller, binding, raw = self._bounded_write_operation()
        controller.advance_one(binding)
        issue = controller._issue_permit_locked
        effects = []

        def advance_clock(*args, **kwargs):
            permit = issue(*args, **kwargs)
            self.fixture.now = binding.deadline_ms
            return permit

        with (
            patch.object(controller, "_issue_permit_locked", advance_clock),
            self.assertRaisesRegex(NativeEgressError, "egress_authority_blocked"),
        ):
            controller.release_bounded(
                binding,
                raw,
                effects.append,
                deadline_ns=time.monotonic_ns() + 1_000_000_000,
            )
        self.assertEqual(effects, [])
        self.assertEqual(controller._live_permits, set())

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
                controlled_readers=getattr(self, "controlled_readers", False),
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
                        total_timeout_seconds=12,
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
        # Receipt ACK proves durable control intake; its foreign projection is
        # deliberately after the write. Observe completion before semantic view.
        for server in self.servers:
            server._threads.join()
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

    def test_group_can_be_provisioned_from_its_founder_before_any_invitation(self):
        import copy

        from daimon_matrix.messaging_config import (
            MessagingConfigError,
            read_publication,
            validate_shape,
        )

        runtime, app, view = GroupRuntimeTests._signed_group_application(
            self, record_key_check=False, founder_only=True
        )
        document, _ = read_publication(runtime, app)
        import json

        import jsonschema

        public_schema = json.loads(
            (
                Path(__file__).resolve().parents[1]
                / "schemas/messaging/v3/application.schema.json"
            ).read_text()
        )
        jsonschema.Draft202012Validator(public_schema).validate(document)
        self.assertEqual(len(document["authorities"]), 1)
        self.assertEqual(len(document["roster"]), 1)
        self.assertEqual(
            document["roster"][0]["being_ref"], self.fixture.founder.state.being_ref
        )
        self.assertEqual(
            [e["kind"] for e in document["relationship_events"]],
            ["matrix/tribe-declaration"],
        )
        self.assertEqual(set(view.service.messaging.channels), {"tribe"})
        for field in ("authorities", "roster"):
            invalid = copy.deepcopy(document)
            invalid[field] = []
            with self.assertRaises(MessagingConfigError):
                validate_shape(invalid)

    def test_group_only_application_uses_supported_signed_provisioning(self):
        GroupRuntimeTests._signed_group_application(self)

    def _signed_group_application(
        self, *, record_key_check=True, application_directory=None, founder_only=False
    ):
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
        if getattr(self, "with_receiving_controller", False):
            from daimon_matrix.local_api import create_capability

            controller = create_capability(
                b"o" * 32,
                client_id=f"client:host:{runtime.service.runtime_label}:receiving-controller",
                methods=["runtime.reader-selection"],
                not_before_ms=fixture.now - 1,
                not_after_ms=fixture.now + 60_000,
            )
            # Explicit trusted owner composition. Signed optional-role issuance
            # and loader validation are qualified by the successor fixtures.
            runtime = replace(
                runtime,
                service=replace(
                    runtime.service,
                    capabilities={
                        **runtime.service.capabilities,
                        controller.capability_id: controller,
                    },
                ),
            )
        relationships = RelationshipStore(
            runtime.state_root / "relationships.sqlite",
            authority_resolver=fixture.sender_lane.authority_resolver,
        )
        selected_events = [fixture.declaration] if founder_only else fixture.events
        for event in selected_events:
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
        identities = (
            (fixture.founder,) if founder_only else (fixture.founder, fixture.member)
        )
        for index, identity in enumerate(identities):
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
                public_document(identity, "founder" if index == 0 else "member")
                for index, identity in enumerate(identities)
            ],
            "relationship_events": selected_events,
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
        app = application_directory or directory / "group-application"
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
        self.assertEqual(
            group.controlled_readers,
            bool(getattr(self, "with_receiving_controller", False)),
        )
        from daimon_matrix.chat_host import application_view
        from daimon_matrix.operator_capabilities import STATUS_OBSERVER_METHODS
        from daimon_matrix.service import MESSAGING_METHODS

        with patch(
            "daimon_matrix.chat_host._visibility_factory",
            return_value=lambda _context: runtime.egress,
        ):
            hosted = application_view(runtime, app, directory / "visibility.json")
        status = [
            cap
            for cap in hosted.service.capabilities.values()
            if cap.client_id == f"client:host:{runtime.service.runtime_label}:status"
        ]
        self.assertEqual(len(status), 1)
        self.assertEqual(set(status[0].methods), STATUS_OBSERVER_METHODS)
        if group.controlled_readers:
            self.assertIs(view.service.receiving.channels["tribe"], group)
            state = group.egress.reader_snapshot(
                "tribe", deadline_ns=time.monotonic_ns() + 1_000_000_000
            )
            self.assertEqual(state["phase"], "unselected")
            self.assertEqual(state["readers"], [])
            self.assertTrue(
                hosted.service.messaging.channels["tribe"].controlled_readers
            )
            self.assertEqual(
                hosted.service.receiving.capability_id, controller.capability_id
            )
            for key, selected in hosted.service.capabilities.items():
                if key == controller.capability_id:
                    continue
                if (
                    selected.client_id
                    == f"client:host:{runtime.service.runtime_label}:status"
                ):
                    self.assertLessEqual(set(selected.methods), STATUS_OBSERVER_METHODS)
                else:
                    self.assertLessEqual(set(selected.methods), MESSAGING_METHODS)
        else:
            self.assertIsNone(view.service.receiving)
            self.assertIsNone(hosted.service.receiving)
            for cap in hosted.service.capabilities.values():
                if cap is not status[0]:
                    self.assertLessEqual(set(cap.methods), MESSAGING_METHODS)
        if not record_key_check:
            return runtime, app, view
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
        return runtime, app, view


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
