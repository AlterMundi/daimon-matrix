"""Process-local receiver selection uses the real native physical-write fence."""

from __future__ import annotations

import copy
import hashlib
import threading
import time
import unittest
import uuid
from dataclasses import replace
from unittest.mock import patch

from daimon_matrix.canonical import canonical_bytes
from daimon_matrix.local_api import (
    LocalApiError,
    create_capability,
    create_request,
    request_hash,
)
from daimon_matrix.native_egress import NativeEgressError, synthetic_visibility
from daimon_matrix.service import (
    HostedWeave,
    MessagingServiceContext,
    ReceivingServiceContext,
    ServiceError,
)
from tests import test_group_messaging_runtime as group_fixtures


def budget():
    return time.monotonic_ns() + 5_000_000_000


def command(controller, *, phase="revoke", readers=None, operation_id=None, **changes):
    current = controller.reader_snapshot("tribe", deadline_ns=budget())
    return {
        "process_instance_id": current["process_instance_id"],
        "channel_id": "tribe",
        "expected_head": current["head"],
        "operation_id": operation_id or current["operation_id"] or str(uuid.uuid4()),
        "release_digest": "a" * 64,
        "phase": phase,
        "readers": readers or [],
        **changes,
    }


def select(controller, value, request=None):
    # Stand in only for an authenticated request's digest, never for the fence
    # or receiving behavior. The owner RPC boundary is qualified separately.
    request = request or hashlib.sha256(uuid.uuid4().bytes).hexdigest()
    return controller.select_readers(
        value, request_sha256=request, deadline_ns=budget()
    )


def reader(**changes):
    return {
        "being_ref": "dm:being:v1:" + "A" * 43,
        "embodiment_id": "embodiment:synthetic",
        "credential_id": "credential:synthetic",
        "incarnation_id": "incarnation:synthetic",
        "authority_manifest_hash": "b" * 64,
        "receiving_selection_sha256": "c" * 64,
        "loaded_view_sha256": "d" * 64,
        "expires_at_ms": 20_000,
        "wire_read": ["dm.tribe.conversation/v1", "dm.tribe.direct-conversation/v1"],
        "authority_epochs": ["b" * 64],
        **changes,
    }


class ReceivingOwnerApiTests(unittest.TestCase):
    controlled_readers = True

    def setUp(self):
        group_fixtures.GroupRuntimeTests.setUp(self)
        self.group = self.groups[0]
        self.controller = create_capability(
            b"c" * 32,
            client_id="client:host:synthetic:receiving-controller",
            methods=["runtime.reader-selection"],
            not_before_ms=0,
            not_after_ms=2**53 - 1,
        )
        self.observer = create_capability(
            b"s" * 32,
            client_id="client:host:synthetic:status",
            methods=["runtime.status"],
            not_before_ms=0,
            not_after_ms=2**53 - 1,
        )
        self.messaging = MessagingServiceContext(
            channels={"tribe": self.group},
            deliveries={"tribe": self.group},
            client_channels={},
        )
        self.service = self.build(self.group)

    def build(self, group):
        return HostedWeave(
            group.ledger,
            group.signer,
            {cap.capability_id: cap for cap in (self.controller, self.observer)},
            group.lane.clock,
            "dm:runtime:v1:" + "A" * 43,
            "synthetic",
            communication=group.communication,
            messaging=replace(
                self.messaging,
                channels={"tribe": group},
                deliveries={"tribe": group},
            ),
            receiving=ReceivingServiceContext(
                self.controller.capability_id, {"tribe": group}
            ),
        )

    def request(self, params, *, method="runtime.reader-selection", capability=None):
        return create_request(
            capability or self.controller,
            request_id=str(uuid.uuid4()),
            issued_at_ms=self.fixture.now,
            method=method,
            params=params,
        )

    def test_authenticated_control_current_retry_supersession_and_independent_status(
        self,
    ):
        with self.assertRaisesRegex(LocalApiError, "authentication_failed"):
            self.request(command(self.group.egress), capability=self.observer)
        revoke = self.request(command(self.group.egress))
        response = self.service.handle(revoke)
        self.assertTrue(response["ok"], response)
        self.assertEqual(self.service.handle(revoke), response)
        selected_request = self.request(
            command(
                self.group.egress,
                phase="select",
                readers=[reader(expires_at_ms=self.fixture.now + 60_000)],
            )
        )
        selected = self.service.handle(selected_request)
        self.assertTrue(selected["ok"], selected)
        self.assertEqual(self.service.handle(selected_request), selected)
        status = self.service.handle(
            self.request({}, method="runtime.status", capability=self.observer)
        )
        self.assertEqual(
            status["result"]["receiving"]["channels"]["tribe"], selected["result"]
        )
        self.assertTrue(
            self.service.handle(self.request(command(self.group.egress)))["ok"]
        )
        rejected = self.service.handle(selected_request)
        self.assertEqual(rejected["error"]["code"], "reader_selection_conflict")
        self.assertEqual(
            self.group.egress.reader_snapshot("tribe", deadline_ns=budget())["readers"],
            [],
        )

    def test_pending_control_reconciles_applied_change_after_lost_rpc_completion(self):
        revoke = self.request(command(self.group.egress))
        self.assertTrue(self.service.handle(revoke)["ok"])
        request = self.request(
            command(
                self.group.egress,
                phase="select",
                readers=[reader(expires_at_ms=self.fixture.now + 60_000)],
            )
        )
        digest = request_hash(request)
        self.service.ledger.begin_rpc(
            client_id=self.controller.client_id,
            request_id=request["request_id"],
            request_hash=digest,
            method=request["method"],
        )
        applied = self.service._dispatch(
            request["method"],
            request["params"],
            client_id=self.controller.client_id,
            request_id=request["request_id"],
            request_hash=digest,
        )
        response = self.service.handle(request)
        self.assertTrue(response["ok"], response)
        self.assertEqual(response["result"], applied)
        self.assertEqual(self.service.handle(request), response)

    def test_concurrent_revocation_before_rpc_completion_cannot_return_stale_enable(
        self,
    ):
        self.assertTrue(
            self.service.handle(self.request(command(self.group.egress)))["ok"]
        )
        request = self.request(
            command(
                self.group.egress,
                phase="select",
                readers=[reader(expires_at_ms=self.fixture.now + 60_000)],
            )
        )
        finish = self.service.ledger.finish_rpc

        def revoke_before_completion(**arguments):
            select(self.group.egress, command(self.group.egress))
            return finish(**arguments)

        with patch.object(
            self.service.ledger, "finish_rpc", side_effect=revoke_before_completion
        ):
            response = self.service.handle(request)
        self.assertEqual(response["error"]["code"], "reader_selection_conflict")
        self.assertEqual(
            self.group.egress.reader_snapshot("tribe", deadline_ns=budget())["readers"],
            [],
        )

    def test_restart_never_reuses_completed_revoke_or_enable_as_current_control(self):
        revoke = self.request(command(self.group.egress))
        self.assertTrue(self.service.handle(revoke)["ok"])
        enabled = self.request(
            command(
                self.group.egress,
                phase="select",
                readers=[reader(expires_at_ms=self.fixture.now + 60_000)],
            )
        )
        self.assertTrue(self.service.handle(enabled)["ok"])
        status_request = self.request(
            {}, method="runtime.status", capability=self.observer
        )
        previous_status = self.service.handle(status_request)
        group = self.group
        fresh = type(group.egress)(
            policy=group.egress._policy,
            proof_key=group.egress._proof_key,
            transport=group.egress._transport,
            clock=group.lane.clock,
            catalog_mode="migrate",
        )
        restarted = group_fixtures.GroupMessaging(
            lane=group.lane,
            policy=group.policy,
            communication=group.communication,
            providers=group.providers,
            config_digest=group.config_digest,
            egress=fresh,
            controlled_readers=True,
        )
        service = self.build(restarted)
        current_status = service.handle(status_request)
        self.assertNotEqual(
            previous_status["result"]["receiving"],
            current_status["result"]["receiving"],
        )
        for retained in (revoke, enabled):
            response = service.handle(retained)
            self.assertEqual(response["error"]["code"], "reader_process_conflict")
        state = fresh.reader_snapshot("tribe", deadline_ns=budget())
        self.assertEqual(state["phase"], "unselected")
        self.assertEqual(state["readers"], [])

    def test_owner_context_cannot_enable_an_ordinary_or_rebound_group(self):
        with self.assertRaisesRegex(ServiceError, "reader_controller_binding_invalid"):
            replace(
                self.service,
                receiving=ReceivingServiceContext(
                    self.observer.capability_id, {"tribe": self.group}
                ),
            )
        with self.assertRaises(TypeError):
            self.service.receiving.channels["tribe"] = self.groups[1]
        # A trusted compositor must bind the exact loaded group, not just its ID.
        with self.assertRaisesRegex(ServiceError, "reader_controller_binding_invalid"):
            replace(
                self.service,
                receiving=ReceivingServiceContext(
                    self.controller.capability_id, {"tribe": self.groups[1]}
                ),
            )


class ReceivingCompositionTests(unittest.TestCase):
    with_receiving_controller = True
    setUp = group_fixtures.GroupRuntimeTests.setUp

    def test_signed_application_composes_explicit_controlled_group(self):
        group_fixtures.GroupRuntimeTests.test_group_only_application_uses_supported_signed_provisioning(
            self
        )


class ReaderSelectionTests(unittest.TestCase):
    def setUp(self):
        self.now = 1_000
        self.controller = synthetic_visibility(clock=lambda: self.now)
        self.controller.register_reader_channel("tribe", "0" * 64)

    def test_default_denial_revoke_select_expiry_and_retained_exact_retry(self):
        c = self.controller
        row = reader()
        self.assertFalse(c.reader_ready("tribe", row))
        with self.assertRaisesRegex(NativeEgressError, "reader_revocation_required"):
            select(c, command(c, phase="select", readers=[row]))
        revoked = select(c, command(c))
        value = command(c, phase="select", readers=[row])
        request = "e" * 64
        selected = select(c, value, request)
        self.assertTrue(c.reader_ready("tribe", row))
        self.assertNotEqual(selected["head"], revoked["head"])
        self.now = row["expires_at_ms"]
        self.assertFalse(c.reader_ready("tribe", row))
        self.assertEqual(select(c, value, request), selected)

    def test_revocation_of_empty_rows_advances_head_and_rejects_delayed_enable(self):
        c = self.controller
        first = select(c, command(c))
        delayed = command(c, phase="select", readers=[reader()])
        second = select(c, command(c))
        self.assertEqual(second["readers"], [])
        self.assertNotEqual(second["head"], first["head"])
        with self.assertRaisesRegex(NativeEgressError, "reader_selection_conflict"):
            select(c, delayed)
        self.assertFalse(c.reader_ready("tribe", reader()))

    def test_revoked_operation_cannot_be_taken_over_before_its_selected_commit(self):
        c = self.controller
        select(c, command(c))
        before = c.reader_snapshot("tribe", deadline_ns=budget())
        for phase in ("revoke", "select"):
            with (
                self.subTest(phase=phase),
                self.assertRaisesRegex(NativeEgressError, "reader_operation_conflict"),
            ):
                select(c, command(c, phase=phase, operation_id=str(uuid.uuid4())))
        self.assertEqual(c.reader_snapshot("tribe", deadline_ns=budget()), before)
        select(c, command(c, phase="select"))
        # A selected empty projection completes the reservation without granting
        # any reader. The next controlled update can reserve a new operation.
        next_operation = str(uuid.uuid4())
        self.assertEqual(
            select(c, command(c, operation_id=next_operation))["operation_id"],
            next_operation,
        )

    def test_snapshot_and_input_mutations_cannot_change_live_readers(self):
        c = self.controller
        select(c, command(c))
        row = reader()
        selected = select(c, command(c, phase="select", readers=[row]))
        row["credential_id"] = "wrong"
        selected["readers"][0]["credential_id"] = "also-wrong"
        selected["readers"][0]["authority_epochs"].clear()
        selected["readers"][0]["wire_read"].clear()
        self.assertTrue(c.reader_ready("tribe", reader()))
        self.assertTrue(
            c.reader_ready(
                "tribe",
                reader(),
                required_wire="dm.tribe.direct-conversation/v1",
                required_authority_epochs=("b" * 64,),
            )
        )
        self.assertFalse(c.reader_ready("tribe", reader(credential_id="wrong")))

    def test_superseded_request_and_restarted_process_cannot_restore_enable(self):
        c = self.controller
        select(c, command(c))
        value = command(c, phase="select", readers=[reader()])
        request = "e" * 64
        select(c, value, request)
        select(c, command(c))
        with self.assertRaisesRegex(NativeEgressError, "reader_selection_conflict"):
            select(c, value, request)
        restarted = synthetic_visibility(clock=lambda: self.now)
        restarted.register_reader_channel("tribe", "0" * 64)
        with self.assertRaisesRegex(NativeEgressError, "reader_process_conflict"):
            select(restarted, value, request)
        self.assertFalse(restarted.reader_ready("tribe", reader()))

    def test_closed_bounded_rows_and_unknown_channels_fail_without_transition(self):
        c = self.controller
        select(c, command(c))
        value = command(c, phase="select", readers=[reader()])
        before = c.reader_snapshot("tribe", deadline_ns=budget())
        variants = [
            {**value, "extra": True},
            {**value, "channel_id": []},
            {**value, "channel_id": "unknown"},
            {**value, "readers": [reader(), reader()]},
            {**value, "readers": [reader(expires_at_ms=True)]},
            {**value, "readers": [reader(expires_at_ms=self.now)]},
            {**value, "readers": [reader(extra=True)]},
        ]
        for changed in variants:
            with self.subTest(changed=changed), self.assertRaises(NativeEgressError):
                select(c, changed)
        self.assertEqual(c.reader_snapshot("tribe", deadline_ns=budget()), before)

    def test_warm_reconstruction_cannot_rebind_a_loaded_context(self):
        c = self.controller
        select(c, command(c))
        select(c, command(c, phase="select", readers=[reader()]))
        before = c.reader_snapshot("tribe", deadline_ns=budget())
        c.register_reader_channel("tribe", "0" * 64)
        self.assertEqual(c.reader_snapshot("tribe", deadline_ns=budget()), before)
        with self.assertRaisesRegex(NativeEgressError, "reader_context_conflict"):
            c.register_reader_channel("tribe", "1" * 64)

    def test_same_credentials_do_not_authorize_uncovered_wire_or_authority_epoch(self):
        c = self.controller
        select(c, command(c))
        select(c, command(c, phase="select", readers=[reader()]))
        self.assertFalse(
            c.reader_ready("tribe", reader(), required_wire="unsupported/v9")
        )
        self.assertFalse(
            c.reader_ready(
                "tribe",
                reader(),
                required_wire="dm.tribe.direct-conversation/v1",
                required_authority_epochs=("f" * 64,),
            )
        )
        self.assertTrue(
            c.reader_ready(
                "tribe",
                reader(),
                required_wire="dm.tribe.direct-conversation/v1",
                required_authority_epochs=("b" * 64,),
            )
        )


class ReaderHTTPTests(unittest.TestCase):
    def setUp(self):
        self.fixture = group_fixtures.GroupRuntimeTests()
        self.fixture.controlled_readers = getattr(self, "controlled_readers", False)
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def arguments(self, sender, receiver):
        value = self.fixture.direct_arguments(sender, receiver)
        if getattr(self, "controlled_readers", False):
            value.pop("destination")
        return value

    def test_root_advance_with_same_recipient_key_stays_unattempted(self):
        from tests.test_group_messaging_runtime import DirectLaneTests

        f = self.fixture
        sender, receiver = f.groups
        c = sender.egress
        select(c, command(c))
        row = reader(
            being_ref=receiver.lane.being_ref,
            embodiment_id=receiver.lane.local_embodiment_id,
            credential_id=receiver.lane.local_credential_id,
            incarnation_id=receiver.ledger.local_origin["incarnation_id"],
            authority_manifest_hash=receiver.ledger.authority.manifest.digest,
            expires_at_ms=receiver.lane.clock() + 60_000,
            authority_epochs=sorted(
                {
                    receiver.ledger.authority.manifest.digest,
                    sender.ledger.authority.manifest.digest,
                    *(
                        event["manifest_hash"]
                        for event in sender.lane.relationships.events()
                    ),
                }
            ),
        )
        select(c, command(c, phase="select", readers=[row]))
        helper = DirectLaneTests()
        helper.fixture = f.fixture
        current, _ = helper.enroll_second_member_body()
        self.assertNotIn(current.manifest.digest, row["authority_epochs"])
        # The existing body retains its key and transport, but the new carrier
        # requires an epoch not proved in the selected loaded-view observation.
        result = f.send_and_settle(sender, **f.direct_arguments(sender, receiver))
        self.assertEqual(len(result["audience"]), 2)
        existing = next(
            item
            for item in result["transport"]
            if item["embodiment_id"] == receiver.lane.local_embodiment_id
        )
        self.assertEqual(existing["current_route"], "available")
        self.assertEqual(existing["attempt_state"], "not-attempted")
        self.assertFalse(existing["reader_readiness"])
        self.assertEqual(receiver.page(after=0, limit=10), [])

    def test_revoke_waits_for_actual_http_write_and_blocks_subsequent_direct(self):
        f = self.fixture
        sender, receiver = f.groups
        c = sender.egress
        select(c, command(c))
        select(
            c,
            command(
                c,
                phase="select",
                readers=[
                    reader(
                        being_ref=receiver.lane.being_ref,
                        embodiment_id=receiver.lane.local_embodiment_id,
                        credential_id=receiver.lane.local_credential_id,
                        incarnation_id=receiver.ledger.local_origin["incarnation_id"],
                        authority_manifest_hash=receiver.ledger.authority.manifest.digest,
                        expires_at_ms=receiver.lane.clock() + 60_000,
                        authority_epochs=sorted(
                            {
                                receiver.ledger.authority.manifest.digest,
                                sender.ledger.authority.manifest.digest,
                                *(
                                    event["manifest_hash"]
                                    for event in sender.lane.relationships.events()
                                ),
                            }
                        ),
                    )
                ],
            ),
        )
        provider = sender.providers[
            (receiver.lane.being_ref, receiver.lane.local_embodiment_id)
        ]["message"]
        original = provider._round_trip
        entered, released, revoking, revoked = (threading.Event() for _ in range(4))
        failures, outcomes = [], []

        def open_exchange(deadline):
            exchange = original.bounded_open(deadline)

            def physical_write(raw):
                entered.set()
                if not released.wait(5):
                    raise AssertionError("physical writer release missing")
                exchange.write(raw)

            return replace(exchange, write=physical_write)

        def send():
            try:
                outcomes.append(sender.send(**self.arguments(sender, receiver)))
            except BaseException as failure:
                failures.append(failure)

        value = command(c)

        def revoke():
            try:
                revoking.set()
                select(c, value)
                revoked.set()
            except BaseException as failure:
                failures.append(failure)

        provider._round_trip = replace(original, bounded_open=open_exchange)
        sending = threading.Thread(target=send)
        revocation = threading.Thread(target=revoke)
        try:
            sending.start()
            self.assertTrue(entered.wait(5))
            revocation.start()
            self.assertTrue(revoking.wait(5))
            self.assertFalse(revoked.wait(0.05))
        finally:
            released.set()
            sending.join(10)
            if revocation.ident is not None:
                revocation.join(10)
            provider._round_trip = original
        self.assertFalse(sending.is_alive())
        self.assertFalse(revocation.is_alive())
        self.assertEqual(failures, [])
        self.assertTrue(revoked.is_set())
        for server in [*f.servers, f.servers[0]]:
            server._threads.join()
        previous = sender.inspect(client_id="test", send_id=outcomes[0]["send_id"])
        self.assertTrue(previous["semantic"]["terminal"])
        native = copy.deepcopy(sender.records.get("native", outcomes[0]["send_id"]))
        previous_remote = next(
            item
            for item in previous["transport"]
            if item["embodiment_id"] == receiver.lane.local_embodiment_id
        )
        self.assertEqual(previous_remote["attempt_state"], "recipient-intake")
        self.assertFalse(previous_remote["reader_readiness"])
        denied = f.send_and_settle(sender, **self.arguments(sender, receiver))
        remote = next(
            item
            for item in denied["transport"]
            if item["embodiment_id"] == receiver.lane.local_embodiment_id
        )
        self.assertEqual(remote["attempt_state"], "not-attempted")
        self.assertEqual(len(receiver.page(after=0, limit=10)), 1)
        self.assertEqual(
            canonical_bytes(sender.records.get("native", outcomes[0]["send_id"])),
            canonical_bytes(native),
        )


class ControlledGroupTests(unittest.TestCase):
    controlled_readers = True
    setUp = ReaderHTTPTests.setUp
    arguments = ReaderHTTPTests.arguments

    def test_revoke_waits_for_actual_group_write(self):
        ReaderHTTPTests.test_revoke_waits_for_actual_http_write_and_blocks_subsequent_direct(
            self
        )

    def install_baseline(self):
        sender, receiver = self.fixture.groups
        select(sender.egress, command(sender.egress))
        value = reader(
            being_ref=receiver.lane.being_ref,
            embodiment_id=receiver.lane.local_embodiment_id,
            credential_id=receiver.lane.local_credential_id,
            incarnation_id=receiver.ledger.local_origin["incarnation_id"],
            authority_manifest_hash=receiver.ledger.authority.manifest.digest,
            expires_at_ms=receiver.lane.clock() + 60_000,
            authority_epochs=sorted(
                {
                    receiver.ledger.authority.manifest.digest,
                    sender.ledger.authority.manifest.digest,
                    *(
                        event["manifest_hash"]
                        for event in sender.lane.relationships.events()
                    ),
                }
            ),
        )
        select(sender.egress, command(sender.egress, phase="select", readers=[value]))
        return value

    def remote(self, result):
        receiver = self.fixture.groups[1]
        return next(
            row
            for row in result["transport"]
            if row["embodiment_id"] == receiver.lane.local_embodiment_id
        )

    def test_unselected_group_and_direct_retain_audiences_then_exact_group_retry(self):
        f = self.fixture
        sender, receiver = f.groups
        arguments = self.arguments(sender, receiver)
        first = f.send_and_settle(sender, **arguments)
        self.assertEqual(first["schema"], "dm.tribe.delivery/v1")
        self.assertEqual(len(first["audience"]), 2)
        self.assertEqual(self.remote(first)["attempt_state"], "not-attempted")
        direct = f.send_and_settle(sender, **f.direct_arguments(sender, receiver))
        self.assertEqual(len(direct["audience"]), 1)
        self.assertEqual(self.remote(direct)["attempt_state"], "not-attempted")
        retained = sender.records.get("native", first["send_id"])
        self.install_baseline()
        second = f.send_and_settle(sender, **arguments)
        self.assertTrue(second["semantic"]["terminal"])
        self.assertEqual(second["message_id"], first["message_id"])
        self.assertEqual(second["audience"], first["audience"])
        self.assertEqual(sender.records.get("native", first["send_id"]), retained)
        self.assertEqual(len(receiver.page(after=0, limit=10)), 1)
        self.assertEqual(
            receiver.egress.reader_snapshot("tribe", deadline_ns=budget())["phase"],
            "unselected",
        )
        # Signed return dispatch and the author's control intake need no positive
        # data projection. Their actual authority/visibility fences still run.
        self.assertEqual(self.remote(second)["attempt_state"], "recipient-intake")

    def test_controlled_group_rejects_opaque_and_unbounded_transport(self):
        from unittest.mock import Mock

        f = self.fixture
        sender, receiver = f.groups
        self.install_baseline()
        provider = sender.providers[
            (receiver.lane.being_ref, receiver.lane.local_embodiment_id)
        ]["message"]
        original = provider._round_trip
        for value in (Mock(), replace(original, bounded_open=None)):
            with self.subTest(opaque=type(value).__name__):
                provider._round_trip = value
                result = f.send_and_settle(sender, **self.arguments(sender, receiver))
                self.assertEqual(self.remote(result)["attempt_state"], "unconfirmed")
                self.assertEqual(receiver.page(after=0, limit=10), [])
                if isinstance(value, Mock):
                    value.assert_not_called()
        provider._round_trip = original

    def test_expired_selection_and_callback_override_cannot_restore_legacy_mode(self):
        f = self.fixture
        sender, receiver = f.groups
        value = self.install_baseline()
        f.fixture.now = value["expires_at_ms"]
        sender.direct_reader_ready = lambda row: True
        result = f.send_and_settle(sender, **self.arguments(sender, receiver))
        self.assertEqual(self.remote(result)["attempt_state"], "not-attempted")
        self.assertEqual(receiver.page(after=0, limit=10), [])
        self.assertTrue(sender.controlled_readers)
        with self.assertRaisesRegex(NativeEgressError, "reader_context_conflict"):
            sender.egress.register_reader_channel("tribe", sender.config_digest)

    def test_group_reader_does_not_cover_new_epoch_with_unchanged_key(self):
        f = self.fixture
        sender, receiver = f.groups
        value = self.install_baseline()
        helper = group_fixtures.DirectLaneTests()
        helper.fixture = f.fixture
        current, _ = helper.enroll_second_member_body()
        self.assertNotIn(current.manifest.digest, value["authority_epochs"])
        result = f.send_and_settle(sender, **self.arguments(sender, receiver))
        self.assertEqual(len(result["audience"]), 3)
        self.assertEqual(self.remote(result)["attempt_state"], "not-attempted")
        self.assertEqual(receiver.page(after=0, limit=10), [])
