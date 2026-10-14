"""Process-local receiver selection uses the real native physical-write fence."""

from __future__ import annotations

import copy
import hashlib
import threading
import time
import unittest
import uuid
from dataclasses import replace

from daimon_matrix.canonical import canonical_bytes
from daimon_matrix.native_egress import NativeEgressError, synthetic_visibility
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
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

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
                outcomes.append(sender.send(**f.direct_arguments(sender, receiver)))
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
        self.assertEqual(previous["transport"][0]["attempt_state"], "recipient-intake")
        self.assertFalse(previous["transport"][0]["reader_readiness"])
        denied = f.send_and_settle(sender, **f.direct_arguments(sender, receiver))
        self.assertEqual(denied["transport"][0]["attempt_state"], "not-attempted")
        self.assertEqual(len(receiver.page(after=0, limit=10)), 1)
        self.assertEqual(
            canonical_bytes(sender.records.get("native", outcomes[0]["send_id"])),
            canonical_bytes(native),
        )
