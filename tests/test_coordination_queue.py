"""Bounded queue with actual signed native intake, not Telegram echoes."""

import sqlite3
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from threading import Barrier

from daimon_matrix.execution_instruction import ExecutionDenied
from daimon_matrix.execution_store import ExecutionStore
from daimon_matrix.review_runner import ReviewController
from daimon_matrix.sealed import SealedDeliveryError
from daimon_matrix.synthetic_relationships import NOW
from tests import test_coordination_funding as funding
from tests.test_native_messaging import Pair
from tests.test_passive_messaging_execution import BoundedFakeRunner, Broker


class QueueTests(unittest.TestCase):
    def setUp(self):
        self.f = funding.FundingTests()
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.store = self.f.store
        self.store.enable_coordination_queue()
        self.pair = Pair(self.f.path.parent / "native")
        self.f.account(
            "native-being", "being", subject=self.pair.recipient.state.being_ref
        )
        self.instruction = self.f.instruction(
            "queued",
            accounts=["tribe", "native-being", "episode"],
            being=self.pair.recipient.state.being_ref,
            embodiment=self.pair.recipient.origin["embodiment_id"],
        )
        self.serial = 100
        self.body = dict(
            coordination=dict(
                schema="execution/coordination-request/v1",
                account_id="episode",
                instruction_sha256=self.instruction.sha256,
                kind="work",
            )
        )
        original = self.deliver()
        self.policy = dict(
            schema="execution/episode-policy/v1",
            store_id=self.store.store_id,
            principal="human:test",
            account_id="episode",
            participants=[self.pair.sender.state.being_ref],
            instructions=[self.instruction.sha256],
            threads=[original["payload"]["intent"]["thread_id"]],
            max_requests=3,
            max_pending=2,
            max_input_bytes=4096,
        )
        self.store.configure_episode(self.policy, self.f.signed(self.policy))
        self.message = original

    def deliver(self, body_extra=None):
        self.serial += 10
        evidence, raw, message, _ = self.pair.wire(
            self.serial, body_extra=body_extra or self.body
        )
        self.pair.receiver.receive_evidence(evidence)
        self.pair.receiver.receive_message(raw)
        return message

    def enqueue(self, message=None):
        return self.store.enqueue_coordination(
            (message or self.message)["event_id"], self.pair.receiver.message
        )

    def controller(self):
        runner = BoundedFakeRunner()
        runner.binding = self.instruction.binding
        control = ReviewController(
            self.store,
            runner,
            Broker(),
            require_queued_source=True,
            read_message=self.pair.receiver.message,
            monotonic=lambda: 0,
        )
        return control, runner

    def test_native_source_queue_context_and_exact_duplicate_after_restart(self):
        work = self.enqueue()
        self.assertEqual(self.enqueue(), work)
        control, runner = self.controller()
        context = control.run_due_once("queued", 1, "task", work_id=work)
        self.assertIsNotNone(context)
        self.assertEqual(
            runner.starts[0][0].work["source"]["message_id"], self.message["event_id"]
        )
        context.inference(
            lambda: self.f.calls.append("one"),
            exposure=self.f.exposure(self.instruction),
        )
        self.store = ExecutionStore(
            self.f.path, funding.verifier(self.f.human), clock=self.f.clock
        )
        self.assertEqual(self.enqueue(), work)
        control, runner = self.controller()
        self.assertIsNone(control.run_due_once("queued", 1, "task", work_id=work))
        self.assertEqual(runner.starts, [])
        self.assertEqual(self.f.calls, ["one"])
        self.assertEqual(
            self.store.coordination_work(work)["cycle_id"], context.cycle.cycle_id
        )

    def test_native_revocation_after_queue_prevents_start(self):
        work = self.enqueue()
        self.pair.receiver_relationships.ingest(
            next(
                event
                for event in self.pair.history
                if event["kind"] == "matrix/relationship-grant-revocation"
            )
        )
        self.pair.now = NOW + 17
        control, runner = self.controller()
        with self.assertRaises(SealedDeliveryError):
            control.run_due_once("queued", 1, "task", work_id=work)
        self.assertEqual(runner.starts, [])
        self.assertEqual(self.store.coordination_work(work)["state"], "queued")

    def test_native_revocation_after_start_prevents_provider_transport(self):
        work = self.enqueue()
        control, _ = self.controller()
        context = control.run_due_once("queued", 1, "task", work_id=work)
        self.pair.receiver_relationships.ingest(
            next(
                event
                for event in self.pair.history
                if event["kind"] == "matrix/relationship-grant-revocation"
            )
        )
        self.pair.now = NOW + 17
        with self.assertRaises(SealedDeliveryError):
            context.inference(
                lambda: self.f.calls.append("forbidden"),
                exposure=self.f.exposure(self.instruction),
            )
        self.assertEqual(self.f.calls, [])
        self.assertEqual(self.store.funding_status("episode")["calls"], 0)

    def test_queue_limits_technical_events_and_no_input_replay(self):
        first = self.enqueue()
        second = self.enqueue(self.deliver())
        with self.assertRaises(ExecutionDenied):
            self.enqueue(self.deliver())
        for kind in ["ack", "result", "status", "reaction", "error"]:
            self.assertIsNone(
                self.enqueue(
                    self.deliver(
                        body_extra=dict(
                            coordination=self.body["coordination"] | {"kind": kind}
                        )
                    )
                )
            )
        self.assertIsNone(
            self.enqueue(self.deliver(body_extra={"text": "ordinary passive speech"}))
        )
        self.assertEqual(self.enqueue(), first)
        self.assertNotEqual(first, second)
        with closing(sqlite3.connect(self.f.path)) as db:
            self.assertEqual(
                db.execute("SELECT count(*) FROM coordination_work").fetchone()[0], 2
            )
        self.assertEqual(self.store.funding_status("episode")["calls"], 0)

    def test_concurrent_source_claim_has_one_existing_cycle_and_no_direct_bypass(self):
        work = self.enqueue()
        barrier = Barrier(2)

        def claim(_):
            barrier.wait(timeout=5)
            return self.store.reserve(
                "queued", 1, self.instruction.binding, work_id=work
            )

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(claim, range(2)))
        self.assertEqual(sum(c is not None for c in results), 1)
        control, runner = self.controller()
        with self.assertRaises(ExecutionDenied):
            control.run_due_once("queued", 1, "task")
        self.assertEqual(runner.starts, [])

    def test_forged_source_root_and_size_are_not_admitted(self):
        with self.assertRaises(ExecutionDenied):
            self.store.enqueue_coordination(
                self.message["event_id"], lambda _: self.message | {"event_id": "wrong"}
            )
        changed = self.deliver(
            body_extra=dict(
                coordination=self.body["coordination"] | {"account_id": "invented-root"}
            )
        )
        with self.assertRaises(ExecutionDenied):
            self.enqueue(changed)
        huge = self.deliver(body_extra=self.body | {"text": "x" * 5000})
        with self.assertRaises(ExecutionDenied):
            self.enqueue(huge)
        self.assertEqual(self.store.funding_status("episode")["calls"], 0)

    def test_slow_final_authorization_read_cannot_renew_provider_horizon(self):
        work = self.enqueue()
        state = {"paid": False, "reads": 0}

        def read(message_id):
            result = self.pair.receiver.message(message_id)
            if state["paid"]:
                state["reads"] += 1
                if state["reads"] == 3:
                    self.f.clock.now = 108
            return result

        runner = BoundedFakeRunner()
        runner.binding = self.instruction.binding
        control = ReviewController(
            self.store,
            runner,
            Broker(),
            require_queued_source=True,
            read_message=read,
            monotonic=lambda: 0,
        )
        context = control.run_due_once("queued", 1, "task", work_id=work)
        state["paid"] = True
        with self.assertRaises(ExecutionDenied):
            context.inference(
                lambda: self.f.calls.append("late"),
                exposure=self.f.exposure(self.instruction),
            )
        self.assertEqual(self.f.calls, [])
        self.assertEqual(self.store.funding_status("episode")["charged"], 30)
        self.assertEqual(
            self.store.cycle_status(context.cycle.cycle_id)["state"], "ambiguous"
        )

    def test_signed_withdrawal_survives_restart_and_never_requeues_original(self):
        work = self.enqueue()
        source = self.store.coordination_work(work)["source"]
        payload = dict(
            schema="execution/work-withdrawal/v1",
            store_id=self.store.store_id,
            principal="human:test",
            work_id=work,
            source_sha256=source["source_sha256"],
        )
        receipt = self.f.signed(payload)
        self.store.withdraw_coordination(payload, receipt)
        self.store = ExecutionStore(
            self.f.path, funding.verifier(self.f.human), clock=self.f.clock
        )
        self.store.withdraw_coordination(payload, receipt)
        self.assertEqual(self.enqueue(), work)
        self.assertEqual(self.store.coordination_work(work)["state"], "withdrawn")
        control, runner = self.controller()
        self.assertIsNone(control.run_due_once("queued", 1, "task", work_id=work))
        self.assertEqual(runner.starts, [])
        self.assertEqual(self.store.funding_status("episode")["calls"], 0)

    def test_withdrawal_never_erases_already_reserved_cycle(self):
        work = self.enqueue()
        control, _ = self.controller()
        context = control.run_due_once("queued", 1, "task", work_id=work)
        payload = dict(
            schema="execution/work-withdrawal/v1",
            store_id=self.store.store_id,
            principal="human:test",
            work_id=work,
            source_sha256=self.store.coordination_work(work)["source"]["source_sha256"],
        )
        with self.assertRaises(ExecutionDenied):
            self.store.withdraw_coordination(payload, self.f.signed(payload))
        self.assertEqual(
            self.store.coordination_work(work)["cycle_id"], context.cycle.cycle_id
        )
        self.assertEqual(self.store.coordination_work(work)["state"], "intent")
