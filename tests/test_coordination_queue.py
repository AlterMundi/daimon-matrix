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
        control, _ = self.controller()
        return control.enqueue_native((message or self.message)["event_id"])

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

    def test_operator_episode_snapshot_conserves_and_never_activates(self):
        before = self.store.episode_status("episode")
        self.assertEqual(before["funding_constraints"], [])
        self.assertEqual(before["work"], {})
        self.assertEqual(len(before["accounts"]), 3)
        work = self.enqueue()
        queued = self.store.episode_status("episode")
        self.assertEqual(queued["work"], {"queued": 1})
        control, runner = self.controller()
        context = control.run_due_once("queued", 1, "task", work_id=work)
        context.inference(lambda: None, exposure=self.f.exposure(self.instruction))
        snapshot = self.store.episode_status("episode")
        self.assertEqual(snapshot["work"], {"intent": 1})
        for account in snapshot["accounts"]:
            self.assertEqual(
                account["calls"] + account["available_calls"], account["max_calls"]
            )
            self.assertEqual(
                account["spent"] + account["reserved"] + account["available_charge"],
                account["max_charge"],
            )
            self.assertEqual(account["calls"], 1)
        starts = len(runner.starts)
        self.store.episode_status("episode")
        self.assertEqual(len(runner.starts), starts)
        self.assertEqual(self.f.calls, [])

    def test_operator_snapshot_remains_available_during_clock_fault_and_pause(self):
        payload = dict(
            schema="execution/funding-control/v1",
            store_id=self.store.store_id,
            principal="human:test",
            account_id="episode",
            revision=1,
            paused=True,
        )
        self.store.control_funding(payload, self.f.signed(payload))
        self.f.clock.now = 99
        report = self.store.episode_status("episode")
        self.assertIsNone(report["observed_at"])
        self.assertIn("clock_untrusted", report["funding_constraints"])
        self.assertIn("paused", report["funding_constraints"])
        self.f.clock.now = 150
        reopened = ExecutionStore(self.f.path, self.store.verifier, clock=self.f.clock)
        self.assertIn(
            "clock_untrusted", reopened.episode_status("episode")["funding_constraints"]
        )
        self.assertEqual(reopened.funding_status("episode")["calls"], 0)

    def test_operator_cli_uses_existing_journal_without_activation(self):
        import io
        import json
        from contextlib import redirect_stdout

        from daimon_matrix.operator_execution import main

        trust = self.f.path.parent / "public-trust.json"
        trust.write_text(
            json.dumps(
                {"human:test": self.f.human.public_key().public_bytes_raw().hex()}
            )
        )
        output = io.StringIO()
        with redirect_stdout(output):
            result = main(
                [
                    "--store",
                    str(self.f.path),
                    "--trust",
                    str(trust),
                    "episode-status",
                    "episode",
                ],
                clock=self.f.clock,
            )
        self.assertEqual(result, 0)
        report = json.loads(output.getvalue())
        self.assertEqual(report["account_id"], "episode")
        self.assertEqual(report["work"], {})
        self.assertTrue(all(account["calls"] == 0 for account in report["accounts"]))

    def test_combined_report_is_available_without_reporting_migration(self):
        report = self.store.episode_report("episode")
        self.assertEqual(report["snapshot"]["account_id"], "episode")
        self.assertFalse(report["reporting_enabled"])
        self.assertIsNone(report["notice"])
        self.store.enable_episode_reporting()
        self.assertTrue(self.store.episode_report("episode")["reporting_enabled"])
        self.assertEqual(self.f.calls, [])

    def notice_policy(self, account, instructions):
        policy = self.policy | {
            "account_id": account,
            "instructions": sorted(i.sha256 for i in instructions),
        }
        self.store.configure_episode(policy, self.f.signed(policy))

    def test_reporting_migration_preserves_policy_and_one_notice_survives_restart(self):
        with closing(sqlite3.connect(self.f.path)) as db:
            before = db.execute(
                "SELECT account_id,payload,proof FROM episode_policies"
            ).fetchall()
        self.store.enable_episode_reporting()
        self.store.enable_episode_reporting()
        with closing(sqlite3.connect(self.f.path)) as db:
            self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], 4)
            self.assertEqual(
                db.execute(
                    "SELECT account_id,payload,proof FROM episode_policies"
                ).fetchall(),
                before,
            )
        self.f.account("one-call", "episode", max_calls=1)
        instruction = self.f.instruction(
            "one-call",
            accounts=["tribe", "native-being", "one-call"],
            maximum=0,
            being=self.instruction.being,
        )
        self.notice_policy("one-call", [instruction])
        self.assertIsNone(self.store.episode_notice("one-call"))
        cycle = self.f.cycle(instruction)
        self.f.send(instruction, cycle, self.f.exposure(instruction, maximum=0))
        self.f.usage(cycle, 0)
        self.store.finish(cycle, "completed")
        with ThreadPoolExecutor(max_workers=4) as pool:
            notices = list(
                pool.map(lambda _: self.store.episode_notice("one-call"), range(8))
            )
        self.assertTrue(all(n == notices[0] for n in notices))
        notice = notices[0]
        self.assertIn("call_fuel_exhausted", notice["constraints"])
        reopened = ExecutionStore(self.f.path, self.store.verifier, clock=self.f.clock)
        self.assertEqual(reopened.episode_notice("one-call"), notice)
        self.assertEqual(len(self.f.calls), 1)
        with closing(sqlite3.connect(self.f.path)) as db:
            self.assertEqual(
                db.execute(
                    "SELECT count(*) FROM episode_policies WHERE notice IS NOT NULL"
                ).fetchone()[0],
                1,
            )

    def test_one_exhausted_member_does_not_exhaust_other_episode_routes(self):
        self.store.enable_episode_reporting()
        self.f.account("multi", "episode")
        self.f.account("limited-being", "being", max_calls=1)
        self.f.account("healthy-being", "being")
        first = self.f.instruction(
            "limited", accounts=["tribe", "limited-being", "multi"], maximum=0
        )
        other = self.f.instruction(
            "healthy", accounts=["tribe", "healthy-being", "multi"], maximum=0
        )
        self.notice_policy("multi", [first, other])
        cycle = self.f.cycle(first)
        self.f.send(first, cycle, self.f.exposure(first, maximum=0))
        self.f.usage(cycle, 0)
        self.store.finish(cycle, "completed")
        snapshot = self.store.episode_status("multi")
        self.assertIn("call_fuel_exhausted", snapshot["funding_constraints"])
        routes = {r["instruction_sha256"]: r for r in snapshot["instructions"]}
        self.assertEqual(routes[other.sha256]["funding_constraints"], [])
        self.assertIsNone(self.store.episode_notice("multi"))

    def test_notice_requires_explicit_migration_and_pause_alone_is_not_exhaustion(self):
        with self.assertRaises(ExecutionDenied):
            self.store.episode_notice("episode")
        self.store.enable_episode_reporting()
        self.f.pause()
        self.assertIsNone(self.store.episode_notice("episode"))
        self.assertEqual(self.f.calls, [])

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
