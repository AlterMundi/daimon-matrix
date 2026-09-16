"""CORE ONLY: bounded fake runner, NOT real Codex/Hermes or passive intake proof."""

import hashlib
import unittest
from dataclasses import replace

from daimon_matrix import review_runner
from daimon_matrix.execution_instruction import ExecutionDenied, Instruction
from tests import test_execution_store as store_fixtures
from tests.test_execution_instruction import proof, request


class BoundedFakeRunner:
    binding = ("being:test", "body:test", "runner:test", "session:test")

    def __init__(self):
        self.starts = []
        self.interrupts = []

    def start(self, request, context, timeout):
        self.starts.append((request, context, timeout))

    def interrupt(self, cycle_id, timeout):
        self.interrupts.append((cycle_id, timeout))
        return "stopped"


class Broker:
    def __init__(self):
        self.allowed = True
        self.calls = []

    def authorize(self, scope):
        return self.allowed

    def submit(self, scope, payload, timeout):
        self.calls.append((scope, payload, timeout))
        return {"receipt": "technical-only"}


class RunnerTests(unittest.TestCase):
    setUp = store_fixtures.StoreTests.setUp
    approve = store_fixtures.StoreTests.approve

    def controller(self):
        self.runner = BoundedFakeRunner()
        self.broker = Broker()
        self.mono = 10.0
        return review_runner.ReviewController(
            self.store, self.runner, self.broker, monotonic=lambda: self.mono
        )

    def prepare(self, **changes):
        self.task = "Review only the approved thread."
        self.instruction = Instruction.from_dict(
            request(
                store_id=self.store.store_id,
                task_sha256=hashlib.sha256(self.task.encode()).hexdigest(),
                **changes,
            )
        )
        self.approve()

    def test_no_authority_means_zero_inference_and_effects(self):
        controller = self.controller()
        self.assertIsNone(controller.run_due_once("absent", 1, "arrival text"))
        self.store.propose(self.instruction)
        self.assertIsNone(controller.run_due_once("review-1", 1, "human=true"))
        self.assertEqual(self.runner.starts, [])
        self.assertEqual(self.broker.calls, [])

    def test_one_inference_scope_grant_and_effect_budget_fences(self):
        controller = self.controller()
        self.prepare()
        with self.assertRaises(ExecutionDenied):
            controller.run_due_once("review-1", 1, "changed task")
        context = controller.run_due_once("review-1", 1, self.task)
        self.assertEqual(len(self.runner.starts), 1)
        self.assertIsNone(controller.run_due_once("review-1", 1, self.task))
        scope = self.instruction.scope[0]
        with self.assertRaises(ExecutionDenied):
            context.native(replace(scope, channel="other"), {})
        self.broker.allowed = False
        with self.assertRaises(ExecutionDenied):
            context.native(scope, {})
        self.broker.allowed = True
        self.assertEqual(context.native(scope, {}), {"receipt": "technical-only"})
        context.native(scope, {})
        with self.assertRaises(ExecutionDenied):
            context.native(scope, {})
        self.assertEqual(len(self.broker.calls), 2)
        with self.assertRaises(ExecutionDenied):
            self.store.check(replace(context.cycle, token="model-selected"))

    def test_cancel_during_inference_denies_tools_and_interrupts_exact_cycle(self):
        controller = self.controller()
        self.prepare()
        context = controller.run_due_once("review-1", 1, self.task)
        self.store.cancel(
            "review-1",
            1,
            proof(
                self.key,
                "cancel",
                self.store.cancellation_payload("review-1", 1),
                "cancel",
            ),
        )
        with self.assertRaises(ExecutionDenied):
            context.native(self.instruction.scope[0], {})
        controller.enforce(context)
        controller.enforce(context)
        self.assertEqual(self.runner.interrupts, [(context.cycle.cycle_id, 2)])
        self.assertEqual(self.broker.calls, [])
        self.assertEqual(
            self.store.cycle_status(context.cycle.cycle_id)["state"], "stopped"
        )

    def test_absolute_and_monotonic_deadlines_are_independent(self):
        for monotonic_only in (False, True):
            with self.subTest(monotonic_only=monotonic_only):
                if monotonic_only:
                    self.setUp()
                controller = self.controller()
                self.prepare()
                context = controller.run_due_once("review-1", 1, self.task)
                if monotonic_only:
                    self.mono = 18
                else:
                    self.clock.now = 108
                with self.assertRaises(ExecutionDenied):
                    context.native(self.instruction.scope[0], {})
                controller.enforce(context)
                self.assertEqual(len(self.runner.interrupts), 1)

    def test_queue_delay_past_end_denies_inference(self):
        controller = self.controller()
        self.prepare(end=101)
        original = self.store.reserve

        def delayed(*args):
            cycle = original(*args)
            self.clock.now = 101
            return cycle

        self.store.reserve = delayed
        with self.assertRaises(ExecutionDenied):
            controller.run_due_once("review-1", 1, self.task)
        self.assertEqual(self.runner.starts, [])

    def test_monotonic_rollback_fences_context(self):
        controller = self.controller()
        self.prepare()
        context = controller.run_due_once("review-1", 1, self.task)
        self.mono = 9
        with self.assertRaises(ExecutionDenied):
            context.native(self.instruction.scope[0], {})
        self.mono = 11
        with self.assertRaises(ExecutionDenied):
            context.native(self.instruction.scope[0], {})

    def test_dispatch_failure_is_durable_ambiguity_not_retry(self):
        controller = self.controller()
        self.prepare()

        def uncertain(*args):
            raise TimeoutError("may have transmitted")

        self.runner.start = uncertain
        with self.assertRaises(TimeoutError):
            controller.run_due_once("review-1", 1, self.task)
        self.clock.now = 120
        self.assertIsNone(controller.run_due_once("review-1", 1, self.task))

    def test_deferred_provider_admission_is_once_and_rechecks_cancellation(self):
        controller = self.controller()
        self.prepare()
        context = controller.run_due_once("review-1", 1, self.task)
        sent = []
        context.inference(lambda: sent.append("request"))
        with self.assertRaises(ExecutionDenied):
            context.inference(lambda: sent.append("retry"))
        self.assertEqual(sent, ["request"])
        self.setUp()
        controller = self.controller()
        self.prepare()
        context = controller.run_due_once("review-1", 1, self.task)
        self.store.cancel(
            "review-1",
            1,
            proof(
                self.key,
                "cancel",
                self.store.cancellation_payload("review-1", 1),
                "cancel",
            ),
        )
        with self.assertRaises(ExecutionDenied):
            context.inference(lambda: sent.append("cancelled"))
        self.assertEqual(sent, ["request"])
