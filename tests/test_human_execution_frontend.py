"""Authenticated host-only human execution ceremonies; synthetic keys and runners."""

from __future__ import annotations

import hashlib
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import MethodType, SimpleNamespace

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from daimon_matrix.execution_instruction import (
    ApprovalVerifier,
    ExecutionDenied,
    Instruction,
)
from daimon_matrix.execution_store import ExecutionStore
from daimon_matrix.human_execution_frontend import HumanTurn
from daimon_matrix.operator_execution import HumanExecutionOperator
from daimon_matrix.review_runner import ReviewController
from tests.test_execution_instruction import proof, request
from tests.test_passive_messaging_execution import Broker


class Clock:
    def __init__(self) -> None:
        self.now = 100.0

    def __call__(self) -> float:
        return self.now


class HumanFrontendTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="dm138-human-frontend-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.key = Ed25519PrivateKey.generate()
        self.clock = Clock()
        self.counters = {"codex": 0, "hermes": 0}
        self.challenge_counter = 0

        def challenge_id() -> str:
            self.challenge_counter += 1
            return f"challenge-{self.challenge_counter}"

        verifier = ApprovalVerifier({"human:test": self.key.public_key()})
        bindings = {}
        for kind in ("codex", "hermes"):
            store = ExecutionStore.create(
                self.root / f"{kind}-execution.sqlite", verifier, clock=self.clock
            )
            binding = ("being:test", "body:test", f"{kind}:runner", f"{kind}:session")
            bindings[kind] = (
                store,
                ReviewController(
                    store, self.runner(kind, binding), Broker(), monotonic=lambda: 10.0
                ),
            )
        self.operator = HumanExecutionOperator(
            challenge_path=self.root / "human-challenges.sqlite",
            bindings=bindings,
            authenticate=lambda turn: turn.authentication == f"session:{turn.turn_id}",
            signer=lambda principal, message: self.key.sign(message),
            clock=self.clock,
            challenge_id=challenge_id,
        )

    def runner(self, kind: str, binding: tuple[str, str, str, str]):
        if kind == "codex":
            from daimon_matrix.codex_review import CodexReviewRunner

            runner = object.__new__(CodexReviewRunner)
        else:
            from daimon_matrix.hermes_review import HermesReviewRunner

            runner = object.__new__(HermesReviewRunner)
        runner.registration = SimpleNamespace(binding=binding, principal="human:test")

        def start(self, request, context, timeout):
            self_counters[kind] += 1

        def interrupt(self, cycle_id, timeout):
            return "stopped"

        self_counters = self.counters
        runner.start = MethodType(start, runner)
        runner.interrupt = MethodType(interrupt, runner)
        return runner

    @staticmethod
    def turn(label: str = "turn-1", origin: str = "direct-human") -> HumanTurn:
        return HumanTurn(
            principal="human:test",
            turn_id=label,
            origin=origin,
            authentication=f"session:{label}",
        )

    def instruction(
        self, kind: str, *, mode: str = "manual"
    ) -> tuple[Instruction, str]:
        store, _ = self.operator.bindings[kind]
        task = f"Review now through {kind}."
        values = request(
            store_id=store.store_id,
            runner=f"{kind}:runner",
            session=f"{kind}:session",
            mode=mode,
            interval=None if mode == "manual" else 10,
            max_cycles=1 if mode == "manual" else 3,
            task_sha256=hashlib.sha256(task.encode()).hexdigest(),
        )
        return Instruction.from_dict(values), task

    def test_signing_and_trust_material_never_enters_runner_or_challenge_state(
        self,
    ) -> None:
        instruction, task = self.instruction("codex")
        display = self.operator.prepare_review_now(
            self.turn("custody-prepare"), "codex", instruction, task
        )
        private = self.key.private_bytes_raw()
        public = self.key.public_key().public_bytes_raw()
        challenge_bytes = (self.root / "human-challenges.sqlite").read_bytes()
        self.assertNotIn(private, challenge_bytes)
        self.assertNotIn(public, challenge_bytes)
        runner = self.operator.bindings["codex"][1].runner
        self.assertNotIn("sign", repr(vars(runner)).lower())
        self.assertNotIn("trust", repr(vars(runner)).lower())
        self.assertEqual(display["payload"], instruction.to_dict())

    def test_untrusted_origins_stale_and_changed_authority_never_execute(self) -> None:
        instruction, task = self.instruction("codex", mode="periodic")
        unauthenticated = HumanTurn(
            principal="human:test",
            turn_id="bad-auth",
            origin="direct-human",
            authentication="invalid",
        )
        with self.assertRaisesRegex(ExecutionDenied, "direct human"):
            self.operator.prepare_finite_periodic(
                unauthenticated, "codex", instruction, task
            )
        for origin in ("quote", "forward", "incoming", "bot", "peer"):
            with (
                self.subTest(origin=origin),
                self.assertRaisesRegex(ExecutionDenied, "direct human"),
            ):
                self.operator.prepare_finite_periodic(
                    self.turn(f"origin-{origin}", origin), "codex", instruction, task
                )
        display = self.operator.prepare_finite_periodic(
            self.turn("immutable-prepare"), "codex", instruction, task
        )
        assert instruction.interval is not None
        mutations = (
            {
                "scope": instruction.to_dict()["scope"]
                + [
                    {
                        "channel": "other",
                        "thread": "other",
                        "tool": "messaging_inbox",
                        "action": "review",
                    }
                ]
            },
            {"end": instruction.end + 1},
            {"interval": instruction.interval + 1},
        )
        for mutation in mutations:
            changed = {**display, "payload": display["payload"] | mutation}
            with (
                self.subTest(mutation=mutation),
                self.assertRaisesRegex(ExecutionDenied, "display changed"),
            ):
                self.operator.confirm(
                    self.turn("immutable-confirm"), display["challenge_id"], changed
                )
        self.assertEqual(self.counters["codex"], 0)
        self.assertEqual(
            self.operator.status(self.turn("pending-status"), "codex")[0]["state"],
            "pending",
        )

        stale_instruction, stale_task = self.instruction("hermes")
        stale = self.operator.prepare_review_now(
            self.turn("stale-prepare"), "hermes", stale_instruction, stale_task
        )
        self.clock.now += 120
        with self.assertRaisesRegex(ExecutionDenied, "stale"):
            self.operator.confirm(
                self.turn("stale-confirm"), stale["challenge_id"], stale
            )
        self.assertEqual(self.counters["hermes"], 0)

    def test_finite_periodic_status_and_signed_cancellation_for_both_runners(
        self,
    ) -> None:
        for index, kind in enumerate(("codex", "hermes"), 1):
            with self.subTest(kind=kind):
                self.clock.now = 110 + index
                instruction, task = self.instruction(kind, mode="periodic")
                display = self.operator.prepare_finite_periodic(
                    self.turn(f"periodic-prepare-{kind}"), kind, instruction, task
                )
                status = self.operator.confirm(
                    self.turn(f"periodic-confirm-{kind}"),
                    display["challenge_id"],
                    display,
                )
                self.assertEqual(status["state"], "active")
                self.assertEqual(status["end"], 200)
                self.assertEqual(status["interval"], 10)
                self.assertEqual(
                    self.operator.status(self.turn(f"status-{kind}"), kind)[0]["state"],
                    "active",
                )
                cancel = self.operator.prepare_cancel(
                    self.turn(f"cancel-prepare-{kind}"),
                    kind,
                    instruction.instruction_id,
                    1,
                )
                changed_cancel = {
                    **cancel,
                    "payload": cancel["payload"] | {"revision": 2},
                }
                with self.assertRaisesRegex(ExecutionDenied, "display changed"):
                    self.operator.confirm_cancel(
                        self.turn(f"cancel-changed-{kind}"),
                        cancel["challenge_id"],
                        changed_cancel,
                    )
                cancelled = self.operator.confirm_cancel(
                    self.turn(f"cancel-confirm-{kind}"), cancel["challenge_id"], cancel
                )
                self.assertEqual(
                    cancelled,
                    {
                        "instruction_id": "review-1",
                        "revision": 1,
                        "state": "cancelled",
                        "interruption": "stopped",
                        "cycles": [],
                    },
                )
                self.assertEqual(self.counters[kind], 0)

    def test_review_now_uses_immutable_single_use_challenge_for_both_runners(
        self,
    ) -> None:
        for index, kind in enumerate(("codex", "hermes"), 1):
            with self.subTest(kind=kind):
                self.clock.now = 100 + index
                instruction, task = self.instruction(kind)
                display = self.operator.prepare_review_now(
                    self.turn(f"prepare-{kind}"), kind, instruction, task
                )
                self.assertEqual(display["operation"], "review-now")
                self.assertEqual(display["runner_type"], kind)
                self.assertEqual(display["payload"], instruction.to_dict())
                self.assertEqual(display["task"], task)
                context = self.operator.confirm(
                    self.turn(f"confirm-{kind}"), display["challenge_id"], display
                )
                self.assertIsNotNone(context)
                self.assertEqual(self.counters[kind], 1)
                with self.assertRaisesRegex(ExecutionDenied, "replay"):
                    self.operator.confirm(
                        self.turn(f"replay-{kind}"), display["challenge_id"], display
                    )

    def test_signed_cancel_during_blocked_start_finds_registered_context(self) -> None:
        instruction, task = self.instruction("codex")
        store, controller = self.operator.bindings["codex"]
        runner = controller.runner
        start_entered = threading.Event()
        start_release = threading.Event()
        cancel_entered = threading.Event()
        interrupts = []

        def blocked_start(self, request, context, timeout):
            start_entered.set()
            if not start_release.wait(5):
                raise ExecutionDenied("test start barrier timeout")

        def interrupt(self, cycle_id, timeout):
            interrupts.append((cycle_id, timeout))
            return "stopped"

        runner.start = MethodType(blocked_start, runner)
        runner.interrupt = MethodType(interrupt, runner)
        original_cancel = store.cancel

        def observed_cancel(identity, revision, signature):
            cancel_entered.set()
            return original_cancel(identity, revision, signature)

        store.cancel = observed_cancel
        display = self.operator.prepare_review_now(
            self.turn("race-prepare"), "codex", instruction, task
        )
        with ThreadPoolExecutor(max_workers=2) as pool:
            confirm = pool.submit(
                self.operator.confirm,
                self.turn("race-confirm"),
                display["challenge_id"],
                display,
            )
            self.assertTrue(start_entered.wait(2))
            cancel = self.operator.prepare_cancel(
                self.turn("race-cancel-prepare"), "codex", "review-1", 1
            )
            cancelling = pool.submit(
                self.operator.confirm_cancel,
                self.turn("race-cancel-confirm"),
                cancel["challenge_id"],
                cancel,
            )
            self.assertTrue(cancel_entered.wait(2))
            self.assertFalse(cancelling.done())
            start_release.set()
            context = confirm.result(3)
            result = cancelling.result(3)

        self.assertEqual(result["interruption"], "stopped")
        self.assertEqual(result["cycles"], [context.cycle.cycle_id])
        self.assertEqual(len(interrupts), 1)
        self.assertEqual(interrupts[0][0], context.cycle.cycle_id)
        self.assertGreater(interrupts[0][1], 0)
        self.assertLessEqual(interrupts[0][1], instruction.cleanup_seconds)
        self.assertEqual(store.status("review-1", 1)["state"], "cancelled")
        self.assertEqual(store.cycle_status(context.cycle.cycle_id)["state"], "stopped")

    def test_restart_cancel_reports_unowned_durable_cycle_unknown(self) -> None:
        instruction, task = self.instruction("codex")
        store, _ = self.operator.bindings["codex"]
        display = self.operator.prepare_review_now(
            self.turn("restart-prepare"), "codex", instruction, task
        )
        context = self.operator.confirm(
            self.turn("restart-confirm"), display["challenge_id"], display
        )
        self.assertIsNotNone(context)
        assert not isinstance(context, dict)

        restarted = ReviewController(
            store,
            self.runner("codex", instruction.binding),
            Broker(),
            monotonic=lambda: 10.0,
        )
        self.operator.bindings["codex"] = (store, restarted)
        cancel = self.operator.prepare_cancel(
            self.turn("restart-cancel-prepare"), "codex", "review-1", 1
        )
        result = self.operator.confirm_cancel(
            self.turn("restart-cancel-confirm"), cancel["challenge_id"], cancel
        )

        self.assertEqual(result["interruption"], "unknown")
        self.assertEqual(result["cycles"], [context.cycle.cycle_id])
        self.assertEqual(store.cycle_status(context.cycle.cycle_id)["state"], "intent")

    def test_restart_cancel_reports_unowned_ambiguous_cycle_unknown(self) -> None:
        instruction, task = self.instruction("hermes")
        store, _ = self.operator.bindings["hermes"]
        display = self.operator.prepare_review_now(
            self.turn("ambiguous-prepare"), "hermes", instruction, task
        )
        context = self.operator.confirm(
            self.turn("ambiguous-confirm"), display["challenge_id"], display
        )
        self.assertIsNotNone(context)
        assert not isinstance(context, dict)
        store.mark_ambiguous(context.cycle)

        restarted = ReviewController(
            store,
            self.runner("hermes", instruction.binding),
            Broker(),
            monotonic=lambda: 10.0,
        )
        self.operator.bindings["hermes"] = (store, restarted)
        cancel = self.operator.prepare_cancel(
            self.turn("ambiguous-cancel-prepare"), "hermes", "review-1", 1
        )
        result = self.operator.confirm_cancel(
            self.turn("ambiguous-cancel-confirm"), cancel["challenge_id"], cancel
        )

        self.assertEqual(result["interruption"], "unknown")
        self.assertEqual(result["cycles"], [context.cycle.cycle_id])
        self.assertEqual(
            store.cycle_status(context.cycle.cycle_id)["state"], "ambiguous"
        )

    def test_restart_cancel_finds_unowned_nonterminal_among_exact_cycles(self) -> None:
        instruction, task = self.instruction("codex", mode="periodic")
        store, controller = self.operator.bindings["codex"]
        display = self.operator.prepare_finite_periodic(
            self.turn("multi-prepare"), "codex", instruction, task
        )
        self.operator.confirm(
            self.turn("multi-confirm"), display["challenge_id"], display
        )
        completed = controller.run_due_once("review-1", 1, task)
        self.assertIsNotNone(completed)
        assert completed is not None
        completed._finish("completed")
        self.clock.now = 110
        unowned = controller.run_due_once("review-1", 1, task)
        self.assertIsNotNone(unowned)
        assert unowned is not None

        restarted = ReviewController(
            store,
            self.runner("codex", instruction.binding),
            Broker(),
            monotonic=lambda: 10.0,
        )
        self.operator.bindings["codex"] = (store, restarted)
        cancel = self.operator.prepare_cancel(
            self.turn("multi-cancel-prepare"), "codex", "review-1", 1
        )
        result = self.operator.confirm_cancel(
            self.turn("multi-cancel-confirm"), cancel["challenge_id"], cancel
        )

        self.assertEqual(result["interruption"], "unknown")
        self.assertEqual(result["cycles"], [unowned.cycle.cycle_id])
        self.assertEqual(
            store.cycle_status(completed.cycle.cycle_id)["state"], "completed"
        )
        self.assertEqual(store.cycle_status(unowned.cycle.cycle_id)["state"], "intent")

    def test_restart_cancel_returns_stopped_when_all_exact_cycles_terminal(
        self,
    ) -> None:
        instruction, task = self.instruction("hermes", mode="periodic")
        instruction = Instruction.from_dict(instruction.to_dict() | {"max_cycles": 2})
        store, controller = self.operator.bindings["hermes"]
        display = self.operator.prepare_finite_periodic(
            self.turn("terminal-prepare"), "hermes", instruction, task
        )
        self.operator.confirm(
            self.turn("terminal-confirm"), display["challenge_id"], display
        )
        completed = controller.run_due_once("review-1", 1, task)
        self.assertIsNotNone(completed)
        assert completed is not None
        completed._finish("completed")
        self.clock.now = 110
        stopped = controller.run_due_once("review-1", 1, task)
        self.assertIsNotNone(stopped)
        assert stopped is not None
        stopped._finish("stopped")

        restarted = ReviewController(
            store,
            self.runner("hermes", instruction.binding),
            Broker(),
            monotonic=lambda: 10.0,
        )
        self.operator.bindings["hermes"] = (store, restarted)
        cancel = self.operator.prepare_cancel(
            self.turn("terminal-cancel-prepare"), "hermes", "review-1", 1
        )
        result = self.operator.confirm_cancel(
            self.turn("terminal-cancel-confirm"), cancel["challenge_id"], cancel
        )

        self.assertEqual(result["interruption"], "stopped")
        self.assertEqual(result["cycles"], [])

    def test_cancel_ignores_unrelated_instruction_and_revision_cycles(self) -> None:
        target, task = self.instruction("codex", mode="periodic")
        store, controller = self.operator.bindings["codex"]
        display = self.operator.prepare_finite_periodic(
            self.turn("unrelated-prepare"), "codex", target, task
        )
        self.operator.confirm(
            self.turn("unrelated-confirm"), display["challenge_id"], display
        )
        old_revision = controller.run_due_once("review-1", 1, task)
        self.assertIsNotNone(old_revision)
        assert old_revision is not None
        successor = Instruction.from_dict(
            target.to_dict()
            | {
                "revision": 2,
                "predecessor": target.sha256,
                "start": 100,
                "end": 200,
            }
        )
        store.approve(
            successor,
            proof(self.key, "approve", successor.to_dict(), "successor-approval"),
        )
        unrelated = Instruction.from_dict(
            request(
                store_id=store.store_id,
                instruction_id="other",
                runner="other:runner",
                session="other:session",
                task_sha256=hashlib.sha256(b"Other task").hexdigest(),
            )
        )
        store.approve(
            unrelated,
            proof(self.key, "approve", unrelated.to_dict(), "other-approval"),
        )
        other_cycle = store.reserve("other", 1, unrelated.binding)
        self.assertIsNotNone(other_cycle)

        cancel = self.operator.prepare_cancel(
            self.turn("unrelated-cancel-prepare"), "codex", "review-1", 2
        )
        result = self.operator.confirm_cancel(
            self.turn("unrelated-cancel-confirm"), cancel["challenge_id"], cancel
        )

        self.assertEqual(result["interruption"], "stopped")
        self.assertEqual(result["cycles"], [])
        self.assertEqual(
            store.cycle_status(old_revision.cycle.cycle_id)["state"], "intent"
        )
        assert other_cycle is not None
        self.assertEqual(store.cycle_status(other_cycle.cycle_id)["state"], "intent")


if __name__ == "__main__":
    unittest.main()
