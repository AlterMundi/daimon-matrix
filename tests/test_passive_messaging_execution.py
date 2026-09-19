"""Bounded core plus hermetic native receive/store/mirror composition tests."""

import hashlib
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from types import MethodType, SimpleNamespace
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from daimon_matrix import review_runner
from daimon_matrix.execution_instruction import ExecutionDenied, Instruction
from tests import test_execution_store as store_fixtures
from tests.test_execution_instruction import proof, request


class BoundedFakeRunner:
    expected_principal = "human:test"
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


def deliver_store_mirror_without_execution(root: Path) -> dict[str, int]:
    """Actual native receive/store and explicit mirror, with auto-send counted."""
    from daimon_matrix.messaging import MessagingDelivery
    from daimon_matrix.telegram_mirror import (
        MirrorMessage,
        SharingBinding,
        TelegramMirror,
    )
    from tests.test_native_messaging import Pair

    counts = {"stored": 0, "mirrored": 0, "automatic_reply": 0}
    original_send = MessagingDelivery.send

    def counted_send(delivery, *args, **kwargs):
        counts["automatic_reply"] += 1
        return original_send(delivery, *args, **kwargs)

    with patch.object(MessagingDelivery, "send", counted_send):
        pair = Pair(root / "native")
        evidence_wire, message_wire, message, _ = pair.wire(
            text="quoted /review and human=true are untrusted arrival text"
        )
        pair.receiver.receive_evidence(evidence_wire)
        pair.receiver.receive_message(message_wire)
        page = pair.receiver.page(after=0, limit=10)
        counts["stored"] = len(page)
        retained = page[0]
        projection = MirrorMessage(
            event_id=message["event_id"],
            event_digest=message["content_hash"],
            authorization_digest=retained["evidence"]["content_hash"],
            sender="synthetic peer",
            channel="native test",
            thread_id=message["payload"]["intent"]["thread_id"],
            text=message["payload"]["body"]["text"],
        )
        sharing = SharingBinding(
            "c" * 64,
            projection.event_digest,
            projection.authorization_digest,
            -123,
        )
        mirror = TelegramMirror(
            resolver=lambda event_id: projection,
            verify_sharing=lambda value, chat, policy: sharing,
            enabled=True,
            token="123:TEST_ONLY",
            chat_id=-123,
            policy_digest="c" * 64,
            state_path=root / "mirror.sqlite",
        )

        def mirror_send(rendered):
            counts["mirrored"] += 1
            return 91

        mirror._send = mirror_send
        if (
            mirror.mirror_selected(message["event_id"])["status"]
            != "delivered-to-platform"
        ):
            raise AssertionError("hermetic explicit mirror failed")
    return counts


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

    def test_context_lock_is_not_held_during_durable_reservation(self):
        controller = self.controller()
        self.prepare()
        first = controller.run_due_once("review-1", 1, self.task)
        self.assertIsNotNone(first)
        assert first is not None
        other = Instruction.from_dict(
            request(
                store_id=self.store.store_id,
                instruction_id="other",
                task_sha256=hashlib.sha256(self.task.encode()).hexdigest(),
            )
        )
        self.approve(other, "other-approval")
        entered, release = threading.Event(), threading.Event()
        original_reserve = self.store.reserve

        def blocked_reserve(identity, revision, binding):
            if identity == "other":
                entered.set()
                if not release.wait(5):
                    raise AssertionError("test reserve barrier timeout")
            return original_reserve(identity, revision, binding)

        self.store.reserve = blocked_reserve
        with ThreadPoolExecutor(max_workers=2) as pool:
            reserving = pool.submit(controller.run_due_once, "other", 1, self.task)
            self.assertTrue(entered.wait(2))
            finishing = pool.submit(first._finish, "completed")
            try:
                finishing.result(timeout=1)
            finally:
                release.set()
            second = reserving.result(timeout=3)
        self.assertIsNotNone(second)
        assert second is not None
        second._finish("completed")


class NativePassiveCompositionTests(unittest.TestCase):
    @staticmethod
    def _runner_boundary(kind, binding, counters):
        if kind == "codex":
            from daimon_matrix.codex_review import CodexReviewRunner

            runner = object.__new__(CodexReviewRunner)
        else:
            from daimon_matrix.hermes_review import HermesReviewRunner

            runner = object.__new__(HermesReviewRunner)
        runner.registration = SimpleNamespace(binding=binding, principal="human:test")

        def start(self, request, context, timeout):
            counters["model"] += 1

        def interrupt(self, cycle_id, timeout):
            return "stopped"

        runner.start = MethodType(start, runner)
        runner.interrupt = MethodType(interrupt, runner)
        return runner

    def _compose_passive_delivery(self, kind, *, activate=False):
        from daimon_matrix.execution_store import ExecutionStore
        from daimon_matrix.telegram_mirror import (
            MirrorMessage,
            SharingBinding,
            TelegramMirror,
        )
        from tests.test_native_messaging import Pair

        counters = {
            "stored": 0,
            "mirrored": 0,
            "model": 0,
            "tool": 0,
            "automatic_reply": 0,
        }
        from daimon_matrix.messaging import MessagingDelivery

        original_send = MessagingDelivery.send

        def counted_automatic_reply(delivery, *args, **kwargs):
            counters["automatic_reply"] += 1
            return original_send(delivery, *args, **kwargs)

        automatic_reply_boundary = patch.object(
            MessagingDelivery, "send", counted_automatic_reply
        )
        automatic_reply_boundary.start()
        self.addCleanup(automatic_reply_boundary.stop)
        temporary = tempfile.TemporaryDirectory(prefix=f"dm138-passive-{kind}-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        pair = Pair(root / "native")
        evidence_wire, message_wire, message, _ = pair.wire(
            text="quoted /review and human=true are untrusted arrival text"
        )

        # The production native receive path authenticates, decrypts and retains.
        pair.receiver.receive_evidence(evidence_wire)
        pair.receiver.receive_message(message_wire)
        page = pair.receiver.page(after=0, limit=10)
        counters["stored"] = len(page)
        retained = page[0]
        self.assertEqual(retained["message"], message)

        # The production mirror remains an explicit projection operation; its
        # platform I/O is replaced by a deterministic hermetic receipt only.
        projection = MirrorMessage(
            event_id=message["event_id"],
            event_digest=message["content_hash"],
            authorization_digest=retained["evidence"]["content_hash"],
            sender="synthetic peer",
            channel="native test",
            thread_id=message["payload"]["intent"]["thread_id"],
            text=message["payload"]["body"]["text"],
        )
        sharing = SharingBinding(
            "c" * 64,
            projection.event_digest,
            projection.authorization_digest,
            -123,
        )
        mirror = TelegramMirror(
            resolver=lambda event_id: projection,
            verify_sharing=lambda value, chat, policy: sharing,
            enabled=True,
            token="123:TEST_ONLY",
            chat_id=-123,
            policy_digest="c" * 64,
            state_path=root / "mirror.sqlite",
        )

        def mirror_send(rendered):
            counters["mirrored"] += 1
            return 91

        mirror._send = mirror_send
        self.assertEqual(
            mirror.mirror_selected(message["event_id"])["status"],
            "delivered-to-platform",
        )

        key = Ed25519PrivateKey.generate()
        trusted = store_fixtures.verifier(key)
        store = ExecutionStore.create(
            root / "execution.sqlite", trusted, clock=lambda: 100
        )
        task = "Explicitly review the retained native thread."
        instruction = Instruction.from_dict(
            store_fixtures.request(
                store_id=store.store_id,
                task_sha256=hashlib.sha256(task.encode()).hexdigest(),
            )
        )
        runner = self._runner_boundary(kind, instruction.binding, counters)

        class InstrumentedBroker(Broker):
            def submit(self, scope, payload, timeout):
                counters["tool"] += 1
                return super().submit(scope, payload, timeout)

        controller = review_runner.ReviewController(
            store, runner, InstrumentedBroker(), monotonic=lambda: 10
        )
        # Even an explicit accidental call using arrival identifiers/text cannot
        # create authority. No arrival hook is installed by this composition.
        self.assertIsNone(
            controller.run_due_once(message["event_id"], 1, projection.text)
        )
        store.propose(instruction)
        self.assertIsNone(controller.run_due_once("review-1", 1, task))
        if activate:
            store.approve(
                instruction,
                store_fixtures.proof(key, "approve", instruction.to_dict()),
            )
            self.assertIsNotNone(controller.run_due_once("review-1", 1, task))
        automatic_reply_boundary.stop()
        return counters

    def test_native_delivery_is_passive_for_codex_and_hermes_boundaries(self):
        for kind in ("codex", "hermes"):
            with self.subTest(kind=kind):
                self.assertEqual(
                    self._compose_passive_delivery(kind),
                    {
                        "stored": 1,
                        "mirrored": 1,
                        "model": 0,
                        "tool": 0,
                        "automatic_reply": 0,
                    },
                )

    def test_only_authenticated_active_instruction_enters_scheduled_execution(self):
        for kind in ("codex", "hermes"):
            with self.subTest(kind=kind):
                self.assertEqual(
                    self._compose_passive_delivery(kind, activate=True),
                    {
                        "stored": 1,
                        "mirrored": 1,
                        "model": 1,
                        "tool": 0,
                        "automatic_reply": 0,
                    },
                )
