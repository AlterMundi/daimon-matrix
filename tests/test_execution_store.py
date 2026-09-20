"""Real SQLite + synthetic signing authority; no services or models."""

import hashlib
import multiprocessing
import sqlite3
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
from threading import Barrier
from typing import Literal

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from daimon_matrix import execution_store
from daimon_matrix.execution_instruction import ExecutionDenied, Instruction
from daimon_matrix.execution_store import ExecutionStore
from daimon_matrix.review_runner import ReviewController
from tests.test_execution_instruction import proof, request, verifier


class Clock:
    def __init__(self):
        self.now = 100.0

    def __call__(self):
        return self.now


def reserve_child(path, trust, store_id, barrier, result):
    store = execution_store.ExecutionStore(path, trust, clock=lambda: 100)
    instruction = Instruction.from_dict(request(store_id=store_id))
    barrier.wait(timeout=10)
    cycle = store.reserve("review-1", 1, instruction.binding)
    result.put(cycle.cycle_id if cycle else None)


def crash_child(path, trust, store_id, pipe):
    import os

    store = execution_store.ExecutionStore(path, trust, clock=lambda: 100)
    instruction = Instruction.from_dict(request(store_id=store_id))
    cycle = store.reserve("review-1", 1, instruction.binding)
    pipe.send(cycle.cycle_id)
    pipe.close()
    store.dispatch(cycle, "inference", None, lambda: None, lambda: os._exit(17))


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "execution.sqlite"
        self.key = Ed25519PrivateKey.generate()
        self.clock = Clock()
        self.store = execution_store.ExecutionStore.create(
            self.path, verifier(self.key), clock=self.clock
        )
        self.instruction = Instruction.from_dict(request(store_id=self.store.store_id))

    def approve(self, instruction=None, event="approval-1"):
        i = instruction or self.instruction
        self.store.approve(i, proof(self.key, "approve", i.to_dict(), event))

    def reopen(self):
        return execution_store.ExecutionStore(
            self.path, verifier(self.key), clock=self.clock
        )

    def test_proposal_is_passive_and_signed_approval_survives_reopen(self):
        self.store.propose(self.instruction)
        self.assertEqual(self.store.status("review-1")["state"], "pending")
        self.assertIsNone(self.store.reserve("review-1", 1, self.instruction.binding))
        self.approve()
        reopened = self.reopen()
        self.assertEqual(reopened.status("review-1")["state"], "active")
        with self.assertRaises(ExecutionDenied):
            self.approve()
        wrong = Instruction.from_dict(request(store_id="wrong-store"))
        with self.assertRaises(ExecutionDenied):
            self.approve(wrong, "wrong-store-event")
        with self.assertRaises(ExecutionDenied):
            execution_store.ExecutionStore(
                Path(self.tmp.name) / "missing", verifier(self.key)
            )

    def test_signed_cancellation_tombstone_and_explicit_renewal(self):
        self.approve()
        payload = self.store.cancellation_payload("review-1", 1)
        with self.assertRaises(ExecutionDenied):
            self.store.cancel("review-1", 1, {"human": True})
        self.store.cancel("review-1", 1, proof(self.key, "cancel", payload, "cancel-1"))
        self.assertEqual(self.reopen().status("review-1")["state"], "cancelled")
        self.assertIsNone(self.store.reserve("review-1", 1, self.instruction.binding))
        renewed = Instruction.from_dict(
            request(
                store_id=self.store.store_id,
                revision=2,
                predecessor=self.instruction.sha256,
                start=110,
                end=210,
            )
        )
        self.approve(renewed, "approval-2")
        self.clock.now = 110
        self.assertEqual(self.store.status("review-1")["revision"], 2)
        self.assertIsNone(self.store.reserve("review-1", 1, self.instruction.binding))
        self.assertEqual(self.store.status("review-1", 1)["state"], "cancelled")

    def test_durable_reservation_no_catchup_and_no_ambiguous_retry(self):
        self.approve()
        self.assertIsNone(self.store.reserve("review-1", 1, ("wrong",) * 4))
        cycle = self.store.reserve("review-1", 1, self.instruction.binding)
        self.assertIsNotNone(cycle)
        self.assertEqual(cycle.slot, 0)
        self.assertEqual(cycle.deadline, 108)
        self.assertIsNone(
            self.reopen().reserve("review-1", 1, self.instruction.binding)
        )
        self.clock.now = 150
        self.assertIsNone(
            self.reopen().reserve("review-1", 1, self.instruction.binding)
        )
        self.store.mark_ambiguous(cycle)
        self.assertEqual(
            self.reopen().cycle_status(cycle.cycle_id)["state"], "ambiguous"
        )
        self.assertIsNone(
            self.reopen().reserve("review-1", 1, self.instruction.binding)
        )
        # Trusted adapter reconciliation must prove stopped; elapsed time is not proof.
        self.store.finish(cycle, "stopped")
        next_cycle = self.store.reserve("review-1", 1, self.instruction.binding)
        self.assertEqual(next_cycle.slot, 5)
        self.store.finish(next_cycle, "completed")
        self.assertIsNone(self.store.reserve("review-1", 1, self.instruction.binding))
        self.clock.now = 200
        self.assertIsNone(self.store.reserve("review-1", 1, self.instruction.binding))
        self.assertEqual(self.store.status("review-1")["state"], "expired")

    def test_multiprocess_single_flight_and_manual_periodic_share_session(self):
        self.approve()
        ctx = multiprocessing.get_context("fork")
        barrier, result = ctx.Barrier(2), ctx.Queue()
        processes = [
            ctx.Process(
                target=reserve_child,
                args=(
                    self.path,
                    verifier(self.key),
                    self.store.store_id,
                    barrier,
                    result,
                ),
            )
            for _ in range(2)
        ]
        for process in processes:
            process.start()
        for process in processes:
            process.join(timeout=15)
            self.assertEqual(process.exitcode, 0)
        self.assertEqual(sum(result.get(timeout=2) is not None for _ in range(2)), 1)
        manual = Instruction.from_dict(
            request(
                store_id=self.store.store_id,
                instruction_id="manual",
                mode="manual",
                interval=None,
                max_cycles=1,
            )
        )
        self.approve(manual, "manual-approval")
        self.assertIsNone(self.store.reserve("manual", 1, manual.binding))
        self.assertIsNone(self.store.status("manual")["next_eligible_slot"])

    def test_operator_cli_proposal_approval_status_cancel_and_renew(self):
        import contextlib
        import io
        import json

        from daimon_matrix import operator_execution

        trust = Path(self.tmp.name) / "public-trust.json"
        trust.write_text(
            json.dumps({"human:test": self.key.public_key().public_bytes_raw().hex()})
        )
        proposal = Path(self.tmp.name) / "proposal.json"
        proposal.write_text(json.dumps(self.instruction.to_dict()))
        approval = Path(self.tmp.name) / "approval.json"
        approval.write_text(
            json.dumps(proof(self.key, "approve", self.instruction.to_dict()))
        )
        base = ["--store", str(self.path), "--trust", str(trust)]

        def run(*args):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(
                    operator_execution.main([*base, *args], clock=self.clock), 0
                )
            return json.loads(output.getvalue())

        self.assertEqual(
            run("status")["summary"], "passive inbox; no agent review scheduled"
        )
        run("propose", str(proposal))
        self.assertEqual(run("status")["instructions"][0]["state"], "pending")
        run("approve", str(proposal), str(approval))
        self.assertEqual(run("status")["instructions"][0]["state"], "active")
        active_status = self.store.status("review-1")
        from jsonschema import Draft202012Validator

        schema = json.loads(
            (
                Path(__file__).resolve().parents[1]
                / "schemas/execution/v1/instruction.schema.json"
            ).read_text()
        )
        Draft202012Validator(schema["$defs"]["status"]).validate(active_status)
        payload = run("cancellation-payload", "review-1", "1")
        Draft202012Validator(schema["$defs"]["cancellation"]).validate(payload)
        approval.write_text(
            json.dumps(proof(self.key, "cancel", payload, "cli-cancel"))
        )
        run("cancel", "review-1", "1", str(approval))
        renewed = Instruction.from_dict(
            request(
                store_id=self.store.store_id,
                revision=2,
                predecessor=self.instruction.sha256,
            )
        )
        proposal.write_text(json.dumps(renewed.to_dict()))
        approval.write_text(
            json.dumps(proof(self.key, "approve", renewed.to_dict(), "cli-renew"))
        )
        run("renew", str(proposal), str(approval))
        self.assertEqual(run("status")["instructions"][-1]["revision"], 2)

    def test_real_process_crash_preserves_visible_dispatch_uncertainty(self):
        self.approve()
        ctx = multiprocessing.get_context("fork")
        receive, send = ctx.Pipe(duplex=False)
        child = ctx.Process(
            target=crash_child,
            args=(self.path, verifier(self.key), self.store.store_id, send),
        )
        child.start()
        self.assertTrue(receive.poll(10))
        cycle_id = receive.recv()
        child.join(timeout=10)
        self.assertEqual(child.exitcode, 17)
        send.close()
        receive.close()
        status = self.reopen().cycle_status(cycle_id)
        self.assertEqual(status["state"], "intent")
        self.assertEqual(status["operations"][0]["state"], "intent")
        self.clock.now = 190
        self.assertIsNone(
            self.reopen().reserve("review-1", 1, self.instruction.binding)
        )

    def test_cancellation_serializes_against_bounded_submission(self):
        from concurrent.futures import ThreadPoolExecutor
        from threading import Event

        self.approve()
        cycle = self.store.reserve("review-1", 1, self.instruction.binding)
        entered, release, cancel_started = Event(), Event(), Event()
        cancellation = proof(
            self.key,
            "cancel",
            self.store.cancellation_payload("review-1", 1),
            "cancel-race",
        )

        def submit():
            entered.set()
            self.assertTrue(release.wait(3))

        def cancel():
            cancel_started.set()
            self.store.cancel("review-1", 1, cancellation)

        with ThreadPoolExecutor(max_workers=2) as pool:
            dispatch = pool.submit(
                self.store.dispatch, cycle, "inference", None, lambda: None, submit
            )
            self.assertTrue(entered.wait(3))
            cancellation_done = pool.submit(cancel)
            self.assertTrue(cancel_started.wait(3))
            self.assertFalse(cancellation_done.done())
            release.set()
            dispatch.result(timeout=5)
            cancellation_done.result(timeout=5)
        with self.assertRaises(ExecutionDenied):
            self.store.check(cycle)

    def test_window_boundaries_manual_once_and_missing_trust(self):
        self.instruction = Instruction.from_dict(
            request(
                store_id=self.store.store_id,
                start=110,
                end=120,
                mode="manual",
                interval=None,
                max_cycles=1,
            )
        )
        with self.assertRaises(ExecutionDenied):
            self.store.approve(self.instruction, {"human": True})
        self.approve()
        self.assertIsNone(self.store.reserve("review-1", 1, self.instruction.binding))
        self.clock.now = 110
        cycle = self.store.reserve("review-1", 1, self.instruction.binding)
        self.assertIsNotNone(cycle)
        self.store.finish(cycle, "completed")
        self.assertEqual(self.store.status("review-1")["state"], "completed")
        self.clock.now = 119
        self.assertIsNone(self.store.reserve("review-1", 1, self.instruction.binding))
        self.clock.now = 120
        self.assertIsNone(self.store.reserve("review-1", 1, self.instruction.binding))
        from daimon_matrix.execution_instruction import ApprovalVerifier

        revoked = execution_store.ExecutionStore(
            self.path, ApprovalVerifier({}), clock=self.clock
        )
        with self.assertRaises(ExecutionDenied):
            revoked.get_instruction("review-1", 1)

    def test_tampered_persisted_payload_and_stale_renewal_rejected(self):
        import json
        import sqlite3
        from contextlib import closing

        self.approve()
        changed = Instruction.from_dict(request(store_id=self.store.store_id, end=201))
        with self.assertRaises(ExecutionDenied):
            self.store.approve(
                changed, proof(self.key, "approve", self.instruction.to_dict())
            )
        successor = Instruction.from_dict(
            request(
                store_id=self.store.store_id,
                revision=2,
                predecessor=self.instruction.sha256,
            )
        )
        self.approve(successor, "renew")
        self.assertIsNone(self.store.reserve("review-1", 1, self.instruction.binding))
        self.assertEqual(self.store.status("review-1", 1)["state"], "superseded")
        stale = Instruction.from_dict(
            request(
                store_id=self.store.store_id,
                revision=3,
                predecessor=self.instruction.sha256,
            )
        )
        with self.assertRaises(ExecutionDenied):
            self.approve(stale, "stale")
        with closing(sqlite3.connect(self.path)) as db:
            payload = successor.to_dict() | {"end": 300}
            db.execute(
                "UPDATE instructions SET payload=? WHERE revision=2",
                (json.dumps(payload),),
            )
            db.commit()
        with self.assertRaises(ExecutionDenied):
            self.reopen().reserve("review-1", 2, self.instruction.binding)

    def test_signed_cancel_still_reports_success_with_latched_clock_fault(self):
        self.approve()
        self.clock.now = 99
        with self.assertRaises(ExecutionDenied):
            self.store.reserve("review-1", 1, self.instruction.binding)
        receipt = self.store.cancel(
            "review-1",
            1,
            proof(
                self.key,
                "cancel",
                self.store.cancellation_payload("review-1", 1),
                "fault-cancel",
            ),
        )
        self.assertEqual(receipt["state"], "cancelled")
        self.assertEqual(receipt["revision"], 1)

    def test_clock_rollback_latches_across_reopen(self):
        self.approve()
        self.clock.now = 99
        with self.assertRaises(ExecutionDenied):
            self.store.reserve("review-1", 1, self.instruction.binding)
        self.clock.now = 101
        with self.assertRaises(ExecutionDenied):
            self.reopen().reserve("review-1", 1, self.instruction.binding)


class ReviewClock:
    now = 100.0
    mono = 10.0

    def __call__(self):
        return self.now


class ProbeRunner:
    expected_principal = "human:test"
    binding = ("being:test", "body:test", "runner:test", "session:test")

    def __init__(self):
        self.starts = []
        self.interrupts = []

    def start(self, request, context, timeout):
        self.starts.append((request, context, timeout))

    def interrupt(self, cycle_id, timeout) -> Literal["stopped", "unknown"]:
        self.interrupts.append((cycle_id, timeout))
        return "stopped"


class TimedProbeRunner(ProbeRunner):
    def __init__(self, outcome: Literal["stopped", "unknown"]):
        super().__init__()
        self.outcome: Literal["stopped", "unknown"] = outcome
        self.timed_interrupts = []

    def interrupt(self, cycle_id, timeout) -> Literal["stopped", "unknown"]:
        self.timed_interrupts.append((cycle_id, timeout, time.monotonic()))
        return self.outcome


class ProbeBroker:
    def __init__(self):
        self.calls = []

    def authorize(self, scope):
        return True

    def submit(self, scope, payload, timeout):
        self.calls.append((scope, dict(payload), timeout))
        return "submitted"


class IndependentReviewRegressions(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="issue138-independent-")
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "journal.sqlite"
        self.clock = ReviewClock()
        self.key = Ed25519PrivateKey.generate()
        self.trust = verifier(self.key)
        self.store = ExecutionStore.create(self.path, self.trust, clock=self.clock)
        self.task = "Review exactly the approved thread."
        self.i = self.instruction()
        self.approve(self.i)
        self.runner, self.broker = ProbeRunner(), ProbeBroker()
        self.controller = ReviewController(
            self.store, self.runner, self.broker, monotonic=lambda: self.clock.mono
        )

    def instruction(self, **changes):
        return Instruction.from_dict(
            request(
                **(
                    dict(
                        store_id=self.store.store_id,
                        task_sha256=hashlib.sha256(self.task.encode()).hexdigest(),
                    )
                    | changes
                )
            )
        )

    def approve(self, i, event="approval-1"):
        self.store.approve(i, proof(self.key, "approve", i.to_dict(), event))

    def start(self):
        context = self.controller.run_due_once("review-1", 1, self.task)
        self.assertIsNotNone(context)
        assert context is not None
        self.assertEqual(len(self.runner.starts), 1)
        return context

    def metadata(self):
        with closing(sqlite3.connect(self.path)) as db:
            return db.execute("SELECT high_water,clock_fault FROM metadata").fetchone()

    def test_invariant_store_denial_must_preserve_observed_high_water(self):
        cycle = self.store.reserve("review-1", 1, self.i.binding)
        self.assertEqual(cycle.deadline, 108)
        self.store.check(cycle)  # positive control
        self.clock.now = 108
        with self.assertRaises(ExecutionDenied):
            self.store.check(cycle)
        print("STORE_EXPIRED_CHECK_METADATA", self.metadata())
        self.clock.now = 107
        reopened = ExecutionStore(self.path, self.trust, clock=self.clock)
        with self.assertRaises(ExecutionDenied):
            reopened.check(cycle)

    def test_invariant_context_cannot_revive_after_observed_absolute_end(self):
        c = self.start()
        self.clock.now = 200  # instruction end; monotonic deadline not yet elapsed
        with self.assertRaises(ExecutionDenied):
            c.native(self.i.scope[0], {})
        self.assertEqual(self.broker.calls, [])
        print("CONTEXT_EXPIRED_METADATA", self.metadata())
        self.clock.now = 107
        self.clock.mono = 11
        denied = False
        try:
            c.native(self.i.scope[0], {"probe": "after-observed-end"})
        except ExecutionDenied:
            denied = True
        print("AFTER_ROLLBACK_NATIVE_CALLS", len(self.broker.calls), "DENIED", denied)
        self.assertTrue(
            denied, "Observed end must fence, including after wall rollback"
        )
        self.assertEqual(self.broker.calls, [])

    def test_invariant_missing_journal_must_not_prevent_exact_cycle_interrupt(self):
        c = self.start()
        self.path.unlink()  # only our disposable DB; no recovery or replacement
        self.clock.now = 108
        failure = None
        try:
            self.controller.enforce(c)
        except Exception as exc:
            failure = type(exc).__name__
        print("MISSING_JOURNAL_ENFORCE", failure, "INTERRUPTS", self.runner.interrupts)
        self.assertFalse(self.path.exists(), "Must not recreate journal")
        self.assertEqual(self.runner.interrupts, [(c.cycle.cycle_id, 2)])

    def test_positive_deadline_interrupt_and_terminal_no_repeat(self):
        c = self.start()
        self.clock.now = 108
        self.controller.enforce(c)
        self.controller.enforce(c)
        self.assertEqual(self.runner.interrupts, [(c.cycle.cycle_id, 2)])
        self.assertEqual(self.store.cycle_status(c.cycle.cycle_id)["state"], "stopped")
        with self.assertRaises(ExecutionDenied):
            c.native(self.i.scope[0], {})

    def test_cancel_cleanup_budget_includes_real_sqlite_write_lock(self):
        self.runner = TimedProbeRunner("unknown")
        self.controller = ReviewController(
            self.store, self.runner, self.broker, monotonic=time.monotonic
        )
        c = self.start()
        self.store.cancel(
            "review-1",
            1,
            proof(
                self.key,
                "cancel",
                self.store.cancellation_payload("review-1", 1),
                "cleanup-lock-cancel",
            ),
        )
        locked = threading.Event()

        def hold_write_lock():
            with closing(sqlite3.connect(self.path)) as db:
                db.execute("BEGIN IMMEDIATE")
                locked.set()
                time.sleep(1.2)
                db.rollback()

        budget = 1.0
        tolerance = 0.12
        with ThreadPoolExecutor(max_workers=1) as pool:
            holder = pool.submit(hold_write_lock)
            self.assertTrue(locked.wait(2), "SQLite write lock was not acquired")
            started = time.monotonic()
            result = self.controller.cancel_active("review-1", 1, budget)
            elapsed = time.monotonic() - started
            holder.result(timeout=3)

        self.assertEqual(result[0], "unknown")
        self.assertEqual(result[1], (c.cycle.cycle_id,))
        self.assertEqual(self.store.status("review-1", 1)["state"], "cancelled")
        self.assertEqual(len(self.runner.timed_interrupts), 1)
        _, interrupt_timeout, interrupted_at = self.runner.timed_interrupts[0]
        spent_before_interrupt = interrupted_at - started
        available_at_interrupt = max(0.0, budget - spent_before_interrupt)
        print(
            "CANCEL_LOCK_BUDGET_EVIDENCE",
            f"budget={budget:.6f}",
            f"elapsed={elapsed:.6f}",
            f"spent_before_interrupt={spent_before_interrupt:.6f}",
            f"interrupt_timeout={interrupt_timeout:.6f}",
            f"available_at_interrupt={available_at_interrupt:.6f}",
        )
        violations = []
        if elapsed > budget + tolerance:
            violations.append(
                f"elapsed {elapsed:.6f}s exceeded {budget:.6f}s budget + "
                f"{tolerance:.6f}s tolerance"
            )
        if interrupt_timeout > available_at_interrupt + 0.03:
            violations.append(
                f"interrupt received stale {interrupt_timeout:.6f}s timeout with only "
                f"{available_at_interrupt:.6f}s remaining"
            )
        self.assertEqual(violations, [], "; ".join(violations))

    def test_cancel_final_exact_audit_does_not_wait_for_sqlite_lock(self):
        c = self.start()
        self.store.cancel(
            "review-1",
            1,
            proof(
                self.key,
                "cancel",
                self.store.cancellation_payload("review-1", 1),
                "cleanup-audit-lock-cancel",
            ),
        )
        restarted = ReviewController(
            self.store, self.runner, self.broker, monotonic=time.monotonic
        )
        locked = threading.Event()

        def hold_exclusive_lock():
            with closing(sqlite3.connect(self.path)) as db:
                db.execute("BEGIN EXCLUSIVE")
                locked.set()
                time.sleep(1.2)
                db.rollback()

        budget = 1.0
        with ThreadPoolExecutor(max_workers=1) as pool:
            holder = pool.submit(hold_exclusive_lock)
            self.assertTrue(locked.wait(2), "SQLite exclusive lock was not acquired")
            started = time.monotonic()
            result = restarted.cancel_active("review-1", 1, budget)
            elapsed = time.monotonic() - started
            holder.result(timeout=3)

        self.assertEqual(result, ("unknown", ()))
        self.assertEqual(self.runner.interrupts, [])
        self.assertLessEqual(elapsed, budget + 0.12)
        self.assertEqual(self.store.status("review-1", 1)["state"], "cancelled")
        self.assertEqual(self.store.cycle_status(c.cycle.cycle_id)["state"], "intent")

    def test_cancel_large_terminal_history_finishes_final_audit_within_budget(self):
        history_size = 750_000
        instruction = self.instruction(
            instruction_id="large-history",
            end=1_000_000,
            interval=1,
            cleanup_seconds=1,
            max_cycles=history_size,
        )
        self.approve(instruction, "large-history-approval")
        with closing(sqlite3.connect(self.path)) as db:
            generation = db.execute(
                "SELECT generation FROM instructions WHERE id=? AND revision=?",
                (instruction.instruction_id, instruction.revision),
            ).fetchone()[0]
            db.execute(
                "WITH RECURSIVE history(slot) AS ("
                "VALUES(0) UNION ALL SELECT slot + 1 FROM history WHERE slot + 1 < ?"
                ") INSERT INTO cycles "
                "(cycle_id,id,revision,slot,binding,deadline,generation,"
                "token_hash,state,outcome) "
                "SELECT printf('terminal-%06d',slot),?,?,slot,?,108 + slot,?,"
                "printf('%064x',slot),"
                "CASE slot % 2 WHEN 0 THEN 'completed' ELSE 'stopped' END,"
                "CASE slot % 2 WHEN 0 THEN 'completed' ELSE 'stopped' END "
                "FROM history",
                (
                    history_size,
                    instruction.instruction_id,
                    instruction.revision,
                    execution_store.canonical(list(instruction.binding[2:])).decode(),
                    generation,
                ),
            )
            db.commit()
        self.store.cancel(
            instruction.instruction_id,
            instruction.revision,
            proof(
                self.key,
                "cancel",
                self.store.cancellation_payload(
                    instruction.instruction_id, instruction.revision
                ),
                "large-history-cancel",
            ),
        )
        restarted = ReviewController(
            self.store, self.runner, self.broker, monotonic=time.monotonic
        )

        budget = float(instruction.cleanup_seconds)
        started = time.monotonic()
        result = restarted.cancel_active(
            instruction.instruction_id, instruction.revision, budget
        )
        elapsed = time.monotonic() - started
        print(
            "LARGE_TERMINAL_HISTORY_AUDIT",
            f"rows={history_size}",
            f"budget={budget:.6f}",
            f"elapsed={elapsed:.6f}",
            f"result={result[0]}",
        )

        self.assertEqual(result, ("stopped", ()))
        self.assertLess(
            elapsed,
            budget,
            "final cancellation audit returned stopped after its shared deadline",
        )

    def test_cancel_final_audit_rechecks_expired_or_faulted_shared_deadline(self):
        self.store.cancel(
            "review-1",
            1,
            proof(
                self.key,
                "cancel",
                self.store.cancellation_payload("review-1", 1),
                "post-audit-deadline-cancel",
            ),
        )
        conditions = {
            "expired": 11.0,
            "nonfinite": float("nan"),
            "backward": 9.0,
            "unreadable": RuntimeError("monotonic unavailable"),
        }
        for condition, final_read in conditions.items():
            with self.subTest(condition=condition):
                reads = iter((10.0, 10.0, final_read))

                def monotonic(reads=reads):
                    value = next(reads)
                    if isinstance(value, Exception):
                        raise value
                    return value

                restarted = ReviewController(
                    self.store, self.runner, self.broker, monotonic=monotonic
                )
                self.assertEqual(
                    restarted.cancel_active("review-1", 1, 1.0), ("unknown", ())
                )

    def test_cancel_terminal_cycle_status_rechecks_shared_deadline(self):
        context = self.start()
        context._finish("completed")
        reads = iter((10.0, 10.0, 11.0))
        self.controller.monotonic = lambda: next(reads)

        self.assertEqual(self.controller.enforce(context, timeout=1.0), "unknown")
        self.assertEqual(
            self.store.cycle_status(context.cycle.cycle_id)["state"], "completed"
        )

    def test_cancel_finish_rechecks_shared_deadline_before_stopped(self):
        context = self.start()
        self.store.cancel(
            "review-1",
            1,
            proof(
                self.key,
                "cancel",
                self.store.cancellation_payload("review-1", 1),
                "post-finish-deadline-cancel",
            ),
        )
        reads = iter((10.0,) * 7 + (11.0,))
        self.controller.monotonic = lambda: next(reads)

        self.assertEqual(self.controller.enforce(context, timeout=1.0), "unknown")
        self.assertEqual(
            self.store.cycle_status(context.cycle.cycle_id)["state"], "stopped"
        )

    def test_cancel_cleanup_budget_unlocked_positive_control(self):
        self.runner = TimedProbeRunner("stopped")
        self.controller = ReviewController(
            self.store, self.runner, self.broker, monotonic=time.monotonic
        )
        c = self.start()
        self.store.cancel(
            "review-1",
            1,
            proof(
                self.key,
                "cancel",
                self.store.cancellation_payload("review-1", 1),
                "cleanup-unlocked-cancel",
            ),
        )
        budget = 1.0
        started = time.monotonic()
        result = self.controller.cancel_active("review-1", 1, budget)
        elapsed = time.monotonic() - started

        self.assertEqual(result, ("stopped", (c.cycle.cycle_id,)))
        self.assertEqual(self.store.cycle_status(c.cycle.cycle_id)["state"], "stopped")
        self.assertEqual(len(self.runner.timed_interrupts), 1)
        _, interrupt_timeout, interrupted_at = self.runner.timed_interrupts[0]
        available_at_interrupt = max(0.0, budget - (interrupted_at - started))
        self.assertGreater(interrupt_timeout, 0)
        self.assertLessEqual(interrupt_timeout, available_at_interrupt + 0.03)
        self.assertLessEqual(elapsed, 0.25)

    def test_cancel_exhausted_or_unreadable_budget_skips_cleanup(self):
        for condition in ("exhausted", "unreadable"):
            with self.subTest(condition=condition):
                if condition == "unreadable":
                    self.setUp()
                c = self.start()
                self.store.cancel(
                    "review-1",
                    1,
                    proof(
                        self.key,
                        "cancel",
                        self.store.cancellation_payload("review-1", 1),
                        f"cleanup-{condition}-cancel",
                    ),
                )
                timeout = 0.0
                if condition == "unreadable":
                    timeout = 1.0
                    self.controller.monotonic = lambda: float("nan")

                result = self.controller.cancel_active("review-1", 1, timeout)

                self.assertEqual(result, ("unknown", (c.cycle.cycle_id,)))
                self.assertEqual(self.runner.interrupts, [])
                self.assertEqual(
                    self.store.cycle_status(c.cycle.cycle_id)["state"], "intent"
                )
                self.assertEqual(self.store.status("review-1", 1)["state"], "cancelled")

    def test_positive_successful_time_observation_latches_later_rollback(self):
        c = self.start()
        self.clock.now = 105
        c.check()
        self.assertEqual(self.metadata(), (105.0, 0))
        self.clock.now = 104
        with self.assertRaises(ExecutionDenied):
            c.native(self.i.scope[0], {})
        self.assertEqual(self.metadata(), (105.0, 1))
        self.clock.now = 106
        with self.assertRaises(ExecutionDenied):
            ExecutionStore(self.path, self.trust, clock=self.clock).check(c.cycle)
        self.assertEqual(self.broker.calls, [])

    def test_cancellation_between_context_check_and_native_dispatch(self):
        c = self.start()
        cancel_proof = proof(
            self.key,
            "cancel",
            self.store.cancellation_payload("review-1", 1),
            "cancel-1",
        )

        def authorize(scope):
            self.store.cancel("review-1", 1, cancel_proof)
            return True

        self.broker.authorize = authorize  # external policy seam, not admission
        with self.assertRaises(ExecutionDenied):
            c.native(self.i.scope[0], {})
        self.assertEqual(self.broker.calls, [])
        self.assertEqual(self.store.status("review-1", 1)["state"], "cancelled")

    def test_real_sqlite_concurrent_native_budget(self):
        c = self.start()
        barrier = Barrier(4)

        def attempt(n):
            barrier.wait(timeout=5)
            try:
                c.native(self.i.scope[0], {"n": n})
                return True
            except ExecutionDenied:
                return False

        with ThreadPoolExecutor(max_workers=4) as pool:
            accepted = list(pool.map(attempt, range(4)))
        self.assertEqual(sum(accepted), 2)
        self.assertEqual(len(self.broker.calls), 2)
        self.assertEqual(
            len(self.store.cycle_status(c.cycle.cycle_id)["operations"]), 3
        )

    def test_real_sqlite_cross_instruction_single_flight(self):
        manual = self.instruction(
            instruction_id="manual", mode="manual", interval=None, max_cycles=1
        )
        self.approve(manual, "manual-approval")
        barrier = Barrier(2)

        def reserve(i):
            reopened = ExecutionStore(self.path, self.trust, clock=self.clock)
            barrier.wait(timeout=5)
            return reopened.reserve(i.instruction_id, 1, i.binding)

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(reserve, (self.i, manual)))
        self.assertEqual(sum(c is not None for c in results), 1)
        other = self.instruction(instruction_id="other", session="session:other")
        self.approve(other, "other-approval")
        self.assertIsNotNone(self.store.reserve("other", 1, other.binding))

    def test_proof_tamper_does_not_consume_event_then_replay_and_new_store_denied(self):
        successor = self.instruction(revision=2, predecessor=self.i.sha256, end=210)
        attestation = proof(self.key, "approve", successor.to_dict(), "successor")
        changed = self.instruction(revision=2, predecessor=self.i.sha256, end=211)
        with self.assertRaises(ExecutionDenied):
            self.store.approve(changed, attestation)
        self.store.approve(successor, attestation)
        with self.assertRaises(ExecutionDenied):
            self.store.approve(successor, attestation)
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM events").fetchone()[0], 2)
        other = ExecutionStore.create(
            Path(self.tmp.name) / "new.sqlite", self.trust, clock=self.clock
        )
        with self.assertRaises(ExecutionDenied):
            other.approve(successor, attestation)
        self.assertEqual(other.statuses(), [])

    def test_expired_approval_denial_must_not_allow_time_rollback_readmission(self):
        # Same class as the failed _guard high-water probe, before any cycle exists.
        self.clock.now = 200
        fresh = self.instruction(instruction_id="fresh")
        attestation = proof(self.key, "approve", fresh.to_dict(), "fresh-event")
        with self.assertRaises(ExecutionDenied):
            self.store.approve(fresh, attestation)
        self.clock.now = 199
        with self.assertRaises(ExecutionDenied):
            self.store.approve(fresh, attestation)

    def test_unavailable_corrupt_and_missing_cycle_still_interrupt(self):
        for damage in ("unavailable", "corrupt", "missing-row"):
            with self.subTest(damage=damage):
                self.setUp()
                c = self.start()
                if damage == "unavailable":
                    self.path.unlink()
                    self.path.mkdir()
                elif damage == "corrupt":
                    self.path.write_bytes(b"not a sqlite database")
                else:
                    with closing(sqlite3.connect(self.path)) as db:
                        db.execute("DELETE FROM cycles")
                        db.commit()
                with self.assertRaises((ExecutionDenied, sqlite3.Error, OSError)):
                    self.controller.enforce(c)
                self.assertEqual(self.runner.interrupts, [(c.cycle.cycle_id, 2)])
                with self.assertRaises((ExecutionDenied, sqlite3.Error, OSError)):
                    c.native(self.i.scope[0], {})
                self.assertEqual(self.broker.calls, [])

    def test_failed_authority_mutation_keeps_time_but_not_event(self):
        # _event runs before immutable-revision rejection. Only the clock may commit.
        self.clock.now = 150
        with self.assertRaises(ExecutionDenied):
            self.approve(self.i, "must-not-consume")
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM events").fetchone()[0], 1)
        self.assertEqual(self.metadata(), (150.0, 0))
        self.clock.now = 149
        with self.assertRaises(ExecutionDenied):
            self.store.check(self.store.reserve("review-1", 1, self.i.binding))
        self.assertEqual(self.metadata(), (150.0, 1))

    def test_context_checkpoint_time_observation_is_also_durable(self):
        c = self.start()
        self.clock.now = 200
        with self.assertRaises(ExecutionDenied):
            c.remaining()
        self.assertEqual(self.metadata(), (200.0, 0))
        self.clock.now = 199
        with self.assertRaises(ExecutionDenied):
            self.approve(self.instruction(instruction_id="fresh"), "fresh")
        self.assertEqual(self.metadata(), (200.0, 1))
