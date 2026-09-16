"""Real SQLite + synthetic signing authority; no services or models."""

import multiprocessing
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from daimon_matrix import execution_store
from daimon_matrix.execution_instruction import ExecutionDenied, Instruction
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
