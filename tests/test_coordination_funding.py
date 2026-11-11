"""Conserved shared funding at the actual existing provider admission boundary.

Real SQLite and signed synthetic human/accounting authority; no network/models.
"""

import hashlib
import multiprocessing
import sqlite3
import tempfile
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, contextmanager
from pathlib import Path
from threading import Barrier

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from daimon_matrix.execution_instruction import ExecutionDenied, Instruction
from daimon_matrix.execution_store import ExecutionStore
from daimon_matrix.review_runner import ReviewController
from tests.test_execution_instruction import proof, request, verifier
from tests.test_execution_store import Clock
from tests.test_passive_messaging_execution import BoundedFakeRunner, Broker


def crash_native_attempt(path, trust, cycle, exposure, identity):
    import os

    store = ExecutionStore(path, trust, clock=lambda: 100)
    store.dispatch_provider_attempt(
        cycle, identity, lambda: None, lambda: os._exit(17), exposure=exposure
    )


class FundingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "journal.sqlite"
        self.human = Ed25519PrivateKey.generate()
        self.accountant = Ed25519PrivateKey.generate()
        self.clock = Clock()
        self.serial = 0
        self.store = ExecutionStore.create(
            self.path,
            verifier(self.human),
            clock=self.clock,
            usage_verifier=verifier(self.accountant),
        )
        self.store.enable_funding()
        self.calls = []
        self.account("tribe", "tribe")
        self.account("being", "being")
        self.account("episode", "episode")

    def signed(self, payload, key=None):
        self.serial += 1
        return proof(
            key or self.human, "approve", payload, event=f"event-{self.serial}"
        )

    def account(self, identity, kind, **changes):
        data = (
            dict(
                schema="execution/funding-account/v1",
                store_id=self.store.store_id,
                principal="human:test",
                account_id=identity,
                kind=kind,
                subject="being:test" if kind == "being" else identity,
                start=100,
                end=200,
                unit="synthetic-charge",
                max_calls=5,
                max_charge=100,
                max_active=3,
                max_bindings=10,
            )
            | changes
        )
        self.store.grant_budget(data, self.signed(data))
        return data

    def instruction(
        self, identity="review-1", accounts=None, maximum=30, attempts=None, **changes
    ):
        data = (
            request(
                store_id=self.store.store_id,
                instruction_id=identity,
                session=identity,
                task_sha256=hashlib.sha256(b"task").hexdigest(),
            )
            | changes
        )
        instruction = Instruction.from_dict(data)
        self.store.approve(instruction, self.signed(data))
        funding = dict(
            schema="execution/instruction-funding/v1",
            store_id=self.store.store_id,
            principal=instruction.principal,
            instruction_sha256=instruction.sha256,
            accounts=accounts or ["tribe", "being", "episode"],
            route="isolated-fake",
            max_charge=maximum,
        )
        if attempts is not None:
            funding["schema"] = "execution/instruction-funding/v2"
            funding["max_provider_attempts"] = attempts
        self.store.fund_instruction(instruction, funding, self.signed(funding))
        return instruction

    def cycle(self, instruction):
        return self.store.reserve(
            instruction.instruction_id, instruction.revision, instruction.binding
        )

    def exposure(self, instruction, maximum=30):
        return dict(
            route="isolated-fake",
            max_charge=maximum,
            provider=instruction.provider,
            model=instruction.model,
            max_input_tokens=instruction.max_input_tokens,
            max_output_tokens=instruction.max_output_tokens,
        )

    def send(self, instruction, cycle, exposure=None):
        return self.store.dispatch(
            cycle,
            "provider",
            None,
            lambda: None,
            lambda: self.calls.append(cycle.cycle_id),
            exposure=exposure or self.exposure(instruction),
        )

    def usage(self, cycle, amount, key=None):
        charge = self.store.cycle_status(cycle.cycle_id)["operations"][-1]
        payload = dict(
            schema="execution/usage/v1",
            store_id=self.store.store_id,
            principal="human:test",
            cycle_id=cycle.cycle_id,
            operation_id=charge["operation_id"],
            actual=amount,
        )
        receipt = self.signed(payload, key or self.accountant)
        self.store.settle_charge(cycle, payload, receipt)
        return payload, receipt

    def pause(self, revision=1, paused=True):
        payload = dict(
            schema="execution/funding-control/v1",
            store_id=self.store.store_id,
            principal="human:test",
            account_id="episode",
            revision=revision,
            paused=paused,
        )
        self.store.control_funding(payload, self.signed(payload))

    def attempt(self, instruction, cycle, identity=None, submit=None):
        identity = identity or str(uuid.uuid4())
        self.store.dispatch_provider_attempt(
            cycle,
            identity,
            lambda: None,
            submit or (lambda: self.calls.append(identity)),
            exposure=self.exposure(instruction),
        )
        return identity

    def settle_attempt(self, cycle, identity, amount):
        payload = dict(
            schema="execution/usage/v1",
            store_id=self.store.store_id,
            principal="human:test",
            cycle_id=cycle.cycle_id,
            operation_id=identity,
            actual=amount,
        )
        receipt = self.signed(payload, self.accountant)
        self.store.settle_charge(cycle, payload, receipt)
        return payload, receipt

    def test_provider_attempt_migration_preserves_legacy_signed_history(self):
        instruction = self.instruction()
        cycle = self.cycle(instruction)
        self.send(instruction, cycle)
        self.usage(cycle, 8)
        self.pause()
        tables = [
            "metadata",
            "instructions",
            "cycles",
            "operations",
            "events",
            "funding_accounts",
            "instruction_funding",
            "funding_members",
            "call_charges",
        ]
        with closing(sqlite3.connect(self.path)) as db:
            before = {t: db.execute(f"SELECT * FROM {t}").fetchall() for t in tables}
        self.store.enable_provider_attempts()
        self.store.enable_provider_attempts()  # idempotent, never another allocation
        with closing(sqlite3.connect(self.path)) as db:
            after = {t: db.execute(f"SELECT * FROM {t}").fetchall() for t in tables}
            self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], 5)
        self.assertEqual(before, after)
        self.assertTrue(self.store.funding_status("episode")["paused"])
        with self.assertRaises(ExecutionDenied):
            self.attempt(instruction, cycle)
        self.pause(2, False)
        with self.assertRaises(ExecutionDenied):
            self.attempt(instruction, cycle)  # migration alone never widens v1
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.store.funding_status("tribe")["active"], 1)
        self.store.finish(cycle, "completed")
        self.assertEqual(self.store.funding_status("tribe")["active"], 0)

    def test_native_attempts_share_work_and_settle_only_exact_charge(self):
        self.store.enable_provider_attempts()
        self.account("one-active", "tribe", max_active=1)
        instruction = self.instruction(
            accounts=["one-active", "being", "episode"], attempts=3
        )
        cycle = self.cycle(instruction)
        with self.assertRaises(ExecutionDenied):
            self.send(instruction, cycle)  # no unlabelled send under v2
        first = self.attempt(instruction, cycle)
        with self.assertRaises(ExecutionDenied):
            self.attempt(instruction, cycle)  # unsettled exposure holds concurrency
        payload, receipt = self.settle_attempt(cycle, first, 8)
        self.store.settle_charge(cycle, payload, receipt)
        for _ in range(2):
            current = self.attempt(instruction, cycle)
            self.settle_attempt(cycle, current, 8)
        with self.assertRaises(ExecutionDenied):
            self.attempt(instruction, cycle)  # per-work fuel, despite spare money
        with self.assertRaises(ExecutionDenied):
            self.attempt(instruction, cycle, first)  # never replays a known return
        self.assertEqual(len(self.calls), 3)
        for account in ["one-active", "being", "episode"]:
            status = self.store.funding_status(account)
            self.assertEqual(
                (
                    status["calls"],
                    status["spent"],
                    status["reserved"],
                    status["active"],
                ),
                (3, 24, 0, 0),
            )
        self.assertEqual(self.store.cycle_status(cycle.cycle_id)["state"], "intent")
        with self.assertRaises(ExecutionDenied):
            self.settle_attempt(cycle, first, 7)  # conflicting usage still refused

    def test_native_attempt_global_fuel_is_atomic_within_one_work(self):
        self.store.enable_provider_attempts()
        self.account("two-calls", "tribe", max_calls=2)
        instruction = self.instruction(
            accounts=["two-calls", "being", "episode"], attempts=4
        )
        cycle = self.cycle(instruction)
        barrier = Barrier(4)

        def compete(_):
            barrier.wait(timeout=5)
            try:
                self.attempt(instruction, cycle)
                return True
            except ExecutionDenied:
                return False

        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(compete, range(4)))
        self.assertGreaterEqual(sum(results), 1)
        self.assertLessEqual(sum(results), 2)
        # A competitor can observe the other attempt's prepared intent. That
        # refusal sent nothing; finish filling the remaining finite test fuel.
        while len(self.calls) < 2:
            self.attempt(instruction, cycle)
        with self.assertRaises(ExecutionDenied):
            self.attempt(instruction, cycle)
        status = self.store.funding_status("two-calls")
        self.assertEqual(
            (len(self.calls), status["calls"], status["charged"]), (2, 2, 60)
        )
        self.assertEqual(len(self.store.cycle_status(cycle.cycle_id)["operations"]), 2)

    def test_native_attempt_unknown_result_reopen_pause_and_expiry_do_not_refund(self):
        self.store.enable_provider_attempts()
        instruction = self.instruction(attempts=3)
        cycle = self.cycle(instruction)
        first = self.attempt(instruction, cycle)
        self.settle_attempt(cycle, first, 8)
        self.pause()
        with self.assertRaises(ExecutionDenied):
            self.attempt(instruction, cycle)
        self.pause(2, False)
        lost_id = str(uuid.uuid4())

        def lost():
            self.calls.append(lost_id)
            raise TimeoutError("unknown physical attempt")

        with self.assertRaises(TimeoutError):
            self.attempt(instruction, cycle, lost_id, lost)
        self.store = ExecutionStore(
            self.path,
            verifier(self.human),
            clock=self.clock,
            usage_verifier=verifier(self.accountant),
        )
        for identity in [lost_id, str(uuid.uuid4())]:
            with self.assertRaises(ExecutionDenied):
                self.attempt(instruction, cycle, identity)
        status = self.store.funding_status("tribe")
        self.assertEqual(
            (status["calls"], status["spent"], status["reserved"]), (2, 8, 30)
        )
        self.assertEqual(len(self.calls), 2)
        self.store.finish(cycle, "stopped")
        self.clock.now = 200
        self.assertEqual(self.store.funding_status("tribe")["charged"], 38)

    def test_missing_operation_metadata_cannot_hide_a_retained_charge(self):
        instruction = self.instruction()
        cycle = self.cycle(instruction)
        self.send(instruction, cycle)
        self.usage(cycle, 8)
        self.store.enable_provider_attempts()
        # Incomplete/corrupt retained metadata must not erase the charge when
        # the successor balance query joins its operation admission state.
        with closing(sqlite3.connect(self.path)) as db:
            db.execute("DELETE FROM operations WHERE cycle_id=?", (cycle.cycle_id,))
            db.commit()
        status = self.store.funding_status("tribe")
        self.assertEqual(
            (status["spent"], status["uncertain"], status["calls"]), (8, 1, 1)
        )

    def test_native_attempt_process_death_fences_same_and_shared_work(self):
        self.store.enable_provider_attempts()
        instruction = self.instruction(attempts=3)
        cycle = self.cycle(instruction)
        identity = str(uuid.uuid4())
        process = multiprocessing.get_context("fork").Process(
            target=crash_native_attempt,
            args=(
                self.path,
                verifier(self.human),
                cycle,
                self.exposure(instruction),
                identity,
            ),
        )
        process.start()
        process.join(timeout=5)
        self.assertFalse(process.is_alive())
        self.assertEqual(process.exitcode, 17)
        self.store = ExecutionStore(self.path, verifier(self.human), clock=self.clock)
        self.assertEqual(self.store.cycle_status(cycle.cycle_id)["state"], "intent")
        for original in [identity, str(uuid.uuid4())]:
            with self.assertRaises(ExecutionDenied):
                self.attempt(instruction, cycle, original)
        other = self.instruction("other-work", attempts=3)
        with self.assertRaises(ExecutionDenied):
            self.attempt(other, self.cycle(other))
        status = self.store.funding_status("tribe")
        self.assertEqual(
            (status["calls"], status["charged"], status["uncertain"]), (1, 30, 1)
        )
        self.assertEqual(self.calls, [])

    def test_native_attempts_reopen_keeps_fuel_and_migration_requires_signed_v2(self):
        with self.assertRaises(ExecutionDenied):
            self.instruction("unmigrated", attempts=2)
        self.store.enable_provider_attempts()
        for value in [0, True, -1]:
            with self.assertRaises(ExecutionDenied):
                self.instruction("bad-" + str(value), attempts=value)
        instruction = self.instruction(attempts=2)
        cycle = self.cycle(instruction)
        first = self.attempt(instruction, cycle)
        self.settle_attempt(cycle, first, 1)
        self.store = ExecutionStore(
            self.path,
            verifier(self.human),
            clock=self.clock,
            usage_verifier=verifier(self.accountant),
        )
        second = self.attempt(instruction, cycle)
        self.settle_attempt(cycle, second, 2)
        with self.assertRaises(ExecutionDenied):
            self.attempt(instruction, cycle)
        self.assertEqual(self.store.funding_status("episode")["calls"], 2)
        self.clock.now = cycle.deadline
        with self.assertRaises(ExecutionDenied):
            self.attempt(instruction, cycle)
        self.assertEqual(len(self.calls), 2)

    def test_atomic_three_ceilings_and_authenticated_idempotent_usage(self):
        instruction = self.instruction()
        cycle = self.cycle(instruction)
        self.send(instruction, cycle)
        for account in ["tribe", "being", "episode"]:
            value = self.store.funding_status(account)
            self.assertEqual(
                (value["calls"], value["charged"], value["available_charge"]),
                (1, 30, 70),
            )
        with self.assertRaises(ExecutionDenied):
            self.usage(cycle, 3, self.human)  # human key is not usage authority
        with self.assertRaises(ExecutionDenied):
            self.usage(cycle, 31)
        payload, receipt = self.usage(cycle, 8)
        self.store.settle_charge(cycle, payload, receipt)
        with self.assertRaises(ExecutionDenied):
            self.usage(cycle, 7)
        self.store.finish(cycle, "completed")
        for account in ["tribe", "being", "episode"]:
            value = self.store.funding_status(account)
            self.assertEqual(
                (value["calls"], value["charged"], value["active"]), (1, 8, 0)
            )
            self.assertEqual(value["available_calls"], 4)  # fuel never refunded

    def test_real_controller_requires_funding_and_rejects_unqualified_adapter(self):
        runner = BoundedFakeRunner()
        controller = ReviewController(
            self.store, runner, Broker(), require_funding=True, monotonic=lambda: 0
        )
        data = request(
            store_id=self.store.store_id,
            task_sha256=hashlib.sha256(b"task").hexdigest(),
        )
        instruction = Instruction.from_dict(data)
        self.store.approve(instruction, self.signed(data))
        with self.assertRaises(ExecutionDenied):
            controller.run_due_once("review-1", 1, "task")
        self.assertEqual(runner.starts, [])
        funded = self.instruction("funded", session="session:test")
        context = controller.run_due_once("funded", 1, "task")
        self.assertIsNotNone(context)
        self.assertEqual(len(runner.starts), 1)
        with self.assertRaises(ExecutionDenied):
            context.inference(lambda: self.calls.append("unqualified"))
        self.assertEqual(self.calls, [])
        context.inference(
            lambda: self.calls.append("bounded"), exposure=self.exposure(funded)
        )
        self.assertEqual(self.calls, ["bounded"])
        with self.assertRaises(ExecutionDenied):
            context.inference(
                lambda: self.calls.append("retry"), exposure=self.exposure(funded)
            )

    def test_shared_pool_concurrent_roots_cannot_double_spend(self):
        self.account("small-global", "tribe", max_calls=1)
        self.account("root2", "episode")
        first = self.instruction("first", accounts=["small-global", "being", "episode"])
        second = self.instruction("second", accounts=["small-global", "being", "root2"])
        cases = [(first, self.cycle(first)), (second, self.cycle(second))]
        barrier = Barrier(2)

        def compete(case):
            barrier.wait(timeout=5)
            try:
                self.send(*case)
                return True
            except ExecutionDenied:
                return False

        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertEqual(sorted(pool.map(compete, cases)), [False, True])
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.store.funding_status("small-global")["calls"], 1)

    def test_unknown_submission_restart_and_renewal_never_refund(self):
        instruction = self.instruction()
        cycle = self.cycle(instruction)

        def lost():
            self.calls.append("possibly-sent")
            raise TimeoutError("lost acknowledgment")

        with self.assertRaises(TimeoutError):
            self.store.dispatch(
                cycle,
                "provider",
                None,
                lambda: None,
                lost,
                exposure=self.exposure(instruction),
            )
        self.store = ExecutionStore(
            self.path,
            verifier(self.human),
            clock=self.clock,
            usage_verifier=verifier(self.accountant),
        )
        second = self.instruction("other-session")
        with self.assertRaises(ExecutionDenied):
            self.send(second, self.cycle(second))
        balance = self.store.funding_status("tribe")
        self.assertEqual(
            (balance["charged"], balance["uncertain"], balance["calls"]), (30, 1, 1)
        )
        self.store.finish(cycle, "stopped")  # stopped is not a usage refund
        self.assertEqual(self.store.funding_status("tribe")["charged"], 30)
        self.assertEqual(self.store.funding_status("tribe")["active"], 1)

    def test_pause_persists_and_old_control_cannot_resume(self):
        instruction = self.instruction()
        cycle = self.cycle(instruction)
        self.pause()
        self.store = ExecutionStore(self.path, verifier(self.human), clock=self.clock)
        with self.assertRaises(ExecutionDenied):
            self.send(instruction, cycle)
        self.assertEqual(self.calls, [])
        with self.assertRaises(ExecutionDenied):
            self.pause(1, False)
        self.pause(2, False)
        self.send(instruction, cycle)
        self.assertEqual(len(self.calls), 1)

    def test_pause_between_reservation_and_transport_retains_exposure(self):
        instruction = self.instruction()
        cycle = self.cycle(instruction)
        original = self.store._transaction
        transactions = 0

        @contextmanager
        def with_pause(*args, **kwargs):
            nonlocal transactions
            with original(*args, **kwargs) as db:
                yield db
            transactions += 1
            if transactions == 1:
                payload = dict(
                    schema="execution/funding-control/v1",
                    store_id=self.store.store_id,
                    principal="human:test",
                    account_id="episode",
                    revision=1,
                    paused=True,
                )
                with original() as db:
                    self.store._event(db, "approve", payload, self.signed(payload))
                    db.execute(
                        "UPDATE funding_accounts SET paused=1,control_revision=1 "
                        "WHERE account_id='episode'"
                    )

        self.store._transaction = with_pause
        with self.assertRaises(ExecutionDenied):
            self.send(instruction, cycle)
        self.assertEqual(self.calls, [])
        self.assertEqual(self.store.funding_status("episode")["charged"], 30)
        self.assertEqual(self.store.cycle_status(cycle.cycle_id)["state"], "ambiguous")

    def test_free_calls_still_exhaust_fuel_and_expensive_call_is_prevented(self):
        self.account("free-root", "episode", max_calls=1, max_charge=0)
        first = self.instruction(
            "free1", accounts=["tribe", "being", "free-root"], maximum=0
        )
        second = self.instruction(
            "free2", accounts=["tribe", "being", "free-root"], maximum=0
        )
        cycle = self.cycle(first)
        self.send(first, cycle, self.exposure(first, 0))
        self.usage(cycle, 0)
        self.store.finish(cycle, "completed")
        with self.assertRaises(ExecutionDenied):
            self.send(second, self.cycle(second), self.exposure(second, 0))
        self.assertEqual(len(self.calls), 1)
        with self.assertRaises(ExecutionDenied):
            self.instruction("expensive", maximum=101)

    def test_fanout_expiry_binding_and_exposure_tamper(self):
        self.account("tiny-root", "episode", max_bindings=1)
        instruction = self.instruction(accounts=["tribe", "being", "tiny-root"])
        with self.assertRaises(ExecutionDenied):
            self.instruction("child", accounts=["tribe", "being", "tiny-root"])
        cycle = self.cycle(instruction)
        for key, value in [
            ("route", "bypass"),
            ("max_charge", 0),
            ("max_output_tokens", 999),
            ("model", "other"),
            ("max_charge", 30.0),
        ]:
            with self.assertRaises(ExecutionDenied):
                self.send(instruction, cycle, self.exposure(instruction) | {key: value})
        self.assertEqual(self.store.funding_status("tribe")["calls"], 0)
        self.clock.now = 200
        with self.assertRaises(ExecutionDenied):
            self.send(instruction, cycle)
        self.assertEqual(self.calls, [])

    def test_explicit_migration_preserves_existing_state(self):
        legacy = Path(self.tmp.name) / "old.sqlite"
        store = ExecutionStore.create(legacy, verifier(self.human), clock=self.clock)
        data = request(store_id=store.store_id)
        instruction = Instruction.from_dict(data)
        store.approve(instruction, self.signed(data))
        cycle = store.reserve("review-1", 1, instruction.binding)

        def content():
            with closing(sqlite3.connect(legacy)) as db:
                return {
                    table: db.execute(f"SELECT * FROM {table}").fetchall()
                    for table in [
                        "metadata",
                        "instructions",
                        "cycles",
                        "operations",
                        "events",
                    ]
                }

        before = content()
        store.enable_funding()
        store.enable_funding()
        self.assertEqual(before, content())
        reopened = ExecutionStore(legacy, verifier(self.human), clock=self.clock)
        reopened.dispatch(
            cycle,
            "provider",
            None,
            lambda: None,
            lambda: self.calls.append("legacy-human"),
        )
        self.assertEqual(self.calls, ["legacy-human"])
        self.assertEqual(reopened.store_id, store.store_id)

    def test_alternating_beings_share_episode_and_global_fuel(self):
        self.account("being2", "being", subject="being:second")
        admitted = 0
        for index in range(10):
            other = bool(index % 2)
            instruction = self.instruction(
                f"loop-{index}",
                accounts=["tribe", "being2" if other else "being", "episode"],
                being="being:second" if other else "being:test",
                embodiment="body:second" if other else "body:test",
            )
            cycle = self.cycle(instruction)
            try:
                self.send(instruction, cycle)
            except ExecutionDenied:
                continue
            admitted += 1
            self.usage(cycle, 1)
            self.store.finish(cycle, "completed")
        self.assertEqual(admitted, 5)
        self.assertEqual(len(self.calls), 5)
        for aid in ["tribe", "episode"]:
            status = self.store.funding_status(aid)
            self.assertEqual(status["available_calls"], 0)
            self.assertEqual(
                status["spent"] + status["reserved"] + status["available_charge"],
                status["max_charge"],
            )

    def test_spend_ceiling_is_independent_of_call_count(self):
        self.account("spend-limited", "tribe", max_calls=10, max_charge=50)
        first = self.instruction(
            "expensive1", accounts=["spend-limited", "being", "episode"]
        )
        second = self.instruction(
            "expensive2", accounts=["spend-limited", "being", "episode"]
        )
        cycle = self.cycle(first)
        self.send(first, cycle)
        self.usage(cycle, 30)
        self.store.finish(cycle, "completed")
        with self.assertRaises(ExecutionDenied):
            self.send(second, self.cycle(second))
        status = self.store.funding_status("spend-limited")
        self.assertEqual(
            (status["available_calls"], status["available_charge"]), (9, 20)
        )
        self.assertEqual(len(self.calls), 1)

    def test_missing_usage_after_known_stop_still_fences_shared_dispatch(self):
        first = self.instruction("missing-usage")
        cycle = self.cycle(first)
        self.send(first, cycle)
        self.store.finish(cycle, "stopped")
        other = self.instruction("later")
        next_cycle = self.cycle(other)
        with self.assertRaises(ExecutionDenied):
            self.send(other, next_cycle)
        self.usage(cycle, 5)
        self.send(other, next_cycle)
        self.assertEqual(len(self.calls), 2)

    def test_clock_fault_fences_admission_but_not_signed_pause(self):
        instruction = self.instruction()
        cycle = self.cycle(instruction)
        self.clock.now = 99
        with self.assertRaises(ExecutionDenied):
            self.send(instruction, cycle)
        self.pause()
        self.clock.now = 100
        with self.assertRaises(ExecutionDenied):
            self.send(instruction, cycle)
        self.assertTrue(self.store.funding_status("episode")["paused"])
        self.assertEqual(self.calls, [])
