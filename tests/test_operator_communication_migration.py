"""Real SQLite migration, in-flight retry and recovery boundaries."""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import time
import unittest
from contextlib import closing
from pathlib import Path
from typing import Any
from unittest.mock import patch

from daimon_matrix import daemon
from daimon_matrix import operator_communication_migration as operator
from daimon_matrix.communication import (
    CommunicationError,
    CommunicationStore,
    select_persisted_schema,
)
from daimon_matrix.operator_communication_migration import (
    MigrationError,
    apply,
    plan,
    recover,
    state_digest,
)
from daimon_matrix.runtime import load_runtime
from daimon_matrix.weave import create_event
from tests import test_native_messaging as native
from tests.test_dm022_ledger import NOW
from tests.test_dm024_runtime import PASSWORD, RuntimeFixture
from tests.test_dm052_communication import (
    MEMBERSHIP,
    LogicalCommunicationFixture,
    identifier,
)


class CommunicationMigrationTests(LogicalCommunicationFixture):
    def backup(self, name: str = "migration") -> Path:
        return self.ledger_a.path.parent / name

    def test_preview_does_not_write_and_requires_exact_approval(self) -> None:
        before = self.ledger_a.path.read_bytes()
        preview = plan(self.ledger_a.path)
        self.assertEqual(preview["status"], "approval-required")
        self.assertEqual(preview["steps"], ["receipts_v2", "legs_v3"])
        self.assertEqual(self.ledger_a.path.read_bytes(), before)
        with self.assertRaisesRegex(MigrationError, "migration_plan_changed"):
            apply(self.store, self.backup(), "0" * 64)
        self.assertFalse(self.backup().exists())

    def test_historical_attempt_migrates_with_exact_retry(self) -> None:
        _, _, accepted = self.append_message([self.target("embodiment:daimonmatrix")])
        attempt = self.attempt(accepted["legs"][0]["leg_id"], 1)
        recorded = self.store.record_attempt(attempt)
        result = apply(
            self.store, self.backup(), plan(self.ledger_a.path)["plan_sha256"]
        )
        self.assertEqual(result["target_version"], 4)
        self.assertEqual(self.store.record_attempt(attempt), recorded)
        self.assertEqual(
            self.store.leg(attempt["leg_id"])["sequence"],
            accepted["legs"][0]["sequence"],
        )

    def test_rehearsal_refuses_corrupt_attempt_before_live_ddl(self) -> None:
        _, _, accepted = self.append_message([self.target("embodiment:daimonmatrix")])
        self.store.record_attempt(self.attempt(accepted["legs"][0]["leg_id"], 1))
        with closing(sqlite3.connect(self.ledger_a.path)) as database:
            database.execute(
                "UPDATE communication_attempts SET attempt_hash=?", ("a" * 64,)
            )
            database.commit()
        preview = plan(self.ledger_a.path)
        anchor = self.store.anchor_path.read_bytes()
        with self.assertRaisesRegex(CommunicationError, "route_attempt_store_corrupt"):
            apply(self.store, self.backup(), preview["plan_sha256"])
        self.assertEqual(plan(self.ledger_a.path), preview)
        self.assertEqual(self.store.anchor_path.read_bytes(), anchor)
        self.assertFalse((self.backup() / "prepared.json").exists())
        self.assertFalse((self.backup() / "completed.json").exists())

    def test_in_flight_retry_reopens_and_recovery_restores_exact_source(self) -> None:
        message, resolution, accepted = self.append_message(
            [self.target("embodiment:daimonmatrix")]
        )
        preview = plan(self.ledger_a.path)
        result = apply(self.store, self.backup(), preview["plan_sha256"])
        self.assertEqual(result["status"], "migrated")
        reopened = CommunicationStore(self.ledger_a, clock=self.store.clock)
        select_persisted_schema(reopened, self.ledger_a)
        reopened.initialize()
        self.assertTrue(reopened.receipts_v2)
        self.assertTrue(reopened.legs_v3)
        replay = reopened.accept(
            message_event_id=message["event_id"],
            resolution_event_id=resolution["event_id"],
        )
        self.assertEqual(len(replay["legs"]), 1)
        self.assertEqual(replay["legs"][0]["sequence"], accepted["legs"][0]["sequence"])
        # Reading/re-accepting the same operation creates no later state.
        restored = recover(
            self.ledger_a.path, self.backup(), state_digest(self.ledger_a.path)
        )
        self.assertEqual(restored["state_sha256"], preview["state_sha256"])
        legacy = CommunicationStore(self.ledger_a, clock=self.store.clock)
        legacy.initialize()
        old = legacy.result(message["event_id"])
        self.assertEqual(old["legs"], accepted["legs"])

    def test_cached_page_migrates_with_exact_replay(self) -> None:
        self.append_message([self.target("embodiment:legion")])
        arguments: dict[str, Any] = dict(
            recipient_id="embodiment:legion",
            consumer_id="consumer:migration",
            request_id=identifier(70_000_000, 1),
            cursor=None,
            limit=1,
        )
        original = self.store.page(**arguments)
        apply(self.store, self.backup(), plan(self.ledger_a.path)["plan_sha256"])
        self.assertEqual(self.store.page(**arguments), original)

    def test_cached_claim_migrates_with_exact_replay(self) -> None:
        self.append_message([self.target("embodiment:legion")])
        arguments: dict[str, Any] = dict(
            recipient_id="embodiment:legion",
            consumer_id="consumer:migration",
            claim_id=identifier(69_000_000, 1),
            limit=1,
            lease_until_ms=NOW + 1_000,
        )
        original = self.store.claim(**arguments)
        apply(self.store, self.backup(), plan(self.ledger_a.path)["plan_sha256"])
        self.assertEqual(self.store.claim(**arguments), original)

    def test_conflict_history_migrates_and_retains_quarantine(self) -> None:
        _, _, accepted = self.append_message([self.target("embodiment:legion")])
        attempt = self.attempt(accepted["legs"][0]["leg_id"], 3)
        self.store.record_attempt(attempt)
        arguments = {
            "attempt_id": attempt["attempt_id"],
            "delivery_id": identifier(60_000_000, 3),
        }
        self.store.record_delivery(**arguments, envelope_hash="a" * 64)
        with self.assertRaisesRegex(CommunicationError, "delivery_id_conflict"):
            self.store.record_delivery(**arguments, envelope_hash="b" * 64)
        original = self.store.conflicts()
        apply(self.store, self.backup(), plan(self.ledger_a.path)["plan_sha256"])
        self.assertEqual(
            [
                {k: v for k, v in row.items() if k != "leg_id"}
                for row in self.store.conflicts()
            ],
            [{k: v for k, v in row.items() if k != "leg_id"} for row in original],
        )
        self.assertEqual(self.store.leg(attempt["leg_id"])["state"], "quarantined")

    def test_existing_v2_upgrade_and_v4_noop(self) -> None:
        self.store.upgrade_receipts_v2()
        preview = plan(self.ledger_a.path)
        self.assertEqual(preview["steps"], ["legs_v3"])
        self.assertEqual(preview["target_version"], 4)
        apply(self.store, self.backup(), preview["plan_sha256"])
        current = plan(self.ledger_a.path)
        result = apply(self.store, self.backup("unused"), current["plan_sha256"])
        self.assertEqual(result["status"], "already-current")
        self.assertFalse(self.backup("unused").exists())

    def test_original_healthy_v3_is_unchanged(self) -> None:
        self.store.upgrade_receipts_v2()
        self.store.upgrade_legs_v3()
        # Reconstruct original canonical schema3 on an empty synthetic store.
        with closing(sqlite3.connect(self.ledger_a.path)) as database:
            database.execute("DROP TABLE communication_leg_aliases")
            database.execute("DROP TABLE communication_leg_migration")
            database.execute(
                "UPDATE communication_meta SET value='3' WHERE key='schema_version'"
            )
            database.commit()
        self.store = CommunicationStore(self.ledger_a, clock=lambda: NOW)
        select_persisted_schema(self.store, self.ledger_a)
        self.append_message([self.target("embodiment:legion")])
        before = plan(self.ledger_a.path)
        self.assertEqual(before["target_version"], 3)
        self.assertEqual(
            apply(self.store, self.backup(), before["plan_sha256"]), before
        )
        self.assertEqual(plan(self.ledger_a.path), before)
        self.assertFalse(self.backup().exists())

    def test_two_receiving_bodies_have_distinct_legs(self) -> None:
        apply(self.store, self.backup(), plan(self.ledger_a.path)["plan_sha256"])
        message, _, result = self.append_message(
            [
                self.target(
                    MEMBERSHIP,
                    recipient_type="relationship",
                    scope_kind="relationship",
                    origin=origin,
                )
                for origin in ("embodiment:legion", "embodiment:daimonmatrix")
            ],
            scope="/tribe",
        )
        self.assertEqual(len(result["legs"]), 2)
        self.assertEqual(len({leg["leg_id"] for leg in result["legs"]}), 2)
        self.assertEqual(
            {leg["receipt_origin_embodiment_id"] for leg in result["legs"]},
            {"embodiment:legion", "embodiment:daimonmatrix"},
        )
        self.receipt(result, MEMBERSHIP, "delivered")
        self.assertFalse(self.store.result(message["event_id"])["terminal"])
        self.receipt(result, MEMBERSHIP, "delivered", remote=True)
        terminal = self.store.result(message["event_id"], require_terminal=True)
        self.assertTrue(terminal["terminal"])
        self.assertEqual(
            len({leg["terminal_receipt_event_id"] for leg in terminal["legs"]}), 2
        )

    def test_interruption_after_receipts_upgrade_can_recover(self) -> None:
        preview = plan(self.ledger_a.path)
        with (
            patch.object(
                self.store, "upgrade_legs_v3", side_effect=RuntimeError("interrupted")
            ),
            self.assertRaisesRegex(RuntimeError, "interrupted"),
        ):
            apply(self.store, self.backup(), preview["plan_sha256"])
        self.assertEqual(plan(self.ledger_a.path)["source_version"], 2)
        self.assertFalse((self.backup() / "completed.json").exists())
        restored = recover(
            self.ledger_a.path, self.backup(), state_digest(self.ledger_a.path)
        )
        self.assertEqual(restored["state_sha256"], preview["state_sha256"])

    def test_completion_publication_failure_can_recover_target4(self) -> None:
        self.append_message([self.target("embodiment:legion")])
        preview = plan(self.ledger_a.path)
        write = operator._write

        def fail_completion(path: Path, value: dict[str, Any]) -> None:
            if path.name == "completed.json":
                raise OSError("injected_completion_failure")
            write(path, value)

        with (
            patch.object(operator, "_write", fail_completion),
            self.assertRaisesRegex(OSError, "injected_completion_failure"),
        ):
            apply(self.store, self.backup(), preview["plan_sha256"])
        self.assertEqual(plan(self.ledger_a.path)["source_version"], 4)
        prepared = json.loads((self.backup() / "prepared.json").read_bytes())
        self.assertIn("4", prepared["allowed_states"])
        self.assertFalse((self.backup() / "completed.json").exists())
        restored = recover(
            self.ledger_a.path, self.backup(), state_digest(self.ledger_a.path)
        )
        self.assertEqual(restored["state_sha256"], preview["state_sha256"])

    def test_recovery_refuses_later_accepted_history(self) -> None:
        apply(self.store, self.backup(), plan(self.ledger_a.path)["plan_sha256"])
        self.append_message([self.target("embodiment:daimonmatrix")])
        current = state_digest(self.ledger_a.path)
        with self.assertRaisesRegex(
            MigrationError, "migration_recovery_would_discard_work"
        ):
            recover(self.ledger_a.path, self.backup(), current)
        self.assertEqual(state_digest(self.ledger_a.path), current)

    def test_tampered_backup_and_hardlinked_source_refuse(self) -> None:
        apply(self.store, self.backup(), plan(self.ledger_a.path)["plan_sha256"])
        source = self.backup() / "source.sqlite"
        os.link(source, self.backup() / "linked.sqlite")
        with self.assertRaisesRegex(MigrationError, "migration_file_unsafe"):
            recover(self.ledger_a.path, self.backup(), state_digest(self.ledger_a.path))
        (self.backup() / "linked.sqlite").unlink()
        with source.open("ab") as stream:
            stream.write(b"changed")
        with self.assertRaisesRegex(MigrationError, "migration_snapshot_changed"):
            recover(self.ledger_a.path, self.backup(), state_digest(self.ledger_a.path))

    def test_process_preview_and_recover_without_opening_custody(self) -> None:
        root = self.ledger_a.path.parent
        bundle = root / "migration-test-runtime.json"
        bundle.write_text(json.dumps({"ledger": self.ledger_a.path.name}))
        bundle.chmod(0o600)
        args = [
            sys.executable,
            "-m",
            "daimon_matrix.operator_communication_migration",
            "plan",
            "--state-root",
            str(root),
            "--bundle",
            bundle.name,
        ]
        preview = subprocess.run(args, capture_output=True, text=True, check=True)
        self.assertEqual(json.loads(preview.stdout), plan(self.ledger_a.path))
        apply(self.store, self.backup(), json.loads(preview.stdout)["plan_sha256"])
        current = plan(self.ledger_a.path)
        noop_args = args.copy()
        noop_args[3] = "apply"
        unused_backup = self.backup("unused-process-backup")
        noop_args.extend(
            [
                "--backup-dir",
                str(unused_backup),
                "--expected-plan-sha256",
                current["plan_sha256"],
            ]
        )
        noop = subprocess.run(noop_args, capture_output=True, text=True, check=True)
        self.assertEqual(json.loads(noop.stdout), current)
        self.assertFalse(unused_backup.exists())
        self.assertEqual(plan(self.ledger_a.path), current)
        args[3] = "recover"
        args.extend(
            [
                "--backup-dir",
                str(self.backup()),
                "--expected-state-sha256",
                state_digest(self.ledger_a.path),
            ]
        )
        result = subprocess.run(args, capture_output=True, text=True, check=True)
        self.assertEqual(json.loads(result.stdout)["status"], "recovered")


class MigrationOperatorProcessTests(RuntimeFixture):
    def test_actual_apply_opens_runtime_custody_and_honors_daemon_lock(self) -> None:
        root, _bundle, _capability, _now = self.make_process_bundle()
        runtime = load_runtime(
            root,
            "runtime.json",
            lambda: bytearray(PASSWORD),
            clock=lambda: time.time_ns() // 1_000_000,
        )
        path = runtime.service.ledger.path
        preview = plan(path)
        args = [
            sys.executable,
            "-m",
            "daimon_matrix.operator_communication_migration",
            "apply",
            "--state-root",
            str(root),
            "--backup-dir",
            str(root / "backup"),
            "--expected-plan-sha256",
            preview["plan_sha256"],
        ]
        lock = daemon.acquire_lock(root)
        try:
            refused = subprocess.run(args, capture_output=True, text=True)
            self.assertEqual(refused.returncode, 1)
            self.assertIn("migration_runtime_running", refused.stderr)
        finally:
            os.close(lock)
        password = root / "migration-password"
        password.write_bytes(PASSWORD)
        password.chmod(0o600)
        with password.open("rb") as stream:
            completed = subprocess.run(
                [*args, "--password-fd", str(stream.fileno())],
                capture_output=True,
                text=True,
                pass_fds=(stream.fileno(),),
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(json.loads(completed.stdout)["status"], "migrated")
        reopened = load_runtime(
            root,
            "runtime.json",
            lambda: bytearray(PASSWORD),
            clock=lambda: time.time_ns() // 1_000_000,
        )
        store = reopened.service.communication
        assert store is not None
        self.assertTrue(store.legs_v3)


class ForeignProofMigrationTests(unittest.TestCase):
    def setUp(self) -> None:
        fixture = native.NativeMessagingTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.root = fixture.root
        self.pair = native.Pair(self.root)
        self.sender = fixture.make_sender(self.pair)
        self.store = CommunicationStore(
            self.sender.ledger,
            clock=lambda: self.pair.now,
            foreign_authority_resolver=lambda ref: self.pair.public[ref],
        )
        self.store.upgrade_receipts_v2()
        self.sender.communication = self.store
        self.sender.prepare(
            client_id="owner",
            send_id=identifier(70_000_001, 1),
            thread_id=identifier(70_000_001, 2),
            text="synthetic foreign proof migration",
        )
        self.message, self.resolution, _ = self.sender.ledger.events()
        self.receipt = create_event(
            authority=self.pair.recipient.authority,
            origin=self.pair.recipient.origin,
            signer=self.pair.recipient.signer,
            event_id=identifier(70_000_001, 3),
            sequence=1,
            previous_event_id=None,
            causal_parents=[],
            kind="experience.observed",
            subject="communication-receipt",
            sensitivity="shareable",
            occurred_at_ms=self.pair.now,
            payload={
                "schema": "dm.communication.receipt/v2",
                "message_being_ref": self.message["being_ref"],
                "message_ref": {
                    "event_id": self.message["event_id"],
                    "event_hash": self.message["content_hash"],
                },
                "resolution_ref": {
                    "event_id": self.resolution["event_id"],
                    "event_hash": self.resolution["content_hash"],
                },
                "thread_id": self.message["payload"]["intent"]["thread_id"],
                "recipient_type": "relationship",
                "recipient_id": self.pair.policy.membership_ref,
                "outcome": "delivered",
                "observed_at_ms": self.pair.now,
            },
        )
        self.store.record_foreign_receipt(
            self.receipt, recipient_being_ref=self.pair.recipient.state.being_ref
        )

    def test_foreign_proof_rehearses_migrates_and_replays_without_import(self) -> None:
        request: dict[str, Any] = dict(
            recipient_id=self.pair.policy.membership_ref,
            consumer_id="migration:foreign-proof",
            request_id=identifier(70_000_001, 4),
            cursor=None,
            limit=1,
        )
        original_page = self.store.page(**request)
        history = self.sender.ledger.events()
        with self.store._database() as database:
            original_proof = database.execute(
                "SELECT receipt_json, receipt_hash FROM communication_foreign_receipts"
            ).fetchall()
        before = plan(self.sender.ledger.path)
        result = apply(self.store, self.root / "migration", before["plan_sha256"])
        self.assertEqual(result["target_version"], 4)
        reopened = CommunicationStore(
            self.sender.ledger,
            clock=lambda: self.pair.now,
            foreign_authority_resolver=self.store.foreign_authority_resolver,
        )
        select_persisted_schema(reopened, self.sender.ledger)
        self.assertEqual(reopened.page(**request), original_page)
        replay = reopened.record_foreign_receipt(
            self.receipt, recipient_being_ref=self.pair.recipient.state.being_ref
        )
        self.assertTrue(replay["terminal"])
        with reopened._database() as database:
            self.assertEqual(
                [
                    tuple(row)
                    for row in database.execute(
                        "SELECT receipt_json, receipt_hash "
                        "FROM communication_foreign_receipts"
                    ).fetchall()
                ],
                [tuple(row) for row in original_proof],
            )
        self.assertEqual(self.sender.ledger.events(), history)
        self.assertIsNone(self.sender.ledger.event(self.receipt["event_id"]))
        restored = recover(
            self.sender.ledger.path,
            self.root / "migration",
            state_digest(self.sender.ledger.path),
        )
        self.assertEqual(restored["state_sha256"], before["state_sha256"])

    def test_missing_foreign_verifier_refuses_before_live_ddl(self) -> None:
        self.store.foreign_authority_resolver = None
        before = plan(self.sender.ledger.path)
        anchor = self.store.anchor_path.read_bytes()
        with self.assertRaisesRegex(CommunicationError, "foreign_receipts_not_enabled"):
            apply(self.store, self.root / "migration", before["plan_sha256"])
        self.assertEqual(plan(self.sender.ledger.path), before)
        self.assertEqual(self.store.anchor_path.read_bytes(), anchor)
        self.assertFalse((self.root / "migration/prepared.json").exists())
