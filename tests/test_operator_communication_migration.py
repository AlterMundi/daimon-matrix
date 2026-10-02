"""Real SQLite migration, in-flight retry and recovery boundaries."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from unittest.mock import patch

from daimon_matrix import daemon
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

    def test_rehearsal_refuses_invalid_migrated_attempt_before_live_ddl(self) -> None:
        _, _, accepted = self.append_message([self.target("embodiment:daimonmatrix")])
        self.store.record_attempt(self.attempt(accepted["legs"][0]["leg_id"], 1))
        preview = plan(self.ledger_a.path)
        with self.assertRaisesRegex(CommunicationError, "route_attempt_store_corrupt"):
            apply(self.store, self.backup(), preview["plan_sha256"])
        self.assertEqual(plan(self.ledger_a.path), preview)
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

    def test_cached_page_refuses_before_live_ddl(self) -> None:
        self.append_message([self.target("embodiment:legion")])
        self.store.page(
            recipient_id="embodiment:legion",
            consumer_id="consumer:migration",
            request_id=identifier(70_000_000, 1),
            cursor=None,
            limit=1,
        )
        self.assert_historical_cache_refused()

    def test_cached_claim_refuses_before_live_ddl(self) -> None:
        self.append_message([self.target("embodiment:legion")])
        self.store.claim(
            recipient_id="embodiment:legion",
            consumer_id="consumer:migration",
            claim_id=identifier(69_000_000, 1),
            limit=1,
            lease_until_ms=NOW + 1_000,
        )
        self.assert_historical_cache_refused()

    def assert_historical_cache_refused(self) -> None:
        before = plan(self.ledger_a.path)
        with self.assertRaisesRegex(
            MigrationError, "migration_history_requires_library_fix"
        ):
            apply(self.store, self.backup(), before["plan_sha256"])
        self.assertEqual(plan(self.ledger_a.path), before)
        self.assertFalse((self.backup() / "prepared.json").exists())

    def test_conflict_history_refuses_before_live_ddl(self) -> None:
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
        self.assertTrue(self.store.conflicts())
        self.assert_historical_cache_refused()

    def test_existing_v2_upgrade_and_v3_noop(self) -> None:
        self.store.upgrade_receipts_v2()
        preview = plan(self.ledger_a.path)
        self.assertEqual(preview["steps"], ["legs_v3"])
        apply(self.store, self.backup(), preview["plan_sha256"])
        current = plan(self.ledger_a.path)
        result = apply(self.store, self.backup("unused"), current["plan_sha256"])
        self.assertEqual(result["status"], "already-current")
        self.assertFalse(self.backup("unused").exists())

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
