from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import threading
import unittest
import uuid
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, cast

from jsonschema import (  # type: ignore[import-untyped]
    Draft202012Validator,
    FormatChecker,
)

from daimon_matrix.canonical import canonical_bytes
from daimon_matrix.memory_policy import (
    MemoryPolicyExecutor,
    create_content_ref,
    create_memory_candidate,
    create_memory_policy,
    evaluate_memory_candidate,
    memory_checkpoint,
)
from daimon_matrix.memory_projection import (
    CAPABILITIES,
    HMK_COMMIT,
    MemoryProjectionAdapter,
    MemoryProjectionError,
    ProjectionJournal,
    create_projection_manifest,
    create_projection_profile,
    negotiate_projection_manifest,
    projection_checkpoint,
    validate_projection_manifest,
    validate_projection_profile,
    validate_projection_receipt,
    validate_rebuild_plan,
    validate_rebuild_receipt,
)
from tests.test_dm022_ledger import NOW, RootLedgerFixture

ROOT = Path(__file__).resolve().parents[1]
VECTOR_ROOT = ROOT / "vectors" / "memory-projection" / "v1"
DEFAULT_HMK_ROOT = ROOT.parent / "hermes-memory-kit"
MEMORY_ID = "34000000-0000-4000-8000-000000000001"


class HMKCLITransport:
    """Test transport for the pinned supported HMK CLI boundary."""

    def __init__(self, root: Path, base: Path, *, instance: str) -> None:
        self.root = root
        self.base = base
        self.instance = instance
        self.lock = threading.Lock()
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.lose_after: str | None = None
        self.corrupt_after: str | None = None

    @property
    def database(self) -> Path:
        return self.base / "library.db"

    def __call__(
        self, operation: str, document: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        environment = os.environ.copy()
        environment["HMK_AGENT_MEMORY_BASE"] = str(self.base)
        environment["HMK_INSTANCE_ID"] = self.instance
        environment.pop("HMK_DB_PATH", None)
        completed = subprocess.run(
            [
                sys.executable,
                str(self.root / "scripts/daimon_projection.py"),
                "--instance-id",
                self.instance,
                operation,
            ],
            input=canonical_bytes(document) + b"\n",
            capture_output=True,
            check=False,
            env=environment,
            timeout=30,
        )
        with self.lock:
            self.calls.append((operation, copy.deepcopy(dict(document))))
        if completed.returncode:
            try:
                diagnostic = json.loads(completed.stderr)
            except json.JSONDecodeError as exception:
                raise RuntimeError(
                    f"HMK CLI failed rc={completed.returncode} "
                    f"stderr={completed.stderr!r} stdout={completed.stdout!r}"
                ) from exception
            raise MemoryProjectionError(cast(str, diagnostic["code"]))
        result = cast(dict[str, Any], json.loads(completed.stdout))
        if self.lose_after == operation:
            self.lose_after = None
            raise ConnectionError("synthetic response loss")
        if self.corrupt_after == operation:
            self.corrupt_after = None
            connection = sqlite3.connect(self.database)
            connection.execute(
                """UPDATE chapters SET raw='post-response corruption'
                WHERE id=(SELECT chapter_id FROM daimon_projections LIMIT 1)"""
            )
            connection.commit()
            connection.close()
        return result

    def memoryctl(self, *arguments: str) -> dict[str, Any] | None:
        environment = os.environ.copy()
        environment["HMK_AGENT_MEMORY_BASE"] = str(self.base)
        environment.pop("HMK_DB_PATH", None)
        completed = subprocess.run(
            [sys.executable, str(self.root / "scripts/memoryctl.py"), *arguments],
            capture_output=True,
            check=True,
            env=environment,
            timeout=30,
        )
        return None if not completed.stdout else json.loads(completed.stdout)


class DM034ProjectionTests(RootLedgerFixture):
    def setUp(self) -> None:
        super().setUp()
        configured = os.environ.get("HMK_CONTRACT_ROOT")
        self.hmk_root = Path(configured) if configured else DEFAULT_HMK_ROOT
        if not (self.hmk_root / "scripts/daimon_projection.py").is_file():
            if configured:
                self.fail("configured pinned HMK contract checkout unavailable")
            self.skipTest("pinned HMK contract checkout unavailable")
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=self.hmk_root,
            check=True,
            capture_output=True,
            text=True,
        )
        if head.stdout.strip() != HMK_COMMIT:
            if configured:
                self.fail(f"configured HMK checkout is not exact pin {HMK_COMMIT}")
            self.skipTest(f"HMK checkout is not exact pin {HMK_COMMIT}")
        self.hmk_base = self.root_path / "hmk"
        self.hmk_base.mkdir(mode=0o700)
        self.transport = HMKCLITransport(
            self.hmk_root, self.hmk_base, instance="hmk:synthetic"
        )
        self.profile = create_projection_profile(
            source_instance="matrix:synthetic", target_instance="hmk:synthetic"
        )
        self.contents: dict[str, bytes] = {}
        self.policy = create_memory_policy(
            subject_me_id=self.state.being_ref,
            version=1,
            predecessor_policy_id=None,
            automatic_categories=[
                "personal-experience",
                "personal-insight",
                "personal-skill",
            ],
            review_classifications=[],
        )
        self.adapter = MemoryProjectionAdapter(
            ledger=self.ledger_a,
            profile=self.profile,
            transport=self.transport,
            content_resolver=self.resolve,
            journal=ProjectionJournal(self.root_path / "projection" / "journal.sqlite"),
        )

    def resolve(self, reference: Mapping[str, Any]) -> bytes:
        try:
            return self.contents[cast(str, reference["sha256"])]
        except KeyError as exception:
            raise FileNotFoundError("synthetic content absent") from exception

    def content(
        self,
        text: str,
        *,
        media_type: str = "text/plain",
        classification: str = "personal",
    ) -> dict[str, Any]:
        raw = text.encode("utf-8")
        digest = hashlib.sha256(raw).hexdigest()
        self.contents[digest] = raw
        return create_content_ref(
            sha256=digest,
            byte_length=len(raw),
            media_type=media_type,
            classification=classification,
        )

    def record(
        self,
        *,
        label: str,
        operation: str = "assert",
        text: str | None = "synthetic orchard memory",
        memory_id: str = MEMORY_ID,
        predecessor: dict[str, Any] | None = None,
        predecessor_decision_id: str | None = None,
        category: str = "personal-insight",
        author: str | None = None,
        media_type: str = "text/plain",
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        sequence = 1 if predecessor is None else predecessor["payload"]["sequence"] + 1
        reference = None if text is None else self.content(text, media_type=media_type)
        candidate = create_memory_candidate(
            subject_me_id=self.state.being_ref,
            author_me_id=author or self.state.being_ref,
            category=category,
            derivation="local-synthesis",
            context="autobiographical",
            content_ref=reference,
            evidence_refs=[],
            classification="personal",
            consent="granted",
            safety="clear",
            contradiction="none",
            effect="local-only",
            lane={
                "memory_id": memory_id,
                "operation": operation,
                "sequence": sequence,
                "predecessor_event_id": None
                if predecessor is None
                else predecessor["event_id"],
                "predecessor_hash": None
                if predecessor is None
                else predecessor["content_hash"],
            },
            body_evidence=None,
            predecessor_decision_id=predecessor_decision_id,
        )
        checkpoint = memory_checkpoint(self.ledger_a, candidate, captured_at_ms=NOW)
        plan = evaluate_memory_candidate(
            self.policy, candidate, checkpoint, evaluated_at_ms=NOW
        )
        self.assertEqual(plan["outcome"], "eligible")
        event = MemoryPolicyExecutor(
            self.ledger_a, self.signers["legion"], clock=lambda: NOW
        ).execute(
            plan,
            self.policy,
            candidate,
            client_id="dm034-test",
            request_id=str(uuid.uuid5(uuid.NAMESPACE_URL, "dm034:" + label)),
        )["event"]
        return event, plan

    def test_manifest_profile_and_exact_pin_are_closed(self) -> None:
        manifest = create_projection_manifest()
        self.assertEqual(validate_projection_manifest(manifest), manifest)
        self.assertEqual(manifest["capabilities"], list(CAPABILITIES))
        self.assertEqual(manifest["authority"]["matrix_authority"], False)
        self.assertEqual(validate_projection_profile(self.profile), self.profile)
        negotiated = negotiate_projection_manifest(manifest, accepted_versions=["v1"])
        self.assertEqual(negotiated["hmk_commit"], HMK_COMMIT)
        with self.assertRaisesRegex(
            MemoryProjectionError, "memory_projection_contract_unsupported"
        ):
            negotiate_projection_manifest(manifest, accepted_versions=["v0"])
        with self.assertRaisesRegex(
            MemoryProjectionError, "unsupported_memory_projection_profile"
        ):
            validate_projection_profile({**self.profile, "hmk_commit": "0" * 40})

    def test_public_schemas_cover_every_matrix_artifact_and_are_closed(self) -> None:
        contracts = json.loads(
            (ROOT / "schemas/memory-projection/v1/contracts.schema.json").read_bytes()
        )
        adapter_contracts = json.loads(
            (ROOT / "schemas/adapters/v0/contracts.schema.json").read_bytes()
        )
        Draft202012Validator.check_schema(contracts)
        Draft202012Validator.check_schema(adapter_contracts)
        validator = Draft202012Validator(contracts, format_checker=FormatChecker())
        adapter_validator = Draft202012Validator(
            adapter_contracts, format_checker=FormatChecker()
        )
        adapter_validator.validate(create_projection_manifest())

        event, _memory_plan = self.record(label="schema")
        receipt = self.adapter.project(
            event_id=event["event_id"], idempotency_key="matrix:schema"
        )
        journal = self.adapter.journal.lookup("matrix:schema")
        self.assertIsNotNone(journal)
        assert journal is not None
        recall = self.adapter.recall(memory_id=MEMORY_ID)
        reconciliation = self.adapter.reconcile(receipt)
        rebuild = self.adapter.rebuild_plan(
            request_id="34000000-0000-4000-8000-000000000030",
            idempotency_key="matrix:schema-rebuild",
        )
        rebuild_receipt = self.adapter.rebuild_apply(rebuild)
        artifacts = [
            self.profile,
            negotiate_projection_manifest(
                create_projection_manifest(), accepted_versions=["v1"]
            ),
            journal.intent,
            receipt,
            reconciliation,
            rebuild,
            rebuild_receipt,
            recall,
            projection_checkpoint(self.ledger_a),
        ]
        for artifact in artifacts:
            validator.validate(artifact)
            self.assertFalse(
                validator.is_valid({**artifact, "ambient_authority": True})
            )

    def test_vectors_bind_hmk_pin_validate_and_regenerate_byte_identically(
        self,
    ) -> None:
        index = json.loads((VECTOR_ROOT / "index.json").read_bytes())
        self.assertEqual(index["hmk_commit"], HMK_COMMIT)
        artifacts = {
            name: json.loads((VECTOR_ROOT / relative).read_bytes())
            for name, relative in index["artifacts"].items()
        }
        for name, artifact in artifacts.items():
            self.assertEqual(
                hashlib.sha256(canonical_bytes(artifact)).hexdigest(),
                index["sha256"][name],
            )
        self.assertEqual(
            validate_projection_manifest(artifacts["manifest"]),
            artifacts["manifest"],
        )
        self.assertEqual(
            validate_projection_profile(artifacts["profile"]), artifacts["profile"]
        )
        self.assertEqual(
            validate_projection_receipt(artifacts["receipt"]), artifacts["receipt"]
        )
        self.assertEqual(
            validate_rebuild_plan(artifacts["rebuild_plan"]),
            artifacts["rebuild_plan"],
        )
        self.assertEqual(
            validate_rebuild_receipt(artifacts["rebuild_receipt"]),
            artifacts["rebuild_receipt"],
        )
        with self.assertRaisesRegex(
            MemoryProjectionError, "memory_projection_receipt_effect_mismatch"
        ):
            validate_projection_receipt(artifacts["negative_receipt"])

        outputs = [self.root_path / "vectors-a", self.root_path / "vectors-b"]
        settings = [("1", "UTC"), ("947", "America/Argentina/Cordoba")]
        for output, (seed, timezone) in zip(outputs, settings, strict=True):
            environment = os.environ.copy()
            environment.update(
                {"PYTHONHASHSEED": seed, "TZ": timezone, "LC_ALL": "C.UTF-8"}
            )
            subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "tools/generate_dm034_vectors.py"),
                    "--output",
                    str(output),
                ],
                check=True,
                cwd=ROOT,
                env=environment,
                timeout=30,
            )
        expected = {
            path.relative_to(VECTOR_ROOT): path.read_bytes()
            for path in VECTOR_ROOT.rglob("*")
            if path.is_file()
        }
        for output in outputs:
            actual = {
                path.relative_to(output): path.read_bytes()
                for path in output.rglob("*")
                if path.is_file()
            }
            self.assertEqual(actual, expected)

    def test_assert_correct_retract_replay_and_verified_recall(self) -> None:
        asserted, asserted_plan = self.record(label="assert")
        first = self.adapter.project(
            event_id=asserted["event_id"], idempotency_key="matrix:assert"
        )
        self.assertEqual(validate_projection_receipt(first), first)
        self.assertEqual(
            self.adapter.project(
                event_id=asserted["event_id"], idempotency_key="matrix:assert"
            ),
            first,
        )
        recalled = self.adapter.recall(memory_id=MEMORY_ID)
        self.assertEqual(recalled["statement"]["text"], "synthetic orchard memory")
        self.assertEqual(recalled["origin"]["kind"], "daimon-projection")
        self.assertEqual(recalled["origin"]["head"]["event_id"], asserted["event_id"])

        corrected, corrected_plan = self.record(
            label="correct",
            operation="correct",
            text="# Corrected\n\nThe river path is canonical.",
            media_type="text/markdown",
            predecessor=asserted,
            predecessor_decision_id=asserted_plan["decision_id"],
        )
        correction = self.adapter.project(
            event_id=corrected["event_id"], idempotency_key="matrix:correct"
        )
        self.assertEqual(correction["operation"], "advance")
        self.assertEqual(
            self.adapter.recall(memory_id=MEMORY_ID)["statement"]["media_type"],
            "text/markdown",
        )

        retracted, _retracted_plan = self.record(
            label="retract",
            operation="retract",
            text=None,
            predecessor=corrected,
            predecessor_decision_id=corrected_plan["decision_id"],
        )
        receipt = self.adapter.project(
            event_id=retracted["event_id"], idempotency_key="matrix:retract"
        )
        self.assertEqual(receipt["operation"], "retract")
        self.assertEqual(receipt["effect"]["active"], False)
        with self.assertRaisesRegex(
            MemoryProjectionError, "memory_projection_inactive"
        ):
            self.adapter.recall(memory_id=MEMORY_ID)

    def test_response_loss_replays_exact_pending_request_and_truth_not_blind_cache(
        self,
    ) -> None:
        event, _plan = self.record(label="response-loss")
        self.transport.lose_after = "apply"
        with self.assertRaisesRegex(
            MemoryProjectionError, "memory_projection_transport_unavailable"
        ):
            self.adapter.project(
                event_id=event["event_id"], idempotency_key="matrix:response-loss"
            )
        self.assertEqual(self.adapter.journal.integrity()["pending"], 1)
        connection = sqlite3.connect(self.transport.database)
        connection.execute(
            """UPDATE chapters SET raw='tampered'
            WHERE id=(SELECT chapter_id FROM daimon_projections LIMIT 1)"""
        )
        connection.commit()
        connection.close()
        with self.assertRaisesRegex(MemoryProjectionError, "projection_content_drift"):
            self.adapter.project(
                event_id=event["event_id"], idempotency_key="matrix:response-loss"
            )
        self.assertEqual(self.adapter.journal.integrity()["pending"], 1)
        connection = sqlite3.connect(self.transport.database)
        connection.execute(
            """UPDATE chapters SET raw='synthetic orchard memory'
            WHERE id=(SELECT chapter_id FROM daimon_projections LIMIT 1)"""
        )
        connection.commit()
        connection.close()
        recovered = self.adapter.project(
            event_id=event["event_id"], idempotency_key="matrix:response-loss"
        )
        self.assertEqual(recovered["outcome"], "applied")
        self.assertEqual(self.adapter.journal.integrity()["completed"], 1)
        requests = [
            document
            for operation, document in self.transport.calls
            if operation == "apply"
        ]
        self.assertEqual(canonical_bytes(requests[0]), canonical_bytes(requests[1]))

        connection = sqlite3.connect(self.transport.database)
        connection.execute(
            """UPDATE chapters SET raw='tampered'
            WHERE id=(SELECT chapter_id FROM daimon_projections LIMIT 1)"""
        )
        connection.commit()
        connection.close()
        with self.assertRaisesRegex(MemoryProjectionError, "projection_content_drift"):
            self.adapter.project(
                event_id=event["event_id"], idempotency_key="matrix:response-loss"
            )

    def test_receipt_identity_and_effect_are_recomputed_not_shape_trusted(self) -> None:
        event, _plan = self.record(label="receipt-binding")
        receipt = self.adapter.project(
            event_id=event["event_id"], idempotency_key="matrix:receipt-binding"
        )
        wrong_source = copy.deepcopy(receipt)
        wrong_source["source_instance"] = "matrix:substituted"
        with self.assertRaisesRegex(
            MemoryProjectionError, "memory_projection_receipt_effect_mismatch"
        ):
            validate_projection_receipt(wrong_source)
        wrong_statement = copy.deepcopy(receipt)
        wrong_statement["effect"]["statement"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(
            MemoryProjectionError, "memory_projection_receipt_effect_mismatch"
        ):
            validate_projection_receipt(wrong_statement)
        wrong_operation = copy.deepcopy(receipt)
        wrong_operation["operation"] = "advance"
        with self.assertRaisesRegex(
            MemoryProjectionError, "invalid_memory_projection_receipt"
        ):
            validate_projection_receipt(wrong_operation)

    def test_fresh_provider_receipt_is_observed_before_local_success(self) -> None:
        event, _plan = self.record(label="post-response-observation")
        self.transport.corrupt_after = "apply"
        with self.assertRaisesRegex(MemoryProjectionError, "projection_content_drift"):
            self.adapter.project(
                event_id=event["event_id"],
                idempotency_key="matrix:post-response-observation",
            )
        self.assertEqual(self.adapter.journal.integrity()["pending"], 1)

    def test_rebuild_rebinds_embedded_hmk_plan_and_refuses_checkpoint_drift(
        self,
    ) -> None:
        first, _first_plan = self.record(label="rebuild-binding")
        self.adapter.project(
            event_id=first["event_id"], idempotency_key="matrix:rebuild-binding"
        )
        plan = self.adapter.rebuild_plan(
            request_id="34000000-0000-4000-8000-000000000020",
            idempotency_key="matrix:rebuild-binding-plan",
        )
        substituted = copy.deepcopy(plan)
        substituted["hmk_plan"]["namespace_id"] = (
            "hmk:daimon-namespace:v1:"
            + base64.urlsafe_b64encode(b"\x00" * 32).rstrip(b"=").decode()
        )
        substituted["hmk_plan_hash"] = hashlib.sha256(
            canonical_bytes(substituted["hmk_plan"])
        ).hexdigest()
        body = {key: substituted[key] for key in substituted if key != "plan_id"}
        substituted["plan_id"] = "dm:memory-projection-rebuild-plan:v1:" + (
            base64.urlsafe_b64encode(
                hashlib.sha256(
                    b"daimon/memory-projection/rebuild-plan/v1\x00"
                    + canonical_bytes(body)
                ).digest()
            )
            .rstrip(b"=")
            .decode()
        )
        with self.assertRaisesRegex(
            MemoryProjectionError, "hmk_rebuild_plan_binding_mismatch"
        ):
            self.adapter.rebuild_apply(substituted)

        self.record(
            label="rebuild-checkpoint-drift",
            memory_id="34000000-0000-4000-8000-000000000003",
            text="checkpoint drift",
        )
        with self.assertRaisesRegex(
            MemoryProjectionError, "rebuild_matrix_checkpoint_drift"
        ):
            self.adapter.rebuild_apply(plan)

    def test_concurrent_duplicate_and_conflicting_routes(self) -> None:
        event, _plan = self.record(label="concurrent")

        def invoke() -> dict[str, Any]:
            return self.adapter.project(
                event_id=event["event_id"], idempotency_key="matrix:concurrent"
            )

        with ThreadPoolExecutor(max_workers=2) as pool:
            receipts = list(pool.map(lambda _index: invoke(), range(2)))
        self.assertEqual(receipts[0], receipts[1])
        other, _other_plan = self.record(
            label="other-memory",
            memory_id="34000000-0000-4000-8000-000000000002",
            text="another lane",
        )
        with self.assertRaisesRegex(
            MemoryProjectionError, "memory_projection_idempotency_conflict"
        ):
            self.adapter.project(
                event_id=other["event_id"], idempotency_key="matrix:concurrent"
            )

    def test_rebuild_is_deterministic_repairs_deleted_projection_and_preserves_native(
        self,
    ) -> None:
        first, _first_plan = self.record(label="rebuild-a")
        self.adapter.project(
            event_id=first["event_id"], idempotency_key="matrix:rebuild-a"
        )
        second, _second_plan = self.record(
            label="rebuild-b",
            memory_id="34000000-0000-4000-8000-000000000002",
            text="second rebuild lane",
        )
        self.adapter.project(
            event_id=second["event_id"], idempotency_key="matrix:rebuild-b"
        )
        self.transport.memoryctl(
            "add-text",
            "--shelf",
            "library",
            "--title",
            "native survivor",
            "--raw",
            "native survivor bytes",
        )
        before = self.adapter.verify()
        plan = self.adapter.rebuild_plan(
            request_id="34000000-0000-4000-8000-000000000010",
            idempotency_key="matrix:full-rebuild",
        )
        self.assertEqual(validate_rebuild_plan(plan), plan)
        self.assertEqual(
            canonical_bytes(plan),
            canonical_bytes(
                self.adapter.rebuild_plan(
                    request_id="34000000-0000-4000-8000-000000000010",
                    idempotency_key="matrix:full-rebuild",
                )
            ),
        )

        connection = sqlite3.connect(self.transport.database)
        projection_rows = connection.execute(
            "SELECT chapter_id FROM daimon_projections"
        ).fetchall()
        connection.execute("DELETE FROM daimon_projections")
        for (chapter_id,) in projection_rows:
            book_id = connection.execute(
                "SELECT book_id FROM chapters WHERE id=?", (chapter_id,)
            ).fetchone()[0]
            connection.execute("DELETE FROM chapters WHERE id=?", (chapter_id,))
            connection.execute("DELETE FROM books WHERE id=?", (book_id,))
        connection.commit()
        connection.close()

        receipt = self.adapter.rebuild_apply(plan)
        self.assertEqual(validate_rebuild_receipt(receipt), receipt)
        after = self.adapter.verify()
        self.assertEqual(after["logical_hash"], before["logical_hash"])
        connection = sqlite3.connect(self.transport.database)
        self.assertEqual(
            connection.execute(
                "SELECT COUNT(*) FROM chapters WHERE raw='native survivor bytes'"
            ).fetchone()[0],
            1,
        )
        connection.close()

    def test_read_only_dry_run_backup_cutover_and_restore_mixed_hmk_state(
        self,
    ) -> None:
        self.transport.memoryctl(
            "add-text",
            "--shelf",
            "library",
            "--title",
            "native pre-cutover",
            "--raw",
            "native authority survives projection cutover",
        )
        indexed_file = self.root_path / "synthetic-wiki/raw/indexed-note.md"
        indexed_file.parent.mkdir(parents=True, mode=0o700)
        indexed_file.write_text(
            "authoritative file index survives projection cutover",
            encoding="utf-8",
        )
        self.transport.memoryctl(
            "add-file",
            "--shelf",
            "evidence",
            "--path",
            str(indexed_file),
            "--title",
            "file-origin pre-cutover index",
        )
        stats_before = cast(dict[str, Any], self.transport.memoryctl("stats"))
        database_before = hashlib.sha256(
            self.transport.database.read_bytes()
        ).hexdigest()
        backup = self.root_path / "backups" / "library.pre-dm034.sqlite"
        backup.parent.mkdir(mode=0o700)
        source_connection = sqlite3.connect(
            f"file:{self.transport.database}?mode=ro", uri=True
        )
        backup_connection = sqlite3.connect(backup)
        source_connection.backup(backup_connection)
        source_connection.close()
        self.assertEqual(
            backup_connection.execute("PRAGMA integrity_check").fetchone()[0], "ok"
        )
        self.assertEqual(
            backup_connection.execute("PRAGMA foreign_key_check").fetchall(), []
        )
        origin_counts = {
            str(kind): int(count)
            for kind, count in backup_connection.execute(
                """SELECT b.source_kind, COUNT(*)
                FROM chapters c JOIN books b ON b.id=c.book_id
                GROUP BY b.source_kind ORDER BY b.source_kind"""
            ).fetchall()
        }
        self.assertEqual(origin_counts, {"file": 1, "text": 1})
        backup_connection.close()
        self.assertGreater(backup.stat().st_size, 0)

        _event, _memory_plan = self.record(label="migration-cutover")
        plan = self.adapter.rebuild_plan(
            request_id="34000000-0000-4000-8000-000000000040",
            idempotency_key="matrix:migration-cutover",
        )
        self.assertIsNone(plan["hmk_plan"]["prior"])
        self.assertEqual(
            hashlib.sha256(self.transport.database.read_bytes()).hexdigest(),
            database_before,
        )
        self.adapter.rebuild_apply(plan)
        self.assertEqual(
            self.adapter.recall(memory_id=MEMORY_ID)["origin"]["kind"],
            "daimon-projection",
        )
        native_results = cast(
            list[dict[str, Any]],
            self.transport.memoryctl(
                "search", "--query", "native authority", "--limit", "8"
            ),
        )
        self.assertEqual(len(native_results), 1)
        self.assertEqual(native_results[0]["origin"]["kind"], "text")
        indexed_results = cast(
            list[dict[str, Any]],
            self.transport.memoryctl(
                "search", "--query", "authoritative file index", "--limit", "8"
            ),
        )
        self.assertEqual(len(indexed_results), 1)
        self.assertEqual(indexed_results[0]["origin"]["kind"], "file")
        stats_after = cast(dict[str, Any], self.transport.memoryctl("stats"))
        self.assertEqual(stats_after["chapters"], stats_before["chapters"] + 1)

        restored_base = self.root_path / "restored-hmk"
        restored_base.mkdir(mode=0o700)
        restored_database = restored_base / "library.db"
        backup_source = sqlite3.connect(f"file:{backup}?mode=ro", uri=True)
        restored_connection = sqlite3.connect(restored_database)
        backup_source.backup(restored_connection)
        backup_source.close()
        restored_connection.close()
        restored_transport = HMKCLITransport(
            self.hmk_root, restored_base, instance="hmk:synthetic"
        )
        restored_stats = cast(dict[str, Any], restored_transport.memoryctl("stats"))
        for field in (
            "shelves",
            "books",
            "chapters",
            "embeddings",
            "links",
            "suggestions",
            "suggestions_total",
            "queries",
            "embed_disabled",
            "embed_disabled_by_reason",
            "embedding_sets",
        ):
            self.assertEqual(restored_stats[field], stats_before[field])
        restored_adapter = MemoryProjectionAdapter(
            ledger=self.ledger_a,
            profile=self.profile,
            transport=restored_transport,
            content_resolver=self.resolve,
            journal=ProjectionJournal(
                self.root_path / "restored-journal/journal.sqlite"
            ),
        )
        with self.assertRaisesRegex(
            MemoryProjectionError, "projection_namespace_unknown"
        ):
            restored_adapter.verify()

    def test_content_policy_category_and_checkpoint_fail_closed(self) -> None:
        unsupported, _plan = self.record(
            label="unsupported-media", media_type="application/octet-stream"
        )
        with self.assertRaisesRegex(
            MemoryProjectionError, "memory_projection_content_mismatch"
        ):
            self.adapter.project(
                event_id=unsupported["event_id"],
                idempotency_key="matrix:unsupported-media",
            )
        self.contents.clear()
        with self.assertRaisesRegex(
            MemoryProjectionError, "memory_projection_content_unavailable"
        ):
            self.adapter.project(
                event_id=unsupported["event_id"],
                idempotency_key="matrix:missing-content",
            )
        checkpoint = projection_checkpoint(self.ledger_a)
        self.assertEqual(checkpoint["sequence"], 1)
        self.append(self.ledger_a, "legion", "unrelated event")
        self.assertEqual(projection_checkpoint(self.ledger_a), checkpoint)

    def test_nonpersonal_records_are_excluded_and_personal_lane_forks_fail(
        self,
    ) -> None:
        event, _plan = self.record(label="lane-authority")
        checkpoint = projection_checkpoint(self.ledger_a)
        external = copy.deepcopy(event["payload"])
        external["memory_id"] = "34000000-0000-4000-8000-000000000090"
        external["category"] = "external-reference"
        external["author_me_id"] = "source:synthetic"
        self.ledger_a.append_local(
            kind="memory.recorded",
            subject=self.state.being_ref,
            payload=external,
            signer=self.signers["legion"],
            occurred_at_ms=NOW,
        )
        self.assertEqual(projection_checkpoint(self.ledger_a), checkpoint)

        fork = copy.deepcopy(event["payload"])
        fork["content_ref"] = self.content("competing root")
        self.ledger_a.append_local(
            kind="memory.recorded",
            subject=self.state.being_ref,
            payload=fork,
            signer=self.signers["legion"],
            occurred_at_ms=NOW,
        )
        with self.assertRaisesRegex(
            MemoryProjectionError, "memory_projection_lane_forked"
        ):
            projection_checkpoint(self.ledger_a)

    def test_generic_hmk_mutations_cannot_modify_projection_managed_rows(self) -> None:
        event, _plan = self.record(label="generic-mutation")
        self.adapter.project(
            event_id=event["event_id"], idempotency_key="matrix:generic-mutation"
        )
        results = cast(
            list[dict[str, Any]],
            self.transport.memoryctl(
                "search", "--query", "synthetic orchard memory", "--limit", "8"
            ),
        )
        self.assertEqual(len(results), 1)
        chapter_id = str(results[0]["id"])
        for arguments in (
            ("update", "--id", chapter_id, "--raw", "generic overwrite"),
            ("delete", "--id", chapter_id),
            (
                "add-text",
                "--shelf",
                "daimon-projection",
                "--title",
                "collision",
                "--raw",
                "generic collision",
            ),
        ):
            with (
                self.subTest(arguments=arguments),
                self.assertRaises(subprocess.CalledProcessError),
            ):
                self.transport.memoryctl(*arguments)
        self.assertEqual(
            self.adapter.recall(memory_id=MEMORY_ID)["statement"]["text"],
            "synthetic orchard memory",
        )


if __name__ == "__main__":
    unittest.main()
