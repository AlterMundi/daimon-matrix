from __future__ import annotations

import copy
import hashlib
import json
import os
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, cast

from jsonschema import (  # type: ignore[import-untyped]
    Draft202012Validator,
    FormatChecker,
)
from referencing import Registry, Resource

from daimon_matrix.canonical import canonical_bytes
from daimon_matrix.client import (
    CLIENT_CONFIG_SCHEMA,
    ClientConfig,
    ClientError,
    LocalClient,
)
from daimon_matrix.daemon import serve_forever
from daimon_matrix.ledger import LedgerStateError
from daimon_matrix.memory_policy import (
    MemoryExecutionError,
    MemoryPolicyError,
    MemoryPolicyExecutor,
    create_content_ref,
    create_memory_candidate,
    create_memory_policy,
    evaluate_memory_candidate,
    memory_checkpoint,
    memory_decision,
    validate_content_ref,
    validate_memory_candidate,
    validate_memory_checkpoint,
    validate_memory_decision,
    validate_memory_plan,
    validate_memory_policy,
    validate_policy_successor,
)
from daimon_matrix.projections import ProjectionEngine
from daimon_matrix.runtime import load_runtime
from tests.test_dm022_ledger import NOW, RootLedgerFixture
from tests.test_dm024_runtime import PASSWORD, RuntimeFixture
from tools.generate_dm030_vectors import generate as generate_vectors

ROOT = Path(__file__).resolve().parents[1]
VECTOR_ROOT = ROOT / "vectors/memory/v1"


class MemoryPolicyTests(RootLedgerFixture):
    def setUp(self) -> None:
        super().setUp()
        self.policy = create_memory_policy(
            subject_me_id=self.state.being_ref,
            version=1,
            predecessor_policy_id=None,
            automatic_categories=[
                "external-reference",
                "incarnation-state",
                "peer-attributed",
                "personal-experience",
                "personal-insight",
                "personal-skill",
                "species-inheritance",
                "tribal-knowledge",
            ],
            review_classifications=["protected"],
        )
        self.content = create_content_ref(
            sha256=hashlib.sha256(b"synthetic memory").hexdigest(),
            byte_length=16,
            media_type="text/plain",
            classification="personal",
        )
        self.evidence = self.append(
            self.ledger_a,
            "legion",
            "body occurrence evidence",
            payload={
                "summary": "body occurrence evidence",
                "session_ref": "session:synthetic",
                "lease_ref": "lease:synthetic",
            },
        )

    def candidate(self, **changes: Any) -> dict[str, Any]:
        origin = self.origins["legion"]
        values: dict[str, Any] = {
            "subject_me_id": self.state.being_ref,
            "author_me_id": self.state.being_ref,
            "category": "personal-experience",
            "derivation": "body-occurrence",
            "context": "autobiographical",
            "content_ref": self.content,
            "evidence_refs": [self.evidence["event_id"]],
            "classification": "personal",
            "consent": "granted",
            "safety": "clear",
            "contradiction": "none",
            "effect": "local-only",
            "lane": {
                "memory_id": "10000000-0000-4000-8000-000000000030",
                "operation": "assert",
                "sequence": 1,
                "predecessor_event_id": None,
                "predecessor_hash": None,
            },
            "body_evidence": {
                "body_ref": origin["body_ref"],
                "embodiment_id": origin["embodiment_id"],
                "incarnation_id": origin["incarnation_id"],
                "session_ref": "session:synthetic",
                "lease_ref": "lease:synthetic",
                "committed_cutoff_event_id": self.evidence["event_id"],
            },
        }
        values.update(changes)
        return create_memory_candidate(**values)

    def plan(self, candidate: dict[str, Any] | None = None) -> dict[str, Any]:
        selected = self.candidate() if candidate is None else candidate
        checkpoint = memory_checkpoint(self.ledger_a, selected, captured_at_ms=NOW)
        return evaluate_memory_candidate(
            self.policy,
            selected,
            checkpoint,
            evaluated_at_ms=NOW,
        )

    def test_canonical_equivalent_inputs_are_byte_identical_and_eligible(self) -> None:
        candidate = self.candidate()
        first = self.plan(candidate)
        reordered = {key: copy.deepcopy(candidate[key]) for key in reversed(candidate)}
        second = self.plan(reordered)
        self.assertEqual(first["outcome"], "eligible")
        self.assertEqual(first["reasons"], [])
        self.assertEqual(canonical_bytes(first), canonical_bytes(second))
        self.assertEqual(first["plan_id"], second["plan_id"])
        self.assertNotIn("path", canonical_bytes(first).decode())

    def test_attributed_material_retains_authority_without_personal_promotion(
        self,
    ) -> None:
        candidate = self.candidate(
            author_me_id="being:peer-author",
            category="peer-attributed",
            derivation="peer-origin",
            body_evidence=None,
        )
        plan = self.plan(candidate)
        self.assertEqual(plan["outcome"], "eligible")
        payload = plan["event_preview"]["payload"]
        self.assertEqual(payload["category"], "peer-attributed")
        self.assertEqual(payload["author_me_id"], "being:peer-author")

        promoted = self.candidate(
            category="personal-insight",
            derivation="external-source",
            body_evidence=None,
        )
        self.assertEqual(self.plan(promoted)["outcome"], "rejected")
        self.assertEqual(
            self.plan(promoted)["reasons"], ["category-derivation-mismatch"]
        )

    def test_total_outcome_precedence_is_fail_closed(self) -> None:
        missing = self.candidate(evidence_refs=[str(uuid.UUID(int=999))])
        self.assertEqual(self.plan(missing)["outcome"], "deferred:incomplete")

        false_author = self.candidate(author_me_id="being:other")
        self.assertEqual(self.plan(false_author)["outcome"], "rejected")
        self.assertEqual(self.plan(false_author)["reasons"], ["false-personal-author"])

        unsafe = self.candidate(safety="unsafe")
        self.assertEqual(self.plan(unsafe)["outcome"], "quarantined")

        review = self.candidate(contradiction="sensitive")
        self.assertEqual(self.plan(review)["outcome"], "review-required")
        self.assertEqual(self.plan(review)["reasons"], ["sensitive-contradiction"])

    def test_content_refs_are_closed_bounded_and_locator_free(self) -> None:
        changed = {**self.content, "path": "/private/memory"}
        with self.assertRaisesRegex(MemoryPolicyError, "invalid_memory_content_ref"):
            validate_content_ref(changed)
        with self.assertRaisesRegex(MemoryPolicyError, "invalid_memory_content_size"):
            create_content_ref(
                sha256="a" * 64,
                byte_length=0,
                media_type="text/plain",
                classification="private",
            )

    def test_executor_commits_once_and_exact_retry_survives_state_change(self) -> None:
        candidate = self.candidate()
        plan = self.plan(candidate)
        executor = MemoryPolicyExecutor(
            self.ledger_a,
            self.signers["legion"],
            clock=lambda: NOW,
        )
        request_id = "20000000-0000-4000-8000-000000000030"
        first = executor.execute(
            plan,
            self.policy,
            candidate,
            client_id="memory-policy-test",
            request_id=request_id,
        )
        second = executor.execute(
            plan,
            self.policy,
            candidate,
            client_id="memory-policy-test",
            request_id=request_id,
        )
        self.assertEqual(first, second)
        event = first["event"]
        self.assertEqual(event["kind"], "memory.recorded")
        self.assertEqual(event["payload"], plan["event_preview"]["payload"])
        self.assertEqual(
            len(
                [
                    item
                    for item in self.ledger_a.events()
                    if item["kind"] == "memory.recorded"
                ]
            ),
            1,
        )
        projection = ProjectionEngine(self.ledger_a).snapshot()
        self.assertIn(
            event["event_id"], {entry["event_id"] for entry in projection["entries"]}
        )

    def test_executor_rejects_review_plan_and_atomic_stale_checkpoint(self) -> None:
        review_candidate = self.candidate(contradiction="sensitive")
        review_plan = self.plan(review_candidate)
        executor = MemoryPolicyExecutor(
            self.ledger_a,
            self.signers["legion"],
            clock=lambda: NOW,
        )
        with self.assertRaisesRegex(
            MemoryExecutionError, "memory_plan_not_automatically_executable"
        ):
            executor.execute(
                review_plan,
                self.policy,
                review_candidate,
                client_id="memory-policy-test",
                request_id="30000000-0000-4000-8000-000000000030",
            )

        candidate = self.candidate()
        stale = self.plan(candidate)
        self.append(self.ledger_a, "legion", "concurrent evidence")
        with self.assertRaisesRegex(MemoryExecutionError, "memory_plan_stale"):
            executor.execute(
                stale,
                self.policy,
                candidate,
                client_id="memory-policy-test",
                request_id="40000000-0000-4000-8000-000000000030",
            )

        fresh_ledger_candidate = self.candidate(
            lane={
                **candidate["lane"],
                "memory_id": "41000000-0000-4000-8000-000000000030",
            }
        )
        fresh_plan = self.plan(fresh_ledger_candidate)
        successor = create_memory_policy(
            subject_me_id=self.state.being_ref,
            version=2,
            predecessor_policy_id=self.policy["policy_id"],
            automatic_categories=["personal-experience"],
            review_classifications=["protected"],
        )
        with self.assertRaisesRegex(
            MemoryExecutionError, "memory_plan_revalidation_mismatch"
        ):
            executor.execute(
                fresh_plan,
                successor,
                fresh_ledger_candidate,
                client_id="memory-policy-test",
                request_id="42000000-0000-4000-8000-000000000030",
            )

        expired_executor = MemoryPolicyExecutor(
            self.ledger_a,
            self.signers["legion"],
            clock=lambda: fresh_plan["expires_at_ms"] + 1,
        )
        with self.assertRaisesRegex(MemoryExecutionError, "memory_plan_expired"):
            expired_executor.execute(
                fresh_plan,
                self.policy,
                fresh_ledger_candidate,
                client_id="memory-policy-test",
                request_id="43000000-0000-4000-8000-000000000030",
            )

    def test_memory_lane_successor_is_exact_and_invariants_do_not_drift(self) -> None:
        candidate = self.candidate()
        plan = self.plan(candidate)
        executor = MemoryPolicyExecutor(
            self.ledger_a,
            self.signers["legion"],
            clock=lambda: NOW,
        )
        first = executor.execute(
            plan,
            self.policy,
            candidate,
            client_id="memory-policy-test",
            request_id="50000000-0000-4000-8000-000000000030",
        )["event"]
        replacement = create_content_ref(
            sha256=hashlib.sha256(b"corrected").hexdigest(),
            byte_length=9,
            media_type="text/plain",
            classification="personal",
        )
        successor_lane = {
            "memory_id": first["payload"]["memory_id"],
            "operation": "correct",
            "sequence": 2,
            "predecessor_event_id": first["event_id"],
            "predecessor_hash": first["content_hash"],
        }
        with self.assertRaisesRegex(MemoryPolicyError, "missing_predecessor_decision"):
            self.candidate(content_ref=replacement, lane=successor_lane)
        wrong_decision = self.candidate(
            content_ref=replacement,
            predecessor_decision_id="dm:memory-decision:v1:" + "A" * 43,
            lane=successor_lane,
        )
        self.assertEqual(
            self.plan(wrong_decision)["reasons"],
            ["memory-lane-predecessor-mismatch"],
        )
        correction = self.candidate(
            content_ref=replacement,
            predecessor_decision_id=plan["decision_id"],
            lane=successor_lane,
        )
        correction_plan = self.plan(correction)
        self.assertEqual(correction_plan["outcome"], "eligible")
        corrected = executor.execute(
            correction_plan,
            self.policy,
            correction,
            client_id="memory-policy-test",
            request_id="60000000-0000-4000-8000-000000000030",
        )["event"]
        self.assertEqual(corrected["supersedes"], first["event_id"])
        self.assertEqual(
            corrected["payload"]["predecessor_decision_id"], plan["decision_id"]
        )

        drift = self.candidate(
            author_me_id="being:other",
            category="peer-attributed",
            derivation="peer-origin",
            body_evidence=None,
            predecessor_decision_id=correction_plan["decision_id"],
            lane={
                "memory_id": first["payload"]["memory_id"],
                "operation": "correct",
                "sequence": 3,
                "predecessor_event_id": corrected["event_id"],
                "predecessor_hash": corrected["content_hash"],
            },
        )
        drift_plan = self.plan(drift)
        self.assertEqual(drift_plan["outcome"], "quarantined")
        self.assertEqual(drift_plan["reasons"], ["memory-lane-invariant-mismatch"])

    def test_plan_and_ledger_guard_tampering_fail(self) -> None:
        candidate = self.candidate()
        plan = self.plan(candidate)
        changed = copy.deepcopy(plan)
        changed["expires_at_ms"] += 1
        with self.assertRaisesRegex(MemoryPolicyError, "memory_plan_id_mismatch"):
            validate_memory_plan(changed)

        with self.assertRaisesRegex(LedgerStateError, "ledger_state_changed"):
            self.ledger_a.append_local_idempotent(
                client_id="guard-test",
                request_id="70000000-0000-4000-8000-000000000030",
                request_hash="a" * 64,
                kind="experience.observed",
                subject="guarded",
                payload={"summary": "guarded"},
                signer=self.signers["legion"],
                expected_state_hash="b" * 64,
            )

    def test_body_cutoff_session_lease_and_origin_are_exact_evidence(self) -> None:
        for field, replacement in (
            ("lease_ref", "lease:substituted"),
            ("session_ref", "session:substituted"),
            ("body_ref", "cluster:substituted:body"),
        ):
            body = copy.deepcopy(self.candidate()["body_evidence"])
            body[field] = replacement
            candidate = self.candidate(body_evidence=body)
            with self.subTest(field=field):
                plan = self.plan(candidate)
                self.assertEqual(plan["outcome"], "rejected")
                self.assertEqual(plan["reasons"], ["body-evidence-mismatch"])

        missing_id = "80000000-0000-4000-8000-000000000030"
        body = copy.deepcopy(self.candidate()["body_evidence"])
        body["committed_cutoff_event_id"] = missing_id
        incomplete = self.candidate(body_evidence=body, evidence_refs=[missing_id])
        self.assertEqual(self.plan(incomplete)["outcome"], "deferred:incomplete")

    def test_every_category_derivation_retains_its_exact_authority(self) -> None:
        rows = (
            ("personal-insight", "local-synthesis", self.state.being_ref),
            ("personal-skill", "local-synthesis", self.state.being_ref),
            ("peer-attributed", "peer-origin", "dm:being:v1:" + "A" * 43),
            ("external-reference", "external-source", "source:publisher"),
            ("tribal-knowledge", "tribe-retrieval", "tribe:authority"),
            ("species-inheritance", "species-application", "species:authority"),
            ("incarnation-state", "incarnation-observation", self.state.being_ref),
        )
        for category, derivation, author in rows:
            candidate = self.candidate(
                category=category,
                derivation=derivation,
                author_me_id=author,
                body_evidence=None,
            )
            with self.subTest(category=category):
                plan = self.plan(candidate)
                self.assertEqual(plan["outcome"], "eligible")
                self.assertEqual(plan["event_preview"]["payload"]["category"], category)
                self.assertEqual(
                    plan["event_preview"]["payload"]["author_me_id"], author
                )

    def test_policy_succession_is_exact_and_never_reinterprets_prior_plan(self) -> None:
        candidate = self.candidate()
        prior_plan = canonical_bytes(self.plan(candidate))
        successor = create_memory_policy(
            subject_me_id=self.state.being_ref,
            version=2,
            predecessor_policy_id=self.policy["policy_id"],
            automatic_categories=["personal-experience"],
            review_classifications=["private", "protected"],
        )
        self.assertEqual(validate_policy_successor(self.policy, successor), successor)
        self.assertEqual(canonical_bytes(self.plan(candidate)), prior_plan)
        wrong = create_memory_policy(
            subject_me_id=self.state.being_ref,
            version=2,
            predecessor_policy_id="dm:memory-policy:v1:" + "A" * 43,
            automatic_categories=["personal-experience"],
            review_classifications=["protected"],
        )
        with self.assertRaisesRegex(
            MemoryPolicyError, "invalid_memory_policy_successor"
        ):
            validate_policy_successor(self.policy, wrong)

    def test_retraction_retains_complete_history_and_nulls_only_new_content(
        self,
    ) -> None:
        candidate = self.candidate()
        executor = MemoryPolicyExecutor(
            self.ledger_a, self.signers["legion"], clock=lambda: NOW
        )
        asserted_plan = self.plan(candidate)
        asserted = executor.execute(
            asserted_plan,
            self.policy,
            candidate,
            client_id="memory-retraction-test",
            request_id="81000000-0000-4000-8000-000000000030",
        )["event"]
        retraction = self.candidate(
            content_ref=None,
            predecessor_decision_id=asserted_plan["decision_id"],
            lane={
                "memory_id": asserted["payload"]["memory_id"],
                "operation": "retract",
                "sequence": 2,
                "predecessor_event_id": asserted["event_id"],
                "predecessor_hash": asserted["content_hash"],
            },
        )
        retracted = executor.execute(
            self.plan(retraction),
            self.policy,
            retraction,
            client_id="memory-retraction-test",
            request_id="82000000-0000-4000-8000-000000000030",
        )["event"]
        history = [
            event
            for event in self.ledger_a.events()
            if event["kind"] == "memory.recorded"
        ]
        self.assertEqual(
            [event["payload"]["operation"] for event in history],
            ["assert", "retract"],
        )
        self.assertIsNone(retracted["payload"]["content_ref"])
        self.assertEqual(history[0], asserted)

    def test_cross_embodiment_same_lane_fork_is_quarantined_without_winner(
        self,
    ) -> None:
        base: dict[str, Any] = {
            "category": "personal-insight",
            "derivation": "local-synthesis",
            "body_evidence": None,
            "evidence_refs": [],
        }
        candidate_a = self.candidate(**base)
        candidate_b = self.candidate(**base)
        event_a = MemoryPolicyExecutor(
            self.ledger_a, self.signers["legion"], clock=lambda: NOW
        ).execute(
            self.plan(candidate_a),
            self.policy,
            candidate_a,
            client_id="fork-a",
            request_id="83000000-0000-4000-8000-000000000030",
        )["event"]
        checkpoint_b = memory_checkpoint(self.ledger_b, candidate_b, captured_at_ms=NOW)
        plan_b = evaluate_memory_candidate(
            self.policy, candidate_b, checkpoint_b, evaluated_at_ms=NOW
        )
        event_b = MemoryPolicyExecutor(
            self.ledger_b, self.signers["daimonmatrix"], clock=lambda: NOW
        ).execute(
            plan_b,
            self.policy,
            candidate_b,
            client_id="fork-b",
            request_id="84000000-0000-4000-8000-000000000030",
        )["event"]
        self.assertNotEqual(event_a["event_id"], event_b["event_id"])
        self.ledger_a.ingest([event_b], source="embodiment:daimonmatrix")
        successor = self.candidate(
            **base,
            predecessor_decision_id=event_a["payload"]["decision_id"],
            lane={
                "memory_id": event_a["payload"]["memory_id"],
                "operation": "correct",
                "sequence": 2,
                "predecessor_event_id": event_a["event_id"],
                "predecessor_hash": event_a["content_hash"],
            },
        )
        checkpoint = memory_checkpoint(self.ledger_a, successor, captured_at_ms=NOW)
        self.assertEqual(checkpoint["lane_state"], "forked")
        self.assertEqual(
            checkpoint["lane_event_ids"],
            sorted([event_a["event_id"], event_b["event_id"]]),
        )
        plan = evaluate_memory_candidate(
            self.policy, successor, checkpoint, evaluated_at_ms=NOW
        )
        self.assertEqual(plan["outcome"], "quarantined")
        self.assertEqual(plan["reasons"], ["memory-lane-forked"])


class MemoryVectorAndSchemaTests(RootLedgerFixture):
    def test_public_vectors_verify_schemas_and_regenerate_byte_identically(
        self,
    ) -> None:
        index = json.loads((VECTOR_ROOT / "index.json").read_bytes())
        artifacts = {
            name: json.loads((VECTOR_ROOT / relative).read_bytes())
            for name, relative in index["artifacts"].items()
        }
        self.assertEqual(
            index["sha256"],
            {
                name: hashlib.sha256(canonical_bytes(value)).hexdigest()
                for name, value in artifacts.items()
            },
        )
        validate_memory_policy(artifacts["policy"])
        validate_memory_candidate(artifacts["eligible_candidate"])
        validate_memory_checkpoint(artifacts["eligible_checkpoint"])
        self.assertEqual(
            evaluate_memory_candidate(
                artifacts["policy"],
                artifacts["eligible_candidate"],
                artifacts["eligible_checkpoint"],
                evaluated_at_ms=artifacts["eligible_plan"]["evaluated_at_ms"],
            ),
            artifacts["eligible_plan"],
        )
        self.assertEqual(
            memory_decision(artifacts["eligible_plan"]),
            artifacts["eligible_decision"],
        )
        validate_memory_decision(artifacts["eligible_decision"])
        for name in ("peer_plan", "review_plan", "incomplete_plan"):
            validate_memory_plan(artifacts[name])
        with self.assertRaises(MemoryPolicyError):
            validate_memory_candidate(artifacts["negative_candidate"])
        with self.assertRaisesRegex(MemoryPolicyError, "memory_plan_id_mismatch"):
            validate_memory_plan(artifacts["negative_plan"])

        schema_paths = [
            *sorted((ROOT / "schemas/memory/v1").glob("*.json")),
            ROOT / "schemas/weave/v1/event.schema.json",
        ]
        schemas = [json.loads(path.read_bytes()) for path in schema_paths]
        registry = Registry().with_resources(
            (schema["$id"], Resource.from_contents(schema)) for schema in schemas
        )
        for schema in schemas:
            Draft202012Validator.check_schema(schema)
        schema_by_name = {
            path.name: schema
            for path, schema in zip(schema_paths, schemas, strict=True)
        }
        for schema_name, artifact_name in (
            ("policy.schema.json", "policy"),
            ("content-ref.schema.json", "content_ref"),
            ("candidate.schema.json", "eligible_candidate"),
            ("checkpoint.schema.json", "eligible_checkpoint"),
            ("decision.schema.json", "eligible_decision"),
            ("transition-plan.schema.json", "eligible_plan"),
        ):
            Draft202012Validator(
                schema_by_name[schema_name],
                registry=registry,
                format_checker=FormatChecker(),
            ).validate(artifacts[artifact_name])

        with TemporaryDirectory(prefix="dm030-vectors-") as directory:
            generated = Path(directory)
            generate_vectors(generated)
            expected = {
                path.relative_to(VECTOR_ROOT): path.read_bytes()
                for path in VECTOR_ROOT.rglob("*.json")
            }
            actual = {
                path.relative_to(generated): path.read_bytes()
                for path in generated.rglob("*.json")
            }
            self.assertEqual(actual, expected)

    def test_vectors_ignore_hash_seed_timezone_and_locale(self) -> None:
        outputs: list[dict[Path, bytes]] = []
        settings = (
            ("1", "UTC", "C"),
            ("997", "America/Argentina/Cordoba", "C.UTF-8"),
        )
        with TemporaryDirectory(prefix="dm030-environments-") as directory:
            root = Path(directory)
            for index, (seed, timezone, locale) in enumerate(settings):
                output = root / str(index)
                environment = os.environ.copy()
                environment.update(
                    {
                        "PYTHONHASHSEED": seed,
                        "TZ": timezone,
                        "LC_ALL": locale,
                    }
                )
                subprocess.run(
                    [
                        sys.executable,
                        str(ROOT / "tools/generate_dm030_vectors.py"),
                        "--out",
                        str(output),
                    ],
                    cwd=ROOT,
                    env=environment,
                    capture_output=True,
                    timeout=15,
                    check=True,
                )
                outputs.append(
                    {
                        path.relative_to(output): path.read_bytes()
                        for path in output.rglob("*.json")
                    }
                )
        self.assertEqual(outputs[0], outputs[1])


class MemoryInstalledRuntimeTests(RuntimeFixture):
    def setUp(self) -> None:
        super().setUp()
        self.state_root, _, self.capability, _ = self.make_process_bundle()
        self.runtime = self._load_runtime()
        self.stop = threading.Event()
        self.fail_after_dispatch = threading.Event()

        def fault(stage: str) -> None:
            if (
                stage == "after_dispatch_before_write"
                and self.fail_after_dispatch.is_set()
            ):
                self.fail_after_dispatch.clear()
                raise ConnectionError("synthetic response loss")

        self._start(fault)
        self.config_path = self.state_root / "memory-client.json"
        self.config_path.write_bytes(
            canonical_bytes(
                {
                    "schema": CLIENT_CONFIG_SCHEMA,
                    "capability": self.capability.descriptor,
                    "expected_server": self.origins["legion"],
                }
            )
        )
        self.config_path.chmod(0o600)
        self.client = LocalClient(
            self.runtime.socket_path,
            ClientConfig(self.capability, self.origins["legion"]),
        )

    def _load_runtime(self) -> Any:
        return load_runtime(
            self.state_root,
            "runtime.json",
            lambda: bytearray(PASSWORD),
            clock=lambda: time.time_ns() // 1_000_000,
        )

    def _start(self, fault: Any = None) -> None:
        arguments: dict[str, Any] = {"runtime": self.runtime, "stop": self.stop}
        if fault is not None:
            arguments["fault_hook"] = fault
        self.thread = threading.Thread(
            target=serve_forever,
            kwargs=arguments,
            daemon=True,
        )
        self.thread.start()
        for _ in range(200):
            if self.runtime.socket_path.exists():
                return
            time.sleep(0.01)
        self.fail("memory runtime socket did not appear")

    def tearDown(self) -> None:
        self.stop.set()
        self.thread.join(timeout=3)
        super().tearDown()

    def policy_candidate(self, **changes: Any) -> tuple[dict[str, Any], dict[str, Any]]:
        policy = create_memory_policy(
            subject_me_id=self.state.being_ref,
            version=1,
            predecessor_policy_id=None,
            automatic_categories=["personal-insight"],
            review_classifications=["protected"],
        )
        values: dict[str, Any] = {
            "subject_me_id": self.state.being_ref,
            "author_me_id": self.state.being_ref,
            "category": "personal-insight",
            "derivation": "local-synthesis",
            "context": "installed-runtime",
            "content_ref": create_content_ref(
                sha256=hashlib.sha256(b"installed synthetic memory").hexdigest(),
                byte_length=26,
                media_type="text/plain",
                classification="personal",
            ),
            "evidence_refs": [],
            "classification": "personal",
            "consent": "granted",
            "safety": "clear",
            "contradiction": "none",
            "effect": "local-only",
            "lane": {
                "memory_id": "90000000-0000-4000-8000-000000000030",
                "operation": "assert",
                "sequence": 1,
                "predecessor_event_id": None,
                "predecessor_hash": None,
            },
            "body_evidence": None,
        }
        values.update(changes)
        return policy, create_memory_candidate(**values)

    def test_real_daemon_response_loss_restart_and_exact_retry_commit_once(
        self,
    ) -> None:
        policy, candidate = self.policy_candidate()
        _, evaluated = self.client.memory_evaluate(
            {"policy": policy, "candidate": candidate}
        )
        plan = evaluated["result"]
        request = self.client.prepare(
            "memory.execute",
            {"policy": policy, "candidate": candidate, "plan": plan},
            request_id="91000000-0000-4000-8000-000000000030",
        )
        self.fail_after_dispatch.set()
        with self.assertRaisesRegex(ClientError, "daemon_response_truncated"):
            self.client.send(request)
        self.stop.set()
        self.thread.join(timeout=3)
        self.assertFalse(self.thread.is_alive())
        self.runtime = self._load_runtime()
        self.stop = threading.Event()
        self._start()
        response = self.client.send(request)
        self.assertTrue(response["ok"], response)
        memory_events = [
            event
            for event in self.runtime.service.ledger.events()
            if event["kind"] == "memory.recorded"
        ]
        self.assertEqual(len(memory_events), 1)
        self.assertEqual(response["result"]["event"], memory_events[0])
        schema_paths = [
            *sorted((ROOT / "schemas/memory/v1").glob("*.json")),
            ROOT / "schemas/weave/v1/event.schema.json",
        ]
        schemas = [json.loads(path.read_bytes()) for path in schema_paths]
        registry = Registry().with_resources(
            (schema["$id"], Resource.from_contents(schema)) for schema in schemas
        )
        by_name = {
            path.name: schema
            for path, schema in zip(schema_paths, schemas, strict=True)
        }
        Draft202012Validator(
            by_name["event.schema.json"],
            registry=registry,
            format_checker=FormatChecker(),
        ).validate(memory_events[0])
        Draft202012Validator(
            by_name["execution.schema.json"],
            registry=registry,
            format_checker=FormatChecker(),
        ).validate(response["result"])

    def _run_cli(self, arguments: list[str]) -> subprocess.CompletedProcess[bytes]:
        read_descriptor, write_descriptor = os.pipe()
        os.write(write_descriptor, self.capability.key)
        os.close(write_descriptor)
        try:
            return subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "daimon_matrix.cli",
                    "--socket",
                    str(self.runtime.socket_path),
                    "--client-config",
                    str(self.config_path),
                    "--capability-key-fd",
                    str(read_descriptor),
                    "--json",
                    *arguments,
                ],
                cwd=ROOT,
                env=os.environ.copy(),
                pass_fds=(read_descriptor,),
                capture_output=True,
                timeout=15,
                check=False,
            )
        finally:
            os.close(read_descriptor)

    def _evaluate_cli(self, policy_path: Path, candidate_path: Path) -> dict[str, Any]:
        result = self._run_cli(
            [
                "memory",
                "evaluate",
                "--policy",
                str(policy_path),
                "--candidate",
                str(candidate_path),
            ]
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return cast(dict[str, Any], json.loads(result.stdout)["response"]["result"])

    def test_installed_cli_exposes_outcomes_and_exact_execution_retry(self) -> None:
        policy, candidate = self.policy_candidate()
        policy_path = self.state_root / "policy.json"
        candidate_path = self.state_root / "candidate.json"
        policy_path.write_bytes(canonical_bytes(policy))
        candidate_path.write_bytes(canonical_bytes(candidate))
        plan = self._evaluate_cli(policy_path, candidate_path)
        self.assertEqual(plan["outcome"], "eligible")
        plan_path = self.state_root / "plan.json"
        plan_path.write_bytes(canonical_bytes(plan))
        retry_path = self.state_root / "execute-request.json"
        execute_arguments = [
            "--request-file",
            str(retry_path),
            "memory",
            "execute",
            "--policy",
            str(policy_path),
            "--candidate",
            str(candidate_path),
            "--plan",
            str(plan_path),
        ]
        executed = self._run_cli(execute_arguments)
        replayed = self._run_cli(execute_arguments)
        self.assertEqual(executed.returncode, 0, executed.stderr)
        self.assertEqual(executed.stdout, replayed.stdout)

        outcomes = (
            (
                "review-required",
                {
                    "contradiction": "sensitive",
                    "lane": {
                        **candidate["lane"],
                        "memory_id": "92000000-0000-4000-8000-000000000030",
                    },
                },
            ),
            (
                "deferred:incomplete",
                {
                    "evidence_refs": ["93000000-0000-4000-8000-000000000030"],
                    "lane": {
                        **candidate["lane"],
                        "memory_id": "94000000-0000-4000-8000-000000000030",
                    },
                },
            ),
        )
        for outcome, changes in outcomes:
            _, changed = self.policy_candidate(**changes)
            candidate_path.write_bytes(canonical_bytes(changed))
            self.assertEqual(
                self._evaluate_cli(policy_path, candidate_path)["outcome"], outcome
            )


if __name__ == "__main__":
    import unittest

    unittest.main()
