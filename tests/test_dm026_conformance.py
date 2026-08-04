from __future__ import annotations

import copy
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from jsonschema import Draft202012Validator  # type: ignore[import-untyped]

from daimon_matrix.canonical import canonical_bytes
from daimon_matrix.conformance import (
    REQUIRED_SCENARIO_IDS,
    ConformanceError,
    Registry,
    _test_exists,
    _write_report,
    build_report,
    deterministic_schedule,
    platform_facts,
)

ROOT = Path(__file__).resolve().parents[1]
REGISTRY_PATH = ROOT / "conformance/registry-v1.json"


class RegistryTests(unittest.TestCase):
    def test_registry_schema_runtime_coverage_and_evidence_are_exact(self) -> None:
        raw = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
        schema = json.loads(
            (ROOT / "schemas/conformance/v1/registry.schema.json").read_text(
                encoding="utf-8"
            )
        )
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(raw)
        registry = Registry.load(REGISTRY_PATH)
        self.assertEqual(
            {scenario.id for scenario in registry.scenarios}, REQUIRED_SCENARIO_IDS
        )
        self.assertEqual(
            [scenario.id for scenario in registry.scenarios],
            sorted(REQUIRED_SCENARIO_IDS),
        )
        for scenario in registry.scenarios:
            for relative in scenario.specifications:
                self.assertTrue((ROOT / relative).is_file(), relative)
            for test_id in scenario.evidence:
                _test_exists(test_id, ROOT)

    def test_registry_removal_addition_duplicate_and_unknown_field_fail(self) -> None:
        value = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
        mutations = []
        removed = copy.deepcopy(value)
        removed["scenarios"].pop()
        mutations.append(removed)
        added = copy.deepcopy(value)
        extra = copy.deepcopy(added["scenarios"][-1])
        extra["id"] = "unexpected_scenario"
        added["scenarios"].append(extra)
        mutations.append(added)
        duplicate = copy.deepcopy(value)
        duplicate["scenarios"].insert(1, copy.deepcopy(duplicate["scenarios"][0]))
        mutations.append(duplicate)
        open_shape = copy.deepcopy(value)
        open_shape["scenarios"][0]["trust"] = True
        mutations.append(open_shape)
        mixed_list = copy.deepcopy(value)
        mixed_list["scenarios"][0]["owners"] = [1, "DM-021"]
        mutations.append(mixed_list)
        semantic_change = copy.deepcopy(value)
        semantic_change["scenarios"][0]["expected"] += " Changed."
        mutations.append(semantic_change)
        with tempfile.TemporaryDirectory(
            prefix="dm026-registry-negative-"
        ) as directory:
            for index, mutation in enumerate(mutations):
                with self.subTest(index=index):
                    path = Path(directory) / f"case-{index}.json"
                    path.write_bytes(canonical_bytes(mutation))
                    with self.assertRaises(ConformanceError):
                        Registry.load(path)


class HarnessTests(unittest.TestCase):
    def test_schedule_is_deterministic_bounded_and_seed_sensitive(self) -> None:
        actors = ["client_a", "client_b", "reader"]
        first = deterministic_schedule("seed-a", actors, 16)
        self.assertEqual(first, deterministic_schedule("seed-a", actors, 16))
        self.assertNotEqual(first, deterministic_schedule("seed-b", actors, 16))
        self.assertTrue(all(sorted(row) == actors for row in first))
        with self.assertRaises(ConformanceError):
            deterministic_schedule("seed", ["reader", "client_a"], 1)
        with self.assertRaises(ConformanceError):
            deterministic_schedule("seed", actors, 0)

    def test_real_platform_probe_requires_delete_full_and_integrity(self) -> None:
        facts = platform_facts()
        self.assertEqual(facts["journal_mode"], "delete")
        self.assertEqual(facts["synchronous"], "FULL")
        self.assertTrue(facts["python"])
        self.assertTrue(facts["sqlite"])

    @mock.patch(
        "daimon_matrix.conformance.platform_facts",
        return_value={
            "python": "3.13.0",
            "sqlite": "3.46.0",
            "system": "linux",
            "machine": "x86_64",
            "journal_mode": "delete",
            "synchronous": "FULL",
        },
    )
    @mock.patch("daimon_matrix.conformance._run_test", return_value=("pass", None))
    def test_report_transcript_is_deterministic_closed_and_schema_valid(
        self, run_test: mock.Mock, facts: mock.Mock
    ) -> None:
        del facts
        registry = Registry.load(REGISTRY_PATH)
        first = build_report(
            registry,
            source_commit="1" * 40,
            seed=registry.fixture_seed,
            artifacts={"wheel": "2" * 64},
        )
        second = build_report(
            registry,
            source_commit="1" * 40,
            seed=registry.fixture_seed,
            artifacts={"wheel": "2" * 64},
        )
        self.assertEqual(canonical_bytes(first), canonical_bytes(second))
        self.assertTrue(first["release_ready"])
        transcript = canonical_bytes(first["transcript"])
        self.assertEqual(
            first["transcript_sha256"], hashlib.sha256(transcript).hexdigest()
        )
        self.assertEqual(
            run_test.call_count,
            2
            * len(
                {test for scenario in registry.scenarios for test in scenario.evidence}
            ),
        )
        self.assertEqual(
            sorted(first["transcript"]["schedule"][0]),
            sorted(
                {test for scenario in registry.scenarios for test in scenario.evidence}
            ),
        )
        schema = json.loads(
            (ROOT / "schemas/conformance/v1/report.schema.json").read_text(
                encoding="utf-8"
            )
        )
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(first)

    @mock.patch("daimon_matrix.conformance._run_test", return_value=("fail", "f" * 64))
    def test_failed_evidence_is_hashed_and_never_release_ready(
        self, run_test: mock.Mock
    ) -> None:
        del run_test
        registry = Registry.load(REGISTRY_PATH)
        report = build_report(
            registry,
            source_commit="3" * 40,
            seed=registry.fixture_seed,
            artifacts={},
        )
        self.assertFalse(report["release_ready"])
        encoded = canonical_bytes(report)
        self.assertNotIn(b"Traceback", encoded)
        self.assertTrue(
            all(
                outcome["diagnostic_hashes"]
                for outcome in report["transcript"]["scenarios"]
            )
        )

    @mock.patch("daimon_matrix.conformance.platform.system", return_value="Darwin")
    @mock.patch(
        "daimon_matrix.conformance.platform_facts",
        return_value={
            "python": "3.13.0",
            "sqlite": "3.46.0",
            "system": "darwin",
            "machine": "arm64",
            "journal_mode": "delete",
            "synchronous": "FULL",
        },
    )
    @mock.patch("daimon_matrix.conformance._run_test", return_value=("pass", None))
    def test_required_platform_skip_fails_release_without_loading_linux_evidence(
        self, run_test: mock.Mock, facts: mock.Mock, system: mock.Mock
    ) -> None:
        del facts, system
        registry = Registry.load(REGISTRY_PATH)
        report = build_report(
            registry,
            source_commit="4" * 40,
            seed=registry.fixture_seed,
            artifacts={},
        )
        outcomes = report["transcript"]["scenarios"]
        linux = {
            scenario.id
            for scenario in registry.scenarios
            if scenario.platform == "linux"
        }
        self.assertFalse(report["release_ready"])
        self.assertEqual(
            {
                outcome["scenario_id"]
                for outcome in outcomes
                if outcome["status"] == "skip"
            },
            linux,
        )
        invoked = {call.args[0] for call in run_test.call_args_list}
        linux_only = {
            test_id
            for scenario in registry.scenarios
            if scenario.platform == "linux"
            for test_id in scenario.evidence
        }
        shared = {
            test_id
            for scenario in registry.scenarios
            if scenario.platform == "all"
            for test_id in scenario.evidence
        }
        self.assertFalse(invoked & (linux_only - shared))

    def test_report_rejects_unverified_artifact_hashes(self) -> None:
        registry = Registry.load(REGISTRY_PATH)
        with self.assertRaisesRegex(ConformanceError, "invalid_artifact_hash"):
            build_report(
                registry,
                source_commit="5" * 40,
                seed=registry.fixture_seed,
                artifacts={"wheel": "not-a-sha256"},
            )

    def test_report_write_is_canonical_atomic_and_owner_only(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dm026-report-write-") as directory:
            root = Path(directory)
            output = root / "report.json"
            output.write_text("old", encoding="utf-8")
            output.chmod(0o644)
            report = {"schema": "test", "value": 1}
            _write_report(output, report)
            self.assertEqual(output.read_bytes(), canonical_bytes(report) + b"\n")
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertEqual(
                [path.name for path in root.iterdir()],
                ["report.json"],
            )
            os.symlink(root, root / "linked-parent")
            with self.assertRaisesRegex(ConformanceError, "report_parent_invalid"):
                _write_report(root / "linked-parent" / "other.json", report)


if __name__ == "__main__":
    unittest.main()
