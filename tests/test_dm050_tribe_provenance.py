from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path
from typing import Any, cast

from jsonschema import Draft202012Validator  # type: ignore[import-untyped]

from daimon_matrix.canonical import canonical_bytes
from tools.check_tribe_provenance import ProvenanceError, validate_manifest

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "provenance/tribe-bridge-v1.json"
SCHEMA = ROOT / "schemas/provenance/v1/tribe-import.schema.json"


class TribeProvenanceTests(unittest.TestCase):
    def value(self) -> dict[str, Any]:
        value = json.loads(MANIFEST.read_bytes())
        self.assertIsInstance(value, dict)
        return cast(dict[str, Any], value)

    def write_mutation(self, value: dict[str, Any], name: str) -> Path:
        directory = tempfile.TemporaryDirectory(prefix="dm050-manifest-")
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / f"{name}.json"
        path.write_bytes(canonical_bytes(value))
        return path

    def test_schema_runtime_summary_and_closed_inventory(self) -> None:
        value = self.value()
        schema = json.loads(SCHEMA.read_bytes())
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(value)
        summary = validate_manifest(MANIFEST)
        self.assertEqual(summary["item_count"], 23)
        self.assertEqual(summary["behavioral_reference_count"], 16)
        self.assertEqual(summary["superseded_count"], 7)
        self.assertFalse(summary["copy_allowed"])
        self.assertEqual(
            [item["path"] for item in value["items"]],
            sorted(item["path"] for item in value["items"]),
        )
        self.assertTrue(all(item["copy_allowed"] is False for item in value["items"]))

    def test_no_upstream_source_schema_fixture_or_runtime_was_imported(self) -> None:
        forbidden = [
            *ROOT.glob("src/tribe_*.py"),
            *ROOT.glob("tests/v1_fixtures.py"),
            *ROOT.glob("protocol/v1/**/*"),
            *ROOT.glob("templates/tribe-*"),
        ]
        self.assertEqual(forbidden, [])
        with (ROOT / "pyproject.toml").open("rb") as stream:
            project = tomllib.load(stream)["project"]
        self.assertNotIn("tribe-bridge", " ".join(project.get("dependencies", [])))

    def test_policy_pin_path_hash_shape_and_semantics_fail_closed(self) -> None:
        base = self.value()
        mutations: list[tuple[str, dict[str, Any]]] = []

        unknown = copy.deepcopy(base)
        unknown["trust"] = True
        mutations.append(("unknown", unknown))

        mutable_ref = copy.deepcopy(base)
        mutable_ref["upstream"]["commit"] = "main"
        mutations.append(("mutable-ref", mutable_ref))

        license_widening = copy.deepcopy(base)
        license_widening["policy"]["copy_allowed"] = True
        mutations.append(("license-widening", license_widening))

        item_widening = copy.deepcopy(base)
        item_widening["items"][0]["copy_allowed"] = True
        mutations.append(("item-widening", item_widening))

        unsafe_path = copy.deepcopy(base)
        unsafe_path["items"][0]["path"] = "runtime/messages.sqlite"
        mutations.append(("unsafe-path", unsafe_path))

        malformed_hash = copy.deepcopy(base)
        malformed_hash["items"][0]["sha256"] = "0" * 63
        mutations.append(("malformed-hash", malformed_hash))

        duplicate = copy.deepcopy(base)
        duplicate["items"].insert(1, copy.deepcopy(duplicate["items"][0]))
        mutations.append(("duplicate", duplicate))

        unsorted = copy.deepcopy(base)
        unsorted["items"][0], unsorted["items"][1] = (
            unsorted["items"][1],
            unsorted["items"][0],
        )
        mutations.append(("unsorted", unsorted))

        semantic_change = copy.deepcopy(base)
        semantic_change["items"][0]["rationale"] += " Altered."
        mutations.append(("semantic-change", semantic_change))

        live_state = copy.deepcopy(base)
        live_state["policy"]["live_state_imported"] = True
        mutations.append(("live-state", live_state))

        for name, mutation in mutations:
            with self.subTest(name=name), self.assertRaises(ProvenanceError):
                validate_manifest(self.write_mutation(mutation, name))

    def test_cli_emits_only_public_pinned_summary(self) -> None:
        completed = subprocess.run(
            [sys.executable, "tools/check_tribe_provenance.py", str(MANIFEST)],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        summary = json.loads(completed.stdout)
        self.assertEqual(summary, validate_manifest(MANIFEST))
        self.assertNotIn("/home/", completed.stdout)
        self.assertEqual(completed.stderr, "")


if __name__ == "__main__":
    unittest.main()
