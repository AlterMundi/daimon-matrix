from __future__ import annotations

import contextlib
import copy
import io
import json
import subprocess
import sys
import unittest
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

from jsonschema import Draft202012Validator  # type: ignore[import-untyped]

sys.path.insert(0, str(Path(__file__).resolve().parent / "fixtures/harness/v0"))

from checker import (  # type: ignore[import-not-found]
    MANDATORY_CONTROLS,
    HarnessConformanceError,
    conformance_report,
    fixture_manifest,
    load_fixture,
    load_profile,
    main,
    validate_profile,
)

ROOT = Path(__file__).resolve().parents[1]
PROFILES = ROOT / "profiles" / "harness" / "v0"
REPORTS = ROOT / "tests" / "fixtures" / "harness" / "v0"
FIXTURE = REPORTS / "manifest.json"
PROFILE_PATHS = tuple(sorted(PROFILES.glob("*.json")))


def _profile(profile_id: str) -> dict[str, Any]:
    return cast(
        dict[str, Any],
        json.loads((PROFILES / f"{profile_id}.json").read_text()),
    )


class DM074HarnessConformanceTests(unittest.TestCase):
    def test_profile_schema_fixture_and_source_inventory_are_closed(self) -> None:
        schema = json.loads(
            (ROOT / "schemas" / "harness" / "v0" / "profile.schema.json").read_text()
        )
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        fixture = load_fixture(FIXTURE)
        self.assertEqual(fixture, fixture_manifest())
        inventory = json.loads((ROOT / "provenance" / "harnesses-v0.json").read_text())
        self.assertEqual(set(inventory), {"accessed_on", "schema", "sources"})
        self.assertEqual(inventory["schema"], "dm.harness-source-inventory/v0")
        source_ids = {source["source_id"] for source in inventory["sources"]}
        self.assertEqual(len(source_ids), len(inventory["sources"]))
        self.assertEqual(
            [source["source_id"] for source in inventory["sources"]],
            sorted(source_ids),
        )
        for source in inventory["sources"]:
            self.assertEqual(
                set(source),
                {
                    "accessed_on",
                    "content_digest",
                    "owner",
                    "pin",
                    "source_id",
                    "title",
                    "url",
                },
            )
            self.assertTrue(
                source["content_digest"].startswith(("sha256:", "git-blob-sha1:"))
            )
        self.assertEqual(len(PROFILE_PATHS), 6)
        for path in PROFILE_PATHS:
            with self.subTest(profile=path.stem):
                profile = json.loads(path.read_text())
                validator.validate(profile)
                validate_profile(profile)
                referenced = set(profile["harness"]["source_refs"])
                referenced.update(
                    ref
                    for control in profile["controls"].values()
                    for ref in control["evidence"]
                )
                self.assertLessEqual(referenced, source_ids)

    def test_normative_evidence_states_and_fail_closed_admission(self) -> None:
        expected = {
            "claude-code": ("documented-candidate", "refused"),
            "codex-cli": ("synthetic-conformant", "accepted"),
            "generic-mcp-cli": ("synthetic-conformant", "accepted"),
            "google-antigravity": ("documented-candidate", "refused"),
            "grok-build": ("documented-candidate", "refused"),
            "kimi-code": ("documented-candidate", "refused"),
        }
        observed = {}
        fixture = load_fixture(FIXTURE)
        for path in PROFILE_PATHS:
            profile = load_profile(path)
            report = conformance_report(profile, fixture)
            observed[profile["profile_id"]] = (
                profile["evidence_state"],
                report["admission"]["observed"],
            )
            blocking = report["admission"]["blocking_controls"]
            if report["admission"]["observed"] == "accepted":
                self.assertEqual(blocking, [])
                self.assertTrue(
                    all(
                        profile["controls"][name]["state"] == "pass"
                        for name in MANDATORY_CONTROLS
                    )
                )
            else:
                self.assertTrue(blocking)
        self.assertEqual(observed, expected)

    def test_synthetic_corpus_is_deterministic_and_complete(self) -> None:
        fixture = load_fixture(FIXTURE)
        first = conformance_report(_profile("generic-mcp-cli"), fixture)
        second = conformance_report(_profile("generic-mcp-cli"), fixture)
        self.assertEqual(first, second)
        self.assertIs(first["passed"], True)
        synthetic = first["synthetic"]
        self.assertEqual(len(synthetic["effective_config_digest"]), 64)
        for name in (
            "adapter_disable_replace_rebuild",
            "authority_methods_refused",
            "changed_request_conflict",
            "exact_retry_after_crash",
            "isolated_profile",
            "lifecycle_stable_and_stale_refused",
            "malformed_and_oversized_refused",
            "native_state_disabled",
            "negotiation_and_downgrade_refusal",
            "profile_cleanup",
            "response_loss_recovered_once",
            "tool_inventory_exact",
            "transcript_export_log_scan_and_quarantine",
        ):
            with self.subTest(check=name):
                self.assertIs(synthetic[name], True)

    def test_frozen_reports_match(self) -> None:
        fixture = load_fixture(FIXTURE)
        for path in PROFILE_PATHS:
            with self.subTest(profile=path.stem):
                profile = load_profile(path)
                expected = json.loads(
                    (REPORTS / f"{path.stem}.report.json").read_text()
                )
                self.assertEqual(conformance_report(profile, fixture), expected)
                self.assertIs(expected["passed"], True)

    def test_generator_has_no_drift(self) -> None:
        subprocess.run(
            [sys.executable, "tools/generate_dm074_profiles.py", "--check"],
            cwd=ROOT,
            check=True,
        )

    def test_cli_checks_every_profile(self) -> None:
        arguments = [
            "--fixture",
            str(FIXTURE),
            *(str(path) for path in PROFILE_PATHS),
        ]
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(main(arguments), 0)
        reports = json.loads(output.getvalue())
        self.assertEqual(len(reports), 6)
        self.assertTrue(all(report["passed"] for report in reports))

    def test_profile_mutations_fail_closed(self) -> None:
        mutations: tuple[tuple[Callable[[dict[str, Any]], None], str], ...] = (
            (lambda value: value.update({"open": True}), "invalid_harness_profile"),
            (
                lambda value: value["matrix_boundary"].update(
                    {"harness_is_being_authority": True}
                ),
                "unsafe_harness_matrix_boundary",
            ),
            (
                lambda value: value["overlay"].update(
                    {"credential_channel": "environment-secret"}
                ),
                "unsafe_harness_credential_channel",
            ),
            (
                lambda value: value["harness"].update(
                    {"source_refs": list(reversed(value["harness"]["source_refs"]))}
                ),
                "invalid_harness_source_refs",
            ),
            (
                lambda value: value["matrix_boundary"].update(
                    {"forbidden_methods": []}
                ),
                "unsafe_harness_matrix_boundary",
            ),
        )
        for mutation, code in mutations:
            with self.subTest(code=code):
                value = copy.deepcopy(_profile("codex-cli"))
                mutation(value)
                with self.assertRaisesRegex(HarnessConformanceError, code):
                    validate_profile(value)

    def test_unknown_mandatory_control_cannot_retain_acceptance(self) -> None:
        value = copy.deepcopy(_profile("codex-cli"))
        value["controls"]["version_pinned"]["state"] = "unknown"
        with self.assertRaisesRegex(
            HarnessConformanceError, "harness_admission_evidence_mismatch"
        ):
            validate_profile(value)

    def test_documented_candidate_cannot_be_promoted_by_label_only(self) -> None:
        value = copy.deepcopy(_profile("generic-mcp-cli"))
        value["evidence_state"] = "documented-candidate"
        with self.assertRaisesRegex(
            HarnessConformanceError, "documented_candidate_cannot_be_admitted"
        ):
            validate_profile(value)

    def test_public_artifacts_contain_no_private_material_or_paths(self) -> None:
        forbidden = (
            "BEGIN PRIVATE KEY",
            "authorization: bearer",
            "client.key",
            "root.password",
            "ssh-rsa",
            "/home/",
            "/tmp/",
        )
        public_paths = (
            *PROFILE_PATHS,
            *sorted(REPORTS.glob("*.json")),
            ROOT / "provenance" / "harnesses-v0.json",
        )
        for path in public_paths:
            lowered = path.read_text().lower()
            for token in forbidden:
                with self.subTest(path=path.name, token=token):
                    self.assertNotIn(token.lower(), lowered)
