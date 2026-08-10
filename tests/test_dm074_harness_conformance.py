from __future__ import annotations

import copy
import json
import subprocess
import sys
import unittest
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

import pytest
from jsonschema import Draft202012Validator  # type: ignore[import-untyped]

sys.path.insert(0, str(Path(__file__).resolve().parent / "fixtures/harness/v0"))

from checker import (
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


class DM074CIGate(unittest.TestCase):
    """Keep the repository's unittest-discovery CI gate aware of DM-074."""

    def test_generated_profiles_pass_the_frozen_fixture(self) -> None:
        fixture = load_fixture(FIXTURE)
        self.assertEqual(fixture, fixture_manifest())
        for path in PROFILE_PATHS:
            expected = json.loads((REPORTS / f"{path.stem}.report.json").read_text())
            self.assertEqual(conformance_report(load_profile(path), fixture), expected)
            self.assertTrue(expected["passed"])


def _profile(profile_id: str) -> dict[str, Any]:
    return cast(
        dict[str, Any],
        json.loads((PROFILES / f"{profile_id}.json").read_text()),
    )


def test_profile_schema_fixture_and_source_inventory_are_closed() -> None:
    schema = json.loads(
        (ROOT / "schemas" / "harness" / "v0" / "profile.schema.json").read_text()
    )
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    fixture = load_fixture(FIXTURE)
    assert fixture == fixture_manifest()
    inventory = json.loads((ROOT / "provenance" / "harnesses-v0.json").read_text())
    assert set(inventory) == {"accessed_on", "schema", "sources"}
    assert inventory["schema"] == "dm.harness-source-inventory/v0"
    source_ids = {source["source_id"] for source in inventory["sources"]}
    assert len(source_ids) == len(inventory["sources"])
    assert [source["source_id"] for source in inventory["sources"]] == sorted(
        source_ids
    )
    for source in inventory["sources"]:
        assert set(source) == {
            "accessed_on",
            "content_digest",
            "owner",
            "pin",
            "source_id",
            "title",
            "url",
        }
        assert source["content_digest"].startswith(("sha256:", "git-blob-sha1:"))
    assert len(PROFILE_PATHS) == 6
    for path in PROFILE_PATHS:
        profile = json.loads(path.read_text())
        validator.validate(profile)
        validate_profile(profile)
        referenced = set(profile["harness"]["source_refs"])
        referenced.update(
            ref
            for control in profile["controls"].values()
            for ref in control["evidence"]
        )
        assert referenced <= source_ids


def test_normative_evidence_states_and_fail_closed_admission() -> None:
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
            assert blocking == []
            assert all(
                profile["controls"][name]["state"] == "pass"
                for name in MANDATORY_CONTROLS
            )
        else:
            assert blocking
    assert observed == expected


def test_synthetic_corpus_is_deterministic_and_covers_required_failures() -> None:
    fixture = load_fixture(FIXTURE)
    first = conformance_report(_profile("generic-mcp-cli"), fixture)
    second = conformance_report(_profile("generic-mcp-cli"), fixture)
    assert first == second
    assert first["passed"] is True
    synthetic = first["synthetic"]
    assert len(synthetic["effective_config_digest"]) == 64
    assert all(
        synthetic[name] is True
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
        )
    )


@pytest.mark.parametrize("path", PROFILE_PATHS, ids=lambda path: path.stem)
def test_frozen_report_matches(path: Path) -> None:
    profile = load_profile(path)
    expected = json.loads((REPORTS / f"{path.stem}.report.json").read_text())
    assert conformance_report(profile, load_fixture(FIXTURE)) == expected
    assert expected["passed"] is True


def test_generator_has_no_drift() -> None:
    subprocess.run(
        [sys.executable, "tools/generate_dm074_profiles.py", "--check"],
        cwd=ROOT,
        check=True,
    )


def test_cli_checks_every_profile(capsys: pytest.CaptureFixture[str]) -> None:
    arguments = ["--fixture", str(FIXTURE), *(str(path) for path in PROFILE_PATHS)]
    assert main(arguments) == 0
    reports = json.loads(capsys.readouterr().out)
    assert len(reports) == 6
    assert all(report["passed"] for report in reports)


@pytest.mark.parametrize(
    ("mutation", "code"),
    [
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
            lambda value: value["matrix_boundary"].update({"forbidden_methods": []}),
            "unsafe_harness_matrix_boundary",
        ),
    ],
)
def test_profile_mutations_fail_closed(
    mutation: Callable[[dict[str, Any]], None], code: str
) -> None:
    value = copy.deepcopy(_profile("codex-cli"))
    mutation(value)
    with pytest.raises(HarnessConformanceError, match=code):
        validate_profile(value)


def test_unknown_mandatory_control_cannot_retain_acceptance() -> None:
    value = copy.deepcopy(_profile("codex-cli"))
    value["controls"]["version_pinned"]["state"] = "unknown"
    with pytest.raises(
        HarnessConformanceError, match="harness_admission_evidence_mismatch"
    ):
        validate_profile(value)


def test_documented_candidate_cannot_be_promoted_by_label_only() -> None:
    value = copy.deepcopy(_profile("generic-mcp-cli"))
    value["evidence_state"] = "documented-candidate"
    with pytest.raises(
        HarnessConformanceError, match="documented_candidate_cannot_be_admitted"
    ):
        validate_profile(value)


def test_public_artifacts_contain_no_private_material_or_local_paths() -> None:
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
            assert token.lower() not in lowered
