#!/usr/bin/env python3
"""Generate the deterministic DM-061 report, vector index, and Section 14 map."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Any, Final

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from daimon_matrix.canonical import canonical_bytes  # noqa: E402
from daimon_matrix.synthetic_species import run_synthetic_species  # noqa: E402

SPEC = ROOT / "specs/species-evolution.md"
SCENARIO_MAP = ROOT / "conformance/species-section14-v0.json"
FIXTURE = ROOT / "conformance/fixtures/dm061-synthetic-species.json"
VECTOR_ROOT = ROOT / "vectors/species/v0"
_ROW: Final = re.compile(r"^\| ([^|]+) \| ([^|]+) \|$")
_SOURCE: Final = (
    "specs/species-evolution.md#14-required-positive-and-negative-scenarios"
)
_EVIDENCE: Final = (
    (
        12,
        "tests.test_dm061_species.DM061SpeciesTests."
        "test_artifact_validation_negative_matrix",
    ),
    (
        39,
        "tests.test_dm061_species.DM061SpeciesTests."
        "test_registry_authority_negative_matrix",
    ),
    (
        62,
        "tests.test_dm061_species.DM061SpeciesTests."
        "test_compatibility_sandbox_negative_matrix",
    ),
    (
        95,
        "tests.test_dm061_species.DM061SpeciesTests."
        "test_application_projection_negative_matrix",
    ),
    (
        124,
        "tests.test_dm061_species.DM061SpeciesTests.test_branch_birth_negative_matrix",
    ),
)


def _sha(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _evidence_for(ordinal: int) -> str:
    for last, evidence in _EVIDENCE:
        if ordinal <= last:
            return evidence
    raise ValueError("dm061_section14_case_unmapped")


def section14_registry() -> dict[str, Any]:
    text = SPEC.read_text(encoding="utf-8")
    section = text.split("## 14. Required positive and negative scenarios\n", 1)[1]
    section = section.split("\n## 15. Downstream contracts", 1)[0]
    rows: list[tuple[str, str]] = []
    for line in section.splitlines():
        match = _ROW.fullmatch(line)
        if match is not None and match.group(1) != "Scenario":
            rows.append((match.group(1).strip(), match.group(2).strip()))
    if len(rows) != 124:
        raise ValueError(f"dm061_section14_case_count:{len(rows)}")
    cases = [
        {
            "case_id": f"dm014-section14-{ordinal:03d}",
            "evidence": _evidence_for(ordinal),
            "required_result": result,
            "scenario": scenario,
        }
        for ordinal, (scenario, result) in enumerate(rows, 1)
    ]
    return {
        "cases": cases,
        "schema": "dm.species-section14-registry/v0",
        "source": _SOURCE,
    }


def generated_values() -> dict[Path, Any]:
    with tempfile.TemporaryDirectory(prefix="dm061-vector-") as directory:
        state = Path(directory)
        os.chmod(state, 0o700)
        report = run_synthetic_species(state)
    registry = section14_registry()
    index = {
        "claims": {
            "agent_zero": False,
            "first_real_speciation": False,
            "live_deployment": False,
            "synthetic": True,
        },
        "report": "synthetic-report.json",
        "report_sha256": _sha(report),
        "runner_provenance": "../../../provenance/wasi-runner-v0.json",
        "scenario_registry": "../../../conformance/species-section14-v0.json",
        "scenario_registry_sha256": _sha(registry),
        "schema": "dm.species-vectors/v0",
    }
    return {
        FIXTURE: report,
        SCENARIO_MAP: registry,
        VECTOR_ROOT / "index.json": index,
        VECTOR_ROOT / "synthetic-report.json": report,
    }


def generate(*, check: bool) -> None:
    mismatches: list[str] = []
    for path, value in generated_values().items():
        expected = canonical_bytes(value) + b"\n"
        if check:
            if not path.is_file() or path.read_bytes() != expected:
                mismatches.append(str(path.relative_to(ROOT)))
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(expected)
    if mismatches:
        raise SystemExit("DM-061 generated artifacts differ: " + ", ".join(mismatches))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    arguments = parser.parse_args()
    generate(check=arguments.check)


if __name__ == "__main__":
    main()
