#!/usr/bin/env python3
"""Generate deterministic DM-081 wire vectors and Section 14 traceability."""

from __future__ import annotations

import argparse
import copy
import hashlib
import sys
import tempfile
from pathlib import Path
from typing import Any, Final

ROOT: Final = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from daimon_matrix.canonical import canonical_bytes  # noqa: E402
from daimon_matrix.synthetic_sources import synthetic_source_evidence  # noqa: E402

VECTOR_ROOT: Final = ROOT / "vectors/source/v0"
FIXTURE: Final = ROOT / "conformance/fixtures/dm081-synthetic-source.json"
SCENARIOS: Final = ROOT / "conformance/source-v0-section14.json"
SPEC: Final = ROOT / "specs/source-ancestry.md"

SYNTHETIC_TEST: Final = (
    "tests.test_dm081_sources.SyntheticSourceJourneyTests."
    "test_two_being_report_is_closed_reproducible_and_secret_free"
)
WIRE_TEST: Final = (
    "tests.test_dm081_sources.SourceWireContractTests."
    "test_published_schema_enforces_action_and_sequence_discriminators"
)
BOUND_TEST: Final = (
    "tests.test_dm081_sources.SourceWireContractTests."
    "test_source_graph_depth_accepts_exact_bound_and_rejects_plus_one"
)
COUNT_TEST: Final = (
    "tests.test_dm081_sources.SourceWireContractTests."
    "test_initial_import_is_quarantine_and_promotion_is_separate"
)
REPUBLISH_TEST: Final = (
    "tests.test_dm081_sources.SourceRegistryTests."
    "test_republish_after_tombstone_creates_new_quarantine_successor"
)
ASSESSMENT_FORK_TEST: Final = (
    "tests.test_dm081_sources.SourceRegistryTests."
    "test_assessment_successor_fork_excludes_locally_admitted_claim"
)
PUBLICATION_FORK_TEST: Final = (
    "tests.test_dm081_sources.SourceRegistryTests."
    "test_publication_successor_fork_is_retained_and_never_offered"
)
INERT_CONTENT_TEST: Final = (
    "tests.test_dm081_sources.SourceCASTests."
    "test_content_is_inert_without_network_execution_or_archive_expansion"
)
INCOMPLETE_PULL_TEST: Final = (
    "tests.test_dm081_sources.SourceRegistryTests."
    "test_incomplete_item_is_reported_but_not_landed_or_marked_known"
)
TRANSITIVE_PUBLICATION_TEST: Final = (
    "tests.test_dm081_sources.SourceRegistryTests."
    "test_item_with_transitive_publication_creates_every_import_receipt"
)
FRESH_TOMBSTONE_TEST: Final = (
    "tests.test_dm081_sources.SourceRegistryTests."
    "test_fresh_receiver_lands_tombstone_without_withdrawn_content"
)


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _section14_rows(raw: str) -> list[tuple[str, str]]:
    marker = "## 14. Required positive and negative scenarios"
    end = "## 15. Cross-protocol and downstream contracts"
    section = raw.split(marker, 1)[1].split(end, 1)[0]
    rows: list[tuple[str, str]] = []
    for line in section.splitlines():
        if not line.startswith("|") or line.startswith("|---"):
            continue
        columns = [column.strip() for column in line.strip().strip("|").split("|")]
        if columns == ["Scenario", "Required result"]:
            continue
        if len(columns) != 2 or not all(columns):
            raise RuntimeError("invalid_dm081_section14_table")
        rows.append((columns[0], columns[1]))
    if len(rows) < 80:
        raise RuntimeError("incomplete_dm081_section14_table")
    return rows


def _evidence(scenario: str) -> list[str]:
    value = scenario.lower()
    tests = {SYNTHETIC_TEST}
    routes = (
        (
            ("source id", "source alias", "source core", "selector", "all-sources"),
            "tests.test_dm081_sources.SourceWireContractTests."
            "test_source_identity_is_byte_exact_and_selector_bound",
        ),
        (
            ("claim", "relation", "retraction", "successor", "expired"),
            "tests.test_dm081_sources.SourceWireContractTests."
            "test_false_self_retraction_and_predecessor_rules_fail_closed",
        ),
        (
            ("evidence", "binding hash", "policy bytes", "snapshot"),
            "tests.test_dm081_sources.SourceWireContractTests."
            "test_claim_binding_and_evidence_are_closed_and_content_bound",
        ),
        (
            ("assessment", "eligible", "local disposition", "remote assessment"),
            "tests.test_dm081_sources.SourceRegistryTests."
            "test_claim_starts_quarantined_then_exact_local_assessment_admits",
        ),
        (
            (
                "publication",
                "consent",
                "license",
                "source uri",
                "tombstone",
                "republish",
            ),
            "tests.test_dm081_sources.SourceRegistryTests."
            "test_reviewed_publication_tombstones_without_deleting_history",
        ),
        (
            ("provenance", "author", "summary", "derivation", "original node"),
            "tests.test_dm081_sources.SourceWireContractTests."
            "test_cyclic_and_disconnected_provenance_is_rejected",
        ),
        (
            ("diff", "continuation", "cursor", "incoming"),
            "tests.test_dm081_sources.SourceRegistryTests."
            "test_paginated_pull_keeps_starting_cursor_until_terminal_page",
        ),
        (
            ("partial bundle", "malformed item", "predecessor/provenance"),
            "tests.test_dm081_sources.SourceRegistryTests."
            "test_malformed_item_is_rejected_while_complete_prefix_lands",
        ),
        (
            ("pull", "auto-promote", "transport ack", "remote index"),
            "tests.test_dm081_sources.SourceRegistryTests."
            "test_pull_resumes_after_crash_and_never_promotes",
        ),
        (
            ("promotion", "autobiography", "body experience", "external knowledge"),
            "tests.test_dm081_sources.SourceRegistryTests."
            "test_publication_pull_quarantines_then_separate_promotion_preserves_authors",
        ),
        (
            ("hmk", "rendered artifact", "outbound receipt", "collective-memory"),
            "tests.test_dm035_publication.DM035PublicationTests."
            "test_final_render_secret_policy_and_unsafe_target",
        ),
        (
            ("ssrf", "ambient credential", "active content", "archive traversal"),
            INERT_CONTENT_TEST,
        ),
        (
            ("birth", "identity may awaken", "birth binding"),
            "tests.test_dm060_synthetic_birth.BirthContractTests."
            "test_distinct_root_birth_first_embodiment_and_empty_memory_activate",
        ),
    )
    for needles, test_id in routes:
        if any(needle in value for needle in needles):
            tests.add(test_id)
    if "fork" in value or "two successors" in value or "late sibling" in value:
        tests.add(
            "tests.test_dm081_sources.SourceRegistryTests."
            "test_same_claim_position_from_two_embodiments_quarantines_series"
        )
    if "exact count" in value or "bound plus one" in value:
        tests.add(BOUND_TEST)
        tests.add(COUNT_TEST)
    if "republish" in value:
        tests.add(REPUBLISH_TEST)
    if "assessment" in value and "fork" in value:
        tests.add(ASSESSMENT_FORK_TEST)
    if "publication" in value and "fork" in value:
        tests.add(PUBLICATION_FORK_TEST)
    if "partial bundle" in value or "missing evidence" in value:
        tests.add(INCOMPLETE_PULL_TEST)
    if "pull receives valid new content" in value:
        tests.add(TRANSITIVE_PUBLICATION_TEST)
    if "tombstone current" in value or "tombstoned" in value:
        tests.add(FRESH_TOMBSTONE_TEST)
    return sorted(tests)


def _scenario_registry() -> dict[str, Any]:
    spec_raw = SPEC.read_bytes()
    rows = _section14_rows(spec_raw.decode("utf-8"))
    return {
        "row_count": len(rows),
        "rows": [
            {
                "evidence": _evidence(scenario),
                "id": f"source-s14-{index:03d}",
                "index": index,
                "required_result": required,
                "scenario": scenario,
            }
            for index, (scenario, required) in enumerate(rows, start=1)
        ],
        "schema": "dm.source-section14-registry/v0",
        "section": "14",
        "spec_path": "specs/source-ancestry.md",
        "spec_sha256": _sha(spec_raw),
    }


def _negative_vectors(artifacts: dict[str, Any]) -> dict[str, dict[str, Any]]:
    selector = copy.deepcopy(artifacts["selector"])
    selector["source_core_hash"] = "A" * 43
    signature = copy.deepcopy(artifacts["publication-event"])
    signature["signature"]["value"] = "A" * 86
    cursor = copy.deepcopy(artifacts["starting-cursor"])
    cursor["event"]["content_hash"] = "0" * 64
    pull = copy.deepcopy(artifacts["initial-page-1-pull"])
    pull["starting_cursor_hash"] = "0" * 64
    return {
        "cursor-content-hash-tampered": {
            "document": cursor,
            "expected_error": "invalid_source_cursor_signature",
            "schema": "dm.source-negative-vector/v0",
        },
        "pull-cursor-substitution": {
            "document": pull,
            "expected_error": "source_pull_preview_stale",
            "schema": "dm.source-negative-vector/v0",
        },
        "publication-signature-tampered": {
            "document": signature,
            "expected_error": "invalid_source_diff_event",
            "schema": "dm.source-negative-vector/v0",
        },
        "selector-substitution": {
            "document": selector,
            "expected_error": "source_selector_mismatch",
            "schema": "dm.source-negative-vector/v0",
        },
    }


def generate() -> dict[Path, bytes]:
    with tempfile.TemporaryDirectory(prefix="dm081-vectors-") as temporary:
        artifacts = synthetic_source_evidence(Path(temporary) / "state")
    outputs: dict[Path, bytes] = {
        FIXTURE: canonical_bytes(artifacts["report"]),
        SCENARIOS: canonical_bytes(_scenario_registry()),
    }
    entries: list[dict[str, Any]] = []
    for name, document in sorted(artifacts.items()):
        path = VECTOR_ROOT / "valid" / f"{name}.json"
        raw = canonical_bytes(document)
        outputs[path] = raw
        entries.append(
            {
                "expected": "accept",
                "path": f"valid/{name}.json",
                "sha256": _sha(raw),
            }
        )
    for name, document in sorted(_negative_vectors(artifacts).items()):
        path = VECTOR_ROOT / "negative" / f"{name}.json"
        raw = canonical_bytes(document)
        outputs[path] = raw
        entries.append(
            {
                "expected": document["expected_error"],
                "path": f"negative/{name}.json",
                "sha256": _sha(raw),
            }
        )
    index = {
        "entries": entries,
        "schema": "dm.source-vector-index/v0",
        "section14_registry": "../../../conformance/source-v0-section14.json",
        "synthetic": True,
    }
    outputs[VECTOR_ROOT / "index.json"] = canonical_bytes(index)
    return outputs


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    arguments = parser.parse_args()
    outputs = generate()
    drift: list[str] = []
    for path, raw in outputs.items():
        if arguments.check:
            if not path.is_file() or path.read_bytes() != raw:
                drift.append(str(path.relative_to(ROOT)))
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
    if drift:
        print("DM-081 generated artifact drift: " + ", ".join(sorted(drift)))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
