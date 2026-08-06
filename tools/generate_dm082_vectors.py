#!/usr/bin/env python3
"""Generate deterministic DM-082 relationship vectors and scenario mapping."""

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
from daimon_matrix.synthetic_relationships import (  # noqa: E402
    synthetic_relationship_evidence,
)

VECTOR_ROOT: Final = ROOT / "vectors/relationships/v1"
FIXTURE: Final = ROOT / "conformance/fixtures/dm082-synthetic-relationships.json"
SCENARIOS: Final = ROOT / "conformance/relationship-v1-scenarios.json"


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _scenario_registry() -> dict[str, Any]:
    rows = [
        (
            "bilateral-consent",
            "One-sided evidence is inert and exact acceptance activates consent.",
            [
                "tests.test_dm082_relationships.RelationshipContractTests."
                "test_one_sided_consent_and_unaccepted_grant_are_inert"
            ],
        ),
        (
            "card-control-and-expiry",
            "Only a current root-bound card supports current authority.",
            [
                "tests.test_dm082_relationships.RelationshipContractTests."
                "test_expired_cards_remove_relationship_and_snapshot_authority"
            ],
        ),
        (
            "membership-predecessor-series",
            "Re-entry names the exact prior terminal and gaps fail closed.",
            [
                "tests.test_dm082_relationships.RelationshipContractTests."
                "test_membership_reentry_requires_exact_terminal_predecessor"
            ],
        ),
        (
            "membership-terminal-race",
            "Competing terminal events quarantine without an arrival-order winner.",
            [
                "tests.test_dm082_relationships.RelationshipContractTests."
                "test_competing_membership_terminals_quarantine_without_winner"
            ],
        ),
        (
            "delegation-attenuation",
            "Widened root or child grants are invalid.",
            [
                "tests.test_dm082_relationships.RelationshipContractTests."
                "test_widened_root_and_child_grants_are_invalid"
            ],
        ),
        (
            "delegation-fork-cascade",
            "A same-position fork quarantines descendants.",
            [
                "tests.test_dm082_relationships.RelationshipContractTests."
                "test_same_delegation_position_forks_lane_and_descendant"
            ],
        ),
        (
            "founder-transfer-order-and-membership",
            "Succession is ordered and the successor is active at acceptance.",
            [
                "tests.test_dm082_relationships.RelationshipContractTests."
                "test_founder_transfer_requires_order_and_active_successor"
            ],
        ),
        (
            "origin-fork-cascade",
            "An origin equivocation quarantines its lane and dependants.",
            [
                "tests.test_dm082_relationships.RelationshipContractTests."
                "test_origin_card_fork_quarantines_its_lane_and_dependants"
            ],
        ),
        (
            "owner-local-exact-replay",
            "Exact retry is inert and changed request bytes conflict.",
            [
                "tests.test_dm082_relationships.RelationshipStoreTests."
                "test_exact_request_replay_and_changed_hash_conflict"
            ],
        ),
        (
            "closed-disclosure-denial",
            "Unauthorized queries return one indistinguishable denial.",
            [
                "tests.test_dm082_relationships.RelationshipServiceTests."
                "test_authenticated_mutation_foreign_ingest_status_and_closed_denial"
            ],
        ),
        (
            "relationship-recipient-delivery",
            "DM-054 selection, DM-051 sealing and DM-053 intake require a "
            "signed DM-052 receipt before delivery.",
            [
                "tests.test_dm082_relationships.RelationshipContractTests."
                "test_synthetic_journey_is_deterministic_and_cascades_revocation"
            ],
        ),
        (
            "restart-stable-synthetic-journey",
            "Consent authorizes encrypted intake, signed delivery and "
            "restart-stable revocation.",
            [
                "tests.test_dm082_relationships.RelationshipContractTests."
                "test_synthetic_journey_is_deterministic_and_cascades_revocation"
            ],
        ),
        (
            "revoked-stale-carrier",
            "Revocation refuses still-valid direct ciphertext and hub forwarding "
            "before another private open.",
            [
                "tests.test_dm082_relationships.RelationshipContractTests."
                "test_synthetic_journey_is_deterministic_and_cascades_revocation"
            ],
        ),
        (
            "v1-exact-bounds",
            "Every locally owned V1 bound accepts exact and rejects plus one.",
            [
                "tests.test_dm082_relationships.RelationshipContractTests."
                "test_every_owned_v1_bound_accepts_exact_and_rejects_plus_one"
            ],
        ),
    ]
    return {
        "rows": [
            {"evidence": evidence, "id": identifier, "required_result": result}
            for identifier, result, evidence in sorted(rows, key=lambda row: row[0])
        ],
        "schema": "dm.relationship-scenario-registry/v1",
        "spec_path": "specs/tribe-relationships.md",
        "spec_sha256": _sha((ROOT / "specs/tribe-relationships.md").read_bytes()),
    }


def _negative_vectors(events: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    by_kind = {event["kind"]: event for event in events}

    card = copy.deepcopy(by_kind["matrix/relationship-card"])
    card["payload"]["unexpected"] = True

    membership = copy.deepcopy(by_kind["matrix/tribe-membership-acceptance"])
    membership["payload"]["membership_sequence"] = 1
    membership["payload"]["previous_membership_terminal_ref"] = None

    offer = copy.deepcopy(by_kind["matrix/relationship-offer"])
    offer["payload"]["responder_being_ref"] = offer["payload"]["initiator_being_ref"]

    grant = copy.deepcopy(by_kind["matrix/relationship-grant"])
    grant["payload"]["subject_being_ref"] = grant["payload"]["grantor_being_ref"]

    return {
        "card-unknown-field": {
            "document": card,
            "expected_error": "invalid_relationship_card",
            "schema": "dm.relationship-negative-vector/v1",
        },
        "grant-self-authority": {
            "document": grant,
            "expected_error": "invalid_relationship_grant",
            "schema": "dm.relationship-negative-vector/v1",
        },
        "membership-missing-predecessor": {
            "document": membership,
            "expected_error": "invalid_tribe_membership_acceptance",
            "schema": "dm.relationship-negative-vector/v1",
        },
        "offer-self-relationship": {
            "document": offer,
            "expected_error": "relationship_requires_distinct_beings",
            "schema": "dm.relationship-negative-vector/v1",
        },
    }


def generate() -> dict[Path, bytes]:
    with tempfile.TemporaryDirectory(prefix="dm082-vectors-") as temporary:
        artifacts = synthetic_relationship_evidence(Path(temporary) / "state")
    events = artifacts["events"]
    outputs = {
        FIXTURE: canonical_bytes(artifacts["report"]) + b"\n",
        SCENARIOS: canonical_bytes(_scenario_registry()),
    }
    entries: list[dict[str, Any]] = []
    for index, event in enumerate(events, start=1):
        slug = event["kind"].removeprefix("matrix/").replace("/", "-")
        path = VECTOR_ROOT / "valid" / f"{index:02d}-{slug}.json"
        raw = canonical_bytes(event)
        outputs[path] = raw
        entries.append(
            {
                "expected": "accept",
                "path": str(path.relative_to(VECTOR_ROOT)),
                "sha256": _sha(raw),
            }
        )
    for name, vector in sorted(_negative_vectors(events).items()):
        path = VECTOR_ROOT / "negative" / f"{name}.json"
        raw = canonical_bytes(vector)
        outputs[path] = raw
        entries.append(
            {
                "expected": vector["expected_error"],
                "path": str(path.relative_to(VECTOR_ROOT)),
                "sha256": _sha(raw),
            }
        )
    index_document = {
        "entries": entries,
        "scenario_registry": "../../../conformance/relationship-v1-scenarios.json",
        "schema": "dm.relationship-vector-index/v1",
        "synthetic": True,
    }
    outputs[VECTOR_ROOT / "index.json"] = canonical_bytes(index_document)
    return outputs


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    arguments = parser.parse_args()
    drift: list[str] = []
    for path, raw in generate().items():
        if arguments.check:
            if not path.is_file() or path.read_bytes() != raw:
                drift.append(str(path.relative_to(ROOT)))
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
    if drift:
        print("DM-082 generated artifact drift: " + ", ".join(sorted(drift)))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
