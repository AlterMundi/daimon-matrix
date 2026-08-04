#!/usr/bin/env python3
"""Generate deterministic public DM-030 memory-policy vectors."""

from __future__ import annotations

import argparse
import copy
import hashlib
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from daimon_matrix.canonical import b64url, canonical_bytes  # noqa: E402
from daimon_matrix.memory_policy import (  # noqa: E402
    CHECKPOINT_SCHEMA,
    create_content_ref,
    create_memory_candidate,
    create_memory_policy,
    evaluate_memory_candidate,
    memory_decision,
)

DEFAULT_OUTPUT = ROOT / "vectors" / "memory" / "v1"
NOW = 1_800_000_000_000
EVIDENCE_ID = "10000000-0000-4000-8000-000000000030"
MISSING_ID = "10000000-0000-4000-8000-000000000031"
MEMORY_ID = "20000000-0000-4000-8000-000000000030"


def _digest(label: str) -> str:
    return hashlib.sha256(f"dm030-vector:{label}".encode()).hexdigest()


def _being(label: str) -> str:
    digest = hashlib.sha256(f"dm030-being:{label}".encode()).digest()
    return "dm:being:v1:" + b64url(digest)


def _write(output: Path, relative: str, value: Any) -> None:
    path = output / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_bytes(value) + b"\n")


def generate(output: Path) -> None:
    subject = _being("subject")
    peer = _being("peer")
    origin = {
        "body_ref": "cluster:vector:compaii",
        "embodiment_id": "embodiment:vector",
        "incarnation_id": "incarnation:vector:0",
        "principal_id": "compaii@vector",
    }
    policy = create_memory_policy(
        subject_me_id=subject,
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
    content = create_content_ref(
        sha256=_digest("content"),
        byte_length=21,
        media_type="text/plain",
        classification="personal",
    )
    body_evidence = {
        "body_ref": origin["body_ref"],
        "embodiment_id": origin["embodiment_id"],
        "incarnation_id": origin["incarnation_id"],
        "session_ref": "session:vector",
        "lease_ref": "lease:vector",
        "committed_cutoff_event_id": EVIDENCE_ID,
    }
    lane = {
        "memory_id": MEMORY_ID,
        "operation": "assert",
        "sequence": 1,
        "predecessor_event_id": None,
        "predecessor_hash": None,
    }
    candidate = create_memory_candidate(
        subject_me_id=subject,
        author_me_id=subject,
        category="personal-experience",
        derivation="body-occurrence",
        context="autobiographical",
        content_ref=content,
        evidence_refs=[EVIDENCE_ID],
        classification="personal",
        consent="granted",
        safety="clear",
        contradiction="none",
        effect="local-only",
        lane=lane,
        body_evidence=body_evidence,
    )
    checkpoint = {
        "schema": CHECKPOINT_SCHEMA,
        "being_ref": subject,
        "manifest_hash": _digest("manifest"),
        "local_origin": origin,
        "ledger_state_hash": _digest("ledger-state"),
        "projection_hash": _digest("projection"),
        "evidence_refs": [EVIDENCE_ID],
        "body_evidence_state": "verified",
        "lane_state": "empty",
        "lane_event_ids": [],
        "lane_head": None,
        "captured_at_ms": NOW,
    }
    eligible = evaluate_memory_candidate(
        policy, candidate, checkpoint, evaluated_at_ms=NOW
    )
    eligible_decision = memory_decision(eligible)
    peer_candidate = create_memory_candidate(
        subject_me_id=subject,
        author_me_id=peer,
        category="peer-attributed",
        derivation="peer-origin",
        context="attributed-learning",
        content_ref=content,
        evidence_refs=[EVIDENCE_ID],
        classification="personal",
        consent="granted",
        safety="clear",
        contradiction="none",
        effect="local-only",
        lane={**lane, "memory_id": "20000000-0000-4000-8000-000000000031"},
        body_evidence=None,
    )
    peer_checkpoint = {
        **checkpoint,
        "body_evidence_state": "absent",
    }
    peer_plan = evaluate_memory_candidate(
        policy, peer_candidate, peer_checkpoint, evaluated_at_ms=NOW
    )
    review_candidate = create_memory_candidate(
        **{
            key: copy.deepcopy(value)
            for key, value in candidate.items()
            if key not in {"candidate_id", "contradiction", "schema"}
        },
        contradiction="sensitive",
    )
    review_plan = evaluate_memory_candidate(
        policy, review_candidate, checkpoint, evaluated_at_ms=NOW
    )
    incomplete_candidate = create_memory_candidate(
        **{
            key: copy.deepcopy(value)
            for key, value in candidate.items()
            if key not in {"candidate_id", "evidence_refs", "schema"}
        },
        evidence_refs=[EVIDENCE_ID, MISSING_ID],
    )
    incomplete_plan = evaluate_memory_candidate(
        policy, incomplete_candidate, checkpoint, evaluated_at_ms=NOW
    )
    negative_candidate = copy.deepcopy(candidate)
    negative_candidate["content_ref"]["path"] = "/not-a-memory-locator"
    negative_plan = copy.deepcopy(eligible)
    negative_plan["expires_at_ms"] += 1
    artifacts = {
        "policy": policy,
        "content_ref": content,
        "eligible_candidate": candidate,
        "eligible_checkpoint": checkpoint,
        "eligible_plan": eligible,
        "eligible_decision": eligible_decision,
        "peer_candidate": peer_candidate,
        "peer_plan": peer_plan,
        "review_candidate": review_candidate,
        "review_plan": review_plan,
        "incomplete_candidate": incomplete_candidate,
        "incomplete_plan": incomplete_plan,
        "negative_candidate": negative_candidate,
        "negative_plan": negative_plan,
    }
    paths = {
        "policy": "policy.json",
        "content_ref": "content-ref.json",
        "eligible_candidate": "candidate-personal-experience.json",
        "eligible_checkpoint": "checkpoint-empty.json",
        "eligible_plan": "plan-eligible.json",
        "eligible_decision": "decision-eligible.json",
        "peer_candidate": "candidate-peer-attributed.json",
        "peer_plan": "plan-peer-attributed.json",
        "review_candidate": "candidate-sensitive-contradiction.json",
        "review_plan": "plan-review-required.json",
        "incomplete_candidate": "candidate-incomplete.json",
        "incomplete_plan": "plan-deferred-incomplete.json",
        "negative_candidate": "negative/candidate-locator.json",
        "negative_plan": "negative/plan-tampered.json",
    }
    for name, value in artifacts.items():
        _write(output, paths[name], value)
    index = {
        "schema": "dm.memory.vectors/v1",
        "artifacts": paths,
        "sha256": {
            name: hashlib.sha256(canonical_bytes(value)).hexdigest()
            for name, value in artifacts.items()
        },
    }
    _write(output, "index.json", index)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUTPUT)
    arguments = parser.parse_args()
    generate(arguments.out)


if __name__ == "__main__":
    main()
