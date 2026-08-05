#!/usr/bin/env python3
"""Generate deterministic public DM-032 curator-worker vectors."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from daimon_matrix.canonical import canonical_bytes  # noqa: E402
from daimon_matrix.curator import (  # noqa: E402
    create_curator_claim,
    create_curator_item,
)
from daimon_matrix.curator_worker import (  # noqa: E402
    create_worker_manifest,
    create_worker_profile,
    create_worker_proposal,
    create_worker_registration,
    create_worker_task,
)

DEFAULT_OUTPUT = ROOT / "vectors" / "curator-worker" / "v1"
MEMORY_ROOT = ROOT / "vectors" / "memory" / "v1"
NOW = 1_800_000_000_000


def _load(name: str) -> dict[str, Any]:
    value = json.loads((MEMORY_ROOT / name).read_bytes())
    if not isinstance(value, dict):
        raise ValueError("invalid DM-030 vector")
    return value


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _write(output: Path, relative: str, value: Any) -> None:
    path = output / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_bytes(value) + b"\n")


def generate(output: Path) -> None:
    policy = _load("policy.json")
    candidate = _load("candidate-personal-experience.json")
    checkpoint = _load("checkpoint-empty.json")
    plan = _load("plan-eligible.json")
    profile = create_worker_profile(
        implementation="deepseek-http-v1",
        secret_handle="secret:SYNTHETIC_VECTOR_REFERENCE",
    )
    registration = create_worker_registration(profile, enabled=False)
    manifest = create_worker_manifest(
        max_input_bytes=profile["limits"]["max_input_bytes"],
        max_output_bytes=profile["limits"]["max_output_bytes"],
        max_runtime_ms=profile["limits"]["timeout_ms"],
    )
    item = create_curator_item(
        subject_me_id=candidate["subject_me_id"],
        resource_ref="memory:proposal:dm032-vector",
        work_kind="memory-proposal",
        input_ref=candidate["candidate_id"],
        input_hash=_digest(candidate),
        coordination_mode="queue-item",
        required_authority="human",
        effect_intent_hash=None,
        queued_at_ms=NOW,
    )
    claim = create_curator_claim(
        claim_id="32000000-0000-4000-8000-000000000001",
        item=item,
        generation=1,
        actor_origin=checkpoint["local_origin"],
        issued_at_ms=NOW,
        lease_until_ms=NOW + 120_000,
        resource_fence=None,
    )
    task = create_worker_task(
        attempt_id="32000000-0000-4000-8000-000000000002",
        idempotency_key=_digest({"dm032": "vector-attempt"}),
        item=item,
        claim=claim,
        policy=policy,
        candidate=candidate,
        checkpoint=checkpoint,
        policy_plan=plan,
        profile=profile,
        allowed_proposal_kinds=["assert"],
        created_at_ms=NOW,
        deadline_ms=NOW + 60_000,
    )
    provider_output = {
        "proposal_kind": "assert",
        "statement": "Synthetic DM-032 proposal",
        "category": candidate["category"],
        "derivation": candidate["derivation"],
        "evidence_refs": candidate["evidence_refs"],
        "contradiction_refs": [],
        "classification_suggestion": "personal",
        "confidence": "medium",
        "uncertainty_labels": ["model-generated"],
        "warnings": [],
    }
    metadata = {
        "provider_request_id": "deepseek-synthetic-vector",
        "response_hash": _digest({"dm032": "synthetic-response"}),
        "system_fingerprint": "synthetic-vector",
        "finish_reason": "stop",
        "usage": {
            "prompt_tokens": 10,
            "completion_tokens": 5,
            "total_tokens": 15,
            "prompt_cache_hit_tokens": 0,
            "prompt_cache_miss_tokens": 10,
            "reasoning_tokens": 0,
        },
        "provider_created_at_ms": NOW,
        "estimated_cost_microusd": 10,
    }
    proposal, proposal_content = create_worker_proposal(
        task=task,
        profile=profile,
        provider_output=provider_output,
        metadata=metadata,
        request_hash=_digest({"dm032": "synthetic-request"}),
        produced_at_ms=NOW + 1_000,
    )
    negative = copy.deepcopy(task)
    negative["deadline_ms"] += 1
    artifacts = {
        "manifest": manifest,
        "profile": profile,
        "registration_disabled": registration,
        "item": item,
        "claim": claim,
        "task": task,
        "provider_output": provider_output,
        "proposal": proposal,
        "negative_task": negative,
    }
    filenames = {
        "manifest": "manifest.json",
        "profile": "profile.json",
        "registration_disabled": "registration-disabled.json",
        "item": "item.json",
        "claim": "claim.json",
        "task": "task.json",
        "provider_output": "provider-output.json",
        "proposal": "proposal.json",
        "negative_task": "negative/task-tampered.json",
    }
    for name, filename in filenames.items():
        _write(output, filename, artifacts[name])
    content_path = output / "proposal-content.txt"
    content_path.write_bytes(proposal_content)
    index = {
        "schema": "dm.curator-worker.vectors/v1",
        "artifacts": dict(sorted(filenames.items())),
        "binary_artifacts": {"proposal_content": "proposal-content.txt"},
        "sha256": {name: _digest(value) for name, value in sorted(artifacts.items())},
        "binary_sha256": {
            "proposal_content": hashlib.sha256(proposal_content).hexdigest()
        },
    }
    _write(output, "index.json", index)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUTPUT)
    arguments = parser.parse_args()
    generate(arguments.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
