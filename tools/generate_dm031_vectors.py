#!/usr/bin/env python3
"""Generate deterministic public DM-031 curator coordination vectors."""

from __future__ import annotations

import argparse
import copy
import hashlib
from pathlib import Path
from typing import Any

from daimon_matrix.canonical import canonical_bytes
from daimon_matrix.cluster import (
    create_effect_receipt,
    create_resource_fence_evidence,
    resource_fence_position,
)
from daimon_matrix.curator import (
    create_curator_claim,
    create_curator_item,
    create_curator_result,
)

NOW = 1_800_000_000_000
ORIGIN = {
    "body_ref": "cluster:legion:compaii",
    "embodiment_id": "embodiment:legion",
    "incarnation_id": "incarnation:legion:0",
    "principal_id": "compaii@legion",
}


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def generate(output: Path) -> None:
    output.mkdir(parents=True, exist_ok=True)
    intent = {"operation": "publish", "resource_ref": "wiki:page:home"}
    queue_item = create_curator_item(
        subject_me_id="dm:being:v1:synthetic",
        resource_ref="memory:item:synthetic",
        work_kind="memory-proposal",
        input_ref="candidate:synthetic",
        input_hash=_digest({"candidate": "synthetic"}),
        coordination_mode="queue-item",
        required_authority="daimon",
        effect_intent_hash=None,
        queued_at_ms=NOW,
    )
    review_item = create_curator_item(
        subject_me_id="dm:being:v1:synthetic",
        resource_ref="review:item:synthetic",
        work_kind="memory-proposal",
        input_ref="plan:review-required",
        input_hash=_digest({"plan": "review-required"}),
        coordination_mode="queue-item",
        required_authority="human",
        effect_intent_hash=None,
        queued_at_ms=NOW,
    )
    resource_item = create_curator_item(
        subject_me_id="dm:being:v1:synthetic",
        resource_ref="wiki:page:home",
        work_kind="publication",
        input_ref="memory:event:synthetic",
        input_hash=_digest({"event": "synthetic"}),
        coordination_mode="resource-fence",
        required_authority="daimon",
        effect_intent_hash=_digest(intent),
        queued_at_ms=NOW,
    )
    queue_claim = create_curator_claim(
        claim_id="31000000-0000-4000-8000-000000000001",
        item=queue_item,
        generation=1,
        actor_origin=ORIGIN,
        issued_at_ms=NOW,
        lease_until_ms=NOW + 1_000,
        resource_fence=None,
    )
    review_claim = create_curator_claim(
        claim_id="31000000-0000-4000-8000-000000000002",
        item=review_item,
        generation=1,
        actor_origin=ORIGIN,
        issued_at_ms=NOW,
        lease_until_ms=NOW + 1_000,
        resource_fence=None,
    )
    fence = create_resource_fence_evidence(
        body_ref=ORIGIN["body_ref"],
        holder_embodiment_id=ORIGIN["embodiment_id"],
        holder_incarnation_id=ORIGIN["incarnation_id"],
        resource_ref=resource_item["resource_ref"],
        epoch=7,
        observed_at_ms=NOW - 100,
        expires_at_ms=NOW + 1_000,
        verification_ref="cluster-proof:synthetic-7",
    )
    resource_claim = create_curator_claim(
        claim_id="31000000-0000-4000-8000-000000000003",
        item=resource_item,
        generation=1,
        actor_origin=ORIGIN,
        issued_at_ms=NOW,
        lease_until_ms=NOW + 1_000,
        resource_fence=resource_fence_position(fence),
    )
    queue_result = create_curator_result(
        item=queue_item,
        claim=queue_claim,
        outcome="completed",
        output_refs=["proposal:synthetic"],
        effect_receipt=None,
        completed_at_ms=NOW + 100,
    )
    review_result = create_curator_result(
        item=review_item,
        claim=review_claim,
        outcome="proposed",
        output_refs=["proposal:review-required"],
        effect_receipt=None,
        completed_at_ms=NOW + 100,
    )
    postcondition = {"generation": 7, "state": "present"}
    receipt = create_effect_receipt(
        effect_id="31000000-0000-4000-8000-000000000004",
        target_event_id="31000000-0000-4000-8000-000000000005",
        decision_event_id="31000000-0000-4000-8000-000000000006",
        adapter="synthetic-wiki/v1",
        preview_hash="a" * 64,
        intent_hash=_digest(intent),
        actor=ORIGIN["principal_id"],
        authority="daimon",
        resource_fence=resource_fence_position(fence),
        result="applied",
        observed_postcondition=postcondition,
        started_at_ms=NOW + 10,
        completed_at_ms=NOW + 20,
    )
    resource_result = create_curator_result(
        item=resource_item,
        claim=resource_claim,
        outcome="completed",
        output_refs=["publication:synthetic"],
        effect_receipt=receipt,
        completed_at_ms=NOW + 20,
    )
    tampered = copy.deepcopy(queue_item)
    tampered["resource_ref"] = "memory:item:substituted"
    artifacts = {
        "queue_item": queue_item,
        "review_item": review_item,
        "resource_item": resource_item,
        "queue_claim": queue_claim,
        "resource_claim": resource_claim,
        "queue_result": queue_result,
        "review_result": review_result,
        "resource_result": resource_result,
        "resource_fence": fence,
        "negative_item": tampered,
    }
    filenames = {
        "queue_item": "item-queue.json",
        "review_item": "item-human-review.json",
        "resource_item": "item-resource-fence.json",
        "queue_claim": "claim-queue.json",
        "resource_claim": "claim-resource-fence.json",
        "queue_result": "result-completed.json",
        "review_result": "result-review-required.json",
        "resource_result": "result-resource-effect.json",
        "resource_fence": "resource-fence.json",
        "negative_item": "negative/item-tampered.json",
    }
    for name, filename in filenames.items():
        path = output / filename
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(canonical_bytes(artifacts[name]))
    index = {
        "schema": "dm.curator.vectors/v1",
        "artifacts": dict(sorted(filenames.items())),
        "sha256": {
            name: hashlib.sha256(canonical_bytes(value)).hexdigest()
            for name, value in sorted(artifacts.items())
        },
    }
    (output / "index.json").write_bytes(canonical_bytes(index))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("vectors/curator/v1"))
    arguments = parser.parse_args()
    generate(arguments.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
