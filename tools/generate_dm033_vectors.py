#!/usr/bin/env python3
"""Generate deterministic public DM-033 human-review vectors."""

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
from daimon_matrix.human_review import (  # noqa: E402
    accept_authorization,
    authorization_core,
    create_access_proof,
    create_decision_draft,
    create_execution_receipt,
    create_review_request,
    create_revocation,
    review_group_id,
    sign_review_decision,
)
from daimon_matrix.identity import signing_descriptor  # noqa: E402
from daimon_matrix.memory_policy import (  # noqa: E402
    CHECKPOINT_SCHEMA,
    create_content_ref,
    create_memory_candidate,
    create_memory_policy,
    evaluate_memory_candidate,
)

DEFAULT_OUTPUT = ROOT / "vectors" / "review" / "v1"
NOW = 1_800_000_000_000
AUTHORIZATION_EVENT_ID = "33000000-0000-4000-8000-000000000001"
REQUEST_EVENT_ID = "33000000-0000-4000-8000-000000000002"
MEMORY_EVENT_ID = "33000000-0000-4000-8000-000000000003"
RPC_REQUEST_ID = "33000000-0000-4000-8000-000000000004"


def _digest(label: str) -> str:
    return hashlib.sha256(f"dm033-vector:{label}".encode()).hexdigest()


def _being(label: str) -> str:
    return "dm:being:v1:" + b64url(
        hashlib.sha256(f"dm033-being:{label}".encode()).digest()
    )


def _write(output: Path, relative: str, value: Any) -> None:
    path = output / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_bytes(value) + b"\n")


def generate(output: Path) -> None:
    subject = _being("subject")
    reviewer_seed = hashlib.sha256(b"dm033-vector:reviewer-seed").digest()
    reviewer = signing_descriptor(reviewer_seed)
    group_id = review_group_id([reviewer["key_id"]], 1)
    policy = create_memory_policy(
        subject_me_id=subject,
        version=1,
        predecessor_policy_id=None,
        automatic_categories=["personal-insight"],
        review_classifications=["protected"],
        plan_ttl_ms=60_000,
    )
    candidate = create_memory_candidate(
        subject_me_id=subject,
        author_me_id=subject,
        category="personal-insight",
        derivation="local-synthesis",
        context="dm033-vector",
        content_ref=create_content_ref(
            sha256=_digest("content"),
            byte_length=20,
            media_type="text/plain",
            classification="protected",
        ),
        evidence_refs=[],
        classification="protected",
        consent="granted",
        safety="clear",
        contradiction="none",
        effect="local-only",
        lane={
            "memory_id": "33000000-0000-4000-8000-000000000033",
            "operation": "assert",
            "sequence": 1,
            "predecessor_event_id": None,
            "predecessor_hash": None,
        },
        body_evidence=None,
    )
    checkpoint: dict[str, Any] = {
        "schema": CHECKPOINT_SCHEMA,
        "being_ref": subject,
        "manifest_hash": _digest("manifest"),
        "local_origin": {
            "body_ref": "cluster:vector:compaii",
            "embodiment_id": "embodiment:vector",
            "incarnation_id": "incarnation:vector:0",
            "principal_id": "compaii@vector",
        },
        "ledger_state_hash": _digest("ledger-state"),
        "projection_hash": _digest("projection"),
        "evidence_refs": [],
        "body_evidence_state": "absent",
        "lane_state": "empty",
        "lane_event_ids": [],
        "lane_head": None,
        "captured_at_ms": NOW,
    }
    plan = evaluate_memory_candidate(policy, candidate, checkpoint, evaluated_at_ms=NOW)
    authorization = accept_authorization(
        authorization_core(
            subject_me_id=subject,
            policy_id=policy["policy_id"],
            policy_hash=hashlib.sha256(canonical_bytes(policy)).hexdigest(),
            reviewer=reviewer,
            group_id=group_id,
            member_key_ids=[reviewer["key_id"]],
            threshold=1,
            categories=["personal-insight"],
            classifications=["protected"],
            actions=["accept", "defer", "edit", "reject"],
            valid_from_ms=NOW,
            expires_at_ms=NOW + 60_000,
            max_outstanding_decisions=8,
            control_position={
                "manifest_hash": checkpoint["manifest_hash"],
                "embodiment_id": checkpoint["local_origin"]["embodiment_id"],
                "incarnation_id": checkpoint["local_origin"]["incarnation_id"],
            },
            issued_at_ms=NOW,
        ),
        reviewer_seed,
    )
    request = create_review_request(
        policy=policy,
        candidate=candidate,
        plan=plan,
        proposal=None,
        authorization_ids=[authorization["authorization_id"]],
        group_id=group_id,
        threshold=1,
        requested_at_ms=NOW,
        expires_at_ms=NOW + 60_000,
    )
    edited_candidate = create_memory_candidate(
        subject_me_id=subject,
        author_me_id=subject,
        category="personal-insight",
        derivation="local-synthesis",
        context="dm033-vector-edited",
        content_ref=create_content_ref(
            sha256=_digest("edited-content"),
            byte_length=27,
            media_type="text/plain",
            classification="protected",
        ),
        evidence_refs=[],
        classification="protected",
        consent="granted",
        safety="clear",
        contradiction="none",
        effect="local-only",
        lane=candidate["lane"],
        body_evidence=None,
    )
    edited_plan = evaluate_memory_candidate(
        policy,
        edited_candidate,
        checkpoint,
        evaluated_at_ms=NOW,
    )
    replacement = {
        "policy": policy,
        "candidate": edited_candidate,
        "plan": edited_plan,
        "proposal": None,
    }
    defer = sign_review_decision(
        create_decision_draft(
            request=request,
            authorization_id=authorization["authorization_id"],
            reviewer_key_id=reviewer["key_id"],
            action="defer",
            replacement=None,
            reason="reconsideration-needed",
            note_ref="note:dm033-vector",
            decision_nonce="33000000-0000-4000-8000-000000000010",
            decided_at_ms=NOW,
            predecessor_decision_id=None,
        ),
        reviewer_seed,
    )
    accept = sign_review_decision(
        create_decision_draft(
            request=request,
            authorization_id=authorization["authorization_id"],
            reviewer_key_id=reviewer["key_id"],
            action="accept",
            replacement=None,
            reason="evidence-sufficient",
            note_ref="note:dm033-vector",
            decision_nonce="33000000-0000-4000-8000-000000000011",
            decided_at_ms=NOW + 1,
            predecessor_decision_id=defer["decision_id"],
        ),
        reviewer_seed,
    )
    reject = sign_review_decision(
        create_decision_draft(
            request=request,
            authorization_id=authorization["authorization_id"],
            reviewer_key_id=reviewer["key_id"],
            action="reject",
            replacement=None,
            reason="evidence-insufficient",
            note_ref=None,
            decision_nonce="33000000-0000-4000-8000-000000000012",
            decided_at_ms=NOW,
            predecessor_decision_id=None,
        ),
        reviewer_seed,
    )
    edit = sign_review_decision(
        create_decision_draft(
            request=request,
            authorization_id=authorization["authorization_id"],
            reviewer_key_id=reviewer["key_id"],
            action="edit",
            replacement=replacement,
            reason="content-correction",
            note_ref="note:dm033-vector-edit",
            decision_nonce="33000000-0000-4000-8000-000000000013",
            decided_at_ms=NOW,
            predecessor_decision_id=None,
        ),
        reviewer_seed,
    )
    successor = create_review_request(
        policy=policy,
        candidate=edited_candidate,
        plan=edited_plan,
        proposal=None,
        authorization_ids=[authorization["authorization_id"]],
        group_id=group_id,
        threshold=1,
        requested_at_ms=NOW + 1,
        expires_at_ms=NOW + 60_000,
    )
    threshold_seeds = [
        hashlib.sha256(f"dm033-vector:threshold:{index}".encode()).digest()
        for index in range(2)
    ]
    threshold_reviewers = [signing_descriptor(seed) for seed in threshold_seeds]
    threshold_group_id = review_group_id(
        [descriptor["key_id"] for descriptor in threshold_reviewers], 2
    )
    threshold_authorizations = [
        accept_authorization(
            authorization_core(
                subject_me_id=subject,
                policy_id=policy["policy_id"],
                policy_hash=hashlib.sha256(canonical_bytes(policy)).hexdigest(),
                reviewer=descriptor,
                group_id=threshold_group_id,
                member_key_ids=[member["key_id"] for member in threshold_reviewers],
                threshold=2,
                categories=["personal-insight"],
                classifications=["protected"],
                actions=["accept"],
                valid_from_ms=NOW,
                expires_at_ms=NOW + 60_000,
                max_outstanding_decisions=1,
                control_position={
                    "manifest_hash": checkpoint["manifest_hash"],
                    "embodiment_id": checkpoint["local_origin"]["embodiment_id"],
                    "incarnation_id": checkpoint["local_origin"]["incarnation_id"],
                },
                issued_at_ms=NOW,
            ),
            seed,
        )
        for seed, descriptor in zip(threshold_seeds, threshold_reviewers, strict=True)
    ]
    threshold_request = create_review_request(
        policy=policy,
        candidate=candidate,
        plan=plan,
        proposal=None,
        authorization_ids=[
            item["authorization_id"] for item in threshold_authorizations
        ],
        group_id=threshold_group_id,
        threshold=2,
        requested_at_ms=NOW,
        expires_at_ms=NOW + 60_000,
    )
    threshold_decisions = [
        sign_review_decision(
            create_decision_draft(
                request=threshold_request,
                authorization_id=authorization_item["authorization_id"],
                reviewer_key_id=descriptor["key_id"],
                action="accept",
                replacement=None,
                reason="evidence-sufficient",
                note_ref=None,
                decision_nonce=f"33000000-0000-4000-8000-{20 + index:012d}",
                decided_at_ms=NOW,
                predecessor_decision_id=None,
            ),
            seed,
        )
        for index, (seed, descriptor, authorization_item) in enumerate(
            zip(
                threshold_seeds,
                threshold_reviewers,
                threshold_authorizations,
                strict=True,
            )
        )
    ]
    access = create_access_proof(
        authorization_id=authorization["authorization_id"],
        rpc_request_id=RPC_REQUEST_ID,
        issued_at_ms=NOW,
        expires_at_ms=NOW + 1_000,
        reviewer_seed=reviewer_seed,
    )
    revocation = create_revocation(
        authorization_id=authorization["authorization_id"],
        authorization_event_id=AUTHORIZATION_EVENT_ID,
        reason="vector-retirement",
        revoked_at_ms=NOW + 10_000,
    )
    receipt = create_execution_receipt(
        review_request_id=request["review_request_id"],
        request_event_id=REQUEST_EVENT_ID,
        action="accept",
        decision_ids=[accept["decision_id"]],
        memory_event_id=MEMORY_EVENT_ID,
        successor_request_id=None,
        executed_at_ms=NOW + 2,
    )
    edit_receipt = create_execution_receipt(
        review_request_id=request["review_request_id"],
        request_event_id="33000000-0000-4000-8000-000000000005",
        action="edit",
        decision_ids=[edit["decision_id"]],
        memory_event_id=None,
        successor_request_id=successor["review_request_id"],
        executed_at_ms=NOW + 2,
    )
    reject_receipt = create_execution_receipt(
        review_request_id=request["review_request_id"],
        request_event_id="33000000-0000-4000-8000-000000000006",
        action="reject",
        decision_ids=[reject["decision_id"]],
        memory_event_id=None,
        successor_request_id=None,
        executed_at_ms=NOW + 2,
    )
    tampered = copy.deepcopy(accept)
    tampered["decision_nonce"] = "33000000-0000-4000-8000-000000000099"
    artifacts = {
        "authorization": authorization,
        "request": request,
        "decision_defer": defer,
        "decision_accept_successor": accept,
        "decision_reject_alternative": reject,
        "decision_edit_alternative": edit,
        "authorization_threshold_a": threshold_authorizations[0],
        "authorization_threshold_b": threshold_authorizations[1],
        "request_threshold": threshold_request,
        "decision_threshold_accept_a": threshold_decisions[0],
        "decision_threshold_accept_b": threshold_decisions[1],
        "access_proof": access,
        "revocation": revocation,
        "execution_receipt": receipt,
        "execution_receipt_edit": edit_receipt,
        "execution_receipt_reject": reject_receipt,
        "negative_tampered_decision": tampered,
    }
    paths = {
        "authorization": "authorization.json",
        "request": "request.json",
        "decision_defer": "decision-defer.json",
        "decision_accept_successor": "decision-accept-successor.json",
        "decision_reject_alternative": "decision-reject-alternative.json",
        "decision_edit_alternative": "decision-edit-alternative.json",
        "authorization_threshold_a": "authorization-threshold-a.json",
        "authorization_threshold_b": "authorization-threshold-b.json",
        "request_threshold": "request-threshold.json",
        "decision_threshold_accept_a": "decision-threshold-accept-a.json",
        "decision_threshold_accept_b": "decision-threshold-accept-b.json",
        "access_proof": "access-proof.json",
        "revocation": "revocation.json",
        "execution_receipt": "execution-receipt.json",
        "execution_receipt_edit": "execution-receipt-edit.json",
        "execution_receipt_reject": "execution-receipt-reject.json",
        "negative_tampered_decision": "negative/decision-tampered.json",
    }
    for name, artifact in artifacts.items():
        _write(output, paths[name], artifact)
    _write(
        output,
        "index.json",
        {
            "schema": "dm.review.vectors/v1",
            "artifacts": paths,
            "sha256": {
                name: hashlib.sha256(canonical_bytes(artifact)).hexdigest()
                for name, artifact in artifacts.items()
            },
        },
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUTPUT)
    arguments = parser.parse_args()
    generate(arguments.out)


if __name__ == "__main__":
    main()
