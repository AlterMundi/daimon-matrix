from __future__ import annotations

import copy
import hashlib
import io
import json
import os
import pty
import re
import select
import signal
import stat
import subprocess
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, cast

from jsonschema import (  # type: ignore[import-untyped]
    Draft202012Validator,
    FormatChecker,
)
from referencing import Registry, Resource

import daimon_matrix
from daimon_matrix.canonical import b64url, canonical_bytes
from daimon_matrix.cli import _ensure_safe_output, _write_result
from daimon_matrix.client import (
    CLIENT_CONFIG_SCHEMA_V3,
    ClientConfig,
    ClientError,
    LocalClient,
)
from daimon_matrix.daemon import FaultHook, serve_forever
from daimon_matrix.human_review import (
    HumanReviewCoordinator,
    HumanReviewError,
    accept_authorization,
    authorization_core,
    create_access_proof,
    create_decision_draft,
    create_review_request,
    sign_review_decision,
    validate_execution_receipt,
    validate_human_decision,
    validate_review_request,
    validate_reviewer_authorization,
)
from daimon_matrix.identity import signing_descriptor
from daimon_matrix.local_api import create_capability, create_request
from daimon_matrix.memory_policy import (
    PLAN_DOMAIN,
    create_content_ref,
    create_memory_candidate,
    create_memory_policy,
    evaluate_memory_candidate,
    memory_checkpoint,
)
from daimon_matrix.reviewer_cli import _byte_diff
from daimon_matrix.runtime import HostedRuntime, load_runtime
from daimon_matrix.service import REVIEW_METHODS, HostedWeave
from tests.test_dm022_ledger import NOW, RootLedgerFixture
from tests.test_dm024_runtime import PASSWORD, RuntimeFixture
from tools.generate_dm033_vectors import generate as generate_vectors

ROOT = Path(__file__).resolve().parents[1]
VECTOR_ROOT = ROOT / "vectors/review/v1"
MCP_META = {
    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
    "io.modelcontextprotocol/clientInfo": {"name": "dm033-test", "version": "1"},
    "io.modelcontextprotocol/clientCapabilities": {},
}


def _group_id(member_key_ids: list[str], threshold: int) -> str:
    digest = hashlib.sha256(
        b"daimon/review/group/v1\x00"
        + canonical_bytes(
            {"member_key_ids": sorted(member_key_ids), "threshold": threshold}
        )
    ).digest()
    return "dm:review-group:v1:" + b64url(digest)


class HumanReviewTests(RootLedgerFixture):
    def setUp(self) -> None:
        super().setUp()
        self.reviewer_seed = bytes(range(32))
        self.reviewer = signing_descriptor(self.reviewer_seed)
        self.group_id = _group_id([self.reviewer["key_id"]], 1)
        self.policy = create_memory_policy(
            subject_me_id=self.state.being_ref,
            version=1,
            predecessor_policy_id=None,
            automatic_categories=["personal-insight"],
            review_classifications=["protected"],
            plan_ttl_ms=60_000,
        )
        self.candidate = create_memory_candidate(
            subject_me_id=self.state.being_ref,
            author_me_id=self.state.being_ref,
            category="personal-insight",
            derivation="local-synthesis",
            context="dm033-synthetic",
            content_ref=create_content_ref(
                sha256=hashlib.sha256(b"reviewed memory").hexdigest(),
                byte_length=15,
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
        checkpoint = memory_checkpoint(
            self.ledger_a, self.candidate, captured_at_ms=NOW
        )
        self.plan = evaluate_memory_candidate(
            self.policy,
            self.candidate,
            checkpoint,
            evaluated_at_ms=NOW,
        )
        self.assertEqual(self.plan["outcome"], "review-required")
        core = authorization_core(
            subject_me_id=self.state.being_ref,
            policy_id=self.policy["policy_id"],
            policy_hash=hashlib.sha256(canonical_bytes(self.policy)).hexdigest(),
            reviewer=self.reviewer,
            group_id=self.group_id,
            member_key_ids=[self.reviewer["key_id"]],
            threshold=1,
            categories=["personal-insight"],
            classifications=["protected"],
            actions=["accept", "defer", "edit", "reject"],
            valid_from_ms=NOW,
            expires_at_ms=NOW + 60_000,
            max_outstanding_decisions=8,
            control_position={
                "manifest_hash": self.ledger_a.authority.manifest.digest,
                "embodiment_id": self.origins["legion"]["embodiment_id"],
                "incarnation_id": self.origins["legion"]["incarnation_id"],
            },
            issued_at_ms=NOW,
        )
        self.authorization = accept_authorization(core, self.reviewer_seed)
        self.coordinator = HumanReviewCoordinator(
            self.ledger_a,
            self.signers["legion"],
            clock=lambda: NOW,
        )
        self.coordinator.authorize(
            self.authorization,
            client_id="dm033-test",
            request_id="33000000-0000-4000-8000-000000000101",
        )
        self.request = create_review_request(
            policy=self.policy,
            candidate=self.candidate,
            plan=self.plan,
            proposal=None,
            authorization_ids=[self.authorization["authorization_id"]],
            group_id=self.group_id,
            threshold=1,
            requested_at_ms=NOW,
            expires_at_ms=NOW + 60_000,
        )
        self.coordinator.request_review(
            self.request,
            client_id="dm033-test",
            request_id="33000000-0000-4000-8000-000000000102",
        )

    def decision(
        self,
        action: str,
        *,
        predecessor_decision_id: str | None = None,
        seed: bytes | None = None,
    ) -> dict[str, Any]:
        reasons = {
            "accept": "evidence-sufficient",
            "edit": "content-correction",
            "reject": "evidence-insufficient",
            "defer": "reconsideration-needed",
        }
        draft = create_decision_draft(
            request=self.request,
            authorization_id=self.authorization["authorization_id"],
            reviewer_key_id=self.reviewer["key_id"],
            action=action,
            replacement=None,
            reason=reasons[action],
            note_ref="note:dm033-synthetic",
            decision_nonce=str(
                uuid.uuid5(
                    uuid.NAMESPACE_URL,
                    f"dm033:{action}:{predecessor_decision_id}",
                )
            ),
            decided_at_ms=NOW,
            predecessor_decision_id=predecessor_decision_id,
        )
        return sign_review_decision(
            draft,
            self.reviewer_seed if seed is None else seed,
        )

    def test_authorization_acceptance_is_content_bound_and_closed(self) -> None:
        self.assertEqual(
            validate_reviewer_authorization(self.authorization), self.authorization
        )
        changed = copy.deepcopy(self.authorization)
        changed["max_outstanding_decisions"] = 9
        with self.assertRaisesRegex(
            HumanReviewError, "reviewer_authorization_id_mismatch"
        ):
            validate_reviewer_authorization(changed)
        extra = {**self.authorization, "generic_signing": True}
        with self.assertRaisesRegex(HumanReviewError, "invalid_reviewer_authorization"):
            validate_reviewer_authorization(extra)

    def test_reviewer_key_is_separate_from_operational_and_root_authority(
        self,
    ) -> None:
        operational_seed = self.signers["legion"].seed
        operational_reviewer = signing_descriptor(operational_seed)
        group_id = _group_id([operational_reviewer["key_id"]], 1)
        authorization = accept_authorization(
            authorization_core(
                subject_me_id=self.state.being_ref,
                policy_id=self.policy["policy_id"],
                policy_hash=hashlib.sha256(canonical_bytes(self.policy)).hexdigest(),
                reviewer=operational_reviewer,
                group_id=group_id,
                member_key_ids=[operational_reviewer["key_id"]],
                threshold=1,
                categories=["personal-insight"],
                classifications=["protected"],
                actions=["accept"],
                valid_from_ms=NOW,
                expires_at_ms=NOW + 60_000,
                max_outstanding_decisions=1,
                control_position={
                    "manifest_hash": self.ledger_a.authority.manifest.digest,
                    "embodiment_id": self.origins["legion"]["embodiment_id"],
                    "incarnation_id": self.origins["legion"]["incarnation_id"],
                },
                issued_at_ms=NOW,
            ),
            operational_seed,
        )
        with self.assertRaisesRegex(
            HumanReviewError, "reviewer_authority_not_separate"
        ):
            self.coordinator.authorize(
                authorization,
                client_id="dm033-separation",
                request_id="33000000-0000-4000-8000-000000000191",
            )
        changed = copy.deepcopy(self.authorization)
        changed["control_position"]["incarnation_id"] = "incarnation:other:1"
        with self.assertRaisesRegex(
            HumanReviewError, "review_authorization_control_not_current"
        ):
            self.coordinator._validate_current_control(changed)

    def test_accept_requires_human_signature_then_subject_executes_once(self) -> None:
        decision = self.decision("accept")
        self.coordinator.submit(
            decision,
            client_id="dm033-test",
            request_id="33000000-0000-4000-8000-000000000103",
        )
        self.assertEqual(
            self.coordinator.state(self.request["review_request_id"])["status"],
            "decided",
        )
        first = self.coordinator.execute(
            self.request["review_request_id"],
            client_id="dm033-test",
            request_id="33000000-0000-4000-8000-000000000104",
        )
        second = self.coordinator.execute(
            self.request["review_request_id"],
            client_id="dm033-test",
            request_id="33000000-0000-4000-8000-000000000104",
        )
        self.assertEqual(first["receipt"], second["receipt"])
        self.assertEqual(first["receipt"]["result"], "applied")
        self.assertEqual(
            len(
                [
                    event
                    for event in self.ledger_a.events()
                    if event["kind"] == "memory.recorded"
                ]
            ),
            1,
        )

    def test_projection_drift_refuses_effect_and_creates_one_review_successor(
        self,
    ) -> None:
        self.coordinator.submit(
            self.decision("accept"),
            client_id="dm033-stale",
            request_id="33000000-0000-4000-8000-000000000246",
        )
        self.ledger_a.append_local(
            kind="experience.observed",
            subject="dm033-unrelated",
            payload={"summary": "unrelated projection drift"},
            signer=self.signers["legion"],
            sensitivity="personal",
        )
        later = HumanReviewCoordinator(
            self.ledger_a,
            self.signers["legion"],
            clock=lambda: NOW + 1,
        )
        with self.assertRaisesRegex(HumanReviewError, "review_revalidation_changed"):
            later.execute(
                self.request["review_request_id"],
                client_id="dm033-stale",
                request_id="33000000-0000-4000-8000-000000000247",
            )
        requests = [
            event["payload"]
            for event in self.ledger_a.events()
            if event["kind"] == "review.requested"
        ]
        self.assertEqual(len(requests), 2)
        successor = next(
            request
            for request in requests
            if request["review_request_id"] != self.request["review_request_id"]
        )
        self.assertEqual(
            successor["predecessor_review_request_id"],
            self.request["review_request_id"],
        )
        self.assertNotEqual(
            successor["plan"]["checkpoint"]["projection_hash"],
            self.plan["checkpoint"]["projection_hash"],
        )
        self.assertEqual(
            later.state(successor["review_request_id"])["status"], "pending"
        )
        self.assertEqual(
            later.state(self.request["review_request_id"])["status"], "superseded"
        )
        self.assertFalse(
            any(event["kind"] == "memory.recorded" for event in self.ledger_a.events())
        )

    def test_tamper_wrong_key_revocation_and_scope_fail_closed(self) -> None:
        decision = self.decision("accept")
        tampered = copy.deepcopy(decision)
        tampered["decision_nonce"] = "33000000-0000-4000-8000-000000000244"
        with self.assertRaisesRegex(HumanReviewError, "review_decision_id_mismatch"):
            validate_human_decision(tampered, self.authorization, self.request)
        with self.assertRaisesRegex(HumanReviewError, "invalid_review_decision_reason"):
            create_decision_draft(
                request=self.request,
                authorization_id=self.authorization["authorization_id"],
                reviewer_key_id=self.reviewer["key_id"],
                action="accept",
                replacement=None,
                reason="policy-conflict",
                note_ref=None,
                decision_nonce="33000000-0000-4000-8000-000000000245",
                decided_at_ms=NOW,
                predecessor_decision_id=None,
            )

        wrong_seed = bytes(range(1, 33))
        with self.assertRaisesRegex(HumanReviewError, "reviewer_seed_mismatch"):
            self.decision("accept", seed=wrong_seed)

        self.coordinator.revoke(
            self.authorization["authorization_id"],
            reason="synthetic-revocation",
            client_id="dm033-test",
            request_id="33000000-0000-4000-8000-000000000105",
        )
        with self.assertRaisesRegex(
            HumanReviewError, "review_authorization_not_current"
        ):
            self.coordinator.submit(
                decision,
                client_id="dm033-test",
                request_id="33000000-0000-4000-8000-000000000106",
            )

    def test_revocation_after_human_decision_blocks_subject_execution(self) -> None:
        self.coordinator.submit(
            self.decision("accept"),
            client_id="dm033-revocation-race",
            request_id="33000000-0000-4000-8000-000000000194",
        )
        later = HumanReviewCoordinator(
            self.ledger_a,
            self.signers["legion"],
            clock=lambda: NOW + 1,
        )
        later.revoke(
            self.authorization["authorization_id"],
            reason="compromise-before-execution",
            client_id="dm033-revocation-race",
            request_id="33000000-0000-4000-8000-000000000195",
        )
        with self.assertRaisesRegex(
            HumanReviewError, "review_authorization_not_current"
        ):
            later.execute(
                self.request["review_request_id"],
                client_id="dm033-revocation-race",
                request_id="33000000-0000-4000-8000-000000000196",
            )
        self.assertFalse(
            any(
                event["kind"] in {"memory.recorded", "review.executed"}
                for event in self.ledger_a.events()
            )
        )

    def test_artifact_idempotency_survives_new_rpc_ids_and_foreign_auth_refuses(
        self,
    ) -> None:
        authorized = self.coordinator.authorize(
            self.authorization,
            client_id="dm033-replay",
            request_id="33000000-0000-4000-8000-000000000117",
        )
        requested = self.coordinator.request_review(
            self.request,
            client_id="dm033-replay",
            request_id="33000000-0000-4000-8000-000000000118",
        )
        self.assertEqual(authorized["authorization"], self.authorization)
        self.assertEqual(requested["request"], self.request)

        decision = self.decision("accept")
        first = self.coordinator.submit(
            decision,
            client_id="dm033-replay",
            request_id="33000000-0000-4000-8000-000000000119",
        )
        second = self.coordinator.submit(
            decision,
            client_id="dm033-replay",
            request_id="33000000-0000-4000-8000-000000000120",
        )
        self.assertEqual(first["event"], second["event"])
        self.assertEqual(
            len(
                [
                    event
                    for event in self.ledger_a.events()
                    if event["kind"] == "review.decided"
                ]
            ),
            1,
        )

        foreign = accept_authorization(
            authorization_core(
                subject_me_id=self.state.being_ref,
                policy_id=self.policy["policy_id"],
                policy_hash=hashlib.sha256(canonical_bytes(self.policy)).hexdigest(),
                reviewer=self.reviewer,
                group_id=self.group_id,
                member_key_ids=[self.reviewer["key_id"]],
                threshold=1,
                categories=["personal-insight"],
                classifications=["protected"],
                actions=["accept"],
                valid_from_ms=NOW,
                expires_at_ms=NOW + 60_000,
                max_outstanding_decisions=9,
                control_position={
                    "manifest_hash": self.ledger_a.authority.manifest.digest,
                    "embodiment_id": self.origins["legion"]["embodiment_id"],
                    "incarnation_id": self.origins["legion"]["incarnation_id"],
                },
                issued_at_ms=NOW,
            ),
            self.reviewer_seed,
        )
        self.coordinator.authorize(
            foreign,
            client_id="dm033-replay",
            request_id="33000000-0000-4000-8000-000000000121",
        )
        foreign_draft = create_decision_draft(
            request=self.request,
            authorization_id=foreign["authorization_id"],
            reviewer_key_id=self.reviewer["key_id"],
            action="accept",
            replacement=None,
            reason="evidence-sufficient",
            note_ref=None,
            decision_nonce="33000000-0000-4000-8000-000000000197",
            decided_at_ms=NOW,
            predecessor_decision_id=None,
        )
        with self.assertRaisesRegex(HumanReviewError, "review_decision_scope_mismatch"):
            self.coordinator.submit(
                sign_review_decision(foreign_draft, self.reviewer_seed),
                client_id="dm033-replay",
                request_id="33000000-0000-4000-8000-000000000122",
            )

    def test_defer_is_nonterminal_and_successor_accept_is_explicit(self) -> None:
        deferred = self.decision("defer")
        self.coordinator.submit(
            deferred,
            client_id="dm033-test",
            request_id="33000000-0000-4000-8000-000000000107",
        )
        self.assertEqual(
            self.coordinator.state(self.request["review_request_id"])["status"],
            "pending",
        )
        accepted = self.decision(
            "accept", predecessor_decision_id=str(deferred["decision_id"])
        )
        self.coordinator.submit(
            accepted,
            client_id="dm033-test",
            request_id="33000000-0000-4000-8000-000000000108",
        )
        state = self.coordinator.state(self.request["review_request_id"])
        self.assertEqual(state["status"], "decided")
        self.assertEqual(state["action"], "accept")

    def test_outstanding_decision_limit_releases_only_after_resolution(self) -> None:
        authorization = accept_authorization(
            authorization_core(
                subject_me_id=self.state.being_ref,
                policy_id=self.policy["policy_id"],
                policy_hash=hashlib.sha256(canonical_bytes(self.policy)).hexdigest(),
                reviewer=self.reviewer,
                group_id=self.group_id,
                member_key_ids=[self.reviewer["key_id"]],
                threshold=1,
                categories=["personal-insight"],
                classifications=["protected"],
                actions=["accept"],
                valid_from_ms=NOW,
                expires_at_ms=NOW + 60_000,
                max_outstanding_decisions=1,
                control_position={
                    "manifest_hash": self.ledger_a.authority.manifest.digest,
                    "embodiment_id": self.origins["legion"]["embodiment_id"],
                    "incarnation_id": self.origins["legion"]["incarnation_id"],
                },
                issued_at_ms=NOW,
            ),
            self.reviewer_seed,
        )
        self.coordinator.authorize(
            authorization,
            client_id="dm033-outstanding",
            request_id="33000000-0000-4000-8000-000000000270",
        )

        def review_fixture(index: int) -> tuple[dict[str, Any], dict[str, Any]]:
            content = f"outstanding review {index}".encode()
            candidate = create_memory_candidate(
                subject_me_id=self.state.being_ref,
                author_me_id=self.state.being_ref,
                category="personal-insight",
                derivation="local-synthesis",
                context=f"dm033-outstanding-{index}",
                content_ref=create_content_ref(
                    sha256=hashlib.sha256(content).hexdigest(),
                    byte_length=len(content),
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
                    "memory_id": f"33000000-0000-4000-8000-{280 + index:012d}",
                    "operation": "assert",
                    "sequence": 1,
                    "predecessor_event_id": None,
                    "predecessor_hash": None,
                },
                body_evidence=None,
            )
            plan = evaluate_memory_candidate(
                self.policy,
                candidate,
                memory_checkpoint(self.ledger_a, candidate, captured_at_ms=NOW),
                evaluated_at_ms=NOW,
            )
            request = create_review_request(
                policy=self.policy,
                candidate=candidate,
                plan=plan,
                proposal=None,
                authorization_ids=[authorization["authorization_id"]],
                group_id=self.group_id,
                threshold=1,
                requested_at_ms=NOW,
                expires_at_ms=NOW + 60_000,
            )
            self.coordinator.request_review(
                request,
                client_id="dm033-outstanding",
                request_id=f"33000000-0000-4000-8000-{290 + index:012d}",
            )
            draft = create_decision_draft(
                request=request,
                authorization_id=authorization["authorization_id"],
                reviewer_key_id=self.reviewer["key_id"],
                action="accept",
                replacement=None,
                reason="evidence-sufficient",
                note_ref=None,
                decision_nonce=f"33000000-0000-4000-8000-{300 + index:012d}",
                decided_at_ms=NOW,
                predecessor_decision_id=None,
            )
            return request, sign_review_decision(draft, self.reviewer_seed)

        first_request, first_decision = review_fixture(1)
        second_request, second_decision = review_fixture(2)
        self.coordinator.submit(
            first_decision,
            client_id="dm033-outstanding",
            request_id="33000000-0000-4000-8000-000000000311",
        )
        with self.assertRaisesRegex(
            HumanReviewError, "review_decision_limit_exhausted"
        ):
            self.coordinator.submit(
                second_decision,
                client_id="dm033-outstanding",
                request_id="33000000-0000-4000-8000-000000000312",
            )
        self.coordinator.execute(
            first_request["review_request_id"],
            client_id="dm033-outstanding",
            request_id="33000000-0000-4000-8000-000000000313",
        )
        submitted = self.coordinator.submit(
            second_decision,
            client_id="dm033-outstanding",
            request_id="33000000-0000-4000-8000-000000000314",
        )
        self.assertEqual(
            submitted["decision"]["review_request_id"],
            second_request["review_request_id"],
        )

    def test_edit_creates_immutable_successor_and_requires_fresh_review(self) -> None:
        replacement_candidate = create_memory_candidate(
            subject_me_id=self.state.being_ref,
            author_me_id=self.state.being_ref,
            category="personal-insight",
            derivation="local-synthesis",
            context="dm033-edited",
            content_ref=create_content_ref(
                sha256=hashlib.sha256(b"edited reviewed memory").hexdigest(),
                byte_length=22,
                media_type="text/plain",
                classification="protected",
            ),
            evidence_refs=[],
            classification="protected",
            consent="granted",
            safety="clear",
            contradiction="none",
            effect="local-only",
            lane=self.candidate["lane"],
            body_evidence=None,
        )
        checkpoint = memory_checkpoint(
            self.ledger_a, replacement_candidate, captured_at_ms=NOW
        )
        replacement_plan = evaluate_memory_candidate(
            self.policy,
            replacement_candidate,
            checkpoint,
            evaluated_at_ms=NOW,
        )
        replacement = {
            "policy": self.policy,
            "candidate": replacement_candidate,
            "plan": replacement_plan,
            "proposal": None,
        }
        draft = create_decision_draft(
            request=self.request,
            authorization_id=self.authorization["authorization_id"],
            reviewer_key_id=self.reviewer["key_id"],
            action="edit",
            replacement=replacement,
            reason="content-correction",
            note_ref=None,
            decision_nonce="33000000-0000-4000-8000-000000000198",
            decided_at_ms=NOW,
            predecessor_decision_id=None,
        )
        edited = sign_review_decision(draft, self.reviewer_seed)
        self.coordinator.submit(
            edited,
            client_id="dm033-test",
            request_id="33000000-0000-4000-8000-000000000112",
        )
        result = self.coordinator.execute(
            self.request["review_request_id"],
            client_id="dm033-test",
            request_id="33000000-0000-4000-8000-000000000113",
        )
        successor = result["successor_request"]
        self.assertEqual(successor["candidate"], replacement_candidate)
        self.assertEqual(
            successor["predecessor_review_request_id"],
            self.request["review_request_id"],
        )
        self.assertEqual(
            self.coordinator.state(successor["review_request_id"])["status"],
            "pending",
        )
        self.assertEqual(
            [
                event
                for event in self.ledger_a.events()
                if event["kind"] == "memory.recorded"
            ],
            [],
        )

        accept_draft = create_decision_draft(
            request=successor,
            authorization_id=self.authorization["authorization_id"],
            reviewer_key_id=self.reviewer["key_id"],
            action="accept",
            replacement=None,
            reason="evidence-sufficient",
            note_ref=None,
            decision_nonce="33000000-0000-4000-8000-000000000199",
            decided_at_ms=NOW,
            predecessor_decision_id=None,
        )
        self.coordinator.submit(
            sign_review_decision(accept_draft, self.reviewer_seed),
            client_id="dm033-test",
            request_id="33000000-0000-4000-8000-000000000114",
        )
        committed = self.coordinator.execute(
            successor["review_request_id"],
            client_id="dm033-test",
            request_id="33000000-0000-4000-8000-000000000115",
        )
        self.assertEqual(committed["receipt"]["result"], "applied")

    def test_edit_replacement_must_be_exact_deterministic_policy_output(self) -> None:
        plan = copy.deepcopy(self.plan)
        plan["event_preview"]["sensitivity"] = "personal"
        core = {key: value for key, value in plan.items() if key != "plan_id"}
        plan["plan_id"] = "dm:memory-plan:v1:" + b64url(
            hashlib.sha256(PLAN_DOMAIN + canonical_bytes(core)).digest()
        )
        with self.assertRaisesRegex(
            HumanReviewError, "review_replacement_policy_mismatch"
        ):
            create_decision_draft(
                request=self.request,
                authorization_id=self.authorization["authorization_id"],
                reviewer_key_id=self.reviewer["key_id"],
                action="edit",
                replacement={
                    "policy": self.policy,
                    "candidate": self.candidate,
                    "plan": plan,
                    "proposal": None,
                },
                reason="content-correction",
                note_ref=None,
                decision_nonce="33000000-0000-4000-8000-000000000200",
                decided_at_ms=NOW,
                predecessor_decision_id=None,
            )

    def test_two_of_two_threshold_requires_matching_distinct_reviewers(self) -> None:
        seeds = (bytes(range(32, 64)), bytes(range(64, 96)))
        reviewers = [signing_descriptor(seed) for seed in seeds]
        group_id = _group_id([item["key_id"] for item in reviewers], 2)
        authorizations = []
        for index, (seed, reviewer) in enumerate(zip(seeds, reviewers, strict=True)):
            core = authorization_core(
                subject_me_id=self.state.being_ref,
                policy_id=self.policy["policy_id"],
                policy_hash=hashlib.sha256(canonical_bytes(self.policy)).hexdigest(),
                reviewer=reviewer,
                group_id=group_id,
                member_key_ids=[item["key_id"] for item in reviewers],
                threshold=2,
                categories=["personal-insight"],
                classifications=["protected"],
                actions=["accept", "reject"],
                valid_from_ms=NOW,
                expires_at_ms=NOW + 60_000,
                max_outstanding_decisions=4,
                control_position={
                    "manifest_hash": self.ledger_a.authority.manifest.digest,
                    "embodiment_id": self.origins["legion"]["embodiment_id"],
                    "incarnation_id": self.origins["legion"]["incarnation_id"],
                },
                issued_at_ms=NOW,
            )
            authorization = accept_authorization(core, seed)
            self.coordinator.authorize(
                authorization,
                client_id="dm033-threshold",
                request_id=f"33000000-0000-4000-8000-{200 + index:012d}",
            )
            authorizations.append(authorization)
        request = create_review_request(
            policy=self.policy,
            candidate=self.candidate,
            plan=self.plan,
            proposal=None,
            authorization_ids=[item["authorization_id"] for item in authorizations],
            group_id=group_id,
            threshold=2,
            requested_at_ms=NOW,
            expires_at_ms=NOW + 60_000,
        )
        self.coordinator.request_review(
            request,
            client_id="dm033-threshold",
            request_id="33000000-0000-4000-8000-000000000202",
        )
        decisions = []
        for index, (seed, reviewer, authorization) in enumerate(
            zip(seeds, reviewers, authorizations, strict=True)
        ):
            draft = create_decision_draft(
                request=request,
                authorization_id=authorization["authorization_id"],
                reviewer_key_id=reviewer["key_id"],
                action="accept",
                replacement=None,
                reason="evidence-sufficient",
                note_ref=None,
                decision_nonce=f"33000000-0000-4000-8000-{230 + index:012d}",
                decided_at_ms=NOW,
                predecessor_decision_id=None,
            )
            decisions.append(sign_review_decision(draft, seed))
        barrier = threading.Barrier(3)

        def submit(index: int) -> dict[str, Any]:
            barrier.wait()
            return self.coordinator.submit(
                decisions[index],
                client_id="dm033-threshold",
                request_id=f"33000000-0000-4000-8000-{203 + index:012d}",
            )

        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(submit, index) for index in range(2)]
            barrier.wait()
            results = [future.result(timeout=5) for future in futures]
        self.assertEqual(len(results), 2)
        state = self.coordinator.state(request["review_request_id"])
        self.assertEqual(state["status"], "decided")
        self.assertEqual(state["decision_count"], 2)

    def test_operationally_signed_but_human_invalid_import_is_quarantined(self) -> None:
        decision = self.decision("accept")
        decision["signature"]["value"] = b64url(bytes(64))
        poisoned = self.ledger_a.append_local(
            kind="review.decided",
            subject=self.state.being_ref,
            payload=decision,
            signer=self.signers["legion"],
            sensitivity="private",
            causal_parents=[
                self.coordinator.review_request(self.request["review_request_id"])[1][
                    "event_id"
                ],
                self.coordinator.authorization(self.authorization["authorization_id"])[
                    1
                ]["event_id"],
            ],
            occurred_at_ms=NOW,
        )
        state = self.coordinator.state(self.request["review_request_id"])
        self.assertEqual(state["status"], "conflict")
        self.assertEqual(state["invalid_decision_event_ids"], [poisoned["event_id"]])
        with self.assertRaisesRegex(HumanReviewError, "review_not_executable"):
            self.coordinator.execute(
                self.request["review_request_id"],
                client_id="dm033-test",
                request_id="33000000-0000-4000-8000-000000000116",
            )

    def test_unsigned_plan_cannot_cross_automatic_executor(self) -> None:
        from daimon_matrix.memory_policy import (
            MemoryExecutionError,
            MemoryPolicyExecutor,
        )

        with self.assertRaisesRegex(
            MemoryExecutionError, "memory_plan_not_automatically_executable"
        ):
            MemoryPolicyExecutor(
                self.ledger_a, self.signers["legion"], clock=lambda: NOW
            ).execute(
                self.plan,
                self.policy,
                self.candidate,
                client_id="dm033-test",
                request_id="33000000-0000-4000-8000-000000000109",
            )

    def test_queue_and_exact_inspection_require_fresh_possession_proof(self) -> None:
        rpc_request_id = "33000000-0000-4000-8000-000000000110"
        proof = create_access_proof(
            authorization_id=self.authorization["authorization_id"],
            rpc_request_id=rpc_request_id,
            issued_at_ms=NOW,
            expires_at_ms=NOW + 1_000,
            reviewer_seed=self.reviewer_seed,
        )
        queue = self.coordinator.queue(
            authorization_id=self.authorization["authorization_id"],
            access_proof=proof,
            rpc_request_id=rpc_request_id,
            after=None,
            limit=10,
        )
        self.assertEqual(len(queue["items"]), 1)
        self.assertNotIn("candidate", queue["items"][0])
        inspection = self.coordinator.inspect(
            review_request_id=self.request["review_request_id"],
            authorization_id=self.authorization["authorization_id"],
            access_proof=proof,
            rpc_request_id=rpc_request_id,
        )
        self.assertEqual(inspection["request"], self.request)

        with self.assertRaisesRegex(HumanReviewError, "invalid_review_access_proof"):
            self.coordinator.queue(
                authorization_id=self.authorization["authorization_id"],
                access_proof=proof,
                rpc_request_id="33000000-0000-4000-8000-000000000111",
                after=None,
                limit=10,
            )

    def test_inspection_does_not_oracle_known_foreign_request_membership(self) -> None:
        seed = hashlib.sha256(b"dm033-independent-reviewer").digest()
        reviewer = signing_descriptor(seed)
        group_id = _group_id([reviewer["key_id"]], 1)
        authorization = accept_authorization(
            authorization_core(
                subject_me_id=self.state.being_ref,
                policy_id=self.policy["policy_id"],
                policy_hash=hashlib.sha256(canonical_bytes(self.policy)).hexdigest(),
                reviewer=reviewer,
                group_id=group_id,
                member_key_ids=[reviewer["key_id"]],
                threshold=1,
                categories=["personal-insight"],
                classifications=["protected"],
                actions=["accept"],
                valid_from_ms=NOW,
                expires_at_ms=NOW + 60_000,
                max_outstanding_decisions=1,
                control_position={
                    "manifest_hash": self.ledger_a.authority.manifest.digest,
                    "embodiment_id": self.origins["legion"]["embodiment_id"],
                    "incarnation_id": self.origins["legion"]["incarnation_id"],
                },
                issued_at_ms=NOW,
            ),
            seed,
        )
        self.coordinator.authorize(
            authorization,
            client_id="dm033-disclosure",
            request_id="33000000-0000-4000-8000-000000000192",
        )
        rpc_request_id = "33000000-0000-4000-8000-000000000193"
        proof = create_access_proof(
            authorization_id=authorization["authorization_id"],
            rpc_request_id=rpc_request_id,
            issued_at_ms=NOW,
            expires_at_ms=NOW + 1_000,
            reviewer_seed=seed,
        )
        failures = []
        for review_request_id in (
            self.request["review_request_id"],
            "dm:review-request:v1:" + "A" * 43,
        ):
            with self.assertRaises(HumanReviewError) as caught:
                self.coordinator.inspect(
                    review_request_id=review_request_id,
                    authorization_id=authorization["authorization_id"],
                    access_proof=proof,
                    rpc_request_id=rpc_request_id,
                )
            failures.append(str(caught.exception))
        self.assertEqual(
            failures,
            ["review_disclosure_unavailable", "review_disclosure_unavailable"],
        )

    def test_queue_order_pagination_and_semantic_dedup_are_deterministic(self) -> None:
        request_ids = [self.request["review_request_id"]]
        for index in range(2):
            candidate = create_memory_candidate(
                subject_me_id=self.state.being_ref,
                author_me_id=self.state.being_ref,
                category="personal-insight",
                derivation="local-synthesis",
                context=f"dm033-page-{index}",
                content_ref=create_content_ref(
                    sha256=hashlib.sha256(f"dm033-page-{index}".encode()).hexdigest(),
                    byte_length=16,
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
                    "memory_id": f"33000000-0000-4000-8000-{400 + index:012d}",
                    "operation": "assert",
                    "sequence": 1,
                    "predecessor_event_id": None,
                    "predecessor_hash": None,
                },
                body_evidence=None,
            )
            plan = evaluate_memory_candidate(
                self.policy,
                candidate,
                memory_checkpoint(self.ledger_a, candidate, captured_at_ms=NOW),
                evaluated_at_ms=NOW,
            )
            request = create_review_request(
                policy=self.policy,
                candidate=candidate,
                plan=plan,
                proposal=None,
                authorization_ids=[self.authorization["authorization_id"]],
                group_id=self.group_id,
                threshold=1,
                requested_at_ms=NOW,
                expires_at_ms=NOW + 60_000,
            )
            for replay in range(2):
                self.coordinator.request_review(
                    request,
                    client_id="dm033-pagination",
                    request_id=(
                        f"33000000-0000-4000-8000-{410 + index * 2 + replay:012d}"
                    ),
                )
            request_ids.append(request["review_request_id"])
        rpc_request_id = "33000000-0000-4000-8000-000000000420"
        proof = create_access_proof(
            authorization_id=self.authorization["authorization_id"],
            rpc_request_id=rpc_request_id,
            issued_at_ms=NOW,
            expires_at_ms=NOW + 1_000,
            reviewer_seed=self.reviewer_seed,
        )
        first = self.coordinator.queue(
            authorization_id=self.authorization["authorization_id"],
            access_proof=proof,
            rpc_request_id=rpc_request_id,
            after=None,
            limit=2,
        )
        self.assertIsNotNone(first["next"])
        second = self.coordinator.queue(
            authorization_id=self.authorization["authorization_id"],
            access_proof=proof,
            rpc_request_id=rpc_request_id,
            after=first["next"],
            limit=2,
        )
        observed = [
            item["review_request_id"]
            for page in (first, second)
            for item in page["items"]
        ]
        self.assertEqual(observed, sorted(request_ids))
        self.assertEqual(second["next"], None)
        self.assertEqual(
            len(
                [
                    event
                    for event in self.ledger_a.events()
                    if event["kind"] == "review.requested"
                ]
            ),
            3,
        )

    def test_public_schemas_are_closed_and_match_runtime_artifacts(self) -> None:
        rpc_request_id = "33000000-0000-4000-8000-000000000123"
        proof = create_access_proof(
            authorization_id=self.authorization["authorization_id"],
            rpc_request_id=rpc_request_id,
            issued_at_ms=NOW,
            expires_at_ms=NOW + 1_000,
            reviewer_seed=self.reviewer_seed,
        )
        queue = self.coordinator.queue(
            authorization_id=self.authorization["authorization_id"],
            access_proof=proof,
            rpc_request_id=rpc_request_id,
            after=None,
            limit=10,
        )
        rejected = self.decision("reject")
        self.coordinator.submit(
            rejected,
            client_id="dm033-schema",
            request_id="33000000-0000-4000-8000-000000000124",
        )
        execution = self.coordinator.execute(
            self.request["review_request_id"],
            client_id="dm033-schema",
            request_id="33000000-0000-4000-8000-000000000125",
        )
        revocation = self.coordinator.revoke(
            self.authorization["authorization_id"],
            reason="schema-fixture",
            client_id="dm033-schema",
            request_id="33000000-0000-4000-8000-000000000126",
        )["revocation"]
        schema_paths = [
            *sorted((ROOT / "schemas/review/v1").glob("*.json")),
            *sorted((ROOT / "schemas/memory/v1").glob("*.json")),
            *sorted((ROOT / "schemas/curator-worker/v1").glob("*.json")),
        ]
        schemas = [json.loads(path.read_bytes()) for path in schema_paths]
        registry = Registry().with_resources(
            (schema["$id"], Resource.from_contents(schema)) for schema in schemas
        )
        for schema in schemas:
            Draft202012Validator.check_schema(schema)
        review_schemas = {
            path.name: schema
            for path, schema in zip(schema_paths, schemas, strict=True)
            if path.parent.name == "v1" and path.parent.parent.name == "review"
        }
        artifacts: dict[str, Any] = {
            "authorization.schema.json": self.authorization,
            "revocation.schema.json": revocation,
            "request.schema.json": self.request,
            "decision.schema.json": rejected,
            "access-proof.schema.json": proof,
            "execution-receipt.schema.json": execution["receipt"],
            "queue.schema.json": queue,
        }
        for name, artifact in artifacts.items():
            Draft202012Validator(
                review_schemas[name],
                registry=registry,
                format_checker=FormatChecker(),
            ).validate(artifact)
            invalid = {**artifact, "ambient_authority": True}
            self.assertFalse(
                Draft202012Validator(
                    review_schemas[name],
                    registry=registry,
                    format_checker=FormatChecker(),
                ).is_valid(invalid)
            )

    def test_published_vectors_reproduce_and_negative_signature_fails(self) -> None:
        index = json.loads((VECTOR_ROOT / "index.json").read_bytes())
        artifacts = {
            name: json.loads((VECTOR_ROOT / relative).read_bytes())
            for name, relative in index["artifacts"].items()
        }
        for name, artifact in artifacts.items():
            self.assertEqual(
                hashlib.sha256(canonical_bytes(artifact)).hexdigest(),
                index["sha256"][name],
            )
        validate_reviewer_authorization(artifacts["authorization"])
        validate_review_request(artifacts["request"])
        validate_human_decision(
            artifacts["decision_edit_alternative"],
            artifacts["authorization"],
            artifacts["request"],
        )
        for suffix in ("a", "b"):
            authorization = artifacts[f"authorization_threshold_{suffix}"]
            validate_reviewer_authorization(authorization)
            validate_human_decision(
                artifacts[f"decision_threshold_accept_{suffix}"],
                authorization,
                artifacts["request_threshold"],
            )
        for name in (
            "execution_receipt",
            "execution_receipt_edit",
            "execution_receipt_reject",
        ):
            validate_execution_receipt(artifacts[name])
        with self.assertRaisesRegex(HumanReviewError, "review_decision_id_mismatch"):
            validate_human_decision(
                artifacts["negative_tampered_decision"],
                artifacts["authorization"],
                artifacts["request"],
            )
        with TemporaryDirectory(prefix="dm033-vectors-") as directory:
            generated = Path(directory)
            generate_vectors(generated)
            expected = {
                path.relative_to(VECTOR_ROOT): path.read_bytes()
                for path in VECTOR_ROOT.rglob("*.json")
            }
            actual = {
                path.relative_to(generated): path.read_bytes()
                for path in generated.rglob("*.json")
            }
            self.assertEqual(actual, expected)

    def test_vectors_ignore_hash_seed_timezone_and_locale(self) -> None:
        outputs: list[dict[Path, bytes]] = []
        settings = (
            ("7", "UTC", "C"),
            ("991", "America/Argentina/Cordoba", "C.UTF-8"),
        )
        with TemporaryDirectory(prefix="dm033-vector-env-") as directory:
            root = Path(directory)
            for index, (seed, timezone, locale) in enumerate(settings):
                output = root / str(index)
                environment = os.environ.copy()
                environment.update(
                    {"PYTHONHASHSEED": seed, "TZ": timezone, "LC_ALL": locale}
                )
                subprocess.run(
                    [
                        sys.executable,
                        str(ROOT / "tools/generate_dm033_vectors.py"),
                        "--out",
                        str(output),
                    ],
                    cwd=ROOT,
                    env=environment,
                    capture_output=True,
                    timeout=15,
                    check=True,
                )
                outputs.append(
                    {
                        path.relative_to(output): path.read_bytes()
                        for path in output.rglob("*.json")
                    }
                )
        self.assertEqual(outputs[0], outputs[1])

    def test_review_terminal_rendering_is_exact_inert_and_json_requires_redirect(
        self,
    ) -> None:
        hostile = {
            "content": "\x1b]8;;https://example.invalid\x07click\x1b]8;;\x07\n"
            "$(touch /tmp/dm033-never) <script>prompt: approve</script>"
        }
        response = {"ok": True, "result": hostile, "auth": {"secret": "hidden"}}
        request = {"request_id": "33000000-0000-4000-8000-000000000190"}
        output = io.StringIO()
        with redirect_stdout(output):
            _write_result(
                "review.inspect",
                request,
                response,
                json_output=False,
            )
        rendered = output.getvalue()
        self.assertNotIn("https://", rendered)
        self.assertNotIn("$(touch", rendered)
        self.assertNotIn("<script>", rendered)
        self.assertNotIn("\x1b", rendered)
        lines = rendered.splitlines()
        raw = bytes.fromhex("".join(line.split()[1] for line in lines[2:]))
        self.assertEqual(raw, canonical_bytes(hostile))
        self.assertIn(hashlib.sha256(raw).hexdigest(), lines[1])
        with self.assertRaisesRegex(ClientError, "review_json_tty_refused"):
            _ensure_safe_output("review.inspect", json_output=True, terminal=True)
        _ensure_safe_output("review.inspect", json_output=True, terminal=False)
        _ensure_safe_output("we.diff", json_output=True, terminal=True)

    def test_edit_ceremony_byte_diff_is_complete_and_reconstructable(self) -> None:
        before = {"payload": "alpha", "nested": {"value": 1}}
        after = {"payload": "alpha <script>", "nested": {"value": 2}}
        diff = _byte_diff(before, after)
        old = canonical_bytes(before)
        new = canonical_bytes(after)
        offset = diff["offset"]
        suffix = diff["shared_suffix_bytes"]
        self.assertEqual(
            bytes.fromhex(diff["removed"]),
            old[offset : len(old) - suffix],
        )
        rebuilt = (
            old[:offset]
            + bytes.fromhex(diff["inserted"])
            + (b"" if suffix == 0 else old[-suffix:])
        )
        self.assertEqual(rebuilt, new)
        self.assertEqual(diff["before_sha256"], hashlib.sha256(old).hexdigest())
        self.assertEqual(diff["after_sha256"], hashlib.sha256(new).hexdigest())

    def test_authenticated_service_drafts_but_only_accepts_presigned_decision(
        self,
    ) -> None:
        capability = create_capability(
            hashlib.sha256(b"dm033-service-capability").digest(),
            client_id="client:dm033-review",
            methods=sorted(REVIEW_METHODS),
            not_before_ms=NOW - 1_000,
            not_after_ms=NOW + 1_000,
        )
        service = HostedWeave(
            self.ledger_a,
            self.signers["legion"],
            {capability.capability_id: capability},
            lambda: NOW,
            "dm:runtime:v1:" + "a" * 43,
            "review",
        )

        def invoke(
            index: int, method: str, params: dict[str, object]
        ) -> dict[str, Any]:
            request = create_request(
                capability,
                request_id=f"33000000-0000-4000-8000-{index:012d}",
                issued_at_ms=NOW,
                method=method,
                params=params,
                nonce=index.to_bytes(16, "big"),
            )
            return service.handle(request)

        draft_response = invoke(
            120,
            "review.decision.draft",
            {
                "review_request_id": self.request["review_request_id"],
                "authorization_id": self.authorization["authorization_id"],
                "action": "accept",
                "replacement": None,
                "reason": "evidence-sufficient",
                "note_ref": None,
                "decision_nonce": "33000000-0000-4000-8000-000000000240",
                "decided_at_ms": NOW,
                "predecessor_decision_id": None,
            },
        )
        self.assertTrue(draft_response["ok"], draft_response)
        draft = draft_response["result"]
        self.assertNotIn("signature", draft)

        unsigned = invoke(121, "review.decision.submit", {"decision": draft})
        self.assertFalse(unsigned["ok"])
        decision = sign_review_decision(draft, self.reviewer_seed)
        submitted = invoke(122, "review.decision.submit", {"decision": decision})
        self.assertTrue(submitted["ok"], submitted)
        executed = invoke(
            123,
            "review.execute",
            {"review_request_id": self.request["review_request_id"]},
        )
        self.assertTrue(executed["ok"], executed)

    def _owner_json(self, name: str, value: dict[str, object]) -> Path:
        path = self.root_path / name
        path.write_bytes(canonical_bytes(value))
        path.chmod(0o600)
        return path

    def _reviewer_pty(
        self, keystore: Path, arguments: list[str]
    ) -> tuple[subprocess.Popen[bytes], bytes, bytes]:
        password_read, password_write = os.pipe()
        os.write(password_write, b"dm033 reviewer password")
        os.close(password_write)
        master, slave = pty.openpty()
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
        process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "daimon_matrix.reviewer_cli",
                "--keystore",
                str(keystore),
                "--password-fd",
                str(password_read),
                *arguments,
            ],
            stdin=slave,
            stdout=subprocess.PIPE,
            stderr=slave,
            pass_fds=(password_read,),
            env=environment,
        )
        os.close(password_read)
        os.close(slave)
        transcript = bytearray()
        for _ in range(200):
            readable, _, _ = select.select([master], [], [], 0.05)
            if readable:
                try:
                    transcript.extend(os.read(master, 65536))
                except OSError:
                    break
            match = re.search(rb"Type SIGN ([A-Za-z0-9_-]{12})", transcript)
            if match is not None:
                os.write(master, b"SIGN " + match.group(1) + b"\n")
                break
        stdout, _ = process.communicate(timeout=10)
        while True:
            readable, _, _ = select.select([master], [], [], 0)
            if not readable:
                break
            try:
                transcript.extend(os.read(master, 65536))
            except OSError:
                break
        os.close(master)
        return process, stdout, bytes(transcript)

    def test_real_pty_reviewer_keystore_acceptance_and_decision_ceremony(
        self,
    ) -> None:
        keystore = self.root_path / "reviewer.keystore"
        created, stdout, transcript = self._reviewer_pty(keystore, ["key-create"])
        self.assertEqual(created.returncode, 0, transcript)
        descriptor = json.loads(stdout)
        self.assertEqual(keystore.stat().st_mode & 0o777, 0o600)
        group_id = _group_id([descriptor["key_id"]], 1)
        core = authorization_core(
            subject_me_id=self.state.being_ref,
            policy_id=self.policy["policy_id"],
            policy_hash=hashlib.sha256(canonical_bytes(self.policy)).hexdigest(),
            reviewer=descriptor,
            group_id=group_id,
            member_key_ids=[descriptor["key_id"]],
            threshold=1,
            categories=["personal-insight"],
            classifications=["protected"],
            actions=["accept", "defer", "edit", "reject"],
            valid_from_ms=NOW,
            expires_at_ms=NOW + 60_000,
            max_outstanding_decisions=8,
            control_position={
                "manifest_hash": self.ledger_a.authority.manifest.digest,
                "embodiment_id": self.origins["legion"]["embodiment_id"],
                "incarnation_id": self.origins["legion"]["incarnation_id"],
            },
            issued_at_ms=NOW,
        )
        core_path = self._owner_json("authorization-core.json", core)
        authorization_path = self.root_path / "authorization.json"
        accepted, _, transcript = self._reviewer_pty(
            keystore,
            [
                "authorization-accept",
                "--core",
                str(core_path),
                "--out",
                str(authorization_path),
            ],
        )
        self.assertEqual(accepted.returncode, 0, transcript)
        authorization = json.loads(authorization_path.read_bytes())
        validate_reviewer_authorization(authorization)
        request = create_review_request(
            policy=self.policy,
            candidate=self.candidate,
            plan=self.plan,
            proposal=None,
            authorization_ids=[authorization["authorization_id"]],
            group_id=group_id,
            threshold=1,
            requested_at_ms=NOW,
            expires_at_ms=NOW + 60_000,
        )
        draft = create_decision_draft(
            request=request,
            authorization_id=authorization["authorization_id"],
            reviewer_key_id=descriptor["key_id"],
            action="accept",
            replacement=None,
            reason="evidence-sufficient",
            note_ref=None,
            decision_nonce="33000000-0000-4000-8000-000000000241",
            decided_at_ms=NOW,
            predecessor_decision_id=None,
        )
        request_path = self._owner_json("review-request.json", request)
        draft_path = self._owner_json("decision-draft.json", draft)
        decision_path = self.root_path / "signed-decision.json"
        signed, _, transcript = self._reviewer_pty(
            keystore,
            [
                "decision-sign",
                "--authorization",
                str(authorization_path),
                "--request",
                str(request_path),
                "--draft",
                str(draft_path),
                "--out",
                str(decision_path),
            ],
        )
        self.assertEqual(signed.returncode, 0, transcript)
        decision = json.loads(decision_path.read_bytes())
        validate_human_decision(decision, authorization, request)

        edited_candidate = create_memory_candidate(
            subject_me_id=self.state.being_ref,
            author_me_id=self.state.being_ref,
            category="personal-insight",
            derivation="local-synthesis",
            context="dm033-pty-edited",
            content_ref=create_content_ref(
                sha256=hashlib.sha256(b"pty edited reviewed memory").hexdigest(),
                byte_length=26,
                media_type="text/plain",
                classification="protected",
            ),
            evidence_refs=[],
            classification="protected",
            consent="granted",
            safety="clear",
            contradiction="none",
            effect="local-only",
            lane=self.candidate["lane"],
            body_evidence=None,
        )
        edited_plan = evaluate_memory_candidate(
            self.policy,
            edited_candidate,
            memory_checkpoint(self.ledger_a, edited_candidate, captured_at_ms=NOW),
            evaluated_at_ms=NOW,
        )
        cases = {
            "edit": (
                "content-correction",
                {
                    "policy": self.policy,
                    "candidate": edited_candidate,
                    "plan": edited_plan,
                    "proposal": None,
                },
            ),
            "reject": ("evidence-insufficient", None),
            "defer": ("reconsideration-needed", None),
        }
        for index, (action, (reason, replacement)) in enumerate(cases.items()):
            action_draft = create_decision_draft(
                request=request,
                authorization_id=authorization["authorization_id"],
                reviewer_key_id=descriptor["key_id"],
                action=action,
                replacement=replacement,
                reason=reason,
                note_ref=None,
                decision_nonce=f"33000000-0000-4000-8000-{250 + index:012d}",
                decided_at_ms=NOW,
                predecessor_decision_id=None,
            )
            action_draft_path = self._owner_json(
                f"decision-{action}-draft.json", action_draft
            )
            action_path = self.root_path / f"decision-{action}.json"
            signed_action, _, action_transcript = self._reviewer_pty(
                keystore,
                [
                    "decision-sign",
                    "--authorization",
                    str(authorization_path),
                    "--request",
                    str(request_path),
                    "--draft",
                    str(action_draft_path),
                    "--out",
                    str(action_path),
                ],
            )
            self.assertEqual(signed_action.returncode, 0, action_transcript)
            signed_value = json.loads(action_path.read_bytes())
            self.assertEqual(signed_value["action"], action)
            validate_human_decision(signed_value, authorization, request)

        password_read, password_write = os.pipe()
        os.write(password_write, b"dm033 reviewer password")
        os.close(password_write)
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
        refused = subprocess.run(
            [
                sys.executable,
                "-m",
                "daimon_matrix.reviewer_cli",
                "--keystore",
                str(keystore),
                "--password-fd",
                str(password_read),
                "decision-sign",
                "--authorization",
                str(authorization_path),
                "--request",
                str(request_path),
                "--draft",
                str(draft_path),
                "--out",
                str(self.root_path / "must-not-exist.json"),
            ],
            input=b"SIGN anything\n",
            capture_output=True,
            pass_fds=(password_read,),
            env=environment,
            timeout=10,
            check=False,
        )
        os.close(password_read)
        self.assertEqual(refused.returncode, 1)
        self.assertIn(b"reviewer_tty_required", refused.stderr)

        no_yes_path = self.root_path / "no-yes-decision.json"
        rejected_yes = subprocess.run(
            [
                sys.executable,
                "-m",
                "daimon_matrix.reviewer_cli",
                "--keystore",
                str(keystore),
                "--password-fd",
                "9",
                "decision-sign",
                "--authorization",
                str(authorization_path),
                "--request",
                str(request_path),
                "--draft",
                str(draft_path),
                "--out",
                str(no_yes_path),
                "--yes",
            ],
            capture_output=True,
            env=environment,
            timeout=10,
            check=False,
        )
        self.assertNotEqual(rejected_yes.returncode, 0)
        self.assertFalse(no_yes_path.exists())

        secret = "synthetic-password-must-not-echo"
        secret_argv = subprocess.run(
            [
                sys.executable,
                "-m",
                "daimon_matrix.reviewer_cli",
                "--password=" + secret,
                "key-create",
            ],
            capture_output=True,
            env=environment,
            timeout=10,
            check=False,
        )
        self.assertEqual(secret_argv.returncode, 1)
        self.assertIn(b"reviewer_secret_channel_refused", secret_argv.stderr)
        self.assertNotIn(secret.encode(), secret_argv.stderr)
        secret_environment = environment.copy()
        secret_environment["DAIMON_REVIEWER_PASSWORD"] = secret
        secret_env = subprocess.run(
            [sys.executable, "-m", "daimon_matrix.reviewer_cli"],
            capture_output=True,
            env=secret_environment,
            timeout=10,
            check=False,
        )
        self.assertEqual(secret_env.returncode, 1)
        self.assertIn(b"reviewer_secret_channel_refused", secret_env.stderr)
        self.assertNotIn(secret.encode(), secret_env.stderr)

        password_read, password_write = os.pipe()
        os.write(password_write, b"dm033 reviewer password")
        os.close(password_write)
        master, slave = pty.openpty()
        interrupted_path = self.root_path / "interrupted-decision.json"
        interrupted = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "daimon_matrix.reviewer_cli",
                "--keystore",
                str(keystore),
                "--password-fd",
                str(password_read),
                "decision-sign",
                "--authorization",
                str(authorization_path),
                "--request",
                str(request_path),
                "--draft",
                str(draft_path),
                "--out",
                str(interrupted_path),
            ],
            stdin=slave,
            stdout=subprocess.PIPE,
            stderr=slave,
            pass_fds=(password_read,),
            env=environment,
        )
        os.close(password_read)
        os.close(slave)
        interrupted_transcript = bytearray()
        for _ in range(200):
            readable, _, _ = select.select([master], [], [], 0.05)
            if readable:
                interrupted_transcript.extend(os.read(master, 65536))
            if b"Type SIGN " in interrupted_transcript:
                interrupted.send_signal(signal.SIGINT)
                break
        interrupted.communicate(timeout=10)
        while True:
            readable, _, _ = select.select([master], [], [], 0)
            if not readable:
                break
            try:
                interrupted_transcript.extend(os.read(master, 65536))
            except OSError:
                break
        os.close(master)
        self.assertEqual(interrupted.returncode, 130, interrupted_transcript)
        self.assertIn(b"reviewer_confirmation_interrupted", interrupted_transcript)
        self.assertFalse(interrupted_path.exists())


class HumanReviewInstalledTests(RuntimeFixture):
    def setUp(self) -> None:
        super().setUp()
        self.now = time.time_ns() // 1_000_000
        self.state_root, bundle, self.capability, _ = self.make_process_bundle(
            capability_profile="review"
        )
        self.runtime_id = bundle["runtime_id"]
        self.runtime_label = bundle["runtime_label"]
        self.runtime = self._load_runtime()
        self.stop = threading.Event()
        self.drop_response = threading.Event()

        def fault(stage: str) -> None:
            if stage == "after_dispatch_before_write" and self.drop_response.is_set():
                self.drop_response.clear()
                raise ConnectionError("synthetic response loss")

        self.fault = fault
        self._start(fault)
        config_path = self.state_root / "review-client.json"
        config_path.write_bytes(
            canonical_bytes(
                {
                    "schema": CLIENT_CONFIG_SCHEMA_V3,
                    "capability": self.capability.descriptor,
                    "expected_server": self.origins["legion"],
                    "runtime_id": self.runtime_id,
                    "runtime_label": self.runtime_label,
                }
            )
        )
        config_path.chmod(0o600)
        self.client = LocalClient(
            self.runtime.socket_path,
            ClientConfig(
                self.capability,
                self.origins["legion"],
                self.runtime_id,
                self.runtime_label,
            ),
        )
        observe_capability = self.operator_capabilities["observe"]
        self.observe_client = LocalClient(
            self.runtime.socket_path,
            ClientConfig(
                observe_capability,
                self.origins["legion"],
                self.runtime_id,
                self.runtime_label,
            ),
        )
        self.request_dir = self.state_root / "mcp-review-requests"
        self.request_dir.mkdir(mode=0o700)

    def _mcp_call(
        self, identifier: str, name: str, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        observing = name in {"review_inspect", "review_queue"}
        capability = (
            self.operator_capabilities["observe"] if observing else self.capability
        )
        config_path = (
            self.state_root / "client.json"
            if observing
            else self.state_root / "review-client.json"
        )
        read_descriptor, write_descriptor = os.pipe()
        os.write(write_descriptor, capability.key)
        os.close(write_descriptor)
        environment = os.environ.copy()
        package_parent = Path(daimon_matrix.__file__).resolve().parent.parent
        environment["PYTHONPATH"] = str(package_parent)
        process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "daimon_matrix.mcp_server",
                "--socket",
                str(self.runtime.socket_path),
                "--client-config",
                str(config_path),
                "--capability-key-fd",
                str(read_descriptor),
                "--request-dir",
                str(self.request_dir),
            ],
            cwd=ROOT,
            env=environment,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            pass_fds=(read_descriptor,),
        )
        os.close(read_descriptor)
        assert process.stdin is not None
        assert process.stdout is not None
        assert process.stderr is not None
        process.stdin.write(
            canonical_bytes(
                {
                    "jsonrpc": "2.0",
                    "id": identifier,
                    "method": "tools/call",
                    "params": {
                        "_meta": MCP_META,
                        "name": name,
                        "arguments": arguments,
                    },
                }
            )
            + b"\n"
        )
        process.stdin.flush()
        readable, _, _ = select.select([process.stdout], [], [], 10)
        self.assertTrue(readable, "DM-033 MCP did not answer before timeout")
        response = process.stdout.readline()
        process.stdin.close()
        return_code = process.wait(timeout=15)
        errors = process.stderr.read()
        process.stdout.close()
        process.stderr.close()
        self.assertEqual(return_code, 0, errors)
        self.assertEqual(errors, b"")
        return cast(dict[str, Any], json.loads(response))

    def _load_runtime(self) -> HostedRuntime:
        return load_runtime(
            self.state_root,
            "runtime.json",
            lambda: bytearray(PASSWORD),
            clock=lambda: self.now,
        )

    def _start(self, fault: FaultHook | None = None) -> None:
        arguments: dict[str, Any] = {
            "runtime": self.runtime,
            "stop": self.stop,
        }
        if fault is not None:
            arguments["fault_hook"] = fault
        self.thread = threading.Thread(
            target=serve_forever,
            kwargs=arguments,
            daemon=True,
        )
        self.thread.start()
        for _ in range(200):
            try:
                info = self.runtime.socket_path.lstat()
            except FileNotFoundError:
                pass
            else:
                if stat.S_ISSOCK(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600:
                    return
            time.sleep(0.01)
        self.fail("DM-033 installed runtime socket did not become ready")

    def _restart(self) -> None:
        self.stop.set()
        self.thread.join(timeout=3)
        self.assertFalse(self.thread.is_alive())
        self.runtime = self._load_runtime()
        self.stop = threading.Event()
        self._start(self.fault)

    def tearDown(self) -> None:
        self.stop.set()
        self.thread.join(timeout=3)
        super().tearDown()

    def test_response_loss_restart_and_exact_retry_never_duplicates_effects(
        self,
    ) -> None:
        reviewer_seed = hashlib.sha256(b"dm033-installed-reviewer").digest()
        reviewer = signing_descriptor(reviewer_seed)
        group_id = _group_id([reviewer["key_id"]], 1)
        policy = create_memory_policy(
            subject_me_id=self.state.being_ref,
            version=1,
            predecessor_policy_id=None,
            automatic_categories=["personal-insight"],
            review_classifications=["protected"],
            plan_ttl_ms=60_000,
        )
        candidate = create_memory_candidate(
            subject_me_id=self.state.being_ref,
            author_me_id=self.state.being_ref,
            category="personal-insight",
            derivation="local-synthesis",
            context="dm033-installed",
            content_ref=create_content_ref(
                sha256=hashlib.sha256(b"installed reviewed memory").hexdigest(),
                byte_length=25,
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
                "memory_id": "33000000-0000-4000-8000-000000000333",
                "operation": "assert",
                "sequence": 1,
                "predecessor_event_id": None,
                "predecessor_hash": None,
            },
            body_evidence=None,
        )
        _, evaluation = self.observe_client.memory_evaluate(
            {"policy": policy, "candidate": candidate},
            request_id="33000000-0000-4000-8000-000000000301",
        )
        plan = evaluation["result"]
        authorization = accept_authorization(
            authorization_core(
                subject_me_id=self.state.being_ref,
                policy_id=policy["policy_id"],
                policy_hash=hashlib.sha256(canonical_bytes(policy)).hexdigest(),
                reviewer=reviewer,
                group_id=group_id,
                member_key_ids=[reviewer["key_id"]],
                threshold=1,
                categories=["personal-insight"],
                classifications=["protected"],
                actions=["accept"],
                valid_from_ms=self.now,
                expires_at_ms=self.now + 60_000,
                max_outstanding_decisions=1,
                control_position={
                    "manifest_hash": (
                        self.runtime.service.ledger.authority.manifest.digest
                    ),
                    "embodiment_id": self.origins["legion"]["embodiment_id"],
                    "incarnation_id": self.origins["legion"]["incarnation_id"],
                },
                issued_at_ms=self.now,
            ),
            reviewer_seed,
        )
        self.client.review_authorize(
            authorization,
            request_id="33000000-0000-4000-8000-000000000302",
        )
        review_request = create_review_request(
            policy=policy,
            candidate=candidate,
            plan=plan,
            proposal=None,
            authorization_ids=[authorization["authorization_id"]],
            group_id=group_id,
            threshold=1,
            requested_at_ms=self.now,
            expires_at_ms=self.now + 60_000,
        )
        self.client.review_request(
            review_request,
            request_id="33000000-0000-4000-8000-000000000303",
        )
        _, drafted = self.client.review_decision_draft(
            {
                "review_request_id": review_request["review_request_id"],
                "authorization_id": authorization["authorization_id"],
                "action": "accept",
                "replacement": None,
                "reason": "evidence-sufficient",
                "note_ref": None,
                "decision_nonce": "33000000-0000-4000-8000-000000000242",
                "decided_at_ms": self.now,
                "predecessor_decision_id": None,
            },
            request_id="33000000-0000-4000-8000-000000000304",
        )
        decision = sign_review_decision(drafted["result"], reviewer_seed)
        submit = self.client.prepare(
            "review.decision.submit",
            {"decision": decision},
            request_id="33000000-0000-4000-8000-000000000305",
        )
        self.drop_response.set()
        with self.assertRaisesRegex(ClientError, "daemon_response_truncated"):
            self.client.send(submit)
        self._restart()
        submitted = self.client.send(submit)
        self.assertTrue(submitted["ok"], submitted)

        execute = self.client.prepare(
            "review.execute",
            {"review_request_id": review_request["review_request_id"]},
            request_id="33000000-0000-4000-8000-000000000306",
        )
        self.drop_response.set()
        with self.assertRaisesRegex(ClientError, "daemon_response_truncated"):
            self.client.send(execute)
        self._restart()
        executed = self.client.send(execute)
        self.assertTrue(executed["ok"], executed)
        events = self.runtime.service.ledger.events()
        self.assertEqual(
            len([event for event in events if event["kind"] == "review.decided"]),
            1,
        )
        self.assertEqual(
            len([event for event in events if event["kind"] == "memory.recorded"]),
            1,
        )
        self.assertEqual(
            len([event for event in events if event["kind"] == "review.executed"]),
            1,
        )

    def test_installed_mcp_request_read_draft_and_disclosure_refusal(self) -> None:
        reviewer_seed = hashlib.sha256(b"dm033-mcp-reviewer").digest()
        reviewer = signing_descriptor(reviewer_seed)
        group_id = _group_id([reviewer["key_id"]], 1)
        policy = create_memory_policy(
            subject_me_id=self.state.being_ref,
            version=1,
            predecessor_policy_id=None,
            automatic_categories=["personal-insight"],
            review_classifications=["protected"],
            plan_ttl_ms=60_000,
        )
        candidate = create_memory_candidate(
            subject_me_id=self.state.being_ref,
            author_me_id=self.state.being_ref,
            category="personal-insight",
            derivation="local-synthesis",
            context="dm033-mcp",
            content_ref=create_content_ref(
                sha256=hashlib.sha256(b"dm033 mcp reviewed memory").hexdigest(),
                byte_length=25,
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
                "memory_id": "33000000-0000-4000-8000-000000000334",
                "operation": "assert",
                "sequence": 1,
                "predecessor_event_id": None,
                "predecessor_hash": None,
            },
            body_evidence=None,
        )
        _, evaluation = self.observe_client.memory_evaluate(
            {"policy": policy, "candidate": candidate},
            request_id="33000000-0000-4000-8000-000000000501",
        )
        plan = evaluation["result"]
        authorization = accept_authorization(
            authorization_core(
                subject_me_id=self.state.being_ref,
                policy_id=policy["policy_id"],
                policy_hash=hashlib.sha256(canonical_bytes(policy)).hexdigest(),
                reviewer=reviewer,
                group_id=group_id,
                member_key_ids=[reviewer["key_id"]],
                threshold=1,
                categories=["personal-insight"],
                classifications=["protected"],
                actions=["accept", "defer", "edit", "reject"],
                valid_from_ms=self.now,
                expires_at_ms=self.now + 60_000,
                max_outstanding_decisions=4,
                control_position={
                    "manifest_hash": (
                        self.runtime.service.ledger.authority.manifest.digest
                    ),
                    "embodiment_id": self.origins["legion"]["embodiment_id"],
                    "incarnation_id": self.origins["legion"]["incarnation_id"],
                },
                issued_at_ms=self.now,
            ),
            reviewer_seed,
        )
        self.client.review_authorize(
            authorization,
            request_id="33000000-0000-4000-8000-000000000502",
        )
        request = create_review_request(
            policy=policy,
            candidate=candidate,
            plan=plan,
            proposal=None,
            authorization_ids=[authorization["authorization_id"]],
            group_id=group_id,
            threshold=1,
            requested_at_ms=self.now,
            expires_at_ms=self.now + 60_000,
        )
        requested = self._mcp_call(
            "mcp-request",
            "review_request",
            {
                "operation_id": "33000000-0000-4000-8000-000000000503",
                "request": request,
            },
        )
        self.assertTrue(requested["result"]["structuredContent"]["ok"])
        queue_operation = "33000000-0000-4000-8000-000000000504"
        queue_proof = create_access_proof(
            authorization_id=authorization["authorization_id"],
            rpc_request_id=queue_operation,
            issued_at_ms=self.now,
            expires_at_ms=self.now + 1_000,
            reviewer_seed=reviewer_seed,
        )
        queued = self._mcp_call(
            "mcp-queue",
            "review_queue",
            {
                "operation_id": queue_operation,
                "authorization_id": authorization["authorization_id"],
                "access_proof": queue_proof,
                "after": None,
                "limit": 10,
            },
        )["result"]["structuredContent"]
        self.assertTrue(queued["ok"])
        self.assertEqual(
            queued["result"]["items"][0]["review_request_id"],
            request["review_request_id"],
        )
        inspect_operation = "33000000-0000-4000-8000-000000000505"
        inspect_proof = create_access_proof(
            authorization_id=authorization["authorization_id"],
            rpc_request_id=inspect_operation,
            issued_at_ms=self.now,
            expires_at_ms=self.now + 1_000,
            reviewer_seed=reviewer_seed,
        )
        inspected = self._mcp_call(
            "mcp-inspect",
            "review_inspect",
            {
                "operation_id": inspect_operation,
                "review_request_id": request["review_request_id"],
                "authorization_id": authorization["authorization_id"],
                "access_proof": inspect_proof,
            },
        )["result"]["structuredContent"]
        self.assertTrue(inspected["ok"])
        self.assertEqual(inspected["result"]["request"], request)
        refused = self._mcp_call(
            "mcp-refused",
            "review_inspect",
            {
                "operation_id": "33000000-0000-4000-8000-000000000506",
                "review_request_id": request["review_request_id"],
                "authorization_id": authorization["authorization_id"],
                "access_proof": inspect_proof,
            },
        )["result"]["structuredContent"]
        self.assertFalse(refused["ok"])
        self.assertEqual(refused["error"]["code"], "invalid_review_access_proof")
        drafted = self._mcp_call(
            "mcp-draft",
            "review_decision_draft",
            {
                "review_request_id": request["review_request_id"],
                "authorization_id": authorization["authorization_id"],
                "action": "defer",
                "replacement": None,
                "reason": "reconsideration-needed",
                "note_ref": None,
                "decision_nonce": "33000000-0000-4000-8000-000000000243",
                "decided_at_ms": self.now,
                "predecessor_decision_id": None,
            },
        )["result"]["structuredContent"]
        self.assertTrue(drafted["ok"])
        self.assertNotIn("signature", drafted["result"])
        self.assertFalse(
            any(
                event["kind"] == "review.decided"
                for event in self.runtime.service.ledger.events()
            )
        )
