from __future__ import annotations

import copy
import hashlib
import json
import unittest
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, cast

from jsonschema import (  # type: ignore[import-untyped]
    Draft202012Validator,
    FormatChecker,
    ValidationError,
)

from daimon_matrix.canonical import canonical_bytes
from daimon_matrix.cluster import (
    BODY_SNAPSHOT_SCHEMA,
    EFFECT_RECONCILIATION_SCHEMA,
    FENCE_VERIFICATION_SCHEMA,
    ClusterEvidenceError,
    FenceVerificationUnavailable,
    FenceVerifier,
    create_effect_receipt,
    create_resource_fence_evidence,
    projection_receipt_payload,
    reconcile_effect_receipt,
    resource_fence_position,
    validate_body_snapshot,
    validate_effect_receipt,
    validate_resource_fence_evidence,
    verify_resource_fence_evidence,
)
from daimon_matrix.weave import WeaveProtocolError
from tests.test_dm022_ledger import NOW, RootLedgerFixture

ROOT = Path(__file__).resolve().parents[1]
BODY = "cluster:body-legion"
EMBODIMENT = "embodiment:legion"
INCARNATION = "incarnation:legion-1"
RESOURCE = "wiki:page:home"
EFFECT_ID = "37000000-0000-4000-8000-000000000001"
TARGET_ID = "37000000-0000-4000-8000-000000000002"
DECISION_ID = "37000000-0000-4000-8000-000000000003"


def intent_hash(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def verification(
    evidence: Mapping[str, Any], at_ms: int, *, current: bool = True
) -> dict[str, Any]:
    return {
        "schema": FENCE_VERIFICATION_SCHEMA,
        "content_hash": evidence["content_hash"],
        "resource_ref": evidence["resource_ref"],
        "holder_embodiment_id": evidence["holder_embodiment_id"],
        "epoch": evidence["epoch"],
        "verified_at_ms": at_ms,
        "current": current,
    }


class ClusterEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.intent = {"operation": "replace", "resource_ref": RESOURCE, "value": 2}
        self.postcondition = {"generation": 2, "state": "present"}
        self.fence = create_resource_fence_evidence(
            body_ref=BODY,
            holder_embodiment_id=EMBODIMENT,
            holder_incarnation_id=INCARNATION,
            resource_ref=RESOURCE,
            epoch=7,
            observed_at_ms=NOW - 100,
            expires_at_ms=NOW + 1_000,
            verification_ref="cluster-proof:fence-7",
        )
        self.receipt = create_effect_receipt(
            effect_id=EFFECT_ID,
            target_event_id=TARGET_ID,
            decision_event_id=DECISION_ID,
            adapter="synthetic-wiki/v1",
            preview_hash="a" * 64,
            intent_hash=intent_hash(self.intent),
            actor="compaii@legion",
            authority="daimon",
            resource_fence=resource_fence_position(self.fence),
            result="applied",
            observed_postcondition=self.postcondition,
            started_at_ms=NOW - 50,
            completed_at_ms=NOW - 40,
        )

    def test_body_snapshot_is_public_exact_closed_sorted_and_time_bound(self) -> None:
        snapshot: dict[str, Any] = {
            "schema": BODY_SNAPSHOT_SCHEMA,
            "body_ref": BODY,
            "embodiment_id": EMBODIMENT,
            "incarnation_id": INCARNATION,
            "observed_at_ms": NOW,
            "state": "running",
            "resource_fences": [
                {"resource_ref": "resource:a", "epoch": 1},
                {"resource_ref": "resource:b", "epoch": 2},
            ],
        }
        self.assertEqual(
            validate_body_snapshot(
                snapshot,
                body_ref=BODY,
                embodiment_id=EMBODIMENT,
                incarnation_id=INCARNATION,
                evaluated_at_ms=NOW,
            ),
            snapshot,
        )
        mutations = []
        for field, value in (
            ("body_ref", "cluster:other"),
            ("embodiment_id", "embodiment:other"),
            ("incarnation_id", "incarnation:other"),
            ("observed_at_ms", NOW + 1),
        ):
            changed = copy.deepcopy(snapshot)
            changed[field] = value
            mutations.append(changed)
        changed = copy.deepcopy(snapshot)
        changed["resource_fences"].reverse()
        mutations.append(changed)
        changed = copy.deepcopy(snapshot)
        changed["resource_fences"].append(copy.deepcopy(changed["resource_fences"][0]))
        mutations.append(changed)
        mutations.append({**snapshot, "endpoint": "https://private.invalid"})
        for changed in mutations:
            with (
                self.subTest(changed=changed),
                self.assertRaisesRegex(ClusterEvidenceError, "body_snapshot_rejected"),
            ):
                validate_body_snapshot(
                    changed,
                    body_ref=BODY,
                    embodiment_id=EMBODIMENT,
                    incarnation_id=INCARNATION,
                    evaluated_at_ms=NOW,
                )

    def test_fence_is_content_bound_and_requires_current_injected_verification(
        self,
    ) -> None:
        checked = verify_resource_fence_evidence(
            self.fence,
            at_ms=NOW,
            verifier=verification,
            body_ref=BODY,
            holder_embodiment_id=EMBODIMENT,
            holder_incarnation_id=INCARNATION,
            resource_ref=RESOURCE,
        )
        self.assertEqual(checked, self.fence)
        for field, value, code in (
            ("epoch", 6, "fence_evidence_hash_mismatch"),
            (
                "holder_embodiment_id",
                "embodiment:other",
                "fence_evidence_hash_mismatch",
            ),
            ("resource_ref", "wiki:page:other", "fence_evidence_hash_mismatch"),
            ("verification_ref", "cluster-proof:other", "fence_evidence_hash_mismatch"),
        ):
            changed = {**self.fence, field: value}
            with (
                self.subTest(field=field),
                self.assertRaisesRegex(ClusterEvidenceError, code),
            ):
                validate_resource_fence_evidence(changed)

    def test_expiry_rollback_and_verifier_outage_are_not_current_truth(self) -> None:
        with self.assertRaisesRegex(ClusterEvidenceError, "fence_not_current"):
            verify_resource_fence_evidence(
                self.fence, at_ms=NOW + 1_001, verifier=verification
            )
        with self.assertRaisesRegex(ClusterEvidenceError, "fence_not_current"):
            verify_resource_fence_evidence(
                self.fence,
                at_ms=NOW,
                verifier=lambda evidence, at: verification(evidence, at, current=False),
            )

        def unavailable(_evidence: Mapping[str, Any], _at_ms: int) -> Mapping[str, Any]:
            raise FenceVerificationUnavailable

        with self.assertRaises(FenceVerificationUnavailable):
            verify_resource_fence_evidence(
                self.fence,
                at_ms=NOW,
                verifier=cast(FenceVerifier, unavailable),
            )

        def unsigned(_evidence: Mapping[str, Any], _at_ms: int) -> Mapping[str, Any]:
            raise ValueError("unsigned")

        with self.assertRaisesRegex(
            ClusterEvidenceError, "fence_verification_rejected"
        ):
            verify_resource_fence_evidence(
                self.fence,
                at_ms=NOW,
                verifier=cast(FenceVerifier, unsigned),
            )

    def test_receipt_is_closed_content_bound_and_projection_exact(self) -> None:
        self.assertEqual(validate_effect_receipt(self.receipt), self.receipt)
        duplicate = create_effect_receipt(
            effect_id=EFFECT_ID,
            target_event_id=TARGET_ID,
            decision_event_id=DECISION_ID,
            adapter="synthetic-wiki/v1",
            preview_hash="a" * 64,
            intent_hash=intent_hash(self.intent),
            actor="compaii@legion",
            authority="daimon",
            resource_fence=resource_fence_position(self.fence),
            result="applied",
            observed_postcondition=self.postcondition,
            started_at_ms=NOW - 50,
            completed_at_ms=NOW - 40,
        )
        self.assertEqual(canonical_bytes(duplicate), canonical_bytes(self.receipt))
        payload = projection_receipt_payload(self.receipt)
        self.assertNotIn("effect_id", payload)
        self.assertNotIn("content_hash", payload)
        self.assertEqual(payload["resource_fence"], resource_fence_position(self.fence))
        for field, value in (
            ("intent_hash", "b" * 64),
            ("result", "failed"),
            ("actor", "other@host"),
        ):
            with (
                self.subTest(field=field),
                self.assertRaisesRegex(
                    ClusterEvidenceError, "effect_receipt_hash_mismatch"
                ),
            ):
                validate_effect_receipt({**self.receipt, field: value})

    def test_replay_only_succeeds_while_effect_truth_matches(self) -> None:
        exact = reconcile_effect_receipt(
            self.receipt,
            intent=self.intent,
            observed_postcondition=self.postcondition,
            at_ms=NOW,
            current_fence_evidence=self.fence,
            fence_verifier=verification,
        )
        self.assertEqual(exact["schema"], EFFECT_RECONCILIATION_SCHEMA)
        self.assertEqual(exact["status"], "verified")
        cases = (
            (
                {**self.intent, "value": 3},
                self.postcondition,
                self.fence,
                verification,
                "effect-truth-discrepancy",
                "intent-mismatch",
            ),
            (
                self.intent,
                {"generation": 3, "state": "present"},
                self.fence,
                verification,
                "effect-truth-discrepancy",
                "postcondition-mismatch",
            ),
            (
                self.intent,
                None,
                self.fence,
                verification,
                "effect-truth-unverifiable",
                "postcondition-unavailable",
            ),
            (
                self.intent,
                self.postcondition,
                None,
                None,
                "effect-truth-unverifiable",
                "fence-observation-unavailable",
            ),
        )
        for intent, postcondition, fence, verifier, status, reason in cases:
            with self.subTest(reason=reason):
                result = reconcile_effect_receipt(
                    self.receipt,
                    intent=intent,
                    observed_postcondition=postcondition,
                    at_ms=NOW,
                    current_fence_evidence=fence,
                    fence_verifier=verifier,
                )
                self.assertEqual((result["status"], result["reason"]), (status, reason))

        def unavailable(_evidence: Mapping[str, Any], _at_ms: int) -> Mapping[str, Any]:
            raise FenceVerificationUnavailable

        outage = reconcile_effect_receipt(
            self.receipt,
            intent=self.intent,
            observed_postcondition=self.postcondition,
            at_ms=NOW,
            current_fence_evidence=self.fence,
            fence_verifier=cast(FenceVerifier, unavailable),
        )
        self.assertEqual(
            (outage["status"], outage["reason"]),
            ("effect-truth-unverifiable", "fence-verifier-unavailable"),
        )

    def test_different_resources_are_independent_and_stale_same_resource_fails(
        self,
    ) -> None:
        other_fence = create_resource_fence_evidence(
            body_ref="cluster:body-other",
            holder_embodiment_id="embodiment:other",
            holder_incarnation_id="incarnation:other-1",
            resource_ref="wiki:page:other",
            epoch=1,
            observed_at_ms=NOW - 100,
            expires_at_ms=NOW + 1_000,
            verification_ref="cluster-proof:other-1",
        )
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(
                pool.map(
                    lambda evidence: verify_resource_fence_evidence(
                        evidence, at_ms=NOW, verifier=verification
                    ),
                    (self.fence, other_fence),
                )
            )
        self.assertEqual(
            {item["resource_ref"] for item in results},
            {RESOURCE, "wiki:page:other"},
        )
        newer = create_resource_fence_evidence(
            body_ref=BODY,
            holder_embodiment_id=EMBODIMENT,
            holder_incarnation_id=INCARNATION,
            resource_ref=RESOURCE,
            epoch=8,
            observed_at_ms=NOW - 10,
            expires_at_ms=NOW + 1_000,
            verification_ref="cluster-proof:fence-8",
        )
        stale = reconcile_effect_receipt(
            self.receipt,
            intent=self.intent,
            observed_postcondition=self.postcondition,
            at_ms=NOW,
            current_fence_evidence=newer,
            fence_verifier=verification,
        )
        self.assertEqual(stale["status"], "effect-truth-discrepancy")
        self.assertEqual(stale["reason"], "fence-epoch-mismatch")

        other_holder = create_resource_fence_evidence(
            body_ref="cluster:body-other",
            holder_embodiment_id="embodiment:other",
            holder_incarnation_id="incarnation:other-2",
            resource_ref=RESOURCE,
            epoch=9,
            observed_at_ms=NOW - 10,
            expires_at_ms=NOW + 1_000,
            verification_ref="cluster-proof:other-holder",
        )
        substituted = reconcile_effect_receipt(
            self.receipt,
            intent=self.intent,
            observed_postcondition=self.postcondition,
            at_ms=NOW,
            current_fence_evidence=other_holder,
            fence_verifier=verification,
        )
        self.assertEqual(
            (substituted["status"], substituted["reason"]),
            ("effect-truth-discrepancy", "fence_binding_mismatch"),
        )

    def test_postcondition_rejects_secrets_private_paths_and_endpoints(self) -> None:
        for postcondition in (
            {"api_token": "hidden"},
            {"state_path": "relative"},
            {"state": "/srv/private"},
            {"state": "https://private.invalid"},
            {"state": "-----BEGIN " + "PRIVATE KEY-----"},
        ):
            with (
                self.subTest(postcondition=postcondition),
                self.assertRaises(ClusterEvidenceError),
            ):
                create_effect_receipt(
                    effect_id=EFFECT_ID,
                    target_event_id=TARGET_ID,
                    decision_event_id=DECISION_ID,
                    adapter="synthetic-wiki/v1",
                    preview_hash="a" * 64,
                    intent_hash=intent_hash(self.intent),
                    actor="compaii@legion",
                    authority="daimon",
                    resource_fence=None,
                    result="applied",
                    observed_postcondition=postcondition,
                    started_at_ms=NOW,
                    completed_at_ms=NOW,
                )

    def test_cluster_schemas_match_runtime_and_are_closed(self) -> None:
        values = {
            "body-snapshot.schema.json": {
                "schema": BODY_SNAPSHOT_SCHEMA,
                "body_ref": BODY,
                "embodiment_id": EMBODIMENT,
                "incarnation_id": INCARNATION,
                "observed_at_ms": NOW,
                "state": "running",
                "resource_fences": [],
            },
            "resource-fence-evidence.schema.json": self.fence,
            "resource-fence-verification.schema.json": verification(self.fence, NOW),
            "effect-receipt.schema.json": self.receipt,
            "effect-reconciliation.schema.json": reconcile_effect_receipt(
                self.receipt,
                intent=self.intent,
                observed_postcondition=self.postcondition,
                at_ms=NOW,
                current_fence_evidence=self.fence,
                fence_verifier=verification,
            ),
        }
        for name, value in values.items():
            with self.subTest(name=name):
                schema = json.loads((ROOT / "schemas/cluster/v1" / name).read_bytes())
                Draft202012Validator.check_schema(schema)
                validator = Draft202012Validator(schema, format_checker=FormatChecker())
                validator.validate(value)
                with self.assertRaises(ValidationError):
                    validator.validate({**value, "unknown": True})
                if name == "effect-receipt.schema.json":
                    disclosed = copy.deepcopy(value)
                    disclosed["observed_postcondition"] = {
                        "endpoint": "https://private.invalid"
                    }
                    with self.assertRaises(ValidationError):
                        validator.validate(disclosed)


class ProjectionFenceContractTests(RootLedgerFixture):
    def test_projection_event_accepts_only_exact_fence_position(self) -> None:
        target = self.append(self.ledger_a, "legion", "dm037-target")
        decision = self.ledger_a.append_local(
            kind="adoption.decided",
            subject=target["subject"],
            payload={
                "target_event_id": target["event_id"],
                "decision": "adopt",
                "reason": "synthetic approval",
            },
            signer=self.signers["legion"],
            causal_parents=[target["event_id"]],
            occurred_at_ms=NOW + 1,
        )
        intent = {"operation": "replace", "resource_ref": RESOURCE}
        fence = create_resource_fence_evidence(
            body_ref=self.origins["legion"]["body_ref"],
            holder_embodiment_id=self.origins["legion"]["embodiment_id"],
            holder_incarnation_id=self.origins["legion"]["incarnation_id"],
            resource_ref=RESOURCE,
            epoch=2,
            observed_at_ms=NOW,
            expires_at_ms=NOW + 1_000,
            verification_ref="cluster-proof:projection",
        )
        effect = create_effect_receipt(
            effect_id=EFFECT_ID,
            target_event_id=target["event_id"],
            decision_event_id=decision["event_id"],
            adapter="synthetic-wiki/v1",
            preview_hash="a" * 64,
            intent_hash=intent_hash(intent),
            actor="compaii@legion",
            authority="daimon",
            resource_fence=resource_fence_position(fence),
            result="applied",
            observed_postcondition={"generation": 2},
            started_at_ms=NOW + 2,
            completed_at_ms=NOW + 3,
        )
        event = self.ledger_a.append_local(
            kind="projection.receipted",
            subject=target["subject"],
            payload=projection_receipt_payload(effect),
            signer=self.signers["legion"],
            causal_parents=[target["event_id"], decision["event_id"]],
            occurred_at_ms=NOW + 3,
        )
        schema = json.loads((ROOT / "schemas/weave/v1/event.schema.json").read_bytes())
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(event)

        arbitrary = copy.deepcopy(projection_receipt_payload(effect))
        arbitrary["resource_fence"] = {"resource_ref": RESOURCE, "epoch": 2}
        with self.assertRaisesRegex(WeaveProtocolError, "invalid_projection_receipt"):
            self.ledger_a.append_local(
                kind="projection.receipted",
                subject=target["subject"],
                payload=arbitrary,
                signer=self.signers["legion"],
                causal_parents=[target["event_id"], decision["event_id"]],
                occurred_at_ms=NOW + 4,
            )

        wrong_holder = copy.deepcopy(projection_receipt_payload(effect))
        wrong_holder["resource_fence"]["holder_embodiment_id"] = "embodiment:other"
        with self.assertRaisesRegex(WeaveProtocolError, "invalid_projection_receipt"):
            self.ledger_a.append_local(
                kind="projection.receipted",
                subject=target["subject"],
                payload=wrong_holder,
                signer=self.signers["legion"],
                causal_parents=[target["event_id"], decision["event_id"]],
                occurred_at_ms=NOW + 4,
            )


if __name__ == "__main__":
    unittest.main()
