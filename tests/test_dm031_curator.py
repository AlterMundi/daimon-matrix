from __future__ import annotations

import copy
import hashlib
import json
import os
import subprocess
import sys
import threading
import time
import uuid
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, cast

from jsonschema import (  # type: ignore[import-untyped]
    Draft202012Validator,
    FormatChecker,
)
from referencing import Registry, Resource

from daimon_matrix.canonical import canonical_bytes
from daimon_matrix.client import CLIENT_CONFIG_SCHEMA_V3
from daimon_matrix.cluster import (
    FENCE_VERIFICATION_SCHEMA,
    create_effect_receipt,
    create_resource_fence_evidence,
    resource_fence_position,
)
from daimon_matrix.curator import (
    CuratorCoordinator,
    CuratorError,
    EffectTruthObserver,
    create_curator_item,
    create_curator_result,
    validate_curator_claim,
    validate_curator_item,
    validate_curator_result,
)
from daimon_matrix.daemon import serve_forever
from daimon_matrix.local_api import create_capability, create_request
from daimon_matrix.runtime import load_runtime
from daimon_matrix.service import CURATOR_METHODS, HostedWeave
from tests.test_dm022_ledger import NOW, RootLedgerFixture, seed
from tests.test_dm024_runtime import PASSWORD, RuntimeFixture
from tools.generate_dm031_vectors import generate as generate_vectors

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_ROOT = ROOT / "schemas"
VECTOR_ROOT = ROOT / "vectors/curator/v1"


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


class CuratorCoordinatorTests(RootLedgerFixture):
    def setUp(self) -> None:
        super().setUp()
        self.now = [NOW]
        self.coordinator = CuratorCoordinator(self.ledger_a, clock=lambda: self.now[0])

    def item(
        self,
        suffix: str = "one",
        *,
        resource_ref: str | None = None,
        coordination_mode: str = "queue-item",
        required_authority: str = "daimon",
        intent: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        selected_intent = intent or {"operation": "replace", "value": suffix}
        return create_curator_item(
            subject_me_id=self.state.being_ref,
            resource_ref=resource_ref or f"memory:item:{suffix}",
            work_kind="memory-proposal",
            input_ref=f"candidate:{suffix}",
            input_hash=digest({"candidate": suffix}),
            coordination_mode=coordination_mode,
            required_authority=required_authority,
            effect_intent_hash=(
                digest(selected_intent)
                if coordination_mode == "resource-fence"
                else None
            ),
            queued_at_ms=self.now[0],
        )

    def enqueue(
        self, item: Mapping[str, Any], suffix: str = "enqueue"
    ) -> dict[str, Any]:
        return self.coordinator.enqueue(
            item,
            client_id="curator-test",
            request_id=str(uuid.uuid5(uuid.NAMESPACE_URL, suffix)),
        )

    def claim(
        self,
        item: Mapping[str, Any],
        suffix: str = "claim",
        *,
        claim_id: str | None = None,
        expected_generation: int = 0,
        fence_evidence: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        return self.coordinator.claim(
            item_id=str(item["item_id"]),
            claim_id=claim_id or str(uuid.uuid5(uuid.NAMESPACE_URL, suffix + ":id")),
            expected_generation=expected_generation,
            lease_until_ms=self.now[0] + 500,
            fence_evidence=fence_evidence,
            client_id="curator-test",
            request_id=str(uuid.uuid5(uuid.NAMESPACE_URL, suffix + ":request")),
        )

    def test_item_is_closed_content_addressed_and_environment_independent(self) -> None:
        first = self.item()
        reordered = {key: copy.deepcopy(first[key]) for key in reversed(first)}
        self.assertEqual(validate_curator_item(reordered), first)
        self.assertEqual(canonical_bytes(reordered), canonical_bytes(first))
        with self.assertRaisesRegex(CuratorError, "invalid_curator_item"):
            validate_curator_item({**first, "global_being_lease": "forbidden"})
        with self.assertRaisesRegex(CuratorError, "curator_item_id_mismatch"):
            validate_curator_item({**first, "resource_ref": "memory:item:other"})
        with self.assertRaisesRegex(CuratorError, "invalid_curator_item"):
            create_curator_item(
                subject_me_id=self.state.being_ref,
                resource_ref="memory:item:no-locator",
                work_kind="memory-proposal",
                input_ref="https://private.invalid/item",
                input_hash="a" * 64,
                coordination_mode="queue-item",
                required_authority="daimon",
                effect_intent_hash=None,
                queued_at_ms=NOW,
            )

    def test_different_resources_claim_concurrently_without_global_exclusion(
        self,
    ) -> None:
        items = [self.item("a"), self.item("b")]
        for index, item in enumerate(items):
            self.enqueue(item, f"enqueue-{index}")
        with ThreadPoolExecutor(max_workers=2) as pool:
            claims = list(
                pool.map(
                    lambda pair: self.claim(pair[1], f"claim-{pair[0]}"),
                    enumerate(items),
                )
            )
        self.assertEqual(
            {claim["resource_ref"] for claim in claims},
            {"memory:item:a", "memory:item:b"},
        )
        self.assertEqual(
            {claim["actor_origin"]["embodiment_id"] for claim in claims},
            {self.origins["legion"]["embodiment_id"]},
        )

    def test_plural_embodiments_work_independently_and_cluster_selects_holder(
        self,
    ) -> None:
        coordinator_b = CuratorCoordinator(self.ledger_b, clock=lambda: self.now[0])
        item_a = self.item("plural-a")
        item_b = self.item("plural-b")

        def work(
            coordinator: CuratorCoordinator,
            item: Mapping[str, Any],
            suffix: str,
        ) -> dict[str, Any]:
            coordinator.enqueue(
                item,
                client_id=f"client:{suffix}",
                request_id=str(uuid.uuid5(uuid.NAMESPACE_URL, suffix + ":enqueue")),
            )
            return coordinator.claim(
                item_id=str(item["item_id"]),
                claim_id=str(uuid.uuid5(uuid.NAMESPACE_URL, suffix + ":claim-id")),
                expected_generation=0,
                lease_until_ms=NOW + 500,
                fence_evidence=None,
                client_id=f"client:{suffix}",
                request_id=str(uuid.uuid5(uuid.NAMESPACE_URL, suffix + ":claim")),
            )

        with ThreadPoolExecutor(max_workers=2) as pool:
            claims = list(
                pool.map(
                    lambda row: work(*row),
                    (
                        (self.coordinator, item_a, "legion"),
                        (coordinator_b, item_b, "daimonmatrix"),
                    ),
                )
            )
        self.assertEqual(
            {claim["actor_origin"]["embodiment_id"] for claim in claims},
            {
                self.origins["legion"]["embodiment_id"],
                self.origins["daimonmatrix"]["embodiment_id"],
            },
        )

        intent = {"operation": "publish", "value": "plural"}
        resource_item = self.item(
            "plural-resource",
            resource_ref="wiki:page:plural",
            coordination_mode="resource-fence",
            intent=intent,
        )

        def fence_for(label: str) -> dict[str, Any]:
            origin = self.origins[label]
            return create_resource_fence_evidence(
                body_ref=origin["body_ref"],
                holder_embodiment_id=origin["embodiment_id"],
                holder_incarnation_id=origin["incarnation_id"],
                resource_ref=resource_item["resource_ref"],
                epoch=7,
                observed_at_ms=NOW - 100,
                expires_at_ms=NOW + 1_000,
                verification_ref=f"cluster-proof:{label}-7",
            )

        def only_legion_current(
            evidence: Mapping[str, Any], at_ms: int
        ) -> dict[str, Any]:
            result = self._verify_fence(evidence, at_ms)
            result["current"] = (
                evidence["holder_embodiment_id"]
                == self.origins["legion"]["embodiment_id"]
            )
            return result

        fenced_a = CuratorCoordinator(
            self.ledger_a,
            clock=lambda: self.now[0],
            fence_verifier=only_legion_current,
        )
        fenced_b = CuratorCoordinator(
            self.ledger_b,
            clock=lambda: self.now[0],
            fence_verifier=only_legion_current,
        )
        for index, coordinator in enumerate((fenced_a, fenced_b)):
            coordinator.enqueue(
                resource_item,
                client_id=f"fenced:{index}",
                request_id=str(
                    uuid.uuid5(uuid.NAMESPACE_URL, f"fenced:{index}:enqueue")
                ),
            )
        accepted = fenced_a.claim(
            item_id=resource_item["item_id"],
            claim_id="31000000-0000-4000-8000-000000000070",
            expected_generation=0,
            lease_until_ms=NOW + 500,
            fence_evidence=fence_for("legion"),
            client_id="fenced:legion",
            request_id="31000000-0000-4000-8000-000000000071",
        )
        self.assertEqual(
            accepted["actor_origin"]["embodiment_id"],
            self.origins["legion"]["embodiment_id"],
        )
        with self.assertRaisesRegex(CuratorError, "curator_fence_rejected"):
            fenced_b.claim(
                item_id=resource_item["item_id"],
                claim_id="31000000-0000-4000-8000-000000000072",
                expected_generation=0,
                lease_until_ms=NOW + 500,
                fence_evidence=fence_for("daimonmatrix"),
                client_id="fenced:daimonmatrix",
                request_id="31000000-0000-4000-8000-000000000073",
            )

    def test_same_resource_enqueue_and_claim_are_compare_and_swap(self) -> None:
        first = self.item("a", resource_ref="memory:item:shared")
        second = self.item("b", resource_ref="memory:item:shared")
        self.enqueue(first)
        with self.assertRaisesRegex(CuratorError, "curator_resource_busy"):
            self.enqueue(second, "enqueue-other")
        claim = self.claim(first)
        self.assertEqual(claim["generation"], 1)
        with self.assertRaisesRegex(CuratorError, "curator_generation_conflict"):
            self.coordinator.claim(
                item_id=first["item_id"],
                claim_id="31000000-0000-4000-8000-000000000099",
                expected_generation=0,
                lease_until_ms=NOW + 600,
                fence_evidence=None,
                client_id="competing-client",
                request_id="31000000-0000-4000-8000-000000000098",
            )

    def test_expired_claim_reclaims_with_new_generation_and_stale_worker_loses(
        self,
    ) -> None:
        item = self.item()
        self.enqueue(item)
        first = self.claim(item)
        self.now[0] += 501
        second = self.claim(
            item,
            "claim-successor",
            expected_generation=1,
        )
        self.assertEqual(second["generation"], 2)
        with self.assertRaisesRegex(CuratorError, "curator_generation_conflict"):
            self.coordinator.complete(
                claim_id=first["claim_id"],
                expected_generation=1,
                outcome="completed",
                output_refs=["proposal:stale"],
                effect_receipt=None,
                client_id="stale-worker",
                request_id="31000000-0000-4000-8000-000000000010",
            )

    def test_claim_id_cannot_be_reused_after_expiry(self) -> None:
        item = self.item()
        self.enqueue(item)
        first = self.claim(item)
        self.now[0] += 501
        with self.assertRaisesRegex(CuratorError, "curator_claim_id_conflict"):
            self.claim(
                item,
                "claim-id-reuse",
                claim_id=first["claim_id"],
                expected_generation=1,
            )

    def test_exact_retry_is_durable_but_changed_request_conflicts(self) -> None:
        item = self.item()
        request_id = "31000000-0000-4000-8000-000000000011"
        first = self.coordinator.enqueue(
            item, client_id="retry-client", request_id=request_id
        )
        restarted = CuratorCoordinator(self.ledger_a, clock=lambda: self.now[0])
        second = restarted.enqueue(
            item, client_id="retry-client", request_id=request_id
        )
        self.assertEqual(first, second)
        with self.assertRaisesRegex(CuratorError, "curator_request_conflict"):
            restarted.enqueue(
                self.item("changed"),
                client_id="retry-client",
                request_id=request_id,
            )

    def test_human_work_can_only_propose_and_retains_actor(self) -> None:
        item = self.item(required_authority="human")
        self.enqueue(item)
        claim = self.claim(item)
        with self.assertRaisesRegex(CuratorError, "human_review_not_satisfied"):
            self.coordinator.complete(
                claim_id=claim["claim_id"],
                expected_generation=1,
                outcome="completed",
                output_refs=["proposal:one"],
                effect_receipt=None,
                client_id="curator-test",
                request_id="31000000-0000-4000-8000-000000000012",
            )
        result = self.coordinator.complete(
            claim_id=claim["claim_id"],
            expected_generation=1,
            outcome="proposed",
            output_refs=["proposal:one"],
            effect_receipt=None,
            client_id="curator-test",
            request_id="31000000-0000-4000-8000-000000000013",
        )
        self.assertTrue(result["human_review_required"])
        self.assertEqual(result["actor_origin"], self.origins["legion"])
        self.assertEqual(
            self.coordinator.inspect(item["item_id"])["state"], "review-required"
        )

    def test_queue_item_completion_is_exactly_once_across_request_ids(self) -> None:
        item = self.item()
        self.enqueue(item)
        claim = self.claim(item)
        first = self.coordinator.complete(
            claim_id=claim["claim_id"],
            expected_generation=1,
            outcome="completed",
            output_refs=["proposal:one"],
            effect_receipt=None,
            client_id="worker-a",
            request_id="31000000-0000-4000-8000-000000000014",
        )
        second = self.coordinator.complete(
            claim_id=claim["claim_id"],
            expected_generation=1,
            outcome="completed",
            output_refs=["proposal:one"],
            effect_receipt=None,
            client_id="worker-b",
            request_id="31000000-0000-4000-8000-000000000015",
        )
        self.assertEqual(first, second)
        with self.assertRaisesRegex(CuratorError, "curator_request_conflict"):
            self.coordinator.complete(
                claim_id=claim["claim_id"],
                expected_generation=1,
                outcome="completed",
                output_refs=["proposal:changed-after-retry"],
                effect_receipt=None,
                client_id="worker-b",
                request_id="31000000-0000-4000-8000-000000000015",
            )
        with self.assertRaisesRegex(CuratorError, "curator_item_terminal"):
            self.coordinator.complete(
                claim_id=claim["claim_id"],
                expected_generation=1,
                outcome="completed",
                output_refs=["proposal:other"],
                effect_receipt=None,
                client_id="worker-c",
                request_id="31000000-0000-4000-8000-000000000016",
            )

    def test_result_factory_rejects_a_claim_for_another_item(self) -> None:
        first = self.item("first")
        second = self.item("second")
        self.enqueue(first, "enqueue-first")
        self.enqueue(second, "enqueue-second")
        foreign_claim = self.claim(second, "claim-second")
        with self.assertRaisesRegex(CuratorError, "curator_result_claim_mismatch"):
            create_curator_result(
                item=first,
                claim=foreign_claim,
                outcome="completed",
                output_refs=["proposal:wrong-item"],
                effect_receipt=None,
                completed_at_ms=NOW,
            )

    def _fence(self, resource_ref: str) -> dict[str, Any]:
        origin = self.origins["legion"]
        return create_resource_fence_evidence(
            body_ref=origin["body_ref"],
            holder_embodiment_id=origin["embodiment_id"],
            holder_incarnation_id=origin["incarnation_id"],
            resource_ref=resource_ref,
            epoch=7,
            observed_at_ms=self.now[0] - 100,
            expires_at_ms=self.now[0] + 1_000,
            verification_ref="cluster-proof:curator-7",
        )

    @staticmethod
    def _verify_fence(evidence: Mapping[str, Any], at_ms: int) -> dict[str, Any]:
        return {
            "schema": FENCE_VERIFICATION_SCHEMA,
            "content_hash": evidence["content_hash"],
            "resource_ref": evidence["resource_ref"],
            "holder_embodiment_id": evidence["holder_embodiment_id"],
            "epoch": evidence["epoch"],
            "verified_at_ms": at_ms,
            "current": True,
        }

    def test_resource_effect_requires_current_exact_cluster_fence(self) -> None:
        intent = {"operation": "publish", "value": "synthetic"}
        item = self.item(
            coordination_mode="resource-fence",
            resource_ref="wiki:page:home",
            intent=intent,
        )
        self.enqueue(item)
        with self.assertRaisesRegex(CuratorError, "curator_fence_unverifiable"):
            self.claim(item)
        fence = self._fence(item["resource_ref"])
        self.coordinator = CuratorCoordinator(
            self.ledger_a,
            clock=lambda: self.now[0],
            fence_verifier=self._verify_fence,
        )
        claim = self.claim(item, fence_evidence=fence)
        self.assertEqual(claim["resource_fence"], resource_fence_position(fence))
        wrong = self._fence("wiki:page:other")
        other = self.item(
            "other",
            coordination_mode="resource-fence",
            resource_ref="wiki:page:home-other",
            intent=intent,
        )
        self.enqueue(other, "enqueue-resource-other")
        with self.assertRaisesRegex(CuratorError, "curator_fence_rejected"):
            self.claim(other, "claim-resource-other", fence_evidence=wrong)

    def test_effect_truth_is_verified_on_commit_and_every_replay(self) -> None:
        intent = {"operation": "publish", "value": "synthetic"}
        postcondition: dict[str, Any] = {"generation": 7, "state": "present"}
        resource_ref = "wiki:page:home"
        item = self.item(
            coordination_mode="resource-fence",
            resource_ref=resource_ref,
            intent=intent,
        )
        fence = self._fence(resource_ref)

        def observer(
            _item: Mapping[str, Any], _receipt: Mapping[str, Any], _at_ms: int
        ) -> dict[str, Any]:
            return {
                "intent": copy.deepcopy(intent),
                "observed_postcondition": copy.deepcopy(postcondition),
                "current_fence_evidence": copy.deepcopy(fence),
            }

        self.coordinator = CuratorCoordinator(
            self.ledger_a,
            clock=lambda: self.now[0],
            fence_verifier=self._verify_fence,
            effect_observer=cast(EffectTruthObserver, observer),
        )
        self.enqueue(item)
        claim = self.claim(item, fence_evidence=fence)
        receipt = create_effect_receipt(
            effect_id="31000000-0000-4000-8000-000000000020",
            target_event_id="31000000-0000-4000-8000-000000000021",
            decision_event_id="31000000-0000-4000-8000-000000000022",
            adapter="synthetic-wiki/v1",
            preview_hash="a" * 64,
            intent_hash=digest(intent),
            actor=self.origins["legion"]["principal_id"],
            authority="daimon",
            resource_fence=resource_fence_position(fence),
            result="applied",
            observed_postcondition=postcondition,
            started_at_ms=NOW - 10,
            completed_at_ms=NOW,
        )
        result = self.coordinator.complete(
            claim_id=claim["claim_id"],
            expected_generation=1,
            outcome="completed",
            output_refs=["publication:synthetic"],
            effect_receipt=receipt,
            client_id="effect-worker",
            request_id="31000000-0000-4000-8000-000000000023",
        )
        self.assertEqual(
            self.coordinator.verify_result_truth(result)["status"], "verified"
        )
        postcondition["generation"] = 8
        with self.assertRaisesRegex(CuratorError, "effect-truth-discrepancy"):
            self.coordinator.verify_result_truth(result)

    def test_authenticated_rpc_cache_rechecks_effect_truth_before_success(self) -> None:
        intent = {"operation": "publish", "value": "rpc-cache"}
        postcondition: dict[str, Any] = {"generation": 7, "state": "present"}
        resource_ref = "wiki:page:rpc-cache"
        item = self.item(
            "rpc-cache",
            coordination_mode="resource-fence",
            resource_ref=resource_ref,
            intent=intent,
        )
        fence = self._fence(resource_ref)

        def observer(
            _item: Mapping[str, Any], _receipt: Mapping[str, Any], _at_ms: int
        ) -> dict[str, Any]:
            return {
                "intent": copy.deepcopy(intent),
                "observed_postcondition": copy.deepcopy(postcondition),
                "current_fence_evidence": copy.deepcopy(fence),
            }

        coordinator = CuratorCoordinator(
            self.ledger_a,
            clock=lambda: self.now[0],
            fence_verifier=self._verify_fence,
            effect_observer=cast(EffectTruthObserver, observer),
        )
        capability = create_capability(
            seed("dm031-capability"),
            client_id="client:dm031-rpc",
            methods=sorted(CURATOR_METHODS),
            not_before_ms=NOW - 1_000,
            not_after_ms=NOW + 10_000,
        )
        service = HostedWeave(
            self.ledger_a,
            self.signers["legion"],
            {capability.capability_id: capability},
            lambda: self.now[0],
            curator=coordinator,
        )

        def invoke(
            method: str, params: Mapping[str, Any], request_id: str, nonce: bytes
        ) -> tuple[dict[str, Any], dict[str, Any]]:
            request = create_request(
                capability,
                request_id=request_id,
                issued_at_ms=self.now[0],
                method=method,
                params=params,
                nonce=nonce,
            )
            return request, service.handle(request)

        _request, response = invoke(
            "curator.enqueue",
            {"item": item},
            "31000000-0000-4000-8000-000000000060",
            b"e" * 16,
        )
        self.assertTrue(response["ok"], response)
        claim_id = "31000000-0000-4000-8000-000000000061"
        _request, response = invoke(
            "curator.claim",
            {
                "item_id": item["item_id"],
                "claim_id": claim_id,
                "expected_generation": 0,
                "lease_until_ms": NOW + 500,
                "fence_evidence": fence,
            },
            "31000000-0000-4000-8000-000000000062",
            b"c" * 16,
        )
        self.assertTrue(response["ok"], response)
        receipt = create_effect_receipt(
            effect_id="31000000-0000-4000-8000-000000000063",
            target_event_id="31000000-0000-4000-8000-000000000064",
            decision_event_id="31000000-0000-4000-8000-000000000065",
            adapter="synthetic-wiki/v1",
            preview_hash="a" * 64,
            intent_hash=digest(intent),
            actor=self.origins["legion"]["principal_id"],
            authority="daimon",
            resource_fence=resource_fence_position(fence),
            result="applied",
            observed_postcondition=postcondition,
            started_at_ms=NOW - 10,
            completed_at_ms=NOW,
        )
        completion_request, response = invoke(
            "curator.complete",
            {
                "claim_id": claim_id,
                "expected_generation": 1,
                "outcome": "completed",
                "output_refs": ["publication:rpc-cache"],
                "effect_receipt": receipt,
            },
            "31000000-0000-4000-8000-000000000066",
            b"r" * 16,
        )
        self.assertTrue(response["ok"], response)
        self.assertEqual(service.handle(completion_request), response)
        postcondition["generation"] = 8
        contradiction = service.handle(completion_request)
        self.assertFalse(contradiction["ok"])
        self.assertEqual(contradiction["error"]["code"], "effect-truth-discrepancy")

    def test_effect_receipt_binding_cannot_substitute_actor_intent_or_fence(
        self,
    ) -> None:
        intent = {"operation": "publish", "value": "synthetic"}
        item = self.item(
            coordination_mode="resource-fence",
            resource_ref="wiki:page:home",
            intent=intent,
        )
        fence = self._fence(item["resource_ref"])
        postcondition = {"generation": 7, "state": "present"}

        def observer(
            _item: Mapping[str, Any], _receipt: Mapping[str, Any], _at_ms: int
        ) -> dict[str, Any]:
            return {
                "intent": intent,
                "observed_postcondition": postcondition,
                "current_fence_evidence": fence,
            }

        self.coordinator = CuratorCoordinator(
            self.ledger_a,
            clock=lambda: self.now[0],
            fence_verifier=self._verify_fence,
            effect_observer=cast(EffectTruthObserver, observer),
        )
        self.enqueue(item)
        claim = self.claim(item, fence_evidence=fence)
        receipt = create_effect_receipt(
            effect_id="31000000-0000-4000-8000-000000000030",
            target_event_id="31000000-0000-4000-8000-000000000031",
            decision_event_id="31000000-0000-4000-8000-000000000032",
            adapter="synthetic-wiki/v1",
            preview_hash="a" * 64,
            intent_hash=digest(intent),
            actor="compaii@other",
            authority="daimon",
            resource_fence=resource_fence_position(fence),
            result="applied",
            observed_postcondition=postcondition,
            started_at_ms=NOW - 10,
            completed_at_ms=NOW,
        )
        with self.assertRaisesRegex(CuratorError, "effect_receipt_binding_mismatch"):
            self.coordinator.complete(
                claim_id=claim["claim_id"],
                expected_generation=1,
                outcome="completed",
                output_refs=["publication:synthetic"],
                effect_receipt=receipt,
                client_id="effect-worker",
                request_id="31000000-0000-4000-8000-000000000033",
            )
        failed_receipt = create_effect_receipt(
            effect_id="31000000-0000-4000-8000-000000000034",
            target_event_id="31000000-0000-4000-8000-000000000031",
            decision_event_id="31000000-0000-4000-8000-000000000032",
            adapter="synthetic-wiki/v1",
            preview_hash="a" * 64,
            intent_hash=digest(intent),
            actor=self.origins["legion"]["principal_id"],
            authority="daimon",
            resource_fence=resource_fence_position(fence),
            result="failed",
            observed_postcondition=postcondition,
            started_at_ms=NOW - 10,
            completed_at_ms=NOW,
        )
        with self.assertRaisesRegex(CuratorError, "effect_receipt_binding_mismatch"):
            self.coordinator.complete(
                claim_id=claim["claim_id"],
                expected_generation=1,
                outcome="completed",
                output_refs=["publication:synthetic"],
                effect_receipt=failed_receipt,
                client_id="effect-worker",
                request_id="31000000-0000-4000-8000-000000000035",
            )
        with self.assertRaisesRegex(
            CuratorError, "curator_noncompletion_effect_forbidden"
        ):
            self.coordinator.complete(
                claim_id=claim["claim_id"],
                expected_generation=1,
                outcome="failed",
                output_refs=[],
                effect_receipt=failed_receipt,
                client_id="effect-worker",
                request_id="31000000-0000-4000-8000-000000000036",
            )

    def test_concurrent_same_item_claim_has_one_winner(self) -> None:
        item = self.item()
        self.enqueue(item)
        barrier = threading.Barrier(2)

        def contender(index: int) -> str:
            barrier.wait()
            try:
                self.claim(item, f"contender-{index}")
            except CuratorError as exception:
                return exception.code
            return "accepted"

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(contender, (1, 2)))
        self.assertEqual(sorted(results), ["accepted", "curator_generation_conflict"])

    def test_public_schemas_validate_runtime_artifacts_and_reject_unknown_fields(
        self,
    ) -> None:
        item = self.item()
        self.enqueue(item)
        claim = self.claim(item)
        result = self.coordinator.complete(
            claim_id=claim["claim_id"],
            expected_generation=1,
            outcome="completed",
            output_refs=["proposal:one"],
            effect_receipt=None,
            client_id="schema-worker",
            request_id="31000000-0000-4000-8000-000000000040",
        )
        inspection = self.coordinator.inspect(item["item_id"])
        enqueue = {
            "schema": "dm.curator.enqueue-result/v1",
            "item": item,
            "state": "queued",
            "generation": 0,
        }
        documents = {
            "item.schema.json": item,
            "claim.schema.json": claim,
            "result.schema.json": result,
            "inspection.schema.json": inspection,
            "enqueue-result.schema.json": enqueue,
        }
        resources: list[tuple[str, dict[str, Any]]] = []
        for path in SCHEMA_ROOT.rglob("*.schema.json"):
            schema = json.loads(path.read_text(encoding="utf-8"))
            resources.append((schema["$id"], schema))
        registry = Registry().with_resources(
            (uri, Resource.from_contents(schema)) for uri, schema in resources
        )
        for filename, document in documents.items():
            schema = json.loads(
                (SCHEMA_ROOT / "curator/v1" / filename).read_text(encoding="utf-8")
            )
            validator = Draft202012Validator(
                schema, registry=registry, format_checker=FormatChecker()
            )
            self.assertEqual(list(validator.iter_errors(document)), [])
            self.assertTrue(list(validator.iter_errors({**document, "secret": "x"})))
        self.assertEqual(validate_curator_claim(claim), claim)
        self.assertEqual(validate_curator_result(result), result)


class CuratorInstalledRuntimeTests(RuntimeFixture):
    def setUp(self) -> None:
        super().setUp()
        self.state_root, bundle, self.capability, _ = self.make_process_bundle(
            capability_profile="curator"
        )
        self.runtime_id = bundle["runtime_id"]
        self.runtime_label = bundle["runtime_label"]
        self.stop = threading.Event()
        self.fail_after_dispatch = threading.Event()
        self.runtime = self._load_runtime()
        self._start()
        self.config_path = self.state_root / "curator-client.json"
        self.config_path.write_bytes(
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
        self.config_path.chmod(0o600)

    def _load_runtime(self) -> Any:
        return load_runtime(
            self.state_root,
            "runtime.json",
            lambda: bytearray(PASSWORD),
            clock=lambda: time.time_ns() // 1_000_000,
        )

    def _start(self) -> None:
        def fault(stage: str) -> None:
            if (
                stage == "after_dispatch_before_write"
                and self.fail_after_dispatch.is_set()
            ):
                self.fail_after_dispatch.clear()
                raise ConnectionError("synthetic response loss")

        self.thread = threading.Thread(
            target=serve_forever,
            kwargs={"runtime": self.runtime, "stop": self.stop, "fault_hook": fault},
            daemon=True,
        )
        self.thread.start()
        for _ in range(200):
            if self.runtime.socket_path.exists():
                return
            time.sleep(0.01)
        self.fail("curator runtime socket did not appear")

    def tearDown(self) -> None:
        self.stop.set()
        self.thread.join(timeout=3)
        super().tearDown()

    def _run_cli(self, arguments: list[str]) -> subprocess.CompletedProcess[bytes]:
        observing = "inspect" in arguments
        capability = (
            self.operator_capabilities["observe"] if observing else self.capability
        )
        config_path = self.state_root / "client.json" if observing else self.config_path
        read_descriptor, write_descriptor = os.pipe()
        os.write(write_descriptor, capability.key)
        os.close(write_descriptor)
        try:
            return subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "daimon_matrix.cli",
                    "--socket",
                    str(self.runtime.socket_path),
                    "--client-config",
                    str(config_path),
                    "--capability-key-fd",
                    str(read_descriptor),
                    "--json",
                    *arguments,
                ],
                cwd=ROOT,
                env=os.environ.copy(),
                pass_fds=(read_descriptor,),
                capture_output=True,
                timeout=15,
                check=False,
            )
        finally:
            os.close(read_descriptor)

    @staticmethod
    def _result(process: subprocess.CompletedProcess[bytes]) -> dict[str, Any]:
        if process.returncode != 0:
            raise AssertionError(process.stderr.decode("utf-8", errors="replace"))
        return cast(dict[str, Any], json.loads(process.stdout)["response"]["result"])

    def test_real_daemon_installed_cli_response_loss_restart_and_exactly_once(
        self,
    ) -> None:
        now = time.time_ns() // 1_000_000
        item = create_curator_item(
            subject_me_id=self.state.being_ref,
            resource_ref="memory:item:installed",
            work_kind="memory-proposal",
            input_ref="candidate:installed",
            input_hash=digest({"candidate": "installed"}),
            coordination_mode="queue-item",
            required_authority="daimon",
            effect_intent_hash=None,
            queued_at_ms=now,
        )
        item_path = self.state_root / "curator-item.json"
        item_path.write_bytes(canonical_bytes(item))
        item_path.chmod(0o600)
        enqueued = self._result(
            self._run_cli(["curator", "enqueue", "--item", str(item_path)])
        )
        self.assertEqual(enqueued["state"], "queued")
        claim_id = "31000000-0000-4000-8000-000000000050"
        claim = self._result(
            self._run_cli(
                [
                    "curator",
                    "claim",
                    "--item-id",
                    item["item_id"],
                    "--claim-id",
                    claim_id,
                    "--expected-generation",
                    "0",
                    "--lease-until-ms",
                    str(now + 30_000),
                ]
            )
        )
        self.assertEqual(claim["generation"], 1)
        retry_path = self.state_root / "curator-complete-request.json"
        arguments = [
            "--request-file",
            str(retry_path),
            "curator",
            "complete",
            "--claim-id",
            claim_id,
            "--expected-generation",
            "1",
            "--outcome",
            "completed",
            "--output-ref",
            "proposal:installed",
        ]
        self.fail_after_dispatch.set()
        lost = self._run_cli(arguments)
        self.assertNotEqual(lost.returncode, 0)
        self.stop.set()
        self.thread.join(timeout=3)
        self.runtime = self._load_runtime()
        self.stop = threading.Event()
        self._start()
        replayed = self._result(self._run_cli(arguments))
        inspection = self._result(
            self._run_cli(["curator", "inspect", "--item-id", item["item_id"]])
        )
        self.assertEqual(inspection["state"], "completed")
        self.assertEqual(inspection["result"], replayed)
        with self.runtime.service.ledger._database() as database:
            count = int(
                database.execute(
                    "SELECT COUNT(*) FROM curator_items WHERE item_id=?",
                    (item["item_id"],),
                ).fetchone()[0]
            )
        self.assertEqual(count, 1)


class CuratorVectorTests(RootLedgerFixture):
    def test_vectors_validate_and_regenerate_byte_identically(self) -> None:
        index = json.loads((VECTOR_ROOT / "index.json").read_bytes())
        artifacts = {
            name: json.loads((VECTOR_ROOT / relative).read_bytes())
            for name, relative in index["artifacts"].items()
        }
        self.assertEqual(
            index["sha256"],
            {
                name: hashlib.sha256(canonical_bytes(value)).hexdigest()
                for name, value in artifacts.items()
            },
        )
        for name in ("queue_item", "review_item", "resource_item"):
            validate_curator_item(artifacts[name])
        for name in ("queue_claim", "resource_claim"):
            validate_curator_claim(artifacts[name])
        for name in ("queue_result", "review_result", "resource_result"):
            validate_curator_result(artifacts[name])
        with self.assertRaisesRegex(CuratorError, "curator_item_id_mismatch"):
            validate_curator_item(artifacts["negative_item"])
        with TemporaryDirectory(prefix="dm031-vectors-") as directory:
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
        with TemporaryDirectory(prefix="dm031-environments-") as directory:
            root = Path(directory)
            for index, settings in enumerate(
                (("1", "UTC", "C"), ("997", "America/Argentina/Cordoba", "C.UTF-8"))
            ):
                output = root / str(index)
                environment = os.environ.copy()
                environment.update(
                    {
                        "PYTHONHASHSEED": settings[0],
                        "TZ": settings[1],
                        "LC_ALL": settings[2],
                        "PYTHONPATH": str(ROOT / "src"),
                    }
                )
                subprocess.run(
                    [
                        sys.executable,
                        str(ROOT / "tools/generate_dm031_vectors.py"),
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


if __name__ == "__main__":
    import unittest

    unittest.main()
