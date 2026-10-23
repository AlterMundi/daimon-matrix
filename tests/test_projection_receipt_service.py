"""Authenticated foreground effect receipts, fresh truth and exact recovery."""

from __future__ import annotations

import hashlib
from dataclasses import replace
from typing import Any

from daimon_matrix.canonical import canonical_bytes
from daimon_matrix.cluster import create_effect_receipt
from daimon_matrix.local_api import (
    create_capability,
    create_request,
    request_hash,
    verify_response,
)
from daimon_matrix.service import (
    METHODS,
    OBSERVE_METHODS,
    OPERATOR_CAPABILITY_PROFILES,
    HostedWeave,
)
from tests.test_dm022_ledger import NOW, RootLedgerFixture


class ProjectionReceiptTests(RootLedgerFixture):
    def setUp(self) -> None:
        super().setUp()
        self.capability = create_capability(
            hashlib.sha256(b"projection-qualification").digest(),
            client_id="client:projection-test",
            methods=sorted(METHODS),
            not_before_ms=NOW - 1000,
            not_after_ms=NOW + 10000,
        )
        self.target = self.ledger_a.append_local(
            kind="configuration.proposed",
            subject="same-being:configuration",
            payload={"content_refs": ["a" * 64]},
            signer=self.signers["legion"],
            sensitivity="private",
        )
        self.decision = self.ledger_a.append_local(
            kind="adoption.decided",
            subject=self.target["subject"],
            payload={
                "target_event_id": self.target["event_id"],
                "decision": "adopt",
                "reason": "Selected local intent",
            },
            causal_parents=[self.target["event_id"]],
            signer=self.signers["legion"],
            sensitivity="private",
        )
        self.intent = {"selection_sha256": "a" * 64}
        self.postcondition = {"materialized": True, "revision": 1}
        self.effect_file = self.root_path / "observed-state.json"
        self.effect_file.write_bytes(canonical_bytes(self.postcondition))
        self.observations = 0
        self.service = HostedWeave(
            self.ledger_a,
            self.signers["legion"],
            {self.capability.capability_id: self.capability},
            lambda: NOW,
            "dm:runtime:v1:" + "r" * 43,
            "receipt-test",
            projection_observer=self.observe,
        )
        self.receipt = create_effect_receipt(
            effect_id="38200000-0000-4000-8000-000000000001",
            target_event_id=self.target["event_id"],
            decision_event_id=self.decision["event_id"],
            adapter="selected-config/v1",
            preview_hash="a" * 64,
            intent_hash=hashlib.sha256(canonical_bytes(self.intent)).hexdigest(),
            actor=self.service.origin["principal_id"],
            authority="daimon",
            resource_fence=None,
            result="applied",
            observed_postcondition=self.postcondition,
            started_at_ms=NOW,
            completed_at_ms=NOW,
        )

    def observe(self, receipt: Any, at_ms: int) -> dict[str, Any]:
        import json

        self.observations += 1
        return {
            "intent": self.intent,
            "observed_postcondition": json.loads(self.effect_file.read_bytes()),
            "current_fence_evidence": None,
        }

    def request(self, index: int = 1, receipt: Any = None) -> dict[str, Any]:
        return create_request(
            self.capability,
            request_id=f"38200000-0000-4000-9000-{index:012d}",
            issued_at_ms=NOW,
            method="we.projection.receipt",
            params={"receipt": self.receipt if receipt is None else receipt},
            nonce=hashlib.sha256(str(index).encode()).digest()[:16],
        )

    def invoke(self, request: dict[str, Any]) -> dict[str, Any]:
        return verify_response(
            self.service.handle(request),
            self.capability,
            expected_request_id=request["request_id"],
            expected_request_hash=request_hash(request),
            expected_server=self.service.origin,
            expected_runtime=self.service.runtime_identity,
        )

    def test_exact_retry_reconciles_and_keeps_one_private_event(self) -> None:
        request = self.request()
        first = self.invoke(request)
        second = self.invoke(request)
        self.assertTrue(first["ok"])
        self.assertEqual(first["result"]["event"], second["result"]["event"])
        self.assertEqual(self.observations, 2)
        event = first["result"]["event"]
        self.assertEqual(event["kind"], "projection.receipted")
        self.assertEqual(event["sensitivity"], "private")
        self.assertEqual(
            event["causal_parents"],
            sorted([self.target["event_id"], self.decision["event_id"]]),
        )
        self.assertEqual(
            len(
                [
                    e
                    for e in self.ledger_a.events()
                    if e["kind"] == "projection.receipted"
                ]
            ),
            1,
        )

    def test_new_request_for_same_effect_does_not_duplicate_event(self) -> None:
        first = self.invoke(self.request())
        second = self.invoke(self.request(2))
        self.assertEqual(first["result"]["event"], second["result"]["event"])
        self.assertEqual(
            len(
                [
                    e
                    for e in self.ledger_a.events()
                    if e["kind"] == "projection.receipted"
                ]
            ),
            1,
        )

    def test_missing_observer_recovers_the_original_request(self) -> None:
        request = self.request()
        self.service = replace(self.service, projection_observer=None)
        absent = self.invoke(request)
        self.assertEqual(
            absent["error"]["code"], "projection_effect_truth_unverifiable"
        )
        self.assertTrue(absent["error"]["retryable"])
        self.assertEqual(len(self.ledger_a.events()), 2)
        self.service = replace(self.service, projection_observer=self.observe)
        recovered = self.invoke(request)
        self.assertTrue(recovered["ok"])
        self.assertTrue(self.invoke(request)["ok"])
        self.assertEqual(len(self.ledger_a.events()), 3)

    def test_cached_success_does_not_hide_current_effect_drift(self) -> None:
        request = self.request()
        original = self.invoke(request)["result"]["event"]
        self.effect_file.write_bytes(
            canonical_bytes({"materialized": True, "revision": 2})
        )
        drift = self.invoke(request)
        self.assertEqual(drift["error"]["code"], "effect-truth-discrepancy")
        self.assertEqual(self.ledger_a.event(original["event_id"]), original)
        self.assertEqual(len(self.ledger_a.events()), 3)

    def test_current_local_adoption_is_required_after_prior_success(self) -> None:
        request = self.request()
        self.assertTrue(self.invoke(request)["ok"])
        self.ledger_a.append_local(
            kind="adoption.decided",
            subject=self.target["subject"],
            payload={
                "target_event_id": self.target["event_id"],
                "decision": "revert",
                "reason": "Local changed decision",
            },
            signer=self.signers["legion"],
            supersedes=self.decision["event_id"],
            causal_parents=[self.target["event_id"]],
            sensitivity="private",
        )
        result = self.invoke(request)
        self.assertEqual(result["error"]["code"], "projection_adoption_not_current")
        self.assertEqual(self.observations, 1)

    def test_actor_target_decision_and_timing_refuse_before_observer(self) -> None:
        cases = [
            ("actor", "another-principal", "projection_effect_actor_mismatch"),
            ("authority", "human", "projection_effect_actor_mismatch"),
            ("completed_at_ms", NOW + 1, "projection_effect_timing_invalid"),
            ("started_at_ms", NOW - 1, "projection_effect_timing_invalid"),
            (
                "target_event_id",
                "38200000-0000-4000-8000-000000000099",
                "projection_known_proposal_required",
            ),
            (
                "decision_event_id",
                "38200000-0000-4000-8000-000000000099",
                "projection_local_adoption_required",
            ),
        ]
        for index, (field, value, code) in enumerate(cases, 10):
            with self.subTest(field=field):
                fields = {
                    k: v
                    for k, v in self.receipt.items()
                    if k not in {"schema", "content_hash"}
                }
                fields[field] = value
                malformed = create_effect_receipt(**fields)
                result = self.invoke(self.request(index, malformed))
                self.assertEqual(result["error"]["code"], code)
        self.assertEqual(self.observations, 0)
        self.assertEqual(len(self.ledger_a.events()), 2)

    def test_mutating_decision_during_observation_cannot_author_success(self) -> None:
        def racing_observer(receipt: Any, at_ms: int) -> dict[str, Any]:
            self.ledger_a.append_local(
                kind="adoption.decided",
                subject=self.target["subject"],
                payload={
                    "target_event_id": self.target["event_id"],
                    "decision": "revert",
                    "reason": "Changed during observation",
                },
                signer=self.signers["legion"],
                supersedes=self.decision["event_id"],
                causal_parents=[self.target["event_id"]],
                sensitivity="private",
            )
            return self.observe(receipt, at_ms)

        self.service = replace(self.service, projection_observer=racing_observer)
        result = self.invoke(self.request())
        self.assertEqual(result["error"]["code"], "projection_decision_view_changed")
        self.assertFalse(
            any(e["kind"] == "projection.receipted" for e in self.ledger_a.events())
        )

    def test_capability_is_mutation_and_observer_cannot_come_from_rpc(self) -> None:
        self.assertNotIn("we.projection.receipt", OBSERVE_METHODS)
        self.assertIn("we.projection.receipt", OPERATOR_CAPABILITY_PROFILES["weave"])
        params = {"receipt": self.receipt, "projection_observer": "peer-selected"}
        request = create_request(
            self.capability,
            request_id="38200000-0000-4000-9000-000000000050",
            issued_at_ms=NOW,
            method="we.projection.receipt",
            params=params,
            nonce=b"n" * 16,
        )
        result = self.invoke(request)
        self.assertEqual(result["error"]["code"], "invalid_params")
        self.assertEqual(self.observations, 0)
