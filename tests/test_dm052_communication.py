from __future__ import annotations

import copy
import hashlib
import json
import sqlite3
import unittest
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
from typing import Any

from jsonschema import (  # type: ignore[import-untyped]
    Draft202012Validator,
    FormatChecker,
)

from daimon_matrix.canonical import canonical_bytes
from daimon_matrix.communication import (
    MESSAGE_PAYLOAD_SCHEMA,
    RECEIPT_PAYLOAD_SCHEMA,
    RESOLUTION_PAYLOAD_SCHEMA,
    ROUTE_ATTEMPT_SCHEMA,
    CommunicationError,
    CommunicationStore,
    dispatch_attempt,
)
from daimon_matrix.local_api import (
    create_capability,
    create_request,
    request_hash,
    verify_response,
)
from daimon_matrix.service import SERVICE_METHODS, HostedWeave
from daimon_matrix.weave import create_event
from tests.test_dm022_ledger import NOW, RootLedgerFixture

ROOT = Path(__file__).resolve().parents[1]


def identifier(prefix: int, index: int) -> str:
    return f"{prefix:08d}-0000-4000-8000-{index:012d}"


def capability_key(label: str) -> bytes:
    return hashlib.sha256(f"dm052:{label}".encode()).digest()


class FakeProvider:
    def __init__(self, provider_ref: str = "route:fake-direct") -> None:
        self._provider_ref = provider_ref
        self.effects: set[str] = set()
        self.fail_after_effect = False

    @property
    def provider_ref(self) -> str:
        return self._provider_ref

    def deliver(self, attempt: Mapping[str, Any]) -> Mapping[str, Any]:
        attempt_id = str(attempt["attempt_id"])
        self.effects.add(attempt_id)
        if self.fail_after_effect:
            self.fail_after_effect = False
            raise ConnectionError("simulated response loss")
        return {
            "schema": "dm.route-ack/v1",
            "provider_ref": self.provider_ref,
            "attempt_id": attempt_id,
            "status": "accepted",
        }


class LogicalCommunicationFixture(RootLedgerFixture):
    def setUp(self) -> None:
        super().setUp()
        self.store = CommunicationStore(self.ledger_a, clock=lambda: NOW)
        self.store.initialize()
        self.thread_index = 0
        self.remote_sequence = 0
        self.remote_previous: str | None = None

    def thread_id(self) -> str:
        self.thread_index += 1
        return identifier(30_000_000, self.thread_index)

    def target(
        self,
        recipient_id: str,
        *,
        scope_kind: str = "we",
        recipient_type: str = "embodiment",
        origin: str | None = None,
        cursor: str = "dm:evidence:v1:synthetic",
    ) -> dict[str, Any]:
        return {
            "scope_kind": scope_kind,
            "recipient_type": recipient_type,
            "recipient_id": recipient_id,
            "receipt_origin_embodiment_id": recipient_id if origin is None else origin,
            "evidence_cursor": cursor,
        }

    def append_message(
        self,
        targets: list[dict[str, Any]],
        *,
        thread_id: str | None = None,
        reply: dict[str, Any] | None = None,
        causal_parents: list[str] | None = None,
        body: dict[str, Any] | None = None,
        scope: str = "/we",
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
        thread = self.thread_id() if thread_id is None else thread_id
        message = self.ledger_a.append_local(
            kind="experience.observed",
            subject="communication",
            payload={
                "schema": MESSAGE_PAYLOAD_SCHEMA,
                "intent": {
                    "operation": "message.send",
                    "scope": scope,
                    "thread_id": thread,
                },
                "body": {"text": "hello"} if body is None else body,
                "reply": reply,
            },
            signer=self.signers["legion"],
            causal_parents=[] if causal_parents is None else causal_parents,
            occurred_at_ms=NOW,
        )
        ordered = sorted(
            targets,
            key=lambda item: (item["recipient_type"], item["recipient_id"]),
        )
        resolution = self.ledger_a.append_local(
            kind="experience.observed",
            subject="communication-resolution",
            payload={
                "schema": RESOLUTION_PAYLOAD_SCHEMA,
                "message_id": message["event_id"],
                "scope": scope,
                "targets": ordered,
            },
            signer=self.signers["legion"],
            causal_parents=[message["event_id"]],
            occurred_at_ms=NOW,
        )
        return (
            message,
            resolution,
            self.store.accept(
                message_event_id=message["event_id"],
                resolution_event_id=resolution["event_id"],
            ),
        )

    def append_invalid_message(
        self,
        payload: dict[str, Any],
        targets: list[dict[str, Any]],
        *,
        causal_parents: list[str] | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        message = self.ledger_a.append_local(
            kind="experience.observed",
            subject="communication",
            payload=payload,
            signer=self.signers["legion"],
            causal_parents=[] if causal_parents is None else causal_parents,
            occurred_at_ms=NOW,
        )
        resolution = self.ledger_a.append_local(
            kind="experience.observed",
            subject="communication-resolution",
            payload={
                "schema": RESOLUTION_PAYLOAD_SCHEMA,
                "message_id": message["event_id"],
                "scope": message["payload"]["intent"]["scope"],
                "targets": sorted(
                    targets,
                    key=lambda item: (
                        item["recipient_type"],
                        item["recipient_id"],
                    ),
                ),
            },
            signer=self.signers["legion"],
            causal_parents=[message["event_id"]],
            occurred_at_ms=NOW,
        )
        return message, resolution

    def receipt(
        self,
        result: dict[str, Any],
        recipient_id: str,
        outcome: str,
        *,
        remote: bool = False,
        evidence_ref: str | None = None,
    ) -> dict[str, Any]:
        leg = next(
            value for value in result["legs"] if value["recipient_id"] == recipient_id
        )
        payload = {
            "schema": RECEIPT_PAYLOAD_SCHEMA,
            "message_id": result["message_id"],
            "thread_id": result["thread_id"],
            "recipient_type": leg["recipient_type"],
            "recipient_id": recipient_id,
            "outcome": outcome,
            "observed_at_ms": NOW,
            "evidence_ref": evidence_ref,
        }
        if remote:
            self.remote_sequence += 1
            receipt = create_event(
                self.authority,
                self.origins["daimonmatrix"],
                self.signers["daimonmatrix"],
                event_id=identifier(40_000_000, self.remote_sequence),
                sequence=self.remote_sequence,
                previous_event_id=self.remote_previous,
                occurred_at_ms=NOW,
                causal_parents=[result["message_id"]],
                kind="experience.observed",
                subject="communication-receipt",
                payload=payload,
            )
            self.remote_previous = receipt["event_id"]
            self.ledger_a.ingest([receipt], source="compaii@daimonmatrix")
        else:
            receipt = self.ledger_a.append_local(
                kind="experience.observed",
                subject="communication-receipt",
                payload=payload,
                signer=self.signers["legion"],
                causal_parents=[result["message_id"]],
                occurred_at_ms=NOW,
            )
        self.store.record_receipt(receipt["event_id"])
        return receipt

    def attempt(
        self,
        leg_id: str,
        index: int,
        *,
        provider_ref: str = "route:fake-direct",
    ) -> dict[str, Any]:
        return {
            "schema": ROUTE_ATTEMPT_SCHEMA,
            "attempt_id": identifier(50_000_000, index),
            "leg_id": leg_id,
            "provider_ref": provider_ref,
            "route_ref": f"route:attempt:{index}",
            "credential_ref": f"credential:recipient:{index}",
            "body_ref": f"body:recipient:{index}",
            "deadline_ms": NOW + 10_000,
        }


class LogicalMessageTests(LogicalCommunicationFixture):
    def test_fanout_preserves_ids_and_returns_per_recipient_terminal_vector(
        self,
    ) -> None:
        targets = [
            self.target("embodiment:legion"),
            self.target("embodiment:daimonmatrix"),
        ]
        message, resolution, result = self.append_message(targets)
        self.assertEqual(result["message_id"], message["event_id"])
        self.assertEqual(result["thread_id"], message["payload"]["intent"]["thread_id"])
        self.assertEqual(len(result["legs"]), 2)
        self.assertEqual({leg["state"] for leg in result["legs"]}, {"accepted"})
        self.assertFalse(result["terminal"])
        self.assertEqual(
            {leg["resolution_event_id"] for leg in result["legs"]},
            {resolution["event_id"]},
        )

        self.receipt(result, "embodiment:legion", "delivered")
        self.receipt(
            result,
            "embodiment:daimonmatrix",
            "delivered",
            remote=True,
        )
        terminal = self.store.result(message["event_id"], require_terminal=True)
        self.assertTrue(terminal["terminal"])
        self.assertEqual(
            [(leg["recipient_id"], leg["state"]) for leg in terminal["legs"]],
            [
                ("embodiment:daimonmatrix", "delivered"),
                ("embodiment:legion", "delivered"),
            ],
        )

    def test_semantic_dedup_ignores_routes_reseal_and_incarnation_details(self) -> None:
        message, resolution, result = self.append_message(
            [self.target("embodiment:daimonmatrix")]
        )
        replay = self.store.accept(
            message_event_id=message["event_id"],
            resolution_event_id=resolution["event_id"],
        )
        self.assertEqual(replay, result)
        leg = result["legs"][0]
        direct = self.attempt(leg["leg_id"], 1)
        hub = self.attempt(leg["leg_id"], 2, provider_ref="route:fake-hub")
        self.store.record_attempt(direct)
        self.store.record_attempt(hub)
        first = self.store.record_delivery(
            attempt_id=direct["attempt_id"],
            delivery_id=identifier(60_000_000, 1),
            envelope_hash="1" * 64,
        )
        duplicate = self.store.record_delivery(
            attempt_id=direct["attempt_id"],
            delivery_id=identifier(60_000_000, 1),
            envelope_hash="1" * 64,
        )
        self.assertFalse(first["replayed"])
        self.assertTrue(duplicate["replayed"])
        self.store.record_delivery(
            attempt_id=hub["attempt_id"],
            delivery_id=identifier(60_000_000, 2),
            envelope_hash="2" * 64,
        )
        self.assertEqual(len(self.store.result(message["event_id"])["legs"]), 1)
        plan = self.store.rebuild_plan(message["event_id"])
        self.assertEqual(plan["message"]["event_id"], message["event_id"])
        self.assertEqual(plan["resolution"]["event_id"], resolution["event_id"])

    def test_concurrent_exact_accept_materializes_one_leg(self) -> None:
        message = self.ledger_a.append_local(
            kind="experience.observed",
            subject="communication",
            payload={
                "schema": MESSAGE_PAYLOAD_SCHEMA,
                "intent": {
                    "operation": "message.send",
                    "scope": "/we",
                    "thread_id": self.thread_id(),
                },
                "body": {"text": "concurrent"},
                "reply": None,
            },
            signer=self.signers["legion"],
            occurred_at_ms=NOW,
        )
        resolution = self.ledger_a.append_local(
            kind="experience.observed",
            subject="communication-resolution",
            payload={
                "schema": RESOLUTION_PAYLOAD_SCHEMA,
                "message_id": message["event_id"],
                "scope": "/we",
                "targets": [self.target("embodiment:legion")],
            },
            signer=self.signers["legion"],
            causal_parents=[message["event_id"]],
            occurred_at_ms=NOW,
        )

        def accept(_index: int) -> dict[str, Any]:
            return CommunicationStore(self.ledger_a, clock=lambda: NOW).accept(
                message_event_id=message["event_id"],
                resolution_event_id=resolution["event_id"],
            )

        with ThreadPoolExecutor(max_workers=4) as workers:
            results = list(workers.map(accept, range(4)))
        self.assertTrue(all(result == results[0] for result in results))
        self.assertEqual(len(results[0]["legs"]), 1)

    def test_same_delivery_id_with_changed_bytes_is_quarantined(self) -> None:
        _message, _resolution, result = self.append_message(
            [self.target("embodiment:legion")]
        )
        attempt = self.attempt(result["legs"][0]["leg_id"], 3)
        self.store.record_attempt(attempt)
        delivery_id = identifier(60_000_000, 3)
        self.store.record_delivery(
            attempt_id=attempt["attempt_id"],
            delivery_id=delivery_id,
            envelope_hash="a" * 64,
        )
        _other_message, _other_resolution, other_result = self.append_message(
            [self.target("embodiment:daimonmatrix")]
        )
        other_attempt = self.attempt(other_result["legs"][0]["leg_id"], 30)
        self.store.record_attempt(other_attempt)
        with self.assertRaisesRegex(CommunicationError, "delivery_id_conflict"):
            self.store.record_delivery(
                attempt_id=other_attempt["attempt_id"],
                delivery_id=delivery_id,
                envelope_hash="b" * 64,
            )
        current = self.store.result(result["message_id"])
        self.assertEqual(current["legs"][0]["state"], "quarantined")
        self.assertEqual(
            self.store.result(other_result["message_id"])["legs"][0]["state"],
            "quarantined",
        )
        self.assertEqual(self.store.conflicts()[0]["lane"], "delivery")

    def test_route_ack_is_not_recipient_intake(self) -> None:
        _message, _resolution, result = self.append_message(
            [self.target("embodiment:legion")]
        )
        attempt = self.attempt(result["legs"][0]["leg_id"], 4)
        provider = FakeProvider()
        ack = dispatch_attempt(self.store, provider, attempt)
        self.assertEqual(ack["state"], "route-acked")
        self.assertEqual(
            self.store.result(result["message_id"])["legs"][0]["state"],
            "accepted",
        )
        with self.assertRaisesRegex(CommunicationError, "terminal_result_incomplete"):
            self.store.result(result["message_id"], require_terminal=True)

    def test_response_loss_retries_one_stable_provider_effect(self) -> None:
        _message, _resolution, result = self.append_message(
            [self.target("embodiment:legion")]
        )
        attempt = self.attempt(result["legs"][0]["leg_id"], 5)
        provider = FakeProvider()
        provider.fail_after_effect = True
        with self.assertRaisesRegex(CommunicationError, "route_result_unknown"):
            dispatch_attempt(self.store, provider, attempt)
        self.assertEqual(provider.effects, {attempt["attempt_id"]})
        second = dispatch_attempt(self.store, provider, attempt)
        self.assertEqual(second["state"], "route-acked")
        self.assertEqual(provider.effects, {attempt["attempt_id"]})

    def test_terminal_receipt_replay_and_conflict(self) -> None:
        _message, _resolution, result = self.append_message(
            [self.target("embodiment:legion")]
        )
        first = self.receipt(result, "embodiment:legion", "delivered")
        replay = self.store.record_receipt(first["event_id"])
        self.assertTrue(replay["terminal"])
        second = self.ledger_a.append_local(
            kind="experience.observed",
            subject="communication-receipt",
            payload={
                "schema": RECEIPT_PAYLOAD_SCHEMA,
                "message_id": result["message_id"],
                "thread_id": result["thread_id"],
                "recipient_type": "embodiment",
                "recipient_id": "embodiment:legion",
                "outcome": "failed:transport",
                "observed_at_ms": NOW,
                "evidence_ref": "route:timeout",
            },
            signer=self.signers["legion"],
            causal_parents=[result["message_id"]],
            occurred_at_ms=NOW,
        )
        with self.assertRaisesRegex(CommunicationError, "terminal_receipt_conflict"):
            self.store.record_receipt(second["event_id"])
        self.assertEqual(
            self.store.result(result["message_id"])["legs"][0]["state"],
            "quarantined",
        )
        self.assertEqual(self.store.conflicts()[-1]["lane"], "terminal-receipt")

    def test_every_terminal_outcome_is_exact_and_accepted_is_never_terminal(
        self,
    ) -> None:
        outcomes = [
            "delivered",
            "failed:transport",
            "refused:policy",
            "expired",
            "resolved:unroutable",
        ]
        for outcome in outcomes:
            with self.subTest(outcome=outcome):
                _message, _resolution, result = self.append_message(
                    [self.target("embodiment:legion")]
                )
                self.assertFalse(result["terminal"])
                self.receipt(result, "embodiment:legion", outcome)
                terminal = self.store.result(
                    result["message_id"], require_terminal=True
                )
                self.assertEqual(terminal["legs"][0]["state"], outcome)
                with self.assertRaisesRegex(
                    CommunicationError, "semantic_leg_not_accepted"
                ):
                    self.store.record_attempt(
                        self.attempt(terminal["legs"][0]["leg_id"], 100 + len(outcome))
                    )

        _message, _resolution, remote = self.append_message(
            [self.target("embodiment:daimonmatrix")]
        )
        wrong_origin = self.ledger_a.append_local(
            kind="experience.observed",
            subject="communication-receipt",
            payload={
                "schema": RECEIPT_PAYLOAD_SCHEMA,
                "message_id": remote["message_id"],
                "thread_id": remote["thread_id"],
                "recipient_type": "embodiment",
                "recipient_id": "embodiment:daimonmatrix",
                "outcome": "delivered",
                "observed_at_ms": NOW,
                "evidence_ref": None,
            },
            signer=self.signers["legion"],
            causal_parents=[remote["message_id"]],
            occurred_at_ms=NOW,
        )
        with self.assertRaisesRegex(CommunicationError, "receipt_origin_mismatch"):
            self.store.record_receipt(wrong_origin["event_id"])

    def test_resolution_and_receipt_require_signed_scope_and_causality(self) -> None:
        message = self.ledger_a.append_local(
            kind="experience.observed",
            subject="communication",
            payload={
                "schema": MESSAGE_PAYLOAD_SCHEMA,
                "intent": {
                    "operation": "message.send",
                    "scope": "/we",
                    "thread_id": self.thread_id(),
                },
                "body": {"text": "causal"},
                "reply": None,
            },
            signer=self.signers["legion"],
            occurred_at_ms=NOW,
        )
        target = self.target("embodiment:legion")
        wrong_scope = self.ledger_a.append_local(
            kind="experience.observed",
            subject="communication-resolution",
            payload={
                "schema": RESOLUTION_PAYLOAD_SCHEMA,
                "message_id": message["event_id"],
                "scope": "/tribe/wrong",
                "targets": [target],
            },
            signer=self.signers["legion"],
            causal_parents=[message["event_id"]],
            occurred_at_ms=NOW,
        )
        with self.assertRaisesRegex(CommunicationError, "resolution_scope_mismatch"):
            self.store.accept(
                message_event_id=message["event_id"],
                resolution_event_id=wrong_scope["event_id"],
            )
        missing_cause = self.ledger_a.append_local(
            kind="experience.observed",
            subject="communication-resolution",
            payload={
                "schema": RESOLUTION_PAYLOAD_SCHEMA,
                "message_id": message["event_id"],
                "scope": "/we",
                "targets": [target],
            },
            signer=self.signers["legion"],
            occurred_at_ms=NOW,
        )
        with self.assertRaisesRegex(
            CommunicationError, "resolution_message_not_causal"
        ):
            self.store.accept(
                message_event_id=message["event_id"],
                resolution_event_id=missing_cause["event_id"],
            )

        _accepted_message, _resolution, result = self.append_message([target])
        missing_receipt_cause = self.ledger_a.append_local(
            kind="experience.observed",
            subject="communication-receipt",
            payload={
                "schema": RECEIPT_PAYLOAD_SCHEMA,
                "message_id": result["message_id"],
                "thread_id": result["thread_id"],
                "recipient_type": "embodiment",
                "recipient_id": "embodiment:legion",
                "outcome": "delivered",
                "observed_at_ms": NOW,
                "evidence_ref": None,
            },
            signer=self.signers["legion"],
            occurred_at_ms=NOW,
        )
        with self.assertRaisesRegex(CommunicationError, "receipt_message_not_causal"):
            self.store.record_receipt(missing_receipt_cause["event_id"])

    def test_direct_reply_is_signed_targeted_causal_and_same_thread(self) -> None:
        parent, _resolution, _result = self.append_message(
            [self.target("embodiment:daimonmatrix")]
        )
        thread = parent["payload"]["intent"]["thread_id"]
        reply = {
            "schema": "daimon-reply/v1",
            "direct_recipient_embodiment_id": "embodiment:daimonmatrix",
            "reply_parent_event_ids": [parent["event_id"]],
        }
        message, _evidence, result = self.append_message(
            [self.target("embodiment:daimonmatrix", scope_kind="direct")],
            thread_id=thread,
            reply=reply,
            causal_parents=[parent["event_id"]],
            scope="/direct",
        )
        self.assertEqual(result["thread_id"], thread)
        self.assertNotEqual(message["event_id"], parent["event_id"])

        sibling, _sibling_resolution, _sibling_result = self.append_message(
            [self.target("embodiment:daimonmatrix")], thread_id=thread
        )
        ordered_parents = sorted([parent["event_id"], sibling["event_id"]])

        invalid_cases = [
            (
                {**reply, "reply_parent_event_ids": []},
                [parent["event_id"]],
                [self.target("embodiment:daimonmatrix", scope_kind="direct")],
                "invalid_direct_reply",
            ),
            (
                {**reply, "reply_parent_event_ids": [parent["event_id"]] * 2},
                [parent["event_id"]],
                [self.target("embodiment:daimonmatrix", scope_kind="direct")],
                "invalid_direct_reply",
            ),
            (
                {**reply, "reply_parent_event_ids": list(reversed(ordered_parents))},
                ordered_parents,
                [self.target("embodiment:daimonmatrix", scope_kind="direct")],
                "invalid_direct_reply",
            ),
            (
                reply,
                [],
                [self.target("embodiment:daimonmatrix", scope_kind="direct")],
                "reply_parent_not_causal",
            ),
            (
                reply,
                [parent["event_id"]],
                [self.target("embodiment:legion", scope_kind="direct")],
                "direct_reply_target_mismatch",
            ),
        ]
        for index, (bad_reply, parents, targets, error) in enumerate(invalid_cases):
            with self.subTest(index=index):
                payload = {
                    "schema": MESSAGE_PAYLOAD_SCHEMA,
                    "intent": {
                        "operation": "message.send",
                        "scope": "/direct",
                        "thread_id": thread,
                    },
                    "body": {"text": "reply"},
                    "reply": bad_reply,
                }
                bad, evidence = self.append_invalid_message(
                    payload, targets, causal_parents=parents
                )
                with self.assertRaisesRegex(CommunicationError, error):
                    self.store.accept(
                        message_event_id=bad["event_id"],
                        resolution_event_id=evidence["event_id"],
                    )

        wrong_thread = self.thread_id()
        bad, evidence = self.append_invalid_message(
            {
                "schema": MESSAGE_PAYLOAD_SCHEMA,
                "intent": {
                    "operation": "message.send",
                    "scope": "/direct",
                    "thread_id": wrong_thread,
                },
                "body": {"text": "reply"},
                "reply": reply,
            },
            [self.target("embodiment:daimonmatrix", scope_kind="direct")],
            causal_parents=[parent["event_id"]],
        )
        with self.assertRaisesRegex(CommunicationError, "reply_thread_mismatch"):
            self.store.accept(
                message_event_id=bad["event_id"],
                resolution_event_id=evidence["event_id"],
            )

        unsigned_alias = copy.deepcopy(parent["payload"])
        unsigned_alias["reply_to"] = parent["event_id"]
        bad, evidence = self.append_invalid_message(
            unsigned_alias, [self.target("embodiment:daimonmatrix")]
        )
        with self.assertRaisesRegex(CommunicationError, "invalid_message_payload"):
            self.store.accept(
                message_event_id=bad["event_id"],
                resolution_event_id=evidence["event_id"],
            )


class CursorAndRecoveryTests(LogicalCommunicationFixture):
    def test_concurrent_claims_are_disjoint_and_do_not_advance_cursor(self) -> None:
        recipient = "embodiment:legion"
        for _ in range(6):
            self.append_message([self.target(recipient)])

        def claim(index: int) -> dict[str, Any]:
            return CommunicationStore(self.ledger_a, clock=lambda: NOW).claim(
                recipient_id=recipient,
                consumer_id=f"consumer:{index}",
                claim_id=identifier(69_000_000, index),
                limit=4,
                lease_until_ms=NOW + 1_000,
            )

        with ThreadPoolExecutor(max_workers=2) as workers:
            claims = list(workers.map(claim, (1, 2)))
        sequences = [
            {item["sequence"] for item in claim_result["items"]}
            for claim_result in claims
        ]
        self.assertFalse(sequences[0] & sequences[1])
        self.assertEqual(len(sequences[0] | sequences[1]), 6)
        replay = self.store.claim(
            recipient_id=recipient,
            consumer_id="consumer:1",
            claim_id=identifier(69_000_000, 1),
            limit=4,
            lease_until_ms=NOW + 1_000,
        )
        self.assertEqual(replay, claims[0])
        with self.assertRaisesRegex(CommunicationError, "consumer_prefix_not_terminal"):
            self.store.advance_consumer(
                recipient_id=recipient,
                consumer_id="consumer:1",
                sequence=max(sequences[0]),
            )

    def test_pages_are_lossless_across_large_same_millisecond_backlog(self) -> None:
        recipient = "embodiment:legion"
        message_ids: list[str] = []
        for index in range(105):
            message, _resolution, _result = self.append_message(
                [self.target(recipient, cursor=f"dm:evidence:v1:{index}")]
            )
            message_ids.append(message["event_id"])
        first = self.store.page(
            recipient_id=recipient,
            consumer_id="consumer:direct",
            request_id=identifier(70_000_000, 1),
            cursor=None,
            limit=17,
        )
        cutoff = first["snapshot_highwater"]
        inserted, _resolution, _result = self.append_message(
            [self.target(recipient, cursor="dm:evidence:v1:late")]
        )
        observed = [item["message_id"] for item in first["items"]]
        cursor = first["next_cursor"]
        page_index = 2
        while cursor is not None:
            page = self.store.page(
                recipient_id=recipient,
                consumer_id="consumer:direct",
                request_id=identifier(70_000_000, page_index),
                cursor=cursor,
                limit=17,
            )
            self.assertEqual(page["snapshot_highwater"], cutoff)
            observed.extend(item["message_id"] for item in page["items"])
            cursor = page["next_cursor"]
            page_index += 1
        self.assertEqual(observed, message_ids)
        self.assertNotIn(inserted["event_id"], observed)
        self.assertEqual(len(observed), len(set(observed)))

        current = self.store.page(
            recipient_id=recipient,
            consumer_id="consumer:direct",
            request_id=identifier(70_000_000, 99),
            cursor=None,
            limit=256,
        )
        self.assertEqual(len(current["items"]), 106)
        self.assertEqual(current["items"][-1]["message_id"], inserted["event_id"])

    def test_page_replay_tamper_and_cross_consumer_binding(self) -> None:
        recipient = "embodiment:legion"
        for index in range(3):
            self.append_message(
                [self.target(recipient, cursor=f"dm:evidence:v1:{index}")]
            )
        request_id = identifier(71_000_000, 1)
        first = self.store.page(
            recipient_id=recipient,
            consumer_id="consumer:a",
            request_id=request_id,
            cursor=None,
            limit=1,
        )
        replay = self.store.page(
            recipient_id=recipient,
            consumer_id="consumer:a",
            request_id=request_id,
            cursor=None,
            limit=1,
        )
        self.assertEqual(replay, first)
        with self.assertRaisesRegex(CommunicationError, "page_request_conflict"):
            self.store.page(
                recipient_id=recipient,
                consumer_id="consumer:a",
                request_id=request_id,
                cursor=None,
                limit=2,
            )
        cursor = str(first["next_cursor"])
        with self.assertRaisesRegex(CommunicationError, "cursor_rejected"):
            self.store.page(
                recipient_id=recipient,
                consumer_id="consumer:a",
                request_id=identifier(71_000_000, 2),
                cursor=cursor[:-1] + ("A" if cursor[-1] != "A" else "B"),
                limit=1,
            )
        with self.assertRaisesRegex(CommunicationError, "cursor_rejected"):
            self.store.page(
                recipient_id=recipient,
                consumer_id="consumer:b",
                request_id=identifier(71_000_000, 3),
                cursor=cursor,
                limit=1,
            )

    def test_cursor_advances_only_across_terminal_owned_prefix(self) -> None:
        recipient = "embodiment:legion"
        results = [self.append_message([self.target(recipient)])[2] for _ in range(3)]
        self.receipt(results[1], recipient, "expired")
        second_sequence = results[1]["legs"][0]["sequence"]
        with self.assertRaisesRegex(CommunicationError, "consumer_prefix_not_terminal"):
            self.store.advance_consumer(
                recipient_id=recipient,
                consumer_id="consumer:a",
                sequence=second_sequence,
            )
        self.receipt(results[0], recipient, "failed:transport")
        advanced = self.store.advance_consumer(
            recipient_id=recipient,
            consumer_id="consumer:a",
            sequence=second_sequence,
        )
        self.assertEqual(advanced["sequence"], second_sequence)
        self.assertEqual(
            self.store.advance_consumer(
                recipient_id=recipient,
                consumer_id="consumer:a",
                sequence=second_sequence,
            ),
            advanced,
        )
        with self.assertRaisesRegex(CommunicationError, "consumer_cursor_regression"):
            self.store.advance_consumer(
                recipient_id=recipient,
                consumer_id="consumer:a",
                sequence=results[0]["legs"][0]["sequence"],
            )

    def test_restart_compaction_and_rollback_detection_preserve_authority(self) -> None:
        recipient = "embodiment:legion"
        _message, _resolution, result = self.append_message([self.target(recipient)])
        self.receipt(result, recipient, "delivered")
        sequence = result["legs"][0]["sequence"]
        self.store.advance_consumer(
            recipient_id=recipient,
            consumer_id="consumer:a",
            sequence=sequence,
        )
        removed = self.store.compact(recipient_id=recipient, through_sequence=sequence)
        self.assertEqual(removed["removed"], 1)
        restarted = CommunicationStore(self.ledger_a, clock=lambda: NOW)
        restarted.initialize()
        self.assertTrue(
            restarted.result(result["message_id"], require_terminal=True)["terminal"]
        )
        self.assertEqual(
            restarted.page(
                recipient_id=recipient,
                consumer_id="consumer:a",
                request_id=identifier(72_000_000, 1),
                cursor=None,
                limit=100,
            )["items"],
            [],
        )

        with closing(sqlite3.connect(self.ledger_a.path)) as database:
            counter = int(
                database.execute(
                    "SELECT value FROM communication_meta WHERE key='mutation_counter'"
                ).fetchone()[0]
            )
            database.execute(
                "UPDATE communication_meta SET value=? WHERE key='mutation_counter'",
                (str(counter - 1),),
            )
            database.commit()
        with self.assertRaisesRegex(CommunicationError, "communication_state_rollback"):
            CommunicationStore(self.ledger_a, clock=lambda: NOW).initialize()


class PublicBoundaryAndSchemaTests(LogicalCommunicationFixture):
    def test_authenticated_service_exposes_logical_operations(self) -> None:
        message = self.ledger_a.append_local(
            kind="experience.observed",
            subject="communication",
            payload={
                "schema": MESSAGE_PAYLOAD_SCHEMA,
                "intent": {
                    "operation": "message.send",
                    "scope": "/we",
                    "thread_id": self.thread_id(),
                },
                "body": {"text": "through daemon boundary"},
                "reply": None,
            },
            signer=self.signers["legion"],
            occurred_at_ms=NOW,
        )
        resolution = self.ledger_a.append_local(
            kind="experience.observed",
            subject="communication-resolution",
            payload={
                "schema": RESOLUTION_PAYLOAD_SCHEMA,
                "message_id": message["event_id"],
                "scope": "/we",
                "targets": [self.target("embodiment:legion")],
            },
            signer=self.signers["legion"],
            causal_parents=[message["event_id"]],
            occurred_at_ms=NOW,
        )
        capability = create_capability(
            capability_key("service"),
            client_id="client:dm052",
            methods=sorted(SERVICE_METHODS),
            not_before_ms=NOW - 1,
            not_after_ms=NOW + 1,
        )
        service = HostedWeave(
            self.ledger_a,
            self.signers["legion"],
            {capability.capability_id: capability},
            lambda: NOW,
            "dm:runtime:v1:" + "a" * 43,
            "communication",
        )
        request = create_request(
            capability,
            request_id=identifier(80_000_000, 1),
            issued_at_ms=NOW,
            method="communication.accept",
            params={
                "message_event_id": message["event_id"],
                "resolution_event_id": resolution["event_id"],
            },
            nonce=b"\x01" * 16,
        )
        api_schema = json.loads(
            (ROOT / "schemas/hosted/v1/local-api.schema.json").read_bytes()
        )
        Draft202012Validator(api_schema, format_checker=FormatChecker()).validate(
            request
        )
        response = service.handle(request)
        verified = verify_response(
            response,
            capability,
            expected_request_id=request["request_id"],
            expected_request_hash=request_hash(request),
            expected_server=service.origin,
            expected_runtime=service.runtime_identity,
        )
        self.assertEqual(verified["result"]["message_id"], message["event_id"])
        self.assertEqual(verified["result"]["legs"][0]["state"], "accepted")

    def test_projection_documents_match_closed_schemas(self) -> None:
        _message, _resolution, result = self.append_message(
            [self.target("embodiment:legion")]
        )
        attempt = self.attempt(result["legs"][0]["leg_id"], 9)
        receipt = self.receipt(result, "embodiment:legion", "delivered")
        documents = [
            (
                "schemas/communication/v1/logical-message.schema.json",
                self.store.rebuild_plan(result["message_id"])["projection"],
                True,
            ),
            (
                "schemas/communication/v1/semantic-leg.schema.json",
                self.store.result(result["message_id"])["legs"][0],
                True,
            ),
            (
                "schemas/communication/v1/route-attempt.schema.json",
                attempt,
                True,
            ),
            (
                "schemas/communication/v1/semantic-receipt.schema.json",
                {
                    "schema": "dm.semantic-receipt/v1",
                    "leg_id": result["legs"][0]["leg_id"],
                    "receipt_event_id": receipt["event_id"],
                    "receipt_hash": receipt["content_hash"],
                    "outcome": "delivered",
                },
                True,
            ),
        ]
        for relative, document, should_validate in documents:
            with self.subTest(schema=relative):
                schema = json.loads((ROOT / relative).read_bytes())
                Draft202012Validator.check_schema(schema)
                validator = Draft202012Validator(schema, format_checker=FormatChecker())
                if should_validate:
                    validator.validate(document)

        fixture = json.loads(
            (
                ROOT / "conformance/fixtures/dm052-logical-communication.json"
            ).read_bytes()
        )
        self.assertEqual(fixture["schema"], "dm.communication.fixtures/v1")
        self.assertGreaterEqual(len(fixture["cases"]), 12)
        self.assertEqual(
            fixture["cases"], sorted(fixture["cases"], key=lambda row: row["id"])
        )

    def test_canonical_signature_tamper_fails_before_projection(self) -> None:
        message, resolution, _result = self.append_message(
            [self.target("embodiment:legion")]
        )
        changed = copy.deepcopy(message)
        changed["payload"]["body"]["text"] = "tampered"
        with closing(sqlite3.connect(self.ledger_a.path)) as database:
            database.execute(
                "UPDATE events SET event_json=? WHERE event_id=?",
                (canonical_bytes(changed), message["event_id"]),
            )
            database.commit()
        with self.assertRaisesRegex(CommunicationError, "communication_event_rejected"):
            self.store.accept(
                message_event_id=message["event_id"],
                resolution_event_id=resolution["event_id"],
            )


if __name__ == "__main__":
    unittest.main()
