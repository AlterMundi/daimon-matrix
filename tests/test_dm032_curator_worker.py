from __future__ import annotations

import copy
import hashlib
import json
import os
import subprocess
import sys
import uuid
from collections.abc import Mapping
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, ClassVar
from unittest.mock import patch

from jsonschema import (  # type: ignore[import-untyped]
    Draft202012Validator,
    FormatChecker,
)
from referencing import Registry, Resource

from daimon_matrix.canonical import canonical_bytes
from daimon_matrix.curator import CuratorCoordinator, CuratorError, create_curator_item
from daimon_matrix.curator_worker import (
    DEEPSEEK_HOST,
    DEEPSEEK_MODEL,
    DEEPSEEK_PATH,
    PROMPT_HASH,
    CuratorWorker,
    CuratorWorkerError,
    DeepSeekHTTPS,
    DeepSeekProvider,
    HTTPResponse,
    build_provider_request,
    create_worker_manifest,
    create_worker_profile,
    create_worker_proposal,
    create_worker_registration,
    create_worker_task,
    negotiate_worker_manifest,
    parse_provider_response,
    provider_output_schema,
    validate_worker_manifest,
    validate_worker_profile,
    validate_worker_proposal,
    validate_worker_registration,
    validate_worker_task,
)
from daimon_matrix.curator_worker_process import (
    CuratorProcessError,
    _document,
    _owner_file,
    _secret_reader,
)
from daimon_matrix.memory_policy import (
    create_content_ref,
    create_memory_candidate,
    create_memory_policy,
    evaluate_memory_candidate,
    memory_checkpoint,
)
from tests.test_dm022_ledger import NOW, RootLedgerFixture
from tools.generate_dm032_vectors import generate as generate_vectors

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_ROOT = ROOT / "schemas"
VECTOR_ROOT = ROOT / "vectors/curator-worker/v1"


class ScriptedTransport:
    def __init__(self, responses: list[HTTPResponse | CuratorWorkerError]) -> None:
        self.responses = list(responses)
        self.calls: list[dict[str, Any]] = []

    def __call__(
        self,
        request_body: bytes,
        api_key: bytearray,
        *,
        timeout_ms: int,
        max_response_bytes: int,
    ) -> HTTPResponse:
        self.calls.append(
            {
                "body": request_body,
                "secret": bytes(api_key),
                "timeout_ms": timeout_ms,
                "max_response_bytes": max_response_bytes,
            }
        )
        selected = self.responses.pop(0)
        if isinstance(selected, CuratorWorkerError):
            raise selected
        return selected


class FakeHTTPResponse:
    def __init__(self, body: bytes, *, status: int = 200) -> None:
        self.body = body
        self.status = status
        self.offset = 0

    def read(self, size: int) -> bytes:
        result = self.body[self.offset : self.offset + size]
        self.offset += len(result)
        return result

    def getheaders(self) -> list[tuple[str, str]]:
        return [("Content-Type", "application/json")]


class FakeHTTPSConnection:
    instances: ClassVar[list[FakeHTTPSConnection]] = []
    response_body = b"{}"
    request_error: BaseException | None = None

    def __init__(self, host: str, port: int, **options: Any) -> None:
        self.host = host
        self.port = port
        self.options = options
        self.request_value: tuple[str, str, bytes, Mapping[str, str]] | None = None
        self.closed = False
        self.instances.append(self)

    def request(
        self, method: str, path: str, *, body: bytes, headers: Mapping[str, str]
    ) -> None:
        if self.request_error is not None:
            raise self.request_error
        self.request_value = (method, path, body, headers)

    def getresponse(self) -> FakeHTTPResponse:
        return FakeHTTPResponse(self.response_body)

    def close(self) -> None:
        self.closed = True


class CuratorWorkerTests(RootLedgerFixture):
    def setUp(self) -> None:
        super().setUp()
        self.now = [NOW]
        self.content = b"synthetic memory"
        self.evidence = self.append(
            self.ledger_a,
            "legion",
            "synthetic curator evidence",
            payload={
                "summary": "synthetic curator evidence",
                "session_ref": "session:dm032",
                "lease_ref": "lease:dm032",
            },
        )
        self.policy = create_memory_policy(
            subject_me_id=self.state.being_ref,
            version=1,
            predecessor_policy_id=None,
            automatic_categories=["personal-experience"],
            review_classifications=["protected"],
            plan_ttl_ms=10_000,
        )
        content_ref = create_content_ref(
            sha256=hashlib.sha256(self.content).hexdigest(),
            byte_length=len(self.content),
            media_type="text/plain",
            classification="personal",
        )
        origin = self.origins["legion"]
        self.candidate = create_memory_candidate(
            subject_me_id=self.state.being_ref,
            author_me_id=self.state.being_ref,
            category="personal-experience",
            derivation="body-occurrence",
            context="autobiographical",
            content_ref=content_ref,
            evidence_refs=[self.evidence["event_id"]],
            classification="personal",
            consent="granted",
            safety="clear",
            contradiction="none",
            effect="local-only",
            lane={
                "memory_id": "32000000-0000-4000-8000-000000000001",
                "operation": "assert",
                "sequence": 1,
                "predecessor_event_id": None,
                "predecessor_hash": None,
            },
            body_evidence={
                "body_ref": origin["body_ref"],
                "embodiment_id": origin["embodiment_id"],
                "incarnation_id": origin["incarnation_id"],
                "session_ref": "session:dm032",
                "lease_ref": "lease:dm032",
                "committed_cutoff_event_id": self.evidence["event_id"],
            },
        )
        self.checkpoint = memory_checkpoint(
            self.ledger_a, self.candidate, captured_at_ms=NOW
        )
        self.decision = evaluate_memory_candidate(
            self.policy, self.candidate, self.checkpoint, evaluated_at_ms=NOW
        )
        self.profile = create_worker_profile(
            implementation="deepseek-http-v1",
            secret_handle="secret:deepseek-curator-v1",
        )
        self.registration = create_worker_registration(self.profile, enabled=True)
        self.coordinator = CuratorCoordinator(self.ledger_a, clock=lambda: self.now[0])
        self.item = create_curator_item(
            subject_me_id=self.state.being_ref,
            resource_ref="memory:proposal:dm032",
            work_kind="memory-proposal",
            input_ref=self.candidate["candidate_id"],
            input_hash=hashlib.sha256(canonical_bytes(self.candidate)).hexdigest(),
            coordination_mode="queue-item",
            required_authority="human",
            effect_intent_hash=None,
            queued_at_ms=NOW,
        )
        self.coordinator.enqueue(
            self.item,
            client_id="dm032-test",
            request_id="32000000-0000-4000-8000-000000000002",
        )
        self.claim = self.coordinator.claim(
            item_id=self.item["item_id"],
            claim_id="32000000-0000-4000-8000-000000000003",
            expected_generation=0,
            lease_until_ms=NOW + 8_000,
            fence_evidence=None,
            client_id="dm032-test",
            request_id="32000000-0000-4000-8000-000000000004",
        )
        self.task = create_worker_task(
            attempt_id="32000000-0000-4000-8000-000000000005",
            idempotency_key="a" * 64,
            item=self.item,
            claim=self.claim,
            policy=self.policy,
            candidate=self.candidate,
            checkpoint=self.checkpoint,
            policy_plan=self.decision,
            profile=self.profile,
            allowed_proposal_kinds=["assert"],
            created_at_ms=NOW,
            deadline_ms=NOW + 5_000,
        )

    def provider_output(self, **changes: Any) -> dict[str, Any]:
        value: dict[str, Any] = {
            "proposal_kind": "assert",
            "statement": "Synthetic curated memory",
            "category": "personal-experience",
            "derivation": "body-occurrence",
            "evidence_refs": [self.evidence["event_id"]],
            "contradiction_refs": [],
            "classification_suggestion": "personal",
            "confidence": "medium",
            "uncertainty_labels": ["model-generated"],
            "warnings": [],
        }
        value.update(changes)
        return value

    def response(
        self, output: Mapping[str, Any] | None = None, **changes: Any
    ) -> HTTPResponse:
        envelope: dict[str, Any] = {
            "id": "deepseek-request-synthetic-1",
            "choices": [
                {
                    "finish_reason": "stop",
                    "index": 0,
                    "message": {
                        "content": canonical_bytes(
                            self.provider_output() if output is None else output
                        ).decode("utf-8"),
                        "role": "assistant",
                    },
                }
            ],
            "created": NOW // 1000,
            "model": DEEPSEEK_MODEL,
            "object": "chat.completion",
            "system_fingerprint": "synthetic-fingerprint",
            "usage": {
                "prompt_tokens": 100,
                "completion_tokens": 20,
                "total_tokens": 120,
                "prompt_cache_hit_tokens": 0,
                "prompt_cache_miss_tokens": 100,
                "completion_tokens_details": {"reasoning_tokens": 0},
            },
        }
        envelope.update(changes)
        return HTTPResponse(
            200,
            {"content-type": "application/json; charset=utf-8"},
            canonical_bytes(envelope),
        )

    def worker(self, transport: ScriptedTransport) -> CuratorWorker:
        return CuratorWorker(
            coordinator=self.coordinator,
            provider=DeepSeekProvider(self.profile, self.registration, transport),
            content_resolver=lambda reference: self.content,
            secret_resolver=lambda handle: bytearray(b"synthetic-provider-key"),
            clock=lambda: self.now[0],
        )

    def task_variant(
        self,
        index: int,
        content: bytes,
        *,
        classification: str = "personal",
        consent: str = "granted",
    ) -> tuple[dict[str, Any], bytes]:
        content_ref = create_content_ref(
            sha256=hashlib.sha256(content).hexdigest(),
            byte_length=len(content),
            media_type="text/plain",
            classification=classification,
        )
        origin = self.origins["legion"]
        candidate = create_memory_candidate(
            subject_me_id=self.state.being_ref,
            author_me_id=self.state.being_ref,
            category="personal-experience",
            derivation="body-occurrence",
            context="autobiographical",
            content_ref=content_ref,
            evidence_refs=[self.evidence["event_id"]],
            classification=classification,
            consent=consent,
            safety="clear",
            contradiction="none",
            effect="local-only",
            lane={
                "memory_id": f"32000000-0000-4000-8001-{index:012x}",
                "operation": "assert",
                "sequence": 1,
                "predecessor_event_id": None,
                "predecessor_hash": None,
            },
            body_evidence={
                "body_ref": origin["body_ref"],
                "embodiment_id": origin["embodiment_id"],
                "incarnation_id": origin["incarnation_id"],
                "session_ref": "session:dm032",
                "lease_ref": "lease:dm032",
                "committed_cutoff_event_id": self.evidence["event_id"],
            },
        )
        checkpoint = memory_checkpoint(self.ledger_a, candidate, captured_at_ms=NOW)
        plan = evaluate_memory_candidate(
            self.policy, candidate, checkpoint, evaluated_at_ms=NOW
        )
        item = create_curator_item(
            subject_me_id=self.state.being_ref,
            resource_ref=f"memory:proposal:dm032-{index}",
            work_kind="memory-proposal",
            input_ref=candidate["candidate_id"],
            input_hash=hashlib.sha256(canonical_bytes(candidate)).hexdigest(),
            coordination_mode="queue-item",
            required_authority="human",
            effect_intent_hash=None,
            queued_at_ms=NOW,
        )
        self.coordinator.enqueue(
            item,
            client_id="dm032-variant",
            request_id=f"32000000-0000-4000-8002-{index:012x}",
        )
        claim = self.coordinator.claim(
            item_id=item["item_id"],
            claim_id=f"32000000-0000-4000-8003-{index:012x}",
            expected_generation=0,
            lease_until_ms=NOW + 8_000,
            fence_evidence=None,
            client_id="dm032-variant",
            request_id=f"32000000-0000-4000-8004-{index:012x}",
        )
        return (
            create_worker_task(
                attempt_id=f"32000000-0000-4000-8005-{index:012x}",
                idempotency_key=hashlib.sha256(
                    f"dm032-variant:{index}".encode()
                ).hexdigest(),
                item=item,
                claim=claim,
                policy=self.policy,
                candidate=candidate,
                checkpoint=checkpoint,
                policy_plan=plan,
                profile=self.profile,
                allowed_proposal_kinds=["assert"],
                created_at_ms=NOW,
                deadline_ms=NOW + 5_000,
            ),
            content,
        )

    def test_manifest_profile_and_task_are_closed_and_authority_denied(self) -> None:
        manifest = create_worker_manifest(
            max_input_bytes=32_768,
            max_output_bytes=65_536,
            max_runtime_ms=30_000,
        )
        self.assertEqual(validate_worker_manifest(manifest), manifest)
        self.assertEqual(
            negotiate_worker_manifest(manifest, accepted_versions=["v1"])["status"],
            "accepted",
        )
        for versions in ([], ["v0"], ["v1", "v2"]):
            with self.assertRaisesRegex(CuratorWorkerError, "contract_unsupported"):
                negotiate_worker_manifest(manifest, accepted_versions=versions)
        self.assertEqual(
            manifest["authority"], {key: False for key in manifest["authority"]}
        )
        self.assertEqual(validate_worker_profile(self.profile), self.profile)
        self.assertEqual(
            validate_worker_registration(self.registration, profile=self.profile),
            self.registration,
        )
        self.assertEqual(
            validate_worker_task(self.task, profile=self.profile), self.task
        )
        with self.assertRaisesRegex(CuratorWorkerError, "authority_escalation"):
            validate_worker_manifest(
                {
                    **manifest,
                    "authority": {**manifest["authority"], "may_sign_as_me": True},
                }
            )
        with self.assertRaisesRegex(CuratorWorkerError, "task_id_mismatch"):
            validate_worker_task(
                {**self.task, "deadline_ms": NOW + 4_000},
                profile=self.profile,
            )
        with self.assertRaisesRegex(CuratorWorkerError, "registration_mismatch"):
            validate_worker_registration(
                {**self.registration, "profile_hash": "0" * 64},
                profile=self.profile,
            )

        disabled = create_worker_registration(self.profile, enabled=False)
        transport = ScriptedTransport([self.response()])
        provider = DeepSeekProvider(self.profile, disabled, transport)
        with self.assertRaisesRegex(CuratorWorkerError, "registration_disabled"):
            provider.invoke(
                self.task,
                self.content,
                lambda _handle: bytearray(b"synthetic-provider-key"),
            )
        self.assertEqual(transport.calls, [])

    def test_request_is_deterministic_nonthinking_toolless_and_injection_is_data(
        self,
    ) -> None:
        request, raw = build_provider_request(self.task, self.profile, self.content)
        second, second_raw = build_provider_request(
            copy.deepcopy(self.task), copy.deepcopy(self.profile), self.content
        )
        self.assertEqual(request, second)
        self.assertEqual(raw, second_raw)
        self.assertEqual(request["thinking"], {"type": "disabled"})
        self.assertNotIn("tools", request)
        self.assertEqual(request["response_format"], {"type": "json_object"})
        self.assertIn(PROMPT_HASH, canonical_bytes(self.task).decode("utf-8"))

        provider_input = json.loads(request["messages"][1]["content"])
        self.assertEqual(provider_input["evidence"], self.content.decode("utf-8"))
        self.assertEqual(len(request["messages"]), 2)

    def test_disclosure_policy_and_final_body_scan_refuse_before_network(self) -> None:
        for index, classification in enumerate(("private", "protected"), start=20):
            task, content = self.task_variant(
                index, b"synthetic sensitive memory", classification=classification
            )
            with (
                self.subTest(classification=classification),
                self.assertRaisesRegex(CuratorWorkerError, "disclosure_refused"),
            ):
                build_provider_request(task, self.profile, content)

        injected, content = self.task_variant(
            22, b"innocent prefix api_key=synthetic-forbidden-value"
        )
        with self.assertRaisesRegex(CuratorWorkerError, "disclosure_refused"):
            build_provider_request(injected, self.profile, content)

        with self.assertRaisesRegex(CuratorWorkerError, "policy_refused"):
            self.task_variant(23, b"consent denied", consent="denied")

    def test_response_status_shape_and_limits_are_typed(self) -> None:
        cases: list[tuple[HTTPResponse, str, bool]] = [
            (
                HTTPResponse(
                    429,
                    {"content-type": "application/json", "retry-after": "3"},
                    b"{}",
                ),
                "transient_failure",
                True,
            ),
            (
                HTTPResponse(401, {"content-type": "application/json"}, b"{}"),
                "request_refused",
                False,
            ),
            (
                HTTPResponse(200, {"content-type": "text/plain"}, b"{}"),
                "boundary_mismatch",
                False,
            ),
            (
                HTTPResponse(
                    200, {"content-type": "application/json"}, b'{"id":1,"id":2}'
                ),
                "duplicate_field",
                False,
            ),
            (
                self.response(choices=[]),
                "choice_mismatch",
                False,
            ),
            (
                self.response(
                    choices=[
                        {
                            "finish_reason": "stop",
                            "index": 0,
                            "message": {
                                "content": "{}",
                                "role": "assistant",
                                "tool_calls": [],
                            },
                        }
                    ]
                ),
                "shape_invalid",
                False,
            ),
        ]
        for response, code, retryable in cases:
            with (
                self.subTest(code=code),
                self.assertRaisesRegex(CuratorWorkerError, code) as raised,
            ):
                parse_provider_response(response, self.task, self.profile)
            self.assertEqual(raised.exception.retryable, retryable)
        with self.assertRaisesRegex(CuratorWorkerError, "transient_failure") as rate:
            parse_provider_response(cases[0][0], self.task, self.profile)
        self.assertEqual(rate.exception.retry_after_ms, 3_000)

    def test_https_transport_pins_origin_bounds_read_and_redacts_failures(self) -> None:
        FakeHTTPSConnection.instances = []
        FakeHTTPSConnection.response_body = b'{"synthetic":true}'
        FakeHTTPSConnection.request_error = None
        with patch(
            "daimon_matrix.curator_worker.http.client.HTTPSConnection",
            FakeHTTPSConnection,
        ):
            response = DeepSeekHTTPS()(
                b'{"request":true}',
                bytearray(b"synthetic-provider-key"),
                timeout_ms=1_250,
                max_response_bytes=128,
            )
        connection = FakeHTTPSConnection.instances[0]
        self.assertEqual((connection.host, connection.port), (DEEPSEEK_HOST, 443))
        self.assertEqual(connection.options["timeout"], 1.25)
        request_value = connection.request_value
        self.assertIsNotNone(request_value)
        assert request_value is not None
        self.assertEqual(request_value[0:2], ("POST", DEEPSEEK_PATH))
        self.assertEqual(response.body, FakeHTTPSConnection.response_body)
        self.assertTrue(connection.closed)

        FakeHTTPSConnection.instances = []
        FakeHTTPSConnection.response_body = b"x" * 129
        with (
            patch(
                "daimon_matrix.curator_worker.http.client.HTTPSConnection",
                FakeHTTPSConnection,
            ),
            self.assertRaisesRegex(CuratorWorkerError, "response_too_large"),
        ):
            DeepSeekHTTPS()(
                b"{}",
                bytearray(b"synthetic-provider-key"),
                timeout_ms=1_250,
                max_response_bytes=128,
            )

        FakeHTTPSConnection.instances = []
        FakeHTTPSConnection.request_error = OSError(
            "synthetic-provider-key must never cross this boundary"
        )
        with (
            patch(
                "daimon_matrix.curator_worker.http.client.HTTPSConnection",
                FakeHTTPSConnection,
            ),
            self.assertRaisesRegex(
                CuratorWorkerError, "provider_transport_failure"
            ) as raised,
        ):
            DeepSeekHTTPS()(
                b"{}",
                bytearray(b"synthetic-provider-key"),
                timeout_ms=1_250,
                max_response_bytes=128,
            )
        self.assertNotIn("synthetic-provider-key", str(raised.exception))
        FakeHTTPSConnection.request_error = None

    def test_success_is_inert_review_required_and_exactly_once(self) -> None:
        transport = ScriptedTransport([self.response()])
        worker = self.worker(transport)
        request_id = "32000000-0000-4000-8000-000000000006"
        first = worker.run(self.task, completion_request_id=request_id)
        second = worker.run(self.task, completion_request_id=request_id)
        self.assertEqual(first, second)
        self.assertEqual(len(transport.calls), 1)
        self.assertEqual(first["authority"], "evidence-only")
        self.assertEqual(validate_worker_proposal(first), first)
        inspection = self.coordinator.inspect(self.item["item_id"])
        self.assertEqual(inspection["state"], "review-required")
        self.assertEqual(inspection["result"]["output_refs"], [first["proposal_id"]])
        self.assertEqual(
            [
                event
                for event in self.ledger_a.events()
                if event["kind"] == "memory.recorded"
            ],
            [],
        )

    def test_secret_is_jit_and_mutable_buffer_is_cleared(self) -> None:
        captured: list[bytearray] = []
        transport = ScriptedTransport([self.response()])

        def resolve(_handle: str) -> bytearray:
            secret = bytearray(b"synthetic-provider-key")
            captured.append(secret)
            return secret

        worker = CuratorWorker(
            self.coordinator,
            DeepSeekProvider(self.profile, self.registration, transport),
            lambda _reference: self.content,
            resolve,
            lambda: self.now[0],
        )
        worker.run(
            self.task,
            completion_request_id="32000000-0000-4000-8000-000000000007",
        )
        self.assertEqual(captured[0], bytearray(len(captured[0])))
        self.assertNotIn(b"synthetic-provider-key", transport.calls[0]["body"])

    def test_transient_failure_retries_but_schema_failure_does_not(self) -> None:
        transport = ScriptedTransport(
            [
                CuratorWorkerError("provider_transport_failure", retryable=True),
                self.response(),
            ]
        )
        worker = self.worker(transport)
        worker.run(
            self.task,
            completion_request_id="32000000-0000-4000-8000-000000000008",
        )
        self.assertEqual(len(transport.calls), 2)

    def test_attempt_budget_survives_restart_and_defers_exactly_once(self) -> None:
        first = self.worker(ScriptedTransport([]))
        value = first._revalidate(self.task)
        first._mark_requested(value)
        self.assertEqual(first._next_attempt(value["task_id"], 2), 1)
        first._record_retryable_error(value["task_id"], "provider_transport_failure")

        transport = ScriptedTransport(
            [CuratorWorkerError("provider_transport_failure", retryable=True)]
        )
        restarted = self.worker(transport)
        request_id = "32000000-0000-4000-8000-000000000011"
        with self.assertRaisesRegex(CuratorWorkerError, "provider_transport_failure"):
            restarted.run(value, completion_request_id=request_id)
        self.assertEqual(len(transport.calls), 1)
        inspection = self.coordinator.inspect(self.item["item_id"])
        self.assertEqual(inspection["state"], "deferred")
        self.assertEqual(inspection["result"]["outcome"], "deferred")

        replay_transport = ScriptedTransport([])
        with self.assertRaisesRegex(CuratorWorkerError, "provider_transport_failure"):
            self.worker(replay_transport).run(value, completion_request_id=request_id)
        self.assertEqual(replay_transport.calls, [])

    def test_nonretryable_provider_refusal_is_durable_failed(self) -> None:
        transport = ScriptedTransport([self.response(model="deepseek-v4-flash")])
        request_id = "32000000-0000-4000-8000-000000000012"
        with self.assertRaisesRegex(CuratorWorkerError, "model_mismatch"):
            self.worker(transport).run(self.task, completion_request_id=request_id)
        self.assertEqual(len(transport.calls), 1)
        inspection = self.coordinator.inspect(self.item["item_id"])
        self.assertEqual(inspection["state"], "failed")
        self.assertEqual(inspection["result"]["outcome"], "failed")

    def test_terminal_row_recovers_dm031_completion_after_process_loss(self) -> None:
        worker = self.worker(ScriptedTransport([]))
        value = worker._revalidate(self.task)
        worker._mark_requested(value)
        worker._store_terminal(
            value, outcome="deferred", error_code="provider_secret_unavailable"
        )
        self.assertEqual(
            self.coordinator.inspect(self.item["item_id"])["state"], "claimed"
        )
        request_id = "32000000-0000-4000-8000-000000000013"
        with self.assertRaisesRegex(CuratorWorkerError, "provider_secret_unavailable"):
            self.worker(ScriptedTransport([])).run(
                value, completion_request_id=request_id
            )
        self.assertEqual(
            self.coordinator.inspect(self.item["item_id"])["state"], "deferred"
        )

    def test_response_cost_budget_is_fail_closed(self) -> None:
        low_budget = create_worker_profile(
            implementation="deepseek-http-v1",
            secret_handle="secret:deepseek-curator-v1",
            max_cost_microusd=1,
        )
        with self.assertRaisesRegex(CuratorWorkerError, "cost_budget_exceeded"):
            parse_provider_response(self.response(), self.task, low_budget)

    def test_model_reasoning_tool_shape_and_evidence_substitution_fail_closed(
        self,
    ) -> None:
        cases = [
            self.response(model="deepseek-v4-flash"),
            self.response(
                choices=[
                    {
                        "finish_reason": "stop",
                        "index": 0,
                        "message": {
                            "content": "{}",
                            "role": "assistant",
                            "reasoning_content": "hidden",
                        },
                    }
                ]
            ),
            self.response(self.provider_output(evidence_refs=[str(uuid.uuid4())])),
            self.response(self.provider_output(contradiction_refs=[str(uuid.uuid4())])),
        ]
        for index, response in enumerate(cases):
            with self.subTest(index=index), self.assertRaises(CuratorWorkerError):
                parse_provider_response(response, self.task, self.profile)

    def test_stale_checkpoint_refuses_before_provider(self) -> None:
        self.append(self.ledger_a, "legion", "state changed after task")
        transport = ScriptedTransport([self.response()])
        with self.assertRaisesRegex(CuratorWorkerError, "checkpoint_stale"):
            self.worker(transport).run(
                self.task,
                completion_request_id="32000000-0000-4000-8000-000000000009",
            )
        self.assertEqual(transport.calls, [])

    def test_persisted_proposal_finishes_dm031_after_response_loss(self) -> None:
        transport = ScriptedTransport([self.response()])
        provider = DeepSeekProvider(self.profile, self.registration, transport)
        worker = self.worker(transport)
        value = worker._revalidate(self.task)
        worker._mark_requested(value)
        output, metadata, request_hash = provider.invoke(
            value, self.content, lambda _handle: bytearray(b"synthetic-provider-key")
        )
        proposal, content = create_worker_proposal(
            task=value,
            profile=self.profile,
            provider_output=output,
            metadata=metadata,
            request_hash=request_hash,
            produced_at_ms=NOW,
        )
        worker._store_proposal(value, proposal, content)
        replay = worker.run(
            value,
            completion_request_id="32000000-0000-4000-8000-000000000010",
        )
        self.assertEqual(replay, proposal)
        self.assertEqual(len(transport.calls), 1)
        self.assertEqual(
            self.coordinator.inspect(self.item["item_id"])["state"],
            "review-required",
        )

    def test_dm031_completion_response_loss_never_reinvokes_provider(self) -> None:
        transport = ScriptedTransport([self.response()])
        worker = self.worker(transport)
        original = self.coordinator.complete

        def lose_response(
            _coordinator: CuratorCoordinator, **arguments: Any
        ) -> dict[str, Any]:
            original(**arguments)
            raise CuratorError("synthetic_completion_response_loss", retryable=True)

        request_id = "32000000-0000-4000-8000-000000000014"
        with (
            patch.object(CuratorCoordinator, "complete", lose_response),
            self.assertRaisesRegex(CuratorWorkerError, "completion_unavailable"),
        ):
            worker.run(self.task, completion_request_id=request_id)
        replay = worker.run(self.task, completion_request_id=request_id)
        self.assertEqual(len(transport.calls), 1)
        self.assertEqual(
            self.coordinator.inspect(self.item["item_id"])["result"]["output_refs"],
            [replay["proposal_id"]],
        )

    def test_public_schemas_match_runtime_artifacts_and_are_closed(self) -> None:
        transport = ScriptedTransport([self.response()])
        output, metadata, request_hash = DeepSeekProvider(
            self.profile, self.registration, transport
        ).invoke(
            self.task,
            self.content,
            lambda _handle: bytearray(b"synthetic-provider-key"),
        )
        proposal, _content = create_worker_proposal(
            task=self.task,
            profile=self.profile,
            provider_output=output,
            metadata=metadata,
            request_hash=request_hash,
            produced_at_ms=NOW,
        )
        documents = {
            "profile.schema.json": self.profile,
            "registration.schema.json": self.registration,
            "task.schema.json": self.task,
            "provider-output.schema.json": output,
            "proposal.schema.json": proposal,
        }
        resources: list[tuple[str, dict[str, Any]]] = []
        schemas: dict[str, dict[str, Any]] = {}
        for path in SCHEMA_ROOT.rglob("*.schema.json"):
            schema = json.loads(path.read_text(encoding="utf-8"))
            resources.append((schema["$id"], schema))
            schemas[path.name] = schema
        registry = Registry().with_resources(
            (uri, Resource.from_contents(schema)) for uri, schema in resources
        )
        for filename, document in documents.items():
            validator = Draft202012Validator(
                schemas[filename], registry=registry, format_checker=FormatChecker()
            )
            self.assertEqual(list(validator.iter_errors(document)), [])
            self.assertTrue(list(validator.iter_errors({**document, "unknown": True})))
        self.assertEqual(
            provider_output_schema(), schemas["provider-output.schema.json"]
        )
        example = json.loads(
            (ROOT / "config/examples/curator-worker-deepseek-v1.json").read_bytes()
        )
        placeholder_profile = create_worker_profile(
            implementation="deepseek-http-v1",
            secret_handle="secret:PLACEHOLDER_OWNER_ONLY_REFERENCE",
        )
        self.assertEqual(
            validate_worker_registration(example, profile=placeholder_profile),
            example,
        )
        example_validator = Draft202012Validator(
            schemas["registration.schema.json"],
            registry=registry,
            format_checker=FormatChecker(),
        )
        self.assertEqual(list(example_validator.iter_errors(example)), [])

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
        validate_worker_manifest(artifacts["manifest"])
        validate_worker_profile(artifacts["profile"])
        validate_worker_registration(
            artifacts["registration_disabled"], profile=artifacts["profile"]
        )
        validate_worker_task(artifacts["task"], profile=artifacts["profile"])
        validate_worker_proposal(artifacts["proposal"])
        self.assertEqual(
            hashlib.sha256(
                (VECTOR_ROOT / "proposal-content.txt").read_bytes()
            ).hexdigest(),
            index["binary_sha256"]["proposal_content"],
        )
        with self.assertRaisesRegex(CuratorWorkerError, "task_id_mismatch"):
            validate_worker_task(
                artifacts["negative_task"], profile=artifacts["profile"]
            )
        with TemporaryDirectory(prefix="dm032-vectors-") as directory:
            generated = Path(directory)
            generate_vectors(generated)
            expected = {
                path.relative_to(VECTOR_ROOT): path.read_bytes()
                for path in VECTOR_ROOT.rglob("*")
                if path.is_file()
            }
            actual = {
                path.relative_to(generated): path.read_bytes()
                for path in generated.rglob("*")
                if path.is_file()
            }
            self.assertEqual(actual, expected)

    def test_installed_process_files_and_secret_descriptor_fail_closed(self) -> None:
        with TemporaryDirectory(prefix="dm032-process-") as directory:
            root = Path(directory)
            root.chmod(0o700)
            document = root / "profile.json"
            document.write_bytes(canonical_bytes(self.profile))
            document.chmod(0o600)
            self.assertEqual(_document(root, "profile.json"), self.profile)
            self.assertEqual(
                _owner_file(root, "profile.json", maximum=512 * 1024),
                canonical_bytes(self.profile),
            )
            document.chmod(0o644)
            with self.assertRaisesRegex(CuratorProcessError, "file_refused"):
                _owner_file(root, "profile.json", maximum=512 * 1024)
            document.chmod(0o600)
            (root / "profile-link.json").symlink_to(document)
            with self.assertRaisesRegex(CuratorProcessError, "file_unavailable"):
                _owner_file(root, "profile-link.json", maximum=512 * 1024)
            with self.assertRaisesRegex(CuratorProcessError, "filename_refused"):
                _owner_file(root, "../profile.json", maximum=512 * 1024)

        read_descriptor, write_descriptor = os.pipe()
        os.write(write_descriptor, b"synthetic-provider-key")
        os.close(write_descriptor)
        resolver = _secret_reader(read_descriptor, self.profile["secret_handle"])
        with self.assertRaisesRegex(CuratorWorkerError, "secret_unavailable"):
            resolver("secret:substituted")
        secret = resolver(self.profile["secret_handle"])
        self.assertEqual(secret, bytearray(b"synthetic-provider-key"))
        with self.assertRaisesRegex(CuratorWorkerError, "secret_unavailable"):
            resolver(self.profile["secret_handle"])
        for index in range(len(secret)):
            secret[index] = 0

        process = subprocess.run(
            [sys.executable, "-m", "daimon_matrix.curator_worker_process", "--help"],
            cwd=ROOT,
            env=os.environ.copy(),
            capture_output=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(process.returncode, 0)
        self.assertNotIn(b"synthetic-provider-key", process.stdout + process.stderr)


if __name__ == "__main__":
    import unittest

    unittest.main()
