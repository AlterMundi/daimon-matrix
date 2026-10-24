from __future__ import annotations

import copy
import hashlib
import hmac
import json
import sqlite3
import unittest
from contextlib import closing
from dataclasses import replace
from typing import Any
from unittest.mock import patch

from daimon_matrix.canonical import b64url, canonical_bytes
from daimon_matrix.communication import MESSAGE_PAYLOAD_SCHEMA
from daimon_matrix.identity import create_incarnation_authorization
from daimon_matrix.labels import LABEL_SCHEMA, LabelIndex
from daimon_matrix.ledger import Ledger
from daimon_matrix.local_api import (
    REQUEST_DOMAIN,
    LocalApiError,
    LocalCapability,
    create_capability,
    create_request,
    decode_document,
    decode_frame,
    encode_frame,
    request_hash,
    verify_response,
)
from daimon_matrix.runtime import RuntimeError as HostedRuntimeError
from daimon_matrix.runtime import load_label_index
from daimon_matrix.service import (
    METHODS,
    OBSERVE_METHODS,
    OPERATOR_CAPABILITY_PROFILES,
    HostedWeave,
    ServiceError,
)
from daimon_matrix.weave import BeingManifest, RootAuthority, create_event
from tests.test_dm022_ledger import NOW, RootLedgerFixture


def rpc_id(index: int) -> str:
    return f"10000000-0000-4000-8000-{index:012d}"


def sync_id(index: int) -> str:
    return f"20000000-0000-4000-8000-{index:012d}"


def key(label: str) -> bytes:
    return hashlib.sha256(f"dm024-local-api:{label}".encode()).digest()


class HostedServiceTests(RootLedgerFixture):
    def setUp(self) -> None:
        super().setUp()
        self.capability = create_capability(
            key("client"),
            client_id="client:synthetic-admin",
            methods=sorted(METHODS),
            not_before_ms=NOW - 10_000,
            not_after_ms=NOW + 10_000,
        )
        capabilities = {self.capability.capability_id: self.capability}
        self.service_a = HostedWeave(
            self.ledger_a,
            self.signers["legion"],
            capabilities,
            lambda: NOW,
            "dm:runtime:v1:" + "a" * 43,
            "service-a",
        )
        self.service_b = HostedWeave(
            self.ledger_b,
            self.signers["daimonmatrix"],
            capabilities,
            lambda: NOW,
            "dm:runtime:v1:" + "b" * 43,
            "service-b",
        )

    def request(
        self,
        index: int,
        method: str,
        params: dict[str, Any],
        *,
        capability: LocalCapability | None = None,
    ) -> dict[str, Any]:
        return create_request(
            self.capability if capability is None else capability,
            request_id=rpc_id(index),
            issued_at_ms=NOW,
            method=method,
            params=params,
            nonce=index.to_bytes(16, "big"),
        )

    def invoke(
        self,
        service: HostedWeave,
        index: int,
        method: str,
        params: dict[str, Any],
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        request = self.request(index, method, params)
        response = service.handle(request)
        verify_response(
            response,
            self.capability,
            expected_request_id=request["request_id"],
            expected_request_hash=request_hash(request),
            expected_server=service.origin,
            expected_runtime=service.runtime_identity,
        )
        return request, response

    def observe_params(self, subject: str) -> dict[str, Any]:
        return {
            "subject": subject,
            "payload": {"summary": subject},
            "sensitivity": "personal",
            "causal_parents": [],
            "occurred_at_ms": NOW,
            "event_id": None,
        }

    def test_canonical_framing_authentication_and_scope_fail_closed(self) -> None:
        request = self.request(1, "runtime.status", {})
        self.assertEqual(decode_frame(encode_frame(request)), request)
        with self.assertRaisesRegex(LocalApiError, "duplicate_json_key"):
            decode_document(b'{"a":1,"a":2}')
        with self.assertRaisesRegex(LocalApiError, "noncanonical_frame"):
            decode_document(b'{ "a":1}')
        with self.assertRaisesRegex(LocalApiError, "truncated_or_trailing_frame"):
            decode_frame(encode_frame(request) + b"x")

        tampered = copy.deepcopy(request)
        tampered["params"] = {"unexpected": True}
        with self.assertRaisesRegex(LocalApiError, "authentication_failed"):
            self.service_a.handle(tampered)

        read_only = create_capability(
            key("read-only"),
            client_id="client:read-only",
            methods=["runtime.status"],
            not_before_ms=NOW - 1,
            not_after_ms=NOW + 1,
        )
        with self.assertRaisesRegex(LocalApiError, "authentication_failed"):
            self.request(
                2,
                "we.observe",
                self.observe_params("forbidden"),
                capability=read_only,
            )
        expired = create_capability(
            key("expired"),
            client_id="client:expired",
            methods=["runtime.status"],
            not_before_ms=NOW - 100,
            not_after_ms=NOW - 1,
        )
        expired_request = create_request(
            expired,
            request_id=rpc_id(3),
            issued_at_ms=NOW - 2,
            method="runtime.status",
            params={},
            nonce=b"e" * 16,
        )
        with self.assertRaisesRegex(LocalApiError, "authentication_failed"):
            self.service_a.handle(expired_request)
        with self.assertRaisesRegex(LocalApiError, "authentication_failed"):
            create_request(
                expired,
                request_id=rpc_id(4),
                issued_at_ms=NOW - 1,
                method="runtime.status",
                params={},
                nonce=b"x" * 16,
            )

    def test_observe_and_decide_are_durably_idempotent(self) -> None:
        observe_request, observe_response = self.invoke(
            self.service_a, 10, "we.observe", self.observe_params("local-observation")
        )
        self.assertTrue(observe_response["ok"])
        self.assertEqual(
            canonical_bytes(self.service_a.handle(observe_request)),
            canonical_bytes(observe_response),
        )
        target = observe_response["result"]["event"]
        self.assertEqual(len(self.ledger_a.events()), 1)

        changed = self.request(10, "we.observe", self.observe_params("conflict"))
        conflict = self.service_a.handle(changed)
        self.assertFalse(conflict["ok"])
        self.assertEqual(conflict["error"]["code"], "request_conflict")
        self.assertEqual(len(self.ledger_a.events()), 1)
        self.assertIn(
            "rpc_request", {item["lane"] for item in self.ledger_a.equivocations()}
        )

        _, adopted = self.invoke(
            self.service_a,
            11,
            "we.decide",
            {
                "target_event_id": target["event_id"],
                "decision": "adopt",
                "reason": "local acceptance",
                "supersedes": None,
                "sensitivity": "personal",
                "occurred_at_ms": NOW + 1,
                "event_id": None,
            },
        )
        adoption = adopted["result"]["event"]
        _, non_projectable = self.invoke(
            self.service_a,
            14,
            "we.decide",
            {
                "target_event_id": adoption["event_id"],
                "decision": "adopt",
                "reason": "invalid target kind",
                "supersedes": None,
                "sensitivity": "personal",
                "occurred_at_ms": NOW + 2,
                "event_id": None,
            },
        )
        self.assertFalse(non_projectable["ok"])
        self.assertEqual(non_projectable["error"]["code"], "target_not_projectable")
        _, reverted = self.invoke(
            self.service_a,
            12,
            "we.decide",
            {
                "target_event_id": target["event_id"],
                "decision": "revert",
                "reason": "local reversal",
                "supersedes": adoption["event_id"],
                "sensitivity": "personal",
                "occurred_at_ms": NOW + 2,
                "event_id": None,
            },
        )
        self.assertTrue(reverted["ok"])
        _, diff = self.invoke(
            self.service_a,
            13,
            "we.diff",
            {"after": None, "kind": None, "limit": 10, "subject": None},
        )
        self.assertEqual(diff["result"]["entries"][0]["state"], "reverted")
        self.assertEqual(len(self.ledger_a.events()), 3)
        self.assertEqual(self.ledger_a.rpc_requests()[0]["state"], "completed")

    def test_typed_proposals_preserve_kind_and_exact_retry(self) -> None:
        for index, kind in enumerate(
            ("configuration.proposed", "skill.proposed"), 1000
        ):
            params = dict(self.observe_params("selected-customization"), kind=kind)
            params["payload"] = {
                "content_sha256": "a" * 64,
                "authority": "unsigned-native",
            }
            request, response = self.invoke(self.service_a, index, "we.propose", params)
            self.assertTrue(response["ok"])
            self.assertEqual(response["result"]["schema"], "dm.we.proposal-result/v1")
            event = response["result"]["event"]
            self.assertEqual(event["kind"], kind)
            self.assertEqual(event["origin"], self.service_a.origin)
            self.assertEqual(self.service_a.handle(request), response)
        self.assertEqual(len(self.ledger_a.events()), 2)
        self.assertTrue(
            all(
                entry["state"] == "pending"
                for entry in self.service_a._diff(
                    {"after": None, "kind": None, "limit": 10, "subject": None}
                )["entries"]
            )
        )

    def test_typed_proposals_do_not_widen_the_observe_profile(self) -> None:
        self.assertNotIn("we.propose", OBSERVE_METHODS)
        self.assertIn("we.propose", OPERATOR_CAPABILITY_PROFILES["weave"])
        self.assertIn("we.event.get", OBSERVE_METHODS)
        observer = create_capability(
            key("observer"),
            client_id="client:observer",
            methods=sorted(OBSERVE_METHODS),
            not_before_ms=NOW - 1,
            not_after_ms=NOW + 1,
        )
        observe_only = replace(
            self.service_a, capabilities={observer.capability_id: observer}
        )
        request = self.request(1010, "runtime.status", {}, capability=observer)
        request["method"] = "we.propose"
        request["params"] = dict(
            self.observe_params("refused"), kind="configuration.proposed"
        )
        # A prohibited method cannot pass create_request's client-side gate.
        # Sign it correctly as this known observer to exercise the server gate.
        core = {key: value for key, value in request.items() if key != "auth"}
        request["auth"]["value"] = b64url(
            hmac.digest(observer.key, REQUEST_DOMAIN + canonical_bytes(core), "sha256")
        )
        with self.assertRaisesRegex(LocalApiError, "authentication_failed"):
            observe_only.handle(request)
        self.assertEqual(self.ledger_a.events(), [])

    def test_proposal_cannot_select_another_kind_or_change_observe(self) -> None:
        kinds: tuple[Any, ...] = (
            "experience.observed",
            "memory.recorded",
            "projection.receipted",
            "adoption.decided",
            None,
            [],
            {},
        )
        for index, kind in enumerate(kinds, 1020):
            _, result = self.invoke(
                self.service_a,
                index,
                "we.propose",
                dict(self.observe_params("refused"), kind=kind),
            )
            self.assertFalse(result["ok"])
            self.assertEqual(result["error"]["code"], "invalid_params")
        _, observed = self.invoke(
            self.service_a,
            1030,
            "we.observe",
            dict(self.observe_params("refused"), kind="configuration.proposed"),
        )
        self.assertFalse(observed["ok"])
        self.assertEqual(observed["error"]["code"], "invalid_params")
        self.assertEqual(self.ledger_a.events(), [])

    def test_exact_event_read_excludes_unknown_and_incomplete_events(self) -> None:
        dependent = create_event(
            self.authority,
            self.origins["daimonmatrix"],
            self.signers["daimonmatrix"],
            event_id=rpc_id(1040),
            sequence=1,
            previous_event_id=None,
            occurred_at_ms=NOW,
            causal_parents=[rpc_id(1041)],
            kind="configuration.proposed",
            subject="pending-source",
            payload={"content_sha256": "b" * 64},
        )
        self.ledger_a.ingest([dependent], source="same-being-peer")
        for index, event_id in enumerate((dependent["event_id"], rpc_id(1042)), 1043):
            _, response = self.invoke(
                self.service_a, index, "we.event.get", {"event_id": event_id}
            )
            self.assertTrue(response["ok"])
            self.assertEqual(
                response["result"], {"schema": "dm.we.event-result/v1", "event": None}
            )
        self.assertEqual(self.ledger_a.incomplete_count(), 1)

    def test_authenticated_sync_receipt_and_import_is_not_adoption(self) -> None:
        _, observed = self.invoke(
            self.service_b,
            20,
            "we.propose",
            dict(
                self.observe_params("remote-customization"),
                kind="configuration.proposed",
            ),
        )
        remote_event = observed["result"]["event"]
        _, request_response = self.invoke(
            self.service_a,
            21,
            "we.sync.request",
            {"request_id": sync_id(1), "limit": 1},
        )
        sync_request = request_response["result"]
        transport_a = {
            "scheme": "tribe-v1",
            "principal_id": self.origins["legion"]["principal_id"],
        }
        _, served = self.invoke(
            self.service_b,
            22,
            "we.sync.serve",
            {"request": sync_request, "transport": transport_a},
        )
        delta = served["result"]
        transport_b = {
            "scheme": "tribe-v1",
            "principal_id": self.origins["daimonmatrix"]["principal_id"],
        }
        pull_request, pulled = self.invoke(
            self.service_a,
            23,
            "we.sync.pull",
            {"delta": delta, "transport": transport_b},
        )
        receipt = pulled["result"]
        self.assertEqual(receipt["inserted"], 1)
        self.assertEqual(
            canonical_bytes(self.service_a.handle(pull_request)),
            canonical_bytes(pulled),
        )
        _, validated = self.invoke(
            self.service_b,
            24,
            "we.sync.validate-receipt",
            {"receipt": receipt, "transport": transport_a},
        )
        self.assertEqual(validated["result"], receipt)

        _, diff = self.invoke(
            self.service_a,
            25,
            "we.diff",
            {"after": None, "kind": None, "limit": 10, "subject": None},
        )
        entry = diff["result"]["entries"][0]
        self.assertEqual(entry["event_id"], remote_event["event_id"])
        self.assertEqual(entry["state"], "pending")
        _, fetched = self.invoke(
            self.service_a, 27, "we.event.get", {"event_id": remote_event["event_id"]}
        )
        self.assertEqual(fetched["result"]["event"], remote_event)
        self.assertEqual(fetched["result"]["event"]["origin"], self.service_b.origin)
        self.assertNotEqual(fetched["result"]["event"]["origin"], self.service_a.origin)

        wrong_transport = self.request(
            26,
            "we.sync.serve",
            {
                "request": sync_request,
                "transport": {
                    "scheme": "tribe-v1",
                    "principal_id": self.origins["daimonmatrix"]["principal_id"],
                },
            },
        )
        refused = self.service_b.handle(wrong_transport)
        self.assertFalse(refused["ok"])
        self.assertEqual(refused["error"]["code"], "invalid_transport_binding")

    def test_owner_label_registry_is_optional_and_fails_closed(self) -> None:
        self.assertIsNone(load_label_index(self.root_path, self.authority))
        registry = {
            "beings": {self.state.being_ref: "compaii"},
            "overrides": {},
            "schema": LABEL_SCHEMA,
        }
        path = self.root_path / "labels.json"
        path.write_text(json.dumps(registry))
        path.chmod(0o600)
        index = load_label_index(self.root_path, self.authority)
        assert index is not None
        self.assertEqual(index.label_of("embodiment:legion"), "compaii.cluster@legion")
        # Group- or world-readable is refused rather than trusted.
        path.chmod(0o640)
        with self.assertRaises(HostedRuntimeError):
            load_label_index(self.root_path, self.authority)
        path.chmod(0o600)
        path.write_text("{not json")
        with self.assertRaises(HostedRuntimeError):
            load_label_index(self.root_path, self.authority)
        path.write_text(json.dumps({**registry, "beings": {}}))
        with self.assertRaises(HostedRuntimeError):
            load_label_index(self.root_path, self.authority)
        path.unlink()
        self.assertIsNone(load_label_index(self.root_path, self.authority))

    def test_label_index_skips_retired_rows_and_refuses_active_duplicates(
        self,
    ) -> None:
        registry = {
            "beings": {self.state.being_ref: "compaii"},
            "overrides": {},
            "schema": LABEL_SCHEMA,
        }
        path = self.root_path / "labels.json"
        path.write_text(json.dumps(registry))
        path.chmod(0o600)
        self.addCleanup(path.unlink, missing_ok=True)

        def authority_with(
            rows: list[Any], extra_incarnations: dict[str, Any] | None = None
        ) -> RootAuthority:
            manifest: dict[str, Any] = copy.deepcopy(dict(self.manifest.value))
            manifest["embodiments"] = rows
            manifest["revision"] += 1
            return RootAuthority(
                BeingManifest.from_value(manifest),
                self.state,
                self.credentials,
                {**self.incarnations, **(extra_incarnations or {})},
            )

        active_row = next(
            dict(row)
            for row in self.manifest.value["embodiments"]
            if row["embodiment_id"] == "embodiment:legion"
        )
        # The live manifest shape: a RETIRED earlier incarnation beside the
        # active one — same embodiment, distinct incarnation ids, sorted.
        credential = self.credentials[active_row["embodiment_credential_id"]]
        active_sequence = self.incarnations[active_row["incarnation_authorization_id"]][
            "body"
        ]["incarnation_sequence"]
        retired_authorization = create_incarnation_authorization(
            credential,
            self.signing_seeds["legion"],
            incarnation_id="incarnation:00000000-0000-4000-8000-000000000000",
            incarnation_sequence=active_sequence,
            started_at_ms=NOW,
        )
        retired_row = {
            **active_row,
            "status": "retired",
            "incarnation_id": "incarnation:00000000-0000-4000-8000-000000000000",
            "incarnation_authorization_id": retired_authorization["artifact_id"],
        }
        index = load_label_index(
            self.root_path,
            authority_with(
                sorted(
                    [retired_row, dict(active_row)],
                    key=lambda row: (row["embodiment_id"], row["incarnation_id"]),
                ),
                {retired_authorization["artifact_id"]: retired_authorization},
            ),
        )
        assert index is not None
        self.assertEqual(index.label_of("embodiment:legion"), "compaii.cluster@legion")
        # Two ACTIVE incarnations of one embodiment stay a fail-closed
        # equivocation: an ambiguous label is never silently resolved.
        second_authorization = create_incarnation_authorization(
            credential,
            self.signing_seeds["legion"],
            incarnation_id="incarnation:ffffffff-ffff-4fff-8fff-ffffffffffff",
            incarnation_sequence=active_sequence + 1,
            started_at_ms=NOW,
        )
        second_active = {
            **active_row,
            "incarnation_id": "incarnation:ffffffff-ffff-4fff-8fff-ffffffffffff",
            "incarnation_authorization_id": second_authorization["artifact_id"],
        }
        with self.assertRaises(HostedRuntimeError):
            load_label_index(
                self.root_path,
                authority_with(
                    sorted(
                        [dict(active_row), second_active],
                        key=lambda row: (row["embodiment_id"], row["incarnation_id"]),
                    ),
                    {second_authorization["artifact_id"]: second_authorization},
                ),
            )

    def test_we_conversation_page_renders_owner_labels(self) -> None:
        registry = {
            "beings": {self.state.being_ref: "compaii"},
            "overrides": {},
            "schema": LABEL_SCHEMA,
        }
        entries = [
            {
                "being_ref": self.state.being_ref,
                "body_ref": row["body_ref"],
                "embodiment_id": row["embodiment_id"],
            }
            for row in self.manifest.value["embodiments"]
        ]
        labelled = replace(self.service_a, labels=LabelIndex(entries, registry))
        message = self.append(
            self.ledger_a,
            "legion",
            "communication",
            payload={
                "schema": MESSAGE_PAYLOAD_SCHEMA,
                "body": {"addressee": ["embodiment:daimonmatrix"], "text": "hola"},
                "intent": {
                    "operation": "we.converse",
                    "scope": "/we",
                    "thread_id": "30000000-0000-4000-8000-000000000003",
                },
                "reply": None,
            },
        )
        _, page = self.invoke(labelled, 63, "we.conversation.page", {})
        row = page["result"]["entries"][0]
        self.assertEqual(row["event_id"], message["event_id"])
        self.assertEqual(row["author_label"], "compaii.cluster@legion")
        self.assertEqual(row["addressee_labels"], ["compaii.cluster@daimonmatrix"])
        # A being-level selector names every body; a full label names exactly one.
        self.assertEqual(
            sorted(labelled._we_addressees(["compaii"])),
            ["embodiment:daimonmatrix", "embodiment:legion"],
        )
        self.assertEqual(
            labelled._we_addressees(["compaii.cluster@daimonmatrix"]),
            ["embodiment:daimonmatrix"],
        )
        # Plain ids keep working, and a label-shaped unknown name fails loudly
        # instead of being silently reinterpreted as an id.
        self.assertEqual(
            labelled._we_addressees(["embodiment:legion"]), ["embodiment:legion"]
        )
        with self.assertRaises(ServiceError) as caught:
            labelled._we_addressees(["nobody.hermes@legion"])
        self.assertEqual(str(caught.exception), "label_unknown")
        # Without a registry the same page carries no labels at all.
        _, bare = self.invoke(self.service_a, 64, "we.conversation.page", {})
        bare_row = bare["result"]["entries"][0]
        self.assertIsNone(bare_row["author_label"])
        self.assertIsNone(bare_row["addressee_labels"])

    def test_we_conversation_page_reads_only_the_we_lane(self) -> None:
        thread_id = "30000000-0000-4000-8000-000000000001"
        message = self.append(
            self.ledger_a,
            "legion",
            "communication",
            payload={
                "schema": MESSAGE_PAYLOAD_SCHEMA,
                "body": {"addressee": ["embodiment:daimonmatrix"], "text": "hola"},
                "intent": {
                    "operation": "we.converse",
                    "scope": "/we",
                    "thread_id": thread_id,
                },
                "reply": None,
            },
        )
        unrelated = self.append(self.ledger_a, "legion", "not-a-conversation")
        _, page = self.invoke(self.service_a, 60, "we.conversation.page", {})
        result = page["result"]
        self.assertEqual(result["schema"], "dm.we.conversation-page/v1")
        self.assertEqual(
            [(row["kind"], row["event_id"]) for row in result["entries"]],
            [("message", message["event_id"])],
        )
        row = result["entries"][0]
        self.assertEqual(row["text"], "hola")
        self.assertEqual(row["thread_id"], thread_id)
        self.assertEqual(row["author"], "embodiment:legion")
        self.assertEqual(row["addressees"], ["embodiment:daimonmatrix"])
        self.assertNotIn(
            unrelated["event_id"], {item["event_id"] for item in result["entries"]}
        )
        _, other_thread = self.invoke(
            self.service_a,
            61,
            "we.conversation.page",
            {"thread_id": "30000000-0000-4000-8000-000000000002"},
        )
        self.assertEqual(other_thread["result"]["entries"], [])
        _, advanced = self.invoke(
            self.service_a,
            62,
            "we.conversation.page",
            {"after": message["occurred_at_ms"]},
        )
        self.assertEqual(advanced["result"]["entries"], [])
        self.assertEqual(advanced["result"]["after"], message["occurred_at_ms"])

    def test_preview_heads_and_projection_methods_are_effect_free(self) -> None:
        remote = self.append(self.ledger_b, "daimonmatrix", "preview-only")
        before = self.ledger_a.events(include_incomplete=True)
        _, preview = self.invoke(self.service_a, 30, "we.preview", {"events": [remote]})
        self.assertEqual(preview["result"]["received"], 1)
        self.assertEqual(self.ledger_a.events(include_incomplete=True), before)

        _, heads = self.invoke(self.service_a, 31, "we.heads", {})
        self.assertEqual(heads["result"]["schema"], "dm.we.heads/v1")
        _, rebuilt = self.invoke(self.service_a, 32, "we.projection.rebuild", {})
        _, cached = self.invoke(self.service_a, 33, "we.projection.get", {})
        self.assertEqual(cached["result"]["snapshot"], rebuilt["result"])

        _, invalid = self.invoke(
            self.service_a,
            34,
            "we.diff",
            {"after": None, "limit": 0, "kind": None, "subject": None},
        )
        self.assertFalse(invalid["ok"])
        self.assertEqual(invalid["error"]["code"], "invalid_params")

    def test_retry_after_semantic_commit_authors_no_second_event(self) -> None:
        request = self.request(40, "we.observe", self.observe_params("crash-window"))
        digest = request_hash(request)
        event = self.ledger_a.append_local_idempotent(
            client_id=self.capability.client_id,
            request_id=request["request_id"],
            request_hash=digest,
            kind="experience.observed",
            subject="crash-window",
            payload={"summary": "crash-window"},
            signer=self.signers["legion"],
            sensitivity="personal",
            causal_parents=[],
            occurred_at_ms=NOW,
        )
        response = self.service_a.handle(request)
        self.assertEqual(response["result"]["event"], event)
        self.assertEqual(len(self.ledger_a.events()), 1)
        self.assertEqual(
            canonical_bytes(self.service_a.handle(request)), canonical_bytes(response)
        )

    def test_exact_durable_retry_survives_freshness_window(self) -> None:
        now = [NOW]
        capability = create_capability(
            key("durable-retry"),
            client_id="client:durable-retry",
            methods=["we.observe"],
            not_before_ms=NOW - 1,
            not_after_ms=NOW + 100_000,
        )
        service = HostedWeave(
            self.ledger_a,
            self.signers["legion"],
            {capability.capability_id: capability},
            lambda: now[0],
            "dm:runtime:v1:" + "a" * 43,
            "service-a",
        )
        request = create_request(
            capability,
            request_id=rpc_id(41),
            issued_at_ms=NOW,
            method="we.observe",
            params=self.observe_params("late-exact-retry"),
            nonce=b"r" * 16,
        )
        first = service.handle(request)
        now[0] = NOW + 31_000
        self.assertEqual(
            canonical_bytes(service.handle(request)), canonical_bytes(first)
        )
        never_seen = create_request(
            capability,
            request_id=rpc_id(42),
            issued_at_ms=NOW,
            method="we.observe",
            params=self.observe_params("never-seen-stale"),
            nonce=b"s" * 16,
        )
        with self.assertRaisesRegex(LocalApiError, "authentication_failed"):
            service.handle(never_seen)
        self.assertEqual(len(self.ledger_a.events()), 1)

    def test_schema_v2_to_v3_preserves_canonical_events(self) -> None:
        original = self.append(self.ledger_a, "legion", "migration")
        with closing(sqlite3.connect(self.ledger_a.path)) as database:
            database.execute("DROP TABLE local_operations")
            database.execute("DROP TABLE rpc_requests")
            database.execute("UPDATE metadata SET value='2' WHERE key='schema_version'")
        reopened = Ledger(
            self.ledger_a.path,
            authority=self.authority,
            local_origin=self.origins["legion"],
            clock=lambda: NOW,
        )
        reopened.initialize()
        self.assertEqual(reopened.events(), [original])
        with closing(sqlite3.connect(self.ledger_a.path)) as database:
            version = database.execute(
                "SELECT value FROM metadata WHERE key='schema_version'"
            ).fetchone()[0]
            tables = {
                row[0]
                for row in database.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
        self.assertEqual(version, "3")
        self.assertTrue({"local_operations", "rpc_requests"} <= tables)


class BoundedReceivingObservationTests(RootLedgerFixture):
    def setUp(self) -> None:
        super().setUp()
        self.capability = create_capability(
            key("bounded-status"),
            client_id="client:bounded-status",
            methods=["runtime.status", "scope.me"],
            not_before_ms=NOW - 10000,
            not_after_ms=NOW + 10000,
        )
        self.service = HostedWeave(
            self.ledger_a,
            self.signers["legion"],
            {self.capability.capability_id: self.capability},
            lambda: NOW,
            "dm:runtime:v1:" + "a" * 43,
            "bounded-status",
        )

    def request(
        self,
        index: int,
        params: dict[str, Any],
        capability: LocalCapability | None = None,
    ) -> dict[str, Any]:
        return create_request(
            capability or self.capability,
            request_id=rpc_id(index),
            issued_at_ms=NOW,
            method="runtime.status",
            params=params,
            nonce=index.to_bytes(16, "big"),
        )

    def test_receiving_view_keeps_current_admission_without_full_ledger_work(
        self,
    ) -> None:
        state = ["running"]
        calls = []

        def body_reader(
            body_ref: str, embodiment_id: str, incarnation_id: str, evaluated_at_ms: int
        ) -> dict[str, Any]:
            calls.append(state[0])
            if state[0] == "unavailable":
                raise ValueError("actual admission reader unavailable")
            if state[0] == "socket-unavailable":
                raise OSError("actual admission socket unavailable")
            if state[0] == "socket-timeout":
                raise TimeoutError("actual admission socket deadline")
            return dict(
                schema="dm.cluster-body-snapshot/v1",
                body_ref=body_ref,
                embodiment_id=embodiment_id,
                incarnation_id=incarnation_id,
                observed_at_ms=evaluated_at_ms,
                state=state[0],
                resource_fences=[],
            )

        assert self.service.scopes is not None
        service = replace(
            self.service, scopes=replace(self.service.scopes, body_reader=body_reader)
        )
        request = self.request(8001, {"view": "receiving"})
        with (
            patch.object(
                self.ledger_a,
                "integrity_check",
                side_effect=AssertionError("full audit"),
            ),
            patch(
                "daimon_matrix.scopes.SyncEngine.heads",
                side_effect=AssertionError("full heads"),
            ),
            patch(
                "daimon_matrix.scopes.ProjectionEngine.snapshot",
                side_effect=AssertionError("full projection"),
            ),
        ):
            first = service.handle(request)
            self.assertTrue(first["ok"], first["error"])
            view = first["result"]
            self.assertEqual(view["schema"], "dm.runtime.receiving-status/v1")
            self.assertEqual(view["identity"]["origin"], first["server"])
            self.assertEqual(view["identity"]["body"]["state"], "running")
            self.assertFalse(
                {"integrity", "counts", "visibility", "heads", "effective"}
                & view.keys()
            )
            self.assertFalse({"heads", "effective"} & view["identity"].keys())
            state[0] = "stopped"
            current = service.handle(request)
            self.assertTrue(current["ok"], current["error"])
            self.assertEqual(current["result"]["identity"]["body"]["state"], "stopped")
            self.assertEqual(calls[0], "running")
            self.assertEqual(calls[-1], "stopped")
            verify_response(
                current,
                self.capability,
                expected_request_id=request["request_id"],
                expected_request_hash=request_hash(request),
                expected_server=first["server"],
                expected_runtime=first["runtime"],
            )
            state[0] = "unavailable"
            refusal = service.handle(request)
            self.assertFalse(refusal["ok"])
            self.assertEqual(refusal["error"]["code"], "body_snapshot_rejected")
            initial_refusal = service.handle(self.request(8002, {"view": "receiving"}))
            self.assertFalse(initial_refusal["ok"])
            for failure in ("socket-unavailable", "socket-timeout"):
                state[0] = failure
                refusal = service.handle(request)
                self.assertFalse(refusal["ok"])
                self.assertEqual(
                    refusal["error"],
                    {"code": "body_snapshot_unavailable", "retryable": True},
                )
                state[0] = "running"
                self.assertTrue(service.handle(request)["ok"])
            state[0] = "running"
            restored = service.handle(request)
            self.assertTrue(restored["ok"])
            self.assertEqual(restored["result"]["identity"]["body"]["state"], "running")

    def test_receiving_identity_does_not_expand_a_status_only_grant(self) -> None:
        capability = create_capability(
            key("status-only"),
            client_id="client:status-only",
            methods=["runtime.status"],
            not_before_ms=NOW - 10000,
            not_after_ms=NOW + 10000,
        )
        service = replace(
            self.service, capabilities={capability.capability_id: capability}
        )
        with self.assertRaisesRegex(LocalApiError, "authentication_failed"):
            service.handle(self.request(8002, {"view": "receiving"}, capability))
        self.assertTrue(service.handle(self.request(8003, {}, capability))["ok"])

    def test_full_default_and_closed_receiving_view_remain_distinct(self) -> None:
        with patch.object(
            self.ledger_a, "integrity_check", wraps=self.ledger_a.integrity_check
        ) as audit:
            response = self.service.handle(self.request(8004, {}))
            self.assertTrue(response["ok"], response["error"])
            self.assertEqual(response["result"]["schema"], "dm.runtime.status/v1")
            self.assertEqual(response["result"]["integrity"], "ok")
            self.assertIn("counts", response["result"])
            self.assertNotIn("identity", response["result"])
            audit.assert_called_once()
        variants: list[dict[str, Any]] = [
            {"view": "full"},
            {"view": "receiving", "audit": False},
        ]
        for index, params in enumerate(variants, 8010):
            response = self.service.handle(self.request(index, params))
            self.assertFalse(response["ok"])
            self.assertEqual(response["error"]["code"], "invalid_params")


if __name__ == "__main__":
    unittest.main()
