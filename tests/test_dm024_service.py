from __future__ import annotations

import copy
import hashlib
import sqlite3
import unittest
from contextlib import closing
from typing import Any

from daimon_matrix.canonical import canonical_bytes
from daimon_matrix.ledger import Ledger
from daimon_matrix.local_api import (
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
from daimon_matrix.service import METHODS, HostedWeave
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
            self.ledger_a, self.signers["legion"], capabilities, lambda: NOW
        )
        self.service_b = HostedWeave(
            self.ledger_b, self.signers["daimonmatrix"], capabilities, lambda: NOW
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
            issued_at_ms=NOW - 1,
            method="runtime.status",
            params={},
            nonce=b"e" * 16,
        )
        with self.assertRaisesRegex(LocalApiError, "authentication_failed"):
            self.service_a.handle(expired_request)

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

    def test_authenticated_sync_receipt_and_import_is_not_adoption(self) -> None:
        _, observed = self.invoke(
            self.service_b, 20, "we.observe", self.observe_params("remote-observation")
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


if __name__ == "__main__":
    unittest.main()
