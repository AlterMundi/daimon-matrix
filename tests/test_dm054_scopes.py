from __future__ import annotations

import copy
import json
import socket
import threading
import unittest
from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, cast
from unittest.mock import patch

from jsonschema import (  # type: ignore[import-untyped]
    Draft202012Validator,
    FormatChecker,
    ValidationError,
)

from daimon_matrix.canonical import b64url, canonical_bytes
from daimon_matrix.communication import (
    MESSAGE_PAYLOAD_SCHEMA,
    RESOLUTION_PAYLOAD_SCHEMA,
    CommunicationStore,
)
from daimon_matrix.daemon import serve_connection
from daimon_matrix.ledger import Ledger
from daimon_matrix.local_api import (
    create_capability,
    create_request,
    decode_frame,
    encode_frame,
    request_hash,
    verify_response,
)
from daimon_matrix.relationships import (
    RelationshipError,
    VerifiedTribeSnapshot,
    tribe_ref,
)
from daimon_matrix.runtime import HostedRuntime
from daimon_matrix.scopes import (
    BODY_SNAPSHOT_SCHEMA,
    ScopeError,
    ScopeExchangeStore,
    ScopeFanout,
    ScopeResolver,
    create_scope_request,
    create_scope_response,
    serve_scope_request,
    validate_scope_request,
    validate_scope_response,
)
from daimon_matrix.sealed import DisclosureAuthorization, SealedDeliveryError
from daimon_matrix.service import HostedWeave
from daimon_matrix.weave import BeingManifest, RootAuthority
from tests.test_dm022_ledger import NOW, RootLedgerFixture

ROOT = Path(__file__).resolve().parents[1]


def request_id(index: int) -> str:
    return f"54000000-0000-4000-8000-{index:012d}"


def rejecting_verifier(code: str) -> Callable[[Mapping[str, Any]], None]:
    def reject(_value: Mapping[str, Any]) -> None:
        raise ValueError(code)

    return reject


def unavailable_peer(
    target: Mapping[str, Any],
    request: Mapping[str, Any],
    deadline_ms: int,
) -> Mapping[str, Any]:
    del target, request, deadline_ms
    raise ConnectionError


class AvailableRouter:
    def __init__(self, store: CommunicationStore) -> None:
        self.store = store

    def inspect_recipient(self, *, recipient_id: str) -> dict[str, Any]:
        return {
            "schema": "dm.route-recipient-inspection/v1",
            "profile_id": "dm:route-profile:v1:test",
            "policy_version": "dm.route-policy/v1",
            "recipient_id": recipient_id,
            "candidates": [
                {
                    "provider_ref": "provider:test",
                    "route_ref": "route:test",
                    "route_class": "direct",
                    "available": True,
                    "status": "available",
                    "evidence_ref": "dm:route-evidence:v1:test",
                }
            ],
        }


class ScopeFixture(RootLedgerFixture):
    def setUp(self) -> None:
        super().setUp()
        self.now = NOW
        self.communication = CommunicationStore(self.ledger_a, clock=lambda: self.now)
        self.communication.initialize()
        self.router = cast(Any, AvailableRouter(self.communication))
        self.resolver_a = ScopeResolver(
            self.ledger_a,
            clock=lambda: self.now,
            router=self.router,
            body_capabilities=("incus.inspect/v1",),
            body_reader=self.body_snapshot,
        )
        self.resolver_b = ScopeResolver(
            self.ledger_b,
            clock=lambda: self.now,
            router=self.router,
            body_capabilities=("incus.inspect/v1",),
            body_reader=self.body_snapshot,
        )
        self.store_a = ScopeExchangeStore(self.ledger_a)
        self.store_b = ScopeExchangeStore(self.ledger_b)
        self.store_a.initialize()
        self.store_b.initialize()

    def body_snapshot(
        self,
        body_ref: str,
        embodiment_id: str,
        incarnation_id: str,
        evaluated_at_ms: int,
    ) -> dict[str, Any]:
        return {
            "schema": BODY_SNAPSHOT_SCHEMA,
            "body_ref": body_ref,
            "embodiment_id": embodiment_id,
            "incarnation_id": incarnation_id,
            "observed_at_ms": evaluated_at_ms,
            "state": "running",
            "resource_fences": [],
        }

    def tribe_snapshot(self) -> VerifiedTribeSnapshot:
        declaration = {
            "created_at_ms": NOW - 100,
            "founder_principal_id": "compaii@legion",
            "nonce": b64url(b"t" * 32),
            "policy_ref": "policy:founder-v1",
        }
        reference = tribe_ref(declaration)
        snapshot = {
            "schema": "dm.tribe-snapshot/v1",
            "tribe_ref": reference,
            "declaration": declaration,
            "founder_epoch": 1,
            "founder_principal_id": "compaii@legion",
            "lineage_head_ref": "dm:tribe-lineage:v1:head",
            "verified_at_ms": NOW,
            "members": [
                {
                    "tribe_ref": reference,
                    "principal_id": "compaii@daimonmatrix",
                    "embodiment_id": "embodiment:daimonmatrix",
                    "membership_ref": "dm:membership:v1:daimonmatrix",
                    "state": "active",
                },
                {
                    "tribe_ref": reference,
                    "principal_id": "compaii@legion",
                    "embodiment_id": "embodiment:legion",
                    "membership_ref": "dm:membership:v1:legion",
                    "state": "active",
                },
            ],
            "grants": [
                {
                    "tribe_ref": reference,
                    "grant_ref": "dm:grant:v1:legion-read",
                    "controller_principal_id": "compaii@daimonmatrix",
                    "grantee_principal_id": "compaii@legion",
                    "resource_ref": "memory:shared",
                    "operations": ["read"],
                    "not_before_ms": NOW - 10,
                    "not_after_ms": NOW + 10_000,
                    "parent_grant_ref": None,
                    "revoked": False,
                }
            ],
        }
        return VerifiedTribeSnapshot.from_value(snapshot, verifier=lambda _value: None)


class ScopeResolutionTests(ScopeFixture):
    def test_resolution_uses_one_clock_sample_per_document(self) -> None:
        samples = iter((NOW, NOW + 1))
        resolver = ScopeResolver(
            self.ledger_a,
            clock=lambda: next(samples),
            router=self.router,
        )
        resolved = resolver.resolution(scope="/we", request_id=request_id(0))
        self.assertEqual(resolved["evaluated_at_ms"], NOW)
        self.assertEqual(next(samples), NOW + 1)

    def test_me_we_diff_and_sync_plan_preserve_exact_authority(self) -> None:
        local = self.append(self.ledger_a, "legion", "local")
        remote = self.append(self.ledger_b, "daimonmatrix", "remote")
        self.ledger_a.ingest([remote], source="test")

        me = self.resolver_a.me()
        self.assertEqual(me["origin"], self.origins["legion"])
        self.assertEqual(me["body"]["body_ref"], self.origins["legion"]["body_ref"])
        self.assertEqual(me["body_capabilities"], ["incus.inspect/v1"])
        self.assertEqual(me["being_ref"], self.authority.manifest.being_ref)
        self.assertEqual(
            {row["event_id"] for row in me["effective"]["entries"]},
            {local["event_id"], remote["event_id"]},
        )

        topology = self.resolver_a.we()
        self.assertEqual(
            [row["embodiment_id"] for row in topology["embodiments"]],
            ["embodiment:daimonmatrix", "embodiment:legion"],
        )
        self.assertEqual(
            {
                row["embodiment_id"]: row["availability"]
                for row in topology["embodiments"]
            },
            {"embodiment:daimonmatrix": "available", "embodiment:legion": "local"},
        )

        difference = self.resolver_a.diff()
        self.assertEqual(
            {row["event_id"] for row in difference["entries"]},
            {local["event_id"], remote["event_id"]},
        )
        remote_entry = next(
            row
            for row in difference["entries"]
            if row["event_id"] == remote["event_id"]
        )
        self.assertEqual(remote_entry["state"], "pending")
        self.assertEqual(remote_entry["local_decision_chain"], [])
        self.assertNotIn("payload", remote_entry)

        plan = self.resolver_a.sync_plan(request_id=request_id(1), limit=7)
        self.assertEqual(len(plan["targets"]), 1)
        self.assertEqual(plan["targets"][0]["embodiment_id"], "embodiment:daimonmatrix")
        self.assertEqual(plan["targets"][0]["request"]["limit"], 7)
        self.assertEqual(
            canonical_bytes(plan),
            canonical_bytes(
                self.resolver_a.sync_plan(request_id=request_id(1), limit=7)
            ),
        )

    def test_resolution_targets_match_dm052_semantics(self) -> None:
        we = self.resolver_a.resolution(scope="/we", request_id=request_id(2))
        self.assertEqual(
            [(row["recipient_type"], row["recipient_id"]) for row in we["targets"]],
            [
                ("embodiment", "embodiment:daimonmatrix"),
                ("embodiment", "embodiment:legion"),
            ],
        )
        message = self.ledger_a.append_local(
            kind="experience.observed",
            subject="communication",
            payload={
                "schema": MESSAGE_PAYLOAD_SCHEMA,
                "intent": {
                    "operation": "message.send",
                    "scope": "/we",
                    "thread_id": request_id(40),
                },
                "body": {"text": "scope parity"},
                "reply": None,
            },
            signer=self.signers["legion"],
            occurred_at_ms=NOW,
        )
        evidence = self.ledger_a.append_local(
            kind="experience.observed",
            subject="communication-resolution",
            payload={
                "schema": RESOLUTION_PAYLOAD_SCHEMA,
                "message_id": message["event_id"],
                "scope": "/we",
                "targets": we["targets"],
            },
            signer=self.signers["legion"],
            causal_parents=[message["event_id"]],
            occurred_at_ms=NOW,
        )
        accepted = self.communication.accept(
            message_event_id=message["event_id"],
            resolution_event_id=evidence["event_id"],
        )
        self.assertEqual(
            [row["recipient_id"] for row in accepted["legs"]],
            ["embodiment:daimonmatrix", "embodiment:legion"],
        )
        authorization = DisclosureAuthorization.from_resolution_event(
            event=message,
            resolution_event=evidence,
            authority=self.authority,
            expires_at_ms=NOW + 10_000,
            authorization_id=request_id(41),
        )
        self.assertEqual(
            [row["embodiment_id"] for row in authorization.value["recipients"]],
            ["embodiment:daimonmatrix", "embodiment:legion"],
        )
        self.assertEqual(authorization.value["evidence_hash"], evidence["content_hash"])
        invalid_targets = copy.deepcopy(we["targets"])
        invalid_targets[0]["evidence_cursor"] = "not valid with spaces"
        invalid_evidence = self.ledger_a.append_local(
            kind="experience.observed",
            subject="communication-resolution",
            payload={
                "schema": RESOLUTION_PAYLOAD_SCHEMA,
                "message_id": message["event_id"],
                "scope": "/we",
                "targets": invalid_targets,
            },
            signer=self.signers["legion"],
            causal_parents=[message["event_id"]],
            occurred_at_ms=NOW,
        )
        with self.assertRaises(SealedDeliveryError):
            DisclosureAuthorization.from_resolution_event(
                event=message,
                resolution_event=invalid_evidence,
                authority=self.authority,
                expires_at_ms=NOW + 10_000,
            )
        snapshot = self.tribe_snapshot()
        resolver = ScopeResolver(
            self.ledger_a,
            clock=lambda: self.now,
            tribes={snapshot.ref: snapshot},
        )
        tribe = resolver.resolution(
            scope="/tribe", request_id=request_id(3), tribe_ref=snapshot.ref
        )
        self.assertEqual(
            [
                (row["recipient_id"], row["receipt_origin_embodiment_id"])
                for row in tribe["targets"]
            ],
            [
                ("dm:membership:v1:daimonmatrix", "embodiment:daimonmatrix"),
                ("dm:membership:v1:legion", "embodiment:legion"),
            ],
        )
        self.assertTrue(
            all(row["recipient_type"] == "relationship" for row in tribe["targets"])
        )

    def test_body_and_tribe_fail_closed_without_external_authority(self) -> None:
        def wrong_body(
            _body: str,
            embodiment: str,
            incarnation: str,
            evaluated_at_ms: int,
        ) -> dict[str, Any]:
            value = self.body_snapshot(
                "cluster:wrong", embodiment, incarnation, evaluated_at_ms
            )
            return value

        resolver = ScopeResolver(
            self.ledger_a, clock=lambda: self.now, body_reader=wrong_body
        )
        with self.assertRaisesRegex(ScopeError, "body_snapshot_rejected"):
            resolver.me()
        with self.assertRaisesRegex(ScopeError, "tribe_not_configured"):
            resolver.tribe(tribe_ref="dm:tribe:v1:absent")
        with self.assertRaisesRegex(RelationshipError, "tribe_verifier_required"):
            VerifiedTribeSnapshot.from_value({}, verifier=None)

    def test_matrix_owns_body_snapshot_evaluation_time(self) -> None:
        received: list[int] = []

        def coordinated(
            body_ref: str,
            embodiment_id: str,
            incarnation_id: str,
            evaluated_at_ms: int,
        ) -> dict[str, Any]:
            received.append(evaluated_at_ms)
            return {
                **self.body_snapshot(
                    body_ref, embodiment_id, incarnation_id, evaluated_at_ms
                ),
                "observed_at_ms": evaluated_at_ms,
            }

        resolver = ScopeResolver(
            self.ledger_a,
            clock=lambda: NOW,
            body_reader=coordinated,
        )
        self.assertEqual(resolver.me()["evaluated_at_ms"], NOW)
        self.assertEqual(received, [NOW])

        def future(
            body_ref: str,
            embodiment_id: str,
            incarnation_id: str,
            evaluated_at_ms: int,
        ) -> dict[str, Any]:
            return {
                **self.body_snapshot(
                    body_ref, embodiment_id, incarnation_id, evaluated_at_ms
                ),
                "observed_at_ms": evaluated_at_ms + 1,
            }

        with self.assertRaisesRegex(ScopeError, "body_snapshot_rejected"):
            ScopeResolver(
                self.ledger_a,
                clock=lambda: NOW,
                body_reader=future,
            ).me()

    def test_external_history_verifier_owns_membership_forks_and_attenuation(
        self,
    ) -> None:
        accepted = self.tribe_snapshot()
        resolved = accepted.resolve(principal_id="compaii@legion", at_ms=NOW)
        self.assertEqual([row["operations"] for row in resolved["grants"]], [["read"]])
        self.assertEqual(resolved["founder_epoch"], 1)

        expired = accepted.resolve(principal_id="compaii@legion", at_ms=NOW + 20_000)
        self.assertEqual(expired["grants"], [])
        with self.assertRaisesRegex(RelationshipError, "tribe_membership_not_active"):
            accepted.resolve(principal_id="compaii@absent", at_ms=NOW)

        for history_error in (
            "forked_founder_epoch",
            "invitation_acceptance_mismatch",
            "grant_not_attenuated",
        ):
            with (
                self.subTest(history_error=history_error),
                self.assertRaisesRegex(RelationshipError, "tribe_snapshot_unverified"),
            ):
                VerifiedTribeSnapshot.from_value(
                    accepted.value,
                    verifier=rejecting_verifier(history_error),
                )


class SignedFanoutTests(ScopeFixture):
    def test_signed_partial_fanout_exact_replay_and_conflict(self) -> None:
        calls = 0

        def peer(
            target: Mapping[str, Any],
            request: Mapping[str, Any],
            deadline_ms: int,
        ) -> Mapping[str, Any]:
            del target, deadline_ms
            nonlocal calls
            calls += 1
            return serve_scope_request(
                self.resolver_b, self.signers["daimonmatrix"], self.store_b, request
            )

        fanout = ScopeFanout(
            self.resolver_a, self.signers["legion"], self.store_a, peer
        )
        first = fanout.execute(request_id=request_id(10), deadline_ms=NOW + 1_000)
        second = fanout.execute_exact(first["request"])
        self.assertFalse(first["partial"])
        self.assertEqual(first["outcomes"][0]["state"], "responded")
        self.assertEqual(
            first["outcomes"][0]["response"]["responder"],
            self.origins["daimonmatrix"],
        )
        self.assertEqual(
            canonical_bytes(first["request"]), canonical_bytes(second["request"])
        )
        self.assertEqual(
            canonical_bytes(first["outcomes"][0]["response"]),
            canonical_bytes(second["outcomes"][0]["response"]),
        )
        self.assertEqual(calls, 2)

        self.now = NOW + 2_000
        replayed_after_deadline = serve_scope_request(
            self.resolver_b,
            self.signers["daimonmatrix"],
            self.store_b,
            first["request"],
        )
        self.assertEqual(
            canonical_bytes(replayed_after_deadline),
            canonical_bytes(first["outcomes"][0]["response"]),
        )
        self.now = NOW

        request = first["request"]
        changed = create_scope_response(
            self.resolver_b,
            self.signers["daimonmatrix"],
            request,
            status="responded",
            content={**self.resolver_b.me(), "evaluated_at_ms": NOW + 1},
            error=None,
        )
        validate_scope_response(
            changed,
            request,
            self.authority,
            expected_origin=self.origins["daimonmatrix"],
        )
        with self.assertRaisesRegex(ScopeError, "scope_response_conflict"):
            self.store_a.record_response(changed)

    def test_timeout_unavailable_and_signature_binding_are_explicit(self) -> None:
        unavailable = ScopeResolver(self.ledger_a, clock=lambda: self.now)
        fanout = ScopeFanout(
            unavailable,
            self.signers["legion"],
            self.store_a,
            lambda *_args: (_ for _ in ()).throw(AssertionError("must not call")),
        )
        result = fanout.execute(request_id=request_id(11), deadline_ms=NOW + 1_000)
        self.assertTrue(result["partial"])
        self.assertEqual(result["outcomes"][0]["state"], "unavailable")

        timed_out = ScopeFanout(
            self.resolver_a,
            self.signers["legion"],
            self.store_a,
            lambda *_args: (_ for _ in ()).throw(TimeoutError),
        ).execute(request_id=request_id(13), deadline_ms=NOW + 1_000)
        self.assertEqual(timed_out["outcomes"][0]["state"], "missing")

        connection_failed = ScopeFanout(
            self.resolver_a,
            self.signers["legion"],
            self.store_a,
            unavailable_peer,
        ).execute(request_id=request_id(17), deadline_ms=NOW + 1_000)
        self.assertEqual(connection_failed["outcomes"][0]["state"], "unavailable")
        self.assertEqual(connection_failed["outcomes"][0]["error"], "peer_unavailable")

        topology = self.resolver_a.we()
        topology["embodiments"][0]["transport_principals"] = []
        with patch.object(ScopeResolver, "we", return_value=topology):
            no_principal = ScopeFanout(
                self.resolver_a,
                self.signers["legion"],
                self.store_a,
                unavailable_peer,
            ).execute(request_id=request_id(18), deadline_ms=NOW + 1_000)
        self.assertEqual(no_principal["outcomes"][0]["state"], "unavailable")
        self.assertEqual(
            no_principal["outcomes"][0]["error"], "target_principal_absent"
        )

        request = create_scope_request(
            self.resolver_a,
            self.signers["legion"],
            request_id=request_id(12),
            deadline_ms=NOW + 1_000,
        )
        validate_scope_request(request, self.authority, now_ms=NOW)
        tampered = copy.deepcopy(request)
        tampered["manifest_hash"] = "0" * 64
        with self.assertRaisesRegex(ScopeError, "scope_hash_mismatch"):
            validate_scope_request(tampered, self.authority, now_ms=NOW)
        revised_authority = RootAuthority(
            BeingManifest.from_value({**self.manifest.value, "revision": 2}),
            self.state,
            self.credentials,
            self.incarnations,
        )
        revised_resolver = ScopeResolver(
            Ledger(
                self.root_path / "revised" / "ledger.sqlite",
                authority=revised_authority,
                local_origin=self.origins["legion"],
                clock=lambda: NOW,
            ),
            clock=lambda: NOW,
        )
        wrong_manifest = create_scope_request(
            revised_resolver,
            self.signers["legion"],
            request_id=request_id(16),
            deadline_ms=NOW + 1_000,
        )
        with self.assertRaisesRegex(ScopeError, "scope_authority_mismatch"):
            validate_scope_request(wrong_manifest, self.authority, now_ms=NOW)
        response = serve_scope_request(
            self.resolver_b, self.signers["daimonmatrix"], self.store_b, request
        )
        with self.assertRaisesRegex(ScopeError, "scope_response_binding_mismatch"):
            validate_scope_response(
                response,
                request,
                self.authority,
                expected_origin=self.origins["legion"],
            )

    def test_bounded_refusal_and_changed_request_id_conflict(self) -> None:
        request = create_scope_request(
            self.resolver_a,
            self.signers["legion"],
            request_id=request_id(14),
            deadline_ms=NOW + 1_000,
            max_response_bytes=2_048,
        )
        response = serve_scope_request(
            self.resolver_b, self.signers["daimonmatrix"], self.store_b, request
        )
        self.assertEqual(response["status"], "refused")
        self.assertEqual(response["error"], "scope_response_too_large")
        self.assertLessEqual(len(canonical_bytes(response)), 2_048)

        changed = create_scope_request(
            self.resolver_a,
            self.signers["legion"],
            request_id=request_id(14),
            deadline_ms=NOW + 2_000,
            max_response_bytes=2_048,
        )
        with self.assertRaisesRegex(ScopeError, "scope_request_conflict"):
            serve_scope_request(
                self.resolver_b,
                self.signers["daimonmatrix"],
                self.store_b,
                changed,
            )

    def test_concurrent_duplicate_requests_freeze_one_response(self) -> None:
        request = create_scope_request(
            self.resolver_a,
            self.signers["legion"],
            request_id=request_id(15),
            deadline_ms=NOW + 1_000,
        )

        def serve(_: int) -> bytes:
            return canonical_bytes(
                serve_scope_request(
                    self.resolver_b,
                    self.signers["daimonmatrix"],
                    self.store_b,
                    request,
                )
            )

        with ThreadPoolExecutor(max_workers=8) as pool:
            responses = list(pool.map(serve, range(32)))
        self.assertEqual(len(set(responses)), 1)


class HostedScopeSurfaceTests(ScopeFixture):
    def test_authenticated_real_daemon_frame_exposes_safe_scope_methods(self) -> None:
        key = b"s" * 32
        capability = create_capability(
            key,
            client_id="client:dm054-scope-reader",
            methods=[
                "scope.me",
                "scope.resolve",
                "scope.tribe",
                "scope.we",
                "scope.we.diff",
                "scope.we.sync-plan",
            ],
            not_before_ms=NOW - 1,
            not_after_ms=NOW + 10_000,
        )
        snapshot = self.tribe_snapshot()
        resolver = ScopeResolver(
            self.ledger_a,
            clock=lambda: self.now,
            router=self.router,
            tribes={snapshot.ref: snapshot},
        )
        service = HostedWeave(
            self.ledger_a,
            self.signers["legion"],
            {capability.capability_id: capability},
            lambda: self.now,
            "dm:runtime:v1:" + "a" * 43,
            "scopes",
            communication=self.communication,
            router=self.router,
            scopes=resolver,
        )
        info = self.root_path.lstat()
        runtime = HostedRuntime(
            service,
            self.root_path,
            (info.st_dev, info.st_ino),
            self.root_path / "dm054.sock",
        )
        request = create_request(
            capability,
            request_id=request_id(20),
            issued_at_ms=NOW,
            method="scope.resolve",
            params={
                "request_id": request_id(21),
                "scope": "/tribe",
                "tribe_ref": snapshot.ref,
            },
            nonce=b"d" * 16,
        )
        client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        worker = threading.Thread(target=serve_connection, args=(runtime, server))
        worker.start()
        client.sendall(encode_frame(request))
        response = decode_frame(client.recv(2 * 1024 * 1024))
        worker.join(timeout=2)
        client.close()
        server.close()
        self.assertFalse(worker.is_alive())
        verify_response(
            response,
            capability,
            expected_request_id=request["request_id"],
            expected_request_hash=request_hash(request),
            expected_server=self.origins["legion"],
            expected_runtime=service.runtime_identity,
        )
        self.assertTrue(response["ok"])
        self.assertEqual(response["result"]["scope"], "/tribe")
        self.assertEqual(
            response["result"]["targets"][0]["recipient_type"], "relationship"
        )
        local_schema = json.loads(
            (ROOT / "schemas/hosted/v1/local-api.schema.json").read_bytes()
        )
        Draft202012Validator(local_schema, format_checker=FormatChecker()).validate(
            request
        )
        Draft202012Validator(local_schema, format_checker=FormatChecker()).validate(
            response
        )


class ScopeSchemaTests(ScopeFixture):
    def test_published_scope_and_tribe_documents_are_closed(self) -> None:
        snapshot = self.tribe_snapshot()
        resolver = ScopeResolver(
            self.ledger_a,
            clock=lambda: self.now,
            router=self.router,
            body_reader=self.body_snapshot,
            tribes={snapshot.ref: snapshot},
        )
        request = create_scope_request(
            resolver,
            self.signers["legion"],
            request_id=request_id(30),
            deadline_ms=NOW + 1_000,
        )
        response = create_scope_response(
            self.resolver_b,
            self.signers["daimonmatrix"],
            request,
            status="responded",
            content=self.resolver_b.me(),
            error=None,
        )
        fanout = ScopeFanout(
            resolver,
            self.signers["legion"],
            self.store_a,
            lambda _target, value, _deadline: serve_scope_request(
                self.resolver_b,
                self.signers["daimonmatrix"],
                self.store_b,
                value,
            ),
        ).execute(request_id=request_id(31), deadline_ms=NOW + 1_000)
        scope_schema = json.loads(
            (ROOT / "schemas/scopes/v1/resolution.schema.json").read_bytes()
        )
        tribe_schema = json.loads(
            (ROOT / "schemas/relationships/v1/tribe.schema.json").read_bytes()
        )
        for schema in (scope_schema, tribe_schema):
            Draft202012Validator.check_schema(schema)
        scope_validator = Draft202012Validator(
            scope_schema, format_checker=FormatChecker()
        )
        values = [
            resolver.me(),
            resolver.me()["body"],
            resolver.we(),
            resolver.diff(),
            resolver.resolution(scope="/we", request_id=request_id(32)),
            resolver.sync_plan(request_id=request_id(33), limit=8),
            request,
            response,
            fanout,
        ]
        for value in values:
            scope_validator.validate(value)
        tribe_validator = Draft202012Validator(
            tribe_schema, format_checker=FormatChecker()
        )
        tribe_validator.validate(snapshot.value)
        tribe_validator.validate(resolver.tribe(tribe_ref=snapshot.ref))
        extra = {**resolver.we(), "endpoint": "https://secret.invalid"}
        with self.assertRaises(ValidationError):
            scope_validator.validate(extra)


if __name__ == "__main__":
    unittest.main()
