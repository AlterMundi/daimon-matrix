from __future__ import annotations

import copy
import http.client
import json
import socket
import sqlite3
import threading
import unittest
from collections.abc import Callable, Mapping
from contextlib import closing
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, cast
from unittest.mock import patch

from jsonschema import (  # type: ignore[import-untyped]
    Draft202012Validator,
    FormatChecker,
)

from daimon_matrix.canonical import canonical_bytes
from daimon_matrix.daemon import create_peer_http_server
from daimon_matrix.identity import (
    create_revocation,
    encryption_descriptor,
    signing_descriptor,
    verify_successor,
)
from daimon_matrix.keystore import EncryptedKeystore
from daimon_matrix.peer_transport import (
    MAX_ENVELOPE_BYTES,
    KeystorePeerCustody,
    PeerClient,
    PeerDispatcher,
    PeerExchangeStore,
    PeerOutbox,
    PeerTransportAmbiguous,
    PeerTransportBusy,
    PeerTransportConflict,
    PeerTransportError,
    http_peer_round_trip,
    open_peer_payload,
    protocol_handlers,
    seal_peer_payload,
)
from daimon_matrix.runtime import RuntimeError as HostedRuntimeError
from daimon_matrix.runtime import load_runtime
from daimon_matrix.scopes import (
    ScopeExchangeStore,
    ScopeResolver,
    create_scope_request,
    validate_scope_response,
)
from daimon_matrix.sealed import RecipientTarget
from daimon_matrix.sync import SyncEngine
from daimon_matrix.weave import BeingManifest, RootAuthority
from tests.test_dm022_ledger import NOW, RootLedgerFixture, seed
from tests.test_dm024_runtime import PASSWORD as RUNTIME_PASSWORD
from tests.test_dm024_runtime import RuntimeFixture

PASSWORD = b"dm055-test-only-password"
ROOT = Path(__file__).resolve().parents[1]


class PeerTransportFixture(RootLedgerFixture):
    def setUp(self) -> None:
        super().setUp()
        self.now = NOW
        self.targets: dict[str, RecipientTarget] = {}
        self.custodies: dict[str, KeystorePeerCustody] = {}
        for label in ("legion", "daimonmatrix"):
            credential = next(
                value
                for value in self.credentials.values()
                if value["body"]["embodiment_id"] == f"embodiment:{label}"
            )
            self.targets[label] = RecipientTarget(
                self.authority, credential["artifact_id"]
            )
            signing_id = signing_descriptor(self.signing_seeds[label])["key_id"]
            encryption_id = encryption_descriptor(seed(f"{label}-encryption"))["key_id"]
            signing_slot = f"peer.signing.v1:{label}"
            encryption_slot = f"peer.encryption.v1:{label}"
            directory = self.root_path / f"peer-custody-{label}"
            directory.mkdir(mode=0o700)
            store = EncryptedKeystore.create(
                directory / "keys.json",
                lambda: bytearray(PASSWORD),
                control_head=self.state.head,
                secrets={
                    signing_slot: self.signing_seeds[label],
                    encryption_slot: seed(f"{label}-encryption"),
                },
            )
            contents = store.open(
                lambda: bytearray(PASSWORD),
                minimum_counter=1,
                required_control_head=self.state.head,
            )
            self.custodies[label] = KeystorePeerCustody(
                secrets=contents.secrets,
                signing_slots={signing_id: signing_slot},
                encryption_slots={encryption_id: encryption_slot},
            )

    def envelope(self) -> bytes:
        return seal_peer_payload(
            {
                "schema": "dm.scope.request/v1",
                "request_id": "05500000-0000-4000-8000-000000000001",
                "scope": "/me",
            },
            content_type="application/vnd.daimon.scope-request+json",
            sender_authority=self.authority,
            sender_origin=self.origins["legion"],
            recipient_target=self.targets["daimonmatrix"],
            custody=self.custodies["legion"],
            issued_at_ms=NOW,
            expires_at_ms=NOW + 30_000,
            envelope_id="05500000-0000-4000-8000-000000000002",
            correlation_id="05500000-0000-4000-8000-000000000001",
        )


class PeerTransportTests(PeerTransportFixture):
    def test_scope_request_and_response_round_trip_between_embodiments(self) -> None:
        request_raw = self.envelope()
        request = open_peer_payload(
            request_raw,
            authority=self.authority,
            local_target=self.targets["daimonmatrix"],
            custody=self.custodies["daimonmatrix"],
            at_ms=NOW + 1,
        )
        self.assertEqual(request.payload["scope"], "/me")
        self.assertEqual(request.sender["embodiment_id"], "embodiment:legion")
        self.assertNotIn(b"dm.scope.request/v1", request_raw)

        response_raw = seal_peer_payload(
            {"schema": "dm.scope.response/v1", "status": "responded"},
            content_type="application/vnd.daimon.scope-response+json",
            sender_authority=self.authority,
            sender_origin=self.origins["daimonmatrix"],
            recipient_target=self.targets["legion"],
            custody=self.custodies["daimonmatrix"],
            issued_at_ms=NOW + 2,
            expires_at_ms=NOW + 30_000,
            envelope_id="05500000-0000-4000-8000-000000000003",
            correlation_id=request.correlation_id,
            reply_to=request.envelope_id,
        )
        response = open_peer_payload(
            response_raw,
            authority=self.authority,
            local_target=self.targets["legion"],
            custody=self.custodies["legion"],
            at_ms=NOW + 3,
        )
        self.assertEqual(response.reply_to, request.envelope_id)
        self.assertEqual(response.correlation_id, request.correlation_id)
        self.assertEqual(response.payload["status"], "responded")

    def test_tamper_recipient_expiry_and_unknown_type_fail_closed(self) -> None:
        raw = self.envelope()
        value = json.loads(raw)
        mutations: tuple[Callable[[dict[str, Any]], None], ...] = (
            lambda row: row.__setitem__(
                "content_type", "application/vnd.daimon.sync-request+json"
            ),
            lambda row: row["recipient"].__setitem__(
                "embodiment_id", "embodiment:legion"
            ),
            lambda row: row["payload"].__setitem__("ciphertext", "A" * 64),
            lambda row: row.__setitem__("profile", "unknown-peer-profile"),
            lambda row: row.__setitem__("being_ref", "being:substituted"),
            lambda row: row.__setitem__("manifest_hash", "0" * 64),
            lambda row: row["sender"].__setitem__("body_ref", "body:substituted"),
            lambda row: row["sender"].__setitem__(
                "incarnation_id", "incarnation:substituted"
            ),
            lambda row: row["sender"].__setitem__(
                "principal_id", "substituted@localhost"
            ),
            lambda row: row["recipient"].__setitem__(
                "encryption_kid", "X25519:substituted"
            ),
        )
        for mutation in mutations:
            changed = copy.deepcopy(value)
            mutation(changed)
            with self.assertRaisesRegex(PeerTransportError, "peer_transport_rejected"):
                open_peer_payload(
                    canonical_bytes(changed),
                    authority=self.authority,
                    local_target=self.targets["daimonmatrix"],
                    custody=self.custodies["daimonmatrix"],
                    at_ms=NOW + 1,
                )
        for malformed in (
            raw + b"\n",
            b'{"schema":"dm.peer-envelope/v1",' + raw[1:],
            b"x" * (MAX_ENVELOPE_BYTES + 1),
        ):
            with self.assertRaisesRegex(PeerTransportError, "peer_transport_rejected"):
                open_peer_payload(
                    malformed,
                    authority=self.authority,
                    local_target=self.targets["daimonmatrix"],
                    custody=self.custodies["daimonmatrix"],
                    at_ms=NOW + 1,
                )
        opened = json.loads(raw)
        opened["unexpected"] = None
        with self.assertRaisesRegex(PeerTransportError, "peer_transport_rejected"):
            open_peer_payload(
                canonical_bytes(opened),
                authority=self.authority,
                local_target=self.targets["daimonmatrix"],
                custody=self.custodies["daimonmatrix"],
                at_ms=NOW + 1,
            )
        with self.assertRaises(PeerTransportError):
            open_peer_payload(
                raw,
                authority=self.authority,
                local_target=self.targets["daimonmatrix"],
                custody=self.custodies["daimonmatrix"],
                at_ms=True,
            )
        with self.assertRaises(PeerTransportError):
            open_peer_payload(
                raw,
                authority=self.authority,
                local_target=self.targets["daimonmatrix"],
                custody=self.custodies["daimonmatrix"],
                at_ms=NOW + 30_000,
            )
        with self.assertRaises(PeerTransportError):
            seal_peer_payload(
                {"schema": "unknown"},
                content_type="application/json",
                sender_authority=self.authority,
                sender_origin=self.origins["legion"],
                recipient_target=self.targets["daimonmatrix"],
                custody=self.custodies["legion"],
                issued_at_ms=NOW,
                expires_at_ms=NOW + 1,
                correlation_id="05500000-0000-4000-8000-000000000001",
            )

    def test_manifest_mismatch_and_revoked_principal_fail_closed(self) -> None:
        raw = self.envelope()
        mismatched_manifest = BeingManifest.from_value(
            {**self.manifest.value, "revision": 2}
        )
        mismatched = RootAuthority(
            mismatched_manifest, self.state, self.credentials, self.incarnations
        )
        with self.assertRaises(PeerTransportError):
            open_peer_payload(
                raw,
                authority=mismatched,
                local_target=RecipientTarget(
                    mismatched, self.targets["daimonmatrix"].credential_id
                ),
                custody=self.custodies["daimonmatrix"],
                at_ms=NOW + 1,
            )

        revocation = create_revocation(
            self.state,
            self.root_seeds,
            embodiment_id="embodiment:legion",
            cutoff_incarnation_sequence=0,
            revocation_generation=1,
        )
        revoked_state = verify_successor(revocation, self.state)
        revoked_manifest = BeingManifest.from_value(
            {**self.manifest.value, "control_head": revoked_state.head, "revision": 2}
        )
        revoked = RootAuthority(
            revoked_manifest, revoked_state, self.credentials, self.incarnations
        )
        with self.assertRaises(PeerTransportError):
            open_peer_payload(
                raw,
                authority=revoked,
                local_target=RecipientTarget(
                    revoked, self.targets["daimonmatrix"].credential_id
                ),
                custody=self.custodies["daimonmatrix"],
                at_ms=NOW + 1,
            )

        recipient_revocation = create_revocation(
            self.state,
            self.root_seeds,
            embodiment_id="embodiment:daimonmatrix",
            cutoff_incarnation_sequence=0,
            revocation_generation=1,
        )
        recipient_state = verify_successor(recipient_revocation, self.state)
        recipient_manifest = BeingManifest.from_value(
            {
                **self.manifest.value,
                "control_head": recipient_state.head,
                "revision": 2,
            }
        )
        recipient_revoked = RootAuthority(
            recipient_manifest,
            recipient_state,
            self.credentials,
            self.incarnations,
        )
        with self.assertRaises(PeerTransportError):
            seal_peer_payload(
                {"schema": "dm.scope.request/v1", "scope": "/me"},
                content_type="application/vnd.daimon.scope-request+json",
                sender_authority=recipient_revoked,
                sender_origin=self.origins["legion"],
                recipient_target=RecipientTarget(
                    recipient_revoked,
                    self.targets["daimonmatrix"].credential_id,
                ),
                custody=self.custodies["legion"],
                issued_at_ms=NOW,
                expires_at_ms=NOW + 30_000,
                correlation_id="05500000-0000-4000-8000-000000000053",
            )

    def test_dispatch_replays_exact_response_and_rejects_id_conflict(self) -> None:
        state = self.root_path / "peer-dispatch"
        state.mkdir(mode=0o700)
        calls = 0

        def serve(payload: Mapping[str, Any]) -> Mapping[str, Any]:
            nonlocal calls
            calls += 1
            return {
                "schema": "dm.scope.response/v1",
                "request_id": payload["request_id"],
                "status": "responded",
            }

        dispatcher = PeerDispatcher(
            authority=self.authority,
            local_origin=self.origins["daimonmatrix"],
            local_target=self.targets["daimonmatrix"],
            custody=self.custodies["daimonmatrix"],
            store=PeerExchangeStore(state / "exchange.sqlite", clock=lambda: self.now),
            handlers={
                "application/vnd.daimon.scope-request+json": (
                    "application/vnd.daimon.scope-response+json",
                    serve,
                )
            },
            clock=lambda: self.now,
        )
        raw = self.envelope()
        first = dispatcher.dispatch(raw)
        second = dispatcher.dispatch(raw)
        self.assertEqual(first, second)
        self.assertEqual(calls, 1)
        opened = open_peer_payload(
            first,
            authority=self.authority,
            local_target=self.targets["legion"],
            custody=self.custodies["legion"],
            at_ms=NOW + 1,
        )
        self.assertEqual(opened.payload["status"], "responded")

        changed = self.envelope()
        self.assertNotEqual(raw, changed)
        with self.assertRaises(PeerTransportConflict):
            dispatcher.dispatch(changed)

    def test_exchange_store_serializes_duplicates_takes_over_and_detects_corruption(
        self,
    ) -> None:
        state = self.root_path / "peer-store-concurrency"
        state.mkdir(mode=0o700)
        now = [NOW]
        store = PeerExchangeStore(state / "exchange.sqlite", clock=lambda: now[0])
        envelope_id = "05500000-0000-4000-8000-000000000050"
        digest = "a" * 64
        barrier = threading.Barrier(2)
        claims: list[Any] = []
        outcomes: list[str] = []

        def contend() -> None:
            barrier.wait()
            try:
                claims.append(store.begin(envelope_id, digest))
                outcomes.append("claimed")
            except PeerTransportBusy:
                outcomes.append("busy")

        workers = [threading.Thread(target=contend) for _ in range(2)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(timeout=2)
            self.assertFalse(worker.is_alive())
        self.assertEqual(sorted(outcomes), ["busy", "claimed"])
        response = b"encrypted-response"
        self.assertEqual(store.finish(claims[0], response), response)
        self.assertEqual(store.begin(envelope_id, digest).response, response)

        takeover_id = "05500000-0000-4000-8000-000000000051"
        first = store.begin(takeover_id, digest, lease_ms=10)
        now[0] += 11
        with self.assertRaises(PeerTransportConflict):
            store.finish(first, response)
        successor = store.begin(takeover_id, digest, lease_ms=10)
        store.finish(successor, response)
        with closing(sqlite3.connect(store.path)) as database:
            database.execute(
                "UPDATE peer_exchanges SET response_sha256=? WHERE envelope_id=?",
                ("b" * 64, takeover_id),
            )
            database.commit()
        with self.assertRaisesRegex(PeerTransportError, "peer_transport_rejected"):
            store.begin(takeover_id, digest)

    def test_outbox_detects_corrupt_replay_and_conflicting_plan(self) -> None:
        state = self.root_path / "peer-outbox-corruption"
        state.mkdir(mode=0o700)
        outbox = PeerOutbox(state / "outbox.sqlite")
        request_id = "05500000-0000-4000-8000-000000000052"
        plan_hash = "c" * 64
        self.assertEqual(
            outbox.get_or_create(request_id, plan_hash, lambda: b"sealed-request"),
            b"sealed-request",
        )
        with self.assertRaises(PeerTransportConflict):
            outbox.get_or_create(request_id, "d" * 64, lambda: b"changed")
        with closing(sqlite3.connect(outbox.path)) as database:
            database.execute(
                "UPDATE peer_outbox SET request_sha256=? WHERE request_id=?",
                ("e" * 64, request_id),
            )
            database.commit()
        with self.assertRaisesRegex(PeerTransportError, "peer_transport_rejected"):
            outbox.get_or_create(request_id, plan_hash, lambda: b"unused")

    def test_handler_failure_releases_request_for_safe_protocol_retry(self) -> None:
        state = self.root_path / "peer-retry"
        state.mkdir(mode=0o700)
        attempts = 0

        def flaky(payload: Mapping[str, Any]) -> Mapping[str, Any]:
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise RuntimeError("synthetic handler failure")
            return {"schema": "dm.scope.response/v1", "echo": payload["scope"]}

        dispatcher = PeerDispatcher(
            authority=self.authority,
            local_origin=self.origins["daimonmatrix"],
            local_target=self.targets["daimonmatrix"],
            custody=self.custodies["daimonmatrix"],
            store=PeerExchangeStore(state / "exchange.sqlite", clock=lambda: self.now),
            handlers={
                "application/vnd.daimon.scope-request+json": (
                    "application/vnd.daimon.scope-response+json",
                    flaky,
                )
            },
            clock=lambda: self.now,
        )
        raw = self.envelope()
        with self.assertRaisesRegex(RuntimeError, "synthetic handler failure"):
            dispatcher.dispatch(raw)
        response = dispatcher.dispatch(raw)
        self.assertTrue(response)
        self.assertEqual(attempts, 2)

    def test_response_loss_retries_identical_ciphertext_without_second_effect(
        self,
    ) -> None:
        server_state = self.root_path / "peer-response-loss-server"
        client_state = self.root_path / "peer-response-loss-client"
        server_state.mkdir(mode=0o700)
        client_state.mkdir(mode=0o700)
        effects = 0
        requests: list[bytes] = []
        lose_first_response = True

        def serve(payload: Mapping[str, Any]) -> Mapping[str, Any]:
            nonlocal effects
            effects += 1
            return {"schema": "dm.scope.response/v1", "echo": payload["scope"]}

        dispatcher = PeerDispatcher(
            authority=self.authority,
            local_origin=self.origins["daimonmatrix"],
            local_target=self.targets["daimonmatrix"],
            custody=self.custodies["daimonmatrix"],
            store=PeerExchangeStore(
                server_state / "exchange.sqlite", clock=lambda: self.now
            ),
            handlers={
                "application/vnd.daimon.scope-request+json": (
                    "application/vnd.daimon.scope-response+json",
                    serve,
                )
            },
            clock=lambda: self.now,
        )

        def unreliable_round_trip(raw: bytes) -> bytes:
            nonlocal lose_first_response
            requests.append(raw)
            response = dispatcher.dispatch(raw)
            if lose_first_response:
                lose_first_response = False
                raise ConnectionError("synthetic response loss")
            return response

        client = PeerClient(
            authority=self.authority,
            local_origin=self.origins["legion"],
            local_target=self.targets["legion"],
            custody=self.custodies["legion"],
            outbox=PeerOutbox(client_state / "outbox.sqlite"),
            round_trip=unreliable_round_trip,
            clock=lambda: self.now,
        )

        def invoke() -> Mapping[str, Any]:
            return client.call(
                {"schema": "dm.scope.request/v1", "scope": "/me"},
                recipient_target=self.targets["daimonmatrix"],
                request_content_type=("application/vnd.daimon.scope-request+json"),
                response_content_type=("application/vnd.daimon.scope-response+json"),
                correlation_id="05500000-0000-4000-8000-000000000010",
                deadline_ms=NOW + 30_000,
            )

        with self.assertRaises(PeerTransportAmbiguous):
            invoke()
        client = PeerClient(
            authority=self.authority,
            local_origin=self.origins["legion"],
            local_target=self.targets["legion"],
            custody=self.custodies["legion"],
            outbox=PeerOutbox(client_state / "outbox.sqlite"),
            round_trip=unreliable_round_trip,
            clock=lambda: self.now,
        )
        dispatcher = PeerDispatcher(
            authority=self.authority,
            local_origin=self.origins["daimonmatrix"],
            local_target=self.targets["daimonmatrix"],
            custody=self.custodies["daimonmatrix"],
            store=PeerExchangeStore(
                server_state / "exchange.sqlite", clock=lambda: self.now
            ),
            handlers={
                "application/vnd.daimon.scope-request+json": (
                    "application/vnd.daimon.scope-response+json",
                    serve,
                )
            },
            clock=lambda: self.now,
        )
        response = invoke()
        self.assertEqual(response["echo"], "/me")
        self.assertEqual(effects, 1)
        self.assertEqual(len(requests), 2)
        self.assertEqual(requests[0], requests[1])

    def test_envelope_matches_closed_schema(self) -> None:
        schema = json.loads(
            (ROOT / "schemas/transport/v1/peer-envelope.schema.json").read_bytes()
        )
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(
            json.loads(self.envelope())
        )

    def test_real_scope_and_sync_handlers_cross_encrypted_boundary(self) -> None:
        server_state = self.root_path / "peer-protocol-server"
        client_state = self.root_path / "peer-protocol-client"
        server_state.mkdir(mode=0o700)
        client_state.mkdir(mode=0o700)
        resolver_a = ScopeResolver(self.ledger_a, clock=lambda: self.now)
        resolver_b = ScopeResolver(self.ledger_b, clock=lambda: self.now)
        scope_store_b = ScopeExchangeStore(self.ledger_b)
        scope_store_b.initialize()
        sync_a = SyncEngine(self.ledger_a)
        sync_b = SyncEngine(self.ledger_b)
        dispatcher = PeerDispatcher(
            authority=self.authority,
            local_origin=self.origins["daimonmatrix"],
            local_target=self.targets["daimonmatrix"],
            custody=self.custodies["daimonmatrix"],
            store=PeerExchangeStore(
                server_state / "exchange.sqlite", clock=lambda: self.now
            ),
            handlers=protocol_handlers(
                resolver=resolver_b,
                signer=self.signers["daimonmatrix"],
                scope_store=scope_store_b,
                sync_engine=sync_b,
            ),
            clock=lambda: self.now,
        )
        client = PeerClient(
            authority=self.authority,
            local_origin=self.origins["legion"],
            local_target=self.targets["legion"],
            custody=self.custodies["legion"],
            outbox=PeerOutbox(client_state / "outbox.sqlite"),
            round_trip=dispatcher.dispatch,
            clock=lambda: self.now,
        )

        scope_request = create_scope_request(
            resolver_a,
            self.signers["legion"],
            request_id="05500000-0000-4000-8000-000000000020",
            deadline_ms=NOW + 30_000,
        )
        scope_response = client.call(
            scope_request,
            recipient_target=self.targets["daimonmatrix"],
            request_content_type="application/vnd.daimon.scope-request+json",
            response_content_type="application/vnd.daimon.scope-response+json",
            correlation_id=scope_request["request_id"],
            deadline_ms=scope_request["deadline_ms"],
        )
        validated_scope = validate_scope_response(
            scope_response,
            scope_request,
            self.authority,
            expected_origin=self.origins["daimonmatrix"],
        )
        self.assertEqual(
            validated_scope["content"]["origin"], self.origins["daimonmatrix"]
        )

        events = [
            self.ledger_b.append_local(
                kind="experience.observed",
                subject=f"dm055 encrypted sync page {index}",
                payload={"summary": "native carrier"},
                signer=self.signers["daimonmatrix"],
                occurred_at_ms=NOW,
            )
            for index in range(3)
        ]
        pages = 0
        while True:
            pages += 1
            sync_request = sync_a.request(
                request_id=f"05500000-0000-4000-8000-{20 + pages:012d}", limit=1
            )
            delta = client.call(
                sync_request,
                recipient_target=self.targets["daimonmatrix"],
                request_content_type="application/vnd.daimon.sync-request+json",
                response_content_type="application/vnd.daimon.sync-delta+json",
                correlation_id=sync_request["request_id"],
                deadline_ms=NOW + 30_000,
            )
            receipt = sync_a.pull(delta)
            self.assertEqual(receipt["inserted"], 1)
            if not delta["more"]:
                break
        self.assertEqual(pages, 3)
        for event in events:
            self.assertEqual(self.ledger_a.event(event["event_id"]), event)

    def test_http_client_rejects_unsafe_url_and_wrong_response_contract(self) -> None:
        for url, timeout in (
            ("http://127.0.0.1:bad/dm-peer/v1", 1),
            ("http://user@127.0.0.1/dm-peer/v1", 1),
            ("http://127.0.0.1/not-peer", 1),
            ("http://127.0.0.1/dm-peer/v1", True),
        ):
            with (
                self.subTest(url=url, timeout=timeout),
                self.assertRaises(PeerTransportError),
            ):
                http_peer_round_trip(url, timeout_seconds=timeout)

        statuses = [503, 200]

        class WrongResponse(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                size = int(self.headers["Content-Length"])
                self.rfile.read(size)
                status = statuses.pop(0)
                if status == 503:
                    self.send_response(503)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                body = b"{}"
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, _format: str, *args: object) -> None:
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), WrongResponse)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            host, port = server.server_address[:2]
            host = cast(str, host)
            exchange = http_peer_round_trip(
                f"http://{host}:{port}/dm-peer/v1", timeout_seconds=2
            )
            with self.assertRaises(PeerTransportAmbiguous):
                exchange(b"opaque")
            with self.assertRaisesRegex(PeerTransportError, "peer_transport_rejected"):
                exchange(b"opaque")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_real_http_carrier_observes_only_encrypted_bytes(self) -> None:
        server_state = self.root_path / "peer-http-server"
        client_state = self.root_path / "peer-http-client"
        server_state.mkdir(mode=0o700)
        client_state.mkdir(mode=0o700)
        observed: list[bytes] = []

        def serve(payload: Mapping[str, Any]) -> Mapping[str, Any]:
            return {"schema": "dm.scope.response/v1", "echo": payload["scope"]}

        dispatcher = PeerDispatcher(
            authority=self.authority,
            local_origin=self.origins["daimonmatrix"],
            local_target=self.targets["daimonmatrix"],
            custody=self.custodies["daimonmatrix"],
            store=PeerExchangeStore(
                server_state / "exchange.sqlite", clock=lambda: self.now
            ),
            handlers={
                "application/vnd.daimon.scope-request+json": (
                    "application/vnd.daimon.scope-response+json",
                    serve,
                )
            },
            clock=lambda: self.now,
        )

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                if self.path != "/dm-peer/v1":
                    self.send_error(404)
                    return
                size = int(self.headers["Content-Length"])
                raw = self.rfile.read(size)
                observed.append(raw)
                response = dispatcher.dispatch(raw)
                self.send_response(200)
                self.send_header("Content-Type", "application/vnd.daimon.peer+jcs")
                self.send_header("Content-Length", str(len(response)))
                self.end_headers()
                self.wfile.write(response)

            def log_message(self, _format: str, *args: object) -> None:
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            host, port = server.server_address[:2]
            host = cast(str, host)
            client = PeerClient(
                authority=self.authority,
                local_origin=self.origins["legion"],
                local_target=self.targets["legion"],
                custody=self.custodies["legion"],
                outbox=PeerOutbox(client_state / "outbox.sqlite"),
                round_trip=http_peer_round_trip(
                    f"http://{host}:{port}/dm-peer/v1", timeout_seconds=3
                ),
                clock=lambda: self.now,
            )
            response = client.call(
                {"schema": "dm.scope.request/v1", "scope": "/me"},
                recipient_target=self.targets["daimonmatrix"],
                request_content_type=("application/vnd.daimon.scope-request+json"),
                response_content_type=("application/vnd.daimon.scope-response+json"),
                correlation_id="05500000-0000-4000-8000-000000000030",
                deadline_ms=NOW + 30_000,
            )
            self.assertEqual(response["echo"], "/me")
            self.assertEqual(len(observed), 1)
            self.assertNotIn(b"dm.scope.request/v1", observed[0])
            self.assertNotIn(b'"scope":"/me"', observed[0])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


class PeerRuntimeBundleTests(PeerTransportFixture, RuntimeFixture):
    def test_v3_bundle_loads_native_peer_custody_and_dispatcher(self) -> None:
        peer_slot = "peer.encryption.v1:local"
        state_root, bundle, _ = self.make_bundle(
            secrets={
                "runtime.signing.v1:local": self.signing_seeds["legion"],
                "runtime.capability.v1:runtime-test": seed("dm024-capability"),
                peer_slot: seed("legion-encryption"),
            },
            state_name="peer-v3-runtime",
        )
        bundle = {
            **bundle,
            "schema": "dm.runtime.bundle/v3",
            "authority_history": [],
            "peer_transport": {
                "enabled": True,
                "encryption_slot": peer_slot,
                "exchange_filename": "peer-exchange.sqlite",
                "listen_host": "127.0.0.1",
                "listen_port": 8686,
                "outbox_filename": "peer-outbox.sqlite",
            },
        }
        schema = json.loads(
            (ROOT / "schemas/hosted/v3/bundle.schema.json").read_bytes()
        )
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(bundle)
        bundle_path = state_root / "runtime.json"
        bundle_path.write_bytes(canonical_bytes(bundle))
        bundle_path.chmod(0o600)
        password_reads = 0

        def one_shot_password() -> bytearray:
            nonlocal password_reads
            password_reads += 1
            if password_reads != 1:
                raise AssertionError("runtime password descriptor was reused")
            return bytearray(RUNTIME_PASSWORD)

        runtime = load_runtime(
            state_root,
            "runtime.json",
            one_shot_password,
            clock=lambda: NOW,
        )
        self.assertEqual(password_reads, 1)
        self.assertIsNotNone(runtime.peer_dispatcher)
        self.assertIsNotNone(runtime.peer_outbox)
        self.assertIsNotNone(runtime.peer_context)
        self.assertEqual(runtime.peer_listen, ("127.0.0.1", 8686))
        assert runtime.peer_dispatcher is not None

        request = create_scope_request(
            ScopeResolver(self.ledger_b, clock=lambda: NOW),
            self.signers["daimonmatrix"],
            request_id="05500000-0000-4000-8000-000000000040",
            deadline_ms=NOW + 30_000,
        )
        raw = seal_peer_payload(
            request,
            content_type="application/vnd.daimon.scope-request+json",
            sender_authority=self.authority,
            sender_origin=self.origins["daimonmatrix"],
            recipient_target=self.targets["legion"],
            custody=self.custodies["daimonmatrix"],
            issued_at_ms=NOW,
            expires_at_ms=NOW + 30_000,
            correlation_id=request["request_id"],
        )
        response = open_peer_payload(
            runtime.peer_dispatcher.dispatch(raw),
            authority=self.authority,
            local_target=self.targets["daimonmatrix"],
            custody=self.custodies["daimonmatrix"],
            at_ms=NOW,
        )
        self.assertEqual(response.payload["status"], "responded")
        self.assertEqual(response.payload["content"]["origin"], self.origins["legion"])

        runtime = replace(runtime, peer_listen=("127.0.0.1", 0))
        server = create_peer_http_server(runtime)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            host, port = server.server_address[:2]
            host = cast(str, host)
            client = PeerClient(
                authority=self.authority,
                local_origin=self.origins["daimonmatrix"],
                local_target=self.targets["daimonmatrix"],
                custody=self.custodies["daimonmatrix"],
                outbox=PeerOutbox(state_root / "remote-peer-outbox.sqlite"),
                round_trip=http_peer_round_trip(
                    f"http://{host}:{port}/dm-peer/v1", timeout_seconds=3
                ),
                clock=lambda: NOW,
            )
            request = create_scope_request(
                ScopeResolver(self.ledger_b, clock=lambda: NOW),
                self.signers["daimonmatrix"],
                request_id="05500000-0000-4000-8000-000000000041",
                deadline_ms=NOW + 30_000,
            )
            result = client.call(
                request,
                recipient_target=self.targets["legion"],
                request_content_type=("application/vnd.daimon.scope-request+json"),
                response_content_type=("application/vnd.daimon.scope-response+json"),
                correlation_id=request["request_id"],
                deadline_ms=request["deadline_ms"],
            )
            self.assertEqual(result["content"]["origin"], self.origins["legion"])
            self.assertEqual(password_reads, 1)

            connection = http.client.HTTPConnection(host, port, timeout=2)
            try:
                connection.request(
                    "POST",
                    "/not-peer",
                    body=b"opaque",
                    headers={"Content-Type": "application/vnd.daimon.peer+jcs"},
                )
                rejected = connection.getresponse()
                self.assertEqual(rejected.status, 404)
                self.assertEqual(rejected.read(), b"")
                self.assertIsNone(rejected.getheader("Server"))
            finally:
                connection.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_v3_absence_malformed_collision_and_wrong_key_fail_closed(self) -> None:
        peer_slot = "peer.encryption.v1:local"

        def configuration() -> dict[str, Any]:
            return {
                "enabled": True,
                "encryption_slot": peer_slot,
                "exchange_filename": "peer-exchange.sqlite",
                "listen_host": "127.0.0.1",
                "listen_port": 8686,
                "outbox_filename": "peer-outbox.sqlite",
            }

        state_root, bundle, _ = self.make_bundle(state_name="peer-v3-disabled")
        disabled = {
            **bundle,
            "schema": "dm.runtime.bundle/v3",
            "authority_history": [],
            "peer_transport": None,
        }
        path = state_root / "runtime.json"
        path.write_bytes(canonical_bytes(disabled))
        path.chmod(0o600)
        runtime = load_runtime(
            state_root,
            "runtime.json",
            lambda: bytearray(RUNTIME_PASSWORD),
            clock=lambda: NOW,
        )
        self.assertIsNone(runtime.peer_dispatcher)
        self.assertIsNone(runtime.peer_context)

        cases = (
            (
                "malformed",
                {**configuration(), "enabled": False},
                seed("legion-encryption"),
            ),
            (
                "collision",
                {**configuration(), "exchange_filename": "ledger.sqlite"},
                seed("legion-encryption"),
            ),
            ("wrong-key", configuration(), seed("wrong-peer-encryption")),
        )
        for name, peer_configuration, peer_seed in cases:
            with self.subTest(name=name):
                state_root, bundle, _ = self.make_bundle(
                    secrets={
                        "runtime.signing.v1:local": self.signing_seeds["legion"],
                        "runtime.capability.v1:runtime-test": seed("dm024-capability"),
                        peer_slot: peer_seed,
                    },
                    state_name=f"peer-v3-{name}",
                )
                candidate = {
                    **bundle,
                    "schema": "dm.runtime.bundle/v3",
                    "authority_history": [],
                    "peer_transport": peer_configuration,
                }
                path = state_root / "runtime.json"
                path.write_bytes(canonical_bytes(candidate))
                path.chmod(0o600)
                with self.assertRaises(HostedRuntimeError):
                    load_runtime(
                        state_root,
                        "runtime.json",
                        lambda: bytearray(RUNTIME_PASSWORD),
                        clock=lambda: NOW,
                    )

    def test_http_server_bounds_connections_before_handler_threads(self) -> None:
        peer_slot = "peer.encryption.v1:local"
        state_root, bundle, _ = self.make_bundle(
            secrets={
                "runtime.signing.v1:local": self.signing_seeds["legion"],
                "runtime.capability.v1:runtime-test": seed("dm024-capability"),
                peer_slot: seed("legion-encryption"),
            },
            state_name="peer-v3-bounded-http",
        )
        candidate = {
            **bundle,
            "schema": "dm.runtime.bundle/v3",
            "authority_history": [],
            "peer_transport": {
                "enabled": True,
                "encryption_slot": peer_slot,
                "exchange_filename": "peer-exchange.sqlite",
                "listen_host": "127.0.0.1",
                "listen_port": 8686,
                "outbox_filename": "peer-outbox.sqlite",
            },
        }
        path = state_root / "runtime.json"
        path.write_bytes(canonical_bytes(candidate))
        path.chmod(0o600)
        runtime = load_runtime(
            state_root,
            "runtime.json",
            lambda: bytearray(RUNTIME_PASSWORD),
            clock=lambda: NOW,
        )
        runtime = replace(runtime, peer_listen=("127.0.0.1", 0))
        with patch("daimon_matrix.daemon.MAX_IN_FLIGHT", 1):
            server = create_peer_http_server(runtime)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        blocker: socket.socket | None = None
        extra: socket.socket | None = None
        try:
            host, port = server.server_address[:2]
            host = cast(str, host)
            blocker = socket.create_connection((host, port), timeout=2)
            blocker.sendall(b"POST /dm-peer/v1 HTTP/1.1\r\nHost: local\r\n")
            slots = cast(Any, server)._peer_slots
            for _ in range(100):
                if not slots.acquire(blocking=False):
                    break
                slots.release()
                threading.Event().wait(0.01)
            else:
                self.fail("first connection never occupied the bounded handler slot")
            extra = socket.create_connection((host, port), timeout=2)
            extra.sendall(b"POST /dm-peer/v1 HTTP/1.0\r\nContent-Length: 0\r\n\r\n")
            extra.settimeout(1)
            try:
                received = extra.recv(1)
            except ConnectionResetError:
                received = b""
            self.assertEqual(received, b"")
        finally:
            if blocker is not None:
                blocker.close()
            if extra is not None:
                extra.close()
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
