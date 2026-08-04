from __future__ import annotations

import copy
import json
import os
import socket
import stat
import subprocess
import sys
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, cast

from jsonschema import (  # type: ignore[import-untyped]
    Draft202012Validator,
    FormatChecker,
)

from daimon_matrix.canonical import b64url, canonical_bytes
from daimon_matrix.daemon import (
    DaemonError,
    acquire_lock,
    serve_connection,
    serve_forever,
)
from daimon_matrix.identity import (
    create_embodiment_credential,
    create_incarnation_authorization,
    x25519_public,
)
from daimon_matrix.keystore import EncryptedKeystore
from daimon_matrix.local_api import (
    create_capability,
    create_request,
    decode_frame,
    encode_frame,
    request_hash,
    verify_response,
)
from daimon_matrix.relationships import tribe_ref
from daimon_matrix.runtime import RuntimeError, load_runtime
from daimon_matrix.scopes import BODY_SNAPSHOT_SCHEMA
from daimon_matrix.service import METHODS, SCOPE_METHODS
from daimon_matrix.weave import BeingManifest
from tests.test_dm022_ledger import NOW, RootLedgerFixture, seed, transport

PASSWORD = b"dm024-descriptor-only-password"
ROOT = Path(__file__).resolve().parents[1]


class RuntimeFixture(RootLedgerFixture):
    def make_bundle(
        self,
        *,
        secrets: dict[str, bytes] | None = None,
        state_name: str = "hosted",
        now_ms: int = NOW,
    ) -> tuple[Path, dict[str, Any], Any]:
        state_root = self.root_path / state_name
        state_root.mkdir(mode=0o700)
        capability = create_capability(
            seed("dm024-capability"),
            client_id="client:runtime-test",
            methods=sorted(METHODS | SCOPE_METHODS),
            not_before_ms=now_ms - 60_000,
            not_after_ms=now_ms + 60_000,
        )
        signing_slot = "runtime.signing.v1:local"
        capability_slot = "runtime.capability.v1:runtime-test"
        actual_secrets = {
            signing_slot: self.signing_seeds["legion"],
            capability_slot: capability.key,
        }
        if secrets is not None:
            actual_secrets = secrets
        EncryptedKeystore.create(
            state_root / "custody.json",
            lambda: bytearray(PASSWORD),
            control_head=self.state.head,
            secrets=actual_secrets,
        )
        bundle = {
            "schema": "dm.runtime.bundle/v1",
            "control_artifacts": [self.genesis],
            "control_head": self.state.head,
            "manifest": self.manifest.value,
            "credentials": list(self.credentials.values()),
            "incarnations": list(self.incarnations.values()),
            "binding": None,
            "binding_activation": None,
            "provisional_history": None,
            "local_origin": self.origins["legion"],
            "ledger": "ledger.sqlite",
            "socket": "matrix.sock",
            "keystore": {
                "filename": "custody.json",
                "counter": 1,
                "signing_slot": signing_slot,
            },
            "capabilities": [
                {
                    "descriptor": capability.descriptor,
                    "secret_slot": capability_slot,
                }
            ],
            "routing": None,
            "scopes": None,
        }
        path = state_root / "runtime.json"
        path.write_bytes(canonical_bytes(bundle))
        path.chmod(0o600)
        return state_root, bundle, capability

    def make_process_bundle(self) -> tuple[Path, dict[str, Any], Any, int]:
        now_ms = time.time_ns() // 1_000_000
        label = "legion"
        origin = self.origins[label]
        credential = create_embodiment_credential(
            self.state,
            self.root_seeds,
            self.signing_seeds[label],
            x25519_public(seed(f"{label}-encryption")),
            embodiment_id=origin["embodiment_id"],
            body_ref=origin["body_ref"],
            purposes=["dm.we", "messages"],
            valid_from_ms=now_ms - 60_000,
            valid_until_ms=now_ms + 60_000,
            transport_principals=[transport(label, origin["principal_id"])],
        )
        incarnation = create_incarnation_authorization(
            credential,
            self.signing_seeds[label],
            incarnation_id=origin["incarnation_id"],
            incarnation_sequence=0,
            started_at_ms=now_ms - 1_000,
        )
        self.credentials = {credential["artifact_id"]: credential}
        self.incarnations = {incarnation["artifact_id"]: incarnation}
        self.manifest = BeingManifest.from_value(
            {
                "schema": "being-manifest/v2",
                "being_ref": self.state.being_ref,
                "control_head": self.state.head,
                "history_binding_id": None,
                "revision": 1,
                "embodiments": [
                    {
                        "body_ref": origin["body_ref"],
                        "embodiment_credential_id": credential["artifact_id"],
                        "embodiment_id": origin["embodiment_id"],
                        "incarnation_authorization_id": incarnation["artifact_id"],
                        "incarnation_id": origin["incarnation_id"],
                        "status": "active",
                    }
                ],
            }
        )
        state_root, bundle, capability = self.make_bundle(
            state_name="process", now_ms=now_ms
        )
        return state_root, bundle, capability, now_ms


class RuntimeBundleTests(RuntimeFixture):
    def test_bundle_loads_exact_authority_and_custody(self) -> None:
        state_root, bundle, capability = self.make_bundle()
        runtime = load_runtime(
            state_root,
            "runtime.json",
            lambda: bytearray(PASSWORD),
            clock=lambda: NOW,
        )
        request = create_request(
            capability,
            request_id="30000000-0000-4000-8000-000000000001",
            issued_at_ms=NOW,
            method="runtime.status",
            params={},
            nonce=b"r" * 16,
        )
        response = runtime.service.handle(request)
        verify_response(
            response,
            capability,
            expected_request_id=request["request_id"],
            expected_request_hash=request_hash(request),
            expected_server=self.origins["legion"],
        )
        self.assertEqual(response["result"]["integrity"], "ok")
        public = canonical_bytes(bundle)
        self.assertNotIn(PASSWORD, public)
        self.assertNotIn(self.signing_seeds["legion"], public)
        self.assertNotIn(capability.key, public)

        bundle_schema = json.loads(
            (ROOT / "schemas/hosted/v1/bundle.schema.json").read_bytes()
        )
        local_schema = json.loads(
            (ROOT / "schemas/hosted/v1/local-api.schema.json").read_bytes()
        )
        for schema in (bundle_schema, local_schema):
            Draft202012Validator.check_schema(schema)
        Draft202012Validator(bundle_schema).validate(bundle)
        Draft202012Validator(local_schema, format_checker=FormatChecker()).validate(
            capability.descriptor
        )
        Draft202012Validator(local_schema, format_checker=FormatChecker()).validate(
            request
        )
        Draft202012Validator(local_schema, format_checker=FormatChecker()).validate(
            response
        )

    def test_bundle_rejects_weak_mode_unknown_fields_and_extra_secret(self) -> None:
        state_root, bundle, _ = self.make_bundle()
        path = state_root / "runtime.json"
        path.chmod(0o644)
        with self.assertRaisesRegex(RuntimeError, "runtime_file_not_owner_only"):
            load_runtime(
                state_root,
                "runtime.json",
                lambda: bytearray(PASSWORD),
                clock=lambda: NOW,
            )
        path.chmod(0o600)
        changed = copy.deepcopy(bundle)
        changed["unknown"] = True
        path.write_bytes(canonical_bytes(changed))
        with self.assertRaisesRegex(RuntimeError, "invalid_runtime_bundle"):
            load_runtime(
                state_root,
                "runtime.json",
                lambda: bytearray(PASSWORD),
                clock=lambda: NOW,
            )

        signing_slot = "runtime.signing.v1:local"
        capability_slot = "runtime.capability.v1:runtime-test"
        state_root, _, _ = self.make_bundle(
            state_name="extra",
            secrets={
                signing_slot: self.signing_seeds["legion"],
                capability_slot: seed("dm024-capability"),
                "root": self.root_seeds[0],
            },
        )
        with self.assertRaisesRegex(RuntimeError, "unexpected_runtime_secret_slot"):
            load_runtime(
                state_root,
                "runtime.json",
                lambda: bytearray(PASSWORD),
                clock=lambda: NOW,
            )

    def test_explicit_cluster_reader_and_verified_tribe_snapshot_load(self) -> None:
        state_root, bundle, capability = self.make_bundle(state_name="scopes")
        declaration = {
            "created_at_ms": NOW - 100,
            "founder_principal_id": "compaii@legion",
            "nonce": b64url(b"r" * 32),
            "policy_ref": "policy:founder-v1",
        }
        reference = tribe_ref(declaration)
        snapshot = {
            "schema": "dm.tribe-snapshot/v1",
            "tribe_ref": reference,
            "declaration": declaration,
            "founder_epoch": 1,
            "founder_principal_id": "compaii@legion",
            "lineage_head_ref": "dm:tribe-lineage:v1:runtime",
            "verified_at_ms": NOW,
            "members": [
                {
                    "tribe_ref": reference,
                    "principal_id": "compaii@legion",
                    "embodiment_id": "embodiment:legion",
                    "membership_ref": "dm:membership:v1:legion",
                    "state": "active",
                }
            ],
            "grants": [],
        }
        relationships = state_root / "tribes.json"
        relationships.write_bytes(
            canonical_bytes(
                {"schema": "dm.tribe-snapshot-set/v1", "snapshots": [snapshot]}
            )
        )
        relationships.chmod(0o600)
        bundle["scopes"] = {
            "body_capabilities": ["incus.inspect/v1"],
            "relationships_filename": "tribes.json",
        }
        bundle_path = state_root / "runtime.json"
        bundle_path.write_bytes(canonical_bytes(bundle))
        with self.assertRaisesRegex(RuntimeError, "runtime_tribe_verifier_required"):
            load_runtime(
                state_root,
                "runtime.json",
                lambda: bytearray(PASSWORD),
                clock=lambda: NOW,
            )

        def body_reader(
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

        runtime = load_runtime(
            state_root,
            "runtime.json",
            lambda: bytearray(PASSWORD),
            clock=lambda: NOW,
            body_reader=body_reader,
            tribe_verifier=lambda _value: None,
        )
        for index, method, params in (
            (91, "scope.me", {}),
            (92, "scope.tribe", {"tribe_ref": reference}),
        ):
            request = create_request(
                capability,
                request_id=f"30000000-0000-4000-8000-{index:012d}",
                issued_at_ms=NOW,
                method=method,
                params=params,
                nonce=index.to_bytes(16, "big"),
            )
            response = runtime.service.handle(request)
            self.assertTrue(response["ok"], response)
        self.assertEqual(response["result"]["tribe_ref"], reference)

    def test_route_profile_requires_exact_private_custody_and_secret(self) -> None:
        route_secret = seed("dm053-runtime-route")
        signing_slot = "runtime.signing.v1:local"
        capability_slot = "runtime.capability.v1:runtime-test"
        route_slot = "runtime.route.v1:local"
        state_root, bundle, _ = self.make_bundle(
            state_name="routes",
            secrets={
                signing_slot: self.signing_seeds["legion"],
                capability_slot: seed("dm024-capability"),
                route_slot: route_secret,
            },
        )
        origin = self.origins["legion"]
        bundle["routing"] = {
            "filename": "route-custody.json",
            "profile": {
                "schema": "dm.route-profile/v1",
                "profile_id": "route-profile:runtime",
                "body_ref": origin["body_ref"],
                "principal_id": origin["principal_id"],
                "policy_version": "dm.route-policy/v1",
                "enabled": True,
                "local_recipient_ids": ["embodiment:daimonmatrix"],
                "routes": [
                    {
                        "schema": "dm.route-binding/v1",
                        "adapter_id": "adapter:local",
                        "credential_ref": "credential:local",
                        "enabled": True,
                        "priority": 0,
                        "provider_ref": "provider:local",
                        "recipient_body_ref": origin["body_ref"],
                        "recipient_id": "embodiment:daimonmatrix",
                        "route_class": "local",
                        "route_ref": "route:local",
                    }
                ],
            },
        }
        custody = {
            "schema": "dm.route-custody/v1",
            "providers": [
                {
                    "endpoint": "recipient-route.sock",
                    "key_ref": "credential:local",
                    "kind": "local",
                    "provider_ref": "provider:local",
                    "route_ref": "route:local",
                    "secret_slot": route_slot,
                    "timeout_ms": 5_000,
                }
            ],
        }
        custody_path = state_root / "route-custody.json"
        custody_path.write_bytes(canonical_bytes(custody))
        custody_path.chmod(0o600)
        bundle_path = state_root / "runtime.json"
        bundle_path.write_bytes(canonical_bytes(bundle))
        runtime = load_runtime(
            state_root,
            "runtime.json",
            lambda: bytearray(PASSWORD),
            clock=lambda: NOW,
        )
        self.assertIsNotNone(runtime.service.router)
        self.assertNotIn(route_secret, canonical_bytes(bundle))
        self.assertNotIn(str(state_root).encode(), canonical_bytes(bundle))

        changed = copy.deepcopy(custody)
        cast(list[dict[str, Any]], changed["providers"])[0]["secret_slot"] = (
            "runtime.route.v1:missing"
        )
        custody_path.write_bytes(canonical_bytes(changed))
        with self.assertRaisesRegex(RuntimeError, "missing_runtime_secret"):
            load_runtime(
                state_root,
                "runtime.json",
                lambda: bytearray(PASSWORD),
                clock=lambda: NOW,
            )


class UnixDaemonTests(RuntimeFixture):
    def test_fault_boundaries_are_absent_or_exactly_once(self) -> None:
        state_root, _, capability = self.make_bundle()
        runtime = load_runtime(
            state_root,
            "runtime.json",
            lambda: bytearray(PASSWORD),
            clock=lambda: NOW,
        )

        class Fault(Exception):
            pass

        def request(index: int) -> dict[str, Any]:
            return create_request(
                capability,
                request_id=f"30000000-0000-4000-8000-{index:012d}",
                issued_at_ms=NOW,
                method="we.observe",
                params={
                    "subject": f"fault-{index}",
                    "payload": {"summary": f"fault-{index}"},
                    "sensitivity": "personal",
                    "causal_parents": [],
                    "occurred_at_ms": NOW,
                    "event_id": None,
                },
                nonce=index.to_bytes(16, "big"),
            )

        def fail_before(stage: str) -> None:
            if stage == "before_dispatch":
                raise Fault

        def fail_after(stage: str) -> None:
            if stage == "after_dispatch_before_write":
                raise Fault

        before = request(200)
        client, server = socket.socketpair()
        with client, server:
            client.sendall(encode_frame(before))
            with self.assertRaises(Fault):
                serve_connection(
                    runtime,
                    server,
                    fault_hook=fail_before,
                )
        self.assertEqual(runtime.service.ledger.events(), [])
        self.assertTrue(runtime.service.handle(before)["ok"])
        self.assertEqual(len(runtime.service.ledger.events()), 1)

        after = request(201)
        client, server = socket.socketpair()
        with client, server:
            client.sendall(encode_frame(after))
            with self.assertRaises(Fault):
                serve_connection(
                    runtime,
                    server,
                    fault_hook=fail_after,
                )
        self.assertEqual(len(runtime.service.ledger.events()), 2)
        first_retry = runtime.service.handle(after)
        second_retry = runtime.service.handle(after)
        self.assertEqual(canonical_bytes(first_retry), canonical_bytes(second_retry))
        self.assertEqual(len(runtime.service.ledger.events()), 2)

    def test_real_socket_frame_replay_shutdown_and_single_writer(self) -> None:
        state_root, _, capability = self.make_bundle()
        lock = acquire_lock(state_root)
        self.addCleanup(os.close, lock)
        with self.assertRaises(BlockingIOError):
            acquire_lock(state_root)
        runtime = load_runtime(
            state_root,
            "runtime.json",
            lambda: bytearray(PASSWORD),
            clock=lambda: NOW,
        )
        stop = threading.Event()
        thread = threading.Thread(
            target=serve_forever,
            kwargs={"runtime": runtime, "stop": stop},
            daemon=True,
        )
        thread.start()
        for _ in range(100):
            try:
                info = runtime.socket_path.lstat()
            except FileNotFoundError:
                pass
            else:
                if stat.S_ISSOCK(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600:
                    break
            time.sleep(0.01)
        self.assertTrue(runtime.socket_path.exists())
        self.assertEqual(stat.S_IMODE(runtime.socket_path.lstat().st_mode), 0o600)
        request = create_request(
            capability,
            request_id="30000000-0000-4000-8000-000000000002",
            issued_at_ms=NOW,
            method="runtime.status",
            params={},
            nonce=b"s" * 16,
        )
        responses = []
        for _ in range(2):
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.connect(str(runtime.socket_path))
                client.sendall(encode_frame(request))
                header = client.recv(4)
                size = int.from_bytes(header, "big")
                body = b""
                while len(body) < size:
                    body += client.recv(size - len(body))
                responses.append(decode_frame(header + body))
        self.assertEqual(canonical_bytes(responses[0]), canonical_bytes(responses[1]))

        def status(index: int) -> dict[str, Any]:
            concurrent_request = create_request(
                capability,
                request_id=f"30000000-0000-4000-8000-{index:012d}",
                issued_at_ms=NOW,
                method="runtime.status",
                params={},
                nonce=index.to_bytes(16, "big"),
            )
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.connect(str(runtime.socket_path))
                client.sendall(encode_frame(concurrent_request))
                header = client.recv(4)
                size = int.from_bytes(header, "big")
                body = b""
                while len(body) < size:
                    body += client.recv(size - len(body))
            return decode_frame(header + body)

        with ThreadPoolExecutor(max_workers=8) as clients:
            concurrent = list(clients.map(status, range(100, 112)))
        self.assertTrue(all(response["ok"] for response in concurrent))

        malformed = (
            (2 * 1024 * 1024 + 1).to_bytes(4, "big"),
            len(b'{"a":1,"a":2}').to_bytes(4, "big") + b'{"a":1,"a":2}',
            len(b'{ "a":1}').to_bytes(4, "big") + b'{ "a":1}',
            b"\x00\x00\x00\x08{}",
        )
        for frame in malformed:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.settimeout(2)
                client.connect(str(runtime.socket_path))
                client.sendall(frame)
                client.shutdown(socket.SHUT_WR)
                self.assertEqual(client.recv(1), b"")
        stop.set()
        thread.join(timeout=3)
        self.assertFalse(thread.is_alive())
        self.assertFalse(runtime.socket_path.exists())

    def test_regular_file_is_not_removed_as_stale_socket(self) -> None:
        state_root, _, _ = self.make_bundle()
        runtime = load_runtime(
            state_root,
            "runtime.json",
            lambda: bytearray(PASSWORD),
            clock=lambda: NOW,
        )
        runtime.socket_path.write_bytes(b"not a socket")
        runtime.socket_path.chmod(0o600)
        with self.assertRaisesRegex(DaemonError, "unsafe_stale_socket"):
            serve_forever(runtime, stop=threading.Event())
        self.assertEqual(runtime.socket_path.read_bytes(), b"not a socket")

    def test_separate_process_unlocks_only_via_descriptor_without_leak(self) -> None:
        state_root, _, capability, now_ms = self.make_process_bundle()
        password_read, password_write = os.pipe()
        ready_read, ready_write = os.pipe()
        environment = os.environ.copy()
        command = [
            sys.executable,
            "-m",
            "daimon_matrix.daemon",
            "--state-root",
            str(state_root),
            "--password-fd",
            str(password_read),
            "--ready-fd",
            str(ready_write),
        ]
        joined_command = "\x00".join(command).encode()
        joined_environment = "\x00".join(environment.values()).encode()
        forbidden = [PASSWORD, self.signing_seeds["legion"], capability.key]
        for secret in forbidden:
            self.assertNotIn(secret, joined_command)
            self.assertNotIn(secret, joined_environment)
        process = subprocess.Popen(
            command,
            cwd=ROOT,
            env=environment,
            pass_fds=(password_read, ready_write),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        os.close(password_read)
        os.close(ready_write)
        os.write(password_write, PASSWORD)
        os.close(password_write)
        try:
            self.assertEqual(os.read(ready_read, 6), b"READY\n")
            request = create_request(
                capability,
                request_id="30000000-0000-4000-8000-000000000003",
                issued_at_ms=now_ms,
                method="runtime.status",
                params={},
                nonce=b"p" * 16,
            )
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.connect(str(state_root / "matrix.sock"))
                client.sendall(encode_frame(request))
                header = client.recv(4)
                size = int.from_bytes(header, "big")
                body = b""
                while len(body) < size:
                    body += client.recv(size - len(body))
            response = decode_frame(header + body)
            verify_response(
                response,
                capability,
                expected_request_id=request["request_id"],
                expected_request_hash=request_hash(request),
                expected_server=self.origins["legion"],
            )
        finally:
            os.close(ready_read)
            process.terminate()
            stdout, stderr = process.communicate(timeout=5)
        self.assertEqual(process.returncode, 0)
        exported = b"".join(
            path.read_bytes() for path in state_root.iterdir() if path.is_file()
        )
        for secret in forbidden:
            self.assertNotIn(secret, stdout)
            self.assertNotIn(secret, stderr)
            self.assertNotIn(secret, exported)
        records = [line for line in stderr.splitlines() if line]
        self.assertEqual(len(records), 2)
        self.assertIn(b'"code":"ready"', records[0])
        self.assertIn(b'"code":"stopped"', records[1])


if __name__ == "__main__":
    unittest.main()
