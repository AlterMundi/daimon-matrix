from __future__ import annotations

import copy
import json
import os
import socket
import stat
import threading
import time
import unittest
import uuid
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from daimon_matrix.canonical import canonical_bytes
from daimon_matrix.client import (
    CLIENT_CONFIG_SCHEMA_V3,
    ClientConfig,
    ClientError,
    LocalClient,
    load_json_document,
    load_prepared_request,
    read_capability_key,
    store_prepared_request,
)
from daimon_matrix.daemon import serve_forever
from daimon_matrix.runtime import load_runtime
from tests.test_dm022_ledger import NOW
from tests.test_dm024_runtime import PASSWORD, RuntimeFixture


class ClientFixture(RuntimeFixture):
    def setUp(self) -> None:
        super().setUp()
        self.state_root, bundle, self.capability = self.make_bundle()
        self.runtime = load_runtime(
            self.state_root,
            "runtime.json",
            lambda: bytearray(PASSWORD),
            clock=lambda: NOW,
        )
        self.stop = threading.Event()
        self.thread = threading.Thread(
            target=serve_forever,
            kwargs={"runtime": self.runtime, "stop": self.stop},
            daemon=True,
        )
        self.thread.start()
        for _ in range(100):
            try:
                info = self.runtime.socket_path.lstat()
            except FileNotFoundError:
                pass
            else:
                if stat.S_ISSOCK(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600:
                    break
            time.sleep(0.01)
        self.config_path = self.state_root / "client.json"
        self.config_value = {
            "schema": CLIENT_CONFIG_SCHEMA_V3,
            "capability": self.capability.descriptor,
            "expected_server": self.origins["legion"],
            "runtime_id": bundle["runtime_id"],
            "runtime_label": bundle["runtime_label"],
        }
        self.config_path.write_bytes(canonical_bytes(self.config_value))
        self.config_path.chmod(0o600)

    def tearDown(self) -> None:
        self.stop.set()
        self.thread.join(timeout=3)
        super().tearDown()

    def client(self) -> LocalClient:
        key = bytearray(self.capability.key)
        config = ClientConfig.load(self.config_path, key)
        self.assertEqual(key, bytearray(32))
        return LocalClient(
            self.runtime.socket_path,
            config,
            clock=lambda: NOW,
            uuid_factory=lambda: uuid.UUID("40000000-0000-4000-8000-000000000001"),
            nonce_factory=lambda size: b"n" * size,
        )


class LocalClientTests(ClientFixture):
    def test_optional_absolute_deadline_preserves_authenticated_success(self) -> None:
        client = replace(self.client(), deadline_ns=time.monotonic_ns() + 2_000_000_000)
        request = client.prepare("runtime.status", {})
        before = copy.deepcopy(request)
        self.assertTrue(client.send(request)["ok"])
        self.assertEqual(request, before)
        for invalid in (True, -1, 2**63, 1.0):
            with self.assertRaisesRegex(ClientError, "invalid_client_deadline"):
                replace(client, deadline_ns=invalid)  # type: ignore[arg-type]

    def test_expired_deadline_during_setup_never_connects(self) -> None:
        import daimon_matrix.client as module

        client = replace(self.client(), deadline_ns=time.monotonic_ns() + 1_000_000_000)
        request = client.prepare("runtime.status", {})
        actual = module._socket_is_owner_only
        assert client.deadline_ns is not None
        expired = client.deadline_ns + 1

        def setup(path: Path) -> None:
            actual(path)
            clock.return_value = expired

        with (
            patch.object(time, "monotonic_ns", return_value=expired - 2) as clock,
            patch.object(module, "_socket_is_owner_only", side_effect=setup),
            patch.object(socket.socket, "connect") as connect,
        ):
            with self.assertRaisesRegex(ClientError, "daemon_deadline_expired"):
                client.send(request)
            connect.assert_not_called()

    def test_absolute_deadline_bounds_fragmented_header_body_and_eof(self) -> None:
        # These read-only peer fixtures deliberately never provide a valid
        # authenticated result. The native request remains the same retry token.
        for phase in ("header", "body", "eof"):
            with self.subTest(phase=phase):
                path = self.root_path / ("slow-" + phase + ".sock")
                listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                listener.bind(str(path))
                path.chmod(0o600)
                listener.listen(1)
                listener.settimeout(2)
                stop = threading.Event()

                def server(
                    listener: socket.socket = listener,
                    phase: str = phase,
                    stop: threading.Event = stop,
                ) -> None:
                    try:
                        with listener.accept()[0] as connection:
                            connection.settimeout(1)
                            connection.recv(65536)
                            if phase == "body":
                                connection.sendall((1024).to_bytes(4, "big"))
                            elif phase == "eof":
                                connection.sendall((2).to_bytes(4, "big") + b"{}")
                                stop.wait(1)
                                return
                            while not stop.wait(0.03):
                                connection.sendall(b"\0" if phase == "header" else b" ")
                    except OSError:
                        pass  # Deadline closes the client connection.

                worker = threading.Thread(target=server)
                worker.start()
                try:
                    start = time.monotonic()
                    client = replace(
                        self.client(),
                        socket_path=path,
                        timeout_seconds=1,
                        deadline_ns=time.monotonic_ns() + 90_000_000,
                    )
                    request = client.prepare("runtime.status", {})
                    before = copy.deepcopy(request)
                    with self.assertRaisesRegex(
                        ClientError, "daemon_unavailable|daemon_deadline_expired"
                    ):
                        client.send(request)
                    self.assertLess(time.monotonic() - start, 0.7)
                    self.assertEqual(request, before)
                finally:
                    stop.set()
                    worker.join(2)
                    listener.close()
                    path.unlink()
                self.assertFalse(worker.is_alive())

    def test_v3_binds_operator_client_to_one_runtime_identity(self) -> None:
        self.config_path.write_bytes(
            canonical_bytes(
                {
                    "schema": CLIENT_CONFIG_SCHEMA_V3,
                    "capability": self.capability.descriptor,
                    "expected_server": self.origins["legion"],
                    "runtime_id": "dm:runtime:v1:" + "a" * 43,
                    "runtime_label": "legion",
                }
            )
        )
        config = ClientConfig.load(self.config_path, bytearray(self.capability.key))
        self.assertEqual(config.runtime_id, "dm:runtime:v1:" + "a" * 43)
        self.assertEqual(config.runtime_label, "legion")
        mismatched = LocalClient(
            self.runtime.socket_path,
            config,
            clock=lambda: NOW,
            uuid_factory=lambda: uuid.UUID("40000000-0000-4000-8000-000000000099"),
            nonce_factory=lambda size: b"r" * size,
        )
        with self.assertRaisesRegex(ClientError, "daemon_response_rejected"):
            mismatched.runtime_status()

        invalid = json.loads(self.config_path.read_bytes())
        invalid["runtime_id"] = "dm:runtime:v1:short"
        self.config_path.write_bytes(canonical_bytes(invalid))
        with self.assertRaisesRegex(ClientError, "invalid_client_runtime_identity"):
            ClientConfig.load(self.config_path, bytearray(self.capability.key))

    def test_typed_client_verifies_response_and_retries_exact_bytes(self) -> None:
        client = self.client()
        request = client.prepare(
            "we.observe",
            {
                "subject": "client-observation",
                "payload": {"summary": "client-observation"},
                "sensitivity": "personal",
                "causal_parents": [],
                "occurred_at_ms": NOW,
                "event_id": None,
            },
        )
        first = client.send(request)
        second = client.send(request)
        self.assertEqual(canonical_bytes(first), canonical_bytes(second))
        self.assertEqual(len(self.runtime.service.ledger.events()), 1)
        _, status = client.runtime_status(
            request_id="40000000-0000-4000-8000-000000000002"
        )
        self.assertTrue(status["ok"])
        _, me = client.scope_me(request_id="40000000-0000-4000-8000-000000000003")
        _, topology = client.scope_we(request_id="40000000-0000-4000-8000-000000000004")
        _, difference = client.scope_diff(
            request_id="40000000-0000-4000-8000-000000000005"
        )
        _, plan = client.scope_sync_plan(
            {
                "request_id": "40000000-0000-4000-8000-000000000006",
                "limit": 8,
            },
            request_id="40000000-0000-4000-8000-000000000007",
        )
        _, resolution = client.scope_resolve(
            {
                "request_id": "40000000-0000-4000-8000-000000000008",
                "scope": "/we",
                "tribe_ref": None,
            },
            request_id="40000000-0000-4000-8000-000000000009",
        )
        _, absent_tribe = client.scope_tribe(
            "dm:tribe:v1:absent",
            request_id="40000000-0000-4000-8000-000000000010",
        )
        self.assertEqual(me["result"]["schema"], "dm.scope.me/v1")
        self.assertEqual(topology["result"]["schema"], "dm.scope.we/v1")
        self.assertEqual(difference["result"]["schema"], "dm.scope.we-diff/v1")
        self.assertEqual(plan["result"]["schema"], "dm.scope.sync-plan/v1")
        self.assertEqual(resolution["result"]["scope"], "/we")
        self.assertEqual(absent_tribe["error"]["code"], "tribe_not_configured")

    def test_config_key_socket_and_response_binding_fail_closed(self) -> None:
        self.config_path.chmod(0o644)
        with self.assertRaisesRegex(ClientError, "client_config_not_owner_only"):
            ClientConfig.load(self.config_path, bytearray(self.capability.key))
        self.config_path.chmod(0o600)

        duplicate = b'{"schema":"x","schema":"x"}'
        with self.assertRaisesRegex(ClientError, "duplicate_json_key"):
            load_json_document(duplicate)

        read_descriptor, write_descriptor = os.pipe()
        os.write(write_descriptor, self.capability.key)
        os.close(write_descriptor)
        supplied = read_capability_key(read_descriptor)
        self.assertEqual(supplied, bytearray(self.capability.key))

        wrong = copy.deepcopy(self.config_value)
        wrong["expected_server"]["principal_id"] = "compaii@wrong"
        self.config_path.write_bytes(canonical_bytes(wrong))
        client = LocalClient(
            self.runtime.socket_path,
            ClientConfig.load(self.config_path, bytearray(self.capability.key)),
            clock=lambda: NOW,
        )
        with self.assertRaisesRegex(ClientError, "daemon_response_rejected"):
            client.runtime_status()

        self.runtime.socket_path.chmod(0o666)
        with self.assertRaisesRegex(ClientError, "daemon_socket_untrusted"):
            self.client().runtime_status()

    def test_pre_v3_config_is_rejected_without_response_fallback(self) -> None:
        old = self.origins["legion"]
        current = {**old, "incarnation_id": "incarnation:client-successor"}
        self.config_path.write_bytes(
            canonical_bytes(
                {
                    "schema": "dm.local.client-config/v2",
                    "capability": self.capability.descriptor,
                    "expected_server": current,
                    "historical_servers": [{"server": old, "retired_at_ms": NOW}],
                }
            )
        )
        with self.assertRaisesRegex(ClientError, "unsupported_client_config"):
            ClientConfig.load(self.config_path, bytearray(self.capability.key))
        retired_v1 = {
            "schema": "dm.local.client-config/v1",
            "capability": self.capability.descriptor,
            "expected_server": old,
        }
        self.config_path.write_bytes(canonical_bytes(retired_v1))
        with self.assertRaisesRegex(ClientError, "unsupported_client_config"):
            ClientConfig.load(self.config_path, bytearray(self.capability.key))

    def test_public_surface_has_no_arbitrary_method_call(self) -> None:
        client = self.client()
        self.assertFalse(hasattr(client, "call"))
        with self.assertRaisesRegex(ClientError, "unsupported_client_method"):
            client.prepare("identity.rotate", {})

    def test_owner_only_request_file_is_an_exact_operation_token(self) -> None:
        client = self.client()
        params = {
            "subject": "durable-client-token",
            "payload": {"summary": "durable-client-token"},
            "sensitivity": "personal",
            "causal_parents": [],
            "occurred_at_ms": NOW,
            "event_id": None,
        }
        request = client.prepare("we.observe", params)
        path = self.state_root / "retry.json"
        store_prepared_request(path, request)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        loaded = load_prepared_request(
            path,
            self.capability,
            method="we.observe",
            params=params,
        )
        self.assertEqual(canonical_bytes(loaded), canonical_bytes(request))
        with self.assertRaisesRegex(ClientError, "request_file_exists"):
            store_prepared_request(path, request)
        with self.assertRaisesRegex(ClientError, "request_operation_mismatch"):
            load_prepared_request(
                path,
                self.capability,
                method="we.observe",
                params={**params, "subject": "different"},
            )


if __name__ == "__main__":
    unittest.main()
