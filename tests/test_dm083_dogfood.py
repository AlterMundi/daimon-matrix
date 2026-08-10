"""Fast Forward regressions found while preparing the real two-host dogfood."""

from __future__ import annotations

import copy
import json
import os
import socket
import sys
import tempfile
import threading
import time
import unittest
import uuid
from collections.abc import Callable
from pathlib import Path

from jsonschema import Draft202012Validator  # type: ignore[import-untyped]

from daimon_matrix.canonical import canonical_bytes
from daimon_matrix.daemon import _bind_private_socket, create_peer_http_server
from daimon_matrix.local_api import LocalCapability, create_request
from daimon_matrix.operator_bootstrap import PROFILE_SCHEMA, BootstrapError, _create
from daimon_matrix.runtime import RuntimeError as MatrixRuntimeError
from daimon_matrix.runtime import load_runtime


class DM083SocketPublicationTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux AF_UNIX boundary")
    def test_private_staging_fits_when_public_socket_fits(self) -> None:
        # Linux sockaddr_un allows 107 non-NUL path bytes.  Exercise a public
        # path at that boundary; the atomic private staging name must not make
        # the effective path longer.
        with tempfile.TemporaryDirectory(prefix="dm083-") as directory:
            root = Path(directory)
            remaining = 107 - len(os.fsencode(root)) - 2 - len("matrix.sock")
            nested = root / ("x" * remaining)
            nested.mkdir(mode=0o700)
            target = nested / "matrix.sock"
            self.assertEqual(len(os.fsencode(target)), 107)

            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                _bind_private_socket(listener, target)
                self.assertTrue(target.is_socket())
                self.assertFalse(
                    any(path.name.startswith(".s-") for path in nested.iterdir())
                )
            finally:
                listener.close()
                target.unlink(missing_ok=True)


def _password_descriptor(password: bytes) -> int:
    reader, writer = os.pipe()
    os.write(writer, password)
    os.close(writer)
    return reader


def _available_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as candidate:
        candidate.bind(("127.0.0.1", 0))
        return int(candidate.getsockname()[1])


def _runtime_password_reader(password: bytes) -> Callable[[], bytearray]:
    def read() -> bytearray:
        return bytearray(password)

    return read


class DM083OperatorBootstrapTests(unittest.TestCase):
    def test_password_reuse_is_rejected_before_output_exists(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dm083-bootstrap-reuse-") as directory:
            root = Path(directory)
            profile = {
                "schema": PROFILE_SCHEMA,
                "embodiments": [
                    {
                        "label": label,
                        "body_ref": f"cluster:{label}:compaii",
                        "principal_id": f"compaii@{label}",
                        "listen_host": "127.0.0.1",
                        "listen_port": _available_port(),
                        "advertised_endpoint": (
                            f"http://127.0.0.1:{_available_port()}/dm-peer/v1"
                        ),
                    }
                    for label in ("daimonmatrix", "legion")
                ],
            }
            profile_path = root / "profile.json"
            profile_path.write_bytes(canonical_bytes(profile))
            reused = b"same-password-is-not-custody-separation"
            output = root / "ceremony"
            with self.assertRaisesRegex(BootstrapError, "password_reuse_rejected"):
                _create(
                    output,
                    profile_path,
                    _password_descriptor(reused),
                    [
                        f"daimonmatrix={_password_descriptor(reused)}",
                        f"legion={_password_descriptor(reused)}",
                    ],
                )
            self.assertFalse(output.exists())

    def test_plural_ceremony_loads_v7_and_pulls_from_configured_peer(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dm083-bootstrap-") as directory:
            root = Path(directory)
            legion_port = _available_port()
            remote_port = _available_port()
            profile = {
                "schema": PROFILE_SCHEMA,
                "embodiments": [
                    {
                        "label": "daimonmatrix",
                        "body_ref": "cluster:daimonmatrix:compaii",
                        "principal_id": "compaii@daimonmatrix",
                        "listen_host": "127.0.0.1",
                        "listen_port": remote_port,
                        "advertised_endpoint": (
                            f"http://127.0.0.1:{remote_port}/dm-peer/v1"
                        ),
                    },
                    {
                        "label": "legion",
                        "body_ref": "cluster:legion:compaii",
                        "principal_id": "compaii@legion",
                        "listen_host": "127.0.0.1",
                        "listen_port": legion_port,
                        "advertised_endpoint": (
                            f"http://127.0.0.1:{legion_port}/dm-peer/v1"
                        ),
                    },
                ],
            }
            profile_path = root / "profile.json"
            profile_path.write_bytes(canonical_bytes(profile))
            password_root = b"root-password-for-dm083"
            password_legion = b"legion-password-for-dm083"
            password_remote = b"remote-password-for-dm083"
            output = root / "ceremony"
            receipt = _create(
                output,
                profile_path,
                _password_descriptor(password_root),
                [
                    f"daimonmatrix={_password_descriptor(password_remote)}",
                    f"legion={_password_descriptor(password_legion)}",
                ],
            )
            self.assertEqual(receipt["runtime_schema"], "dm.runtime.bundle/v7")
            schema = json.loads(
                (
                    Path(__file__).resolve().parents[1]
                    / "schemas/hosted/v7/bundle.schema.json"
                ).read_bytes()
            )
            Draft202012Validator.check_schema(schema)

            loaded = {}
            for label, password in (
                ("daimonmatrix", password_remote),
                ("legion", password_legion),
            ):
                state_root = output / "runtimes" / label
                bundle = json.loads((state_root / "runtime.json").read_bytes())
                Draft202012Validator(schema).validate(bundle)
                self.assertNotIn(password, (state_root / "runtime.json").read_bytes())
                loaded[label] = load_runtime(
                    state_root,
                    "runtime.json",
                    _runtime_password_reader(password),
                    clock=lambda: time.time_ns() // 1_000_000,
                )

            invalid_bundle = copy.deepcopy(
                json.loads((output / "runtimes/legion/runtime.json").read_bytes())
            )
            target = invalid_bundle["peer_transport"]["targets"][0]
            invalid_bundle["peer_transport"]["targets"] = [
                {**target, "embodiment_id": "z-unsorted"},
                {**target, "embodiment_id": "a-unsorted"},
            ]
            invalid_path = output / "runtimes/legion/runtime-invalid.json"
            invalid_path.write_bytes(canonical_bytes(invalid_bundle))
            invalid_path.chmod(0o600)
            with self.assertRaisesRegex(
                MatrixRuntimeError, "invalid_peer_target_configuration"
            ):
                load_runtime(
                    output / "runtimes/legion",
                    invalid_path.name,
                    _runtime_password_reader(password_legion),
                    clock=lambda: time.time_ns() // 1_000_000,
                )

            remote = loaded["daimonmatrix"]
            legion = loaded["legion"]
            event = remote.service.ledger.append_local(
                kind="experience.observed",
                subject="dm083/operator-bootstrap",
                payload={"summary": "configured peer pull"},
                signer=remote.service.signer,
                sensitivity="shareable",
            )
            server = create_peer_http_server(remote)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                key = (output / "runtimes/legion/client.key").read_bytes()
                config = json.loads(
                    (output / "runtimes/legion/client.json").read_bytes()
                )
                capability = LocalCapability.from_value(config["capability"], key)
                now = time.time_ns() // 1_000_000
                scope_request = create_request(
                    capability,
                    request_id=str(uuid.uuid4()),
                    issued_at_ms=now,
                    method="scope.we",
                    params={},
                )
                scope = legion.service.handle(scope_request)
                self.assertTrue(scope["ok"], scope)
                self.assertFalse(scope["result"]["partial"])
                remote_id = remote.service.origin["embodiment_id"]
                availability = {
                    row["embodiment_id"]: row["availability"]
                    for row in scope["result"]["embodiments"]
                }
                self.assertEqual(availability[remote_id], "available")

                pull_request = create_request(
                    capability,
                    request_id=str(uuid.uuid4()),
                    issued_at_ms=time.time_ns() // 1_000_000,
                    method="we.sync.peer-pull",
                    params={
                        "sync_request_id": str(uuid.uuid4()),
                        "target_embodiment_id": remote_id,
                        "limit": 16,
                    },
                )
                response = legion.service.handle(pull_request)
                self.assertTrue(response["ok"], response)
                self.assertEqual(response["result"]["events"], 1)
                self.assertEqual(
                    response["result"]["receipt"]["page_hash"],
                    response["result"]["page_hash"],
                )
                imported = legion.service.ledger.event(event["event_id"])
                self.assertEqual(imported, event)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
