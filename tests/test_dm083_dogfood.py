"""Fast Forward regressions found while preparing the real two-host dogfood."""

from __future__ import annotations

import copy
import json
import os
import shutil
import socket
import sys
import tempfile
import threading
import time
import unittest
import uuid
from collections.abc import Callable
from pathlib import Path

from jsonschema import (  # type: ignore[import-untyped]
    Draft202012Validator,
    ValidationError,
)

from daimon_matrix.canonical import canonical_bytes
from daimon_matrix.daemon import _bind_private_socket, create_peer_http_server
from daimon_matrix.keystore import EncryptedKeystore
from daimon_matrix.local_api import (
    LocalApiError,
    LocalCapability,
    create_capability,
    create_request,
)
from daimon_matrix.operator_bootstrap import (
    PROFILE_SCHEMA,
    BootstrapError,
    _create,
)
from daimon_matrix.operator_capabilities import (
    OBSERVE_PROFILE,
    OPERATOR_PROFILE_NAMES,
    operator_capability_lifecycle,
)
from daimon_matrix.runtime import RuntimeError as MatrixRuntimeError
from daimon_matrix.runtime import load_runtime
from daimon_matrix.service import OPERATOR_CAPABILITY_PROFILES, SERVICE_METHODS


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
            self.assertEqual(
                receipt["capability_lifecycle"],
                operator_capability_lifecycle(receipt["created_at_ms"]),
            )
            schema = json.loads(
                (
                    Path(__file__).resolve().parents[1]
                    / "schemas/hosted/v7/bundle.schema.json"
                ).read_bytes()
            )
            Draft202012Validator.check_schema(schema)

            loaded = {}
            bundles = {}
            validator = Draft202012Validator(schema)
            for label, password in (
                ("daimonmatrix", password_remote),
                ("legion", password_legion),
            ):
                state_root = output / "runtimes" / label
                bundle = json.loads((state_root / "runtime.json").read_bytes())
                validator.validate(bundle)
                bundles[label] = bundle
                if label == "daimonmatrix":
                    missing_role = copy.deepcopy(bundle)
                    missing_role["capabilities"].pop()
                    with self.assertRaises(ValidationError):
                        validator.validate(missing_role)
                    duplicate_role = copy.deepcopy(bundle)
                    duplicate_role["capabilities"][-1] = copy.deepcopy(
                        duplicate_role["capabilities"][0]
                    )
                    with self.assertRaises(ValidationError):
                        validator.validate(duplicate_role)
                self.assertNotIn(password, (state_root / "runtime.json").read_bytes())
                bundle_capabilities = bundle["capabilities"]
                self.assertEqual(len(bundle_capabilities), len(OPERATOR_PROFILE_NAMES))
                self.assertEqual(
                    {
                        row["descriptor"]["client_id"].rsplit(":", 1)[-1]
                        for row in bundle_capabilities
                    },
                    set(OPERATOR_PROFILE_NAMES),
                )
                self.assertEqual(
                    len({row["descriptor"]["key_id"] for row in bundle_capabilities}),
                    len(OPERATOR_PROFILE_NAMES),
                )
                self.assertEqual(
                    {row["runtime_id"] for row in bundle_capabilities},
                    {bundle["runtime_id"]},
                )
                status_key_path = state_root / "client.key"
                status_config_path = state_root / "client.json"
                self.assertEqual(status_key_path.stat().st_mode & 0o777, 0o600)
                self.assertEqual(status_config_path.stat().st_mode & 0o777, 0o600)
                status_key = status_key_path.read_bytes()
                status_config = json.loads(status_config_path.read_bytes())
                status_capability = LocalCapability.from_value(
                    status_config["capability"], status_key
                )
                self.assertEqual(
                    frozenset(status_capability.methods),
                    OPERATOR_CAPABILITY_PROFILES[OBSERVE_PROFILE],
                )
                self.assertEqual(
                    status_config["expected_server"], bundle["local_origin"]
                )
                self.assertEqual(
                    len(list((state_root / "operator-clients").iterdir())),
                    len(OPERATOR_PROFILE_NAMES) - 1,
                )
                for role in OPERATOR_PROFILE_NAMES:
                    if role == OBSERVE_PROFILE:
                        continue
                    role_root = state_root / "operator-clients" / role
                    self.assertEqual(role_root.stat().st_mode & 0o777, 0o700)
                    self.assertEqual(
                        (role_root / "client.json").stat().st_mode & 0o777,
                        0o600,
                    )
                    self.assertEqual(
                        (role_root / "capability.key").stat().st_mode & 0o777,
                        0o600,
                    )
                    self.assertNotEqual(
                        status_key, (role_root / "capability.key").read_bytes()
                    )
                loaded[label] = load_runtime(
                    state_root,
                    "runtime.json",
                    _runtime_password_reader(password),
                    clock=lambda: time.time_ns() // 1_000_000,
                )

            with tempfile.TemporaryDirectory(prefix="dm083-mixed-runtime-") as mixed:
                mixed_root = Path(mixed) / "runtime"
                legion_root = output / "runtimes/legion"
                beta_root = output / "runtimes/daimonmatrix"
                shutil.copytree(legion_root, mixed_root)
                mixed_bundle = copy.deepcopy(bundles["legion"])
                role = "weave"
                alpha_row = next(
                    row
                    for row in mixed_bundle["capabilities"]
                    if row["profile"]["role"] == role
                )
                beta_row = next(
                    row
                    for row in bundles["daimonmatrix"]["capabilities"]
                    if row["profile"]["role"] == role
                )
                mixed_bundle["capabilities"][
                    mixed_bundle["capabilities"].index(alpha_row)
                ] = copy.deepcopy(beta_row)
                shutil.copyfile(
                    beta_root / "operator-clients" / role / "client.json",
                    mixed_root / "operator-clients" / role / "client.json",
                )
                shutil.copyfile(
                    beta_root / "operator-clients" / role / "capability.key",
                    mixed_root / "operator-clients" / role / "capability.key",
                )
                alpha_contents = EncryptedKeystore(legion_root / "custody.json").open(
                    _runtime_password_reader(password_legion)
                )
                beta_contents = EncryptedKeystore(beta_root / "custody.json").open(
                    _runtime_password_reader(password_remote)
                )
                mixed_secrets = dict(alpha_contents.secrets)
                del mixed_secrets[alpha_row["secret_slot"]]
                mixed_secrets[beta_row["secret_slot"]] = beta_contents.secrets[
                    beta_row["secret_slot"]
                ]
                EncryptedKeystore.create(
                    mixed_root / "mixed-custody.json",
                    _runtime_password_reader(password_legion),
                    control_head=mixed_bundle["control_head"],
                    secrets=mixed_secrets,
                )
                mixed_bundle["keystore"]["filename"] = "mixed-custody.json"
                mixed_path = mixed_root / "mixed-runtime.json"
                mixed_path.write_bytes(canonical_bytes(mixed_bundle))
                mixed_path.chmod(0o600)
                with self.assertRaisesRegex(
                    MatrixRuntimeError, "invalid_operator_runtime_identity"
                ):
                    load_runtime(
                        mixed_root,
                        mixed_path.name,
                        _runtime_password_reader(password_legion),
                        clock=lambda: time.time_ns() // 1_000_000,
                    )

                mixed_bundle["capabilities"][
                    mixed_bundle["capabilities"].index(beta_row)
                ]["runtime_id"] = mixed_bundle["runtime_id"]
                mixed_path.write_bytes(canonical_bytes(mixed_bundle))
                with self.assertRaisesRegex(
                    MatrixRuntimeError, "invalid_operator_capability_profile"
                ):
                    load_runtime(
                        mixed_root,
                        mixed_path.name,
                        _runtime_password_reader(password_legion),
                        clock=lambda: time.time_ns() // 1_000_000,
                    )

            with tempfile.TemporaryDirectory(prefix="dm083-mixed-client-") as mixed:
                mixed_root = Path(mixed) / "runtime"
                shutil.copytree(output / "runtimes/legion", mixed_root)
                role = "weave"
                shutil.copyfile(
                    output
                    / "runtimes/daimonmatrix/operator-clients"
                    / role
                    / "client.json",
                    mixed_root / "operator-clients" / role / "client.json",
                )
                shutil.copyfile(
                    output
                    / "runtimes/daimonmatrix/operator-clients"
                    / role
                    / "capability.key",
                    mixed_root / "operator-clients" / role / "capability.key",
                )
                with self.assertRaisesRegex(
                    MatrixRuntimeError, "runtime_operator_client_mismatch"
                ):
                    load_runtime(
                        mixed_root,
                        "runtime.json",
                        _runtime_password_reader(password_legion),
                        clock=lambda: time.time_ns() // 1_000_000,
                    )

            invalid_bundle = copy.deepcopy(
                json.loads((output / "runtimes/legion/runtime.json").read_bytes())
            )
            regrouped = copy.deepcopy(invalid_bundle)
            observe_row = next(
                row
                for row in regrouped["capabilities"]
                if row["profile"]["role"] == OBSERVE_PROFILE
            )
            observe_descriptor = observe_row["descriptor"]
            observe_row["descriptor"] = create_capability(
                (output / "runtimes/legion/client.key").read_bytes(),
                client_id=observe_descriptor["client_id"],
                methods=sorted(SERVICE_METHODS),
                not_before_ms=observe_descriptor["not_before_ms"],
                not_after_ms=observe_descriptor["not_after_ms"],
            ).descriptor
            regrouped_path = output / "runtimes/legion/runtime-regrouped.json"
            regrouped_path.write_bytes(canonical_bytes(regrouped))
            regrouped_path.chmod(0o600)
            with self.assertRaisesRegex(
                MatrixRuntimeError, "invalid_operator_capability_profile"
            ):
                load_runtime(
                    output / "runtimes/legion",
                    regrouped_path.name,
                    _runtime_password_reader(password_legion),
                    clock=lambda: time.time_ns() // 1_000_000,
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
            status_config = json.loads(
                (output / "runtimes/legion/client.json").read_bytes()
            )
            status_capability = LocalCapability.from_value(
                status_config["capability"],
                (output / "runtimes/legion/client.key").read_bytes(),
            )
            status_response = legion.service.handle(
                create_request(
                    status_capability,
                    request_id=str(uuid.uuid4()),
                    issued_at_ms=time.time_ns() // 1_000_000,
                    method="runtime.status",
                    params={},
                )
            )
            self.assertTrue(status_response["ok"], status_response)
            with self.assertRaisesRegex(LocalApiError, "authentication_failed"):
                create_request(
                    status_capability,
                    request_id=str(uuid.uuid4()),
                    issued_at_ms=time.time_ns() // 1_000_000,
                    method="we.sync.peer-pull",
                    params={},
                )
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
                observe_key = (output / "runtimes/legion/client.key").read_bytes()
                observe_config = json.loads(
                    (output / "runtimes/legion/client.json").read_bytes()
                )
                observe_capability = LocalCapability.from_value(
                    observe_config["capability"], observe_key
                )
                now = time.time_ns() // 1_000_000
                scope_request = create_request(
                    observe_capability,
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
                    LocalCapability.from_value(
                        json.loads(
                            (
                                output
                                / "runtimes/legion/operator-clients/weave/client.json"
                            ).read_bytes()
                        )["capability"],
                        (
                            output
                            / "runtimes/legion/operator-clients/weave/capability.key"
                        ).read_bytes(),
                    ),
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
