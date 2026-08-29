from __future__ import annotations

import copy
import hashlib
import json
import os
import socket
import subprocess
import sys
import threading
import uuid
from collections.abc import Sequence
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase

from daimon_matrix.canonical import b64url, canonical_bytes, digest
from daimon_matrix.daemon import create_peer_http_server
from daimon_matrix.keystore import EncryptedKeystore, PasswordReader
from daimon_matrix.local_api import LocalCapability, create_request
from daimon_matrix.operator_first_embodiment import (
    ACTIVATION_DOMAIN as FIRST_ACTIVATION_DOMAIN,
)
from daimon_matrix.operator_first_embodiment import (
    ACTIVATION_ID_PREFIX as FIRST_ACTIVATION_ID_PREFIX,
)
from daimon_matrix.operator_first_embodiment import (
    FirstEmbodimentError,
    activate_runtime,
    aggregate_activation,
    create_root_share,
    prepare_target,
    validate_activation,
)
from daimon_matrix.operator_genesis import (
    PENDING_CONTROL_HEAD,
    aggregate_intent,
    create_holder_package,
    create_holder_share,
    create_intent,
)
from daimon_matrix.operator_rebirth import (
    REQUEST_DOMAIN,
    REQUEST_ID_PREFIX,
    TRANSPORT_REQUEST_DOMAIN,
    RebirthError,
    _request_signature,
    activate_target_runtime,
    aggregate_distributed_enrollment,
    apply_activation_to_runtime_bundle,
    create_distributed_enrollment_intent,
    create_distributed_enrollment_share_from_holder,
    create_target_preparation,
)
from daimon_matrix.operator_rebirth import (
    validate_activation as validate_rebirth_activation,
)
from daimon_matrix.runtime import load_runtime

NOW = 1_800_000_000_000
ROOT = Path(__file__).resolve().parents[1]


def _reader(value: bytes) -> PasswordReader:
    return lambda: bytearray(value)


def _available_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as candidate:
        candidate.bind(("127.0.0.1", 0))
        return int(candidate.getsockname()[1])


class FirstEmbodimentTests(TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory(prefix="dm-first-embodiment-")
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        self.passwords: dict[str, bytes] = {}
        self.holders: dict[str, Path] = {}
        descriptors: list[dict[str, object]] = []
        for role in ("root", "recovery"):
            for index in range(3):
                name = f"{role}-{index}"
                password = f"first-{name}-password".encode()
                holder = self.root / name
                descriptor = create_holder_package(
                    holder,
                    role,
                    _reader(password),
                )
                self.passwords[name] = password
                self.holders[name] = holder
                descriptors.append(descriptor)
        intent = create_intent(
            descriptors,
            root_threshold=2,
            recovery_threshold=2,
            created_at_ms=NOW,
            nonce=b"g" * 32,
        )
        shares = [
            create_holder_share(
                intent, self.holders[name], _reader(self.passwords[name])
            )
            for name in ("root-0", "root-1", "recovery-0", "recovery-1")
        ]
        self.genesis = aggregate_intent(intent, shares)
        self.target_password = b"first-target-password"
        self.first_port = _available_port()
        self.preparation_directory = self.root / "preparation"
        self.preparation = prepare_target(
            self.preparation_directory,
            self.genesis,
            {
                "schema": "dm.operator.rebirth-target-profile/v1",
                "label": "first",
                "body_ref": "cluster:test:first",
                "principal_id": "first@test",
                "listen_host": "127.0.0.1",
                "listen_port": self.first_port,
                "advertised_endpoint": (
                    f"http://127.0.0.1:{self.first_port}/dm-peer/v1"
                ),
                "targets": [],
            },
            _reader(self.target_password),
            created_at_ms=NOW + 10,
        )
        self.request = json.loads(
            (self.preparation_directory / "request.json").read_bytes()
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def invoke_rebirth(
        self, arguments: Sequence[str], password: bytes | None = None
    ) -> subprocess.CompletedProcess[bytes]:
        descriptors: tuple[int, ...] = ()
        values = list(arguments)
        reader = -1
        if password is not None:
            reader, writer = os.pipe()
            os.write(writer, password)
            os.close(writer)
            descriptors = (reader,)
            values = [
                str(reader) if value == "{password}" else value for value in values
            ]
        try:
            return subprocess.run(
                [sys.executable, "-m", "daimon_matrix.operator_rebirth", *values],
                cwd=ROOT,
                env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
                pass_fds=descriptors,
                capture_output=True,
                check=False,
            )
        finally:
            if reader >= 0:
                os.close(reader)

    def root_share(self, name: str) -> dict[str, object]:
        return create_root_share(
            self.genesis,
            self.request,
            self.holders[name],
            _reader(self.passwords[name]),
            observed_at_ms=NOW + 20,
        )

    def activation(self) -> dict[str, object]:
        return aggregate_activation(
            self.genesis,
            self.request,
            [self.root_share("root-0"), self.root_share("root-1")],
            observed_at_ms=NOW + 20,
        )

    def resigned_request(self) -> dict[str, object]:
        body = copy.deepcopy(self.request["body"])
        body["expires_at_ms"] += 30_000
        body["nonce"] = b64url(b"r" * 32)
        body_custody = EncryptedKeystore(
            self.preparation_directory / "custody.json"
        ).open(
            _reader(self.target_password),
            required_control_head=self.request["body"]["control_head"],
        )
        transport_custody = EncryptedKeystore(
            self.preparation_directory / "transport-custody.json"
        ).open(
            _reader(self.target_password),
            required_control_head=self.request["body"]["control_head"],
        )
        signing_seed = body_custody.secrets[self.preparation["slots"]["signing"]]
        transport_seed = transport_custody.secrets[
            self.preparation["slots"]["transport"]
        ]
        return {
            "schema": self.request["schema"],
            "request_id": REQUEST_ID_PREFIX + b64url(digest(REQUEST_DOMAIN, body)),
            "body": body,
            "signature": _request_signature(signing_seed, body),
            "transport_signature": _request_signature(
                transport_seed,
                body,
                domain=TRANSPORT_REQUEST_DOMAIN,
            ),
        }

    def test_distributed_genesis_becomes_a_loadable_first_runtime(self) -> None:
        activation = self.activation()
        verified, authority = validate_activation(
            self.genesis, self.request, activation
        )
        self.assertEqual(verified, activation)
        self.assertEqual(authority.manifest.value["revision"], 1)
        self.assertEqual(len(authority.manifest.value["embodiments"]), 1)

        output = self.root / "activated"
        receipt = activate_runtime(
            output,
            self.genesis,
            self.preparation_directory,
            self.preparation,
            self.request,
            activation,
            _reader(self.target_password),
        )
        self.assertEqual(receipt["runtime_schema"], "dm.runtime.bundle/v7")
        self.assertFalse(receipt["root_seeds_in_target"])
        bundle = json.loads((output / "runtime/runtime.json").read_bytes())
        self.assertEqual(bundle["manifest"]["revision"], 1)
        self.assertEqual(bundle["peer_transport"]["targets"], [])
        runtime = load_runtime(
            output / "runtime",
            "runtime.json",
            _reader(self.target_password),
            clock=lambda: NOW + 20,
        )
        self.assertEqual(
            runtime.service.ledger.authority.manifest.digest,
            receipt["manifest_hash"],
        )

        public = json.dumps(
            {
                "genesis": self.genesis,
                "request": self.request,
                "activation": activation,
                "receipt": receipt,
            }
        ).encode()
        for name, holder in self.holders.items():
            self.assertNotIn(self.passwords[name], public)
            self.assertNotIn((holder / "holder.json").read_bytes(), public)
        body_custody = EncryptedKeystore(
            self.preparation_directory / "custody.json"
        ).open(
            _reader(self.target_password),
            required_control_head=authority.state.head,
        )
        self.assertFalse(any(slot.startswith("root.") for slot in body_custody.secrets))

    def test_threshold_duplicates_roles_tamper_and_password_fail_closed(self) -> None:
        first = self.root_share("root-0")
        with self.assertRaisesRegex(
            FirstEmbodimentError, "first_embodiment_threshold_rejected"
        ):
            aggregate_activation(
                self.genesis,
                self.request,
                [first],
                observed_at_ms=NOW + 20,
            )
        with self.assertRaisesRegex(
            FirstEmbodimentError, "first_embodiment_share_rejected"
        ):
            aggregate_activation(
                self.genesis,
                self.request,
                [first, first],
                observed_at_ms=NOW + 20,
            )
        with self.assertRaisesRegex(
            FirstEmbodimentError, "first_embodiment_root_holder_rejected"
        ):
            self.root_share("recovery-0")
        with self.assertRaisesRegex(
            FirstEmbodimentError, "first_embodiment_request_rejected"
        ):
            create_root_share(
                self.genesis,
                self.request,
                self.holders["root-0"],
                _reader(self.passwords["root-0"]),
                observed_at_ms=self.request["body"]["expires_at_ms"],
            )

        activation = self.activation()
        tampered = copy.deepcopy(activation)
        tampered["body"]["origin"]["principal_id"] = "forged@test"  # type: ignore[index]
        with self.assertRaises(FirstEmbodimentError):
            validate_activation(self.genesis, self.request, tampered)

        output = self.root / "wrong-password-output"
        with self.assertRaisesRegex(
            FirstEmbodimentError, "first_embodiment_target_rejected"
        ):
            activate_runtime(
                output,
                self.genesis,
                self.preparation_directory,
                self.preparation,
                self.request,
                activation,
                _reader(b"wrong-target-password"),
            )
        self.assertFalse(output.exists())

        root_store = EncryptedKeystore(self.holders["root-0"] / "holder.json").open(
            _reader(self.passwords["root-0"]),
            required_control_head=PENDING_CONTROL_HEAD,
        )
        self.assertEqual(set(root_store.secrets), {"genesis.root.v1:holder"})

    def test_root_approvals_cannot_be_reassociated_to_a_new_request(self) -> None:
        shares = [self.root_share("root-0"), self.root_share("root-1")]
        replacement = self.resigned_request()
        rebound = copy.deepcopy(shares)
        for share in rebound:
            share["request_id"] = replacement["request_id"]
            share["request_sha256"] = hashlib.sha256(
                canonical_bytes(replacement)
            ).hexdigest()
        with self.assertRaisesRegex(
            FirstEmbodimentError, "first_embodiment_share_rejected"
        ):
            aggregate_activation(
                self.genesis,
                replacement,
                rebound,
                observed_at_ms=NOW + 20,
            )

        activation = aggregate_activation(
            self.genesis,
            self.request,
            shares,
            observed_at_ms=NOW + 20,
        )
        reassociated = copy.deepcopy(activation)
        reassociated["body"]["request_id"] = replacement["request_id"]
        replacement_hash = hashlib.sha256(canonical_bytes(replacement)).hexdigest()
        for approval in reassociated["body"]["root_approvals"]:
            approval["request_id"] = replacement["request_id"]
            approval["request_sha256"] = replacement_hash
        reassociated["activation_id"] = FIRST_ACTIVATION_ID_PREFIX + b64url(
            digest(FIRST_ACTIVATION_DOMAIN, reassociated["body"])
        )
        with self.assertRaisesRegex(
            FirstEmbodimentError, "invalid_first_embodiment_activation"
        ):
            validate_activation(self.genesis, replacement, reassociated)

    def test_intermediate_symlink_and_fifo_inputs_fail_without_writes(self) -> None:
        real = self.root / "real-output-parent"
        real.mkdir(mode=0o700)
        parent = real / "parent"
        parent.mkdir(mode=0o700)
        alias = self.root / "output-alias"
        alias.symlink_to(real, target_is_directory=True)
        with self.assertRaisesRegex(
            FirstEmbodimentError, "first_embodiment_preparation_rejected"
        ):
            prepare_target(
                alias / "parent/output",
                self.genesis,
                self.preparation["profile"],
                _reader(b"another-target-password"),
                created_at_ms=NOW + 20,
            )
        self.assertFalse((parent / "output").exists())

        fifo = self.root / "genesis.fifo"
        os.mkfifo(fifo, 0o600)
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "daimon_matrix.operator_first_embodiment",
                "prepare",
                "--genesis",
                str(fifo),
                "--profile",
                str(self.preparation_directory / "request.json"),
                "--password-fd",
                "0",
                "--output",
                str(self.root / "fifo-output"),
            ],
            cwd=ROOT,
            env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            timeout=2,
        )
        self.assertEqual(result.returncode, 2, result.stderr.decode())
        self.assertIn(b"first_embodiment_genesis_unavailable", result.stderr)
        self.assertFalse((self.root / "fifo-output").exists())

    def test_second_embodiment_syncs_an_event_from_before_its_birth(self) -> None:
        first_activation = self.activation()
        _verified, first_authority = validate_activation(
            self.genesis, self.request, first_activation
        )
        first_output = self.root / "first"
        activate_runtime(
            first_output,
            self.genesis,
            self.preparation_directory,
            self.preparation,
            self.request,
            first_activation,
            _reader(self.target_password),
        )
        first_runtime = load_runtime(
            first_output / "runtime",
            "runtime.json",
            _reader(self.target_password),
            clock=lambda: NOW + 20,
        )
        old_event = first_runtime.service.ledger.append_local(
            kind="experience.observed",
            subject="before-second-embodiment",
            payload={"summary": "memory predates the second embodiment"},
            signer=first_runtime.service.signer,
            sensitivity="shareable",
        )
        self.assertEqual(old_event["manifest_hash"], first_authority.manifest.digest)

        second_port = _available_port()
        second_password = b"second-target-password"
        second_preparation_directory = self.root / "second-preparation"
        second_preparation = create_target_preparation(
            second_preparation_directory,
            first_authority,
            {
                "schema": "dm.operator.rebirth-target-profile/v1",
                "label": "second",
                "body_ref": "cluster:test:second",
                "principal_id": "second@test",
                "listen_host": "127.0.0.1",
                "listen_port": second_port,
                "advertised_endpoint": (f"http://127.0.0.1:{second_port}/dm-peer/v1"),
                "targets": [
                    {
                        "embodiment_id": first_runtime.service.origin["embodiment_id"],
                        "endpoint": (f"http://127.0.0.1:{self.first_port}/dm-peer/v1"),
                        "timeout_ms": 5_000,
                    }
                ],
            },
            _reader(second_password),
            created_at_ms=NOW + 30,
            expires_at_ms=NOW + 60_030,
        )
        second_request = json.loads(
            (second_preparation_directory / "request.json").read_bytes()
        )
        intent = create_distributed_enrollment_intent(
            second_request,
            first_authority,
            issued_at_ms=NOW + 40,
            expires_at_ms=NOW + 60_040,
            nonce=b"e" * 32,
        )
        enrollment_shares = [
            create_distributed_enrollment_share_from_holder(
                intent,
                second_request,
                first_authority,
                self.holders[name],
                _reader(self.passwords[name]),
                observed_at_ms=NOW + 40,
            )
            for name in ("root-0", "root-1")
        ]
        with self.assertRaisesRegex(
            RebirthError, "rebirth_enrollment_share_threshold_rejected"
        ):
            aggregate_distributed_enrollment(
                intent,
                second_request,
                first_authority,
                enrollment_shares[:1],
                observed_at_ms=NOW + 40,
            )
        second_activation = aggregate_distributed_enrollment(
            intent,
            second_request,
            first_authority,
            enrollment_shares,
            observed_at_ms=NOW + 40,
        )
        first_bundle_path = first_output / "runtime/runtime.json"
        first_bundle = json.loads(first_bundle_path.read_bytes())
        second_output = self.root / "second"
        activate_target_runtime(
            second_output,
            second_preparation_directory,
            second_preparation,
            second_request,
            second_activation,
            first_bundle,
            _reader(second_password),
        )
        updated_first = apply_activation_to_runtime_bundle(
            first_bundle,
            second_activation,
            first_authority,
            target_endpoint=f"http://127.0.0.1:{second_port}/dm-peer/v1",
        )
        first_bundle_path.write_bytes(canonical_bytes(updated_first))
        first = load_runtime(
            first_output / "runtime",
            "runtime.json",
            _reader(self.target_password),
            clock=lambda: NOW + 50,
        )
        second = load_runtime(
            second_output / "runtime",
            "runtime.json",
            _reader(second_password),
            clock=lambda: NOW + 50,
        )
        self.assertEqual(first.service.ledger.event(old_event["event_id"]), old_event)
        self.assertIsNone(second.service.ledger.event(old_event["event_id"]))

        server = create_peer_http_server(first)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            client_directory = second_output / "runtime/operator-clients/weave"
            capability = LocalCapability.from_value(
                json.loads((client_directory / "client.json").read_bytes())[
                    "capability"
                ],
                (client_directory / "capability.key").read_bytes(),
            )
            response = second.service.handle(
                create_request(
                    capability,
                    request_id=str(uuid.uuid4()),
                    issued_at_ms=NOW + 50,
                    method="we.sync.peer-pull",
                    params={
                        "sync_request_id": str(uuid.uuid4()),
                        "target_embodiment_id": first.service.origin["embodiment_id"],
                        "limit": 16,
                    },
                )
            )
            self.assertTrue(response["ok"], response)
            self.assertEqual(response["result"]["events"], 1)
            self.assertEqual(
                second.service.ledger.event(old_event["event_id"]), old_event
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_distributed_enrollment_cli_keeps_holders_in_separate_processes(
        self,
    ) -> None:
        first_activation = self.activation()
        _verified, authority = validate_activation(
            self.genesis, self.request, first_activation
        )
        authority_path = self.root / "authority.json"
        authority_path.write_bytes(
            canonical_bytes(
                {
                    "schema": "dm.operator.authority/v1",
                    "control_artifacts": [self.genesis],
                    "control_head": authority.state.head,
                    "manifest": authority.manifest.value,
                    "credentials": list(authority.credentials.values()),
                    "incarnations": list(authority.incarnations.values()),
                }
            )
        )
        authority_path.chmod(0o600)
        port = _available_port()
        profile_path = self.root / "cli-profile.json"
        profile_path.write_bytes(
            canonical_bytes(
                {
                    "schema": "dm.operator.rebirth-target-profile/v1",
                    "label": "cli-second",
                    "body_ref": "cluster:test:cli-second",
                    "principal_id": "cli-second@test",
                    "listen_host": "127.0.0.1",
                    "listen_port": port,
                    "advertised_endpoint": (f"http://127.0.0.1:{port}/dm-peer/v1"),
                    "targets": [
                        {
                            "embodiment_id": self.request["body"]["origin"][
                                "embodiment_id"
                            ],
                            "endpoint": (
                                f"http://127.0.0.1:{self.first_port}/dm-peer/v1"
                            ),
                            "timeout_ms": 5_000,
                        }
                    ],
                }
            )
        )
        profile_path.chmod(0o600)
        password = b"cli-second-target-password"
        preparation = self.root / "cli-preparation"
        prepared = self.invoke_rebirth(
            [
                "prepare",
                "--authority",
                str(authority_path),
                "--profile",
                str(profile_path),
                "--output",
                str(preparation),
                "--password-fd",
                "{password}",
            ],
            password,
        )
        self.assertEqual(prepared.returncode, 0, prepared.stderr.decode())
        request_path = preparation / "request.json"
        intent_path = self.root / "cli-intent.json"
        created = self.invoke_rebirth(
            [
                "create-enrollment-intent",
                "--authority",
                str(authority_path),
                "--request",
                str(request_path),
                "--output",
                str(intent_path),
            ]
        )
        self.assertEqual(created.returncode, 0, created.stderr.decode())
        share_paths: list[Path] = []
        for name in ("root-0", "root-1"):
            share_path = self.root / f"cli-{name}-share.json"
            shared = self.invoke_rebirth(
                [
                    "enrollment-share",
                    "--authority",
                    str(authority_path),
                    "--request",
                    str(request_path),
                    "--intent",
                    str(intent_path),
                    "--holder",
                    str(self.holders[name]),
                    "--password-fd",
                    "{password}",
                    "--output",
                    str(share_path),
                ],
                self.passwords[name],
            )
            self.assertEqual(shared.returncode, 0, shared.stderr.decode())
            share_paths.append(share_path)
        activation_path = self.root / "cli-activation.json"
        aggregated = self.invoke_rebirth(
            [
                "aggregate-enrollment",
                "--authority",
                str(authority_path),
                "--request",
                str(request_path),
                "--intent",
                str(intent_path),
                *(item for path in share_paths for item in ("--share", str(path))),
                "--output",
                str(activation_path),
            ]
        )
        self.assertEqual(aggregated.returncode, 0, aggregated.stderr.decode())
        activation = json.loads(activation_path.read_bytes())
        validate_rebirth_activation(
            activation,
            authority,
            request=json.loads(request_path.read_bytes()),
        )
        public = b"".join(
            path.read_bytes()
            for path in [request_path, intent_path, *share_paths, activation_path]
        )
        for name in ("root-0", "root-1"):
            self.assertNotIn((self.holders[name] / "holder.json").read_bytes(), public)
            self.assertNotIn(self.passwords[name], public)
