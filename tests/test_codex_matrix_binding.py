"""Current authority checks with real root-signed synthetic Matrix fixtures."""

from __future__ import annotations

import copy
import hashlib
import importlib
import json
import os
import subprocess
import sys
import threading
import time
from dataclasses import replace
from pathlib import Path
from typing import Any
from unittest import mock

from daimon_matrix import codex_body, codex_matrix_binding
from daimon_matrix.canonical import b64url
from daimon_matrix.client import ClientConfig, ClientError, LocalClient
from daimon_matrix.codex_body import CodexBodyError, bind_plan, create_plan_value
from daimon_matrix.codex_matrix_binding import (
    CurrentMatrixBinding,
    DaemonBootstrapVerifier,
    NativeAdmissionVerifier,
    SessionProofJournal,
    attest_owner_bootstrap_request,
    authenticate_matrix_binding,
    bootstrap_attestation_payload,
    bootstrap_from_attestation,
    check_current_runtime_authority,
    observe_native_cluster_body,
    open_owner_native_session,
    owner_cluster_body_reader,
    owner_local_admission,
    pinned_cluster_body_reader,
    prepare_owner_bootstrap_request,
    read_native_capability_key,
    session_witness_payload,
    validate_current_runtime_status,
    verify_bootstrap_attestation,
    verify_session_continuity,
)
from daimon_matrix.daemon import acquire_lock, serve_forever
from daimon_matrix.identity import create_revocation, verify_successor
from daimon_matrix.local_api import (
    create_capability,
    create_request,
    request_hash,
    verify_response,
)
from daimon_matrix.operator_capabilities import create_operator_capability_binding
from daimon_matrix.runtime import load_runtime
from daimon_matrix.weave import BeingManifest, RootAuthority
from tests.test_dm022_ledger import NOW
from tests.test_dm024_runtime import PASSWORD, RuntimeFixture


class MatrixBindingTests(RuntimeFixture):
    def setUp(self) -> None:
        super().setUp()
        self.runtime_root, self.bundle, self.capability = self.make_bundle()

    def _assert_owner_reopening_saved_tip(
        self,
        client: LocalClient,
        bootstrap: dict[str, Any],
        witness: dict[str, Any],
        proof_path: Path,
        snapshot: dict[str, Any],
        *,
        external_auth: bool = False,
    ) -> None:
        """Exercise real signed/socket/profile I/O before the native boundary."""
        binary = self.root_path / "synthetic-native"
        binary.write_bytes(b"#!/bin/sh\nexit 0\n")
        binary.chmod(0o700)
        pin = replace(
            codex_body.SUCCESSOR_RELEASE,
            binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
        )
        key = self.root_path / "reopening.key"
        key.write_bytes(self.capability.key)
        key.chmod(0o600)
        descriptor = os.open(key, os.O_RDONLY)
        original_proofs = proof_path.read_bytes()
        try:
            with mock.patch.object(codex_body, "SUCCESSOR_RELEASE", pin):
                plan = bind_plan(
                    create_plan_value(
                        bootstrap=bootstrap,
                        model="synthetic",
                        provider="openai",
                        workspace_ref="dm:workspace:v1:" + b64url(bytes(32)),
                        release="0.155.1",
                        provider_auth="chatgpt-external" if external_auth else None,
                    ),
                    profile_root=self.root_path
                    / ("external-profile" if external_auth else "reopening-profile"),
                    workspace=self.root_path,
                    codex_binary=binary,
                    mcp_binary=binary,
                    mcp_args=(
                        "--socket",
                        str(client.socket_path),
                        "--client-config",
                        str(self.runtime_root / "client.json"),
                        "--capability-key-fd",
                        str(descriptor),
                        "--request-dir",
                        str(self.root_path),
                    ),
                )
                bootstrap_verifier = DaemonBootstrapVerifier(
                    client, self.authority, self.admission()
                )
                codex_body.create_profile(
                    plan,
                    bootstrap_verifier=lambda evidence, at_ms: bootstrap_verifier(
                        evidence, at_ms
                    ),
                    clock=lambda: NOW,
                )
                handles = codex_body.RuntimeHandleJournal(
                    plan.profile_root / "runtime-handles.jsonl", plan=plan
                )
                core = {
                    name: bootstrap[name]
                    for name in (
                        "being_ref",
                        "body_ref",
                        "embodiment_id",
                        "incarnation_id",
                        "matrix_session_id",
                    )
                }
                core.update(
                    matrix_high_water=witness["content_hash"],
                    thread_id="saved-thread",
                    session_tree_id="saved-session",
                    turn_id=None,
                    observed_at_ms=NOW,
                )

                def reopen(provider_token: str | None = None) -> Any:
                    return open_owner_native_session(
                        plan,
                        self.bundle,
                        client,
                        body_reader=lambda *_: snapshot,
                        proof_journal_path=proof_path,
                        max_age_ms=1000,
                        clock=lambda: NOW,
                        provider_token=provider_token,
                    )

                # Only native process/protocol initialization are replaced.
                # Admission, signatures, profile and both journals remain real.
                with (
                    mock.patch.object(
                        codex_matrix_binding, "AppServerProcess"
                    ) as spawn,
                    mock.patch.object(codex_body.CodexBodyAdapter, "initialize"),
                ):
                    for state in ("active", "resuming", "parking"):
                        handles.append({**core, "state": state})
                        saved_handles = handles.path.read_bytes()
                        session = reopen()
                        session.close()
                        self.assertEqual(handles.path.read_bytes(), saved_handles)
                        self.assertEqual(proof_path.read_bytes(), original_proofs)
                    self.assertEqual(spawn.call_count, 3)
                    self.assertIsNone(spawn.call_args.kwargs["inherited_environment"])
                    token = "synthetic-provider-value"
                    if external_auth:
                        token = (
                            "synthetic."
                            + b64url(
                                json.dumps(
                                    {
                                        "https://api.openai.com/auth": {
                                            "chatgpt_account_id": "synthetic-account"
                                        }
                                    }
                                ).encode()
                            )
                            + ".synthetic"
                        )
                        spawn.return_value.request_bounded.side_effect = [
                            ({"type": "chatgptAuthTokens"}, []),
                            ({"account": {"type": "chatgpt"}}, []),
                        ]
                    session = reopen(provider_token=token)
                    session.close()
                    self.assertEqual(
                        spawn.call_args.kwargs["inherited_environment"],
                        None if external_auth else {"CODEX_ACCESS_TOKEN": token},
                    )
                    if external_auth:
                        self.assertEqual(
                            spawn.return_value.request_bounded.call_args_list,
                            [
                                mock.call(
                                    "account/login/start",
                                    codex_body.chatgpt_login_params(token),
                                    deadline=mock.ANY,
                                ),
                                mock.call(
                                    "account/read",
                                    {"refreshToken": False},
                                    deadline=mock.ANY,
                                ),
                            ],
                        )
                        calls = spawn.return_value.request_bounded.call_args_list
                        self.assertEqual(
                            calls[0].kwargs["deadline"], calls[1].kwargs["deadline"]
                        )
                        self.assertFalse((plan.profile_root / "auth.json").exists())
                    spawn.reset_mock()
                    corruptions = {
                        "missing": None,
                        "empty": b"",
                        "torn": original_proofs[:-1],
                        "substituted": original_proofs.replace(
                            witness["content_hash"].encode(), b"0" * 64
                        ),
                    }
                    for name, raw in corruptions.items():
                        with self.subTest(ancestry=name):
                            if raw is None:
                                proof_path.unlink()
                            else:
                                proof_path.write_bytes(raw)
                                proof_path.chmod(0o600)
                            with self.assertRaises(CodexBodyError):
                                reopen()
                            spawn.assert_not_called()
                            self.assertEqual(handles.path.read_bytes(), saved_handles)
                            if raw is None:
                                self.assertFalse(proof_path.exists())
                            else:
                                self.assertEqual(proof_path.read_bytes(), raw)
                            proof_path.write_bytes(original_proofs)
                            proof_path.chmod(0o600)
        finally:
            os.close(descriptor)

    def test_session_journal_fifo_refuses_before_lock_or_verification(self) -> None:
        path = self.root_path / "proof.fifo"
        os.mkfifo(path, 0o600)
        before = path.stat()
        bootstrap = (
            Path(__file__).resolve().parents[1]
            / "vectors/codex/v2/valid/bootstrap.json"
        )
        code = """import json,sys
from pathlib import Path
from daimon_matrix.codex_body import CodexBodyError
from daimon_matrix.codex_matrix_binding import SessionProofJournal
journal=SessionProofJournal(Path(sys.argv[1]),bootstrap=json.loads(Path(sys.argv[2]).read_bytes()))
def verifier(*args):
    raise AssertionError('unsafe journal reached verification')
try:
    if sys.argv[3]=='load':
        journal.load(expected_high_water=journal.bootstrap['matrix_high_water'],verifier=verifier)
    else:
        journal.append({},expected_high_water=journal.bootstrap['matrix_high_water'],verifier=verifier)
except CodexBodyError as error:
    sys.exit(0 if error.code=='session_proof_file_unsafe' else 1)
sys.exit(2)
"""
        for action in ("load", "append"):
            with self.subTest(action=action):
                result = subprocess.run(
                    [sys.executable, "-c", code, str(path), str(bootstrap), action],
                    capture_output=True,
                    timeout=2,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr.decode())
        after = path.stat()
        self.assertEqual((before.st_ino, before.st_mode), (after.st_ino, after.st_mode))

    def test_native_descriptor_repeated_reads_preserve_shared_offset(self) -> None:
        path = self.root_path / "native-capability"
        path.write_bytes(self.capability.key)
        path.chmod(0o600)
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.lseek(descriptor, 32, os.SEEK_SET)
            for _ in range(2):
                self.assertEqual(
                    read_native_capability_key(descriptor), self.capability.key
                )
                self.assertEqual(os.lseek(descriptor, 0, os.SEEK_CUR), 32)
            path.chmod(0o640)
            with self.assertRaises(CodexBodyError):
                read_native_capability_key(descriptor)
            path.chmod(0o600)
            alias = self.root_path / "capability-alias"
            os.link(path, alias)
            with self.assertRaises(CodexBodyError):
                read_native_capability_key(descriptor)
        finally:
            os.close(descriptor)

    def test_native_parent_descriptor_checks_real_kernel_parent_and_pin(self) -> None:
        path = self.root_path / "native-parent-capability"
        path.write_bytes(self.capability.key)
        path.chmod(0o600)
        descriptor = os.open(path, os.O_RDONLY)
        self.addCleanup(os.close, descriptor)
        os.lseek(descriptor, 32, os.SEEK_SET)
        python_hash = hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest()
        code = """
import hashlib,os,sys
from dataclasses import replace
from daimon_matrix import codex_matrix_binding as bridge
from daimon_matrix.codex_body import CodexBodyError
source=int(sys.argv[1])
os.close(source)
bridge.CURRENT_RELEASE=replace(bridge.CURRENT_RELEASE,binary_sha256=sys.argv[2])
opened=-1
try:
    opened=bridge._open_native_parent_capability(source)
    key=bridge.read_native_capability_key(opened)
    try:
        assert hashlib.sha256(key).hexdigest()==sys.argv[3]
    finally:
        key[:]=bytes(len(key))
except CodexBodyError as error:
    sys.exit(0 if error.code==sys.argv[4] else 2)
finally:
    if opened>=0:os.close(opened)
sys.exit(0 if sys.argv[4]=='pass' else 3)
"""
        for pin, permission, expected in (
            (python_hash, 0o600, "pass"),
            ("0" * 64, 0o600, "native_capability_parent_rejected"),
            (python_hash, 0o640, "native_capability_descriptor_unsafe"),
        ):
            with self.subTest(expected=expected):
                path.chmod(permission)
                result = subprocess.run(
                    [
                        sys.executable,
                        "-c",
                        code,
                        str(descriptor),
                        pin,
                        hashlib.sha256(self.capability.key).hexdigest(),
                        expected,
                    ],
                    pass_fds=(descriptor,),
                    capture_output=True,
                    timeout=3,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr.decode())
                self.assertEqual(os.lseek(descriptor, 0, os.SEEK_CUR), 32)
        path.chmod(0o600)

    def test_native_descriptor_rejects_single_consumer_pipe(self) -> None:
        read_fd, write_fd = os.pipe()
        try:
            os.write(write_fd, self.capability.key)
            with self.assertRaises(CodexBodyError):
                read_native_capability_key(read_fd)
            self.assertEqual(os.read(read_fd, 32), self.capability.key)
        finally:
            os.close(read_fd)
            os.close(write_fd)

    def test_body_observation_requires_exact_fresh_running_cluster_snapshot(
        self,
    ) -> None:
        binding = self.check()
        snapshot: dict[str, Any] = {
            "schema": "dm.cluster-body-snapshot/v1",
            "body_ref": binding.body_ref,
            "embodiment_id": binding.embodiment_id,
            "incarnation_id": binding.incarnation_id,
            "observed_at_ms": NOW,
            "state": "running",
            "resource_fences": [],
        }
        result = observe_native_cluster_body(
            binding, lambda *_: snapshot, max_age_ms=1000
        )
        self.assertEqual(result.snapshot, snapshot)
        self.assertEqual(result.fresh_until_ms, NOW + 1000)
        substitutions: tuple[tuple[str, Any], ...] = (
            ("state", "stopped"),
            ("state", "unavailable"),
            ("body_ref", "another-body"),
            ("incarnation_id", "incarnation:other:0"),
            ("observed_at_ms", NOW + 1),
            ("observed_at_ms", NOW - 1000),
        )
        for field, replacement in substitutions:
            with self.subTest(field=field, replacement=replacement):
                changed = {**snapshot, field: replacement}
                with self.assertRaises(CodexBodyError):
                    observe_native_cluster_body(
                        binding, lambda *_, current=changed: current, max_age_ms=1000
                    )

        def outage(*_: Any) -> dict[str, Any]:
            raise OSError("synthetic host unavailable")

        with self.assertRaises(CodexBodyError) as refused:
            observe_native_cluster_body(binding, outage, max_age_ms=1000)
        self.assertTrue(refused.exception.retryable)

    def test_pinned_cluster_registry_adapter_supplies_body_observation(self) -> None:
        configured = os.environ.get("DAIMON_DM070_CLUSTER_ROOT")
        if configured is None:
            self.skipTest("exact pinned Cluster contract checkout not configured")
        root = Path(configured)
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        self.assertEqual(head, "676495e852e6772a60de8221271ee9fc976f77ce")
        sys.path.insert(0, str(root))
        try:
            registry_module = importlib.import_module("clusterctl.embodiments")
            host_module = importlib.import_module("clusterctl.matrix_host")
        finally:
            sys.path.pop(0)
        binding = self.check()
        cluster_root = self.root_path / "cluster"
        cluster_root.mkdir(mode=0o700)
        registry = registry_module.Registry(cluster_root)
        registry.register(
            body_ref=binding.body_ref, embodiment_id=binding.embodiment_id
        )
        registry.start(
            binding.embodiment_id,
            incarnation_id=binding.incarnation_id,
            started_at_ms=NOW - 1,
        )
        before = registry.path.read_bytes()
        host = host_module.MatrixHostAdapter(
            cluster_root, binding.embodiment_id, clock=lambda: NOW
        )
        observed = observe_native_cluster_body(
            binding, host.body_snapshot, max_age_ms=1000
        )
        self.assertEqual(observed.snapshot["state"], "running")
        self.assertEqual(registry.path.read_bytes(), before)
        reader_checkout = self.root_path / "verified-reader"
        reader_checkout.mkdir(mode=0o700)
        (reader_checkout / "clusterctl").mkdir(mode=0o700)
        for name in ("__init__", "embodiments", "fences", "matrix_host"):
            target = reader_checkout / "clusterctl" / f"{name}.py"
            target.write_bytes((root / "clusterctl" / f"{name}.py").read_bytes())
            target.chmod(0o600)
        reader = pinned_cluster_body_reader(
            reader_checkout, cluster_root, binding.embodiment_id
        )
        self.assertEqual(
            observe_native_cluster_body(binding, reader, max_age_ms=1000).snapshot,
            observed.snapshot,
        )
        self.assertEqual(registry.path.read_bytes(), before)
        selected_reader = owner_cluster_body_reader(
            checkout=reader_checkout,
            state_root=cluster_root,
            socket_path=None,
            owner_uid=None,
            embodiment_id=binding.embodiment_id,
        )
        self.assertEqual(
            observe_native_cluster_body(
                binding, selected_reader, max_age_ms=1000
            ).snapshot,
            observed.snapshot,
        )
        (reader_checkout / "clusterctl/matrix_host.py").write_text(
            "raise RuntimeError('unverified source executed')\n"
        )
        with self.assertRaisesRegex(CodexBodyError, "owner_cluster_source_mismatch"):
            pinned_cluster_body_reader(
                reader_checkout, cluster_root, binding.embodiment_id
            )
        registry.stop(binding.embodiment_id)
        with self.assertRaises(CodexBodyError):
            observe_native_cluster_body(binding, host.body_snapshot, max_age_ms=1000)

    def admission(self) -> dict[str, Any]:
        return {
            "origin": self.bundle["local_origin"],
            "runtime_id": self.bundle["runtime_id"],
            "runtime_label": self.bundle["runtime_label"],
            "capability_rows": self.bundle["capabilities"],
            "capability_binding": self.bundle["operator_capability_binding"],
            "at_ms": NOW,
            "capability_id": self.capability.capability_id,
            "client_id": self.capability.client_id,
            "required_methods": frozenset({"runtime.status", "we.heads", "we.observe"}),
        }

    def check(
        self, *, authority: RootAuthority | None = None, **changes: Any
    ) -> CurrentMatrixBinding:
        arguments = self.admission()
        arguments.update(changes)
        return authenticate_matrix_binding(
            authority
            or RootAuthority(
                self.manifest, self.state, self.credentials, self.incarnations
            ),
            **arguments,
        )

    def attest(self) -> dict[str, Any]:
        payload = bootstrap_attestation_payload(
            self.check(),
            matrix_session_id="dm:session:v1:"
            + b64url(hashlib.sha256(b"session").digest()),
            expires_at_ms=NOW + 30_000,
        )
        return self.ledger_a.append_local(
            kind="experience.observed",
            subject="codex-body/bootstrap",
            payload=payload,
            signer=self.signers["legion"],
            sensitivity="private",
            occurred_at_ms=NOW,
        )

    def witness(
        self,
        bootstrap: dict[str, Any],
        previous: dict[str, Any],
        sequence: int,
        **payload_changes: Any,
    ) -> dict[str, Any]:
        payload = session_witness_payload(bootstrap, previous, sequence=sequence)
        payload.update(payload_changes)
        return self.ledger_a.append_local(
            kind="experience.observed",
            subject="codex-body/session-witness",
            payload=payload,
            signer=self.signers["legion"],
            sensitivity="private",
            occurred_at_ms=NOW,
            causal_parents=[previous["event_id"]],
        )

    def test_signed_session_ancestry_allows_unrelated_events_without_reading_them(
        self,
    ) -> None:
        event = self.attest()
        bootstrap = bootstrap_from_attestation(
            event, self.authority, **self.admission()
        )
        first = self.witness(bootstrap, event, 1)
        self.append(self.ledger_a, "legion", "unrelated fixture event")
        second = self.witness(bootstrap, first, 2)
        result = verify_session_continuity(
            bootstrap,
            [first, second],
            self.authority,
            expected_high_water=second["content_hash"],
            **self.admission(),
        )
        self.assertEqual(result.event, second)
        self.assertEqual(result.witness_sequence, 2)
        self.assertEqual(result.matrix_session_id, bootstrap["matrix_session_id"])
        initial = verify_session_continuity(
            bootstrap,
            [],
            self.authority,
            expected_high_water=event["content_hash"],
            **self.admission(),
        )
        self.assertEqual(initial.witness_sequence, 0)

    def test_session_truncation_reordering_and_fork_refuse(self) -> None:
        event = self.attest()
        bootstrap = bootstrap_from_attestation(
            event, self.authority, **self.admission()
        )
        first = self.witness(bootstrap, event, 1)
        second = self.witness(bootstrap, first, 2)
        fork = self.witness(bootstrap, event, 2)
        for proofs in ([first], [second, first], [first, fork], [first, first]):
            with (
                self.subTest(ids=[item["event_id"] for item in proofs]),
                self.assertRaises(CodexBodyError),
            ):
                verify_session_continuity(
                    bootstrap,
                    proofs,
                    self.authority,
                    expected_high_water=second["content_hash"],
                    **self.admission(),
                )

    def test_session_journal_reopens_and_refuses_stale_or_truncated_history(
        self,
    ) -> None:
        event = self.attest()
        bootstrap = bootstrap_from_attestation(
            event, self.authority, **self.admission()
        )
        path = self.root_path / "session-proofs.jsonl"
        journal = SessionProofJournal(path, bootstrap=bootstrap)

        def verifier(proofs: Any, tip: str) -> Any:
            return verify_session_continuity(
                bootstrap,
                proofs,
                self.authority,
                expected_high_water=tip,
                **self.admission(),
            )

        first = self.witness(bootstrap, event, 1)
        second = self.witness(bootstrap, first, 2)
        journal.append(
            first, expected_high_water=event["content_hash"], verifier=verifier
        )
        first_bytes = path.read_bytes()
        reopened = SessionProofJournal(path, bootstrap=bootstrap)
        self.assertEqual(
            reopened.load(expected_high_water=first["content_hash"], verifier=verifier),
            [first],
        )
        with self.assertRaises(CodexBodyError):
            reopened.append(
                second, expected_high_water=event["content_hash"], verifier=verifier
            )
        self.assertEqual(path.read_bytes(), first_bytes)
        reopened.append(
            second, expected_high_water=first["content_hash"], verifier=verifier
        )
        self.assertEqual(
            journal.load(expected_high_water=second["content_hash"], verifier=verifier),
            [first, second],
        )
        path.write_bytes(first_bytes)
        with self.assertRaises(CodexBodyError):
            journal.load(expected_high_water=second["content_hash"], verifier=verifier)
        self.assertEqual(path.read_bytes(), first_bytes)

    def test_session_journal_preserves_torn_noncanonical_and_unsafe_files(self) -> None:
        event = self.attest()
        bootstrap = bootstrap_from_attestation(
            event, self.authority, **self.admission()
        )
        path = self.root_path / "session-proofs.jsonl"
        journal = SessionProofJournal(path, bootstrap=bootstrap)

        def verifier(proofs: Any, tip: str) -> Any:
            return verify_session_continuity(
                bootstrap,
                proofs,
                self.authority,
                expected_high_water=tip,
                **self.admission(),
            )

        first = self.witness(bootstrap, event, 1)
        journal.append(
            first, expected_high_water=event["content_hash"], verifier=verifier
        )
        original = path.read_bytes()
        for damaged in (original[:-1], b" " + original):
            path.write_bytes(damaged)
            with self.assertRaises(CodexBodyError):
                journal.load(
                    expected_high_water=first["content_hash"], verifier=verifier
                )
            self.assertEqual(path.read_bytes(), damaged)
        path.write_bytes(original)
        alias = self.root_path / "session-proofs-alias"
        os.link(path, alias)
        with self.assertRaises(CodexBodyError):
            journal.load(expected_high_water=first["content_hash"], verifier=verifier)
        alias.unlink()
        path.chmod(0o640)
        with self.assertRaises(CodexBodyError):
            journal.load(expected_high_water=first["content_hash"], verifier=verifier)
        self.assertEqual(path.read_bytes(), original)

    def test_session_journal_concurrent_writers_accept_only_one_branch(self) -> None:
        event = self.attest()
        bootstrap = bootstrap_from_attestation(
            event, self.authority, **self.admission()
        )
        path = self.root_path / "session-proofs.jsonl"
        branches = [self.witness(bootstrap, event, 1) for _ in range(2)]
        barrier = threading.Barrier(2)
        results: list[bool] = []

        def verifier(proofs: Any, tip: str) -> Any:
            return verify_session_continuity(
                bootstrap,
                proofs,
                self.authority,
                expected_high_water=tip,
                **self.admission(),
            )

        def append(proof: dict[str, Any]) -> None:
            journal = SessionProofJournal(path, bootstrap=bootstrap)
            barrier.wait(timeout=2)
            try:
                journal.append(
                    proof, expected_high_water=event["content_hash"], verifier=verifier
                )
            except CodexBodyError:
                results.append(False)
            else:
                results.append(True)

        threads = [threading.Thread(target=append, args=(proof,)) for proof in branches]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=3)
            self.assertFalse(thread.is_alive())
        self.assertEqual(sorted(results), [False, True])
        record = path.read_bytes()
        self.assertEqual(record.count(b"\n"), 1)

    def test_signed_wrong_session_or_parent_hash_refuses(self) -> None:
        event = self.attest()
        bootstrap = bootstrap_from_attestation(
            event, self.authority, **self.admission()
        )
        substitutions = (
            {"matrix_session_id": "dm:session:v1:" + b64url(bytes(32))},
            {"previous_event_hash": "a" * 64},
            {"bootstrap_event_hash": "a" * 64},
            {"witness_sequence": True},
        )
        for changes in substitutions:
            with self.subTest(changes=changes):
                wrong = self.witness(bootstrap, event, 1, **changes)
                with self.assertRaises(CodexBodyError):
                    verify_session_continuity(
                        bootstrap,
                        [wrong],
                        self.authority,
                        expected_high_water=wrong["content_hash"],
                        **self.admission(),
                    )

    def test_signed_attestation_bootstrap_and_later_verification(self) -> None:
        event = self.attest()
        bootstrap = bootstrap_from_attestation(
            event, self.authority, **self.admission()
        )
        self.assertEqual(bootstrap["schema"], "dm.codex-body.bootstrap/v2")
        self.assertEqual(bootstrap["matrix_high_water"], event["content_hash"])
        self.assertEqual(bootstrap["attestation"], event)
        arguments = self.admission()
        arguments["at_ms"] = NOW + 1
        self.assertTrue(
            verify_bootstrap_attestation(bootstrap, self.authority, **arguments)
        )
        for at_ms in (NOW - 1, NOW + 30_000):
            arguments["at_ms"] = at_ms
            with self.assertRaises(CodexBodyError):
                verify_bootstrap_attestation(bootstrap, self.authority, **arguments)
        workspace = "dm:workspace:v1:" + b64url(hashlib.sha256(b"workspace").digest())
        create_plan_value(
            bootstrap=bootstrap,
            model="probe",
            provider="openai",
            workspace_ref=workspace,
            release="0.155.1",
        )
        with self.assertRaises(CodexBodyError):
            create_plan_value(
                bootstrap=bootstrap,
                model="probe",
                provider="openai",
                workspace_ref=workspace,
            )

    def test_attestation_payload_and_signature_tampering_refuse(self) -> None:
        event = self.attest()
        for field in ("certificate_hash", "capability_set_hash", "matrix_session_id"):
            with self.subTest(field=field):
                changed = copy.deepcopy(event)
                changed["payload"]["bootstrap"][field] = "a" * 64
                with self.assertRaises(CodexBodyError):
                    bootstrap_from_attestation(
                        changed, self.authority, **self.admission()
                    )
        changed = copy.deepcopy(event)
        changed["signature"]["value"] = b64url(bytes(64))
        with self.assertRaises(CodexBodyError):
            bootstrap_from_attestation(changed, self.authority, **self.admission())

    def test_validly_signed_wrong_binding_is_not_a_bootstrap(self) -> None:
        event = self.attest()
        payload = copy.deepcopy(event["payload"])
        payload["bootstrap"]["certificate_hash"] = "a" * 64
        signed = self.ledger_a.append_local(
            kind="experience.observed",
            subject="codex-body/bootstrap",
            payload=payload,
            signer=self.signers["legion"],
            sensitivity="private",
            occurred_at_ms=NOW,
        )
        with self.assertRaises(CodexBodyError):
            bootstrap_from_attestation(signed, self.authority, **self.admission())

    def test_authenticated_daemon_observation_and_exact_retry_issue_same_proof(
        self,
    ) -> None:
        runtime = load_runtime(
            self.runtime_root,
            "runtime.json",
            lambda: bytearray(PASSWORD),
            clock=lambda: NOW,
        )
        payload = bootstrap_attestation_payload(
            self.check(),
            matrix_session_id="dm:session:v1:"
            + b64url(hashlib.sha256(b"daemon-session").digest()),
            expires_at_ms=NOW + 30_000,
        )
        request = create_request(
            self.capability,
            request_id="30000000-0000-4000-8000-000000009205",
            issued_at_ms=NOW,
            method="we.observe",
            params={
                "subject": "codex-body/bootstrap",
                "payload": payload,
                "sensitivity": "private",
                "causal_parents": [],
                "occurred_at_ms": NOW,
                "event_id": None,
            },
            nonce=b"b" * 16,
        )
        response = runtime.service.handle(request)
        verified = verify_response(
            response,
            self.capability,
            expected_request_id=request["request_id"],
            expected_request_hash=request_hash(request),
            expected_server=self.origins["legion"],
            expected_runtime={
                "runtime_id": self.bundle["runtime_id"],
                "runtime_label": self.bundle["runtime_label"],
            },
        )
        self.assertTrue(verified["ok"])
        proof = verified["result"]["event"]
        bootstrap = bootstrap_from_attestation(
            proof, self.authority, **self.admission()
        )
        self.assertEqual(bootstrap["matrix_high_water"], proof["content_hash"])
        self.assertEqual(runtime.service.handle(request), response)

    def test_real_socket_metadata_and_daemon_bootstrap_verifier(self) -> None:
        runtime = load_runtime(
            self.runtime_root,
            "runtime.json",
            lambda: bytearray(PASSWORD),
            clock=lambda: NOW,
        )
        lock = acquire_lock(self.runtime_root)
        stop = threading.Event()
        thread = threading.Thread(
            target=serve_forever, kwargs={"runtime": runtime, "stop": stop}, daemon=True
        )
        thread.start()
        try:
            deadline = time.monotonic() + 2
            while not runtime.socket_path.exists() and time.monotonic() < deadline:
                self.assertTrue(thread.is_alive())
                time.sleep(0.01)
            self.assertTrue(runtime.socket_path.exists())
            client = LocalClient(
                runtime.socket_path,
                ClientConfig(
                    self.capability,
                    self.origins["legion"],
                    self.bundle["runtime_id"],
                    self.bundle["runtime_label"],
                ),
                clock=lambda: NOW,
            )
            binding = check_current_runtime_authority(
                client, self.authority, **self.admission()
            )
            self.assertEqual(binding, self.check())
            request_path = self.root_path / "owner-bootstrap-request.json"
            output_path = self.root_path / "owner-bootstrap.json"
            session_id = "dm:session:v1:" + b64url(bytes(32))
            prepared = prepare_owner_bootstrap_request(
                self.bundle,
                client,
                request_path,
                matrix_session_id=session_id,
                expires_at_ms=NOW + 30_000,
                at_ms=NOW,
            )
            stored = request_path.read_bytes()
            sent = []
            original_send = LocalClient.send

            def lose_first_response(
                selected: LocalClient, request: dict[str, Any]
            ) -> dict[str, Any]:
                response = original_send(selected, request)
                if request["method"] == "we.observe":
                    sent.append(copy.deepcopy(request))
                    if len(sent) == 1:
                        raise ClientError("synthetic_response_lost_after_acceptance")
                return response

            with mock.patch.object(LocalClient, "send", lose_first_response):
                with self.assertRaisesRegex(
                    CodexBodyError, "owner_bootstrap_request_rejected"
                ):
                    attest_owner_bootstrap_request(
                        self.bundle,
                        client,
                        request_path,
                        output_path,
                        matrix_session_id="dm:session:v1:" + b64url(bytes([1]) * 32),
                        expires_at_ms=NOW + 30_000,
                        at_ms=NOW,
                    )
                self.assertEqual(sent, [])
                with self.assertRaisesRegex(
                    CodexBodyError, "owner_bootstrap_response_unavailable"
                ):
                    attest_owner_bootstrap_request(
                        self.bundle,
                        client,
                        request_path,
                        output_path,
                        matrix_session_id=session_id,
                        expires_at_ms=NOW + 30_000,
                        at_ms=NOW,
                    )
                self.assertFalse(output_path.exists())
                recovered = attest_owner_bootstrap_request(
                    self.bundle,
                    client,
                    request_path,
                    output_path,
                    matrix_session_id=session_id,
                    expires_at_ms=NOW + 30_000,
                    at_ms=NOW,
                )
            self.assertEqual(sent, [prepared, prepared])
            self.assertEqual(request_path.read_bytes(), stored)
            self.assertEqual(recovered["matrix_session_id"], session_id)
            self.assertEqual(
                attest_owner_bootstrap_request(
                    self.bundle,
                    client,
                    request_path,
                    output_path,
                    matrix_session_id=session_id,
                    expires_at_ms=NOW + 30_000,
                    at_ms=NOW,
                ),
                recovered,
            )
            public_authority, operator_admission, operator_binding = (
                owner_local_admission(self.bundle, client, at_ms=NOW)
            )
            self.assertEqual(operator_binding, binding)
            self.assertEqual(public_authority.manifest.digest, binding.manifest_hash)
            self.assertEqual(
                check_current_runtime_authority(
                    client, public_authority, **operator_admission
                ),
                binding,
            )
            absent_client = LocalClient(
                self.runtime_root / "absent.sock", client.config, clock=lambda: NOW
            )
            with self.assertRaisesRegex(
                CodexBodyError, "matrix_runtime_metadata_unavailable"
            ):
                owner_local_admission(self.bundle, absent_client, at_ms=NOW)
            payload = bootstrap_attestation_payload(
                binding,
                matrix_session_id="dm:session:v1:"
                + b64url(hashlib.sha256(b"socket-session").digest()),
                expires_at_ms=NOW + 30_000,
            )
            response = client.send(
                client.prepare(
                    "we.observe",
                    {
                        "subject": "codex-body/bootstrap",
                        "payload": payload,
                        "sensitivity": "private",
                        "causal_parents": [],
                        "occurred_at_ms": NOW,
                        "event_id": None,
                    },
                )
            )
            self.assertTrue(response["ok"])
            bootstrap = bootstrap_from_attestation(
                response["result"]["event"], self.authority, **self.admission()
            )
            self.assertTrue(
                DaemonBootstrapVerifier(client, self.authority, self.admission())(
                    bootstrap, NOW
                )
            )
            key_path = self.root_path / "native-owner.key"
            key_path.write_bytes(self.capability.key)
            key_path.chmod(0o600)
            descriptor = os.open(key_path, os.O_RDONLY)
            try:
                plan = bind_plan(
                    create_plan_value(
                        bootstrap=bootstrap,
                        model="no-model",
                        provider="openai",
                        workspace_ref="dm:workspace:v1:" + b64url(bytes(32)),
                        release="0.155.1",
                    ),
                    profile_root=self.root_path / "uncreated-owner-profile",
                    workspace=self.root_path,
                    codex_binary=self.root_path / "unavailable-native",
                    mcp_binary=self.root_path / "unavailable-mcp",
                    mcp_args=(
                        "--socket",
                        str(client.socket_path),
                        "--client-config",
                        str(self.runtime_root / "client.json"),
                        "--capability-key-fd",
                        str(descriptor),
                        "--request-dir",
                        str(self.root_path),
                    ),
                )

                def stopped_host(*_arguments: Any) -> dict[str, Any]:
                    return {
                        "schema": "dm.cluster-body-snapshot/v1",
                        "body_ref": binding.body_ref,
                        "embodiment_id": binding.embodiment_id,
                        "incarnation_id": binding.incarnation_id,
                        "observed_at_ms": NOW,
                        "resource_fences": [],
                        "state": "stopped",
                    }

                with self.assertRaisesRegex(
                    CodexBodyError, "native_cluster_body_not_current"
                ):
                    open_owner_native_session(
                        plan,
                        self.bundle,
                        client,
                        body_reader=stopped_host,
                        proof_journal_path=self.root_path
                        / "owner-session-proofs.jsonl",
                        max_age_ms=1000,
                        create=True,
                        clock=lambda: NOW,
                    )
                self.assertFalse(plan.profile_root.exists())
                self.assertFalse(
                    (self.root_path / "owner-session-proofs.jsonl").exists()
                )
                self.assertEqual(os.lseek(descriptor, 0, os.SEEK_CUR), 0)
            finally:
                os.close(descriptor)
            witness_response = client.send(
                client.prepare(
                    "we.observe",
                    {
                        "subject": "codex-body/session-witness",
                        "payload": session_witness_payload(
                            bootstrap, bootstrap["attestation"], sequence=1
                        ),
                        "sensitivity": "private",
                        "causal_parents": [bootstrap["attestation"]["event_id"]],
                        "occurred_at_ms": NOW,
                        "event_id": None,
                    },
                )
            )
            self.assertTrue(witness_response["ok"])
            witness = witness_response["result"]["event"]
            continuity = verify_session_continuity(
                bootstrap,
                [witness],
                self.authority,
                expected_high_water=witness["content_hash"],
                **self.admission(),
            )
            self.assertEqual(continuity.witness_sequence, 1)
            proof_path = self.root_path / "socket-session-proofs.jsonl"

            def verify_saved(proofs: Any, tip: str) -> Any:
                check_current_runtime_authority(
                    client, self.authority, **self.admission()
                )
                return verify_session_continuity(
                    bootstrap,
                    proofs,
                    self.authority,
                    expected_high_water=tip,
                    **self.admission(),
                )

            SessionProofJournal(proof_path, bootstrap=bootstrap).append(
                witness,
                expected_high_water=bootstrap["matrix_high_water"],
                verifier=verify_saved,
            )
            self.assertEqual(
                SessionProofJournal(proof_path, bootstrap=bootstrap).load(
                    expected_high_water=witness["content_hash"],
                    verifier=verify_saved,
                ),
                [witness],
            )
            requested = {
                key: bootstrap[key]
                for key in (
                    "being_ref",
                    "body_ref",
                    "embodiment_id",
                    "incarnation_id",
                    "matrix_session_id",
                    "matrix_high_water",
                )
            }
            requested["matrix_high_water"] = witness["content_hash"]
            snapshot = {
                "schema": "dm.cluster-body-snapshot/v1",
                "body_ref": binding.body_ref,
                "embodiment_id": binding.embodiment_id,
                "incarnation_id": binding.incarnation_id,
                "observed_at_ms": NOW,
                "state": "running",
                "resource_fences": [],
            }
            native_admission = NativeAdmissionVerifier(
                client,
                self.authority,
                self.admission(),
                SessionProofJournal(proof_path, bootstrap=bootstrap),
                lambda *_: snapshot,
                1000,
            )
            admitted = native_admission(requested, NOW)
            self.assertEqual(admitted["matrix_high_water"], witness["content_hash"])
            self.assertEqual(admitted["expires_at_ms"], NOW + 1000)
            self._assert_owner_reopening_saved_tip(
                client, bootstrap, witness, proof_path, snapshot
            )
            self._assert_owner_reopening_saved_tip(
                client, bootstrap, witness, proof_path, snapshot, external_auth=True
            )
            with self.assertRaises(CodexBodyError):
                native_admission(
                    {**requested, "incarnation_id": "another-incarnation"}, NOW
                )
            snapshot["state"] = "stopped"
            with self.assertRaises(CodexBodyError):
                native_admission(requested, NOW)
            stale_value = copy.deepcopy(dict(self.manifest.value))
            stale_value["revision"] += 1
            different_epoch = RootAuthority(
                BeingManifest.from_value(stale_value),
                self.state,
                self.credentials,
                self.incarnations,
            )
            saved_bytes = proof_path.read_bytes()

            def verify_changed_epoch(proofs: Any, tip: str) -> Any:
                check_current_runtime_authority(
                    client, different_epoch, **self.admission()
                )
                return verify_session_continuity(
                    bootstrap,
                    proofs,
                    different_epoch,
                    expected_high_water=tip,
                    **self.admission(),
                )

            with self.assertRaises(CodexBodyError):
                SessionProofJournal(proof_path, bootstrap=bootstrap).load(
                    expected_high_water=witness["content_hash"],
                    verifier=verify_changed_epoch,
                )
            self.assertEqual(proof_path.read_bytes(), saved_bytes)
            with self.assertRaises(CodexBodyError) as refused:
                check_current_runtime_authority(
                    client, different_epoch, **self.admission()
                )
            self.assertEqual(
                refused.exception.code, "matrix_runtime_authority_mismatch"
            )
            wrong_client = LocalClient(
                runtime.socket_path,
                ClientConfig(
                    self.capability,
                    self.origins["legion"],
                    "another-runtime",
                    self.bundle["runtime_label"],
                ),
                clock=lambda: NOW,
            )
            with self.assertRaises(CodexBodyError) as refused:
                check_current_runtime_authority(
                    wrong_client, self.authority, **self.admission()
                )
            self.assertEqual(refused.exception.code, "matrix_runtime_client_mismatch")
        finally:
            stop.set()
            thread.join(timeout=3)
            os.close(lock)
        self.assertFalse(thread.is_alive())

    def test_current_epoch_status_drift_refuses(self) -> None:
        binding = self.check()
        status: dict[str, Any] = {
            "schema": "dm.runtime.status/v1",
            "integrity": "ok",
            "being_ref": binding.being_ref,
            "local_origin": self.origins["legion"],
            "manifest_hash": binding.manifest_hash,
            "authority_epoch": {
                "schema": "dm.we.authority-epoch-status/v1",
                "active_manifest_hash": binding.manifest_hash,
                "accepted_manifest_hashes": [binding.manifest_hash],
                "epoch_count": 1,
            },
        }
        validate_current_runtime_status(status, binding)
        substitutions: tuple[tuple[str, Any], ...] = (
            ("manifest_hash", "a" * 64),
            ("being_ref", "different-being"),
            ("local_origin", self.origins["daimonmatrix"]),
            ("integrity", "failed"),
        )
        for field, replacement in substitutions:
            with self.subTest(field=field):
                changed = copy.deepcopy(status)
                changed[field] = replacement
                with self.assertRaises(CodexBodyError):
                    validate_current_runtime_status(changed, binding)
        for field, replacement in (
            ("active_manifest_hash", "a" * 64),
            ("epoch_count", True),
            ("accepted_manifest_hashes", []),
        ):
            with self.subTest(epoch_field=field):
                changed = copy.deepcopy(status)
                changed["authority_epoch"][field] = replacement
                with self.assertRaises(CodexBodyError):
                    validate_current_runtime_status(changed, binding)

    def test_real_root_and_signed_capabilities_preserve_nominal_ids(self) -> None:
        result = self.check()
        self.assertEqual(result.being_ref, self.state.being_ref)
        self.assertEqual(result.embodiment_id, "embodiment:legion")
        self.assertEqual(result.incarnation_id, "incarnation:legion:0")
        self.assertEqual(result.body_ref, "cluster:legion:compaii")
        self.assertEqual(len(result.certificate_hash), 64)
        self.assertEqual(len(result.capability_set_hash), 64)

    def test_expired_credential_does_not_gain_historical_admission(self) -> None:
        with self.assertRaises(CodexBodyError):
            self.check(at_ms=NOW + 100_001)

    def test_capability_expiry_boundary_and_future_validity_refuse(self) -> None:
        self.check(at_ms=NOW + 59_999)
        for at_ms in (NOW - 60_001, NOW + 60_000):
            with self.subTest(at_ms=at_ms), self.assertRaises(CodexBodyError):
                self.check(at_ms=at_ms)

    def test_selected_capability_client_and_required_methods_are_exact(self) -> None:
        substitutions: tuple[dict[str, Any], ...] = (
            {"capability_id": "unbound-capability"},
            {"client_id": "different-client"},
            {"required_methods": frozenset({"not.a.matrix.method"})},
            {"required_methods": frozenset()},
            {"required_methods": frozenset({"we.decide"})},
        )
        for changes in substitutions:
            with self.subTest(changes=changes), self.assertRaises(CodexBodyError):
                self.check(**changes)

    def test_signed_revoked_future_and_underprivileged_capabilities_refuse(
        self,
    ) -> None:
        substitutions: tuple[dict[str, Any], ...] = (
            {"status": "revoked"},
            {"not_before_ms": NOW + 1},
            {"not_after_ms": NOW},
            {"methods": ["runtime.status", "we.heads"]},
        )
        for changes in substitutions:
            with self.subTest(changes=changes):
                arguments = {
                    "client_id": self.capability.client_id,
                    "methods": self.capability.methods,
                    "not_before_ms": NOW - 1,
                    "not_after_ms": NOW + 2,
                    "status": "active",
                }
                arguments.update(changes)
                selected = create_capability(self.capability.key, **arguments)
                rows = copy.deepcopy(self.bundle["capabilities"])
                for row in rows:
                    if (
                        row["descriptor"]["capability_id"]
                        == self.capability.capability_id
                    ):
                        row["descriptor"] = selected.descriptor
                binding = create_operator_capability_binding(
                    runtime_id=self.bundle["runtime_id"],
                    runtime_label=self.bundle["runtime_label"],
                    being_ref=self.state.being_ref,
                    origin=self.origins["legion"],
                    signing_seed=self.signing_seeds["legion"],
                    capability_rows=rows,
                )
                with self.assertRaises(CodexBodyError) as refused:
                    self.check(
                        capability_rows=rows,
                        capability_binding=binding,
                        capability_id=selected.capability_id,
                    )
                self.assertEqual(
                    refused.exception.code, "matrix_capability_not_authorized"
                )

    def test_root_signed_revocation_refuses_historically_valid_credential(self) -> None:
        state = verify_successor(
            create_revocation(
                self.state,
                self.root_seeds,
                embodiment_id="embodiment:legion",
                cutoff_incarnation_sequence=0,
                revocation_generation=1,
            ),
            self.state,
        )
        value = copy.deepcopy(dict(self.manifest.value))
        value["control_head"] = state.head
        authority = RootAuthority(
            BeingManifest.from_value(value), state, self.credentials, self.incarnations
        )
        # Historical origin validation still succeeds; current admission must not.
        authority.validate_origin(self.origins["legion"], require_active=True)
        with self.assertRaises(CodexBodyError):
            self.check(authority=authority)

    def test_retired_manifest_does_not_admit_startup(self) -> None:
        value = copy.deepcopy(dict(self.manifest.value))
        for member in value["embodiments"]:
            if member["embodiment_id"] == "embodiment:legion":
                member["status"] = "retired"
        authority = RootAuthority(
            BeingManifest.from_value(value),
            self.state,
            self.credentials,
            self.incarnations,
        )
        with self.assertRaises(CodexBodyError):
            self.check(authority=authority)

    def test_relabelled_runtime_and_capabilities_refuse(self) -> None:
        for changes in (
            {"runtime_label": "other"},
            {"runtime_id": "other-runtime"},
            {"origin": self.origins["daimonmatrix"]},
        ):
            with self.subTest(changes=changes), self.assertRaises(CodexBodyError):
                self.check(**changes)
        rows = copy.deepcopy(self.bundle["capabilities"])
        rows[0]["descriptor"]["methods"] = []
        with self.assertRaises(CodexBodyError):
            self.check(capability_rows=rows)

    def test_signed_row_for_another_runtime_is_not_admitted(self) -> None:
        rows = copy.deepcopy(self.bundle["capabilities"])
        for row in rows:
            if row["descriptor"]["capability_id"] == self.capability.capability_id:
                row["runtime_id"] = "different-runtime"
        binding = create_operator_capability_binding(
            runtime_id=self.bundle["runtime_id"],
            runtime_label=self.bundle["runtime_label"],
            being_ref=self.state.being_ref,
            origin=self.origins["legion"],
            signing_seed=self.signing_seeds["legion"],
            capability_rows=rows,
        )
        with self.assertRaises(CodexBodyError) as refused:
            self.check(capability_rows=rows, capability_binding=binding)
        self.assertEqual(refused.exception.code, "matrix_capability_not_bound")
