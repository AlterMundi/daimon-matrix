#!/usr/bin/env python3
"""DM-042 real local Codex/Hermes plural-body validation."""

from __future__ import annotations

import concurrent.futures
import copy
import hashlib
import json
import os
import subprocess
import sys
import threading
import unittest
from collections.abc import Mapping
from contextlib import suppress
from pathlib import Path
from typing import Any
from unittest import mock

from jsonschema import (  # type: ignore[import-untyped]
    Draft202012Validator,
    FormatChecker,
)

from daimon_matrix.canonical import b64url, canonical_bytes
from daimon_matrix.codex_body import (
    BOOTSTRAP_SCHEMA as CODEX_BOOTSTRAP_SCHEMA,
)
from daimon_matrix.codex_body import (
    CODEX_VERSION,
    MATRIX_TOOLS,
    CodexBodyAdapter,
)
from daimon_matrix.codex_body import (
    RuntimeHandleJournal as CodexJournal,
)
from daimon_matrix.codex_body import (
    bind_plan as bind_codex_plan,
)
from daimon_matrix.codex_body import (
    create_launch_receipt as create_codex_launch_receipt,
)
from daimon_matrix.codex_body import (
    create_plan_value as create_codex_plan_value,
)
from daimon_matrix.codex_body import (
    create_profile as create_codex_profile,
)
from daimon_matrix.codex_body import (
    verify_profile as verify_codex_profile,
)
from daimon_matrix.hermes_body import (
    BOOTSTRAP_SCHEMA as HERMES_BOOTSTRAP_SCHEMA,
)
from daimon_matrix.hermes_body import (
    PROVIDER_READY_SCHEMA,
    READY_DOMAIN,
    HermesBodyAdapter,
    _heads_high_water,
)
from daimon_matrix.hermes_body import (
    RuntimeHandleJournal as HermesJournal,
)
from daimon_matrix.hermes_body import (
    bind_plan as bind_hermes_plan,
)
from daimon_matrix.hermes_body import (
    create_plan_value as create_hermes_plan_value,
)
from daimon_matrix.hermes_body import (
    create_profile as create_hermes_profile,
)
from daimon_matrix.hermes_body import (
    plan_id as hermes_plan_id,
)
from daimon_matrix.ledger import Ledger
from daimon_matrix.local_we import (
    LocalWeError,
    create_local_we_report,
    validate_local_we_report,
)
from daimon_matrix.projections import PROJECTION_DOMAIN, ProjectionEngine
from daimon_matrix.sync import SyncEngine, SyncProtocolError
from daimon_matrix.weave import BeingManifest, RootAuthority
from tests.test_dm022_ledger import NOW, RootLedgerFixture
from tests.test_dm041_hermes_body import supported_test_python
from tools.generate_dm042_vectors import outputs as generated_outputs

ROOT = Path(__file__).resolve().parents[1]


def derived(kind: str, label: str) -> str:
    return f"dm:{kind}:v1:" + b64url(hashlib.sha256(label.encode()).digest())


class FakeCodexTransport:
    def __init__(self, responses: Mapping[str, list[Mapping[str, Any]]]) -> None:
        self.responses = {
            method: [copy.deepcopy(dict(item)) for item in values]
            for method, values in responses.items()
        }
        self.notifications: list[tuple[str, dict[str, Any]]] = []

    def request(self, method: str, params: Mapping[str, Any]) -> Mapping[str, Any]:
        del params
        values = self.responses.get(method)
        if not values:
            raise AssertionError(f"unexpected Codex request: {method}")
        return values.pop(0)

    def notify(self, method: str, params: Mapping[str, Any]) -> None:
        self.notifications.append((method, copy.deepcopy(dict(params))))

    def read_message(self, timeout_seconds: float) -> Mapping[str, Any]:
        raise AssertionError(timeout_seconds)

    def close(self) -> None:
        return None


class LocalWeFixture(RootLedgerFixture):
    """Build two real adapter state machines over one root-bound authority."""

    def setUp(self) -> None:
        super().setUp()
        self.descriptors: list[int] = []
        self.addCleanup(self._close_descriptors)
        self.high_water = _heads_high_water([])

        self.codex_workspace = self._directory("codex-workspace")
        self.codex_profiles = self._directory("codex-profiles")
        self.codex_binary = self._executable("codex", b"#!/bin/sh\nexit 0\n")
        self.mcp_binary = self._executable("daimon-mcp", b"#!/bin/sh\nexit 0\n")
        self.hook_python = self._executable("hook-python", b"#!/bin/sh\nexit 0\n")
        codex_hash = hashlib.sha256(self.codex_binary.read_bytes()).hexdigest()
        self.codex_hash_patch = mock.patch(
            "daimon_matrix.codex_body.CODEX_BINARY_SHA256", codex_hash
        )
        self.codex_hash_patch.start()
        self.addCleanup(self.codex_hash_patch.stop)

        self.codex_bootstrap = self._bootstrap(
            "legion", CODEX_BOOTSTRAP_SCHEMA, "codex"
        )
        codex_value = create_codex_plan_value(
            bootstrap=self.codex_bootstrap,
            model="gpt-5.6-terra",
            provider="openai",
            workspace_ref=derived("workspace", "dm042-codex"),
        )
        self.codex_plan = bind_codex_plan(
            codex_value,
            profile_root=self.codex_profiles / "body",
            workspace=self.codex_workspace,
            codex_binary=self.codex_binary,
            mcp_binary=self.mcp_binary,
            mcp_args=(
                "--socket",
                os.fspath(self.root_path / "codex-matrix.sock"),
                "--client-config",
                os.fspath(self.root_path / "codex-client.json"),
                "--capability-key-fd",
                "7",
                "--request-dir",
                os.fspath(self.root_path / "codex-requests"),
            ),
            hook_python=self.hook_python,
        )

        self.hermes_workspace = self._directory("hermes-workspace")
        self.hermes_profiles = self._directory("hermes-profiles")
        self.hermes_source = self._directory("hermes-source")
        source_contract = self.hermes_source / "pyproject.toml"
        source_contract.write_text('[project]\nversion = "0.19.0"\n')
        source_contract.chmod(0o600)
        contracts = {
            "pyproject.toml": hashlib.sha256(source_contract.read_bytes()).hexdigest()
        }
        self.hermes_contract_patch = mock.patch(
            "daimon_matrix.hermes_body.HERMES_CONTRACT_DIGESTS", contracts
        )
        self.hermes_contract_patch.start()
        self.addCleanup(self.hermes_contract_patch.stop)
        self.hermes_python = supported_test_python(self.root_path)
        self.hermes_client_config = self.root_path / "hermes-client.json"
        self.hermes_client_config.write_text("{}")
        self.hermes_client_config.chmod(0o600)
        capability_reader, capability_writer = os.pipe()
        ready_reader, ready_writer = os.pipe()
        self.descriptors.extend(
            [capability_reader, capability_writer, ready_reader, ready_writer]
        )
        self.capability_reader = capability_reader
        self.ready_reader = ready_reader
        self.ready_writer = ready_writer

        self.hermes_bootstrap = self._bootstrap(
            "daimonmatrix", HERMES_BOOTSTRAP_SCHEMA, "hermes"
        )
        hermes_value = create_hermes_plan_value(
            bootstrap=self.hermes_bootstrap,
            model="synthetic/model",
            provider="synthetic",
            workspace_ref=derived("workspace", "dm042-hermes"),
        )
        self.hermes_plan = bind_hermes_plan(
            hermes_value,
            profile_root=self.hermes_profiles / "body",
            workspace=self.hermes_workspace,
            hermes_source=self.hermes_source,
            hermes_python=self.hermes_python,
            matrix_socket=self.root_path / "hermes-matrix.sock",
            matrix_client_config=self.hermes_client_config,
            capability_fd=self.capability_reader,
            ready_fd=self.ready_writer,
        )

    def _directory(self, name: str) -> Path:
        path = self.root_path / name
        path.mkdir(mode=0o700)
        return path

    def _executable(self, name: str, content: bytes) -> Path:
        path = self.root_path / name
        path.write_bytes(content)
        path.chmod(0o700)
        return path

    def _close_descriptors(self) -> None:
        for descriptor in self.descriptors:
            with suppress(OSError):
                os.close(descriptor)

    def _bootstrap(self, label: str, schema: str, harness: str) -> dict[str, Any]:
        origin = self.origins[label]
        return {
            "schema": schema,
            "being_ref": self.state.being_ref,
            "body_ref": origin["body_ref"],
            "embodiment_id": origin["embodiment_id"],
            "incarnation_id": origin["incarnation_id"],
            "matrix_session_id": derived("session", f"dm042-{harness}"),
            "matrix_high_water": self.high_water,
            "capability_set_hash": hashlib.sha256(
                f"dm042-{harness}-capabilities".encode()
            ).hexdigest(),
            "certificate_hash": hashlib.sha256(
                f"dm042-{harness}-certificate".encode()
            ).hexdigest(),
            "issued_at_ms": NOW - 1_000,
            "expires_at_ms": NOW + 100_000,
            "signature": {
                "alg": "Ed25519",
                "kid": derived("key", f"dm042-{harness}-bootstrap"),
                "value": b64url(bytes(range(64))),
            },
        }

    def _codex_responses(self) -> dict[str, list[Mapping[str, Any]]]:
        thread = {
            "activePermissionProfile": None,
            "thread": {
                "id": "dm042-codex-thread",
                "sessionId": "dm042-codex-tree",
                "cliVersion": CODEX_VERSION,
                "modelProvider": "openai",
            },
            "approvalPolicy": "on-request",
            "approvalsReviewer": "user",
            "cwd": os.fspath(self.codex_workspace),
            "instructionSources": [
                os.fspath(self.codex_plan.profile_root / "AGENTS.md")
            ],
            "model": "gpt-5.6-terra",
            "modelProvider": "openai",
            "multiAgentMode": "explicitRequestOnly",
            "runtimeWorkspaceRoots": [os.fspath(self.codex_workspace)],
            "sandbox": {"type": "workspaceWrite"},
        }
        inventory = {
            "data": [
                {
                    "name": "matrix",
                    "authStatus": "unsupported",
                    "resourceTemplates": [],
                    "resources": [],
                    "serverInfo": {"name": "daimon-matrix", "version": "0.0.0"},
                    "tools": {
                        name: {"name": name, "inputSchema": {}} for name in MATRIX_TOOLS
                    },
                }
            ],
            "nextCursor": None,
        }
        return {
            "initialize": [
                {
                    "codexHome": os.fspath(self.codex_plan.profile_root),
                    "platformFamily": "unix",
                    "platformOs": "linux",
                    "userAgent": f"codex_cli_rs/{CODEX_VERSION}",
                }
            ],
            "thread/start": [thread],
            "mcpServerStatus/list": [inventory],
        }

    def launch_bodies(self) -> None:
        codex_profile = create_codex_profile(
            self.codex_plan,
            bootstrap_verifier=lambda evidence, at_ms: (
                evidence == self.codex_bootstrap and at_ms == NOW
            ),
            clock=lambda: NOW,
        )
        codex_journal = CodexJournal(self.root_path / "codex-runtime-handles.jsonl")

        def presence(binding: Mapping[str, Any], at_ms: int) -> Mapping[str, Any]:
            if at_ms != NOW:
                raise AssertionError(at_ms)
            return {
                **{
                    key: binding[key]
                    for key in (
                        "body_ref",
                        "embodiment_id",
                        "incarnation_id",
                        "matrix_session_id",
                        "matrix_high_water",
                    )
                },
                "state": "active",
                "expires_at_ms": NOW + 60_000,
            }

        codex_adapter = CodexBodyAdapter(
            self.codex_plan,
            FakeCodexTransport(self._codex_responses()),
            presence,
            codex_journal,
            clock=lambda: NOW,
        )
        hermes_profile = create_hermes_profile(
            self.hermes_plan,
            bootstrap_verifier=lambda evidence, at_ms: (
                evidence == self.hermes_bootstrap and at_ms == NOW
            ),
            clock=lambda: NOW,
        )
        ready_core = {
            "schema": PROVIDER_READY_SCHEMA,
            "plan_id": hermes_plan_id(self.hermes_plan.value),
            "being_ref": self.hermes_bootstrap["being_ref"],
            "body_ref": self.hermes_bootstrap["body_ref"],
            "embodiment_id": self.hermes_bootstrap["embodiment_id"],
            "incarnation_id": self.hermes_bootstrap["incarnation_id"],
            "matrix_session_id": self.hermes_bootstrap["matrix_session_id"],
            "hermes_session_id": "dm042-hermes-session",
            "matrix_high_water": self.high_water,
            "at_ms": NOW,
        }
        ready = {
            **ready_core,
            "ready_id": "dm:hermes-ready:v1:"
            + b64url(
                hashlib.sha256(READY_DOMAIN + canonical_bytes(ready_core)).digest()
            ),
        }
        os.write(self.ready_writer, canonical_bytes(ready) + b"\n")
        process = mock.Mock()
        process.poll.return_value = None
        hermes_adapter = HermesBodyAdapter(
            self.hermes_plan,
            HermesJournal(self.root_path / "hermes-runtime-handles.jsonl"),
            clock=lambda: NOW,
        )
        admission_barrier = threading.Barrier(2)

        def start_codex() -> Mapping[str, Any]:
            codex_adapter.initialize()
            admission_barrier.wait(timeout=3)
            return codex_adapter.start()

        def start_hermes() -> Any:
            admission_barrier.wait(timeout=3)
            return hermes_adapter.start(
                hermes_session_id="dm042-hermes-session",
                ready_reader_fd=self.ready_reader,
                provider_environment={"SYNTHETIC_API_KEY": "not-a-live-secret"},
            )

        with (
            mock.patch(
                "daimon_matrix.hermes_body.verify_profile",
                return_value=hermes_profile,
            ),
            mock.patch(
                "daimon_matrix.hermes_body.subprocess.Popen", return_value=process
            ),
            concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool,
        ):
            codex_future = pool.submit(start_codex)
            hermes_future = pool.submit(start_hermes)
            codex_handle = codex_future.result(timeout=5)
            hermes_process = hermes_future.result(timeout=5)
        self.codex_launch = create_codex_launch_receipt(
            self.codex_plan,
            codex_profile,
            codex_handle,
            outcome="started",
        )
        self.hermes_launch = hermes_process.receipt
        self.assertEqual(codex_handle["state"], "active")
        self.assertEqual(hermes_process.handle["state"], "active")
        self.assertEqual(codex_profile, verify_codex_profile(self.codex_plan))
        self.assertEqual(hermes_profile["profile_id"], self.hermes_launch["profile_id"])

    @staticmethod
    def transfer(
        receiver: SyncEngine,
        sender: SyncEngine,
        request_id: str,
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
        request = receiver.request(request_id=request_id, limit=64)
        page = sender.serve(request)
        receipt = receiver.pull(page)
        return request, page, receipt

    def converged_report(self) -> tuple[dict[str, Any], dict[str, Any]]:
        self.launch_bodies()
        target = self.ledger_a.append_local(
            kind="experience.observed",
            subject="dm042-shared-target",
            payload={"summary": "Codex-authored shared target"},
            signer=self.signers["legion"],
            occurred_at_ms=NOW,
            event_id="42000000-0000-4000-8000-000000000001",
        )
        hermes_observation = self.ledger_b.append_local(
            kind="experience.observed",
            subject="dm042-hermes-observation",
            payload={"summary": "Hermes-authored independent evidence"},
            signer=self.signers["daimonmatrix"],
            occurred_at_ms=NOW,
            event_id="42000000-0000-4000-8000-000000000002",
        )
        self.assertIsNone(self.ledger_a.event(hermes_observation["event_id"]))
        self.assertIsNone(self.ledger_b.event(target["event_id"]))

        sync_a = SyncEngine(self.ledger_a)
        sync_b = SyncEngine(self.ledger_b)
        request_1, page_1, receipt_1 = self.transfer(
            sync_b, sync_a, "42000000-0000-4000-8000-000000000011"
        )
        request_2, page_2, receipt_2 = self.transfer(
            sync_a, sync_b, "42000000-0000-4000-8000-000000000012"
        )
        codex_decision = self.ledger_a.append_local(
            kind="adoption.decided",
            subject=target["subject"],
            payload={
                "target_event_id": target["event_id"],
                "decision": "adopt",
                "reason": "Codex-local choice",
            },
            signer=self.signers["legion"],
            causal_parents=[target["event_id"]],
            occurred_at_ms=NOW + 1,
            event_id="42000000-0000-4000-8000-000000000003",
        )
        hermes_decision = self.ledger_b.append_local(
            kind="adoption.decided",
            subject=target["subject"],
            payload={
                "target_event_id": target["event_id"],
                "decision": "reject",
                "reason": "Hermes-local choice",
            },
            signer=self.signers["daimonmatrix"],
            causal_parents=[target["event_id"]],
            occurred_at_ms=NOW + 1,
            event_id="42000000-0000-4000-8000-000000000004",
        )
        request_3, page_3, receipt_3 = self.transfer(
            sync_b, sync_a, "42000000-0000-4000-8000-000000000013"
        )
        request_4, page_4, receipt_4 = self.transfer(
            sync_a, sync_b, "42000000-0000-4000-8000-000000000014"
        )

        restarted_a = SyncEngine(
            Ledger(
                self.ledger_a.path,
                authority=self.authority,
                local_origin=self.origins["legion"],
                clock=lambda: NOW,
            )
        )
        restarted_b = SyncEngine(
            Ledger(
                self.ledger_b.path,
                authority=self.authority,
                local_origin=self.origins["daimonmatrix"],
                clock=lambda: NOW,
            )
        )
        for engine, page, receipt in (
            (restarted_b, page_1, receipt_1),
            (restarted_a, page_2, receipt_2),
            (restarted_b, page_3, receipt_3),
            (restarted_a, page_4, receipt_4),
        ):
            self.assertEqual(
                canonical_bytes(engine.pull(page)), canonical_bytes(receipt)
            )
        for engine, request, page in (
            (restarted_a, request_1, page_1),
            (restarted_b, request_2, page_2),
            (restarted_a, request_3, page_3),
            (restarted_b, request_4, page_4),
        ):
            self.assertEqual(
                canonical_bytes(engine.serve(request)), canonical_bytes(page)
            )
        with self.assertRaisesRegex(SyncProtocolError, "sync_request_id_conflict"):
            restarted_b.request(request_id=request_1["request_id"], limit=63)
        unsolicited = SyncEngine(
            Ledger(
                self.root_path / "unsolicited" / "ledger.sqlite",
                authority=self.authority,
                local_origin=self.origins["daimonmatrix"],
                clock=lambda: NOW,
            )
        )
        with self.assertRaisesRegex(SyncProtocolError, "unsolicited_sync_delta"):
            unsolicited.pull(page_1)

        codex_projection = ProjectionEngine(self.ledger_a).snapshot()
        hermes_projection = ProjectionEngine(self.ledger_b).snapshot()
        codex_entry = next(
            item
            for item in codex_projection["entries"]
            if item["event_id"] == target["event_id"]
        )
        hermes_entry = next(
            item
            for item in hermes_projection["entries"]
            if item["event_id"] == target["event_id"]
        )
        self.assertEqual(codex_entry["decision_event_id"], codex_decision["event_id"])
        self.assertEqual(hermes_entry["decision_event_id"], hermes_decision["event_id"])

        inputs = {
            "authority": self.authority,
            "codex_plan": self.codex_plan,
            "codex_launch_receipt": self.codex_launch,
            "codex_ledger": self.ledger_a,
            "codex_projection": codex_projection,
            "hermes_plan": self.hermes_plan,
            "hermes_launch_receipt": self.hermes_launch,
            "hermes_ledger": self.ledger_b,
            "hermes_projection": hermes_projection,
            "sync_receipts": [receipt_1, receipt_2, receipt_3, receipt_4],
            "target_event_id": target["event_id"],
            "observed_at_ms": NOW + 2,
        }
        return create_local_we_report(**inputs), inputs


class LocalWeIntegrationTests(LocalWeFixture):
    def test_two_real_bodies_converge_but_keep_independent_adoption(self) -> None:
        report, inputs = self.converged_report()
        self.assertEqual(validate_local_we_report(report), report)
        self.assertEqual(
            canonical_bytes(create_local_we_report(**inputs)), canonical_bytes(report)
        )
        self.assertEqual(
            [item["harness"] for item in report["bodies"]], ["codex", "hermes"]
        )
        self.assertEqual(
            [item["state"] for item in report["bodies"]], ["adopted", "rejected"]
        )
        self.assertEqual(len(report["sync"]), 4)
        self.assertNotIn(os.fspath(self.root_path), canonical_bytes(report).decode())
        self.assertNotEqual(
            self.ledger_a.path.stat().st_ino, self.ledger_b.path.stat().st_ino
        )

    def test_report_and_runtime_substitutions_fail_closed(self) -> None:
        report, inputs = self.converged_report()
        wrong_id = copy.deepcopy(report)
        wrong_id["report_id"] = derived("local-we-validation", "wrong")
        false_storage = copy.deepcopy(report)
        false_storage["storage_isolation"]["ledger_files_distinct"] = False
        aliased_capability = copy.deepcopy(report)
        aliased_capability["bodies"][1]["capability_set_hash"] = aliased_capability[
            "bodies"
        ][0]["capability_set_hash"]
        aliased_decision = copy.deepcopy(report)
        aliased_decision["bodies"][1]["decision_event_id"] = aliased_decision["bodies"][
            0
        ]["decision_event_id"]
        for changed in (
            wrong_id,
            false_storage,
            aliased_capability,
            aliased_decision,
        ):
            with self.assertRaises(LocalWeError):
                validate_local_we_report(changed)

        for field in (
            "embodiment_credential_id",
            "signing_key_id",
            "encryption_key_id",
            "matrix_session_id",
            "profile_id",
        ):
            aliased = copy.deepcopy(report)
            aliased["bodies"][1][field] = aliased["bodies"][0][field]
            with self.subTest(field=field), self.assertRaises(LocalWeError):
                validate_local_we_report(aliased)
        aliased_transport = copy.deepcopy(report)
        aliased_transport["bodies"][1]["transport_key_ids"] = copy.deepcopy(
            aliased_transport["bodies"][0]["transport_key_ids"]
        )
        with self.assertRaises(LocalWeError):
            validate_local_we_report(aliased_transport)

        revised_manifest = BeingManifest.from_value(
            {**self.manifest.value, "revision": self.manifest.value["revision"] + 1}
        )
        revised_authority = RootAuthority(
            revised_manifest,
            self.state,
            self.credentials,
            self.incarnations,
        )
        manifest_drift = dict(inputs)
        manifest_drift["authority"] = revised_authority
        with self.assertRaisesRegex(LocalWeError, "manifest_hash_mismatch"):
            create_local_we_report(**manifest_drift)

        shared_ledger = dict(inputs)
        shared_ledger["hermes_ledger"] = self.ledger_a
        with self.assertRaisesRegex(LocalWeError, "shared_writable_ledger"):
            create_local_we_report(**shared_ledger)

        fabricated_projection = copy.deepcopy(inputs["hermes_projection"])
        fabricated_projection["local_embodiment_id"] = self.origins["legion"][
            "embodiment_id"
        ]
        projection_core = {
            key: value
            for key, value in fabricated_projection.items()
            if key != "projection_hash"
        }
        fabricated_projection["projection_hash"] = hashlib.sha256(
            PROJECTION_DOMAIN + canonical_bytes(projection_core)
        ).hexdigest()
        wrong_projection = dict(inputs)
        wrong_projection["codex_projection"] = fabricated_projection
        with self.assertRaisesRegex(LocalWeError, "projection_ledger_mismatch"):
            create_local_we_report(**wrong_projection)

        wrong_launch = dict(inputs)
        wrong_launch["codex_launch_receipt"] = copy.deepcopy(self.codex_launch)
        wrong_launch["codex_launch_receipt"]["matrix_binding"]["body_ref"] = (
            self.hermes_bootstrap["body_ref"]
        )
        with self.assertRaisesRegex(LocalWeError, "body_launch_evidence_invalid"):
            create_local_we_report(**wrong_launch)


class PublishedContractTests(unittest.TestCase):
    def test_schema_vectors_index_and_generator_are_exact(self) -> None:
        schema = json.loads(
            (ROOT / "schemas/local-we/v1/validation.schema.json").read_bytes()
        )
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema, format_checker=FormatChecker())
        vector_root = ROOT / "vectors/local-we/v1"
        valid = json.loads((vector_root / "valid/report.json").read_bytes())
        validator.validate(valid)
        self.assertEqual(validate_local_we_report(valid), valid)

        for path in sorted((vector_root / "negative").glob("*.json")):
            with self.subTest(path=path.name):
                value = json.loads(path.read_bytes())
                with self.assertRaises(LocalWeError):
                    validate_local_we_report(value)

        index = json.loads((vector_root / "index.json").read_bytes())
        self.assertEqual(index["schema"], "dm.local-we.vector-index/v1")
        for item in index["files"]:
            self.assertEqual(
                hashlib.sha256((vector_root / item["name"]).read_bytes()).hexdigest(),
                item["sha256"],
            )
        for path, raw in generated_outputs().items():
            self.assertEqual(path.read_bytes(), raw, path)
        completed = subprocess.run(
            [sys.executable, "tools/generate_dm042_vectors.py", "--check"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)


if __name__ == "__main__":
    unittest.main()
