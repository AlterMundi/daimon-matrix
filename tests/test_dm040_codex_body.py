#!/usr/bin/env python3
"""DM-040 isolated Codex body contract and adversarial tests."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import select
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import tomllib
import unittest
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, cast
from unittest import mock

from jsonschema import Draft202012Validator  # type: ignore[import-untyped]

from daimon_matrix.canonical import b64url, canonical_bytes
from daimon_matrix.client import CLIENT_CONFIG_SCHEMA
from daimon_matrix.codex_body import (
    AGENTS_TEMPLATE,
    APP_SERVER_SCHEMA_DIGEST,
    APP_SERVER_TYPESCRIPT_DIGEST,
    BOOTSTRAP_SCHEMA,
    CODEX_BINARY_SHA256,
    CODEX_VERSION,
    MATRIX_TOOLS,
    AppServerProcess,
    CodexBodyAdapter,
    CodexBodyError,
    CodexBodyPlan,
    PresenceVerifier,
    RuntimeHandleJournal,
    bind_plan,
    build_ephemeral_argv,
    create_launch_receipt,
    create_plan_value,
    create_profile,
    normalized_schema_bundle_digest,
    render_config,
    run_hook,
    typescript_bundle_digest,
    validate_bootstrap,
    validate_plan,
    verify_effective_features,
    verify_profile,
)
from daimon_matrix.daemon import serve_forever
from daimon_matrix.runtime import load_runtime
from tests.test_dm024_runtime import PASSWORD, RuntimeFixture

ROOT = Path(__file__).resolve().parents[1]
NOW = 1_800_000_000_000
FAKE_FEATURE_PROBE = b"""if sys.argv[1:] == ['features', 'list']:
    for name, enabled in (
        ('apps', False), ('browser_use', False), ('chronicle', False),
        ('computer_use', False), ('external_agent_memory_import', False),
        ('hooks', True), ('memories', False), ('multi_agent', False),
        ('plugins', False),
    ):
        print(name, 'stable', str(enabled).lower())
    raise SystemExit(0)
"""


def derived(kind: str, label: str) -> str:
    return f"dm:{kind}:v1:" + b64url(hashlib.sha256(label.encode()).digest())


def bootstrap(label: str = "alpha") -> dict[str, Any]:
    return {
        "schema": BOOTSTRAP_SCHEMA,
        "being_ref": derived("being", f"being-{label}"),
        "body_ref": f"cluster:synthetic:body-{label}",
        "embodiment_id": f"embodiment:synthetic:{label}",
        "incarnation_id": f"incarnation:synthetic:{label}:0",
        "matrix_session_id": derived("session", f"matrix-session-{label}"),
        "matrix_high_water": hashlib.sha256(f"high-water-{label}".encode()).hexdigest(),
        "capability_set_hash": hashlib.sha256(
            f"capabilities-{label}".encode()
        ).hexdigest(),
        "certificate_hash": hashlib.sha256(f"certificate-{label}".encode()).hexdigest(),
        "issued_at_ms": NOW - 10_000,
        "expires_at_ms": NOW + 3_600_000,
        "signature": {
            "alg": "Ed25519",
            "kid": derived("key", f"key-{label}"),
            "value": b64url(bytes(range(64))),
        },
    }


class FakeTransport:
    def __init__(self, responses: Mapping[str, list[Mapping[str, Any]]]) -> None:
        self.responses = {
            key: [copy.deepcopy(dict(item)) for item in value]
            for key, value in responses.items()
        }
        self.requests: list[tuple[str, dict[str, Any]]] = []
        self.notifications: list[tuple[str, dict[str, Any]]] = []
        self.closed = False

    def request(self, method: str, params: Mapping[str, Any]) -> Mapping[str, Any]:
        self.requests.append((method, copy.deepcopy(dict(params))))
        values = self.responses.get(method)
        if not values:
            raise AssertionError(f"unexpected request: {method}")
        return values.pop(0)

    def notify(self, method: str, params: Mapping[str, Any]) -> None:
        self.notifications.append((method, copy.deepcopy(dict(params))))

    def read_message(self, timeout_seconds: float) -> Mapping[str, Any]:
        raise AssertionError(timeout_seconds)

    def close(self) -> None:
        self.closed = True


class CodexBodyFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="dm040-test-")
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir(mode=0o700)
        self.profile_parent = self.root / "profiles"
        self.profile_parent.mkdir(mode=0o700)
        self.codex_binary = self.root / "codex"
        self.mcp_binary = self.root / "daimon-mcp"
        self.python_binary = self.root / "python3"
        for path, body in (
            (self.codex_binary, b"#!/bin/sh\nexit 0\n"),
            (self.mcp_binary, b"#!/bin/sh\nexit 0\n"),
            (self.python_binary, b"#!/bin/sh\nexit 0\n"),
        ):
            path.write_bytes(body)
            path.chmod(0o700)
        self.fake_codex_hash = hashlib.sha256(
            self.codex_binary.read_bytes()
        ).hexdigest()
        self.hash_patch = mock.patch(
            "daimon_matrix.codex_body.CODEX_BINARY_SHA256", self.fake_codex_hash
        )
        self.hash_patch.start()
        self.addCleanup(self.hash_patch.stop)
        self.bootstrap = bootstrap()
        self.plan_value = create_plan_value(
            bootstrap=self.bootstrap,
            model="gpt-5.6-terra",
            provider="openai",
            workspace_ref=derived("workspace", "workspace-alpha"),
        )
        self.plan = self.make_plan(self.profile_parent / "alpha")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def make_plan(
        self,
        root: Path,
        *,
        value: Mapping[str, Any] | None = None,
        capability_fd: int = 7,
    ) -> CodexBodyPlan:
        return bind_plan(
            value or self.plan_value,
            profile_root=root,
            workspace=self.workspace,
            codex_binary=self.codex_binary,
            mcp_binary=self.mcp_binary,
            mcp_args=(
                "--socket",
                os.fspath(self.root / "matrix.sock"),
                "--client-config",
                os.fspath(self.root / "client.json"),
                "--capability-key-fd",
                str(capability_fd),
                "--request-dir",
                os.fspath(self.root / "requests"),
            ),
            hook_python=self.python_binary,
        )

    def create(self, plan: CodexBodyPlan | None = None) -> dict[str, Any]:
        return create_profile(
            plan or self.plan,
            bootstrap_verifier=lambda evidence, at_ms: (
                evidence == self.bootstrap and at_ms == NOW
            ),
            clock=lambda: NOW,
        )

    def presence(self, binding: Mapping[str, Any], at_ms: int) -> Mapping[str, Any]:
        self.assertEqual(at_ms, NOW)
        return {
            "body_ref": binding["body_ref"],
            "embodiment_id": binding["embodiment_id"],
            "incarnation_id": binding["incarnation_id"],
            "matrix_session_id": binding["matrix_session_id"],
            "matrix_high_water": binding["matrix_high_water"],
            "state": "active",
            "expires_at_ms": NOW + 60_000,
        }

    def thread_result(
        self, thread: str = "thread-alpha", session: str = "tree-alpha"
    ) -> dict[str, Any]:
        return {
            "activePermissionProfile": None,
            "thread": {
                "id": thread,
                "sessionId": session,
                "cliVersion": CODEX_VERSION,
                "modelProvider": "openai",
            },
            "approvalPolicy": "on-request",
            "approvalsReviewer": "user",
            "cwd": os.fspath(self.workspace),
            "instructionSources": [os.fspath(self.plan.profile_root / "AGENTS.md")],
            "model": "gpt-5.6-terra",
            "modelProvider": "openai",
            "multiAgentMode": "explicitRequestOnly",
            "runtimeWorkspaceRoots": [os.fspath(self.workspace)],
            "sandbox": {"type": "workspaceWrite"},
        }

    def mcp_inventory(self) -> dict[str, Any]:
        return {
            "data": [
                {
                    "name": "matrix",
                    "authStatus": "unsupported",
                    "resourceTemplates": [],
                    "resources": [],
                    "serverInfo": {
                        "name": "daimon-matrix",
                        "version": "0.1.0rc1",
                    },
                    "tools": {
                        name: {"name": name, "inputSchema": {}} for name in MATRIX_TOOLS
                    },
                }
            ],
            "nextCursor": None,
        }


class ContractTests(CodexBodyFixture):
    def test_pinned_contract_and_closed_plan(self) -> None:
        self.assertEqual(CODEX_VERSION, "0.146.0")
        self.assertEqual(
            CODEX_BINARY_SHA256,
            "2e863156ed35ecc5253b1e2f907a9143077b9f7cb51942070c61996471ff6e04",
        )
        self.assertEqual(
            APP_SERVER_SCHEMA_DIGEST,
            "146a56d701ccd97a76ad1a461d51fc454f32df6c5b4d338ea65968331ccc8b7a",
        )
        self.assertEqual(
            APP_SERVER_TYPESCRIPT_DIGEST,
            "b60eaad826761bac1ebb33a933e0a0ad389a343f983b288107484e2e2b9c93e2",
        )
        self.assertEqual(validate_plan(self.plan_value), self.plan_value)
        tampered = copy.deepcopy(self.plan_value)
        tampered["unknown"] = True
        with self.assertRaisesRegex(CodexBodyError, "invalid_codex_body_plan"):
            validate_plan(tampered)

    def test_bootstrap_is_signed_bounded_and_explicitly_nonambient(self) -> None:
        self.assertEqual(validate_bootstrap(self.bootstrap), self.bootstrap)
        for field in ("signature", "matrix_high_water", "matrix_session_id"):
            tampered = copy.deepcopy(self.bootstrap)
            del tampered[field]
            with self.subTest(field=field), self.assertRaises(CodexBodyError):
                validate_bootstrap(tampered)
        tampered = copy.deepcopy(self.bootstrap)
        tampered["signature"]["value"] = b64url(b"short")
        with self.assertRaisesRegex(CodexBodyError, "invalid_codex_bootstrap"):
            validate_bootstrap(tampered)

    def test_generated_schema_digest_canonicalizes_unstable_definition_order(
        self,
    ) -> None:
        first = self.root / "schemas-a"
        second = self.root / "schemas-b"
        first.mkdir()
        second.mkdir()
        (first / "one.json").write_text('{"definitions":{"a":1,"b":2}}')
        (second / "one.json").write_text('{"definitions":{"b":2,"a":1}}')
        self.assertEqual(
            normalized_schema_bundle_digest(first),
            normalized_schema_bundle_digest(second),
        )
        ts_a = self.root / "ts-a"
        ts_b = self.root / "ts-b"
        ts_a.mkdir()
        ts_b.mkdir()
        (ts_a / "one.ts").write_text("export type X = string;\n")
        (ts_b / "one.ts").write_text("export type X = string;\n")
        self.assertEqual(typescript_bundle_digest(ts_a), typescript_bundle_digest(ts_b))


class GeneratedArtifactTests(unittest.TestCase):
    def test_closed_schema_accepts_valid_and_rejects_negative_vectors(self) -> None:
        schema = json.loads(
            (ROOT / "schemas/codex/v1/contracts.schema.json").read_text()
        )
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        vector_root = ROOT / "vectors/codex/v1"
        for path in sorted((vector_root / "valid").glob("*.json")):
            with self.subTest(path=path.name):
                validator.validate(json.loads(path.read_text()))
        for path in sorted((vector_root / "negative").glob("*.json")):
            with self.subTest(path=path.name):
                self.assertTrue(
                    list(validator.iter_errors(json.loads(path.read_text())))
                )

    def test_vector_index_templates_and_generator_are_exact(self) -> None:
        vector_root = ROOT / "vectors/codex/v1"
        index = json.loads((vector_root / "index.json").read_text())
        self.assertEqual(index["schema"], "dm.codex-body.vector-index/v1")
        for item in index["files"]:
            self.assertEqual(
                hashlib.sha256((vector_root / item["name"]).read_bytes()).hexdigest(),
                item["sha256"],
            )
        self.assertEqual(
            (ROOT / "templates/codex/v1/AGENTS.md").read_text(), AGENTS_TEMPLATE
        )
        result = subprocess.run(
            [sys.executable, "tools/generate_dm040_vectors.py", "--check"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


class ProfileTests(CodexBodyFixture):
    def test_deterministic_config_agents_hooks_and_profile_manifest(self) -> None:
        first = render_config(self.plan)
        second = render_config(self.plan)
        self.assertEqual(first, second)
        config = tomllib.loads(first.decode())
        self.assertEqual(config["history"], {"persistence": "none"})
        self.assertFalse(config["features"]["memories"])
        self.assertFalse(config["memories"]["use_memories"])
        self.assertFalse(config["memories"]["generate_memories"])
        self.assertEqual(
            config["projects"][os.fspath(self.workspace)]["trust_level"],
            "untrusted",
        )
        self.assertTrue(config["mcp_servers"]["matrix"]["required"])
        self.assertEqual(
            config["mcp_servers"]["matrix"]["enabled_tools"], list(MATRIX_TOOLS)
        )
        self.assertNotIn("dangerously-bypass", first.decode())
        self.assertNotIn("auth.json", AGENTS_TEMPLATE.lower())
        self.assertNotIn("api key", AGENTS_TEMPLATE.lower())
        manifest = self.create()
        self.assertEqual(verify_profile(self.plan), manifest)
        self.assertEqual(
            (self.plan.profile_root / "config.toml").stat().st_mode & 0o777, 0o600
        )
        self.assertEqual(
            (self.plan.profile_root / "hooks/lifecycle.py").stat().st_mode & 0o777,
            0o700,
        )

    def test_existing_profile_is_refused_without_deletion(self) -> None:
        self.plan.profile_root.mkdir(mode=0o700)
        marker = self.plan.profile_root / "human-state"
        marker.write_text("keep")
        with self.assertRaisesRegex(CodexBodyError, "profile_already_exists"):
            self.create()
        self.assertEqual(marker.read_text(), "keep")

    def test_unsafe_parent_mode_symlink_and_hardlink_are_rejected(self) -> None:
        unsafe = self.root / "unsafe"
        unsafe.mkdir(mode=0o777)
        unsafe.chmod(0o777)
        with self.assertRaisesRegex(CodexBodyError, "profile_parent_not_owner_only"):
            self.create(self.make_plan(unsafe / "profile"))

        link = self.profile_parent / "linked"
        link.symlink_to(self.workspace, target_is_directory=True)
        with self.assertRaises(CodexBodyError):
            self.create(self.make_plan(link / "profile"))

        self.create()
        config = self.plan.profile_root / "config.toml"
        hardlink = self.root / "config-hardlink"
        os.link(config, hardlink)
        with self.assertRaisesRegex(CodexBodyError, "profile_file_rejected"):
            verify_profile(self.plan)

    def test_path_replacement_and_generated_memory_fail_closed(self) -> None:
        self.create()
        config = self.plan.profile_root / "config.toml"
        config.unlink()
        config.symlink_to(self.plan.profile_root / "AGENTS.md")
        with self.assertRaisesRegex(CodexBodyError, "profile_file_rejected"):
            verify_profile(self.plan)

        second = self.make_plan(self.profile_parent / "memory-negative")
        self.create(second)
        memories = second.profile_root / "memories"
        memories.mkdir(mode=0o700)
        (memories / "generated.md").write_text("synthetic")
        with self.assertRaisesRegex(CodexBodyError, "codex_native_memory_artifact"):
            verify_profile(second)

        third = self.make_plan(self.profile_parent / "auth-negative")
        self.create(third)
        (third.profile_root / "auth.json").write_text("{}")
        with self.assertRaisesRegex(CodexBodyError, "codex_native_memory_artifact"):
            verify_profile(third)

    def test_effective_features_reject_managed_override(self) -> None:
        self.create()
        safe = b"\n".join(
            f"{name} stable {'true' if enabled else 'false'}".encode()
            for name, enabled in {
                "apps": False,
                "browser_use": False,
                "chronicle": False,
                "computer_use": False,
                "external_agent_memory_import": False,
                "hooks": True,
                "memories": False,
                "multi_agent": False,
                "plugins": False,
            }.items()
        )
        completed = subprocess.CompletedProcess([], 0, safe + b"\n", b"")
        with mock.patch(
            "daimon_matrix.codex_body.subprocess.run", return_value=completed
        ):
            verify_effective_features(self.plan)

        managed = safe.replace(b"memories stable false", b"memories stable true")
        completed = subprocess.CompletedProcess([], 0, managed + b"\n", b"")
        with (
            mock.patch(
                "daimon_matrix.codex_body.subprocess.run", return_value=completed
            ),
            self.assertRaisesRegex(CodexBodyError, "codex_managed_override_conflict"),
        ):
            verify_effective_features(self.plan)

    def test_two_beings_have_disjoint_profiles_and_bootstrap(self) -> None:
        self.create()
        other_bootstrap = bootstrap("beta")
        other_value = create_plan_value(
            bootstrap=other_bootstrap,
            model="gpt-5.6-terra",
            provider="openai",
            workspace_ref=derived("workspace", "workspace-beta"),
        )
        other = self.make_plan(self.profile_parent / "beta", value=other_value)
        create_profile(
            other,
            bootstrap_verifier=lambda evidence, at_ms: (
                evidence == other_bootstrap and at_ms == NOW
            ),
            clock=lambda: NOW,
        )
        self.assertNotEqual(
            (self.plan.profile_root / "bootstrap.json").read_bytes(),
            (other.profile_root / "bootstrap.json").read_bytes(),
        )
        self.assertNotEqual(
            verify_profile(self.plan)["profile_id"], verify_profile(other)["profile_id"]
        )
        self.assertFalse((self.plan.profile_root / "auth.json").exists())
        self.assertFalse((other.profile_root / "auth.json").exists())

    def test_ephemeral_argv_is_fixed_and_prompt_is_not_an_argument(self) -> None:
        self.create()
        argv = build_ephemeral_argv(self.plan)
        self.assertIn("--ephemeral", argv)
        self.assertIn("--strict-config", argv)
        self.assertEqual(argv[-1], "-")
        self.assertNotIn("--dangerously-bypass-approvals-and-sandbox", argv)
        self.assertNotIn("--dangerously-bypass-hook-trust", argv)


class HookTests(CodexBodyFixture):
    def setUp(self) -> None:
        super().setUp()
        self.create()

    def payload(self, event: str) -> dict[str, Any]:
        return {
            "session_id": "019abcde-0000-7000-8000-000000000001",
            "transcript_path": None,
            "cwd": os.fspath(self.workspace),
            "hook_event_name": event,
            "model": "gpt-5.6-terra",
            "permission_mode": "default",
        }

    def test_session_start_emits_only_signed_bounded_descriptor(self) -> None:
        payload = self.payload("SessionStart")
        payload["source"] = "startup"
        result = run_hook(
            "session-start",
            self.plan.profile_root / "bootstrap.json",
            self.plan.profile_root / "lifecycle-observations.jsonl",
            payload,
            clock=lambda: NOW,
        )
        context = result["hookSpecificOutput"]["additionalContext"]
        self.assertTrue(context.startswith("DAIMON_BODY_BOOTSTRAP="))
        self.assertNotIn(os.fspath(self.workspace), context)
        self.assertNotIn("prompt", context.lower())
        observation = json.loads(
            (self.plan.profile_root / "lifecycle-observations.jsonl")
            .read_text()
            .strip()
        )
        self.assertEqual(observation["event"], "session-start")
        self.assertNotIn("cwd", observation)

    def test_hook_rejects_mismatched_event_and_oversized_identity(self) -> None:
        payload = self.payload("Stop")
        with self.assertRaisesRegex(CodexBodyError, "hook_event_mismatch"):
            run_hook(
                "session-start",
                self.plan.profile_root / "bootstrap.json",
                self.plan.profile_root / "observations.jsonl",
                payload,
                clock=lambda: NOW,
            )
        payload["hook_event_name"] = "SessionStart"
        payload["source"] = "startup"
        payload["session_id"] = "x" * 1000
        with self.assertRaisesRegex(CodexBodyError, "hook_session_invalid"):
            run_hook(
                "session-start",
                self.plan.profile_root / "bootstrap.json",
                self.plan.profile_root / "observations.jsonl",
                payload,
                clock=lambda: NOW,
            )
        malicious = self.payload("SessionStart")
        malicious["source"] = "startup"
        malicious["unexpected_environment"] = "LD_PRELOAD=/tmp/attacker"
        with self.assertRaisesRegex(CodexBodyError, "hook_input_schema_drift"):
            run_hook(
                "session-start",
                self.plan.profile_root / "bootstrap.json",
                self.plan.profile_root / "observations.jsonl",
                malicious,
                clock=lambda: NOW,
            )


class JournalAndAdapterTests(CodexBodyFixture):
    def setUp(self) -> None:
        super().setUp()
        self.create()
        self.journal = RuntimeHandleJournal(
            self.plan.profile_root / "runtime-handles.jsonl"
        )

    def responses(
        self, starts: int = 1, resumes: int = 0
    ) -> dict[str, list[Mapping[str, Any]]]:
        return {
            "initialize": [
                {
                    "codexHome": os.fspath(self.plan.profile_root),
                    "platformFamily": "unix",
                    "platformOs": "linux",
                    "userAgent": f"codex_cli_rs/{CODEX_VERSION}",
                }
            ],
            "thread/start": [self.thread_result() for _ in range(starts)],
            "thread/resume": [self.thread_result() for _ in range(resumes)],
            "mcpServerStatus/list": [
                self.mcp_inventory() for _ in range(starts + resumes)
            ],
        }

    def adapter(
        self,
        transport: FakeTransport,
        presence: Callable[[Mapping[str, Any], int], Mapping[str, Any]] | None = None,
    ) -> CodexBodyAdapter:
        return CodexBodyAdapter(
            self.plan,
            transport,
            cast(PresenceVerifier, presence or self.presence),
            self.journal,
            clock=lambda: NOW,
        )

    def test_start_resume_turn_and_park_are_separate_chained_handles(self) -> None:
        transport = FakeTransport(self.responses(starts=1, resumes=1))
        adapter = self.adapter(transport)
        adapter.initialize()
        started = adapter.start()
        launch = create_launch_receipt(
            self.plan, verify_profile(self.plan), started, outcome="started"
        )
        resumed = adapter.resume()
        turn = adapter.record_turn("thread-alpha", "turn-alpha")
        parked = adapter.park()
        self.assertEqual(
            [
                started["generation"],
                resumed["generation"],
                turn["generation"],
                parked["generation"],
            ],
            [1, 3, 4, 5],
        )
        self.assertEqual(started["thread_id"], resumed["thread_id"])
        self.assertEqual(launch["runtime"]["thread_id"], started["thread_id"])
        self.assertNotIn(os.fspath(self.workspace), canonical_bytes(launch).decode())
        self.assertEqual(started["session_tree_id"], resumed["session_tree_id"])
        self.assertNotEqual(started["matrix_session_id"], started["session_tree_id"])
        self.assertEqual(parked["state"], "parked")
        with self.assertRaisesRegex(CodexBodyError, "codex_thread_not_resumable"):
            adapter.resume()
        self.assertEqual(
            [item["state"] for item in self.journal.load()],
            ["starting", "active", "resuming", "active", "active", "parked"],
        )

    def test_response_loss_blocks_blind_duplicate_start(self) -> None:
        class ResponseLoss(FakeTransport):
            def request(
                self, method: str, params: Mapping[str, Any]
            ) -> Mapping[str, Any]:
                if method == "thread/start":
                    self.requests.append((method, copy.deepcopy(dict(params))))
                    raise CodexBodyError("app_server_closed", retryable=True)
                return super().request(method, params)

        transport = ResponseLoss(self.responses())
        adapter = self.adapter(transport)
        adapter.initialize()
        with self.assertRaisesRegex(CodexBodyError, "app_server_closed"):
            adapter.start()
        self.assertEqual(self.journal.load()[-1]["state"], "starting")
        with self.assertRaisesRegex(CodexBodyError, "codex_launch_outcome_unknown"):
            adapter.start()
        self.assertEqual(
            [method for method, _params in transport.requests].count("thread/start"), 1
        )

    def test_presence_allows_high_water_advance_and_refuses_rollback(self) -> None:
        transport = FakeTransport(self.responses(starts=1, resumes=1))
        adapter = self.adapter(transport)
        adapter.initialize()
        started = adapter.start()

        def expired(binding: Mapping[str, Any], at_ms: int) -> Mapping[str, Any]:
            result = dict(self.presence(binding, at_ms))
            result["expires_at_ms"] = NOW
            return result

        expired_adapter = self.adapter(transport, expired)
        expired_adapter.initialized = True
        with self.assertRaisesRegex(CodexBodyError, "matrix_presence_rejected"):
            expired_adapter.resume()

        advanced_high_water = hashlib.sha256(b"advanced-high-water").hexdigest()

        def advanced(binding: Mapping[str, Any], at_ms: int) -> Mapping[str, Any]:
            self.assertEqual(binding["matrix_high_water"], started["matrix_high_water"])
            result = dict(self.presence(binding, at_ms))
            result["matrix_high_water"] = advanced_high_water
            return result

        advanced_adapter = self.adapter(transport, advanced)
        advanced_adapter.initialized = True
        resumed = advanced_adapter.resume()
        self.assertEqual(resumed["matrix_high_water"], advanced_high_water)

        def rollback(binding: Mapping[str, Any], at_ms: int) -> Mapping[str, Any]:
            del at_ms
            self.assertEqual(binding["matrix_high_water"], advanced_high_water)
            raise RuntimeError("Matrix rejected a non-descendant high-water")

        rollback_adapter = self.adapter(transport, rollback)
        rollback_adapter.initialized = True
        with self.assertRaisesRegex(CodexBodyError, "matrix_presence_unavailable"):
            rollback_adapter.resume()

    def test_wrong_mcp_version_extra_tool_and_instruction_source_fail_closed(
        self,
    ) -> None:
        responses = self.responses()
        bad_inventory = copy.deepcopy(self.mcp_inventory())
        bad_inventory["data"][0]["serverInfo"]["version"] = "9.9.9"
        responses["mcpServerStatus/list"] = [bad_inventory]
        adapter = self.adapter(FakeTransport(responses))
        adapter.initialize()
        with self.assertRaisesRegex(CodexBodyError, "matrix_mcp_version_mismatch"):
            adapter.start()

        self.journal = RuntimeHandleJournal(
            self.plan.profile_root / "runtime-handles-tools.jsonl"
        )
        responses = self.responses()
        bad_inventory = copy.deepcopy(self.mcp_inventory())
        bad_inventory["data"][0]["tools"]["generic_shell"] = {
            "name": "generic_shell",
            "inputSchema": {},
        }
        responses["mcpServerStatus/list"] = [bad_inventory]
        adapter = self.adapter(FakeTransport(responses))
        adapter.initialize()
        with self.assertRaisesRegex(
            CodexBodyError, "matrix_mcp_tool_inventory_mismatch"
        ):
            adapter.start()

        self.journal = RuntimeHandleJournal(
            self.plan.profile_root / "runtime-handles-instructions.jsonl"
        )
        responses = self.responses()
        bad_thread = self.thread_result()
        bad_thread["instructionSources"].append("/tmp/untrusted/AGENTS.md")
        responses["thread/start"] = [bad_thread]
        adapter = self.adapter(FakeTransport(responses))
        adapter.initialize()
        with self.assertRaisesRegex(CodexBodyError, "instruction_sources_drift"):
            adapter.start()

    def test_torn_or_tampered_journal_is_not_replayed(self) -> None:
        transport = FakeTransport(self.responses())
        adapter = self.adapter(transport)
        adapter.initialize()
        adapter.start()
        journal_path = self.plan.profile_root / "runtime-handles.jsonl"
        journal_path.write_bytes(journal_path.read_bytes() + b'{"partial":')
        with self.assertRaisesRegex(CodexBodyError, "handle_journal_torn"):
            self.journal.load()


class SubprocessContractTests(CodexBodyFixture):
    def test_missing_capability_descriptor_refuses_before_spawn(self) -> None:
        self.create()
        with (
            self.assertRaisesRegex(
                CodexBodyError, "matrix_capability_descriptor_missing"
            ),
            mock.patch("daimon_matrix.codex_body.subprocess.Popen") as spawn,
        ):
            AppServerProcess(self.plan)
        spawn.assert_not_called()

    def test_fragmented_notification_and_response_are_correlated(self) -> None:
        script = (
            b"""#!/usr/bin/python3
import json, sys, time
"""
            + FAKE_FEATURE_PROBE
            + b"""
for line in sys.stdin:
    request = json.loads(line)
    if request.get("method") == "ping":
        sys.stdout.write('{"method":"warning","params":{"message":"bounded"}}\\n')
        sys.stdout.flush()
        response = json.dumps({"id": request["id"], "result": {"ok": True}}) + "\\n"
        sys.stdout.write(response[:8]); sys.stdout.flush(); time.sleep(0.01)
        sys.stdout.write(response[8:]); sys.stdout.flush()
"""
        )
        self.codex_binary.write_bytes(script)
        self.codex_binary.chmod(0o700)
        patched_hash = hashlib.sha256(script).hexdigest()
        read_fd, write_fd = os.pipe()
        try:
            with mock.patch(
                "daimon_matrix.codex_body.CODEX_BINARY_SHA256", patched_hash
            ):
                value = create_plan_value(
                    bootstrap=self.bootstrap,
                    model="gpt-5.6-terra",
                    provider="openai",
                    workspace_ref=derived("workspace", "workspace-subprocess"),
                )
                plan = self.make_plan(
                    self.profile_parent / "subprocess",
                    value=value,
                    capability_fd=read_fd,
                )
                create_profile(
                    plan,
                    bootstrap_verifier=lambda evidence, at_ms: True,
                    clock=lambda: NOW,
                )
                process = AppServerProcess(plan, pass_fds=(read_fd,))
                try:
                    self.assertEqual(process.request("ping", {}), {"ok": True})
                finally:
                    process.close()
        finally:
            os.close(read_fd)
            os.close(write_fd)

    def test_unknown_notification_is_protocol_drift(self) -> None:
        script = (
            b"""#!/usr/bin/python3
import json, sys
"""
            + FAKE_FEATURE_PROBE
            + b"""
for line in sys.stdin:
    request = json.loads(line)
    sys.stdout.write('{"method":"future/unknown","params":{}}\\n')
    sys.stdout.write(json.dumps({"id": request["id"], "result": {"ok": True}}) + "\\n")
    sys.stdout.flush()
"""
        )
        self.codex_binary.write_bytes(script)
        self.codex_binary.chmod(0o700)
        patched_hash = hashlib.sha256(script).hexdigest()
        read_fd, write_fd = os.pipe()
        try:
            with mock.patch(
                "daimon_matrix.codex_body.CODEX_BINARY_SHA256", patched_hash
            ):
                value = create_plan_value(
                    bootstrap=self.bootstrap,
                    model="gpt-5.6-terra",
                    provider="openai",
                    workspace_ref=derived("workspace", "workspace-drift"),
                )
                plan = self.make_plan(
                    self.profile_parent / "drift",
                    value=value,
                    capability_fd=read_fd,
                )
                create_profile(
                    plan,
                    bootstrap_verifier=lambda evidence, at_ms: True,
                    clock=lambda: NOW,
                )
                process = AppServerProcess(plan, pass_fds=(read_fd,))
                try:
                    with self.assertRaisesRegex(
                        CodexBodyError, "app_server_protocol_drift"
                    ):
                        process.request("ping", {})
                finally:
                    process.close()
        finally:
            os.close(read_fd)
            os.close(write_fd)


class InstalledCodexSmokeTests(unittest.TestCase):
    def test_exact_binary_strict_config_and_feature_state_when_available(self) -> None:
        binary = Path(
            "/home/nicolas/.npm-global/lib/node_modules/@openai/codex/"
            "node_modules/@openai/codex-linux-x64/vendor/"
            "x86_64-unknown-linux-musl/bin/codex"
        )
        if not binary.exists():
            self.skipTest("pinned private Codex binary is not installed")
        if hashlib.sha256(binary.read_bytes()).hexdigest() != CODEX_BINARY_SHA256:
            self.skipTest(
                "installed Codex binary is outside the pinned DM-040 contract"
            )
        version = subprocess.run(
            [binary, "--version"], check=True, capture_output=True, text=True
        )
        self.assertEqual(version.stdout.strip(), f"codex-cli {CODEX_VERSION}")
        with tempfile.TemporaryDirectory(prefix="dm040-real-config-") as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            workspace = root / "workspace"
            workspace.mkdir(mode=0o700)
            profiles = root / "profiles"
            profiles.mkdir(mode=0o700)
            fake_codex = root / "codex"
            fake_codex.write_text("#!/bin/sh\nexit 0\n")
            fake_codex.chmod(0o700)
            fake_mcp = root / "daimon-mcp"
            fake_mcp.write_text("#!/bin/sh\nexit 2\n")
            fake_mcp.chmod(0o700)
            fake_hash = hashlib.sha256(fake_codex.read_bytes()).hexdigest()
            evidence = bootstrap("real-config")
            with mock.patch("daimon_matrix.codex_body.CODEX_BINARY_SHA256", fake_hash):
                value = create_plan_value(
                    bootstrap=evidence,
                    model="gpt-5.6-terra",
                    provider="openai",
                    workspace_ref=derived("workspace", "real-config"),
                )
                plan = bind_plan(
                    value,
                    profile_root=profiles / "body",
                    workspace=workspace,
                    codex_binary=fake_codex,
                    mcp_binary=fake_mcp,
                    mcp_args=(
                        "--socket",
                        os.fspath(root / "matrix.sock"),
                        "--client-config",
                        os.fspath(root / "client.json"),
                        "--capability-key-fd",
                        "7",
                        "--request-dir",
                        os.fspath(root / "requests"),
                    ),
                    hook_python=Path("/usr/bin/python3").resolve(),
                )
                create_profile(
                    plan,
                    bootstrap_verifier=lambda value, at_ms: (
                        value == evidence and at_ms == NOW
                    ),
                    clock=lambda: NOW,
                )
            environment = {
                "CODEX_HOME": os.fspath(plan.profile_root),
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "PATH": "/usr/bin:/bin",
            }
            process = subprocess.Popen(
                [binary, "--strict-config", "app-server", "--stdio"],
                cwd=workspace,
                env=environment,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
            assert process.stdin is not None
            assert process.stdout is not None
            try:
                process.stdin.write(
                    canonical_bytes(
                        {
                            "method": "initialize",
                            "id": 1,
                            "params": {
                                "clientInfo": {
                                    "name": "daimon_matrix_test",
                                    "version": "1.0.0",
                                }
                            },
                        }
                    )
                    + b"\n"
                )
                process.stdin.flush()
                ready, _, _ = select.select([process.stdout], [], [], 10)
                self.assertTrue(ready, "real App Server did not initialize")
                response = json.loads(process.stdout.readline())
                self.assertEqual(response["id"], 1)
                self.assertEqual(
                    response["result"]["codexHome"], os.fspath(plan.profile_root)
                )
                self.assertIn(CODEX_VERSION, response["result"]["userAgent"])
            finally:
                process.stdin.close()
                process.terminate()
                process.wait(timeout=10)
                process.stdout.close()
            features = subprocess.run(
                [binary, "features", "list"],
                cwd=workspace,
                env=environment,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.splitlines()
            state = {line.split()[0]: line.split()[-1] for line in features if line}
            for name in (
                "apps",
                "browser_use",
                "chronicle",
                "computer_use",
                "external_agent_memory_import",
                "memories",
                "multi_agent",
                "plugins",
            ):
                self.assertEqual(state[name], "false")
            self.assertEqual(state["hooks"], "true")


class PrivateRealCodexMatrixSmokeTests(RuntimeFixture):
    """Opt-in exact Codex ↔ synthetic Matrix runtime start/write/restart smoke."""

    def setUp(self) -> None:
        if os.environ.get("DAIMON_DM040_REAL_BODY_SMOKE") != "1":
            self.skipTest("set DAIMON_DM040_REAL_BODY_SMOKE=1 for private smoke")
        configured = os.environ.get("DAIMON_DM040_CODEX_BINARY")
        self.installed_codex = Path(
            configured
            or (
                "/home/nicolas/.npm-global/lib/node_modules/@openai/codex/"
                "node_modules/@openai/codex-linux-x64/vendor/"
                "x86_64-unknown-linux-musl/bin/codex"
            )
        )
        if not self.installed_codex.is_file():
            self.skipTest("pinned private Codex binary is not installed")
        if hashlib.sha256(self.installed_codex.read_bytes()).hexdigest() != (
            CODEX_BINARY_SHA256
        ):
            self.skipTest("private Codex binary is outside the pinned contract")
        super().setUp()

        self.state_root, _, self.capability, self.now_ms = self.make_process_bundle()
        self.runtime = load_runtime(
            self.state_root,
            "runtime.json",
            lambda: bytearray(PASSWORD),
            clock=lambda: time.time_ns() // 1_000_000,
        )
        self.stop = threading.Event()
        self.thread = threading.Thread(
            target=serve_forever,
            kwargs={"runtime": self.runtime, "stop": self.stop},
            daemon=True,
        )
        self.thread.start()
        for _ in range(100):
            if self.runtime.socket_path.exists():
                break
            time.sleep(0.01)
        if not self.runtime.socket_path.exists():
            self.fail("synthetic Matrix daemon did not start")
        self.config_path = self.state_root / "client.json"
        self.config_path.write_bytes(
            canonical_bytes(
                {
                    "schema": CLIENT_CONFIG_SCHEMA,
                    "capability": self.capability.descriptor,
                    "expected_server": self.origins["legion"],
                }
            )
        )
        self.config_path.chmod(0o600)
        self.request_dir = self.state_root / "requests"
        self.request_dir.mkdir(mode=0o700)

    def tearDown(self) -> None:
        self.stop.set()
        self.thread.join(timeout=3)
        super().tearDown()

    def _high_water(self) -> str:
        event_ids = [
            event["event_id"] for event in self.runtime.service.ledger.events()
        ]
        return hashlib.sha256(canonical_bytes(event_ids)).hexdigest()

    def _ref(self, kind: str, source: str) -> str:
        return f"dm:{kind}:v1:" + b64url(hashlib.sha256(source.encode()).digest())

    def _load_capability(self, descriptor: int) -> None:
        read_descriptor, write_descriptor = os.pipe()
        if read_descriptor != descriptor:
            os.dup2(read_descriptor, descriptor, inheritable=True)
            os.close(read_descriptor)
        else:
            os.set_inheritable(descriptor, True)
        os.write(write_descriptor, self.capability.key)
        os.close(write_descriptor)

    def test_real_start_projection_write_and_restart(self) -> None:
        root = self.root_path / "codex-body"
        root.mkdir(mode=0o700)
        workspace = root / "workspace"
        workspace.mkdir(mode=0o700)
        profiles = root / "profiles"
        profiles.mkdir(mode=0o700)
        codex_binary = root / "codex"
        shutil.copyfile(self.installed_codex, codex_binary)
        codex_binary.chmod(0o700)
        mcp_binary = root / "daimon-mcp"
        mcp_binary.write_text(
            f"#!{sys.executable}\n"
            "import sys\n"
            f"sys.path.insert(0, {str(ROOT / 'src')!r})\n"
            "from daimon_matrix.mcp_server import main\n"
            "raise SystemExit(main())\n"
        )
        mcp_binary.chmod(0o700)

        initial_high_water = self._high_water()
        origin = self.origins["legion"]
        evidence = {
            "schema": BOOTSTRAP_SCHEMA,
            "being_ref": self.state.being_ref,
            "body_ref": self._ref("body", origin["body_ref"]),
            "embodiment_id": self._ref("embodiment", origin["embodiment_id"]),
            "incarnation_id": self._ref("incarnation", origin["incarnation_id"]),
            "matrix_session_id": self._ref("session", "dm040-private-smoke"),
            "matrix_high_water": initial_high_water,
            "capability_set_hash": hashlib.sha256(
                canonical_bytes(self.capability.descriptor)
            ).hexdigest(),
            "certificate_hash": hashlib.sha256(
                canonical_bytes(self.credentials)
            ).hexdigest(),
            "issued_at_ms": self.now_ms - 1_000,
            "expires_at_ms": self.now_ms + 60_000,
            "signature": {
                "alg": "Ed25519",
                "kid": self._ref("key", "dm040-private-smoke"),
                "value": b64url(bytes(range(64))),
            },
        }
        plan_value = create_plan_value(
            bootstrap=evidence,
            model="gpt-5.6-terra",
            provider="openai",
            workspace_ref=self._ref("workspace", "dm040-private-smoke"),
        )
        first_read, first_write = os.pipe()
        capability_fd = first_read
        os.write(first_write, self.capability.key)
        os.close(first_write)
        plan = bind_plan(
            plan_value,
            profile_root=profiles / "body",
            workspace=workspace,
            codex_binary=codex_binary,
            mcp_binary=mcp_binary,
            mcp_args=(
                "--socket",
                os.fspath(self.runtime.socket_path),
                "--client-config",
                os.fspath(self.config_path),
                "--capability-key-fd",
                str(capability_fd),
                "--request-dir",
                os.fspath(self.request_dir),
            ),
            hook_python=Path("/usr/bin/python3").resolve(),
        )
        manifest = create_profile(
            plan,
            bootstrap_verifier=lambda value, at_ms: (
                value == evidence and at_ms == self.now_ms
            ),
            clock=lambda: self.now_ms,
        )
        accepted_high_water = initial_high_water

        def presence(binding: Mapping[str, Any], at_ms: int) -> Mapping[str, Any]:
            nonlocal accepted_high_water
            if binding["matrix_high_water"] != accepted_high_water:
                raise RuntimeError("Matrix high-water is not the accepted ancestor")
            accepted_high_water = self._high_water()
            return {
                "body_ref": binding["body_ref"],
                "embodiment_id": binding["embodiment_id"],
                "incarnation_id": binding["incarnation_id"],
                "matrix_session_id": binding["matrix_session_id"],
                "matrix_high_water": accepted_high_water,
                "state": "active",
                "expires_at_ms": at_ms + 60_000,
            }

        journal = RuntimeHandleJournal(plan.profile_root / "runtime-handles.jsonl")
        process = AppServerProcess(plan, pass_fds=(capability_fd,))
        try:
            adapter = CodexBodyAdapter(
                plan,
                process,
                presence,
                journal,
                clock=lambda: self.now_ms,
            )
            adapter.initialize()
            started = adapter.start()
            projection = process.request(
                "mcpServer/tool/call",
                {
                    "threadId": started["thread_id"],
                    "server": "matrix",
                    "tool": "we_projection_get",
                    "arguments": {},
                },
            )
            self.assertFalse(projection.get("isError", False))
            self.assertTrue(
                cast(Mapping[str, Any], projection["structuredContent"])["ok"]
            )
            observation = process.request(
                "mcpServer/tool/call",
                {
                    "threadId": started["thread_id"],
                    "server": "matrix",
                    "tool": "we_observe",
                    "arguments": {
                        "operation_id": "70000000-0000-4000-8000-000000000040",
                        "subject": "dm040-private-smoke",
                        "payload": {"kind": "synthetic-codex-body-smoke"},
                    },
                },
            )
            self.assertFalse(observation.get("isError", False))
            observed = cast(Mapping[str, Any], observation["structuredContent"])
            self.assertTrue(observed["ok"])
            self.assertEqual(
                cast(Mapping[str, Any], observed["result"])["schema"],
                "dm.we.observe-result/v1",
            )
            self.assertEqual(
                observed["request_id"], "70000000-0000-4000-8000-000000000040"
            )
            self.assertEqual(len(self.runtime.service.ledger.events()), 1)
            self.assertEqual(
                process.request(
                    "thread/name/set",
                    {"threadId": started["thread_id"], "name": "dm040-smoke"},
                ),
                {},
            )
        finally:
            process.close()
            os.close(capability_fd)

        self._load_capability(capability_fd)
        restarted = AppServerProcess(plan, pass_fds=(capability_fd,))
        try:
            adapter = CodexBodyAdapter(
                plan,
                restarted,
                presence,
                journal,
                clock=lambda: self.now_ms,
            )
            adapter.initialize()
            resumed = adapter.resume()
            self.assertEqual(resumed["thread_id"], started["thread_id"])
            self.assertEqual(resumed["matrix_high_water"], self._high_water())
            self.assertEqual(adapter.park()["state"], "parked")
        finally:
            restarted.close()
            os.close(capability_fd)
        self.assertEqual(verify_profile(plan), manifest)
        self.assertFalse(
            any(
                (plan.profile_root / name).exists()
                for name in ("memories", "auth.json")
            )
        )


if __name__ == "__main__":
    unittest.main()
