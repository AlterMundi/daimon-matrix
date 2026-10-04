"""Exact-release admission boundaries for the Codex successor."""

from __future__ import annotations

import copy
import hashlib
import importlib
import json
import os
import subprocess
import sys
import tempfile
import tomllib
import unittest
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
from typing import Any
from unittest import mock
from urllib.parse import urljoin

from jsonschema import Draft202012Validator  # type: ignore[import-untyped]
from referencing import Registry, Resource

from daimon_matrix import codex_body as body
from daimon_matrix.canonical import b64url, canonical_bytes
from daimon_matrix.codex_body import CodexBodyError, verify_compatibility_bundle


class ReleaseAdmissionTests(unittest.TestCase):
    def test_native_duration_exception_requires_exact_correlated_reply(self) -> None:
        frame: dict[str, Any] = {
            "id": 7,
            "result": {
                "config": {
                    "mcp_servers": {
                        "matrix": {
                            "startup_timeout_sec": 10.0,
                            "tool_timeout_sec": 30.0,
                        }
                    }
                }
            },
        }
        raw = json.dumps(frame).encode()
        normalized = body._native_configuration_frame(raw, 7)
        self.assertIs(
            type(
                normalized["result"]["config"]["mcp_servers"]["matrix"][
                    "startup_timeout_sec"
                ]
            ),
            int,
        )
        with self.assertRaises(CodexBodyError):
            body._json_load(raw, "canonical_fixture")
        for change in (
            "foreign",
            "boolean",
            "duration",
            "unknown",
            "notification",
            "nan",
        ):
            bad = copy.deepcopy(frame)
            if change == "foreign":
                bad["id"] = 8
            elif change == "boolean":
                bad["id"] = True
            elif change == "duration":
                bad["result"]["config"]["mcp_servers"]["matrix"]["tool_timeout_sec"] = (
                    30.5
                )
            elif change == "unknown":
                bad["result"]["config"]["unreviewed"] = 1.0
            elif change == "notification":
                bad.pop("id")
                bad["method"] = "synthetic"
            else:
                bad["result"]["config"]["mcp_servers"]["matrix"]["tool_timeout_sec"] = (
                    float("nan")
                )
            with self.subTest(change=change), self.assertRaises(CodexBodyError):
                body._native_configuration_frame(json.dumps(bad).encode(), 7)
        with self.assertRaises(CodexBodyError):
            body._native_configuration_frame(b'{"id":7,"id":7,"result":{}}', 7)

    def test_successor_adoption_keeps_incomplete_controls_refused(self) -> None:
        from tests.test_dm074_harness_conformance import FIXTURE

        checker = importlib.import_module("checker")

        root = Path(__file__).resolve().parents[1]
        directory = root / "vectors/codex/v2/adoption"
        candidate = json.loads((directory / "profile.json").read_bytes())
        schema = json.loads(
            (root / "schemas/harness/v0/profile.schema.json").read_bytes()
        )
        Draft202012Validator(schema).validate(candidate)
        checker.validate_profile(candidate)
        report = json.loads((directory / "report.json").read_bytes())
        self.assertEqual(
            checker.conformance_report(candidate, checker.load_fixture(FIXTURE)), report
        )
        self.assertEqual(candidate["evidence_state"], "documented-candidate")
        self.assertEqual(candidate["admission"]["expected"], "refused")
        self.assertEqual(candidate["launch"]["status"], "reference-only")
        for control in (
            "instruction_precedence_audited",
            "history_persistence_disabled",
            "native_memory_disabled",
        ):
            self.assertEqual(candidate["controls"][control]["state"], "unknown")
        sources = json.loads((directory / "sources.json").read_bytes())["sources"]
        source_ids = {source["source_id"] for source in sources}
        self.assertEqual(set(candidate["harness"]["source_refs"]), source_ids)
        self.assertTrue(
            all(
                set(control["evidence"]) <= source_ids
                for control in candidate["controls"].values()
            )
        )

    def test_frozen_successor_vectors_match_closed_schema_and_runtime_validators(
        self,
    ) -> None:
        root = Path(__file__).resolve().parents[1]
        schema = json.loads(
            (root / "schemas/codex/v2/contracts.schema.json").read_bytes()
        )
        Draft202012Validator.check_schema(schema)
        registry: Registry[Any] = Registry().with_resource(
            schema["$id"], Resource.from_contents(schema)
        )
        for relative, name in (
            ("../v1/contracts.schema.json", "schemas/codex/v1/contracts.schema.json"),
            ("../../weave/v1/event.schema.json", "schemas/weave/v1/event.schema.json"),
        ):
            referenced = json.loads((root / name).read_bytes())
            resource = Resource.from_contents(referenced)
            registry = registry.with_resource(
                urljoin(schema["$id"], relative), resource
            )
            registry = registry.with_resource(referenced["$id"], resource)
        validator = Draft202012Validator(schema, registry=registry)
        vectors = root / "vectors/codex/v2"
        index = json.loads((vectors / "index.json").read_bytes())
        validators = {
            "valid/bootstrap.json": body.validate_bootstrap,
            "valid/plan.json": body.validate_plan,
            "valid/continuity-plan.json": body.validate_plan,
            "valid/parking-handle.json": body.validate_runtime_handle,
            "valid/turning-handle.json": body.validate_runtime_handle,
            "valid/turn-intent.json": body.validate_turn_intent,
            "valid/turn-result.json": body.validate_native_turn_result,
            "valid/launch-receipt.json": body.validate_launch_receipt,
        }
        for row in index["files"]:
            raw = (vectors / row["name"]).read_bytes()
            self.assertEqual(hashlib.sha256(raw).hexdigest(), row["sha256"])
            value = json.loads(raw)
            with self.subTest(vector=row["name"]):
                if row["valid"]:
                    validator.validate(value)
                    runtime_validator = validators.get(row["name"])
                    if runtime_validator is not None:
                        runtime_validator(value)
                else:
                    self.assertFalse(validator.is_valid(value))
                    with self.assertRaises(CodexBodyError):
                        body.validate_plan(value)

    def test_native_error_notification_is_data_and_preserves_historical_inventory(
        self,
    ) -> None:
        event: dict[str, Any] = {
            "method": "error",
            "params": {
                "error": {"message": "Synthetic provider failure"},
                "threadId": "synthetic-thread",
                "turnId": "synthetic-turn",
                "willRetry": False,
            },
        }
        self.assertEqual(
            body._validate_notification(event, allow_hooks=False)[0], "error"
        )
        with self.assertRaises(CodexBodyError):
            body._validate_notification(event)
        for bad in (1, None, "true"):
            changed = copy.deepcopy(event)
            changed["params"]["willRetry"] = bad
            with self.assertRaises(CodexBodyError):
                body._validate_notification(changed, allow_hooks=False)

    def test_unknown_release_refuses_before_artifact_access(self) -> None:
        with tempfile.TemporaryDirectory(prefix="codex-release-") as directory:
            root = Path(directory)
            for version in ("latest", "0.155", "0.155.2", "0.146.1", ""):
                with self.subTest(version=version):
                    with self.assertRaises(CodexBodyError) as refused:
                        verify_compatibility_bundle(
                            root / "absent-binary",
                            root / "absent-json",
                            root / "absent-typescript",
                            release=version,
                        )
                    self.assertEqual(
                        refused.exception.code, "codex_release_unsupported"
                    )
            self.assertEqual(list(root.iterdir()), [])

    def test_known_releases_never_execute_an_unpinned_artifact(self) -> None:
        with tempfile.TemporaryDirectory(prefix="codex-release-") as directory:
            root = Path(directory)
            marker = root / "executed"
            binary = root / "codex"
            # Actual executable I/O seam: accepting this file would create a marker.
            binary.write_text(f"#!/bin/sh\ntouch '{marker}'\necho codex-cli 0.155.1\n")
            binary.chmod(0o700)
            for version in ("0.146.0", "0.155.1"):
                with self.subTest(version=version):
                    with self.assertRaises(CodexBodyError) as refused:
                        verify_compatibility_bundle(
                            binary, root / "json", root / "typescript", release=version
                        )
                    self.assertEqual(
                        refused.exception.code, "codex_binary_hash_mismatch"
                    )
                    self.assertFalse(marker.exists())


class SuccessorProfileTests(unittest.TestCase):
    """Profile I/O with synthetic authority; native lifecycle is a separate gate."""

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="codex-successor-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir(mode=0o700)
        self.profiles = self.root / "profiles"
        self.profiles.mkdir(mode=0o700)
        self.binary = self.root / "native"
        self.binary.write_bytes(b"#!/bin/sh\nexit 0\n")
        self.binary.chmod(0o700)
        pin = replace(
            body.SUCCESSOR_RELEASE,
            binary_sha256=hashlib.sha256(self.binary.read_bytes()).hexdigest(),
        )
        patch = mock.patch.object(body, "SUCCESSOR_RELEASE", pin)
        patch.start()
        self.addCleanup(patch.stop)

        def identifier(kind: str) -> str:
            return f"dm:{kind}:v1:" + b64url(hashlib.sha256(kind.encode()).digest())

        self.now = 1_800_000_000_000
        self.bootstrap: dict[str, Any] = {
            "schema": body.BOOTSTRAP_SCHEMA,
            "being_ref": identifier("being"),
            "body_ref": "cluster:synthetic:successor",
            "embodiment_id": "embodiment:synthetic:successor",
            "incarnation_id": "incarnation:synthetic:successor:0",
            "matrix_session_id": identifier("session"),
            "matrix_high_water": "a" * 64,
            "capability_set_hash": "b" * 64,
            "certificate_hash": "c" * 64,
            "issued_at_ms": self.now - 1000,
            "expires_at_ms": self.now + 60_000,
            "signature": {
                "alg": "Ed25519",
                "kid": identifier("key"),
                "value": b64url(bytes(range(64))),
            },
        }
        self.value = body.create_plan_value(
            bootstrap=self.bootstrap,
            model="dm_probe",
            provider="dm_probe",
            workspace_ref=identifier("workspace"),
            release="0.155.1",
        )
        self.plan = body.bind_plan(
            self.value,
            profile_root=self.profiles / "successor",
            workspace=self.workspace,
            codex_binary=self.binary,
            mcp_binary=self.binary,
            mcp_args=(
                "--socket",
                os.fspath(self.root / "matrix.sock"),
                "--client-config",
                os.fspath(self.root / "client.json"),
                "--capability-key-fd",
                "7",
                "--request-dir",
                os.fspath(self.root / "requests"),
            ),
        )

    def selected_skills(self) -> body.CodexBodyPlan:
        source = self.root / "selected-skills"
        source.mkdir(mode=0o700)
        payloads = {
            "memory/SKILL.md": (
                b"---\nname: memory\ndescription: Explicit recall fixture\n---\n"
            ),
            "memory/references/SKILL.md": b"Auxiliary document\n",
            "memory/librarian/SKILL.md": (
                b"---\nname: librarian\ndescription: Nested skill fixture\n---\n"
            ),
            "memory/scripts/recall.py": b"print('fixture')\n",
        }
        for name, raw in payloads.items():
            target = source / name
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            target.write_bytes(raw)
            target.chmod(0o700 if name.endswith(".py") else 0o600)
        packages = []
        for root in ("memory", "memory/librarian"):
            files = sorted(
                [
                    dict(
                        path=name[len(root) + 1 :],
                        sha256=hashlib.sha256(raw).hexdigest(),
                        bytes=len(raw),
                        executable=name.endswith(".py"),
                    )
                    for name, raw in payloads.items()
                    if name.startswith(root + "/")
                ],
                key=lambda entry: str(entry["path"]),
            )
            packages.append(
                dict(
                    path=root,
                    sha256=hashlib.sha256(canonical_bytes(files)).hexdigest(),
                    files=files,
                )
            )
        value = copy.deepcopy(self.value)
        value["skill_packages"] = body.validate_skill_packages(
            dict(schema="dm.codex-skill-packages/v1", packages=packages)
        )
        return replace(self.plan, value=value, skill_source=source)

    def test_selected_skills_are_manifest_bound_and_source_independent(self) -> None:
        self.plan = self.selected_skills()
        manifest = self.create()
        projected = self.plan.profile_root / ".agents/skills"
        self.assertTrue((projected / "memory/scripts/recall.py").stat().st_mode & 0o100)
        names = {entry["name"] for entry in manifest["files"]}
        self.assertIn(".agents/skills/memory/librarian/SKILL.md", names)
        config = tomllib.loads(body.render_config(self.plan).decode())
        self.assertEqual(
            config["skills"]["config"],
            [dict(path=str(projected / "memory/references/SKILL.md"), enabled=False)],
        )
        self.assertEqual(
            body.verify_profile(replace(self.plan, skill_source=None)), manifest
        )
        assert self.plan.skill_source is not None
        (self.plan.skill_source / "memory/SKILL.md").write_text("Source evolved later")
        self.assertEqual(body.verify_profile(self.plan), manifest)
        body._validate_native_configuration(dict(config=config, origins={}), self.plan)
        config["skills"]["config"][0]["enabled"] = True
        with self.assertRaisesRegex(CodexBodyError, "native_configuration_drift"):
            body._validate_native_configuration(
                dict(config=config, origins={}), self.plan
            )

    def test_selected_skills_refuse_source_drift_before_creating_profile(self) -> None:
        self.plan = self.selected_skills()
        assert self.plan.skill_source is not None
        (self.plan.skill_source / "memory/SKILL.md").write_text("Changed")
        with self.assertRaisesRegex(CodexBodyError, "skill_source_drift"):
            self.create()
        self.assertFalse(self.plan.profile_root.exists())

    def test_selected_skills_refuse_added_changed_missing_or_linked_files(self) -> None:
        self.plan = self.selected_skills()
        self.create()
        root = self.plan.profile_root / ".agents/skills"
        extra = root / "extra/SKILL.md"
        extra.parent.mkdir(mode=0o700)
        extra.write_bytes(b"extra")
        extra.chmod(0o600)
        with self.assertRaisesRegex(CodexBodyError, "skill_surface_drift"):
            body.verify_profile(self.plan)
        extra.unlink()
        target = root / "memory/SKILL.md"
        original = target.read_bytes()
        target.write_bytes(b"changed")
        with self.assertRaisesRegex(CodexBodyError, "skill_file_drift"):
            body.verify_profile(self.plan)
        target.unlink()
        with self.assertRaisesRegex(CodexBodyError, "skill_file_rejected"):
            body.verify_profile(self.plan)
        assert self.plan.skill_source is not None
        target.symlink_to(self.plan.skill_source / "memory/SKILL.md")
        with self.assertRaisesRegex(CodexBodyError, "skill_file_rejected"):
            body.verify_profile(self.plan)
        target.unlink()
        target.write_bytes(original)
        target.chmod(0o600)
        body.verify_profile(self.plan)

    def test_skill_inventory_refuses_traversal_overlap_digest_and_historical_replay(
        self,
    ) -> None:
        plan = self.selected_skills()
        inventory = plan.value["skill_packages"]
        schema = importlib.import_module(
            "tools.generate_codex_0155_vectors"
        ).contracts_schema()
        Draft202012Validator(
            schema["$defs"]["plan"]["properties"]["skill_packages"]
        ).validate(inventory)
        for edit in ("path", "digest", "overlap"):
            changed = copy.deepcopy(inventory)
            if edit == "path":
                changed["packages"][0]["path"] = "../escape"
            elif edit == "digest":
                changed["packages"][0]["sha256"] = "0" * 64
            else:
                changed["packages"][1]["files"][0]["executable"] = True
            with self.assertRaises(CodexBodyError):
                body.validate_skill_packages(changed)
        historical = dict(copy.deepcopy(plan.value))
        historical.update(schema=body.PLAN_SCHEMA, adapter_version="1.0.0")
        with self.assertRaisesRegex(
            CodexBodyError, "historical_codex_skills_forbidden"
        ):
            body.validate_plan(historical)

    def create(self) -> dict[str, Any]:
        return body.create_profile(
            self.plan, bootstrap_verifier=lambda *_: True, clock=lambda: self.now
        )

    def test_profile_has_no_automatic_hook_surface(self) -> None:
        manifest = self.create()
        self.assertEqual(
            {p.name for p in self.plan.profile_root.iterdir()},
            {"AGENTS.md", "bootstrap.json", "config.toml", "profile-manifest.json"},
        )
        config = tomllib.loads((self.plan.profile_root / "config.toml").read_text())
        self.assertFalse(config["features"]["hooks"])
        self.assertNotIn("hooks", config)
        self.assertIsNone(self.plan.hook_python)
        self.assertNotIn("hook_python_sha256", manifest)
        self.assertEqual(manifest["lifecycle"], "human-request-only")
        self.assertEqual(body.verify_profile(self.plan), manifest)

    def test_effective_configuration_requires_owned_controls_and_strict_types(
        self,
    ) -> None:
        expected = tomllib.loads(body.render_config(self.plan).decode())
        response: dict[str, Any] = {"config": expected, "origins": {}, "layers": None}
        expected["history"]["max_bytes"] = 12345
        body._validate_native_configuration(response, self.plan)
        # The pinned binary emits null for an unconfigured skills table.
        # It does not authorize an unexpected selected skill or malformed table.
        native_default = copy.deepcopy(response)
        native_default["config"]["skills"] = None
        body._validate_native_configuration(native_default, self.plan)
        for field, value in (
            ("approval_policy", "never"),
            ("sandbox_mode", "danger-full-access"),
            ("features", {"hooks": True}),
            ("history", {"persistence": "save-all"}),
            ("memories", {"generate_memories": True}),
            ("otel", {"exporter": "synthetic"}),
            ("projects", {}),
            ("developer_instructions", "synthetic override"),
            ("hooks", {}),
            ("notify", ["/bin/true"]),
            ("model_instructions_file", "/synthetic/instructions.txt"),
            ("experimental_compact_prompt_file", "/synthetic/compact.txt"),
            ("skills", []),
            ("skills", {"config": [{"path": "/unselected", "enabled": True}]}),
        ):
            changed = copy.deepcopy(response)
            changed["config"][field] = value
            with self.subTest(field=field), self.assertRaises(CodexBodyError):
                body._validate_native_configuration(changed, self.plan)
        changed = copy.deepcopy(response)
        changed["config"]["analytics"]["enabled"] = 0
        with self.assertRaises(CodexBodyError):
            body._validate_native_configuration(changed, self.plan)
        for table in ("mcp_servers", "projects"):
            changed = copy.deepcopy(response)
            changed["config"][table]["unexpected"] = {}
            with self.subTest(table=table), self.assertRaises(CodexBodyError):
                body._validate_native_configuration(changed, self.plan)

    def test_native_profile_lock_is_exclusive_and_released_by_descriptor_close(
        self,
    ) -> None:
        self.create()
        original = {
            path.name: path.read_bytes() for path in self.plan.profile_root.iterdir()
        }
        descriptor = body._acquire_native_profile_lock(self.plan)
        try:
            with self.assertRaises(CodexBodyError) as refused:
                body._acquire_native_profile_lock(self.plan)
            self.assertEqual(refused.exception.code, "codex_profile_in_use")
            self.assertTrue(refused.exception.retryable)
        finally:
            os.close(descriptor)
        reopened = body._acquire_native_profile_lock(self.plan)
        os.close(reopened)
        self.assertEqual(
            {path.name: path.read_bytes() for path in self.plan.profile_root.iterdir()},
            original,
        )

    def test_reintroduced_hook_file_is_refused(self) -> None:
        self.create()
        forbidden = self.plan.profile_root / "hooks.json"
        forbidden.write_bytes(b"{}\n")
        forbidden.chmod(0o600)
        with self.assertRaises(CodexBodyError) as refused:
            body.verify_profile(self.plan)
        self.assertEqual(refused.exception.code, "codex_automatic_hooks_forbidden")
        self.assertTrue(forbidden.exists())

    def test_changed_binding_during_authority_check_creates_no_profile(self) -> None:
        def authority_check(evidence: Mapping[str, Any], at_ms: int) -> bool:
            self.plan.value["bootstrap"]["matrix_high_water"] = "d" * 64
            return True

        with self.assertRaises(CodexBodyError) as refused:
            body.create_profile(
                self.plan, bootstrap_verifier=authority_check, clock=lambda: self.now
            )
        self.assertEqual(
            refused.exception.code, "codex_plan_changed_during_verification"
        )
        self.assertFalse(self.plan.profile_root.exists())

    def test_successor_does_not_inherit_noninteractive_approval_override(self) -> None:
        with self.assertRaises(CodexBodyError) as refused:
            body.build_ephemeral_argv(self.plan)
        self.assertEqual(refused.exception.code, "successor_requires_app_server")
        self.assertFalse(self.plan.profile_root.exists())

    def thread_response(self) -> dict[str, Any]:
        return {
            "approvalPolicy": "on-request",
            "approvalsReviewer": "user",
            "cwd": os.fspath(self.workspace),
            "model": "dm_probe",
            "modelProvider": "dm_probe",
            "multiAgentMode": "explicitRequestOnly",
            "runtimeWorkspaceRoots": [os.fspath(self.workspace)],
            "sandbox": {
                "type": "workspaceWrite",
                "writableRoots": [],
                "networkAccess": False,
                "excludeTmpdirEnvVar": False,
                "excludeSlashTmp": False,
            },
            "thread": {
                "id": "native-thread",
                "sessionId": "native-session",
                "cliVersion": "0.155.1",
                "modelProvider": "dm_probe",
            },
            "instructionSources": [os.fspath(self.plan.profile_root / "AGENTS.md")],
        }

    def test_successor_refuses_effective_sandbox_or_reviewer_drift(self) -> None:
        valid = self.thread_response()
        self.assertEqual(body._thread_result(valid, self.plan)[0], "native-thread")
        for field, replacement in (
            ("networkAccess", True),
            ("writableRoots", [os.fspath(self.root)]),
            ("type", "dangerFullAccess"),
        ):
            with self.subTest(field=field):
                changed = copy.deepcopy(valid)
                changed["sandbox"][field] = replacement
                with self.assertRaises(CodexBodyError) as refused:
                    body._thread_result(changed, self.plan)
                self.assertEqual(refused.exception.code, "app_server_policy_drift")
        changed = copy.deepcopy(valid)
        changed["approvalsReviewer"] = "guardian_subagent"
        with self.assertRaises(CodexBodyError):
            body._thread_result(changed, self.plan)

    def test_native_metadata_resume_accepts_opaque_cursors_without_hydrating_history(
        self,
    ) -> None:
        response = self.thread_response()
        response.update(
            initialTurnsPage=None,
            itemsBackwardsCursor="opaque-item-cursor",
            turnsBackwardsCursor="opaque-turn-cursor",
        )
        self.assertEqual(
            body._thread_result(response, self.plan)[:2],
            ("native-thread", "native-session"),
        )
        bad_values: tuple[Any, ...] = (True, 1, {}, "x" * 8193)
        for bad in bad_values:
            changed = copy.deepcopy(response)
            changed["turnsBackwardsCursor"] = bad
            with self.assertRaises(CodexBodyError):
                body._thread_result(changed, self.plan)
        response["initialTurnsPage"] = {"turns": []}
        with self.assertRaises(CodexBodyError):
            body._thread_result(response, self.plan)

    def test_successor_requires_full_mcp_inventory_and_refuses_hook_notifications(
        self,
    ) -> None:
        empty = {
            "data": [
                {
                    "name": "matrix",
                    "authStatus": "notLoggedIn",
                    "resourceTemplates": [],
                    "resources": [],
                    "tools": {},
                }
            ]
        }
        with self.assertRaises(CodexBodyError) as refused:
            body._verify_matrix_mcp(empty, require_tools=True)
        self.assertEqual(refused.exception.code, "matrix_mcp_tool_inventory_mismatch")
        complete = copy.deepcopy(empty)
        complete["data"][0]["tools"] = {
            name: {"name": name} for name in body.MATRIX_TOOLS
        }
        body._verify_matrix_mcp(complete, require_tools=True)
        with self.assertRaises(CodexBodyError) as refused:
            body._validate_notification(
                {"method": "hook/started", "params": {}}, allow_hooks=False
            )
        self.assertEqual(refused.exception.code, "codex_automatic_hooks_forbidden")

    def test_successor_mcp_status_and_resources_are_closed(self) -> None:
        server: dict[str, Any] = {
            "name": "matrix",
            "authStatus": "unsupported",
            "runtimeStatus": "connected",
            "pluginId": None,
            "toolsError": None,
            "serverInfo": {"name": "daimon-matrix", "version": "0.1.0rc1"},
            "resourceTemplates": [],
            "resources": [
                {"uri": uri, "mimeType": "application/vnd.daimon-matrix+json"}
                for uri in (
                    "daimon:contract/server",
                    "daimon:contract/tools",
                    "daimon:contract/local-api",
                    "daimon:runtime/status",
                    "daimon:scope/me",
                    "daimon:scope/we",
                    "daimon:we/heads",
                    "daimon:we/projection",
                )
            ],
            "tools": {name: {"name": name} for name in body.MATRIX_TOOLS},
        }
        body._verify_matrix_mcp(
            {"data": [server]}, require_tools=True, release="0.155.1"
        )
        substitutions: tuple[tuple[str, Any], ...] = (
            ("runtimeStatus", "starting"),
            ("toolsError", "discovery failed"),
            ("pluginId", "another-plugin"),
            ("serverInfo", None),
            ("resources", []),
            ("tools", {}),
            ("unknownStatus", True),
        )
        for field, replacement in substitutions:
            with self.subTest(field=field):
                changed = copy.deepcopy(server)
                changed[field] = replacement
                with self.assertRaises(CodexBodyError):
                    body._verify_matrix_mcp(
                        {"data": [changed]}, require_tools=True, release="0.155.1"
                    )

    def test_successor_receipt_is_versioned_and_pending_launch_is_refused(self) -> None:
        manifest = self.create()
        journal = body.RuntimeHandleJournal(
            self.plan.profile_root / "runtime-handles.jsonl", plan=self.plan
        )
        core = {
            key: self.bootstrap[key]
            for key in (
                "being_ref",
                "body_ref",
                "embodiment_id",
                "incarnation_id",
                "matrix_session_id",
                "matrix_high_water",
            )
        }
        core.update(
            thread_id="native-thread",
            session_tree_id="native-session",
            turn_id=None,
            state="starting",
            observed_at_ms=self.now,
        )
        pending = journal.append(core)
        with self.assertRaises(CodexBodyError) as refused:
            body.create_launch_receipt(self.plan, manifest, pending, outcome="started")
        self.assertEqual(refused.exception.code, "launch_outcome_not_observed")
        core["state"] = "active"
        handle = journal.append(core)
        receipt = body.create_launch_receipt(
            self.plan, manifest, handle, outcome="started"
        )
        self.assertEqual(receipt["schema"], "dm.codex-body.launch-receipt/v2")
        self.assertEqual(receipt["compatibility"]["lifecycle"], "human-request-only")
        self.assertNotIn("hook_sha256", receipt["reviewed_files"])
        replay = copy.deepcopy(receipt)
        replay["schema"] = body.LAUNCH_RECEIPT_SCHEMA
        with self.assertRaises(CodexBodyError):
            body.validate_launch_receipt(replay)

    def test_journal_rejects_legacy_replay_and_preserves_bytes(self) -> None:
        self.create()
        path = self.plan.profile_root / "runtime-handles.jsonl"
        legacy = body.RuntimeHandleJournal(path)
        core = {
            key: self.bootstrap[key]
            for key in (
                "being_ref",
                "body_ref",
                "embodiment_id",
                "incarnation_id",
                "matrix_session_id",
                "matrix_high_water",
            )
        }
        core.update(
            thread_id="native-thread",
            session_tree_id="native-session",
            turn_id=None,
            state="active",
            observed_at_ms=self.now,
        )
        legacy.append(core)
        before = path.read_bytes()
        bound = body.RuntimeHandleJournal(path, plan=self.plan)
        with self.assertRaises(CodexBodyError) as refused:
            bound.load()
        self.assertEqual(refused.exception.code, "handle_journal_profile_mismatch")
        with self.assertRaises(CodexBodyError):
            bound.append(core)
        self.assertEqual(path.read_bytes(), before)

    def test_bound_journal_rejects_foreign_identity_and_downgrade(self) -> None:
        self.create()
        path = self.plan.profile_root / "runtime-handles.jsonl"
        bound = body.RuntimeHandleJournal(path, plan=self.plan)
        core = {
            key: self.bootstrap[key]
            for key in (
                "being_ref",
                "body_ref",
                "embodiment_id",
                "incarnation_id",
                "matrix_session_id",
                "matrix_high_water",
            )
        }
        core.update(
            thread_id="native-thread",
            session_tree_id="native-session",
            turn_id=None,
            state="active",
            observed_at_ms=self.now,
        )
        handle = bound.append(core)
        self.assertEqual(handle["schema"], "dm.codex-body.runtime-handle/v2")
        self.assertEqual(bound.load(), [handle])
        before = path.read_bytes()
        for key in bound.profile_binding or {}:
            with self.subTest(binding=key):
                foreign = copy.deepcopy(core)
                foreign[key] = "foreign-binding"
                with self.assertRaises(CodexBodyError) as refused:
                    bound.append(foreign)
                self.assertEqual(
                    refused.exception.code, "handle_journal_profile_mismatch"
                )
                self.assertEqual(path.read_bytes(), before)
        with self.assertRaises(CodexBodyError):
            body.RuntimeHandleJournal(path).load()
        self.assertEqual(path.read_bytes(), before)
        alias = self.root / "handle-alias"
        os.link(path, alias)
        try:
            with self.assertRaises(CodexBodyError):
                bound.load()
            with self.assertRaises(CodexBodyError):
                bound.append(core)
            self.assertEqual(path.read_bytes(), before)
        finally:
            alias.unlink()

    def test_successor_adapter_refuses_unbound_journal_before_transport(self) -> None:
        self.create()
        transport = mock.Mock()
        with self.assertRaises(CodexBodyError) as refused:
            body.CodexBodyAdapter(
                self.plan,
                transport,
                mock.Mock(),
                body.RuntimeHandleJournal(self.plan.profile_root / "handles.jsonl"),
            )
        self.assertEqual(refused.exception.code, "codex_journal_profile_mismatch")
        self.assertEqual(transport.mock_calls, [])

    def test_start_rechecks_admission_and_preserves_pending(self) -> None:
        self.create()
        now = [self.now]
        calls: list[int] = []

        def presence(binding: Mapping[str, Any], at_ms: int) -> dict[str, Any]:
            calls.append(at_ms)
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
                "expires_at_ms": self.now + 1000,
            }

        from tests.test_dm040_codex_body import CodexBodyFixture

        inventory = CodexBodyFixture.mcp_inventory(self)  # type: ignore[arg-type]
        server = inventory["data"][0]
        server.update(runtimeStatus="connected", pluginId=None, toolsError=None)
        server["resources"] = [
            {"uri": uri, "mimeType": "application/vnd.daimon-matrix+json"}
            for uri in (
                "daimon:contract/server",
                "daimon:contract/tools",
                "daimon:contract/local-api",
                "daimon:runtime/status",
                "daimon:scope/me",
                "daimon:scope/we",
                "daimon:we/heads",
                "daimon:we/projection",
            )
        ]

        def rpc(method: str, _params: Any) -> dict[str, Any]:
            if method == "thread/start":
                now[0] += 2000
                return self.thread_response()
            self.assertEqual(method, "mcpServerStatus/list")
            return inventory

        transport = mock.Mock()
        transport.request.side_effect = rpc
        journal = body.RuntimeHandleJournal(
            self.plan.profile_root / "runtime-handles.jsonl", plan=self.plan
        )
        adapter = body.CodexBodyAdapter(
            self.plan, transport, presence, journal, clock=lambda: now[0]
        )
        adapter.initialized = True
        with self.assertRaises(CodexBodyError) as refused:
            adapter.start()
        self.assertEqual(refused.exception.code, "matrix_presence_rejected")
        self.assertEqual(calls, [self.now, self.now + 2000])
        self.assertEqual([row["state"] for row in journal.load()], ["starting"])
        with self.assertRaises(CodexBodyError) as retry:
            adapter.start()
        self.assertEqual(retry.exception.code, "codex_launch_outcome_unknown")
        self.assertEqual(transport.request.call_count, 2)
        preserved = journal.path.read_bytes()
        observed = body.describe_native_launch_state(self.plan)
        self.assertEqual(observed["outcome"], "unknown-first-start")
        self.assertFalse(observed["native_ids_saved"])
        self.assertFalse(observed["process_termination_proven"])
        self.assertFalse(observed["automatic_retry_allowed"])
        self.assertEqual(journal.path.read_bytes(), preserved)
        self.assertEqual(transport.request.call_count, 2)

    def test_runtime_journal_fifo_refuses_without_waiting_for_writer(self) -> None:
        path = self.root / "handles.fifo"
        os.mkfifo(path, 0o600)
        code = """import sys
from pathlib import Path
from daimon_matrix.codex_body import CodexBodyError, RuntimeHandleJournal
try:
    RuntimeHandleJournal(Path(sys.argv[1])).load()
except CodexBodyError as error:
    sys.exit(0 if error.code == 'handle_journal_rejected' else 1)
sys.exit(2)
"""
        result = subprocess.run(
            [sys.executable, "-c", code, os.fspath(path)],
            capture_output=True,
            timeout=2,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertTrue(path.exists())

    def test_native_park_cannot_claim_shutdown_through_generic_rpc_transport(
        self,
    ) -> None:
        self.create()
        transport = mock.Mock()
        presence = mock.Mock()
        journal = body.RuntimeHandleJournal(
            self.root / "park-handles.jsonl", plan=self.plan
        )
        adapter = body.CodexBodyAdapter(
            self.plan, transport, presence, journal, clock=lambda: self.now
        )
        adapter.initialized = True
        adapter._record_handle(
            "native-thread",
            "native-session",
            None,
            "active",
            {"matrix_high_water": self.bootstrap["matrix_high_water"]},
        )
        before = journal.path.read_bytes()
        with self.assertRaises(CodexBodyError) as refused:
            adapter.park()
        self.assertEqual(
            refused.exception.code, "codex_native_park_transport_unsupported"
        )
        self.assertEqual(journal.path.read_bytes(), before)
        with self.assertRaises(CodexBodyError) as refused:
            adapter.recover_park()
        self.assertEqual(refused.exception.code, "codex_park_recovery_not_pending")
        self.assertEqual(transport.mock_calls, [])
        self.assertEqual(presence.mock_calls, [])

    def test_pending_resume_recovery_refuses_start_loss_or_changed_native_ids(
        self,
    ) -> None:
        self.create()
        cases = (
            (
                [("starting", "pending-operation", "pending-operation")],
                "codex_resume_recovery_not_pending",
            ),
            (
                [("resuming", "native-thread", "native-session")],
                "codex_resume_recovery_unproved",
            ),
            (
                [
                    ("active", "native-thread", "native-session"),
                    ("resuming", "other-thread", "native-session"),
                ],
                "codex_resume_recovery_unproved",
            ),
            (
                [
                    ("active", "native-thread", "native-session"),
                    ("resuming", "native-thread", "other-session"),
                ],
                "codex_resume_recovery_unproved",
            ),
        )
        for number, (records, code) in enumerate(cases):
            with self.subTest(code=code, records=records):
                transport = mock.Mock()
                presence = mock.Mock()
                journal = body.RuntimeHandleJournal(
                    self.root / f"pending-{number}.jsonl", plan=self.plan
                )
                adapter = body.CodexBodyAdapter(
                    self.plan, transport, presence, journal, clock=lambda: self.now
                )
                adapter.initialized = True
                for state, thread, session in records:
                    adapter._record_handle(
                        thread,
                        session,
                        None,
                        state,
                        {"matrix_high_water": self.bootstrap["matrix_high_water"]},
                    )
                before = journal.path.read_bytes()
                with self.assertRaises(CodexBodyError) as refused:
                    adapter.recover_resume()
                self.assertEqual(refused.exception.code, code)
                self.assertEqual(journal.path.read_bytes(), before)
                self.assertEqual(transport.mock_calls, [])
                self.assertEqual(presence.mock_calls, [])

    def test_native_helper_aliases_are_exact_and_cannot_redirect(self) -> None:
        self.create()
        tmp = self.plan.profile_root / "tmp"
        tmp.mkdir(mode=0o700)
        arg0 = tmp / "arg0"
        arg0.mkdir(mode=0o700)
        session = arg0 / "codex-arg0Ab123x"
        session.mkdir(mode=0o700)
        alias = session / "apply_patch"
        alias.symlink_to(self.plan.codex_binary)
        body.verify_profile(self.plan)
        alias.unlink()
        alias.symlink_to(Path("/usr/bin/false"))
        with self.assertRaises(CodexBodyError) as refused:
            body.verify_profile(self.plan)
        self.assertEqual(refused.exception.code, "profile_generated_state_unsafe")
        alias.unlink()
        unreviewed = session / "arbitrary-helper"
        unreviewed.symlink_to(self.plan.codex_binary)
        with self.assertRaises(CodexBodyError):
            body.verify_profile(self.plan)

    def test_schema_or_policy_replay_does_not_admit_the_successor(self) -> None:
        for field, replacement in (
            ("schema", body.PLAN_SCHEMA),
            ("adapter_version", "1.0.0"),
        ):
            with self.subTest(field=field):
                changed = copy.deepcopy(self.value)
                changed[field] = replacement
                with self.assertRaises(CodexBodyError):
                    body.validate_plan(changed)
        changed = copy.deepcopy(self.value)
        changed["profile_policy"]["hooks"] = "enabled"
        with self.assertRaises(CodexBodyError) as refused:
            body.validate_plan(changed)
        self.assertEqual(refused.exception.code, "unsupported_codex_profile_policy")


if __name__ == "__main__":
    unittest.main()
