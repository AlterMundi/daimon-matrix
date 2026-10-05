"""Explicit 0.160 admission and real profile/journal I/O without live authority."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

from daimon_matrix import codex_body as body
from tests import test_codex_0155_body as profile_fixture
from tools.generate_codex_0155_vectors import outputs


class CurrentProfileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = profile_fixture.SuccessorProfileTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        pin = replace(
            body.CURRENT_RELEASE,
            binary_sha256=hashlib.sha256(self.fixture.binary.read_bytes()).hexdigest(),
        )
        patch = mock.patch.object(body, "CURRENT_RELEASE", pin)
        patch.start()
        self.addCleanup(patch.stop)
        value = body.create_plan_value(
            bootstrap=self.fixture.bootstrap,
            model="dm_probe",
            provider="dm_probe",
            workspace_ref=self.fixture.value["workspace_ref"],
            release="0.160.0",
        )
        self.fixture.plan = replace(self.fixture.plan, value=value)

    def test_current_native_envelope_is_version_specific_and_plugins_disabled(
        self,
    ) -> None:
        fixture = self.fixture
        response = fixture.thread_response()
        response["thread"]["cliVersion"] = "0.160.0"
        response["disabledPluginIds"] = []
        body._thread_result(response, fixture.plan)
        for substitute in (None, ["foreign"], "disabled"):
            changed = copy.deepcopy(response)
            changed["disabledPluginIds"] = substitute
            with self.assertRaises(body.CodexBodyError):
                body._thread_result(changed, fixture.plan)
        del response["disabledPluginIds"]
        with self.assertRaises(body.CodexBodyError):
            body._thread_result(response, fixture.plan)

    def test_current_profile_and_cold_journal_are_bound_to_exact_release(self) -> None:
        fixture = self.fixture
        manifest = fixture.create()
        self.assertEqual(
            body._native_mcp_arguments(fixture.plan)[-1],
            "--capability-from-native-parent",
        )
        self.assertEqual(manifest["schema"], "dm.codex-body.profile-manifest/v3")
        self.assertEqual(manifest["codex_version"], "0.160.0")
        path = fixture.plan.profile_root / "runtime-handles.jsonl"
        journal = body.RuntimeHandleJournal(path, plan=fixture.plan)
        core = {
            key: fixture.bootstrap[key]
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
            observed_at_ms=fixture.now,
        )
        handle = journal.append(core)
        self.assertEqual(handle["schema"], "dm.codex-body.runtime-handle/v3")
        self.assertEqual(
            body.RuntimeHandleJournal(path, plan=fixture.plan).load(), [handle]
        )
        receipt = body.create_launch_receipt(
            fixture.plan, manifest, handle, outcome="started"
        )
        self.assertEqual(body.validate_launch_receipt(receipt), receipt)
        self.assertEqual(receipt["schema"], "dm.codex-body.launch-receipt/v3")
        intent = body.prepare_turn_intent(
            fixture.plan,
            request_id="00000205-0000-4000-8000-000000000160",
            input_text="Synthetic input",
            active_handle=handle,
            timeout_seconds=1,
            max_response_bytes=1024,
            retain_until_ms=fixture.now + 1000,
            at_ms=fixture.now,
        )
        self.assertEqual(body.validate_turn_intent(intent), intent)
        before = path.read_bytes()
        old_value = body.create_plan_value(
            bootstrap=fixture.bootstrap,
            model="dm_probe",
            provider="dm_probe",
            workspace_ref=fixture.value["workspace_ref"],
            release="0.155.1",
        )
        with self.assertRaises(body.CodexBodyError):
            body.RuntimeHandleJournal(
                path, plan=replace(fixture.plan, value=old_value)
            ).load()
        self.assertEqual(path.read_bytes(), before)
        for value, field, substitute, validator in (
            (handle, "codex_version", "0.155.1", body.validate_runtime_handle),
            (intent, "codex_version", "0.155.1", body.validate_turn_intent),
            (
                receipt,
                "schema",
                "dm.codex-body.launch-receipt/v2",
                body.validate_launch_receipt,
            ),
        ):
            changed = copy.deepcopy(value)
            changed[field] = substitute
            with self.assertRaises(body.CodexBodyError):
                validator(changed)


class CurrentReleaseTests(unittest.TestCase):
    def test_current_mcp_rejects_http_or_changed_server_capabilities(self) -> None:
        server = {
            "name": "matrix",
            "authStatus": "unsupported",
            "runtimeStatus": "connected",
            "pluginId": None,
            "toolsError": None,
            "httpOrigin": None,
            "serverInfo": {"name": "daimon-matrix", "version": "0.1.0rc1"},
            "serverCapabilities": {
                "experimental": {},
                "resources": {"subscribe": False, "listChanged": False},
                "tools": {"listChanged": False},
            },
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
            {"data": [server]}, require_tools=True, release="0.160.0"
        )
        for field, substitute in (
            ("httpOrigin", "https://foreign.invalid"),
            ("serverCapabilities", {}),
            ("pluginId", "foreign"),
        ):
            changed = copy.deepcopy(server)
            changed[field] = substitute
            with self.subTest(field=field), self.assertRaises(body.CodexBodyError):
                body._verify_matrix_mcp(
                    {"data": [changed]}, require_tools=True, release="0.160.0"
                )
        with self.assertRaises(body.CodexBodyError):
            body._verify_matrix_mcp(
                {"data": [server]}, require_tools=True, release="0.155.1"
            )

    def test_unknown_and_wrong_native_artifacts_refuse_before_execution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = root / "executed"
            binary = root / "native"
            binary.write_text(f"#!/bin/sh\ntouch '{marker}'\n")
            binary.chmod(0o700)
            for version, code in (
                ("0.160.0", "codex_binary_hash_mismatch"),
                ("0.160.1", "codex_release_unsupported"),
            ):
                with (
                    self.subTest(version=version),
                    self.assertRaises(body.CodexBodyError) as error,
                ):
                    body.verify_compatibility_bundle(
                        binary, root / "json", root / "typescript", release=version
                    )
                self.assertEqual(error.exception.code, code)
                self.assertFalse(marker.exists())

    def test_codec_vectors_and_schemas_are_current_without_rewriting_history(
        self,
    ) -> None:
        from jsonschema import Draft202012Validator  # type: ignore[import-untyped]
        from referencing import Registry, Resource

        root = Path(__file__).resolve().parents[1]
        generated = outputs(body.CURRENT_RELEASE)
        self.assertTrue(
            all(path.read_bytes() == raw for path, raw in generated.items())
        )
        schema_path = root / "schemas/codex/v3/contracts.schema.json"
        schema = json.loads(generated[schema_path])

        def retrieve(uri: str) -> Resource:
            from urllib.parse import urlparse

            path = root / "schemas" / urlparse(uri).path.removeprefix("/daimon-matrix/")
            return Resource.from_contents(json.loads(path.read_bytes()))

        registry = Registry(retrieve=retrieve)  # type: ignore[call-arg]
        validator = Draft202012Validator(schema, registry=registry)
        for path, raw in generated.items():
            if "/valid/" in os.fspath(path):
                validator.validate(json.loads(raw))
        old = outputs(body.SUCCESSOR_RELEASE)
        self.assertTrue(all(path.read_bytes() == raw for path, raw in old.items()))
        plan = json.loads(generated[root / "vectors/codex/v3/valid/plan.json"])
        plan["codex"]["version"] = "0.155.1"
        with self.assertRaises(body.CodexBodyError):
            body.validate_plan(plan)


if __name__ == "__main__":
    unittest.main()
