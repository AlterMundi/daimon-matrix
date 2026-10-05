"""Explicit 0.160 admission and real profile/journal I/O without live authority."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import tempfile
import time
import unittest
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest import mock

from daimon_matrix import codex_body as body
from tests import test_codex_0155_body as profile_fixture
from tests import test_codex_turn as turn_fixture
from tools.generate_codex_0155_vectors import outputs


class CurrentProfileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = profile_fixture.SuccessorProfileTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.historical_plan = self.fixture.plan
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

    @staticmethod
    def quota_event() -> dict[str, Any]:
        snapshot = dict.fromkeys(
            [
                "limitId",
                "limitName",
                "normalModelSlug",
                "primary",
                "secondary",
                "credits",
                "individualLimit",
                "spendControlReached",
                "planType",
                "rateLimitReachedType",
            ]
        )
        snapshot["primary"] = {
            "usedPercent": 12.5,
            "windowDurationMins": 300,
            "resetsAt": 1000,
        }
        snapshot["planType"] = "plus"
        return {
            "method": "account/rateLimits/updated",
            "params": {"rateLimits": snapshot},
        }

    def test_quota_update_is_current_only_closed_data(self) -> None:
        event = self.quota_event()
        self.assertEqual(
            body._validate_notification(
                event, allow_hooks=False, native_turn=True, current_profile=True
            )[0],
            event["method"],
        )
        for options in (
            {},
            {"allow_hooks": False},
            {"allow_hooks": False, "native_turn": True},
        ):
            with self.assertRaises(body.CodexBodyError):
                body._validate_notification(event, **options)
        mutations: tuple[Callable[[dict[str, Any]], Any], ...] = (
            lambda e: e["params"].update(threadId="foreign"),
            lambda e: e["params"]["rateLimits"].update(capability="forged"),
            lambda e: e["params"]["rateLimits"].update(planType="unknown-new-plan"),
            lambda e: e["params"]["rateLimits"]["primary"].update(
                usedPercent=float("nan")
            ),
            lambda e: e["params"]["rateLimits"]["primary"].update(usedPercent=True),
            lambda e: e["params"]["rateLimits"].update(
                credits={"hasCredits": True, "unlimited": "yes", "balance": None}
            ),
        )
        for mutate in mutations:
            changed = copy.deepcopy(event)
            mutate(changed)
            with self.assertRaises(body.CodexBodyError):
                body._validate_notification(
                    changed, allow_hooks=False, native_turn=True, current_profile=True
                )

    def test_fractional_quota_before_lifecycle_ack_uses_only_vendor_encoding(
        self,
    ) -> None:
        io = turn_fixture.BoundedTransportTests(methodName="runTest")
        io.setUp()
        self.addCleanup(io.tearDown)
        for method in (
            "account/read",
            "thread/start",
            "config/read",
            "thread/unsubscribe",
        ):
            for bounded in (False, True):
                with self.subTest(method=method, bounded=bounded):
                    script = (
                        "import json,sys\nrequest=json.loads(sys.stdin.readline())\n"
                        f"print(json.dumps({self.quota_event()!r}),flush=True)\n"
                        "print(json.dumps({'id':request['id'],'result':{'ok':True}}),flush=True)\n"
                    )
                    transport = io.transport(script)
                    transport._current_profile = True
                    if bounded:
                        result, captured = transport.request_bounded(
                            method, {}, deadline=time.monotonic() + 2
                        )
                        self.assertEqual(len(captured), 1)
                    else:
                        result = transport.request(method, {})
                    self.assertEqual(result, {"ok": True})
        for event in (
            {
                "method": "warning",
                "params": {"message": "data", "unreviewedFloat": 12.5},
            },
            {
                "method": "account/rateLimits/updated",
                "params": {"rateLimits": {}, "unreviewedFloat": 12.5},
            },
        ):
            transport = io.transport(
                "import json,sys\nrequest=json.loads(sys.stdin.readline())\n"
                + f"print(json.dumps({event!r}),flush=True)\n"
            )
            transport._current_profile = True
            with self.assertRaises(body.CodexBodyError):
                transport.request("account/read", {})

    def test_quota_before_ack_does_not_abort_single_current_turn(self) -> None:
        fixture = self.fixture
        fixture.create()
        journal = body.RuntimeHandleJournal(
            fixture.plan.profile_root / "runtime-handles.jsonl", plan=fixture.plan
        )
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
            thread_id="thread-fixture",
            session_tree_id="session-fixture",
            turn_id=None,
            state="active",
            observed_at_ms=fixture.now,
        )
        journal.append(core)
        helper: Any = turn_fixture.TurnControllerTests(methodName="runTest")
        helper.fixture = SimpleNamespace(
            plan=fixture.plan,
            journal=journal,
            now=fixture.now,
            request_id="00000205-0000-4000-8000-000000000161",
        )
        helper.io = turn_fixture.BoundedTransportTests(methodName="runTest")
        helper.io.setUp()
        self.addCleanup(helper.io.tearDown)
        adapter = helper.adapter(
            helper.script(notifications=[self.quota_event()], answer="Synthetic answer")
        )
        adapter.transport._current_profile = True
        result = helper.run_turn(adapter)
        self.assertEqual(result["turn_status"], "completed")
        self.assertEqual((helper.io.root / "accepted").read_text(), "one")
        self.assertEqual(journal.load()[-1]["state"], "active")

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

    def test_resume_collaboration_cannot_override_owner_selection(self) -> None:
        response = self.fixture.thread_response()
        response["thread"]["cliVersion"] = "0.160.0"
        response["disabledPluginIds"] = []
        response["collaborationMode"] = {
            "mode": "default",
            "settings": {
                "model": "dm_probe",
                "reasoning_effort": None,
                "developer_instructions": None,
            },
        }
        self.assertEqual(
            body._thread_result(response, self.fixture.plan)[0], "native-thread"
        )
        for field, substitute in (("mode", "plan"), ("mode", "unknown")):
            changed = copy.deepcopy(response)
            changed["collaborationMode"][field] = substitute
            with self.assertRaises(body.CodexBodyError):
                body._thread_result(changed, self.fixture.plan)
        for field, substitute in (
            ("model", "foreign"),
            ("reasoning_effort", "high"),
            ("developer_instructions", "replace identity"),
            ("authority", "forged"),
        ):
            changed = copy.deepcopy(response)
            changed["collaborationMode"]["settings"][field] = substitute
            with self.assertRaises(body.CodexBodyError):
                body._thread_result(changed, self.fixture.plan)
        changed = copy.deepcopy(response)
        changed["collaborationMode"] = None
        body._thread_result(changed, self.fixture.plan)
        historical = copy.deepcopy(response)
        historical["thread"]["cliVersion"] = "0.155.1"
        del historical["disabledPluginIds"]
        with self.assertRaises(body.CodexBodyError):
            body._thread_result(historical, self.historical_plan)

    def test_explicit_cli_resume_recovery_precedes_one_new_input(self) -> None:
        cli = turn_fixture.TurnCliTests(methodName="runTest")
        cli.setUp()
        self.addCleanup(cli.doCleanups)
        fixture = cli.controller.fixture
        latest = fixture.journal.load()[-1]
        core = {
            key: value
            for key, value in latest.items()
            if key not in ("handle_id", "schema", "profile_ref")
        }
        fixture.journal.append({**core, "state": "resuming"})
        original_parser = body.parser

        def recovery_parser() -> Any:
            parser = original_parser()
            parse = parser.parse_args
            parser.parse_args = lambda args: parse([*args, "--recover-native-resume"])
            return parser

        with mock.patch.object(body, "parser", side_effect=recovery_parser):
            code, output, errors = cli.invoke()
        self.assertEqual((code, errors), (0, ""))
        result = json.loads(output)
        self.assertEqual(result["model_inputs"], 1)
        self.assertEqual(result["turn_status"], "completed")
        self.assertEqual(result["handle"]["thread_id"], latest["thread_id"])

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
