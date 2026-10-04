"""Owner-selected execution survives profile I/O and native policy checks."""

from __future__ import annotations

import copy
import json
import tomllib
import unittest
from dataclasses import replace
from typing import Any
from unittest import mock

from daimon_matrix import codex_body as body
from daimon_matrix.canonical import b64url
from tests import test_codex_0155_body as fixtures


class ExecutionPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = fixtures.SuccessorProfileTests(methodName="runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        value = body.create_plan_value(
            bootstrap=self.fixture.bootstrap,
            model="gpt-6.1-sol",
            provider="openai",
            workspace_ref=self.fixture.value["workspace_ref"],
            release="0.155.1",
            reasoning_effort="medium",
            full_access=True,
        )
        self.plan = replace(self.fixture.plan, value=value)

    def test_selected_policy_is_private_profile_bound_and_reopens(self) -> None:
        manifest = body.create_profile(
            self.plan,
            bootstrap_verifier=lambda *_: True,
            clock=lambda: self.fixture.now,
        )
        config = tomllib.loads((self.plan.profile_root / "config.toml").read_text())
        self.assertEqual(config["approval_policy"], "never")
        self.assertEqual(config["sandbox_mode"], "danger-full-access")
        self.assertEqual(config["model_reasoning_effort"], "medium")
        self.assertFalse(config["features"]["hooks"])
        self.assertEqual(body.verify_profile(self.plan), manifest)
        substituted = copy.deepcopy(self.plan.value)
        substituted["profile_policy"].update(body._execution_policy())
        with self.assertRaises(body.CodexBodyError):
            body.verify_profile(replace(self.plan, value=substituted))

    def test_default_keeps_original_config_and_policy(self) -> None:
        value = self.fixture.value
        self.assertNotIn("reasoning_effort", value["codex"])
        config = tomllib.loads(body.render_config(self.fixture.plan).decode())
        self.assertNotIn("model_reasoning_effort", config)
        self.assertEqual(config["approval_policy"], "on-request")
        self.assertEqual(config["sandbox_mode"], "workspace-write")

    def test_historical_override_refused(self) -> None:
        selections: list[dict[str, Any]] = [
            {"full_access": True},
            {"reasoning_effort": "medium"},
        ]
        for options in selections:
            with (
                self.subTest(options=options),
                self.assertRaisesRegex(
                    body.CodexBodyError, "historical_codex_execution_override_forbidden"
                ),
            ):
                body.create_plan_value(
                    bootstrap=self.fixture.bootstrap,
                    model="dm_probe",
                    provider="dm_probe",
                    workspace_ref=self.fixture.value["workspace_ref"],
                    **options,
                )

    def test_mixed_or_unknown_policy_refused(self) -> None:
        for field, replacement in (
            ("sandbox", "workspace-write"),
            ("approval_policy", "on-request"),
            ("network", "disabled"),
            ("hooks", "enabled"),
        ):
            value = copy.deepcopy(self.plan.value)
            value["profile_policy"][field] = replacement
            with self.subTest(field=field), self.assertRaises(body.CodexBodyError):
                body.validate_plan(value)
        value = copy.deepcopy(self.plan.value)
        value["codex"]["reasoning_effort"] = "unselected"
        with self.assertRaises(body.CodexBodyError):
            body.validate_plan(value)

    def test_effective_config_refuses_policy_or_effort_substitution(self) -> None:
        config = tomllib.loads(body.render_config(self.plan).decode())
        body._validate_effective_config(config, self.plan)
        for field, replacement in (
            ("approval_policy", "on-request"),
            ("sandbox_mode", "workspace-write"),
            ("model_reasoning_effort", "high"),
        ):
            changed = copy.deepcopy(config)
            changed[field] = replacement
            with self.subTest(field=field):
                with self.assertRaises(body.CodexBodyError):
                    body._validate_effective_config(changed, self.plan)
                with self.assertRaises(body.CodexBodyError):
                    body._validate_native_configuration(
                        {"config": changed, "origins": {}}, self.plan
                    )

    def response(self) -> dict[str, Any]:
        row = self.fixture.thread_response()
        row.update(
            approvalPolicy="never",
            sandbox={"type": "dangerFullAccess"},
            reasoningEffort="medium",
            model="gpt-6.1-sol",
            modelProvider="openai",
        )
        row["thread"]["modelProvider"] = "openai"
        return row

    def test_native_thread_must_report_selected_policy_and_effort(self) -> None:
        row = self.response()
        self.assertEqual(body._thread_result(row, self.plan)[0], "native-thread")
        for field, replacement in (
            ("approvalPolicy", "on-request"),
            ("sandbox", {"type": "workspaceWrite"}),
            ("reasoningEffort", "high"),
            ("approvalsReviewer", "guardian_subagent"),
        ):
            changed = copy.deepcopy(row)
            changed[field] = replacement
            with self.subTest(field=field), self.assertRaises(body.CodexBodyError):
                body._thread_result(changed, self.plan)

    def test_start_and_resume_use_selected_execution(self) -> None:
        from tests.test_dm040_codex_body import CodexBodyFixture

        body.create_profile(
            self.plan,
            bootstrap_verifier=lambda *_: True,
            clock=lambda: self.fixture.now,
        )
        inventory = CodexBodyFixture.mcp_inventory(self.fixture)  # type: ignore[arg-type]
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
        calls = []

        def rpc(method: str, params: Any) -> dict[str, Any]:
            calls.append((method, params))
            if method in ("thread/start", "thread/resume"):
                return self.response()
            self.assertEqual(method, "mcpServerStatus/list")
            return inventory

        def presence(binding: Any, at_ms: int) -> dict[str, Any]:
            return {
                **{
                    name: binding[name]
                    for name in (
                        "body_ref",
                        "embodiment_id",
                        "incarnation_id",
                        "matrix_session_id",
                        "matrix_high_water",
                    )
                },
                "state": "active",
                "expires_at_ms": at_ms + 1000,
            }

        transport = mock.Mock()
        transport.request.side_effect = rpc
        journal = body.RuntimeHandleJournal(
            self.plan.profile_root / "runtime-handles.jsonl", plan=self.plan
        )
        adapter = body.CodexBodyAdapter(
            self.plan, transport, presence, journal, clock=lambda: self.fixture.now
        )
        adapter.initialized = True
        first = adapter.start()
        resumed = adapter.resume()
        self.assertEqual(first["thread_id"], resumed["thread_id"])
        receipt = body.create_launch_receipt(
            self.plan, body.verify_profile(self.plan), resumed, outcome="resumed"
        )
        self.assertEqual(receipt["runtime"]["approval_policy"], "never")
        self.assertEqual(receipt["runtime"]["sandbox"], "danger-full-access")
        self.assertEqual(receipt["runtime"]["network"], "enabled")
        for method, params in calls:
            if method in ("thread/start", "thread/resume"):
                self.assertEqual(params["approvalPolicy"], "never")
                self.assertEqual(params["sandbox"], "danger-full-access")


class ExternalAuthTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = fixtures.SuccessorProfileTests(methodName="runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        value = body.create_plan_value(
            bootstrap=self.fixture.bootstrap,
            model="dm_probe",
            provider="openai",
            workspace_ref=self.fixture.value["workspace_ref"],
            release="0.155.1",
            provider_auth="chatgpt-external",
        )
        self.plan = replace(self.fixture.plan, value=value)
        self.token = (
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
        body.create_profile(
            self.plan,
            bootstrap_verifier=lambda *_: True,
            clock=lambda: self.fixture.now,
        )

    def test_external_login_through_real_pipes_preserves_profile(self) -> None:
        from tests.test_codex_turn import BoundedTransportTests

        io = BoundedTransportTests(methodName="runTest")
        io.setUp()
        self.addCleanup(io.tearDown)
        transport = io.transport(
            "import json,sys\n"
            "login=json.loads(sys.stdin.readline())\n"
            "assert login['method']=='account/login/start'\n"
            "assert login['params']['type']=='chatgptAuthTokens'\n"
            "assert login['params']['chatgptAccountId']=='synthetic-account'\n"
            "print(json.dumps({'method':'account/login/completed','params':"
            "{'loginId':None,'success':True,'error':None,'onboardingEntrypoint':None}}),flush=True)\n"
            "print(json.dumps({'id':login['id'],'result':{'type':'chatgptAuthTokens'}}),flush=True)\n"
            "read=json.loads(sys.stdin.readline())\n"
            "assert read['method']=='account/read'\n"
            "assert read['params']=={'refreshToken':False}\n"
            "print(json.dumps({'method':'account/updated','params':{'authMode':'chatgpt','planType':'plus'}}),flush=True)\n"
            "print(json.dumps({'id':read['id'],'result':{'account':{'type':'chatgpt'},'requiresOpenaiAuth':True}}),flush=True)\n"
        )
        before = body.verify_profile(self.plan)
        body.authenticate_chatgpt(self.plan, transport, self.token)
        self.assertEqual(body.verify_profile(self.plan), before)
        self.assertFalse((self.plan.profile_root / "auth.json").exists())
        for path in self.plan.profile_root.iterdir():
            if path.is_file():
                self.assertNotIn(self.token.encode(), path.read_bytes())

    def test_malformed_or_duplicate_claims_refuse_without_secret_error(self) -> None:
        for value in (
            "synthetic",
            "x.e30.x",
            "x."
            + b64url(
                b'{"https://api.openai.com/auth":{},"https://api.openai.com/auth":{}}'
            )
            + ".x",
        ):
            with (
                self.subTest(value=value),
                self.assertRaises(body.CodexBodyError) as caught,
            ):
                body.chatgpt_login_params(value)
            self.assertNotIn(value, str(caught.exception))

    def test_external_auth_requires_explicit_selection_and_success(self) -> None:
        transport = mock.Mock()
        with self.assertRaises(body.CodexBodyError):
            body.authenticate_chatgpt(self.fixture.plan, transport, self.token)
        transport.request.assert_not_called()
        transport.request.return_value = {"type": "chatgpt"}
        with self.assertRaises(body.CodexBodyError):
            body.authenticate_chatgpt(self.plan, transport, self.token)
        self.assertEqual(transport.request.call_count, 1)

    def test_auth_notifications_are_restricted_to_explicit_auth_requests(self) -> None:
        value: dict[str, Any] = {
            "method": "account/updated",
            "params": {"authMode": "chatgpt", "planType": "plus"},
        }
        with self.assertRaises(body.CodexBodyError):
            body._validate_notification(value, allow_hooks=False)
        body._validate_notification(value, allow_hooks=False, authenticating=True)
        value["params"]["authMode"] = "apikey"
        with self.assertRaises(body.CodexBodyError):
            body._validate_notification(value, allow_hooks=False, authenticating=True)

    def test_auth_selection_requires_successor_and_openai_provider(self) -> None:
        value = copy.deepcopy(self.plan.value)
        value["codex"]["provider"] = "another-provider"
        with self.assertRaises(body.CodexBodyError):
            body.validate_plan(value)
        with self.assertRaises(body.CodexBodyError):
            body.create_plan_value(
                bootstrap=self.fixture.bootstrap,
                model="dm_probe",
                provider="openai",
                workspace_ref=self.fixture.value["workspace_ref"],
                provider_auth="chatgpt-external",
            )

    def test_initialize_enables_external_auth_only_when_selected(self) -> None:
        default = replace(
            self.fixture.plan, profile_root=self.plan.profile_root.parent / "default"
        )
        body.create_profile(
            default,
            bootstrap_verifier=lambda *_: True,
            clock=lambda: self.fixture.now,
        )
        for plan, selected in ((self.plan, True), (default, False)):
            transport = mock.Mock()
            transport.request.return_value = {}
            journal = body.RuntimeHandleJournal(
                plan.profile_root / "runtime-handles.jsonl", plan=plan
            )
            adapter = body.CodexBodyAdapter(plan, transport, lambda *_: {}, journal)
            # Stop after the actual initialization request; a malformed native
            # response must not advance to config or skills validation.
            with self.assertRaises(body.CodexBodyError):
                adapter.initialize()
            self.assertEqual(transport.request.call_count, 1)
            self.assertEqual(
                transport.request.call_args.args[1]["capabilities"]["experimentalApi"],
                selected,
            )


if __name__ == "__main__":
    unittest.main()
