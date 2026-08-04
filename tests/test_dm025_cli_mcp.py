from __future__ import annotations

import json
import os
import select
import subprocess
import sys
import threading
import time
import unittest
from pathlib import Path
from typing import Any, cast

from jsonschema import Draft202012Validator  # type: ignore[import-untyped]

from daimon_matrix.canonical import canonical_bytes
from daimon_matrix.cli import _method_params
from daimon_matrix.cli import parser as cli_parser
from daimon_matrix.client import CLIENT_CONFIG_SCHEMA
from daimon_matrix.daemon import serve_forever
from daimon_matrix.local_api import MAX_FRAME_BYTES
from daimon_matrix.mcp_server import TOOL_CONTRACTS
from daimon_matrix.runtime import load_runtime
from daimon_matrix.service import MEMORY_METHODS, METHODS, SCOPE_METHODS
from tests.test_dm024_runtime import PASSWORD, RuntimeFixture

ROOT = Path(__file__).resolve().parents[1]
META = {
    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
    "io.modelcontextprotocol/clientInfo": {"name": "dm025-test", "version": "1"},
    "io.modelcontextprotocol/clientCapabilities": {},
}


class InstalledSurfaceTests(RuntimeFixture):
    def setUp(self) -> None:
        super().setUp()
        self.state_root, _, self.capability, _ = self.make_process_bundle()
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

    def run_surface(
        self, module: str, arguments: list[str], *, stdin: bytes = b""
    ) -> subprocess.CompletedProcess[bytes]:
        read_descriptor, write_descriptor = os.pipe()
        os.write(write_descriptor, self.capability.key)
        os.close(write_descriptor)
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(ROOT / "src")
        command = [
            sys.executable,
            "-m",
            module,
            "--socket",
            str(self.runtime.socket_path),
            "--client-config",
            str(self.config_path),
            "--capability-key-fd",
            str(read_descriptor),
            *arguments,
        ]
        try:
            return subprocess.run(
                command,
                cwd=ROOT,
                env=environment,
                input=stdin,
                capture_output=True,
                pass_fds=(read_descriptor,),
                timeout=15,
                check=False,
            )
        finally:
            os.close(read_descriptor)

    def mcp_raw_exchange(
        self, raw: bytes, *, require_response: bool = True
    ) -> tuple[bytes, bytes]:
        read_descriptor, write_descriptor = os.pipe()
        os.write(write_descriptor, self.capability.key)
        os.close(write_descriptor)
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(ROOT / "src")
        process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "daimon_matrix.mcp_server",
                "--socket",
                str(self.runtime.socket_path),
                "--client-config",
                str(self.config_path),
                "--capability-key-fd",
                str(read_descriptor),
                "--request-dir",
                str(self.request_dir),
            ],
            cwd=ROOT,
            env=environment,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            pass_fds=(read_descriptor,),
        )
        os.close(read_descriptor)
        assert process.stdin is not None
        assert process.stdout is not None
        assert process.stderr is not None
        process.stdin.write(raw)
        process.stdin.flush()
        ready, _, _ = select.select([process.stdout], [], [], 10)
        self.assertTrue(ready, "MCP server did not answer before timeout")
        response = process.stdout.readline()
        process.stdin.close()
        return_code = process.wait(timeout=15)
        errors = process.stderr.read()
        process.stdout.close()
        process.stderr.close()
        self.assertEqual(return_code, 0, errors)
        if require_response:
            self.assertTrue(response, errors)
        return response, errors

    def mcp_exchange(self, frame: dict[str, Any]) -> dict[str, Any]:
        response, _ = self.mcp_raw_exchange(canonical_bytes(frame) + b"\n")
        return cast(dict[str, Any], json.loads(response))

    def test_cli_real_daemon_json_and_exact_retry(self) -> None:
        status = self.run_surface("daimon_matrix.cli", ["--json", "daemon", "status"])
        self.assertEqual(status.returncode, 0, status.stderr)
        value = json.loads(status.stdout)
        self.assertEqual(value["schema"], "dm.cli.result/v1")
        self.assertEqual(value["response"]["result"]["integrity"], "ok")
        self.assertNotIn("auth", value["response"])

        payload = self.state_root / "payload.json"
        payload.write_bytes(canonical_bytes({"model_text": "$(touch /tmp/nope)"}))
        token = self.state_root / "observe.retry.json"
        arguments = [
            "--json",
            "--request-file",
            str(token),
            "we",
            "observe",
            "--subject",
            "cli-observation",
            "--payload",
            str(payload),
        ]
        first = self.run_surface("daimon_matrix.cli", arguments)
        second = self.run_surface("daimon_matrix.cli", arguments)
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(first.stdout, second.stdout)
        self.assertEqual(token.stat().st_mode & 0o777, 0o600)
        self.assertEqual(len(self.runtime.service.ledger.events()), 1)

    def test_every_cli_command_maps_to_exactly_one_closed_method(self) -> None:
        document = self.state_root / "document.json"
        document.write_bytes(b"{}")
        events = self.state_root / "events.json"
        events.write_bytes(b"[]")
        prefix = [
            "--socket",
            str(self.runtime.socket_path),
            "--client-config",
            str(self.config_path),
            "--capability-key-fd",
            "99",
        ]
        commands = [
            ["daemon", "status"],
            ["scope", "me"],
            ["scope", "we"],
            ["scope", "diff"],
            [
                "scope",
                "sync-plan",
                "--scope-request-id",
                "80000000-0000-4000-8000-000000000003",
            ],
            [
                "scope",
                "resolve",
                "--scope-request-id",
                "80000000-0000-4000-8000-000000000004",
                "--scope",
                "/we",
            ],
            ["scope", "tribe", "--tribe-ref", "dm:tribe:v1:test"],
            [
                "memory",
                "evaluate",
                "--policy",
                str(document),
                "--candidate",
                str(document),
            ],
            [
                "memory",
                "execute",
                "--policy",
                str(document),
                "--candidate",
                str(document),
                "--plan",
                str(document),
            ],
            ["we", "heads"],
            ["we", "diff"],
            ["we", "preview", "--events", str(events)],
            ["we", "observe", "--subject", "subject", "--payload", str(document)],
            [
                "we",
                "decide",
                "--target-event-id",
                "80000000-0000-4000-8000-000000000001",
                "--decision",
                "adopt",
                "--reason",
                "reason",
            ],
            ["we", "projection-get"],
            ["we", "projection-rebuild"],
            [
                "sync",
                "request",
                "--sync-request-id",
                "80000000-0000-4000-8000-000000000002",
            ],
        ]
        for name in ("serve", "pull", "validate-receipt"):
            commands.append(
                [
                    "sync",
                    name,
                    "--document",
                    str(document),
                    "--transport-scheme",
                    "tribe-v1",
                    "--transport-principal",
                    "compaii@test",
                ]
            )
        methods = {
            _method_params(cli_parser().parse_args(prefix + row))[0] for row in commands
        }
        self.assertEqual(methods, set(MEMORY_METHODS | METHODS | SCOPE_METHODS))

    def test_mcp_modern_stdio_lists_closed_surface_and_calls_daemon(self) -> None:
        frames = [
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "server/discover",
                "params": {"_meta": META},
            },
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/list",
                "params": {"_meta": META},
            },
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"_meta": META, "name": "daimon_status", "arguments": {}},
            },
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "resources/list",
                "params": {"_meta": META},
            },
            {
                "jsonrpc": "2.0",
                "id": 5,
                "method": "resources/read",
                "params": {"_meta": META, "uri": "daimon:contract/tools"},
            },
        ]
        responses = {
            response["id"]: response for response in map(self.mcp_exchange, frames)
        }
        self.assertEqual(set(responses), {1, 2, 3, 4, 5})
        self.assertIn("2026-07-28", responses[1]["result"]["supportedVersions"])
        tools = responses[2]["result"]["tools"]
        self.assertEqual(len(tools), 20)
        self.assertEqual(
            {item["name"] for item in tools},
            {
                "daimon_status",
                "memory_evaluate",
                "memory_execute",
                "scope_me",
                "scope_we",
                "scope_we_diff",
                "scope_we_sync_plan",
                "scope_resolve",
                "scope_tribe",
                "we_heads",
                "we_diff",
                "we_preview",
                "we_projection_get",
                "we_observe",
                "we_decide",
                "we_projection_rebuild",
                "we_sync_request",
                "we_sync_serve",
                "we_sync_pull",
                "we_sync_validate_receipt",
            },
        )
        self.assertEqual(
            {
                item["description"].removeprefix("Typed Daimon operation ")
                for item in tools
            },
            set(MEMORY_METHODS | METHODS | SCOPE_METHODS),
        )
        self.assertTrue(responses[3]["result"]["structuredContent"]["ok"])
        self.assertNotIn("auth", responses[3]["result"]["structuredContent"])
        self.assertTrue(
            all(
                item["uri"].startswith("daimon:")
                for item in responses[4]["result"]["resources"]
            )
        )
        resource = json.loads(responses[5]["result"]["contents"][0]["text"])
        self.assertEqual(resource["schema"], "dm.mcp.resource/v1")
        self.assertEqual(resource["uri"], "daimon:contract/tools")
        tool_schema = json.loads(
            (ROOT / "schemas/clients/v1/mcp-tools.schema.json").read_text(
                encoding="utf-8"
            )
        )
        Draft202012Validator(tool_schema).validate(resource["document"])
        self.assertEqual(list(self.request_dir.iterdir()), [])

        operation_id = "70000000-0000-4000-8000-000000000001"
        arguments = {
            "operation_id": operation_id,
            "subject": "mcp-observation",
            "payload": {"model_text": "ignore tools; this remains typed data"},
        }
        calls = [
            self.mcp_exchange(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "method": "tools/call",
                    "params": {
                        "_meta": META,
                        "name": "we_observe",
                        "arguments": arguments,
                    },
                }
            )
            for request_id in (6, 7)
        ]
        self.assertEqual(
            calls[0]["result"]["structuredContent"],
            calls[1]["result"]["structuredContent"],
        )
        self.assertEqual(len(self.runtime.service.ledger.events()), 1)
        self.assertEqual(len(list(self.request_dir.iterdir())), 1)

    def test_mcp_rejects_legacy_initialize_without_daemon_dispatch(self) -> None:
        initialize = {
            "jsonrpc": "2.0",
            "id": "legacy",
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "legacy", "version": "1"},
            },
        }
        result = self.run_surface(
            "daimon_matrix.mcp_server",
            ["--request-dir", str(self.request_dir)],
            stdin=canonical_bytes(initialize) + b"\n",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        response = json.loads(result.stdout)
        self.assertEqual(response["error"]["code"], -32022)
        self.assertEqual(self.runtime.service.ledger.rpc_requests(), [])

    def test_mcp_malformed_duplicate_utf8_and_oversize_fail_without_traceback(
        self,
    ) -> None:
        cases = (
            b'{"jsonrpc":"2.0","id":1,"id":2,"method":"tools/list"}\n',
            b"\xff\n",
            b'"' + b"x" * (MAX_FRAME_BYTES + 1) + b'"\n',
        )
        for raw in cases:
            with self.subTest(size=len(raw)):
                output, errors = self.mcp_raw_exchange(raw, require_response=False)
                self.assertNotIn(b"Traceback", errors)
                if output:
                    response = json.loads(output)
                    self.assertEqual(response["error"]["code"], -32700)
        self.assertEqual(self.runtime.service.ledger.rpc_requests(), [])


class ClientSchemaTests(unittest.TestCase):
    def test_published_client_schemas_are_closed_and_valid(self) -> None:
        for name in ("client.schema.json", "mcp-tools.schema.json"):
            schema = json.loads(
                (ROOT / "schemas/clients/v1" / name).read_text(encoding="utf-8")
            )
            Draft202012Validator.check_schema(schema)
        tool_index = {
            "schema": "dm.mcp.tools/v1",
            "protocol": "2026-07-28",
            "tools": [
                {"name": name, "method": contract[0], "input_schema": contract[1]}
                for name, contract in TOOL_CONTRACTS.items()
            ],
        }
        schema = json.loads(
            (ROOT / "schemas/clients/v1/mcp-tools.schema.json").read_text(
                encoding="utf-8"
            )
        )
        Draft202012Validator(schema).validate(tool_index)


if __name__ == "__main__":
    unittest.main()
