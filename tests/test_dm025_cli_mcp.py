from __future__ import annotations

import hashlib
import json
import os
import select
import subprocess
import sys
import threading
import time
import unittest
from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

from jsonschema import (  # type: ignore[import-untyped]
    Draft202012Validator,
    ValidationError,
)
from referencing import Registry, Resource

from daimon_matrix.canonical import canonical_bytes
from daimon_matrix.cli import _method_params
from daimon_matrix.cli import parser as cli_parser
from daimon_matrix.client import CLIENT_CONFIG_SCHEMA_V3
from daimon_matrix.cluster import create_effect_receipt
from daimon_matrix.daemon import serve_forever
from daimon_matrix.local_api import (
    MAX_CAPABILITY_METHODS,
    MAX_FRAME_BYTES,
    LocalApiError,
    create_capability,
)
from daimon_matrix.mcp_server import TOOL_CONTRACTS
from daimon_matrix.runtime import load_runtime
from daimon_matrix.service import (
    CURATOR_METHODS,
    MEMORY_METHODS,
    METHODS,
    PEER_METHODS,
    RELATIONSHIP_METHODS,
    REVIEW_METHODS,
    SCOPE_METHODS,
    SERVICE_METHODS,
    SOURCE_METHODS,
    SPECIES_METHODS,
)
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
        self.state_root, bundle, self.capability, _ = self.make_process_bundle()
        self.projection_intents: dict[str, dict[str, Any]] = {}
        self.projection_posts = self.state_root / "observed-projections.json"
        self.projection_posts.write_bytes(canonical_bytes({}))
        self.runtime = load_runtime(
            self.state_root,
            "runtime.json",
            lambda: bytearray(PASSWORD),
            clock=lambda: time.time_ns() // 1_000_000,
            projection_observer=self.observe_projection,
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
                    "schema": CLIENT_CONFIG_SCHEMA_V3,
                    "capability": self.capability.descriptor,
                    "expected_server": self.origins["legion"],
                    "runtime_id": bundle["runtime_id"],
                    "runtime_label": bundle["runtime_label"],
                }
            )
        )
        self.config_path.chmod(0o600)
        self.request_dir = self.state_root / "requests"
        self.request_dir.mkdir(mode=0o700)

    def observe_projection(
        self, receipt: Mapping[str, Any], at_ms: int
    ) -> Mapping[str, Any]:
        return {
            "intent": self.projection_intents[str(receipt["effect_id"])],
            "observed_postcondition": json.loads(self.projection_posts.read_bytes())[
                receipt["effect_id"]
            ],
            "current_fence_evidence": None,
        }

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
        client_schema = json.loads(
            (ROOT / "schemas/clients/v1/client.schema.json").read_bytes()
        )
        local_schema = json.loads(
            (ROOT / "schemas/hosted/v1/local-api.schema.json").read_bytes()
        )
        registry = Registry().with_resources(
            (document["$id"], Resource.from_contents(document))
            for document in (client_schema, local_schema)
        )
        Draft202012Validator(client_schema, registry=registry).validate(value)

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

    def test_proposal_cli_and_mcp_use_real_daemon_with_exact_retry_and_read(
        self,
    ) -> None:
        observer = self.capability
        self.capability = self.operator_capabilities["weave"]
        config = json.loads(self.config_path.read_bytes())
        config["capability"] = self.capability.descriptor
        self.config_path.write_bytes(canonical_bytes(config))
        payload = self.state_root / "selected-customization.json"
        payload.write_bytes(canonical_bytes({"content_sha256": "a" * 64}))
        arguments = [
            "--json",
            "--request-file",
            str(self.state_root / "proposal.retry.json"),
            "we",
            "propose",
            "--kind",
            "configuration.proposed",
            "--subject",
            "selected",
            "--payload",
            str(payload),
        ]
        first = self.run_surface("daimon_matrix.cli", arguments)
        again = self.run_surface("daimon_matrix.cli", arguments)
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(first.stdout, again.stdout)
        cli_event = json.loads(first.stdout)["response"]["result"]["event"]
        self.assertEqual(cli_event["kind"], "configuration.proposed")

        def mcp(name: str, values: dict[str, Any]) -> dict[str, Any]:
            response = self.mcp_exchange(
                {
                    "jsonrpc": "2.0",
                    "id": "integration",
                    "method": "tools/call",
                    "params": {"_meta": META, "name": name, "arguments": values},
                }
            )
            result = response["result"]["structuredContent"]
            self.assertTrue(result["ok"], result)
            return cast(dict[str, Any], result["result"]["event"])

        values = {
            "kind": "skill.proposed",
            "subject": "selected-skill",
            "payload": {"content_sha256": "b" * 64},
            "operation_id": "70000000-0000-4000-8000-000000000099",
        }
        mcp_event = mcp("we_propose", values)
        self.assertEqual(mcp("we_propose", values), mcp_event)
        self.assertEqual(mcp_event["kind"], "skill.proposed")
        self.assertEqual(len(self.runtime.service.ledger.events()), 2)
        self.capability = observer
        config["capability"] = observer.descriptor
        self.config_path.write_bytes(canonical_bytes(config))
        fetched = self.run_surface(
            "daimon_matrix.cli",
            ["--json", "we", "event-get", "--event-id", cli_event["event_id"]],
        )
        self.assertEqual(fetched.returncode, 0, fetched.stderr)
        self.assertEqual(
            json.loads(fetched.stdout)["response"]["result"]["event"], cli_event
        )
        self.assertEqual(
            mcp("we_event_get", {"event_id": mcp_event["event_id"]}), mcp_event
        )
        self.assertTrue(
            all(
                item["state"] == "pending"
                for item in self.runtime.service._diff(
                    {"after": None, "kind": None, "limit": 10, "subject": None}
                )["entries"]
            )
        )

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
            ["curator", "enqueue", "--item", str(document)],
            [
                "curator",
                "claim",
                "--item-id",
                "dm:curator-item:v1:" + "a" * 43,
                "--claim-id",
                "80000000-0000-4000-8000-000000000005",
                "--expected-generation",
                "0",
                "--lease-until-ms",
                "1800000001000",
            ],
            [
                "curator",
                "complete",
                "--claim-id",
                "80000000-0000-4000-8000-000000000005",
                "--expected-generation",
                "1",
                "--outcome",
                "completed",
                "--output-ref",
                "proposal:test",
            ],
            [
                "curator",
                "inspect",
                "--item-id",
                "dm:curator-item:v1:" + "a" * 43,
            ],
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
            ["review", "authorize", "--authorization", str(document)],
            [
                "review",
                "revoke",
                "--authorization-id",
                "dm:review-authorization:v1:" + "A" * 43,
                "--reason",
                "synthetic",
            ],
            ["review", "request", "--review-request", str(document)],
            [
                "review",
                "queue",
                "--authorization-id",
                "dm:review-authorization:v1:" + "A" * 43,
                "--access-proof",
                str(document),
            ],
            [
                "review",
                "inspect",
                "--review-request-id",
                "dm:review-request:v1:" + "A" * 43,
                "--authorization-id",
                "dm:review-authorization:v1:" + "A" * 43,
                "--access-proof",
                str(document),
            ],
            [
                "review",
                "draft",
                "--review-request-id",
                "dm:review-request:v1:" + "A" * 43,
                "--authorization-id",
                "dm:review-authorization:v1:" + "A" * 43,
                "--action",
                "accept",
                "--reason",
                "evidence-sufficient",
                "--decision-nonce",
                "33000000-0000-4000-8000-000000000025",
                "--decided-at-ms",
                "1",
            ],
            ["review", "submit", "--signed-decision", str(document)],
            [
                "review",
                "execute",
                "--review-request-id",
                "dm:review-request:v1:" + "A" * 43,
            ],
            [
                "source",
                "content-put",
                "--content",
                str(document),
                "--media-type",
                "application/json",
            ],
            ["source", "claim", "--payload", str(document)],
            ["source", "assess", "--payload", str(document)],
            ["source", "publication-append", "--payload", str(document)],
            ["source", "import-decide", "--payload", str(document)],
            ["source", "status", "--selector", str(document)],
            ["source", "cursor-create", "--selector", str(document)],
            [
                "source",
                "diff",
                "--selector",
                str(document),
                "--source-request-id",
                "81000000-0000-4000-8000-000000000001",
                "--requester-me-id",
                "dm:me:v0:requester",
                "--requester-cursor",
                str(document),
            ],
            ["source", "incoming", "--bundle", str(document)],
            [
                "source",
                "pull",
                "--operation-id",
                "81000000-0000-4000-8000-000000000002",
                "--bundle",
                str(document),
                "--preview",
                str(document),
            ],
            [
                "source",
                "promote",
                "--publication-id",
                "dm:source-publication:v0:" + "A" * 43,
                "--policy-ref",
                str(document),
                "--evidence-snapshot-ref",
                str(document),
            ],
            [
                "source",
                "projection",
                "--publication-id",
                "dm:source-publication:v0:" + "A" * 43,
            ],
            ["relationship", "card-publish", "--payload", str(document)],
            ["relationship", "offer", "--payload", str(document)],
            ["relationship", "accept", "--payload", str(document)],
            ["relationship", "close", "--payload", str(document)],
            ["relationship", "grant", "--payload", str(document)],
            ["relationship", "grant-accept", "--payload", str(document)],
            ["relationship", "grant-revoke", "--payload", str(document)],
            ["relationship", "grant-relinquish", "--payload", str(document)],
            ["relationship", "event-ingest", "--event", str(document)],
            ["relationship", "cursor"],
            ["relationship", "status"],
            [
                "relationship",
                "snapshot",
                "--tribe-ref",
                "dm:tribe:v1:" + "A" * 43,
            ],
            [
                "relationship",
                "disclose",
                "--requester-being-ref",
                "dm:being:v1:" + "A" * 43,
                "--resource-ref",
                "dm:resource:v1:" + "A" * 43,
                "--operation",
                "read",
                "--classification",
                "shareable",
            ],
            ["tribe", "declare", "--payload", str(document)],
            ["tribe", "invite", "--payload", str(document)],
            ["tribe", "membership-accept", "--payload", str(document)],
            ["tribe", "leave", "--payload", str(document)],
            ["tribe", "expel", "--payload", str(document)],
            ["tribe", "founder-transfer", "--payload", str(document)],
            ["tribe", "founder-accept", "--payload", str(document)],
            ["species", "genesis-ingest", "--artifact", str(document)],
            ["species", "release-ingest", "--artifact", str(document)],
            ["species", "incoming"],
            [
                "species",
                "apply",
                "--operation-id",
                "80000000-0000-4000-8000-000000000006",
                "--snapshot",
                str(document),
            ],
            [
                "species",
                "rollback",
                "--operation-id",
                "80000000-0000-4000-8000-000000000007",
                "--reason",
                "runtime-failure",
                "--snapshot",
                str(document),
            ],
            ["we", "heads"],
            ["we", "projection-receipt", "--receipt", str(document)],
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
            ["we", "event-get", "--event-id", "33000000-0000-4000-8000-000000000026"],
            [
                "we",
                "propose",
                "--kind",
                "configuration.proposed",
                "--subject",
                "selected",
                "--payload",
                str(document),
            ],
            ["we", "projection-get"],
            ["we", "projection-rebuild"],
            [
                "we",
                "converse",
                "--text",
                "hola hermano",
                "--addressee",
                "embodiment:remote",
                "--request-id",
                "80000000-0000-4000-8000-000000000008",
            ],
            ["we", "conversation-page"],
            [
                "sync",
                "request",
                "--sync-request-id",
                "80000000-0000-4000-8000-000000000002",
            ],
            [
                "sync",
                "peer-pull",
                "--sync-request-id",
                "80000000-0000-4000-8000-000000000003",
                "--target-embodiment-id",
                "embodiment:remote",
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
        self.assertEqual(
            methods,
            set(
                CURATOR_METHODS
                | MEMORY_METHODS
                | METHODS
                | PEER_METHODS
                | RELATIONSHIP_METHODS
                | REVIEW_METHODS
                | SCOPE_METHODS
                | SOURCE_METHODS
                | SPECIES_METHODS
            ),
        )

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
        self.assertEqual(len(tools), len(TOOL_CONTRACTS))
        self.assertEqual(
            {item["name"] for item in tools},
            {
                "daimon_status",
                "curator_enqueue",
                "curator_claim",
                "curator_complete",
                "curator_inspect",
                "memory_evaluate",
                "memory_execute",
                "review_request",
                "review_queue",
                "review_inspect",
                "review_decision_draft",
                "review_decision_submit",
                "relationship_accept",
                "relationship_card_publish",
                "relationship_close",
                "relationship_cursor",
                "relationship_disclose",
                "relationship_event_ingest",
                "relationship_grant",
                "relationship_grant_accept",
                "relationship_grant_relinquish",
                "relationship_grant_revoke",
                "relationship_offer",
                "relationship_snapshot",
                "relationship_status",
                "scope_me",
                "scope_we",
                "scope_we_diff",
                "scope_we_sync_plan",
                "scope_resolve",
                "scope_tribe",
                "species_genesis_ingest",
                "species_release_ingest",
                "species_incoming",
                "species_apply",
                "species_rollback",
                "source_content_put",
                "source_claim",
                "source_assess",
                "source_publication_append",
                "source_import_decide",
                "source_status",
                "source_cursor_create",
                "source_diff",
                "source_incoming",
                "source_pull",
                "source_promote",
                "source_projection",
                "tribe_declare",
                "tribe_expel",
                "tribe_founder_accept",
                "tribe_founder_transfer",
                "tribe_invite",
                "tribe_leave",
                "tribe_membership_accept",
                "we_heads",
                "we_event_get",
                "we_propose",
                "we_projection_receipt",
                "we_diff",
                "we_preview",
                "we_projection_get",
                "we_observe",
                "we_decide",
                "we_projection_rebuild",
                "we_sync_request",
                "we_sync_peer_pull",
                "we_sync_serve",
                "we_sync_pull",
                "we_sync_validate_receipt",
                "we_converse",
                "we_conversation_page",
            },
        )
        self.assertEqual(
            {TOOL_CONTRACTS[item["name"]][0] for item in tools},
            set(
                (
                    CURATOR_METHODS
                    | MEMORY_METHODS
                    | METHODS
                    | PEER_METHODS
                    | RELATIONSHIP_METHODS
                    | REVIEW_METHODS
                    | SCOPE_METHODS
                    | SOURCE_METHODS
                    | SPECIES_METHODS
                )
                - {"review.authorize", "review.revoke", "review.execute"}
            ),
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

    def test_mcp_human_decision_submit_is_structurally_refused(self) -> None:
        response = self.mcp_exchange(
            {
                "jsonrpc": "2.0",
                "id": "review-submit",
                "method": "tools/call",
                "params": {
                    "_meta": META,
                    "name": "review_decision_submit",
                    "arguments": {"decision": {}},
                },
            }
        )
        self.assertEqual(response["error"]["code"], -32600)
        self.assertIn("human-held signing CLI", response["error"]["message"])
        self.assertEqual(self.runtime.service.ledger.rpc_requests(), [])

    def test_mcp_accepts_codex_handshake_without_daemon_dispatch(self) -> None:
        initialize = {
            "jsonrpc": "2.0",
            "id": "codex",
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "codex", "version": "0.146.0"},
            },
        }
        result = self.run_surface(
            "daimon_matrix.mcp_server",
            ["--request-dir", str(self.request_dir)],
            stdin=canonical_bytes(initialize) + b"\n",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        response = json.loads(result.stdout)
        self.assertEqual(response["result"]["protocolVersion"], "2025-06-18")
        self.assertEqual(self.runtime.service.ledger.rpc_requests(), [])

    def test_mcp_rejects_unreviewed_legacy_initialize_without_dispatch(self) -> None:
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

    def test_projection_receipt_cli_mcp_reconcile_real_host_observation(self) -> None:
        self.capability = self.operator_capabilities["weave"]
        config = json.loads(self.config_path.read_bytes())
        config["capability"] = self.capability.descriptor
        self.config_path.write_bytes(canonical_bytes(config))
        service = self.runtime.service
        target = service.ledger.append_local(
            kind="configuration.proposed",
            subject="selected-effect",
            payload={"content_refs": ["a" * 64]},
            signer=service.signer,
            sensitivity="private",
        )
        decision = service.ledger.append_local(
            kind="adoption.decided",
            subject=target["subject"],
            payload={
                "target_event_id": target["event_id"],
                "decision": "adopt",
                "reason": "Fixture-owned selected effect",
            },
            signer=service.signer,
            causal_parents=[target["event_id"]],
            sensitivity="private",
        )
        effect_id = "38200000-0000-4000-8000-000000000075"
        intent = {"selection_sha256": "a" * 64}
        self.projection_intents[effect_id] = intent
        postcondition = {"materialized": True, "revision": 1}
        self.projection_posts.write_bytes(canonical_bytes({effect_id: postcondition}))
        now = time.time_ns() // 1_000_000
        receipt = create_effect_receipt(
            effect_id=effect_id,
            target_event_id=target["event_id"],
            decision_event_id=decision["event_id"],
            adapter="fixture-owned-config/v1",
            preview_hash="a" * 64,
            intent_hash=hashlib.sha256(canonical_bytes(intent)).hexdigest(),
            actor=service.origin["principal_id"],
            authority="daimon",
            resource_fence=None,
            result="applied",
            observed_postcondition=postcondition,
            started_at_ms=now,
            completed_at_ms=now,
        )
        document = self.state_root / "effect-receipt.json"
        document.write_bytes(canonical_bytes(receipt))
        token = self.state_root / "effect-retry.json"
        arguments = [
            "--json",
            "--request-file",
            str(token),
            "we",
            "projection-receipt",
            "--receipt",
            str(document),
        ]
        first = self.run_surface("daimon_matrix.cli", arguments)
        self.assertEqual(first.returncode, 0, first.stderr)
        exact_request = token.read_bytes()
        repeated = self.run_surface("daimon_matrix.cli", arguments)
        self.assertEqual(repeated.returncode, 0, repeated.stderr)
        self.assertEqual(token.read_bytes(), exact_request)
        event = json.loads(first.stdout)["response"]["result"]["event"]
        self.assertEqual(
            json.loads(repeated.stdout)["response"]["result"]["event"], event
        )
        response = self.mcp_exchange(
            {
                "jsonrpc": "2.0",
                "id": "projection",
                "method": "tools/call",
                "params": {
                    "_meta": META,
                    "name": "we_projection_receipt",
                    "arguments": {
                        "receipt": receipt,
                        "operation_id": "70000000-0000-4000-8000-000000000075",
                    },
                },
            }
        )
        result = response["result"]["structuredContent"]
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["result"]["event"], event)
        self.assertEqual(len(service.ledger.events()), 3)
        self.projection_posts.write_bytes(
            canonical_bytes({effect_id: {"materialized": True, "revision": 2}})
        )
        changed = self.run_surface("daimon_matrix.cli", arguments)
        self.assertNotEqual(changed.returncode, 0)
        self.assertEqual(
            json.loads(changed.stdout)["response"]["error"]["code"],
            "effect-truth-discrepancy",
        )
        self.assertEqual(len(service.ledger.events()), 3)


class ClientSchemaTests(unittest.TestCase):
    def test_published_surface_counts_match_runtime_constants(self) -> None:
        report = json.loads(
            (ROOT / "docs/verification/dm025-invariants.json").read_bytes()
        )
        cli_methods = (
            CURATOR_METHODS
            | MEMORY_METHODS
            | METHODS
            | PEER_METHODS
            | RELATIONSHIP_METHODS
            | REVIEW_METHODS
            | SCOPE_METHODS
            | SOURCE_METHODS
            | SPECIES_METHODS
        )
        self.assertEqual(report["service_method_count"], len(SERVICE_METHODS))
        self.assertEqual(report["cli_command_count"], len(cli_methods))
        self.assertEqual(report["mcp_tool_count"], len(TOOL_CONTRACTS))

    def test_local_request_schema_covers_exact_service_surface(self) -> None:
        schema = json.loads(
            (ROOT / "schemas/hosted/v1/local-api.schema.json").read_bytes()
        )
        rows = schema["$defs"]["request"]["allOf"][0]["oneOf"]
        methods = [row["properties"]["method"]["const"] for row in rows]
        self.assertEqual(len(methods), len(set(methods)))
        self.assertEqual(set(methods), set(SERVICE_METHODS))

    def test_capability_method_bound_covers_full_service_surface(self) -> None:
        key = b"x" * 32
        methods = [f"method.{index:03d}" for index in range(MAX_CAPABILITY_METHODS)]
        capability = create_capability(
            key,
            client_id="client:dm025-bound",
            methods=methods,
            not_before_ms=0,
            not_after_ms=1,
        )
        schema = json.loads(
            (ROOT / "schemas/hosted/v1/local-api.schema.json").read_bytes()
        )
        Draft202012Validator(schema).validate(capability.descriptor)
        with self.assertRaisesRegex(LocalApiError, "invalid_local_capability"):
            create_capability(
                key,
                client_id="client:dm025-bound",
                methods=[*methods, f"method.{MAX_CAPABILITY_METHODS:03d}"],
                not_before_ms=0,
                not_after_ms=1,
            )

    def test_host_reader_selection_schema_accepts_native_requests_and_is_closed(
        self,
    ) -> None:
        import copy

        from daimon_matrix.local_api import create_request
        from tests.reader_fixtures import reader, reader_v2

        schema = json.loads(
            (ROOT / "schemas/hosted/v1/local-api.schema.json").read_bytes()
        )
        validator = Draft202012Validator(schema)
        capability = create_capability(
            b"r" * 32,
            client_id="client:host:synthetic:receiving-controller",
            methods=["runtime.reader-selection"],
            not_before_ms=0,
            not_after_ms=100,
        )

        def request(params: dict[str, Any]) -> dict[str, Any]:
            return create_request(
                capability,
                request_id="fe5c6192-66cc-4105-b60c-3d871c5a47fe",
                issued_at_ms=10,
                method="runtime.reader-selection",
                params=params,
                nonce=b"n" * 16,
            )

        revoked: dict[str, Any] = {
            "process_instance_id": "92449f17-b5c4-4fbe-b393-d71899304f63",
            "channel_id": "tribe",
            "expected_head": "a" * 64,
            "operation_id": "91a4462c-1b62-4bd2-849d-68ce87649465",
            "release_digest": "b" * 64,
            "phase": "revoke",
            "readers": [],
        }
        selected = {
            **revoked,
            "phase": "select",
            "readers": [reader()],
            "expected_roster_sha256": "c" * 64,
        }
        validator.validate(request(revoked))
        validator.validate(request(selected))
        typed = {
            **selected,
            "schema": "dm.runtime.reader-selection/v2",
            "readers": [reader_v2()],
        }
        validator.validate(request(typed))
        validator.validate(
            request(
                {
                    **typed,
                    "readers": [
                        reader_v2(
                            validity={
                                "mode": "finite",
                                "not_before_ms": 0,
                                "not_after_ms": 100,
                            }
                        )
                    ],
                }
            )
        )
        invalid = [
            {key: value for key, value in revoked.items() if key != "expected_head"},
            {**revoked, "unknown": True},
            {**revoked, "readers": [reader()]},
            {**selected, "readers": [reader(expires_at_ms=True)]},
            {**selected, "readers": [reader(wire_read=["unsupported-wire"])]},
            {
                key: value
                for key, value in typed.items()
                if key != "expected_roster_sha256"
            },
            {**typed, "readers": [reader_v2(expires_at_ms=100)]},
            {
                **typed,
                "readers": [
                    reader_v2(
                        validity={
                            "mode": "until-revoked",
                            "not_before_ms": True,
                        }
                    )
                ],
            },
        ]
        extra = copy.deepcopy(selected)
        extra["readers"][0]["unknown"] = True
        for params in [*invalid, extra]:
            with self.subTest(params=params), self.assertRaises(ValidationError):
                validator.validate(request(params))

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

        client_schema = json.loads(
            (ROOT / "schemas/clients/v1/client.schema.json").read_text(encoding="utf-8")
        )
        capability_schema = json.loads(
            (ROOT / "schemas/hosted/v1/local-api.schema.json").read_text(
                encoding="utf-8"
            )
        )
        registry = Registry().with_resources(
            (document["$id"], Resource.from_contents(document))
            for document in (client_schema, capability_schema)
        )
        origin = {
            "body_ref": "body:dm025-schema",
            "embodiment_id": "embodiment:dm025-schema",
            "incarnation_id": "incarnation:dm025-schema:1",
            "principal_id": "compaii@dm025-schema",
        }
        retired_config = {
            "schema": "dm.local.client-config/v2",
            "capability": create_capability(
                b"v" * 32,
                client_id="client:dm025-schema",
                methods=["runtime.status"],
                not_before_ms=0,
                not_after_ms=1,
            ).descriptor,
            "expected_server": {
                **origin,
                "incarnation_id": "incarnation:dm025-schema:2",
            },
            "historical_servers": [{"server": origin, "retired_at_ms": 1}],
        }
        config_v3 = {
            "schema": CLIENT_CONFIG_SCHEMA_V3,
            "capability": retired_config["capability"],
            "expected_server": retired_config["expected_server"],
            "runtime_id": "dm:runtime:v1:" + "a" * 43,
            "runtime_label": "dm025",
        }
        Draft202012Validator(client_schema, registry=registry).validate(config_v3)
        with self.assertRaises(ValidationError):
            Draft202012Validator(client_schema, registry=registry).validate(
                retired_config
            )
        with self.assertRaises(ValidationError):
            Draft202012Validator(client_schema, registry=registry).validate(
                {**config_v3, "unreviewed": True}
            )


if __name__ == "__main__":
    unittest.main()
