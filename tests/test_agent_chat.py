"""Existing-agent attachment, human-request-only, no real participants."""

import argparse
import asyncio
import importlib.util
import json
import tempfile
import time
import unittest
import uuid
from pathlib import Path
from unittest.mock import Mock, patch

import mcp_types as types

from daimon_matrix.agent_chat import AgentChatMcp, bridge, load_binding
from daimon_matrix.canonical import canonical_bytes
from daimon_matrix.client import CLIENT_CONFIG_SCHEMA_V3, ClientConfig, ClientError
from daimon_matrix.local_api import create_capability
from daimon_matrix.service import MESSAGING_METHODS
from tools.install_agent_chat import install


class AgentChatTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        now = time.time_ns() // 1_000_000
        self.cap = create_capability(
            b"a" * 32,
            client_id="client:chat",
            methods=sorted(MESSAGING_METHODS),
            not_before_ms=now - 60000,
            not_after_ms=now + 600000,
        )
        self.config = {
            "schema": CLIENT_CONFIG_SCHEMA_V3,
            "capability": self.cap.descriptor,
            "expected_server": {
                "body_ref": "body:test",
                "principal_id": "test",
                "embodiment_id": "embodiment:test",
                "incarnation_id": "incarnation:test",
            },
            "runtime_id": "dm:runtime:v1:" + "a" * 43,
            "runtime_label": "test",
        }
        self.write("client.json", canonical_bytes(self.config))
        self.write("client.key", b"a" * 32)
        self.args = argparse.Namespace(
            attachment=self.root / "attachment",
            socket=self.root / "matrix.sock",
            client_config=self.root / "client.json",
            client_key=self.root / "client.key",
            incoming=["in"],
            outgoing=["out"],
            hermes_home=self.root / "hermes",
            skills_dir=self.root / "codex-skills",
        )

    def write(self, name, raw):
        path = self.root / name
        path.write_bytes(raw)
        path.chmod(0o600)
        return path

    def setup_binding(self):
        install(self.args)
        return load_binding(self.args.attachment / "binding.json")

    def test_install_is_idempotent_no_network_identity_or_daemon(self):
        with patch("socket.socket", side_effect=AssertionError("no network")):
            first = install(self.args)
            self.assertEqual(first, install(self.args))
            self.assertEqual(first["new_daemons"], 0)
            self.assertEqual(first["new_identities"], 0)
            self.assertEqual(list((self.args.attachment / "requests").iterdir()), [])
        hermes = self.args.hermes_home / "skills/daimon-chat"
        codex = self.args.skills_dir / "daimon-chat"
        self.assertEqual(
            (hermes / "SKILL.md").read_bytes(), (codex / "SKILL.md").read_bytes()
        )
        self.assertFalse((self.args.hermes_home / "config.yaml").exists())
        self.assertFalse((self.args.hermes_home / "SOUL.md").exists())

    def test_plugin_registration_never_reads_inbox_or_registers_hooks(self):
        self.setup_binding()
        path = self.args.hermes_home / "plugins/daimon-chat/__init__.py"
        spec = importlib.util.spec_from_file_location("test_chat_plugin", path)
        plugin = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(plugin)
        ctx = Mock()
        with patch.object(
            plugin.subprocess, "run", side_effect=AssertionError("no calls")
        ):
            plugin.register(ctx)
        self.assertEqual(ctx.register_tool.call_count, 5)
        ctx.register_hook.assert_not_called()
        names = {c.kwargs["name"] for c in ctx.register_tool.call_args_list}
        self.assertEqual(
            names,
            {
                "messaging_channels",
                "messaging_inbox",
                "messaging_send",
                "messaging_reply",
                "messaging_delivery",
            },
        )

    def test_plugin_only_explicit_tool_call_uses_stdin_not_shell(self):
        self.setup_binding()
        path = self.args.hermes_home / "plugins/daimon-chat/__init__.py"
        spec = importlib.util.spec_from_file_location("test_chat_plugin_call", path)
        plugin = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(plugin)
        ctx = Mock()
        plugin.register(ctx)
        handler = next(
            c.kwargs["handler"]
            for c in ctx.register_tool.call_args_list
            if c.kwargs["name"] == "messaging_send"
        )
        arguments = {"channel_id": "out", "text": "$(never execute me)"}
        with patch.object(
            plugin.subprocess, "run", return_value=Mock(stdout='{"ok": true}')
        ) as run:
            self.assertTrue(json.loads(handler(arguments))["ok"])
            self.assertNotIn(arguments["text"], run.call_args.args[0])
            self.assertEqual(json.loads(run.call_args.kwargs["input"]), arguments)
            self.assertNotIn("shell", run.call_args.kwargs)

    def test_changed_install_and_symlink_are_refused(self):
        self.setup_binding()
        soul = self.write("hermes/SOUL.md", b"existing identity")
        skill = self.args.skills_dir / "daimon-chat/SKILL.md"
        skill.write_text("user change")
        with self.assertRaises(ValueError):
            install(self.args)
        self.assertEqual(skill.read_text(), "user change")
        self.assertEqual(soul.read_bytes(), b"existing identity")
        binding = self.args.attachment / "binding.json"
        binding.rename(binding.with_suffix(".original"))
        binding.symlink_to(binding.with_suffix(".original"))
        from daimon_matrix.messaging_config import MessagingConfigError

        with self.assertRaises(MessagingConfigError):
            load_binding(binding)

    def test_same_send_id_reuses_exact_request_and_rejects_changed_payload(self):
        binding = self.setup_binding()
        client = Mock()
        client.config = ClientConfig.load(self.args.client_config, self.cap.key)
        from daimon_matrix.client import LocalClient

        real = LocalClient(self.args.socket, client.config)
        client.prepare.side_effect = real.prepare
        client.send.return_value = {"ok": True, "result": {}, "auth": "not-exported"}
        adapter = AgentChatMcp(client, binding)
        arguments = {
            "channel_id": "out",
            "send_id": str(uuid.uuid4()),
            "thread_id": str(uuid.uuid4()),
            "text": "hello",
        }

        def invoke(args):
            return asyncio.run(
                adapter.call_tool(
                    None,
                    types.CallToolRequestParams(name="messaging_send", arguments=args),
                )
            )

        invoke(arguments)
        invoke(arguments)
        self.assertEqual(client.send.call_args_list[0], client.send.call_args_list[1])
        self.assertEqual(client.prepare.call_count, 1)
        with self.assertRaises(ClientError):
            invoke({**arguments, "text": "changed"})
        self.assertEqual(client.send.call_count, 2)
        self.assertEqual(len(list((self.args.attachment / "requests").iterdir())), 1)

    def test_wrong_channel_and_broad_capability_fail_without_io(self):
        from mcp.shared.exceptions import MCPError

        binding = self.setup_binding()
        client = Mock()
        adapter = AgentChatMcp(client, binding)
        with self.assertRaises(MCPError):
            asyncio.run(
                adapter.call_tool(
                    None,
                    types.CallToolRequestParams(
                        name="messaging_inbox", arguments={"channel_id": "other"}
                    ),
                )
            )
        client.send.assert_not_called()
        now = time.time_ns() // 1_000_000
        broad = create_capability(
            b"a" * 32,
            client_id="client:broad",
            methods=["runtime.status"],
            not_before_ms=now - 1000,
            not_after_ms=now + 60000,
        )
        self.config["capability"] = broad.descriptor
        self.write("client.json", canonical_bytes(self.config))
        with self.assertRaisesRegex(ValueError, "messaging_only"):
            bridge(binding)


if __name__ == "__main__":
    unittest.main()
