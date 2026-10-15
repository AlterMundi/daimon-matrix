"""Existing-agent attachment, human-request-only, no real participants."""

import argparse
import asyncio
import hashlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import time
import tomllib
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
from tools.install_agent_chat import install, refresh_guidance


class AgentChatTests(unittest.TestCase):
    def tooling_fixture(
        self, *, disabled=False, binding_filename="binding.json", startup=""
    ):
        self.setup_binding()
        from tools.install_agent_chat import reconcile_tooling

        attachment = self.args.attachment
        mirror = self.args.skills_dir / "daimon-chat/connection.json"
        if binding_filename != "binding.json":
            (attachment / "binding.json").rename(attachment / binding_filename)
            for path in (attachment / "connection.json", mirror):
                value = json.loads(path.read_bytes())
                value["command"][-1] = str(attachment / binding_filename)
                path.write_bytes(canonical_bytes(value))
        old = json.loads((attachment / "connection.json").read_bytes())["command"]
        command = [
            "/selected/python",
            "-B",
            "-I",
            "-S",
            "--binding",
            str(attachment / binding_filename),
        ]
        home = self.root / "codex-home"
        home.mkdir(mode=0o700)
        config = home / "config.toml"
        fragment = (
            f"command = {json.dumps(old[0])}\nargs = {json.dumps([*old[1:], 'mcp'])}\n"
        )
        original = (
            'model = "personal"\n[mcp_servers.other]\ncommand = "/bin/false"\n'
            "[mcp_servers.matrix]\n"
            + fragment
            + 'env = { KEEP = "synthetic" }\ntool_timeout_sec = 53.0\n'
            + ("enabled = false\n" if disabled else "")
            + startup
        )
        config.write_text(original)
        config.chmod(0o600)
        protected = [
            self.args.attachment / binding_filename,
            self.args.client_config,
            self.args.client_key,
            self.write("AGENTS.md", b"Personal instructions"),
            self.write("installation.json", b"Original installation receipt"),
        ]
        request = attachment / "requests/pending.json"
        request.write_bytes(b"Original uncertain request")
        request.chmod(0o600)
        protected.append(request)
        preserved = {path: path.read_bytes() for path in protected}

        def writer(codex, candidate_home, selected, **options):
            self.assertNotEqual(candidate_home, home)
            self.assertEqual(selected, [*command, "mcp"])
            replacement = (
                f"command = {json.dumps(command[0])}\n"
                f"args = {json.dumps([*command[1:], 'mcp'])}\n"
            )
            (candidate_home / "config.toml").write_text(
                original.replace(fragment, replacement)
                + (
                    f"startup_timeout_sec = {options['startup_timeout_seconds']}\n"
                    if "startup_timeout_seconds" in options
                    else ""
                )
            )

        operation_id = "operation:" + str(uuid.uuid4())

        def reconcile(**options):
            return reconcile_tooling(
                attachment, command, operation_id, connections=[mirror], **options
            )

        return home, config, mirror, command, preserved, writer, reconcile

    def test_tooling_adopts_existing_owner_binding_without_renaming_or_replaying(self):
        home, config, mirror, command, preserved, writer, reconcile = (
            self.tooling_fixture(binding_filename="owner-binding.json")
        )
        with (
            patch.dict(os.environ, {"CODEX_HOME": str(home)}),
            patch("tools.install_agent_chat.shutil.which", return_value="/codex"),
            patch(
                "tools.install_agent_chat._write_codex_role", side_effect=writer
            ) as run,
        ):
            result = reconcile()
            self.assertEqual(result["status"], "configured")
            self.assertEqual(reconcile(), result)
            self.assertEqual(run.call_count, 1)
        self.assertFalse((self.args.attachment / "binding.json").exists())
        self.assertEqual(preserved, {p: p.read_bytes() for p in preserved})
        self.assertEqual(json.loads(mirror.read_bytes())["command"], command)
        self.assertIn("owner-binding.json", config.read_text())

    def test_tooling_startup_default_preserves_explicit_budgets_and_restrictions(self):
        for startup, key, value in (
            ("", "startup_timeout_sec", 60.0),
            ("startup_timeout_sec = 7.0\n", "startup_timeout_sec", 7.0),
            ("startup_timeout_ms = 8000\n", "startup_timeout_ms", 8000),
        ):
            with self.subTest(startup=startup):
                home, config, _, _, _, writer, reconcile = self.tooling_fixture(
                    disabled=True,
                    startup=startup + 'enabled_tools = ["messaging_inbox"]\n',
                )
                with (
                    patch.dict(os.environ, {"CODEX_HOME": str(home)}),
                    patch(
                        "tools.install_agent_chat.shutil.which", return_value="/codex"
                    ),
                    patch(
                        "tools.install_agent_chat._write_codex_role", side_effect=writer
                    ) as run,
                ):
                    first = reconcile()
                    after = config.read_bytes()
                    self.assertEqual(reconcile(), first)
                    self.assertEqual(run.call_count, 1)
                    self.assertEqual(config.read_bytes(), after)
                role = tomllib.loads(after.decode())["mcp_servers"]["matrix"]
                self.assertEqual(role[key], value)
                self.assertEqual(role["enabled_tools"], ["messaging_inbox"])
                self.assertFalse(role["enabled"])
                if key == "startup_timeout_ms":
                    self.assertNotIn("startup_timeout_sec", role)
                # Each subcase owns its private synthetic tree.
                self.tearDown()
                self.setUp()

    def test_tooling_cannot_switch_existing_binding_or_request_history(self):
        home, config, mirror, command, preserved, writer, reconcile = (
            self.tooling_fixture(binding_filename="owner-binding.json")
        )
        attachment = self.args.attachment
        alternate = json.loads((attachment / "owner-binding.json").read_bytes())
        requests = attachment / "different-requests"
        requests.mkdir(mode=0o700)
        alternate["request_dir"] = str(requests)
        path = attachment / "binding.json"
        path.write_bytes(canonical_bytes(alternate))
        path.chmod(0o600)
        command[-1] = str(path)
        before = {
            p: p.read_bytes() for p in (config, mirror, attachment / "connection.json")
        }
        with (
            patch.dict(os.environ, {"CODEX_HOME": str(home)}),
            patch("tools.install_agent_chat.shutil.which", return_value="/codex"),
            patch(
                "tools.install_agent_chat._write_codex_role", side_effect=writer
            ) as run,
        ):
            with self.assertRaisesRegex(ValueError, "tooling_connection_invalid"):
                reconcile()
            run.assert_not_called()
        self.assertEqual(before, {p: p.read_bytes() for p in before})
        self.assertEqual(preserved, {p: p.read_bytes() for p in preserved})

    def test_tooling_private_preparation_cannot_publish_after_owner_deadline(self):
        home, config, mirror, _command, preserved, writer, reconcile = (
            self.tooling_fixture()
        )
        connection = self.args.attachment / "connection.json"
        before = {p: p.read_bytes() for p in (connection, mirror, config)}
        clock = [1]

        def late_writer(*args, **options):
            self.assertGreater(options["timeout_seconds"], 0)
            self.assertLess(options["timeout_seconds"], 30)
            writer(*args, **options)
            clock[0] = 101

        with (
            patch.dict(os.environ, {"CODEX_HOME": str(home)}),
            patch(
                "tools.install_agent_chat.time.monotonic_ns",
                side_effect=lambda: clock[0],
            ),
            patch("tools.install_agent_chat.shutil.which", return_value="/codex"),
            patch(
                "tools.install_agent_chat._write_codex_role", side_effect=late_writer
            ) as run,
        ):
            with self.assertRaisesRegex(ValueError, "tooling_deadline_expired"):
                reconcile(deadline_ns=100)
            self.assertEqual({p: p.read_bytes() for p in before}, before)
            self.assertEqual(reconcile(deadline_ns=200)["status"], "configured")
            self.assertEqual(run.call_count, 1)
        self.assertEqual({p: p.read_bytes() for p in preserved}, preserved)

    def test_tooling_slow_temporary_write_cannot_publish_after_deadline(self):
        from tools import install_agent_chat as installer

        home, config, mirror, _command, preserved, writer, reconcile = (
            self.tooling_fixture()
        )
        connection = self.args.attachment / "connection.json"
        before = {p: p.read_bytes() for p in (connection, mirror, config)}
        clock = [1]
        put = installer._put

        def late_put(path, raw):
            put(path, raw)
            if path.name.startswith(".matrix-tooling-"):
                clock[0] = 101

        with (
            patch.dict(os.environ, {"CODEX_HOME": str(home)}),
            patch(
                "tools.install_agent_chat.time.monotonic_ns",
                side_effect=lambda: clock[0],
            ),
            patch("tools.install_agent_chat.shutil.which", return_value="/codex"),
            patch(
                "tools.install_agent_chat._write_codex_role", side_effect=writer
            ) as run,
            patch("tools.install_agent_chat._put", side_effect=late_put),
        ):
            with self.assertRaisesRegex(ValueError, "tooling_deadline_expired"):
                reconcile(deadline_ns=100)
            self.assertEqual({p: p.read_bytes() for p in before}, before)
            self.assertEqual(reconcile(deadline_ns=200)["status"], "configured")
            self.assertEqual(run.call_count, 1)
        self.assertEqual({p: p.read_bytes() for p in preserved}, preserved)

    def test_tooling_adoption_reconciles_each_lost_file_reply_without_repreparation(
        self,
    ):
        home, config, mirror, command, preserved, writer, reconcile = (
            self.tooling_fixture()
        )
        connection = self.args.attachment / "connection.json"
        replace = os.replace
        pending = {connection, mirror, config}

        def lose_reply(source, target):
            replace(source, target)
            if target in pending:
                pending.remove(target)
                raise OSError("lost reply after owned replacement")

        from tools import install_agent_chat as installer

        put = installer._put

        def lose_preparation(path, raw):
            put(path, raw)
            if path.name == "2.after":
                raise OSError("lost reply after private preparation")

        with (
            patch.dict(os.environ, {"CODEX_HOME": str(home)}),
            patch("tools.install_agent_chat.shutil.which", return_value="/codex"),
            patch(
                "tools.install_agent_chat._write_codex_role", side_effect=writer
            ) as run,
        ):
            with (
                patch("tools.install_agent_chat._put", side_effect=lose_preparation),
                self.assertRaisesRegex(OSError, "private preparation"),
            ):
                reconcile()
            with patch("tools.install_agent_chat.os.replace", side_effect=lose_reply):
                for _ in range(3):
                    with self.assertRaisesRegex(OSError, "lost reply"):
                        reconcile()
            self.assertEqual(pending, set())
            result = reconcile()
            selected = {p: p.read_bytes() for p in (connection, mirror, config)}
            self.assertEqual(reconcile(), result)
            self.assertEqual(selected, {p: p.read_bytes() for p in selected})
            self.assertEqual(run.call_count, 1)
            with self.assertRaises(ValueError):
                installer.reconcile_tooling(
                    self.args.attachment,
                    ["/different/python", *command[1:]],
                    result["operation_id"],
                    connections=[mirror],
                )
            self.assertEqual(selected, {p: p.read_bytes() for p in selected})
        self.assertEqual(result["status"], "configured")
        self.assertEqual(result["catalog_acceptance"], "unobserved")
        self.assertEqual(json.loads(connection.read_bytes())["command"], command)
        self.assertEqual(preserved, {p: p.read_bytes() for p in preserved})

    def test_tooling_adoption_refuses_intervening_config_edit_before_connection_writes(
        self,
    ):
        home, config, mirror, _, preserved, writer, reconcile = self.tooling_fixture()
        connections = [self.args.attachment / "connection.json", mirror]
        before = {p: p.read_bytes() for p in connections}

        def edited(*args, **options):
            writer(*args, **options)
            config.write_text(config.read_text().replace('"personal"', '"owner-edit"'))

        with (
            patch.dict(os.environ, {"CODEX_HOME": str(home)}),
            patch("tools.install_agent_chat.shutil.which", return_value="/codex"),
            patch("tools.install_agent_chat._write_codex_role", side_effect=edited),
            self.assertRaisesRegex(ValueError, "tooling_conflict"),
        ):
            reconcile()
        self.assertIn('"owner-edit"', config.read_text())
        self.assertEqual(before, {p: p.read_bytes() for p in connections})
        self.assertEqual(preserved, {p: p.read_bytes() for p in preserved})

    def test_tooling_adoption_preserves_disabled_role_and_reports_it(self):
        home, config, _, _, _, writer, reconcile = self.tooling_fixture(disabled=True)
        with (
            patch.dict(os.environ, {"CODEX_HOME": str(home)}),
            patch("tools.install_agent_chat.shutil.which", return_value="/codex"),
            patch("tools.install_agent_chat._write_codex_role", side_effect=writer),
        ):
            self.assertEqual(reconcile()["status"], "disabled")
            self.assertIn("enabled = false", config.read_text())

    def test_tooling_adoption_refuses_unrelated_native_role_without_mutation(self):
        home, config, mirror, _, _, _, reconcile = self.tooling_fixture()
        config.write_text(config.read_text().replace('"mcp"', '"other-command"'))
        before = {
            p: p.read_bytes()
            for p in (config, mirror, self.args.attachment / "connection.json")
        }
        with (
            patch.dict(os.environ, {"CODEX_HOME": str(home)}),
            patch("tools.install_agent_chat._write_codex_role") as run,
            self.assertRaisesRegex(ValueError, "codex_mcp_conflict"),
        ):
            reconcile()
        run.assert_not_called()
        self.assertEqual(before, {p: p.read_bytes() for p in before})

    def test_native_writer_bounds_stalled_input_and_reaps_after_close_failure(self):
        from tools.install_agent_chat import _write_codex_role

        real_popen = subprocess.Popen
        for fault in ("stdin-stall", "close-failure"):
            with self.subTest(fault=fault):
                home = self.root / fault
                home.mkdir(mode=0o700)
                stub = home / "codex"
                stub.write_text(
                    f"#!{sys.executable}\n"
                    "import json,os,sys,time\n"
                    "from pathlib import Path\n"
                    "for raw in sys.stdin:\n"
                    " value=json.loads(raw)\n"
                    " if 'id' not in value:continue\n"
                    " method=value['method'];result={}\n"
                    " if method=='config/read':\n"
                    "  result={'layers':[{'name':{'type':'user','file':"
                    "str(Path(os.environ['CODEX_HOME'])/'config.toml')},'version':'one'}]}\n"
                    " print(json.dumps({'id':value['id'],'result':result}),"
                    "flush=True)\n"
                    + (
                        " if method=='config/read':time.sleep(60)\n"
                        if fault == "stdin-stall"
                        else " if method=='config/batchWrite':break\n"
                    )
                )
                stub.chmod(0o700)
                processes = []

                def start(*args, selected_fault=fault, started=processes, **kwargs):
                    process = real_popen(*args, **kwargs)
                    started.append(process)
                    if selected_fault == "close-failure":
                        from types import SimpleNamespace

                        stream = process.stdin

                        def close():
                            stream.close()
                            raise BrokenPipeError("synthetic close failure")

                        process.stdin = SimpleNamespace(
                            fileno=stream.fileno, close=close
                        )
                    return process

                with patch(
                    "tools.install_agent_chat.subprocess.Popen", side_effect=start
                ):
                    before = time.monotonic()
                    if fault == "stdin-stall":
                        with self.assertRaisesRegex(ValueError, "registration_failed"):
                            _write_codex_role(
                                str(stub),
                                home,
                                ["x" * 1024 * 1024],
                                timeout_seconds=0.5,
                            )
                    else:
                        _write_codex_role(
                            str(stub),
                            home,
                            ["/synthetic/python"],
                            startup_timeout_seconds=60,
                        )
                    self.assertLess(time.monotonic() - before, 5)
                self.assertEqual(len(processes), 1)
                self.assertIsNotNone(processes[0].poll())

    def test_codex_existing_command_receives_missing_startup_default_once(self):
        from tools.install_agent_chat import register_codex_mcp

        home = self.root / "codex-home"
        home.mkdir(mode=0o700)
        config = home / "config.toml"
        original = '[mcp_servers.matrix]\ncommand = "/python"\nargs = ["mcp"]\n'
        config.write_text(original)
        config.chmod(0o600)

        def writer(codex, candidate_home, command, **options):
            self.assertEqual(options["startup_timeout_seconds"], 60.0)
            (candidate_home / "config.toml").write_text(
                original + "startup_timeout_sec = 60.0\n"
            )

        with (
            patch.dict(os.environ, {"CODEX_HOME": str(home)}),
            patch("tools.install_agent_chat.shutil.which", return_value="/codex"),
            patch(
                "tools.install_agent_chat._write_codex_role", side_effect=writer
            ) as run,
        ):
            first = register_codex_mcp(self.root / "attachment", ["/python", "mcp"])
            self.assertEqual(
                (Path(first["history"]) / "config.before.toml").read_text(), original
            )
            register_codex_mcp(self.root / "attachment", ["/python", "mcp"])
            self.assertEqual(run.call_count, 1)

    def test_codex_candidate_refusal_never_changes_real_config_on_retry(self):
        from tools.install_agent_chat import register_codex_mcp

        home = self.root / "codex-home"
        home.mkdir(mode=0o700)
        config = home / "config.toml"
        original = '[mcp_servers.memory]\ncommand = "memory"\nenabled = true\n'
        config.write_text(original)
        config.chmod(0o600)

        def writer(codex, candidate_home, selected_command, **options):
            staged = candidate_home / "config.toml"
            self.assertEqual(staged.read_text(), original)
            self.assertNotEqual(staged, config)
            staged.write_text(
                original.replace("enabled = true\n", "")
                + '[mcp_servers.matrix]\ncommand = "/python"\nargs = ["mcp"]\n'
                "startup_timeout_sec = 60.0\n"
            )
            return Mock(returncode=0)

        with (
            patch.dict(os.environ, {"CODEX_HOME": str(home)}),
            patch("tools.install_agent_chat.shutil.which", return_value="/codex"),
            patch(
                "tools.install_agent_chat._write_codex_role", side_effect=writer
            ) as run,
        ):
            for _ in range(2):
                with self.assertRaisesRegex(ValueError, "configuration_conflict"):
                    register_codex_mcp(self.root / "attachment", ["/python", "mcp"])
                self.assertEqual(config.read_text(), original)
            self.assertEqual(run.call_count, 2)

    def test_codex_missing_home_under_symlink_never_invokes_writer(self):
        from tools.install_agent_chat import register_codex_mcp

        real = self.root / "real"
        real.mkdir(mode=0o700)
        link = self.root / "link"
        link.symlink_to(real, target_is_directory=True)
        with (
            patch.dict(os.environ, {"CODEX_HOME": str(link / "missing")}),
            patch("tools.install_agent_chat._write_codex_role") as run,
            self.assertRaises(ValueError),
        ):
            register_codex_mcp(self.root / "attachment", ["/python", "mcp"])
        run.assert_not_called()
        self.assertFalse((real / "missing" / "config.toml").exists())

    def test_codex_lost_publication_reply_reconciles_without_rewriting(self):
        from tools.install_agent_chat import register_codex_mcp

        home = self.root / "codex-home"
        home.mkdir(mode=0o700)
        config = home / "config.toml"
        original = 'model = "preserved"\n'
        config.write_text(original)
        config.chmod(0o600)
        candidate = (
            original + '[mcp_servers.matrix]\ncommand = "/python"\nargs = ["mcp"]\n'
            "startup_timeout_sec = 60.0\n"
        )

        def writer(codex, candidate_home, selected_command, **options):
            (candidate_home / "config.toml").write_text(candidate)
            return Mock(returncode=0)

        replace = os.replace

        def lost_reply(source, target):
            replace(source, target)
            raise OSError("synthetic reply lost after publication")

        with (
            patch.dict(os.environ, {"CODEX_HOME": str(home)}),
            patch("tools.install_agent_chat.shutil.which", return_value="/codex"),
            patch(
                "tools.install_agent_chat._write_codex_role", side_effect=writer
            ) as run,
        ):
            with (
                patch("tools.install_agent_chat.os.replace", side_effect=lost_reply),
                self.assertRaisesRegex(OSError, "reply lost"),
            ):
                register_codex_mcp(self.root / "attachment", ["/python", "mcp"])
            self.assertEqual(config.read_text(), candidate)
            history = self.root / "attachment" / "codex-mcp-history"
            saved = list(history.iterdir())
            self.assertEqual(len(saved), 1)
            self.assertEqual((saved[0] / "config.before.toml").read_text(), original)
            self.assertEqual(
                (saved[0] / "config.candidate.toml").read_text(), candidate
            )
            self.assertEqual(
                register_codex_mcp(self.root / "attachment", ["/python", "mcp"])[
                    "status"
                ],
                "configured",
            )
            self.assertEqual(run.call_count, 1)

    def test_codex_intervening_owner_edit_is_not_overwritten(self):
        from tools.install_agent_chat import register_codex_mcp

        home = self.root / "codex-home"
        home.mkdir(mode=0o700)
        config = home / "config.toml"
        original = 'model = "original"\n'
        intervening = 'model = "owner-change"\n'
        config.write_text(original)
        config.chmod(0o600)

        def writer(codex, candidate_home, selected_command, **options):
            staged = candidate_home / "config.toml"
            staged.write_text(
                original + '[mcp_servers.matrix]\ncommand = "/python"\nargs = ["mcp"]\n'
                "startup_timeout_sec = 60.0\n"
            )
            config.write_text(intervening)
            return Mock(returncode=0)

        with (
            patch.dict(os.environ, {"CODEX_HOME": str(home)}),
            patch("tools.install_agent_chat.shutil.which", return_value="/codex"),
            patch("tools.install_agent_chat._write_codex_role", side_effect=writer),
            self.assertRaisesRegex(ValueError, "configuration_changed"),
        ):
            register_codex_mcp(self.root / "attachment", ["/python", "mcp"])
        self.assertEqual(config.read_text(), intervening)

    def test_codex_role_replacement_requires_exact_reviewed_predecessor(self):
        from tools.install_agent_chat import register_codex_mcp

        home = self.root / "codex-home"
        home.mkdir(mode=0o700)
        config = home / "config.toml"
        original = '[mcp_servers.matrix]\ncommand = "/old/python"\nargs = ["mcp"]\n'
        config.write_text(original)
        config.chmod(0o600)
        previous = hashlib.sha256(
            canonical_bytes({"command": "/old/python", "args": ["mcp"]})
        ).hexdigest()

        def writer(codex, candidate_home, selected_command, **options):
            staged = candidate_home / "config.toml"
            staged.write_text(
                original.replace("/old/python", "/new/python")
                + "startup_timeout_sec = 60.0\n"
            )
            return Mock(returncode=0)

        with (
            patch.dict(os.environ, {"CODEX_HOME": str(home)}),
            patch(
                "tools.install_agent_chat.shutil.which", return_value="/existing/codex"
            ),
            patch(
                "tools.install_agent_chat._write_codex_role", side_effect=writer
            ) as run,
        ):
            result = register_codex_mcp(
                self.root / "attachment",
                ["/new/python", "mcp"],
                previous_sha256=previous,
            )
            self.assertEqual(run.call_count, 1)
            self.assertEqual(
                (Path(result["history"]) / "config.before.toml").read_text(), original
            )
            config.write_text(config.read_text() + "enabled = false\n")
            with self.assertRaisesRegex(ValueError, "codex_mcp_disabled"):
                register_codex_mcp(self.root / "attachment", ["/new/python", "mcp"])
            self.assertEqual(run.call_count, 1)

    def test_codex_registration_preserves_other_config_and_exact_role_retries(self):
        from tools.install_agent_chat import register_codex_mcp

        home = self.root / "codex-home"
        home.mkdir(mode=0o700)
        config = home / "config.toml"
        original = (
            'model = "existing"\n[mcp_servers.memory]\ncommand = "memory-reader"\n'
        )
        config.write_text(original)
        config.chmod(0o600)
        command = ["/qualified/python", "-I", "-m", "daimon_matrix.agent_chat", "mcp"]

        def writer(codex, candidate_home, selected_command, **options):
            self.assertEqual(codex, "/existing/codex")
            self.assertEqual(selected_command, command)
            staged = candidate_home / "config.toml"
            staged.write_text(
                original + '\n[mcp_servers.matrix]\ncommand = "/qualified/python"\n'
                'args = ["-I", "-m", "daimon_matrix.agent_chat", "mcp"]\n'
                "startup_timeout_sec = 60.0\n"
            )
            return Mock(returncode=0)

        with (
            patch.dict(os.environ, {"CODEX_HOME": str(home)}),
            patch(
                "tools.install_agent_chat.shutil.which", return_value="/existing/codex"
            ),
            patch(
                "tools.install_agent_chat._write_codex_role", side_effect=writer
            ) as run,
        ):
            installed = register_codex_mcp(self.root / "attachment", command)
            self.assertEqual(installed["status"], "configured")
            self.assertEqual(installed["catalog_acceptance"], "unobserved")
            self.assertEqual(
                (Path(installed["history"]) / "config.before.toml").read_text(),
                original,
            )
            self.assertEqual(
                register_codex_mcp(self.root / "attachment", command)["status"],
                "configured",
            )
            self.assertEqual(run.call_count, 1)
            before_conflict = config.read_bytes()
            with self.assertRaisesRegex(ValueError, "codex_mcp_conflict"):
                register_codex_mcp(self.root / "attachment", ["/another/python", "mcp"])
            self.assertEqual(config.read_bytes(), before_conflict)
            self.assertEqual(run.call_count, 1)

    def test_codex_successor_preserves_optional_settings_and_disabled_intent(self):
        from tools.install_agent_chat import register_codex_mcp

        home = self.root / "codex-home"
        home.mkdir(mode=0o700)
        config = home / "config.toml"
        original = (
            'model = "existing"\n[mcp_servers.matrix]\n'
            'command = "/old/python"\nargs = ["mcp"]\n'
            'env = { KEEP = "synthetic" }\nstartup_timeout_sec = 31.0\n'
            'tool_timeout_sec = 53.0\nenabled_tools = ["messaging_channels"]\n'
        )
        config.write_text(original)
        config.chmod(0o600)
        previous = hashlib.sha256(
            canonical_bytes({"command": "/old/python", "args": ["mcp"]})
        ).hexdigest()

        def writer(codex, candidate_home, command, **options):
            self.assertNotEqual(candidate_home, home)
            self.assertEqual(command, ["/new/python", "mcp"])
            (candidate_home / "config.toml").write_text(
                original.replace("/old/python", "/new/python")
            )

        with (
            patch.dict(os.environ, {"CODEX_HOME": str(home)}),
            patch("tools.install_agent_chat.shutil.which", return_value="/codex"),
            patch(
                "tools.install_agent_chat._write_codex_role", side_effect=writer
            ) as run,
        ):
            register_codex_mcp(
                self.root / "attachment",
                ["/new/python", "mcp"],
                previous_sha256=previous,
            )
            self.assertEqual(
                config.read_text(), original.replace("/old/python", "/new/python")
            )
            config.write_text(config.read_text() + "enabled = false\n")
            disabled = config.read_bytes()
            with self.assertRaisesRegex(ValueError, "codex_mcp_disabled"):
                register_codex_mcp(
                    self.root / "attachment",
                    ["/other/python", "mcp"],
                    previous_sha256=previous,
                )
            self.assertEqual(config.read_bytes(), disabled)
            self.assertEqual(run.call_count, 1)

    def test_native_catalog_has_bound_channels_and_one_logical_send_id(self):
        from daimon_matrix.mcp_server import MESSAGING_TOOL_CONTRACTS

        binding = self.setup_binding()
        adapter = AgentChatMcp(Mock(), binding)
        tools = {
            tool.name: tool
            for tool in asyncio.run(adapter.list_tools(None, None)).tools
        }
        for name in ("messaging_send", "messaging_reply"):
            properties = tools[name].input_schema["properties"]
            self.assertNotIn("operation_id", properties)
            self.assertEqual(
                properties["channel_id"]["enum"], binding["outgoing_channels"]
            )
            self.assertIn("exact arguments", properties["send_id"]["description"])
        self.assertEqual(
            tools["messaging_inbox"].input_schema["properties"]["channel_id"]["enum"],
            binding["incoming_channels"],
        )
        self.assertIn("parent and thread", tools["messaging_reply"].description)
        self.assertIn(
            "without sending it again", tools["messaging_delivery"].description
        )
        # The low-level wire/legacy caller contract is unchanged.
        self.assertIn(
            "operation_id", MESSAGING_TOOL_CONTRACTS["messaging_reply"][1]["properties"]
        )

    def test_cli_argument_errors_are_precise_and_never_construct_a_client(self):
        from types import SimpleNamespace

        from daimon_matrix import agent_chat

        self.setup_binding()
        original = dict(
            channel_id="out",
            received_channel_id="in",
            message_id=str(uuid.uuid4()),
            send_id=str(uuid.uuid4()),
            text="explicit synthetic reply",
        )
        cases = [
            (
                {**original, "operation_id": str(uuid.uuid4())},
                "agent_chat_operation_id_must_match_send_id",
            ),
            ({**original, "send_id": "not-a-uuid"}, "agent_chat_arguments_invalid"),
            ({**original, "text": "e\u0301"}, "invalid_json_document"),
        ]
        for arguments, expected in cases:
            with (
                self.subTest(error=expected),
                patch.object(
                    agent_chat,
                    "bridge",
                    side_effect=AssertionError(
                        "invalid arguments reached native client"
                    ),
                ),
                patch.object(
                    agent_chat.sys,
                    "stdin",
                    SimpleNamespace(buffer=io.BytesIO(json.dumps(arguments).encode())),
                ),
                patch.object(agent_chat.sys, "stdout", io.StringIO()) as output,
            ):
                self.assertEqual(
                    agent_chat.main(
                        [
                            "--binding",
                            str(self.args.attachment / "binding.json"),
                            "call",
                            "messaging_reply",
                        ]
                    ),
                    1,
                )
                self.assertEqual(
                    json.loads(output.getvalue()), {"ok": False, "error": expected}
                )
        # Direct Python callers bypass the CLI's canonical JSON loader.
        with (
            patch.object(agent_chat, "bridge", side_effect=AssertionError("no client")),
            self.assertRaisesRegex(ValueError, "agent_chat_arguments_invalid"),
        ):
            asyncio.run(
                agent_chat.call(
                    load_binding(self.args.attachment / "binding.json"),
                    "messaging_reply",
                    {**original, "text": "e\u0301"},
                )
            )

    def test_cli_preserves_multi_aliases_and_rejects_cross_link_before_client(self):
        from unittest.mock import AsyncMock

        from daimon_matrix import agent_chat

        child = self.setup_binding()
        binding = {
            "schema": agent_chat.MULTI_SCHEMA,
            "links": {"oliva": child, "codex": child},
            "incoming_channels": ["oliva/in", "codex/in"],
            "outgoing_channels": ["oliva/out", "codex/out"],
        }
        adapter = Mock()
        adapter.call_tool = AsyncMock(
            return_value=types.CallToolResult(
                content=[], structured_content={"ok": True}
            )
        )
        reply = dict(
            channel_id="oliva/out",
            received_channel_id="oliva/in",
            message_id=str(uuid.uuid4()),
            send_id=str(uuid.uuid4()),
            text="synthetic retained reply",
        )
        with patch.object(agent_chat, "bridge", return_value=adapter) as make_client:
            for name, arguments in (
                ("messaging_inbox", {"channel_id": "oliva/in"}),
                ("messaging_reply", reply),
            ):
                original = dict(arguments)
                self.assertEqual(
                    asyncio.run(agent_chat.call(binding, name, arguments)), {"ok": True}
                )
                dispatched = adapter.call_tool.call_args.args[1].arguments
                self.assertEqual(dispatched["channel_id"], original["channel_id"])
                self.assertEqual(arguments, original)
            self.assertEqual(make_client.call_count, 2)
            with self.assertRaisesRegex(ValueError, "cross_link_reply_rejected"):
                asyncio.run(
                    agent_chat.call(
                        binding,
                        "messaging_reply",
                        {**reply, "received_channel_id": "codex/in"},
                    )
                )
            self.assertEqual(make_client.call_count, 2)

    def test_messaging_selector_is_closed_typed_and_never_a_telegram_alias(self):
        from mcp.shared.exceptions import MCPError

        from daimon_matrix.mcp_server import _messaging_tool_params

        arguments = dict(
            channel_id="tribe",
            send_id=str(uuid.uuid4()),
            thread_id=str(uuid.uuid4()),
            text="direct",
        )
        selected = {"kind": "being", "being_ref": "dm:being:v1:" + "A" * 43}
        method, params, _ = _messaging_tool_params(
            "messaging_send", {**arguments, "destination": selected}
        )
        self.assertEqual(method, "messaging.send")
        self.assertEqual(params["destination"], selected)
        _, old_params, _ = _messaging_tool_params("messaging_send", arguments)
        self.assertNotIn("destination", old_params)
        for wrong in (
            None,
            "@compaii",
            {"kind": []},
            {**selected, "authority_manifest_hash": "a" * 64},
            {**selected, "being_ref": "@eko"},
            {**selected, "embodiment_id": "unrequested"},
        ):
            with self.subTest(wrong=wrong), self.assertRaises(MCPError):
                _messaging_tool_params(
                    "messaging_send", {**arguments, "destination": wrong}
                )

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

    def test_offline_guidance_refresh_preserves_identity_commands_and_retry_bytes(self):
        self.setup_binding()
        connection_path = self.args.attachment / "connection.json"
        connection = json.loads(connection_path.read_bytes())
        original_command = connection["command"]
        for tool in connection["tools"]:
            tool["description"] = "old guidance"
            for prop in tool["parameters"].get("properties", {}).values():
                prop.pop("description", None)
        connection_path.write_bytes(canonical_bytes(connection))
        skill = self.args.skills_dir / "daimon-chat/SKILL.md"
        skill.write_bytes(b"previous skill version")
        retry = self.args.attachment / "requests/retained.json"
        retry.write_bytes(b"retained exact retry bytes")
        frozen = {
            p: p.read_bytes()
            for p in (
                self.args.attachment / "binding.json",
                self.args.client_config,
                self.args.client_key,
                retry,
            )
        }
        previous = {p: p.read_bytes() for p in (connection_path, skill)}
        self.args.refresh_guidance_plan = self.write(
            "refresh-plan.json",
            canonical_bytes(
                {
                    "schema": "dm.agent-chat.guidance-plan/v1",
                    "files": [
                        {"path": str(p), "sha256": hashlib.sha256(raw).hexdigest()}
                        for p, raw in previous.items()
                    ],
                }
            ),
        )
        with patch("socket.socket", side_effect=AssertionError("no network")):
            result = refresh_guidance(self.args)
        self.assertEqual(result["status"], "refreshed")
        self.assertEqual(result["files"], 2)
        self.assertEqual(
            json.loads(connection_path.read_bytes())["command"], original_command
        )
        self.assertIn(b"human-readable", skill.read_bytes())
        self.assertEqual(frozen, {p: p.read_bytes() for p in frozen})
        history = Path(result["history"])
        self.assertEqual((history / "0.before").read_bytes(), previous[connection_path])
        self.assertEqual((history / "1.before").read_bytes(), previous[skill])
        with self.assertRaisesRegex(ValueError, "guidance_conflict"):
            refresh_guidance(self.args)  # Stale plans cannot overwrite newer bytes.

    def test_guidance_refresh_refuses_changed_schema_before_any_write(self):
        self.setup_binding()
        connection_path = self.args.attachment / "connection.json"
        connection = json.loads(connection_path.read_bytes())
        connection["tools"][1]["parameters"]["properties"]["unauthorized"] = {
            "type": "string"
        }
        connection_path.write_bytes(canonical_bytes(connection))
        raw = connection_path.read_bytes()
        self.args.refresh_guidance_plan = self.write(
            "refresh-plan.json",
            canonical_bytes(
                {
                    "schema": "dm.agent-chat.guidance-plan/v1",
                    "files": [
                        {
                            "path": str(connection_path),
                            "sha256": hashlib.sha256(raw).hexdigest(),
                        },
                    ],
                }
            ),
        )
        with self.assertRaisesRegex(ValueError, "capability_change_refused"):
            refresh_guidance(self.args)
        self.assertEqual(connection_path.read_bytes(), raw)
        self.assertFalse((self.args.attachment / "guidance-history").exists())

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

    def test_multiple_links_route_explicit_calls_without_cross_link_replies(self):
        from unittest.mock import AsyncMock

        from mcp.shared.exceptions import MCPError

        self.setup_binding()
        path = self.write(
            "collection.json",
            canonical_bytes(
                {
                    "schema": "dm.agent-chat.binding/v2",
                    "links": {
                        name: str(self.args.attachment / "binding.json")
                        for name in ("oliva", "codex")
                    },
                }
            ),
        )
        with patch("socket.socket", side_effect=AssertionError("no automatic I/O")):
            binding = load_binding(path)
            adapter = bridge(binding)
        self.assertEqual(binding["incoming_channels"], ["codex/in", "oliva/in"])
        for link in adapter.links.values():
            link.call_tool = AsyncMock(return_value=types.CallToolResult(content=[]))
        asyncio.run(
            adapter.call_tool(
                None,
                types.CallToolRequestParams(
                    name="messaging_inbox", arguments={"channel_id": "oliva/in"}
                ),
            )
        )
        adapter.links["codex"].call_tool.assert_not_called()
        call = adapter.links["oliva"].call_tool.call_args.args[1]
        self.assertEqual(call.arguments["channel_id"], "in")
        with self.assertRaises(MCPError):
            asyncio.run(
                adapter.call_tool(
                    None,
                    types.CallToolRequestParams(
                        name="messaging_reply",
                        arguments={
                            "channel_id": "codex/out",
                            "received_channel_id": "oliva/in",
                            "send_id": str(uuid.uuid4()),
                        },
                    ),
                )
            )
        adapter.links["codex"].call_tool.assert_not_called()

    def test_collection_cannot_mix_runtime_identities_or_recurse(self):
        self.setup_binding()
        collection = self.write(
            "collection.json",
            canonical_bytes(
                {
                    "schema": "dm.agent-chat.binding/v2",
                    "links": {
                        "one": str(self.args.attachment / "binding.json"),
                        "two": str(self.root / "other-binding.json"),
                    },
                }
            ),
        )
        other_config = {**self.config, "runtime_id": "dm:runtime:v1:" + "b" * 43}
        self.write("other-client.json", canonical_bytes(other_config))
        other = load_binding(self.args.attachment / "binding.json")
        other["client_config"] = str(self.root / "other-client.json")
        self.write("other-binding.json", canonical_bytes(other))
        with self.assertRaisesRegex(ValueError, "mixed_identities"):
            load_binding(collection)
        self.write("other-binding.json", collection.read_bytes())
        with self.assertRaisesRegex(ValueError, "nested_binding"):
            load_binding(collection)


if __name__ == "__main__":
    unittest.main()
