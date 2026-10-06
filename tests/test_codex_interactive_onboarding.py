"""Real file installation keeps the native CLI and existing private state."""

from __future__ import annotations

import argparse
import importlib.util
import os
import stat
import tempfile
import tomllib
import unittest
from pathlib import Path
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "install_codex_identity",
    Path(__file__).resolve().parents[1] / "tools/install_codex_identity.py",
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class InteractiveOnboardingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.home = self.root / ".codex"
        self.home.mkdir()
        self.identity = self.root / "selected-identity.md"
        self.identity.write_text("You are the owner's selected existing daimon body.\n")
        self.config = b"""# Preserve this original in the backup.
model = "old"
[mcp_servers.documentation]
url = "https://example.org/docs"
[projects."/owner/project"]
trust_level = "trusted"
[shell_environment_policy]
inherit = "all"
exclude = ["PRIVATE_TOKEN"]
"""
        (self.home / "config.toml").write_bytes(self.config)
        (self.home / "AGENTS.md").write_text("old context")
        (self.home / "auth.json").write_bytes(b"synthetic authentication: never read")
        (self.home / "history.jsonl").write_bytes(b"synthetic old conversation")
        self.args = argparse.Namespace(
            codex_home=self.home,
            identity_file=self.identity,
            soul=None,
            foundation=None,
            memory_access=None,
            model="owner-selected-model",
            reasoning="medium",
            approval="never",
            sandbox="danger-full-access",
            apply=True,
        )

    def test_native_state_and_unrelated_settings_survive(self) -> None:
        report = MODULE.install(self.args)
        self.assertTrue(report["applied"])
        result = tomllib.loads((self.home / "config.toml").read_text())
        prior = tomllib.loads(self.config.decode())
        for name in ("mcp_servers", "projects", "shell_environment_policy"):
            self.assertEqual(result[name], prior[name])
        self.assertEqual(result["approval_policy"], "never")
        self.assertEqual(
            (self.home / "auth.json").read_bytes(),
            b"synthetic authentication: never read",
        )
        self.assertEqual(
            (self.home / "history.jsonl").read_bytes(), b"synthetic old conversation"
        )
        self.assertEqual(
            (Path(report["backup"]) / "config.toml").read_bytes(), self.config
        )
        self.assertEqual((self.home / "AGENTS.md").stat().st_mode & 0o777, 0o600)
        self.assertFalse(MODULE.install(self.args)["changed"])
        instructions = (self.home / "AGENTS.md").read_text()
        self.assertIn("finite, resumable foreground inbox", instructions)
        self.assertIn(
            "selected peer/thread/task until completion or revocation", instructions
        )
        self.assertIn("do not install a background", instructions)

    def test_dry_run_has_no_configuration_effect(self) -> None:
        self.args.apply = False
        self.assertFalse(MODULE.install(self.args)["applied"])
        self.assertEqual((self.home / "config.toml").read_bytes(), self.config)
        self.assertEqual((self.home / "AGENTS.md").read_text(), "old context")

    def test_full_selected_context_is_included_in_order(self) -> None:
        soul = self.root / "SOUL.md"
        soul.write_text("Full owner-selected soul, including its history.")
        self.args.soul = soul
        MODULE.install(self.args)
        text = (self.home / "AGENTS.md").read_text()
        self.assertIn(soul.read_text(), text)
        self.assertLess(
            text.index(soul.read_text()), text.index("Current interactive embodiment")
        )

    def test_oversize_context_refuses_before_replacement(self) -> None:
        self.identity.write_bytes(b"a" * 32768)
        with self.assertRaisesRegex(ValueError, "exceeds_native_bound"):
            MODULE.install(self.args)
        self.assertEqual((self.home / "AGENTS.md").read_text(), "old context")

    def test_symlink_config_is_not_followed(self) -> None:
        config = self.home / "config.toml"
        config.unlink()
        config.symlink_to(self.identity)
        with self.assertRaises(OSError):
            MODULE.install(self.args)
        self.assertTrue(config.is_symlink())

    def test_global_override_refuses_before_identity_or_config_change(self) -> None:
        override = self.home / "AGENTS.override.md"
        override.write_text("Another global identity takes precedence.")
        with self.assertRaisesRegex(ValueError, "override_requires_owner_selection"):
            MODULE.install(self.args)
        self.assertEqual((self.home / "AGENTS.md").read_text(), "old context")
        self.assertEqual((self.home / "config.toml").read_bytes(), self.config)
        self.assertEqual(
            override.read_text(), "Another global identity takes precedence."
        )

    def test_symlink_override_is_not_followed(self) -> None:
        (self.home / "AGENTS.override.md").symlink_to(self.identity)
        with self.assertRaises(OSError):
            MODULE.install(self.args)
        self.assertEqual((self.home / "AGENTS.md").read_text(), "old context")

    def test_partial_write_rolls_back_original_files(self) -> None:
        write = MODULE.atomic_write
        failed = False

        def fail_once(path: Path, raw: bytes) -> None:
            nonlocal failed
            if path == self.home / "config.toml" and not failed:
                failed = True
                raise OSError("synthetic second replacement failure")
            write(path, raw)

        with (
            patch.object(MODULE, "atomic_write", side_effect=fail_once),
            self.assertRaisesRegex(OSError, "synthetic"),
        ):
            MODULE.install(self.args)
        self.assertEqual((self.home / "config.toml").read_bytes(), self.config)
        self.assertEqual((self.home / "AGENTS.md").read_text(), "old context")

    def test_nested_config_roundtrip(self) -> None:
        value = {"a": [{"dotted.key": {"enabled": True}}], "table": {"empty": {}}}
        self.assertEqual(tomllib.loads(MODULE.config_bytes(value).decode()), value)

    def test_backup_names_are_durable_before_first_replacement(self) -> None:
        synced: list[str] = []
        original_sync = os.fsync
        original_write = MODULE.atomic_write

        def sync(fd: int) -> None:
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                synced.append(os.readlink(f"/proc/self/fd/{fd}"))
            original_sync(fd)

        def write(path: Path, raw: bytes) -> None:
            if path == self.home / "AGENTS.md":
                self.assertIn(str(self.home), synced)
                self.assertIn(str(self.home / "identity-install-backups"), synced)
                self.assertTrue(
                    any(
                        Path(p).parent.name == "identity-install-backups"
                        for p in synced
                    )
                )
            original_write(path, raw)

        with (
            patch.object(MODULE.os, "fsync", side_effect=sync),
            patch.object(MODULE, "atomic_write", side_effect=write),
        ):
            MODULE.install(self.args)


if __name__ == "__main__":
    unittest.main()
