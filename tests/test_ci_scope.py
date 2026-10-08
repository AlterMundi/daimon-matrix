"""CI cannot classify runtime, custody, dependency or contract changes as tools."""

import subprocess
import unittest
from unittest.mock import patch

from tools.ci_scope import profile, select


class CIScopeTests(unittest.TestCase):
    def test_native_peer_tool_and_its_ci_have_a_focused_profile(self):
        self.assertEqual(
            profile(
                [
                    "tools/chat_link.py",
                    "tests/test_chat_link.py",
                    "tests/test_chat_host.py",
                ]
            ),
            "peer",
        )
        self.assertEqual(
            profile(
                [
                    "tools/ci_scope.py",
                    "tests/test_ci_scope.py",
                    ".github/workflows/tests.yml",
                ]
            ),
            "peer",
        )

    def test_unknown_and_empty_changes_keep_full_qualification(self):
        for path in (
            "src/daimon_matrix/daemon.py",
            "requirements-dev.txt",
            "specs/DM-041.md",
            "docs/foundation/daimon-matrix.md",
            "src/daimon_matrix/chat_host.py",
            "tools/prepare_chat_identity.py",
        ):
            with self.subTest(path=path):
                self.assertEqual(profile(["tools/chat_link.py", path]), "full")
        self.assertEqual(profile([]), "full")

    def test_messaging_core_and_derived_package_evidence_run_messaging_checks(self):
        changes = [
            "src/daimon_matrix/messaging.py",
            "tools/chat_link.py",
            "tests/test_chat_link.py",
            "provenance/hermes-agent-0.19.0.json",
            "vectors/hermes/v1/index.json",
            "vectors/hermes/v1/valid/launch-receipt.json",
            "vectors/hermes/v1/valid/profile-manifest.json",
        ]
        self.assertEqual(profile(changes), "messaging")
        self.assertEqual(profile(["provenance/hermes-agent-0.19.0.json"]), "full")
        for path in (
            "src/daimon_matrix/runtime.py",
            "src/daimon_matrix/identity.py",
            "src/daimon_matrix/relationship_store.py",
            "pyproject.toml",
            "specs/tribe-relationships.md",
            "tools/generate_dm041_vectors.py",
        ):
            with self.subTest(path=path):
                self.assertEqual(profile([*changes, path]), "full")

    def test_missing_base_and_failed_observation_keep_full_qualification(self):
        with patch("tools.ci_scope.subprocess.run") as run:
            self.assertEqual(select(""), "full")
            self.assertEqual(select("0" * 40), "full")
            run.assert_not_called()
            run.return_value = subprocess.CompletedProcess(
                [], 1, "tools/chat_link.py\n"
            )
            self.assertEqual(select("missing"), "full")

    def test_renamed_runtime_is_not_hidden_by_a_peer_destination(self):
        with patch("tools.ci_scope.subprocess.run") as run:
            run.return_value = subprocess.CompletedProcess(
                [], 0, "src/daimon_matrix/runtime.py\ntools/chat_link.py\n"
            )
            self.assertEqual(select("base"), "full")
            self.assertIn("--no-renames", run.call_args.args[0])
