"""CI cannot classify runtime, custody, dependency or contract changes as tools."""

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools.ci_scope import profile, select


class CIScopeTests(unittest.TestCase):
    def test_mirror_boundary_correction_uses_installed_visibility_only(self):
        changed = [
            "src/daimon_matrix/telegram_mirror.py",
            "tests/test_telegram_mirror.py",
            "tools/ci_scope.py",
            "tests/test_ci_scope.py",
            "provenance/hermes-agent-0.19.0.json",
            "vectors/hermes/v1/index.json",
            "vectors/hermes/v1/valid/launch-receipt.json",
            "vectors/hermes/v1/valid/profile-manifest.json",
            ".github/workflows/tests.yml",
        ]
        self.assertEqual(profile(changed), "mirror")
        for path in (
            "src/daimon_matrix/messaging.py",
            "src/daimon_matrix/messaging_store.py",
            "src/daimon_matrix/runtime.py",
            "src/daimon_matrix/keystore.py",
            "pyproject.toml",
            "unknown.py",
        ):
            with self.subTest(path=path):
                self.assertEqual(profile([*changed, path]), "full")

    def test_operator_presentation_correction_runs_installed_visibility_checks(self):
        changed = [
            "src/daimon_matrix/operator_messaging.py",
            "tests/test_operator_messaging.py",
            "provenance/hermes-agent-0.19.0.json",
            "vectors/hermes/v1/index.json",
            "vectors/hermes/v1/valid/launch-receipt.json",
            "vectors/hermes/v1/valid/profile-manifest.json",
        ]
        self.assertEqual(profile(changed), "visibility")
        for path in (
            "src/daimon_matrix/keystore.py",
            "src/daimon_matrix/identity.py",
            "pyproject.toml",
            "requirements-dev.txt",
            "specs/DM-051.md",
            "unknown.py",
        ):
            with self.subTest(path=path):
                self.assertEqual(profile([*changed, path]), "full")

    def test_memory_preservation_runs_archive_qualification(self):
        changes = [
            "tools/preserve_memory.py",
            "tests/test_memory_preservation.py",
            "tests/test_dm034_memory_projection.py",
            "docs/runbooks/memory-preservation.md",
            "tools/ci_scope.py",
            "tests/test_ci_scope.py",
            ".github/workflows/tests.yml",
        ]
        self.assertEqual(profile(changes), "archive")
        self.assertEqual(
            profile([*changes, "src/daimon_matrix/memory_projection.py"]), "full"
        )

    def test_protected_archive_qualifies_crypto_without_unchanged_runtime_jobs(self):
        changes = [
            "tools/export_being.py",
            "tools/protected_being.py",
            "tools/receive_being.py",
            "tests/test_being_receive.py",
            "tests/test_being_protection.py",
            "tests/test_ci_scope.py",
            "tools/ci_scope.py",
            ".github/workflows/tests.yml",
        ]
        self.assertEqual(profile(changes), "protected-archive")
        self.assertEqual(profile([*changes, "pyproject.toml"]), "full")
        self.assertEqual(profile([*changes, "src/daimon_matrix/keystore.py"]), "full")

    def test_archive_scanner_keeps_own_export_receive_boundary(self):
        changes = [
            "tools/export_being.py",
            "tests/test_being_export.py",
            "tools/ci_scope.py",
            "tests/test_ci_scope.py",
            ".github/workflows/tests.yml",
        ]
        self.assertEqual(profile(changes), "archive")
        self.assertEqual(
            profile([*changes, "tools/receive_being.py"]), "protected-archive"
        )
        for path in (
            "src/daimon_matrix/runtime.py",
            "pyproject.toml",
        ):
            self.assertEqual(profile([*changes, path]), "full")

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

    def test_native_store_and_inspection_regressions_use_installed_messaging_gate(self):
        changed = [
            "src/daimon_matrix/messaging_store.py",
            "tests/test_native_messaging.py",
            "tests/test_messaging_runtime.py",
            "tools/ci_scope.py",
            "tests/test_ci_scope.py",
            ".github/workflows/tests.yml",
        ]
        self.assertEqual(profile(changed), "messaging")
        self.assertEqual(
            profile([*changed, "src/daimon_matrix/messaging.py"]), "messaging"
        )
        for path in (
            "src/daimon_matrix/keystore.py",
            "src/daimon_matrix/relationship_store.py",
            "src/daimon_matrix/runtime.py",
            "requirements-dev.txt",
            "specs/DM-051.md",
            "unknown.py",
        ):
            with self.subTest(path=path):
                self.assertEqual(profile([*changed, path]), "full")

    def test_readable_egress_profile_covers_native_boundaries_but_not_unrelated_changes(
        self,
    ):
        from tools.ci_scope import VISIBILITY_FILES

        changed = sorted(VISIBILITY_FILES)
        self.assertEqual(profile(changed), "visibility")
        for path in (
            "src/daimon_matrix/keystore.py",
            "src/daimon_matrix/identity.py",
            "pyproject.toml",
            "specs/DM-051.md",
            "tools/generate_dm041_vectors.py",
        ):
            self.assertEqual(profile([*changed, path]), "full")
        # An isolated runtime change cannot hide behind the presentation profile.
        self.assertEqual(profile(["src/daimon_matrix/runtime.py"]), "full")

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


class ActualMergeScopeTests(unittest.TestCase):
    def test_stale_event_base_does_not_hide_actual_pr_sdk_changes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            def git(*args):
                return subprocess.run(
                    ["git", "-C", str(root), *args],
                    check=True,
                    capture_output=True,
                    text=True,
                ).stdout.strip()

            def commit(path, text):
                target = root / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(text)
                git("add", path)
                git(
                    "-c",
                    "user.name=Fixture",
                    "-c",
                    "user.email=fixture@example.invalid",
                    "commit",
                    "-qm",
                    text,
                )
                return git("rev-parse", "HEAD")

            git("init", "-q", "-b", "main")
            # Even --no-commit merges require an identity. Keep the fixture
            # independent of any account/global Git configuration in CI.
            git("config", "user.name", "Fixture")
            git("config", "user.email", "fixture@example.invalid")
            stale_base = commit("README.md", "initial")
            git("checkout", "-qb", "feature")
            feature_head = commit("tools/preserve_memory.py", "selected tool change")
            git("checkout", "main")
            current_base = commit(
                "src/daimon_matrix/runtime.py", "unrelated later main change"
            )
            git(
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "merge",
                "--no-ff",
                "feature",
                "-m",
                "synthetic PR merge",
            )
            runner = Path(__file__).resolve().parents[1] / "tools/ci_scope.py"

            def selected(head):
                return subprocess.run(
                    [
                        "python3",
                        str(runner),
                        "--base",
                        stale_base,
                        "--pull-request-head",
                        head,
                    ],
                    cwd=root,
                    check=True,
                    capture_output=True,
                    text=True,
                ).stdout.strip()

            self.assertEqual(selected(feature_head), "profile=archive")
            self.assertEqual(selected(current_base), "profile=full")
            self.assertEqual(selected(""), "profile=full")
            git("checkout", "feature")
            actual_sdk_head = commit(
                "src/daimon_matrix/runtime.py", "actual PR SDK change"
            )
            git("checkout", "main")
            # Both sides change this file: resolve deliberately in the synthetic
            # fixture, retaining the PR head as the merge's actual second parent.
            merge = subprocess.run(
                ["git", "-C", str(root), "merge", "--no-ff", "feature", "--no-commit"],
                capture_output=True,
                text=True,
            )
            self.assertEqual(merge.returncode, 1)
            commit("src/daimon_matrix/runtime.py", "resolved actual SDK change")
            self.assertEqual(selected(actual_sdk_head), "profile=full")
