"""CI cannot classify runtime, custody, dependency or contract changes as tools."""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools.ci_scope import main, profile, select


class CIScopeTests(unittest.TestCase):
    def test_migration_checks_are_installed_and_combined_admission_keeps_them(self):
        from tools.ci_scope import COMMUNICATION_MIGRATION_FILES

        self.assertEqual(
            profile(list(COMMUNICATION_MIGRATION_FILES)), "communication-migration"
        )
        self.assertEqual(
            profile(
                [
                    *COMMUNICATION_MIGRATION_FILES,
                    "tests/test_group_messaging_runtime.py",
                ]
            ),
            "group-admission",
        )
        self.assertEqual(
            profile([*COMMUNICATION_MIGRATION_FILES, "src/daimon_matrix/keystore.py"]),
            "full",
        )
        workflow = (
            Path(__file__).parents[1] / ".github/workflows/tests.yml"
        ).read_text()
        group = workflow.split("  tribe-group:", 1)[1].split("  human-tribu:", 1)[0]
        self.assertIn("dist/*.whl", group)
        core = group.split("- name: Group delivery", 1)[1].split("- name:", 1)[0]
        self.assertIn("needs.scope.outputs.group_migration_only != 'true'", core)
        migration = group.split(
            "- name: Installed resumable communication migration", 1
        )[1].split("- name:", 1)[0]
        self.assertIn("tests.test_operator_communication_migration", migration)
        self.assertIn("group_admission_checks == 'true'", migration)
        self.assertIn("group_migration_only == 'true'", migration)

    def test_migration_only_reuses_wheel_job_without_unrelated_group_journeys(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "scope-output"
            with (
                patch("tools.ci_scope.select", return_value="communication-migration"),
                patch.object(sys, "argv", ["ci_scope.py", "--base", "base"]),
                patch.dict(os.environ, {"GITHUB_OUTPUT": str(output)}),
            ):
                main()
            selected = dict(
                line.split("=", 1) for line in output.read_text().splitlines()
            )
            self.assertEqual(selected["profile"], "tribe-group")
            self.assertEqual(selected["group_migration_only"], "true")
            self.assertEqual(selected["group_receipt_checks"], "false")
            self.assertNotEqual(selected.get("group_admission_checks"), "true")

    def test_combined_group_and_admission_keeps_both_contract_sets(self):
        changed = [
            "src/daimon_matrix/messaging.py",
            "tests/test_group_messaging_runtime.py",
        ]
        self.assertEqual(profile(changed), "tribe-group")
        for admission in (
            "src/daimon_matrix/operator_messaging.py",
            "src/daimon_matrix/messaging_config.py",
            "tests/test_operator_messaging.py",
            "tests/test_closed_visibility_provisioning.py",
            "tests/test_dm025_cli_mcp.py",
            "schemas/hosted/v1/local-api.schema.json",
        ):
            self.assertEqual(profile([*changed, admission]), "group-admission")
        self.assertEqual(profile([*changed, "src/daimon_matrix/identity.py"]), "full")
        workflow = (
            Path(__file__).parents[1] / ".github/workflows/tests.yml"
        ).read_text()
        group = workflow.split("  tribe-group:", 1)[1].split("  human-tribu:", 1)[0]
        step = group.split(
            "- name: Changed group admission, visibility and native API contracts", 1
        )[1]
        step = step.split("- name:", 1)[0]
        self.assertIn("needs.scope.outputs.group_admission_checks == 'true'", step)
        for module in (
            "tests.test_operator_messaging",
            "tests.test_closed_visibility_provisioning",
            "tests.test_dm025_cli_mcp",
        ):
            self.assertIn(module, step)

    def test_combined_admission_uses_one_existing_installed_group_job(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "scope-output"
            with (
                patch("tools.ci_scope.select", return_value="group-admission"),
                patch.object(sys, "argv", ["ci_scope.py", "--base", "base"]),
                patch.dict(os.environ, {"GITHUB_OUTPUT": str(output)}),
            ):
                main()
            selected = dict(
                line.split("=", 1) for line in output.read_text().splitlines()
            )
            self.assertEqual(selected["profile"], "tribe-group")
            self.assertEqual(selected["group_admission_checks"], "true")
            self.assertNotEqual(selected.get("group_receipt_checks"), "false")

    def test_published_runtime_contract_corrections_keep_installed_native_checks(self):
        paths = [
            "src/daimon_matrix/operator_messaging.py",
            "src/daimon_matrix/messaging_config.py",
            "schemas/hosted/v1/local-api.schema.json",
            "docs/verification/dm025-invariants.json",
            "tests/test_operator_messaging.py",
            "tests/test_dm025_cli_mcp.py",
            "tests/test_closed_visibility_provisioning.py",
        ]
        self.assertEqual(profile(paths), "visibility")
        self.assertEqual(profile([*paths, "src/daimon_matrix/identity.py"]), "full")

    def test_group_admission_uses_existing_installed_visibility_contracts(self):
        changed = [
            "src/daimon_matrix/operator_messaging.py",
            "tests/test_operator_messaging.py",
            "docs/runbooks/group-admission.md",
            "provenance/hermes-agent-0.19.0.json",
            "vectors/hermes/v1/index.json",
            "vectors/hermes/v1/valid/profile-manifest.json",
            "vectors/hermes/v1/valid/launch-receipt.json",
            "tools/ci_scope.py",
            "tests/test_ci_scope.py",
        ]
        self.assertEqual(profile(changed), "visibility")
        for unrelated in (
            "src/daimon_matrix/identity.py",
            "src/daimon_matrix/keystore.py",
            "docs/runbooks/unknown.md",
        ):
            self.assertEqual(profile([*changed, unrelated]), "full")

    def test_native_chat_uses_installed_chat_and_receiving_contracts(self):
        from tools.ci_scope import RECEIVING_CONTROL_FILES

        chat = ["src/daimon_matrix/agent_chat.py", "tests/test_agent_chat.py"]
        self.assertEqual(profile(chat), "visibility")
        self.assertEqual(
            profile([*RECEIVING_CONTROL_FILES, *chat]), "receiving-control"
        )
        self.assertEqual(profile([*chat, "src/daimon_matrix/identity.py"]), "full")
        workflow = (
            Path(__file__).parents[1] / ".github/workflows/tests.yml"
        ).read_text()
        for section, end in (
            ("  visibility:", "  authority-adoption:"),
            ("  tribe-group:", "  human-tribu:"),
        ):
            job = workflow.split(section, 1)[1].split(end, 1)[0]
            self.assertIn("tests.test_agent_chat", job)
            self.assertIn("tests.test_neutral_binding.SkillDiscoveryTests", job)
            self.assertIn("dist/*.whl", job)

    def test_receiving_control_requires_installed_role_and_replay_contracts(self):
        from tools.ci_scope import RECEIVING_CONTROL_FILES

        self.assertEqual(profile(list(RECEIVING_CONTROL_FILES)), "receiving-control")
        self.assertEqual(
            profile(
                [
                    "src/daimon_matrix/operator_runtime_upgrade.py",
                    "tests/test_operator_runtime_upgrade.py",
                    "docs/runbooks/operator-bootstrap.md",
                    "docs/runbooks/operator-capability-upgrade.md",
                ]
            ),
            "receiving-control",
        )
        for unrelated in (
            "src/daimon_matrix/identity.py",
            "src/daimon_matrix/keystore.py",
            "pyproject.toml",
            "unknown.py",
        ):
            self.assertEqual(profile([*RECEIVING_CONTROL_FILES, unrelated]), "full")
        workflow = (
            Path(__file__).parents[1] / ".github/workflows/tests.yml"
        ).read_text()
        group = workflow.split("  tribe-group:", 1)[1].split("  human-tribu:", 1)[0]
        for contract in (
            "tests.test_receiving_runtime",
            "tests.test_dm025_client.LocalClientTests",
            "tests.test_dm079_capability_profiles",
            "tests.test_operator_runtime_upgrade.CurrentCapabilityUpgradeTests",
            "tests.test_dm024_runtime.RuntimeBundleTests",
            "tests.test_dm024_service.HostedServiceTests",
        ):
            self.assertIn(contract, group)
        self.assertIn("needs.scope.outputs.group_receiving_checks == 'true'", group)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "scope-output"
            with (
                patch("tools.ci_scope.select", return_value="receiving-control"),
                patch.object(sys, "argv", ["ci_scope.py", "--base", "base"]),
                patch.dict(os.environ, {"GITHUB_OUTPUT": str(output)}),
            ):
                main()
            selected = dict(
                line.split("=", 1) for line in output.read_text().splitlines()
            )
            self.assertEqual(selected["profile"], "tribe-group")
            self.assertEqual(selected["group_receiving_checks"], "true")
            self.assertNotEqual(selected.get("group_receipt_checks"), "false")

    def test_bounded_group_checks_omit_only_unchanged_receipt_membership_code(self):
        from tools.ci_scope import BOUNDED_GROUP_FILES

        paths = list(BOUNDED_GROUP_FILES)
        self.assertEqual(profile(paths), "bounded-group-transport")
        for changed in (
            "src/daimon_matrix/communication.py",
            "src/daimon_matrix/tribe_conversation.py",
            "tests/test_cross_being_semantic_receipts.py",
        ):
            # This vector also changes messaging_config; once the narrow
            # bounded-transport profile no longer applies, keep its native
            # configuration/admission contracts alongside group and receipts.
            self.assertEqual(profile([*paths, changed]), "group-admission")
        self.assertEqual(profile([*paths, "src/daimon_matrix/identity.py"]), "full")
        workflow = (
            Path(__file__).parents[1] / ".github/workflows/tests.yml"
        ).read_text()
        self.assertIn("needs.scope.outputs.group_receipt_checks != 'false'", workflow)

    def test_group_scope_includes_durable_intake_reader_qualification(self):
        paths = [
            "src/daimon_matrix/messaging.py",
            "src/daimon_matrix/routes.py",
            "src/daimon_matrix/release_compatibility.py",
            "tests/test_group_messaging_runtime.py",
            "tests/test_release_compatibility.py",
            "tests/test_cross_being_semantic_receipts.py",
        ]
        self.assertEqual(profile(paths), "tribe-group")
        workflow = (
            Path(__file__).parents[1] / ".github/workflows/tests.yml"
        ).read_text()
        group = workflow.split("  tribe-group:", 1)[1]
        self.assertIn("tests.test_release_compatibility", group)
        self.assertIn("tests.test_cross_being_semantic_receipts", group)
        self.assertIn("tests.test_dm053_routes.BoundedTransportTests", group)
        self.assertIn("tests.test_dm053_routes.InboxAndProtocolTests", group)

    def test_release_contract_qualifies_installed_codec_without_unchanged_transport(
        self,
    ):
        from tools.ci_scope import RELEASE_COMPATIBILITY_FILES

        self.assertEqual(
            profile(list(RELEASE_COMPATIBILITY_FILES)), "release-compatibility"
        )
        for other in (
            "src/daimon_matrix/messaging.py",
            "src/daimon_matrix/identity.py",
            "src/daimon_matrix/keystore.py",
            "pyproject.toml",
            "requirements-dev.txt",
            "unknown.py",
        ):
            self.assertEqual(profile([*RELEASE_COMPATIBILITY_FILES, other]), "full")
        self.assertEqual(profile(["specs/receiver-compatible-release.md"]), "full")
        root = Path(__file__).resolve().parents[1]
        workflow = (root / ".github/workflows/tests.yml").read_text()
        self.assertIn(
            "if: needs.scope.outputs.profile == 'release-compatibility'", workflow
        )
        self.assertIn("tests.test_release_compatibility", workflow)
        portability = (root / ".github/workflows/telegram-portability.yml").read_text()
        self.assertIn(
            "needs.scope.outputs.profile != 'release-compatibility'", portability
        )

    def test_current_context_docs_do_not_repeat_runtime_qualification(self):
        from tools.ci_scope import CONTEXT_DOC_FILES

        self.assertEqual(profile(list(CONTEXT_DOC_FILES)), "context-docs")
        for other in (
            "src/daimon_matrix/runtime.py",
            "specs/tribe-conversation.md",
            "schemas/unknown.json",
            "docs/unknown.md",
            "pyproject.toml",
        ):
            self.assertEqual(profile([*CONTEXT_DOC_FILES, other]), "full")

    def test_membership_group_qualifies_affected_contracts_once(self):
        from tools.ci_scope import TRIBE_GROUP_FILES

        self.assertEqual(profile(list(TRIBE_GROUP_FILES)), "group-admission")
        for other in (
            "src/daimon_matrix/identity.py",
            "src/daimon_matrix/keystore.py",
            "pyproject.toml",
            "unknown.py",
        ):
            self.assertEqual(profile([*TRIBE_GROUP_FILES, other]), "full")

    def test_authority_adoption_scope_keeps_unknown_contracts_full(self):
        from tools.ci_scope import AUTHORITY_ADOPTION_FILES

        self.assertEqual(profile(list(AUTHORITY_ADOPTION_FILES)), "authority-adoption")
        inspection = [
            "src/daimon_matrix/messaging.py",
            "src/daimon_matrix/messaging_store.py",
            "src/daimon_matrix/messaging_config.py",
            "tests/test_republish_after_advance.py",
        ]
        self.assertEqual(profile(inspection), "authority-adoption")
        self.assertEqual(profile([*inspection, "schemas/unknown.json"]), "full")
        for path in (
            "src/daimon_matrix/identity.py",
            "src/daimon_matrix/authority_epochs.py",
            "src/daimon_matrix/runtime.py",
            "pyproject.toml",
            "unknown.py",
        ):
            self.assertEqual(profile([*AUTHORITY_ADOPTION_FILES, path]), "full")

    def test_resource_doc_scope_is_exact_and_keeps_runtime_changes_full(self):
        from tools.ci_scope import RESOURCE_DOC_FILES

        self.assertEqual(profile(list(RESOURCE_DOC_FILES)), "resource-docs")
        for other in (
            "src/daimon_matrix/service.py",
            "schemas/unknown.json",
            "pyproject.toml",
            "docs/foundation/daimon-matrix.md",
        ):
            self.assertEqual(profile([*RESOURCE_DOC_FILES, other]), "full")
        workflow = (
            Path(__file__).resolve().parents[1] / ".github/workflows/tests.yml"
        ).read_text()
        self.assertIn("if: needs.scope.outputs.profile == 'resource-docs'", workflow)

    def test_human_tribu_scope_is_closed_and_keeps_installed_contracts(self):
        from tools.ci_scope import HUMAN_TRIBU_FILES

        changes = list(HUMAN_TRIBU_FILES)
        self.assertEqual(profile(changes), "human-tribu")
        for other in (
            "src/daimon_matrix/runtime.py",
            "src/daimon_matrix/service.py",
            "pyproject.toml",
            "unknown.py",
        ):
            self.assertEqual(profile([*changes, other]), "full")
        self.assertEqual(profile(["docs/runbooks/tribu-human-mentions.md"]), "full")

    def test_mirror_scope_keeps_portability_skip_and_native_default(
        self,
    ):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "scope-output"
            for selected in ("mirror", "visibility", "full", "messaging"):
                with (
                    self.subTest(selected=selected),
                    patch("tools.ci_scope.select", return_value=selected),
                    patch.object(sys, "argv", ["ci_scope.py", "--base", "base"]),
                    patch.dict(os.environ, {"GITHUB_OUTPUT": str(output)}),
                ):
                    output.write_text("")
                    main()
                    self.assertEqual(
                        output.read_text().splitlines(),
                        [
                            "profile="
                            + ("visibility" if selected == "mirror" else selected),
                            "native_checks="
                            + ("false" if selected == "mirror" else "true"),
                        ],
                    )

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
            "docs/runbooks/tribu-readable-traffic.md",
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
