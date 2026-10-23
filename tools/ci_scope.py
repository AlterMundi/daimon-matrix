"""Select native peer/messaging qualification; unknown changes keep full CI."""

from __future__ import annotations

import argparse
import os
import subprocess
from pathlib import Path

INSTALLER_FILES = frozenset(
    {
        "tools/install_agent_chat.py",
        "tests/test_agent_chat.py",
        "tools/ci_scope.py",
        "tests/test_ci_scope.py",
        ".github/workflows/tests.yml",
    }
)

BEHAVIOR_INVENTORY_FILES = frozenset(
    {
        "tools/behavior_inventory.py",
        "tests/test_behavior_inventory.py",
        "docs/runbooks/same-being-delta.md",
        "tools/ci_scope.py",
        "tests/test_ci_scope.py",
        ".github/workflows/tests.yml",
    }
)

PEER_FILES = frozenset(
    {
        "tools/chat_link.py",
        "tests/test_chat_link.py",
        "tests/test_chat_host.py",
        "tools/ci_scope.py",
        "tests/test_ci_scope.py",
        ".github/workflows/tests.yml",
        ".github/workflows/telegram-portability.yml",
    }
)
MESSAGING_FILES = PEER_FILES | frozenset(
    {
        "src/daimon_matrix/messaging.py",
        "src/daimon_matrix/messaging_store.py",
        "tests/test_native_messaging.py",
        "tests/test_messaging_runtime.py",
        "docs/runbooks/tribu-readable-traffic.md",
        "provenance/hermes-agent-0.19.0.json",
        "vectors/hermes/v1/index.json",
        "vectors/hermes/v1/valid/launch-receipt.json",
        "vectors/hermes/v1/valid/profile-manifest.json",
    }
)
MIRROR_FILES = frozenset(
    {
        ".github/workflows/tests.yml",
        "src/daimon_matrix/telegram_mirror.py",
        "tests/test_telegram_mirror.py",
        "tools/ci_scope.py",
        "tests/test_ci_scope.py",
        "provenance/hermes-agent-0.19.0.json",
        "vectors/hermes/v1/index.json",
        "vectors/hermes/v1/valid/launch-receipt.json",
        "vectors/hermes/v1/valid/profile-manifest.json",
    }
)
VISIBILITY_FILES = MESSAGING_FILES | frozenset(
    {
        "docs/mandatory-telegram-visibility.md",
        "docs/existing-agent-chat.md",
        "docs/multi-agent-chat.md",
        "docs/runbooks/neutral-territory.md",
        "docs/runbooks/tribu-readable-traffic.md",
        "docs/runbooks/group-admission.md",
        "docs/verification/dm025-invariants.json",
        "schemas/hosted/v1/local-api.schema.json",
        "schemas/messaging/v2/echo-proof.schema.json",
        "schemas/messaging/v2/visibility-policy.schema.json",
        "src/daimon_matrix/agent_chat_assets/SKILL.md",
        "src/daimon_matrix/agent_chat.py",
        "src/daimon_matrix/daemon.py",
        "src/daimon_matrix/labels.py",
        "src/daimon_matrix/mandatory_echo.py",
        "src/daimon_matrix/mcp_server.py",
        "src/daimon_matrix/messaging_config.py",
        "src/daimon_matrix/messaging_store.py",
        "src/daimon_matrix/native_egress.py",
        "src/daimon_matrix/routes.py",
        "src/daimon_matrix/neutral_skill_assets/daimon-chat/SKILL.md",
        "src/daimon_matrix/neutral_skill_assets/daimon-chat/agents/openai.yaml",
        "src/daimon_matrix/operator_messaging.py",
        "src/daimon_matrix/runtime.py",
        "src/daimon_matrix/telegram_mirror.py",
        "tests/test_agent_chat.py",
        "tests/test_neutral_binding.py",
        "tests/test_dm053_routes.py",
        "tests/test_labels.py",
        "tests/test_mandatory_echo.py",
        "tests/test_mandatory_echo_integration.py",
        "tests/test_messaging_runtime.py",
        "tests/test_operator_messaging.py",
        "tests/test_dm025_cli_mcp.py",
        "tests/test_closed_visibility_provisioning.py",
        "tests/test_telegram_mirror.py",
        "tools/install_agent_chat.py",
    }
)
ARCHIVE_FILES = frozenset(
    {
        "tools/export_being.py",
        "tests/test_being_export.py",
        "tools/preserve_memory.py",
        "tests/test_memory_preservation.py",
        "tests/test_dm034_memory_projection.py",
        "docs/runbooks/memory-preservation.md",
        "tools/ci_scope.py",
        "tests/test_ci_scope.py",
        ".github/workflows/tests.yml",
    }
)
PROTECTED_FILES = ARCHIVE_FILES | frozenset(
    {
        "tools/protected_being.py",
        "tools/receive_being.py",
        "tests/test_being_receive.py",
        "tests/test_being_protection.py",
    }
)


HUMAN_TRIBU_FILES = MIRROR_FILES | frozenset(
    {
        "src/daimon_matrix/human_tribu.py",
        "src/daimon_matrix/human_tribu_process.py",
        "tests/test_human_tribu.py",
        "tests/test_human_tribu_process.py",
        "docs/runbooks/tribu-human-mentions.md",
        "tests/test_package_scaffold.py",
        "tests/test_dm041_hermes_body.py",
        "tools/reproducible_build.py",
        "tools/check_distribution.py",
        ".github/workflows/telegram-portability.yml",
    }
)


RESOURCE_DOC_FILES = frozenset(
    {
        "docs/resource-access.md",
        "tools/ci_scope.py",
        "tests/test_ci_scope.py",
        ".github/workflows/tests.yml",
    }
)


AUTHORITY_ADOPTION_FILES = frozenset(
    {
        "src/daimon_matrix/operator_messaging.py",
        "src/daimon_matrix/messaging_config.py",
        "src/daimon_matrix/messaging.py",
        "src/daimon_matrix/messaging_store.py",
        "src/daimon_matrix/chat_host.py",
        "src/daimon_matrix/daemon.py",
        "tests/test_operator_messaging.py",
        "tests/test_chat_host.py",
        "tests/test_native_messaging.py",
        "tests/test_republish_after_advance.py",
        "tools/ci_scope.py",
        "tests/test_ci_scope.py",
        ".github/workflows/tests.yml",
        "AGENTS.md",
        "docs/runbooks/receiver-compatible-authority-updates.md",
        "provenance/hermes-agent-0.19.0.json",
        "vectors/hermes/v1/index.json",
        "vectors/hermes/v1/valid/launch-receipt.json",
        "vectors/hermes/v1/valid/profile-manifest.json",
    }
)


COMMUNICATION_MIGRATION_FILES = frozenset(
    {
        "src/daimon_matrix/operator_communication_migration.py",
        "tests/test_operator_communication_migration.py",
        "docs/runbooks/group-admission.md",
        "provenance/hermes-agent-0.19.0.json",
        "vectors/hermes/v1/index.json",
        "vectors/hermes/v1/valid/launch-receipt.json",
        "vectors/hermes/v1/valid/profile-manifest.json",
        "tools/ci_scope.py",
        "tests/test_ci_scope.py",
        ".github/workflows/tests.yml",
    }
)


TRIBE_GROUP_FILES = (
    VISIBILITY_FILES
    | AUTHORITY_ADOPTION_FILES
    | COMMUNICATION_MIGRATION_FILES
    | frozenset(
        {
            "specs/tribe-conversation.md",
            "docs/tribe-group-runtime.md",
            "schemas/messaging/v1/application.schema.json",
            "schemas/messaging/v2/application.schema.json",
            "schemas/messaging/v3/application.schema.json",
            "src/daimon_matrix/communication.py",
            "src/daimon_matrix/relationship_store.py",
            "src/daimon_matrix/scopes.py",
            "src/daimon_matrix/service.py",
            "src/daimon_matrix/tribe_conversation.py",
            "tests/test_group_messaging_runtime.py",
            "tests/test_cross_being_semantic_receipts.py",
            "src/daimon_matrix/release_compatibility.py",
            "tests/test_release_compatibility.py",
            "tests/test_dm051_sealed.py",
            "tests/test_dm052_communication.py",
            "tests/test_dm054_scopes.py",
            "tests/test_dm082_relationships.py",
            "tests/test_dm091_tribe_policy.py",
        }
    )
)


CONTEXT_DOC_FILES = frozenset(
    {
        "README.md",
        "RESUME.md",
        "docs/current-architecture.md",
        "docs/runbooks/receiver-compatible-authority-updates.md",
        "docs/mandatory-telegram-visibility.md",
        "docs/packaging.md",
        "specs/identity-continuity.md",
        "specs/operational-stack-contract.md",
        "AGENTS.md",
        "CURRENT-STATE.md",
        "docs/file-peer-enrollment.md",
        "docs/existing-agent-chat.md",
        "docs/multi-agent-chat.md",
        "tools/ci_scope.py",
        "tests/test_ci_scope.py",
        ".github/workflows/tests.yml",
    }
)


RELEASE_COMPATIBILITY_FILES = frozenset(
    {
        "src/daimon_matrix/release_compatibility.py",
        "tests/test_release_compatibility.py",
        "specs/receiver-compatible-release.md",
        "tools/ci_scope.py",
        "tests/test_ci_scope.py",
        "tools/reproducible_build.py",
        "tools/check_distribution.py",
        "tests/test_package_scaffold.py",
        "tests/test_dm041_hermes_body.py",
        ".github/workflows/tests.yml",
        ".github/workflows/telegram-portability.yml",
        "provenance/hermes-agent-0.19.0.json",
        "vectors/hermes/v1/index.json",
        "vectors/hermes/v1/valid/launch-receipt.json",
        "vectors/hermes/v1/valid/profile-manifest.json",
    }
)


BOUNDED_GROUP_FILES = frozenset(
    {
        ".github/workflows/tests.yml",
        "docs/tribe-group-runtime.md",
        "specs/tribe-conversation.md",
        "src/daimon_matrix/daemon.py",
        "src/daimon_matrix/messaging.py",
        "src/daimon_matrix/messaging_config.py",
        "src/daimon_matrix/native_egress.py",
        "src/daimon_matrix/routes.py",
        "src/daimon_matrix/release_compatibility.py",
        "tests/test_ci_scope.py",
        "tests/test_dm053_routes.py",
        "tests/test_group_messaging_runtime.py",
        "tests/test_native_messaging.py",
        "tests/test_release_compatibility.py",
        "tools/ci_scope.py",
        "provenance/hermes-agent-0.19.0.json",
        "vectors/hermes/v1/index.json",
        "vectors/hermes/v1/valid/launch-receipt.json",
        "vectors/hermes/v1/valid/profile-manifest.json",
    }
)


RECEIVING_CONTROL_FILES = TRIBE_GROUP_FILES | frozenset(
    {
        "docs/runbooks/operator-bootstrap.md",
        "docs/runbooks/operator-capability-upgrade.md",
        "src/daimon_matrix/client.py",
        "src/daimon_matrix/operator_capabilities.py",
        "src/daimon_matrix/operator_runtime_upgrade.py",
        "tests/test_dm079_capability_profiles.py",
        "tests/test_operator_runtime_upgrade.py",
        "tests/test_receiving_runtime.py",
        "tests/test_dm024_runtime.py",
        "tests/test_dm025_client.py",
    }
)


LEDGER_GROUP_FILES = RECEIVING_CONTROL_FILES | frozenset(
    {
        ".githooks/pre-push",
        "src/daimon_matrix/ledger.py",
        "tests/test_dm022_ledger.py",
        "tests/test_dm031_curator.py",
        "tests/test_dm032_curator_worker.py",
        "tests/test_dm054_scopes.py",
    }
)


def profile(paths: list[str]) -> str:
    changed = set(paths)
    if (
        changed & {"tools/behavior_inventory.py", "tests/test_behavior_inventory.py"}
        and changed <= BEHAVIOR_INVENTORY_FILES
    ):
        return "behavior-inventory"
    if (
        changed <= LEDGER_GROUP_FILES
        and {
            "src/daimon_matrix/ledger.py",
            "src/daimon_matrix/communication.py",
            "src/daimon_matrix/messaging.py",
            "tests/test_group_messaging_runtime.py",
        }
        <= changed
    ):
        return (
            "ledger-group-integration"
            if changed
            & {
                "src/daimon_matrix/operator_messaging.py",
                "src/daimon_matrix/operator_communication_migration.py",
                "schemas/hosted/v1/local-api.schema.json",
            }
            else "ledger-group-storage"
        )
    if "tools/install_agent_chat.py" in changed and changed <= INSTALLER_FILES:
        return "agent-chat-installer"
    migration = changed & {
        "src/daimon_matrix/operator_communication_migration.py",
        "tests/test_operator_communication_migration.py",
    }
    if migration and changed <= COMMUNICATION_MIGRATION_FILES:
        return "communication-migration"
    if changed <= RECEIVING_CONTROL_FILES and changed & {
        "src/daimon_matrix/operator_capabilities.py",
        "src/daimon_matrix/operator_runtime_upgrade.py",
        "tests/test_dm079_capability_profiles.py",
        "tests/test_operator_runtime_upgrade.py",
        "tests/test_receiving_runtime.py",
    }:
        return "receiving-control"
    if (
        changed <= BOUNDED_GROUP_FILES
        and {
            "src/daimon_matrix/routes.py",
            "src/daimon_matrix/native_egress.py",
            "tests/test_dm053_routes.py",
        }
        <= changed
    ):
        return "bounded-group-transport"
    if (
        "src/daimon_matrix/release_compatibility.py" in changed
        and changed <= RELEASE_COMPATIBILITY_FILES
    ):
        return "release-compatibility"
    if changed & {"AGENTS.md", "CURRENT-STATE.md"} and changed <= CONTEXT_DOC_FILES:
        return "context-docs"
    if (
        changed
        & {
            "src/daimon_matrix/tribe_conversation.py",
            "tests/test_group_messaging_runtime.py",
        }
        and changed <= TRIBE_GROUP_FILES
    ):
        if changed & {
            "src/daimon_matrix/operator_communication_migration.py",
            "tests/test_operator_communication_migration.py",
            "src/daimon_matrix/operator_messaging.py",
            "src/daimon_matrix/messaging_config.py",
            "tests/test_operator_messaging.py",
            "tests/test_closed_visibility_provisioning.py",
            "tests/test_dm025_cli_mcp.py",
            "schemas/hosted/v1/local-api.schema.json",
            "docs/verification/dm025-invariants.json",
        }:
            return "group-admission"
        return "tribe-group"
    if (
        changed <= AUTHORITY_ADOPTION_FILES
        and "src/daimon_matrix/messaging_config.py" in changed
        and changed
        & {"src/daimon_matrix/operator_messaging.py", "src/daimon_matrix/messaging.py"}
    ):
        return "authority-adoption"
    if "docs/resource-access.md" in changed and changed <= RESOURCE_DOC_FILES:
        return "resource-docs"
    if (
        changed
        & {
            "src/daimon_matrix/human_tribu.py",
            "src/daimon_matrix/human_tribu_process.py",
        }
        and changed <= HUMAN_TRIBU_FILES
    ):
        return "human-tribu"
    if (
        changed
        & {
            "tools/protected_being.py",
            "tests/test_being_protection.py",
            "tools/receive_being.py",
        }
        and changed <= PROTECTED_FILES
    ):
        return "protected-archive"
    if (
        changed & {"tools/export_being.py", "tools/preserve_memory.py"}
        and changed <= ARCHIVE_FILES
    ):
        return "archive"
    if "src/daimon_matrix/telegram_mirror.py" in changed and changed <= MIRROR_FILES:
        return "mirror"
    if (
        {
            "src/daimon_matrix/telegram_mirror.py",
            "src/daimon_matrix/mandatory_echo.py",
        }
        <= changed
        or changed
        & {
            "src/daimon_matrix/agent_chat.py",
            "src/daimon_matrix/operator_messaging.py",
            "src/daimon_matrix/native_egress.py",
            "src/daimon_matrix/routes.py",
        }
    ) and changed <= VISIBILITY_FILES:
        return "visibility"
    if changed and changed <= PEER_FILES:
        return "peer"
    if (
        changed
        & {
            "src/daimon_matrix/messaging.py",
            "src/daimon_matrix/messaging_store.py",
        }
        and changed <= MESSAGING_FILES
    ):
        return "messaging"
    return "full"


def select(base: str, *, pull_request_head: str = "") -> str:
    if not base or set(base) == {"0"}:
        return "full"
    if pull_request_head:
        # GitHub's event base SHA can precede newer main commits included in
        # its synthetic merge. Bind to the explicit PR head before selecting
        # the actual first parent; unexpected merge topology stays full.
        parents = subprocess.run(
            ["git", "show", "-s", "--format=%P", "HEAD"],
            capture_output=True,
            text=True,
            check=False,
        )
        values = parents.stdout.split()
        if parents.returncode or len(values) != 2 or values[1] != pull_request_head:
            return "full"
        base = values[0]
    result = subprocess.run(
        ["git", "diff", "--no-renames", "--name-only", base, "HEAD"],
        capture_output=True,
        text=True,
        check=False,
    )
    return profile(result.stdout.splitlines()) if result.returncode == 0 else "full"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", required=True)
    parser.add_argument("--pull-request-head", default="")
    args = parser.parse_args()
    selected = select(args.base, pull_request_head=args.pull_request_head)
    # Reuse the installed visibility job and its portability skip. Only the
    # unchanged native suite is omitted for the closed mirror-only allowlist.
    value = (
        "profile="
        + (
            "visibility"
            if selected == "mirror"
            else "tribe-group"
            if selected
            in {
                "bounded-group-transport",
                "ledger-group-storage",
                "ledger-group-integration",
                "receiving-control",
                "group-admission",
                "communication-migration",
            }
            else selected
        )
        + "\nnative_checks="
        + ("false" if selected == "mirror" else "true")
    )
    if selected in {"bounded-group-transport", "communication-migration"}:
        value += "\ngroup_receipt_checks=false"
    if selected == "communication-migration":
        value += "\ngroup_migration_only=true"
    if selected in {
        "receiving-control",
        "ledger-group-storage",
        "ledger-group-integration",
    }:
        value += "\ngroup_receiving_checks=true"
    if selected in {"ledger-group-storage", "ledger-group-integration"}:
        value += "\ngroup_ledger_checks=true"
    if selected in {"group-admission", "ledger-group-integration"}:
        value += "\ngroup_admission_checks=true"
    print(value.splitlines()[0])
    if output := os.environ.get("GITHUB_OUTPUT"):
        with Path(output).open("a", encoding="utf-8") as stream:
            stream.write(value + "\n")


if __name__ == "__main__":
    main()
