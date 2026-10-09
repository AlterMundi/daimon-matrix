"""Select native peer/messaging qualification; unknown changes keep full CI."""

from __future__ import annotations

import argparse
import os
import subprocess
from pathlib import Path

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
        "docs/runbooks/tribu-readable-traffic.md",
        "schemas/messaging/v2/echo-proof.schema.json",
        "schemas/messaging/v2/visibility-policy.schema.json",
        "src/daimon_matrix/agent_chat_assets/SKILL.md",
        "src/daimon_matrix/daemon.py",
        "src/daimon_matrix/labels.py",
        "src/daimon_matrix/mandatory_echo.py",
        "src/daimon_matrix/mcp_server.py",
        "src/daimon_matrix/messaging_config.py",
        "src/daimon_matrix/messaging_store.py",
        "src/daimon_matrix/native_egress.py",
        "src/daimon_matrix/neutral_skill_assets/daimon-chat/SKILL.md",
        "src/daimon_matrix/operator_messaging.py",
        "src/daimon_matrix/runtime.py",
        "src/daimon_matrix/telegram_mirror.py",
        "tests/test_agent_chat.py",
        "tests/test_labels.py",
        "tests/test_mandatory_echo.py",
        "tests/test_messaging_runtime.py",
        "tests/test_operator_messaging.py",
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


def profile(paths: list[str]) -> str:
    changed = set(paths)
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
        or "src/daimon_matrix/operator_messaging.py" in changed
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
    value = "profile=" + select(args.base, pull_request_head=args.pull_request_head)
    print(value)
    if output := os.environ.get("GITHUB_OUTPUT"):
        with Path(output).open("a", encoding="utf-8") as stream:
            stream.write(value + "\n")


if __name__ == "__main__":
    main()
