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
        "provenance/hermes-agent-0.19.0.json",
        "vectors/hermes/v1/index.json",
        "vectors/hermes/v1/valid/launch-receipt.json",
        "vectors/hermes/v1/valid/profile-manifest.json",
    }
)
ARCHIVE_FILES = frozenset(
    {
        "tools/export_being.py",
        "tests/test_being_export.py",
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
    if "tools/export_being.py" in changed and changed <= ARCHIVE_FILES:
        return "archive"
    if changed and changed <= PEER_FILES:
        return "peer"
    if "src/daimon_matrix/messaging.py" in changed and changed <= MESSAGING_FILES:
        return "messaging"
    return "full"


def select(base: str) -> str:
    if not base or set(base) == {"0"}:
        return "full"
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
    args = parser.parse_args()
    value = "profile=" + select(args.base)
    print(value)
    if output := os.environ.get("GITHUB_OUTPUT"):
        with Path(output).open("a", encoding="utf-8") as stream:
            stream.write(value + "\n")


if __name__ == "__main__":
    main()
