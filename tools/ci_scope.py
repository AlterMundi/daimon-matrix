"""Select the native peer-tool qualification; unknown changes keep full CI."""

from __future__ import annotations

import argparse
import os
import subprocess
from pathlib import Path

PEER_FILES = frozenset(
    {
        "tools/chat_link.py",
        "tests/test_chat_link.py",
        "tools/ci_scope.py",
        "tests/test_ci_scope.py",
        ".github/workflows/tests.yml",
        ".github/workflows/telegram-portability.yml",
    }
)


def profile(paths: list[str]) -> str:
    return "peer" if paths and set(paths) <= PEER_FILES else "full"


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
