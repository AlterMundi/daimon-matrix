#!/usr/bin/env python3
"""Run local/CI unit qualification without inheriting live integration switches.

Dependencies must already be installed. This command does not install packages,
fetch repositories, contact participants, or qualify a deployed service.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PINS = {
    "COLLECTIVE_MEMORY_CONTRACT_ROOT": "3e3b39416917f8e3c2bc5ca69362b20296205938",
    "HMK_CONTRACT_ROOT": "f10fd5c3089c0962920314c97e14bc024feffa7a",
}


def check_checkout(path: Path, commit: str) -> None:
    """Archives are insufficient: contract tests inspect Git object identity."""
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=path,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    status = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=all"],
        cwd=path,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    if head != commit or status:
        raise ValueError("contract checkout must be clean and at its exact pin")


def environment(contracts: dict[str, Path], temporary: Path) -> dict[str, str]:
    """No inherited provider credentials, PYTHONPATH, or DAIMON_* test gates."""
    return {
        "HOME": str(temporary / "home"),
        "PATH": os.pathsep.join((str(Path(sys.executable).parent), os.defpath)),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TZ": "UTC",
        "TMPDIR": str(temporary),
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONPATH": str(ROOT / "src"),
        **{key: str(path.resolve()) for key, path in contracts.items()},
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--collective-memory", type=Path, required=True)
    parser.add_argument("--hmk", type=Path)
    parser.add_argument("--preflight-only", action="store_true")
    parser.add_argument(
        "tests", nargs="*", help="Dotted unittest names; default: full discovery"
    )
    args = parser.parse_args(argv)
    contracts = {"COLLECTIVE_MEMORY_CONTRACT_ROOT": args.collective_memory}
    if args.hmk is not None:
        contracts["HMK_CONTRACT_ROOT"] = args.hmk
    try:
        for key, path in contracts.items():
            check_checkout(path, PINS[key])
    except (OSError, ValueError, subprocess.CalledProcessError):
        print(
            "qualification preflight failed: "
            "require clean Git checkouts at documented pins",
            file=sys.stderr,
        )
        return 2
    if any(
        not name.startswith("tests.")
        or not all(p.isidentifier() for p in name.split("."))
        for name in args.tests
    ):
        parser.error("test selectors must be dotted names beginning with tests.")
    print(
        "Qualification: local synthetic tests; no live integration gates enabled.",
        flush=True,
    )
    print(
        "HMK contract: "
        + ("enabled" if args.hmk else "not requested (reported skips remain skips)"),
        flush=True,
    )
    if args.preflight_only:
        return 0
    # A short, private /tmp root avoids the AF_UNIX 108-byte pathname limit.
    with tempfile.TemporaryDirectory(prefix="dmq-", dir="/tmp") as name:
        temporary = Path(name)
        (temporary / "home").mkdir(mode=0o700)
        command = [
            sys.executable,
            "-B",
            "-W",
            "error::ResourceWarning",
            "-m",
            "unittest",
        ]
        command += (
            [*args.tests, "-v"] if args.tests else ["discover", "-s", "tests", "-v"]
        )
        old_umask = os.umask(0o022)
        try:
            return subprocess.run(
                command, cwd=ROOT, env=environment(contracts, temporary), check=False
            ).returncode
        finally:
            os.umask(old_umask)


if __name__ == "__main__":
    raise SystemExit(main())
