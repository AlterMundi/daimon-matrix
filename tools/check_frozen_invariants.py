#!/usr/bin/env python3
"""Fail fast on the two drifts that cost a red head twice in one week.

A frozen value in this repository is rarely frozen in one place. The package
module count is asserted by the scaffold inventory test and again by the DM-041
public contract test; a specification's digest is pinned by a generated
conformance artifact. Editing one and not the other passes every local suite that
does not happen to include the second, and then fails CI in the installed-wheel
job, which is the slowest place to find out.

This check is deliberately cheap and deliberately narrow: it compares the actual
package module set against every inventory and every asserted count, and it runs
the generated-artifact check set. It does not run tests and it is not a substitute
for them. Run it before pushing; a pre-push hook in `.githooks` does it for you.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = ROOT / "src" / "daimon_matrix"
GENERATORS = (
    "generate_dm036_vectors.py",
    "generate_dm041_vectors.py",
    "generate_dm042_vectors.py",
    "generate_dm061_vectors.py",
    "generate_dm078_recovery_vectors.py",
    "generate_dm078_vectors.py",
    "generate_dm081_vectors.py",
    "generate_dm082_vectors.py",
)
# Every place the package module count is asserted as a literal, by construction.
COUNT_ASSERTIONS = (
    (
        "tests/test_package_scaffold.py",
        re.compile(r"assertEqual\(len\(modules\),\s*(\d+)\)"),
    ),
    (
        "tests/test_dm041_hermes_body.py",
        re.compile(
            r'assertEqual\(len\(manifest\["matrix_package"\]\["modules"\]\),\s*(\d+)\)'
        ),
    ),
)


def _fail(problems: list[str], message: str) -> None:
    problems.append(message)


def actual_modules() -> set[str]:
    return {path.relative_to(ROOT).as_posix() for path in sorted(PACKAGE.rglob("*.py"))}


def check_inventories(modules: set[str], problems: list[str]) -> None:
    sys.path.insert(0, str(ROOT))
    try:
        from tools.check_distribution import SDIST_FILES, WHEEL_FILES
        from tools.reproducible_build import BUILD_INPUTS
    finally:
        sys.path.pop(0)
    for name, inventory in (
        ("BUILD_INPUTS", {path.as_posix() for path in BUILD_INPUTS}),
        ("SDIST_FILES", set(SDIST_FILES)),
        ("WHEEL_FILES", {f"src/{path}" for path in WHEEL_FILES}),
    ):
        listed = {path for path in inventory if path.endswith(".py")}
        if listed != modules:
            missing = sorted(modules - listed)
            extra = sorted(listed - modules)
            _fail(
                problems,
                f"{name} disagrees with the package tree: "
                f"missing={missing or '[]'} extra={extra or '[]'}",
            )


def check_counts(modules: set[str], problems: list[str]) -> None:
    for relative, pattern in COUNT_ASSERTIONS:
        text = (ROOT / relative).read_text(encoding="utf-8")
        found = pattern.findall(text)
        if not found:
            _fail(
                problems,
                f"{relative}: no module-count assertion matched; the check is stale",
            )
            continue
        for literal in found:
            if int(literal) != len(modules):
                _fail(
                    problems,
                    f"{relative} asserts {literal} package modules, "
                    f"the tree has {len(modules)}",
                )


def check_generated(python: str, problems: list[str]) -> None:
    for name in GENERATORS:
        path = ROOT / "tools" / name
        if not path.is_file():
            continue
        result = subprocess.run(
            [python, str(path), "--check"],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            tail = (result.stdout + result.stderr).strip().splitlines()[-1:]
            _fail(
                problems,
                f"tools/{name} --check failed: a spec, doc or source change was "
                f"not regenerated ({tail[0] if tail else 'no output'})",
            )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--python",
        default=sys.executable,
        help="interpreter used to run the generated-artifact checks",
    )
    parser.add_argument(
        "--skip-generated",
        action="store_true",
        help="only check module inventories and counts",
    )
    arguments = parser.parse_args(argv)
    modules = actual_modules()
    problems: list[str] = []
    check_inventories(modules, problems)
    check_counts(modules, problems)
    if not arguments.skip_generated:
        check_generated(arguments.python, problems)
    if problems:
        for problem in problems:
            print(f"frozen-invariant: {problem}", file=sys.stderr)
        print(
            f"frozen-invariant: {len(problems)} problem(s); "
            "regenerate artifacts and align every assertion before pushing",
            file=sys.stderr,
        )
        return 1
    print(
        f"frozen-invariant: ok ({len(modules)} package modules, "
        "inventories and counts agree, generated artifacts current)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
