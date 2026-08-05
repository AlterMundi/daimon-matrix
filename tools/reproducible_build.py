#!/usr/bin/env python3
"""Build DM-020 twice in isolation and require byte-identical artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Final

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.check_distribution import (
    SDIST_NAME,
    SOURCE_DATE_EPOCH,
    WHEEL_NAME,
    inspect_artifacts,
)

BUILD_INPUTS: Final = (
    Path(".gitignore"),
    Path("LICENSE"),
    Path("README.md"),
    Path("pyproject.toml"),
    Path("src/daimon_matrix/__init__.py"),
    Path("src/daimon_matrix/authority_epochs.py"),
    Path("src/daimon_matrix/canonical.py"),
    Path("src/daimon_matrix/cli.py"),
    Path("src/daimon_matrix/client.py"),
    Path("src/daimon_matrix/cluster.py"),
    Path("src/daimon_matrix/codex_body.py"),
    Path("src/daimon_matrix/communication.py"),
    Path("src/daimon_matrix/conformance.py"),
    Path("src/daimon_matrix/curator.py"),
    Path("src/daimon_matrix/curator_worker.py"),
    Path("src/daimon_matrix/curator_worker_process.py"),
    Path("src/daimon_matrix/daemon.py"),
    Path("src/daimon_matrix/identity.py"),
    Path("src/daimon_matrix/human_review.py"),
    Path("src/daimon_matrix/hermes_body.py"),
    Path("src/daimon_matrix/keystore.py"),
    Path("src/daimon_matrix/ledger.py"),
    Path("src/daimon_matrix/local_api.py"),
    Path("src/daimon_matrix/mcp_server.py"),
    Path("src/daimon_matrix/memory_policy.py"),
    Path("src/daimon_matrix/memory_projection.py"),
    Path("src/daimon_matrix/publication.py"),
    Path("src/daimon_matrix/projections.py"),
    Path("src/daimon_matrix/py.typed"),
    Path("src/daimon_matrix/reviewer_cli.py"),
    Path("src/daimon_matrix/runtime.py"),
    Path("src/daimon_matrix/routes.py"),
    Path("src/daimon_matrix/relationships.py"),
    Path("src/daimon_matrix/scopes.py"),
    Path("src/daimon_matrix/sealed.py"),
    Path("src/daimon_matrix/service.py"),
    Path("src/daimon_matrix/sync.py"),
    Path("src/daimon_matrix/weave.py"),
)


class ReproducibleBuildError(RuntimeError):
    """Raised when a build input or output violates the reproducibility contract."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _copy_clean_source(source_root: Path, destination: Path) -> None:
    for relative in BUILD_INPUTS:
        source = source_root / relative
        if source.is_symlink() or not source.is_file():
            raise ReproducibleBuildError(f"invalid build input: {relative}")
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)


def _build_once(source_root: Path, workspace: Path) -> dict[str, Path]:
    project = workspace / "project"
    output = workspace / "dist"
    project.mkdir()
    output.mkdir()
    _copy_clean_source(source_root, project)
    environment = os.environ.copy()
    environment.update(
        {
            "LC_ALL": "C.UTF-8",
            "PYTHONHASHSEED": "0",
            "SOURCE_DATE_EPOCH": str(SOURCE_DATE_EPOCH),
            "TZ": "UTC",
        }
    )
    subprocess.run(
        [sys.executable, "-m", "build", "--outdir", str(output)],
        cwd=project,
        env=environment,
        check=True,
    )
    artifacts = {path.name: path for path in output.iterdir() if path.is_file()}
    expected = {SDIST_NAME, WHEEL_NAME}
    if set(artifacts) != expected:
        raise ReproducibleBuildError(
            f"unexpected build outputs: {sorted(artifacts)}; "
            f"expected {sorted(expected)}"
        )
    return artifacts


def reproducible_build(source_root: Path, output: Path) -> dict[str, object]:
    """Run two clean isolated builds, compare bytes, inspect, and retain one pair."""

    source_root = source_root.resolve()
    output = output.resolve()
    with (
        tempfile.TemporaryDirectory(prefix="dm020-build-a-") as first_dir,
        tempfile.TemporaryDirectory(prefix="dm020-build-b-") as second_dir,
    ):
        first = _build_once(source_root, Path(first_dir))
        second = _build_once(source_root, Path(second_dir))
        digests: dict[str, str] = {}
        for name in sorted(first):
            first_digest = _sha256(first[name])
            second_digest = _sha256(second[name])
            if first_digest != second_digest:
                raise ReproducibleBuildError(
                    f"non-reproducible artifact {name}: "
                    f"{first_digest} != {second_digest}"
                )
            if first[name].read_bytes() != second[name].read_bytes():
                raise ReproducibleBuildError(
                    f"digest collision while comparing artifact {name}"
                )
            digests[name] = first_digest

        inspection = inspect_artifacts(
            first[SDIST_NAME], first[WHEEL_NAME], source_root
        )
        output.mkdir(parents=True, exist_ok=True)
        for name, artifact in first.items():
            shutil.copyfile(artifact, output / name)

    return {
        "schema": "dm-020-reproducible-build-report/v0",
        "builds": 2,
        "byte_identical": True,
        "digests": digests,
        "inspection": inspection,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path, default=Path("dist"))
    return parser


def main() -> int:
    args = _parser().parse_args()
    report = reproducible_build(args.source_root, args.output)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
