#!/usr/bin/env python3
"""DM-020 package metadata and public-artifact boundary tests."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import tomllib
import unittest
import zipfile
from pathlib import Path
from typing import Any

from tools.check_distribution import (
    SDIST_FILES,
    WHEEL_FILES,
    PackageCheckError,
    validate_member,
)
from tools.reproducible_build import BUILD_INPUTS
from tools.scan_secrets import SecretScanError, scan_archive, scan_path

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures/package/rejected/cases.json"


class PackageMetadataTests(unittest.TestCase):
    def setUp(self) -> None:
        with (ROOT / "pyproject.toml").open("rb") as stream:
            self.configuration: dict[str, Any] = tomllib.load(stream)

    def test_public_metadata_and_runtime_dependency_boundary(self) -> None:
        project = self.configuration["project"]
        self.assertEqual(project["name"], "daimon-matrix")
        self.assertEqual(project["version"], "0.0.0")
        self.assertEqual(project["requires-python"], ">=3.11")
        self.assertEqual(
            project["dependencies"],
            ["cryptography==50.0.0", "mcp==2.0.0", "wasmtime==45.0.0"],
        )
        self.assertEqual(project["license"], "MIT")
        self.assertEqual(
            project["scripts"],
            {
                "daimon": "daimon_matrix.cli:main",
                "daimon-codex-body": "daimon_matrix.codex_body:main",
                "daimon-conformance": "daimon_matrix.conformance:main",
                "daimon-curator-worker": "daimon_matrix.curator_worker_process:main",
                "daimon-hermes-body": "daimon_matrix.hermes_body:main",
                "daimon-matrixd": "daimon_matrix.daemon:main",
                "daimon-mcp": "daimon_matrix.mcp_server:main",
                "daimon-reviewer": "daimon_matrix.reviewer_cli:main",
                "daimon-synthetic-birth": "daimon_matrix.synthetic_birth:main",
                "daimon-synthetic-species": "daimon_matrix.synthetic_species:main",
            },
        )

    def test_supported_versions_and_backend_are_explicit(self) -> None:
        classifiers = set(self.configuration["project"]["classifiers"])
        for version in ("3.11", "3.12", "3.13", "3.14"):
            self.assertIn(f"Programming Language :: Python :: {version}", classifiers)
        self.assertEqual(
            self.configuration["build-system"]["requires"],
            ["hatchling==1.31.0"],
        )
        self.assertTrue(self.configuration["tool"]["hatch"]["build"]["reproducible"])

    def test_namespace_import_is_behavior_free_and_typed(self) -> None:
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(ROOT / "src")
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                "import daimon_matrix; "
                "assert daimon_matrix.__all__ == ['__version__']; "
                "assert daimon_matrix.__version__ == '0.0.0'",
            ],
            cwd=ROOT,
            env=environment,
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.stdout, "")
        self.assertEqual(
            (ROOT / "src/daimon_matrix/py.typed").read_bytes().strip(), b""
        )

    def test_tool_requirements_are_exact_and_not_runtime_metadata(self) -> None:
        self.assertEqual(
            [
                line
                for line in (ROOT / "requirements-build.txt")
                .read_text(encoding="utf-8")
                .splitlines()
                if line
            ],
            [
                "# DM-020 build frontend. The backend is exactly pinned "
                "in pyproject.toml.",
                "build==1.5.0",
            ],
        )
        development = {
            line
            for line in (ROOT / "requirements-dev.txt")
            .read_text(encoding="utf-8")
            .splitlines()
            if line
        }
        self.assertEqual(
            development,
            {
                "-r requirements-build.txt",
                "mcp==2.0.0",
                "mypy==2.3.0",
                "ruff==0.16.1",
            },
        )


class ArtifactBoundaryTests(unittest.TestCase):
    def test_reproducible_build_inputs_match_sdist_sources(self) -> None:
        expected_sources = {
            Path(path) for path in SDIST_FILES if path.startswith("src/daimon_matrix/")
        }
        self.assertEqual(
            {
                path
                for path in BUILD_INPUTS
                if path.parts[:2] == ("src", "daimon_matrix")
            },
            expected_sources,
        )

    def test_allowlists_are_frozen(self) -> None:
        self.assertEqual(
            SDIST_FILES,
            {
                ".gitignore",
                "LICENSE",
                "PKG-INFO",
                "README.md",
                "pyproject.toml",
                "src/daimon_matrix/__init__.py",
                "src/daimon_matrix/authority_epochs.py",
                "src/daimon_matrix/birth.py",
                "src/daimon_matrix/canonical.py",
                "src/daimon_matrix/cli.py",
                "src/daimon_matrix/client.py",
                "src/daimon_matrix/cluster.py",
                "src/daimon_matrix/codex_body.py",
                "src/daimon_matrix/communication.py",
                "src/daimon_matrix/conformance.py",
                "src/daimon_matrix/curator.py",
                "src/daimon_matrix/curator_worker.py",
                "src/daimon_matrix/curator_worker_process.py",
                "src/daimon_matrix/daemon.py",
                "src/daimon_matrix/identity.py",
                "src/daimon_matrix/human_review.py",
                "src/daimon_matrix/hermes_body.py",
                "src/daimon_matrix/keystore.py",
                "src/daimon_matrix/ledger.py",
                "src/daimon_matrix/local_api.py",
                "src/daimon_matrix/local_we.py",
                "src/daimon_matrix/mcp_server.py",
                "src/daimon_matrix/memory_policy.py",
                "src/daimon_matrix/memory_projection.py",
                "src/daimon_matrix/peer_transport.py",
                "src/daimon_matrix/publication.py",
                "src/daimon_matrix/projections.py",
                "src/daimon_matrix/py.typed",
                "src/daimon_matrix/relationships.py",
                "src/daimon_matrix/reviewer_cli.py",
                "src/daimon_matrix/runtime.py",
                "src/daimon_matrix/routes.py",
                "src/daimon_matrix/scopes.py",
                "src/daimon_matrix/sealed.py",
                "src/daimon_matrix/service.py",
                "src/daimon_matrix/species.py",
                "src/daimon_matrix/species_runner.py",
                "src/daimon_matrix/sync.py",
                "src/daimon_matrix/synthetic_birth.py",
                "src/daimon_matrix/synthetic_species.py",
                "src/daimon_matrix/weave.py",
            },
        )
        self.assertEqual(
            WHEEL_FILES,
            {
                "daimon_matrix/__init__.py",
                "daimon_matrix/authority_epochs.py",
                "daimon_matrix/birth.py",
                "daimon_matrix/canonical.py",
                "daimon_matrix/cli.py",
                "daimon_matrix/client.py",
                "daimon_matrix/cluster.py",
                "daimon_matrix/codex_body.py",
                "daimon_matrix/communication.py",
                "daimon_matrix/conformance.py",
                "daimon_matrix/curator.py",
                "daimon_matrix/curator_worker.py",
                "daimon_matrix/curator_worker_process.py",
                "daimon_matrix/daemon.py",
                "daimon_matrix/identity.py",
                "daimon_matrix/human_review.py",
                "daimon_matrix/hermes_body.py",
                "daimon_matrix/keystore.py",
                "daimon_matrix/ledger.py",
                "daimon_matrix/local_api.py",
                "daimon_matrix/local_we.py",
                "daimon_matrix/mcp_server.py",
                "daimon_matrix/memory_policy.py",
                "daimon_matrix/memory_projection.py",
                "daimon_matrix/peer_transport.py",
                "daimon_matrix/publication.py",
                "daimon_matrix/projections.py",
                "daimon_matrix/py.typed",
                "daimon_matrix/relationships.py",
                "daimon_matrix/reviewer_cli.py",
                "daimon_matrix/runtime.py",
                "daimon_matrix/routes.py",
                "daimon_matrix/scopes.py",
                "daimon_matrix/sealed.py",
                "daimon_matrix/service.py",
                "daimon_matrix/species.py",
                "daimon_matrix/species_runner.py",
                "daimon_matrix/sync.py",
                "daimon_matrix/synthetic_birth.py",
                "daimon_matrix/synthetic_species.py",
                "daimon_matrix/weave.py",
                "daimon_matrix-0.0.0.dist-info/METADATA",
                "daimon_matrix-0.0.0.dist-info/entry_points.txt",
                "daimon_matrix-0.0.0.dist-info/RECORD",
                "daimon_matrix-0.0.0.dist-info/WHEEL",
                "daimon_matrix-0.0.0.dist-info/licenses/LICENSE",
            },
        )

    def test_every_named_rejection_case_is_enforced(self) -> None:
        fixture: dict[str, Any] = json.loads(FIXTURES.read_text(encoding="utf-8"))
        self.assertEqual(fixture["schema"], "dm-020-rejected-package-cases/v0")
        names: set[str] = set()
        for case in fixture["cases"]:
            with self.subTest(case=case["name"]):
                names.add(case["name"])
                data = "".join(case["parts"]).encode("utf-8")
                with self.assertRaises(PackageCheckError):
                    validate_member(case["member"], data)
        self.assertEqual(
            names,
            {
                "absolute-path",
                "cache",
                "credential",
                "egg-info",
                "experimental-module",
                "private-key",
                "sqlite",
                "traversal",
            },
        )

    def test_zip_symlink_is_rejected_without_extraction(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dm020-test-") as directory:
            archive_path = Path(directory) / "adversarial.whl"
            info = zipfile.ZipInfo("daimon_matrix/link")
            info.create_system = 3
            info.external_attr = 0o120777 << 16
            with zipfile.ZipFile(archive_path, mode="w") as archive:
                archive.writestr(info, "../../private")
            with self.assertRaises(SecretScanError):
                scan_archive(archive_path)

    def test_checkout_secret_scan_is_clean(self) -> None:
        self.assertGreater(scan_path(ROOT), 0)


if __name__ == "__main__":
    unittest.main()
