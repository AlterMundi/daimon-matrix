from __future__ import annotations

import os
import subprocess
import unittest
from collections import Counter
from pathlib import Path
from unittest.mock import patch

from tools import qualify, unittest_shard


class QualificationRunnerTests(unittest.TestCase):
    def test_shards_preserve_every_case_including_imported_duplicates(self) -> None:
        cases = [
            type("Case", (unittest.TestCase,), {"__module__": module})()
            for module in (
                "test_one",
                "tests.test_two",
                "helpers.shared",
                "unittest.loader",
            )
            for _ in range(2)
        ]
        suite = unittest.TestSuite(
            [unittest.TestSuite(cases[:3]), unittest.TestSuite(cases[3:])]
        )

        def flatten(value):
            for test in value:
                if isinstance(test, unittest.TestSuite):
                    yield from flatten(test)
                else:
                    yield test

        owners = {}
        combined = []
        for index in range(4):
            selected = list(flatten(unittest_shard.select(suite, index, 4)))
            combined.extend(selected)
            for test in selected:
                module = type(test).__module__
                self.assertEqual(owners.setdefault(module, index), index)
        self.assertEqual(Counter(map(id, combined)), Counter(map(id, cases)))

    def test_invalid_shard_never_starts_qualification(self) -> None:
        with (
            patch("tools.qualify.subprocess.run") as run,
            self.assertRaises(SystemExit),
        ):
            qualify.main(
                [
                    "--collective-memory",
                    "/missing",
                    "--shard-index",
                    "4",
                    "--shard-count",
                    "4",
                ]
            )
        run.assert_not_called()

    def test_legacy_fixture_matches_production_migration_pin(self) -> None:
        from daimon_matrix.operator_runtime_upgrade import LEGACY_REVISION

        self.assertEqual(qualify.LEGACY_REVISION, LEGACY_REVISION)

    def test_environment_does_not_inherit_credentials_or_live_gates(self) -> None:
        with patch.dict(
            os.environ,
            {
                "DAIMON_RUN_DOCKER_TESTS": "1",
                "SECRET_TOKEN": "synthetic",
                "PYTHONPATH": "/untrusted",
                "HMK_CONTRACT_ROOT": "/wrong",
            },
        ):
            env = qualify.environment({}, Path("/tmp/synthetic"))
        self.assertNotIn("DAIMON_RUN_DOCKER_TESTS", env)
        self.assertNotIn("SECRET_TOKEN", env)
        self.assertNotIn("HMK_CONTRACT_ROOT", env)
        self.assertEqual(env["PYTHONPATH"], str(qualify.ROOT / "src"))
        self.assertEqual(env["HOME"], "/tmp/synthetic/home")

    def test_checkout_requires_matching_head_and_clean_content(self) -> None:
        pin = qualify.PINS["HMK_CONTRACT_ROOT"]
        for head, status in ((pin, " M changed"), ("0" * 40, "")):
            with (
                self.subTest(head=head, status=status),
                patch(
                    "tools.qualify.subprocess.run",
                    side_effect=[
                        subprocess.CompletedProcess([], 0, stdout=head),
                        subprocess.CompletedProcess([], 0, stdout=status),
                    ],
                ),
                self.assertRaises(ValueError),
            ):
                qualify.check_checkout(Path("/synthetic"), pin)

    def test_bad_preflight_never_starts_suite(self) -> None:
        with (
            patch("tools.qualify.check_checkout", side_effect=ValueError),
            patch("tools.qualify.subprocess.run") as run,
        ):
            self.assertEqual(qualify.main(["--collective-memory", "/missing"]), 2)
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
