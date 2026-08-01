from __future__ import annotations

import datetime as dt
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from coordination.github_claims import COMMAND_MARKER, decide_command, validate_command
from tools import github_coordination as cli

from tests.test_github_claims import NOW, WORKFLOW_SHA, command_body, signed_command


class SigningCliTests(unittest.TestCase):
    def test_sign_file_reads_real_pem_and_emits_verifiable_comment(self) -> None:
        key = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            body_path = root / "command.json"
            key_path = root / "session.pem"
            body_path.write_text(json.dumps(command_body()), encoding="utf-8")
            key_path.write_bytes(
                key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
            )
            rendered = cli.sign_file(body_path, key_path)
        self.assertTrue(rendered.startswith("/claim\n\n<!-- " + COMMAND_MARKER))
        payload = rendered.split("\n", 3)[3].rsplit("\n-->", 1)[0]
        parsed = validate_command(json.loads(payload))
        self.assertEqual(parsed.claim_id, command_body()["claim_id"])

    def test_run_gh_passes_closed_json_to_stdin(self) -> None:
        completed = subprocess.CompletedProcess(
            ["gh"], returncode=0, stdout='{"ok":true}', stderr=""
        )
        with mock.patch("subprocess.run", return_value=completed) as run:
            result = cli._run_gh(
                ["api", "--input", "-"], input_data={"labels": ["status:ready"]}
            )
        self.assertTrue(result["ok"])
        self.assertEqual(
            json.loads(run.call_args.kwargs["input"]),
            {"labels": ["status:ready"]},
        )


class RecoveryCliTests(unittest.TestCase):
    def setUp(self) -> None:
        command = signed_command(Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33))))
        self.current = cli.validate_receipt(
            decide_command(
                command,
                None,
                now=NOW,
                workflow_sha=WORKFLOW_SHA,
                issue_ready=True,
            )
        )
        self.issue = {
            "labels": [
                {"name": "type:implementation"},
                {"name": "status:ready"},
            ]
        }

    def test_periodic_pass_repairs_label_drift_without_new_receipt(self) -> None:
        with (
            mock.patch.object(cli, "_registry", return_value={}),
            mock.patch.object(cli, "_issue", return_value=self.issue),
            mock.patch.object(cli, "_state", return_value=(self.current, [self.current])),
            mock.patch.object(cli, "_set_status") as set_status,
        ):
            result = cli.expire_issue(
                "AlterMundi/daimon-matrix",
                6,
                now=NOW + dt.timedelta(hours=1),
                workflow_sha=WORKFLOW_SHA,
            )
        self.assertFalse(result["expired"])
        self.assertTrue(result["reconciled"])
        set_status.assert_called_once_with(
            "AlterMundi/daimon-matrix", 6, self.issue, "in_progress"
        )

    def test_periodic_pass_posts_expiry_before_ready_label(self) -> None:
        with (
            mock.patch.object(cli, "_registry", return_value={}),
            mock.patch.object(cli, "_issue", return_value=self.issue),
            mock.patch.object(cli, "_state", return_value=(self.current, [self.current])),
            mock.patch.object(cli, "_post_receipt", return_value={"html_url": "https://receipt"}),
            mock.patch.object(cli, "_set_status") as set_status,
        ):
            result = cli.expire_issue(
                "AlterMundi/daimon-matrix",
                6,
                now=NOW + dt.timedelta(hours=7),
                workflow_sha=WORKFLOW_SHA,
            )
        self.assertTrue(result["expired"])
        self.assertEqual(result["comment"], "https://receipt")
        set_status.assert_called_once_with(
            "AlterMundi/daimon-matrix", 6, self.issue, "ready"
        )


if __name__ == "__main__":
    unittest.main()
