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

from coordination.github_claims import (
    COMMAND_MARKER,
    RECEIPT_MARKER,
    decide_command,
    parse_receipt_comment,
    render_block,
    sign_command,
    validate_command,
)
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


class FakeGitHub:
    """Small stateful stand-in for the exact GitHub API surface used by the CLI."""

    def __init__(self, command_comment: dict) -> None:
        self.repo = "AlterMundi/daimon-matrix"
        self.issue_number = 6
        self.issue = {
            "number": self.issue_number,
            "labels": [
                {"name": "type:implementation"},
                {"name": "status:ready"},
            ],
        }
        self.comments = [command_comment]
        self.next_comment_id = command_comment["id"] + 1

    def __call__(self, arguments: list[str], *, input_data=None):
        issue_path = f"repos/{self.repo}/issues/{self.issue_number}"
        if arguments == ["api", issue_path]:
            return self.issue
        if arguments[:2] == ["api", "--paginate"]:
            target = arguments[-1]
            if target.startswith(issue_path + "/comments?"):
                return [list(self.comments)]
            if target.startswith(f"repos/{self.repo}/issues?"):
                label = target.rsplit("labels=", 1)[1].replace("%3A", ":")
                names = {entry["name"] for entry in self.issue["labels"]}
                return [[self.issue] if label in names else []]
        if len(arguments) == 2 and arguments[1].startswith(
            f"repos/{self.repo}/issues/comments/"
        ):
            comment_id = int(arguments[1].rsplit("/", 1)[1])
            return next(item for item in self.comments if item["id"] == comment_id)
        if arguments[1:3] == ["--method", "POST"]:
            body = next(value[5:] for value in arguments if value.startswith("body="))
            comment = {
                "id": self.next_comment_id,
                "created_at": "2026-08-01T18:00:00Z",
                "updated_at": "2026-08-01T18:00:00Z",
                "user": {"login": "github-actions[bot]"},
                "body": body,
                "html_url": f"https://example.test/comments/{self.next_comment_id}",
            }
            self.next_comment_id += 1
            self.comments.append(comment)
            return comment
        if arguments[1:3] == ["--method", "PATCH"]:
            self.issue["labels"] = [{"name": name} for name in input_data["labels"]]
            return self.issue
        raise AssertionError(f"unexpected gh invocation: {arguments!r}")


class HandlerIntegrationTests(unittest.TestCase):
    def test_claim_then_scheduled_expiry_round_trips_through_fake_github(self) -> None:
        key = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
        wrapper = sign_command(command_body(), key)
        command_comment = {
            "id": 100,
            "created_at": "2026-08-01T18:00:00Z",
            "updated_at": "2026-08-01T18:00:00Z",
            "user": {"login": "nicoechaniz"},
            "body": render_block(COMMAND_MARKER, wrapper, "claim"),
        }
        github = FakeGitHub(command_comment)

        with mock.patch.object(cli, "_run_gh", side_effect=github):
            claimed = cli.handle_comment(
                github.repo,
                github.issue_number,
                command_comment["id"],
                now=NOW,
                workflow_sha=WORKFLOW_SHA,
            )
            expired = cli.expire_issue(
                github.repo,
                github.issue_number,
                now=NOW + dt.timedelta(hours=7),
                workflow_sha=WORKFLOW_SHA,
            )

        self.assertTrue(claimed["accepted"])
        self.assertEqual(claimed["decision"], "accepted")
        self.assertEqual(claimed["posted_comments"], ["https://example.test/comments/101"])
        self.assertTrue(expired["expired"])
        self.assertEqual(expired["comment"], "https://example.test/comments/102")
        self.assertIn("status:ready", {entry["name"] for entry in github.issue["labels"]})

        receipts = [
            receipt
            for comment in github.comments
            if (receipt := parse_receipt_comment(comment, cli._registry())) is not None
        ]
        self.assertEqual([receipt.state for receipt in receipts], ["in_progress", "ready"])
        self.assertEqual(receipts[1].previous_receipt_id, receipts[0].receipt_id)
        self.assertTrue(github.comments[1]["body"].startswith("<!-- " + RECEIPT_MARKER))


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
