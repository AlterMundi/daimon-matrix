from __future__ import annotations

import datetime as dt
import json
import subprocess
import tempfile
import threading
import unittest
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

import jsonschema
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from coordination.github_claims import (
    COMMAND_MARKER,
    RECEIPT_MARKER,
    CoordinationError,
    decide_command,
    parse_receipt_comment,
    render_block,
    sign_command,
    validate_command,
)
from tests.test_github_claims import (
    NOW,
    WORKFLOW_SHA,
    command_body,
    receipt_comment,
    signed_command,
)
from tools import github_coordination as cli


class SigningCliTests(unittest.TestCase):
    def test_empty_actions_response_requires_explicit_opt_in(self):
        completed = subprocess.CompletedProcess(
            ["gh"], returncode=0, stdout="", stderr=""
        )
        with mock.patch("subprocess.run", return_value=completed):
            self.assertIsNone(cli._run_gh(["api", "endpoint"], allow_empty=True))
            with self.assertRaisesRegex(CoordinationError, "invalid JSON"):
                cli._run_gh(["api", "endpoint"])

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


class CoordinationSchemaTests(unittest.TestCase):
    def setUp(self) -> None:
        schema_path = Path(__file__).parents[1] / "coordination" / "claim.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator.check_schema(schema)
        self.validator = jsonschema.Draft202012Validator(
            schema,
            format_checker=jsonschema.FormatChecker(),
        )

    def test_generated_command_and_receipt_conform_to_published_schema(self) -> None:
        key = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
        command = sign_command(command_body(), key)
        receipt = decide_command(
            validate_command(command),
            None,
            now=NOW,
            workflow_sha=WORKFLOW_SHA,
            issue_ready=True,
        )
        self.validator.validate(command)
        self.validator.validate(receipt)

    def test_schema_rejects_branches_rejected_by_runtime(self) -> None:
        key = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
        command = sign_command(command_body(), key)
        for unsafe in ("", "-bad..branch/", ".hidden", "topic.lock"):
            candidate = json.loads(json.dumps(command))
            candidate["body"]["branch"] = unsafe
            with (
                self.subTest(branch=unsafe),
                self.assertRaises(jsonschema.ValidationError),
            ):
                self.validator.validate(candidate)


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
        self.assertEqual(
            claimed["posted_comments"], ["https://example.test/comments/101"]
        )
        self.assertTrue(expired["expired"])
        self.assertEqual(expired["comment"], "https://example.test/comments/102")
        self.assertIn(
            "status:ready", {entry["name"] for entry in github.issue["labels"]}
        )

        receipts = [
            receipt
            for comment in github.comments
            if (receipt := parse_receipt_comment(comment, cli._registry())) is not None
        ]
        self.assertEqual(
            [receipt.state for receipt in receipts], ["in_progress", "ready"]
        )
        self.assertEqual(receipts[1].previous_receipt_id, receipts[0].receipt_id)
        self.assertTrue(github.comments[1]["body"].startswith("<!-- " + RECEIPT_MARKER))


class ReviewRefreshApiTests(unittest.TestCase):
    """Real HTTP effects with authentic signed commands and receipt reduction."""

    def setUp(self) -> None:
        self.key = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
        wrapper = sign_command(command_body(), self.key)
        self.github = FakeGitHub(
            {
                "id": 100,
                "created_at": "2026-08-01T18:00:00Z",
                "updated_at": "2026-08-01T18:00:00Z",
                "user": {"login": "nicoechaniz"},
                "body": render_block(COMMAND_MARKER, wrapper, "claim"),
            }
        )
        self.pull = {
            "number": 68,
            "state": "open",
            "body": (
                f"Closes #6\nClaim-ID: {command_body()['claim_id']}\n"
                "Deployment: none\n## Tests\nReal HTTP.\n"
            ),
            "head": {
                "sha": "b" * 40,
                "ref": command_body()["branch"],
                "repo": {"full_name": self.github.repo},
            },
        }
        self.workflow_run = {
            "id": 11,
            "workflow_id": 7,
            "event": "pull_request",
            "path": ".github/workflows/coordination.yml",
            "head_sha": "b" * 40,
            "head_branch": self.pull["head"]["ref"],
            "head_repository": {"full_name": self.github.repo},
            "run_attempt": 1,
            "status": "completed",
            "conclusion": "failure",
        }
        self.job = {
            "id": 22,
            "run_id": 11,
            "name": "pull-request",
            "head_sha": "b" * 40,
            "status": "completed",
            "conclusion": "failure",
        }
        self.workflow_run["pull_requests"] = [
            {"number": 68, "head": dict(self.pull["head"])}
        ]
        self.reruns = []
        self.before_rerun_read = None
        test = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                self.respond(None)

            def do_POST(self):
                self.respond(
                    json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                )

            def do_PATCH(self):
                self.respond(
                    json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                )

            def respond(self, value):
                try:
                    result = test.route(
                        self.command, self.path.removeprefix("/"), value
                    )
                except Exception as exc:
                    self.send_response(500)
                    self.end_headers()
                    self.wfile.write(str(exc).encode())
                    return
                self.send_response(201 if self.path.endswith("/rerun") else 200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                if result is not None:
                    self.wfile.write(json.dumps(result).encode())

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.thread.join)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(cli, "_run_gh", side_effect=self.http_gh).start()
        mock.patch.object(cli, "_now", return_value=NOW).start()
        cli.handle_comment(self.github.repo, 6, 100, now=NOW, workflow_sha=WORKFLOW_SHA)
        current, _ = cli._state(self.github.repo, 6, cli._registry())
        body = command_body(
            action="review",
            command_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            pull_request=68,
            previous_receipt_id=current.receipt_id,
            previous_receipt_hash=current.receipt_hash,
        )
        self.review_comment = dict(
            self.github.comments[0],
            id=200,
            body=render_block(COMMAND_MARKER, sign_command(body, self.key), "review"),
        )
        self.github.comments.append(self.review_comment)

    def http_gh(self, arguments, *, input_data=None, allow_empty=False):
        method = (
            arguments[arguments.index("--method") + 1]
            if "--method" in arguments
            else "GET"
        )
        target = next(arg for arg in arguments if arg.startswith("repos/"))
        if "-f" in arguments:
            input_data = {"body": arguments[arguments.index("-f") + 1][5:]}
        data = json.dumps(input_data or {}).encode() if method != "GET" else None
        request = urllib.request.Request(
            f"http://127.0.0.1:{self.server.server_port}/{target}",
            data=data,
            method=method,
        )
        with urllib.request.urlopen(request, timeout=2) as reply:
            raw = reply.read()
        result = None if allow_empty and not raw else json.loads(raw)
        return [result] if "--slurp" in arguments else result

    def route(self, method, path, value):
        base = f"repos/{self.github.repo}"
        if path == base + "/pulls/68":
            if self.before_rerun_read and self.job.get("read"):
                self.before_rerun_read()
                self.before_rerun_read = None
            return self.pull
        if path.startswith(base + "/pulls?"):
            return [self.pull]
        if path == base + "/actions/workflows/coordination.yml":
            return {"id": 7, "path": ".github/workflows/coordination.yml"}
        if path.startswith(base + "/actions/workflows/7/runs?"):
            return {"workflow_runs": [self.workflow_run]}
        if path.startswith(base + "/actions/runs/11/jobs?"):
            self.job["read"] = True
            return {"jobs": [self.job]}
        if path == base + "/actions/runs/11":
            return self.workflow_run
        if path == base + "/actions/jobs/22/rerun" and method == "POST":
            self.reruns.append(path)
            self.workflow_run.update(run_attempt=2, status="queued")
            return None
        arguments = ["api", path]
        if "comments?" in path or "issues?" in path:
            return self.github(["api", "--paginate", "--slurp", path])[0]
        if method == "POST":
            arguments = ["api", "--method", "POST", path, "-f", "body=" + value["body"]]
        elif method == "PATCH":
            arguments = ["api", "--method", "PATCH", path]
        return self.github(arguments, input_data=value)

    def accept_review(self):
        return cli.handle_comment(
            self.github.repo, 6, 200, now=NOW, workflow_sha=WORKFLOW_SHA
        )

    def test_accepted_review_requests_real_job_once_not_a_success(self):
        result = self.accept_review()
        self.assertTrue(result["accepted"])
        self.assertEqual(result["review_refresh"]["status"], "rerun_requested")
        self.assertEqual(result["review_refresh"]["head_sha"], "b" * 40)
        cli.refresh_completed_run(self.github.repo, 11, now=NOW)
        self.assertEqual(len(self.reruns), 1)

    def test_review_before_initial_completion_uses_completion_event(self):
        self.workflow_run.update(status="in_progress", conclusion=None)
        result = self.accept_review()
        self.assertEqual(
            result["review_refresh"]["status"], "awaiting_initial_completion"
        )
        self.assertEqual(self.reruns, [])
        self.workflow_run.update(status="completed", conclusion="failure")
        result = cli.refresh_completed_run(self.github.repo, 11, now=NOW)
        self.assertEqual(result["results"][0]["status"], "rerun_requested")
        self.assertEqual(len(self.reruns), 1)

    def test_changed_head_immediately_before_effect_refuses(self):
        self.before_rerun_read = lambda: self.pull["head"].update(sha="c" * 40)
        result = self.accept_review()
        self.assertEqual(result["review_refresh"]["status"], "changed_head_or_body")
        self.assertEqual(self.reruns, [])

    def test_expired_review_and_untrusted_receipt_do_not_refresh(self):
        self.workflow_run.update(status="in_progress", conclusion=None)
        self.accept_review()
        self.workflow_run.update(status="completed", conclusion="failure")
        result = cli.refresh_completed_run(
            self.github.repo, 11, now=NOW + dt.timedelta(hours=7)
        )
        self.assertEqual(result["results"][0]["status"], "not_eligible")
        self.github.comments[-1]["user"] = {"login": "mallory"}
        result = cli.refresh_completed_run(self.github.repo, 11, now=NOW)
        self.assertEqual(result["results"][0]["status"], "not_eligible")
        self.assertEqual(self.reruns, [])

    def test_wrong_session_review_is_refused_without_rerun(self):
        current, _ = cli._state(self.github.repo, 6, cli._registry())
        body = command_body(
            action="review",
            pull_request=68,
            previous_receipt_id=current.receipt_id,
            previous_receipt_hash=current.receipt_hash,
        )
        other = Ed25519PrivateKey.from_private_bytes(bytes(range(2, 34)))
        self.review_comment["body"] = render_block(
            COMMAND_MARKER, sign_command(body, other), "review"
        )
        result = self.accept_review()
        self.assertFalse(result["accepted"])
        self.assertNotIn("review_refresh", result)
        self.assertEqual(self.reruns, [])

    def test_wrong_branch_never_requests_a_rerun(self):
        self.pull["head"]["ref"] = "issue-6-other-branch"
        result = self.accept_review()
        self.assertEqual(result["review_refresh"]["status"], "not_eligible")
        self.assertEqual(self.reruns, [])

    def test_completion_for_different_signed_pr_never_requests_a_rerun(self):
        current, _ = cli._state(self.github.repo, 6, cli._registry())
        body = command_body(
            action="review",
            command_id="dddddddd-dddd-4ddd-8ddd-dddddddddddd",
            pull_request=69,
            previous_receipt_id=current.receipt_id,
            previous_receipt_hash=current.receipt_hash,
        )
        self.review_comment["body"] = render_block(
            COMMAND_MARKER, sign_command(body, self.key), "review"
        )
        # Admission itself is real signed/API work. The observed completed
        # event names68, whereas the authentic review grants only69.
        with mock.patch.object(
            cli, "refresh_review_pr", return_value={"status": "awaiting_initial_run"}
        ):
            self.assertTrue(self.accept_review()["accepted"])
        result = cli.refresh_completed_run(self.github.repo, 11, now=NOW)
        self.assertEqual(result["results"][0]["status"], "not_eligible")
        self.assertEqual(self.reruns, [])

    def test_release_before_completion_removes_refresh_eligibility(self):
        self.workflow_run.update(status="in_progress", conclusion=None)
        self.accept_review()
        current, _ = cli._state(self.github.repo, 6, cli._registry())
        body = command_body(
            action="release",
            command_id="cccccccc-cccc-4ccc-8ccc-cccccccccccc",
            lease_seconds=None,
            previous_receipt_id=current.receipt_id,
            previous_receipt_hash=current.receipt_hash,
        )
        self.github.comments.append(
            dict(
                self.review_comment,
                id=300,
                body=render_block(
                    COMMAND_MARKER, sign_command(body, self.key), "release"
                ),
            )
        )
        cli.handle_comment(self.github.repo, 6, 300, now=NOW, workflow_sha=WORKFLOW_SHA)
        self.workflow_run.update(status="completed", conclusion="failure")
        result = cli.refresh_completed_run(self.github.repo, 11, now=NOW)
        self.assertEqual(result["results"][0]["status"], "not_eligible")
        self.assertEqual(self.reruns, [])

    def test_bad_job_binding_fails_after_preserving_accepted_receipt(self):
        self.job["head_sha"] = "c" * 40
        result = self.accept_review()
        self.assertTrue(result["accepted"])
        self.assertFalse(result["ok"])
        current, _ = cli._state(self.github.repo, 6, cli._registry())
        self.assertEqual(current.state, "in_review")
        self.assertEqual(self.reruns, [])

    def test_run_for_wrong_pr_or_old_head_is_not_selected(self):
        self.workflow_run["pull_requests"][0]["number"] = 69
        result = self.accept_review()
        self.assertEqual(result["review_refresh"]["status"], "awaiting_initial_run")
        self.assertEqual(self.reruns, [])
        self.workflow_run["pull_requests"][0]["number"] = 68
        self.workflow_run["head_sha"] = "c" * 40
        result = cli.refresh_review_pr(self.github.repo, 68, now=NOW)
        self.assertEqual(result["status"], "awaiting_initial_run")
        self.assertEqual(self.reruns, [])

    def test_successful_native_audit_is_not_rerun(self):
        self.job["conclusion"] = "success"
        self.assertEqual(
            self.accept_review()["review_refresh"]["status"], "already_successful"
        )
        self.assertEqual(self.reruns, [])


class ReceiptPoisoningTests(unittest.TestCase):
    def setUp(self) -> None:
        command = signed_command(
            Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
        )
        self.wrapper = decide_command(
            command,
            None,
            now=NOW,
            workflow_sha=WORKFLOW_SHA,
            issue_ready=True,
        )

    def test_untrusted_forged_and_malformed_markers_are_inert(self) -> None:
        comments = [
            {
                "id": 1,
                "user": {"login": "mallory"},
                "body": render_block(RECEIPT_MARKER, self.wrapper),
            },
            receipt_comment(self.wrapper, comment_id=2),
            {
                "id": 3,
                "user": {"login": "mallory"},
                "body": "<!-- daimon-claim-receipt/v0\nnot closed",
            },
        ]
        with mock.patch.object(cli, "_comments", return_value=comments):
            current, receipts = cli._state(
                "AlterMundi/daimon-matrix", 6, cli._registry()
            )
        self.assertEqual(current.receipt_id, receipts[0].receipt_id)
        self.assertEqual(len(receipts), 1)

    def test_malformed_authorized_receipt_still_fails_closed(self) -> None:
        comment = {
            "id": 2,
            "user": {"login": "github-actions[bot]"},
            "body": "<!-- daimon-claim-receipt/v0\nnot closed",
        }
        with (
            mock.patch.object(cli, "_comments", return_value=[comment]),
            self.assertRaisesRegex(CoordinationError, "unterminated"),
        ):
            cli._state("AlterMundi/daimon-matrix", 6, cli._registry())


class ClaimabilityTests(unittest.TestCase):
    def test_open_blocked_by_card_prevents_claimability(self) -> None:
        issue = {
            "body": "## Blocked by\n\nDM-000 and DM-016.\n\n## Acceptance criteria"
        }
        catalog = [
            [
                {"number": 1, "title": "[DM-000] Audit", "state": "closed"},
                {"number": 10, "title": "[DM-016] Tribe", "state": "open"},
            ]
        ]
        with mock.patch.object(cli, "_run_gh", return_value=catalog):
            blockers = cli._open_blockers("AlterMundi/daimon-matrix", issue)
        self.assertEqual(blockers, ("DM-016",))


class BatchExpiryTests(unittest.TestCase):
    def test_one_corrupt_issue_does_not_abort_other_expiries(self) -> None:
        healthy = {"ok": True, "expired": True, "issue": 7}
        with (
            mock.patch.object(
                cli,
                "_issues_with_label",
                side_effect=[[6, 7], [], []],
            ),
            mock.patch.object(
                cli,
                "expire_issue",
                side_effect=[CoordinationError("broken chain"), healthy],
            ) as expire_issue,
        ):
            result = cli.expire_all(
                "AlterMundi/daimon-matrix", now=NOW, workflow_sha=WORKFLOW_SHA
            )
        self.assertFalse(result["ok"])
        self.assertEqual(result["checked"], [6, 7])
        self.assertEqual(result["expired"], [healthy])
        self.assertEqual(result["failures"][0]["issue"], 6)
        self.assertEqual(expire_issue.call_count, 2)


class RecoveryCliTests(unittest.TestCase):
    def setUp(self) -> None:
        command = signed_command(
            Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
        )
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
            mock.patch.object(
                cli, "_state", return_value=(self.current, [self.current])
            ),
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
            mock.patch.object(
                cli, "_state", return_value=(self.current, [self.current])
            ),
            mock.patch.object(
                cli, "_post_receipt", return_value={"html_url": "https://receipt"}
            ),
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
