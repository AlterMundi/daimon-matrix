#!/usr/bin/env python3
"""Drive signed Daimon Matrix claim commands through GitHub issue comments."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from coordination.github_claims import (  # noqa: E402
    ACTIVE_STATES,
    COMMAND_MARKER,
    RECEIPT_MARKER,
    CoordinationError,
    IssueRef,
    authorize_command,
    decide_command,
    expire_if_due,
    format_timestamp,
    parse_command_comment,
    parse_receipt_comment,
    parse_timestamp,
    reduce_receipts,
    render_block,
    sign_command,
    validate_receipt,
)


REGISTRY_FILE = ROOT / "coordination" / "principals.json"
_CLOSES = re.compile(
    r"(?im)^\s*(?:close[sd]?|fix(?:e[sd])?|resolve[sd]?)\s+"
    r"(?:https://github\.com/([^/\s]+/[^/\s]+)/issues/)?#?(\d+)\b"
)
_CLAIM_ID = re.compile(
    r"(?im)^\s*Claim-ID:\s*([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12})\s*$"
)
_DEPLOYMENT = re.compile(r"(?im)^\s*Deployment:\s*(.+?)\s*$")
_TESTS = re.compile(r"(?ims)^##\s+Tests\s*$\s*(.+?)(?=^##\s+|\Z)")


def _run_gh(arguments: list[str], *, input_data: Mapping[str, Any] | None = None) -> Any:
    environment = dict(os.environ)
    token = environment.get("GH_TOKEN") or environment.get("GITHUB_TOKEN")
    if token:
        environment["GH_TOKEN"] = token
    completed = subprocess.run(
        ["gh", *arguments],
        check=False,
        capture_output=True,
        text=True,
        input=json.dumps(input_data) if input_data is not None else None,
        env=environment,
    )
    if completed.returncode:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise CoordinationError(f"gh {' '.join(arguments)} failed: {detail}")
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise CoordinationError("GitHub CLI returned invalid JSON") from exc


def _registry() -> dict[str, Any]:
    try:
        return json.loads(REGISTRY_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CoordinationError(f"cannot load {REGISTRY_FILE}: {exc}") from exc


def _comments(repo: str, issue: int) -> list[dict[str, Any]]:
    pages = _run_gh(
        [
            "api",
            "--paginate",
            "--slurp",
            f"repos/{repo}/issues/{issue}/comments?per_page=100",
        ]
    )
    return [comment for page in pages for comment in page]


def _issue(repo: str, issue: int) -> dict[str, Any]:
    return _run_gh(["api", f"repos/{repo}/issues/{issue}"])


def _now(value: str | None) -> dt.datetime:
    return parse_timestamp(value, "now") if value else dt.datetime.now(dt.timezone.utc)


def _workflow_sha(value: str | None) -> str:
    candidate = value or os.environ.get("GITHUB_SHA")
    if not candidate or not re.fullmatch(r"[0-9a-f]{40}", candidate):
        raise CoordinationError("--workflow-sha or GITHUB_SHA must be lowercase 40-hex")
    return candidate


def _state(repo: str, issue: int, registry: dict[str, Any]):
    issue_ref = IssueRef(repo, issue)
    receipts = []
    for comment in _comments(repo, issue):
        receipt = parse_receipt_comment(comment, registry)
        if receipt is not None:
            receipts.append(receipt)
    return reduce_receipts(receipts, issue_ref), receipts


def _status_label(state: str) -> str:
    return {
        "ready": "status:ready",
        "in_progress": "status:claimed",
        "in_review": "status:review",
        "done": "status:review",
    }[state]


def _set_status(repo: str, issue_number: int, issue: dict[str, Any], state: str) -> None:
    labels = [entry["name"] for entry in issue.get("labels", [])]
    labels = [label for label in labels if not label.startswith("status:")]
    labels.append(_status_label(state))
    _run_gh(
        [
            "api",
            "--method",
            "PATCH",
            f"repos/{repo}/issues/{issue_number}",
            "--input",
            "-",
        ],
        input_data={"labels": sorted(labels)},
    )


def _post_receipt(repo: str, issue: int, wrapper: dict[str, Any]) -> dict[str, Any]:
    return _run_gh(
        [
            "api",
            "--method",
            "POST",
            f"repos/{repo}/issues/{issue}/comments",
            "-f",
            "body=" + render_block(RECEIPT_MARKER, wrapper),
        ]
    )


def _labels(issue: dict[str, Any]) -> set[str]:
    return {entry["name"] for entry in issue.get("labels", [])}


def handle_comment(
    repo: str,
    issue_number: int,
    comment_id: int,
    *,
    now: dt.datetime,
    workflow_sha: str,
) -> dict[str, Any]:
    registry = _registry()
    issue = _issue(repo, issue_number)
    comment = _run_gh(["api", f"repos/{repo}/issues/comments/{comment_id}"])
    command = parse_command_comment(comment)
    if command is None:
        raise CoordinationError("target comment has no signed claim command")
    if command.issue != IssueRef(repo, issue_number):
        raise CoordinationError("command names another issue")
    slash = re.match(r"\s*/(claim|heartbeat|review|release)\b", comment.get("body", ""))
    if not slash or slash.group(1) != command.action:
        raise CoordinationError("slash command and signed action differ")
    authorize_command(command, registry)
    current, _ = _state(repo, issue_number, registry)

    posted: list[dict[str, Any]] = []
    expiry = expire_if_due(current, now=now, workflow_sha=workflow_sha)
    if expiry is not None:
        posted.append(_post_receipt(repo, issue_number, expiry))
        current = validate_receipt(expiry)
        _set_status(repo, issue_number, issue, "ready")
        issue = _issue(repo, issue_number)

    conflict_reason = (
        _resource_conflict(
            repo,
            issue_number,
            command.resources,
            now=now,
            registry=registry,
        )
        if command.action == "claim"
        else None
    )
    wrapper = decide_command(
        command,
        current,
        now=now,
        workflow_sha=workflow_sha,
        issue_ready="status:ready" in _labels(issue),
        conflict_reason=conflict_reason,
    )
    receipt = validate_receipt(wrapper)
    posted.append(_post_receipt(repo, issue_number, wrapper))
    if receipt.decision == "accepted":
        _set_status(repo, issue_number, issue, receipt.state)
    return {
        "ok": True,
        "accepted": receipt.decision == "accepted",
        "decision": receipt.decision,
        "reason": receipt.reason,
        "receipt_id": receipt.receipt_id,
        "posted_comments": [item.get("html_url") for item in posted],
    }


def expire_issue(
    repo: str,
    issue_number: int,
    *,
    now: dt.datetime,
    workflow_sha: str,
) -> dict[str, Any]:
    registry = _registry()
    issue = _issue(repo, issue_number)
    current, _ = _state(repo, issue_number, registry)
    wrapper = expire_if_due(current, now=now, workflow_sha=workflow_sha)
    if wrapper is None:
        if current is not None:
            _set_status(repo, issue_number, issue, current.state)
        return {
            "ok": True,
            "expired": False,
            "reconciled": current is not None,
            "issue": issue_number,
        }
    receipt = validate_receipt(wrapper)
    posted = _post_receipt(repo, issue_number, wrapper)
    _set_status(repo, issue_number, issue, "ready")
    return {
        "ok": True,
        "expired": True,
        "issue": issue_number,
        "receipt_id": receipt.receipt_id,
        "comment": posted.get("html_url"),
    }


def _issues_with_label(repo: str, label: str) -> list[int]:
    pages = _run_gh(
        [
            "api",
            "--paginate",
            "--slurp",
            f"repos/{repo}/issues?state=open&per_page=100&labels={label}",
        ]
    )
    return [item["number"] for page in pages for item in page if "pull_request" not in item]


def _resource_conflict(
    repo: str,
    issue_number: int,
    resources: tuple[str, ...],
    *,
    now: dt.datetime,
    registry: dict[str, Any],
) -> str | None:
    active_issues = sorted(
        set(_issues_with_label(repo, "status%3Aclaimed"))
        | set(_issues_with_label(repo, "status%3Areview"))
    )
    for other_number in active_issues:
        if other_number == issue_number:
            continue
        other, _ = _state(repo, other_number, registry)
        if other is None or not other.is_live(now):
            continue
        overlap = sorted(set(resources).intersection(other.resources))
        if overlap:
            return "resource_conflict"
    return None


def expire_all(repo: str, *, now: dt.datetime, workflow_sha: str) -> dict[str, Any]:
    issues = sorted(
        set(_issues_with_label(repo, "status%3Aready"))
        | set(_issues_with_label(repo, "status%3Aclaimed"))
        | set(_issues_with_label(repo, "status%3Areview"))
    )
    results = [
        expire_issue(repo, issue, now=now, workflow_sha=workflow_sha)
        for issue in issues
    ]
    return {"ok": True, "checked": issues, "expired": [r for r in results if r["expired"]]}


def audit_issue(repo: str, issue_number: int, *, now: dt.datetime) -> dict[str, Any]:
    registry = _registry()
    issue = _issue(repo, issue_number)
    current, receipts = _state(repo, issue_number, registry)
    findings = []
    if current is None:
        findings.append({"code": "missing_receipt", "message": "issue has no automation receipt"})
    else:
        expected = _status_label("ready" if current.lease_until and current.lease_until <= now else current.state)
        if expected not in _labels(issue):
            findings.append({"code": "label_drift", "message": f"expected {expected}"})
        if current.state in ACTIVE_STATES and current.lease_until and current.lease_until <= now:
            findings.append({"code": "expired_lease", "message": f"lease expired at {format_timestamp(current.lease_until)}"})
    return {
        "ok": not findings,
        "repository": repo,
        "issue": issue_number,
        "receipt_count": len(receipts),
        "current": current.body if current else None,
        "findings": findings,
    }


def _linked_issue(body: str, repo: str) -> int | None:
    for match in _CLOSES.finditer(body):
        linked_repo = match.group(1)
        if linked_repo is None or linked_repo.lower() == repo.lower():
            return int(match.group(2))
    return None


def audit_pr(repo: str, pr_number: int, *, now: dt.datetime) -> dict[str, Any]:
    pull = _run_gh(["api", f"repos/{repo}/pulls/{pr_number}"])
    body = pull.get("body") or ""
    findings = []
    issue_number = _linked_issue(body, repo)
    claim_match = _CLAIM_ID.search(body)
    if issue_number is None:
        findings.append({"code": "missing_linked_issue", "message": "PR must contain Closes #N"})
    if claim_match is None:
        findings.append({"code": "missing_claim_id", "message": "PR must contain canonical Claim-ID"})
    if _DEPLOYMENT.search(body) is None:
        findings.append({"code": "missing_deployment", "message": "PR must declare Deployment"})
    tests_match = _TESTS.search(body)
    if tests_match is None or not tests_match.group(1).strip():
        findings.append({"code": "missing_tests", "message": "PR must contain non-empty Tests section"})
    current = None
    if issue_number is not None:
        registry = _registry()
        current, _ = _state(repo, issue_number, registry)
        if current is None:
            findings.append({"code": "missing_receipt", "message": "linked issue has no claim receipt"})
        else:
            if claim_match and claim_match.group(1) != current.claim_id:
                findings.append({"code": "claim_mismatch", "message": "PR Claim-ID is not effective"})
            if current.state != "in_review" or not current.is_live(now):
                findings.append({"code": "claim_not_live_review", "message": "claim is not live in review"})
            if current.branch != pull.get("head", {}).get("ref"):
                findings.append({"code": "branch_mismatch", "message": "claim branch differs from PR head"})
            if current.pull_request != pr_number:
                findings.append({"code": "pr_mismatch", "message": "claim receipt names another PR"})
    return {
        "ok": not findings,
        "repository": repo,
        "pull_request": pr_number,
        "linked_issue": issue_number,
        "current": current.body if current else None,
        "findings": findings,
    }


def sign_file(body_path: Path, key_path: Path) -> str:
    try:
        body = json.loads(body_path.read_text(encoding="utf-8"))
        loaded = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise CoordinationError(f"cannot load signing input: {exc}") from exc
    if not isinstance(loaded, Ed25519PrivateKey):
        raise CoordinationError("private key must be unencrypted Ed25519 PEM")
    wrapper = sign_command(body, loaded)
    return render_block(COMMAND_MARKER, wrapper, body["action"])


def _print(result: dict[str, Any]) -> int:
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("ok") else 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY"))
    parser.add_argument("--now", help="RFC 3339 UTC test override")
    parser.add_argument("--workflow-sha")
    commands = parser.add_subparsers(dest="command", required=True)
    handle = commands.add_parser("handle-comment")
    handle.add_argument("--issue", type=int, required=True)
    handle.add_argument("--comment", type=int, required=True)
    expire = commands.add_parser("expire")
    expire.add_argument("--issue", type=int)
    issue = commands.add_parser("audit-issue")
    issue.add_argument("--issue", type=int, required=True)
    pr = commands.add_parser("audit-pr")
    pr.add_argument("--pr", type=int, required=True)
    sign = commands.add_parser("sign")
    sign.add_argument("--body", type=Path, required=True)
    sign.add_argument("--private-key", type=Path, required=True)
    args = parser.parse_args()

    try:
        if args.command == "sign":
            print(sign_file(args.body, args.private_key))
            return 0
        if not args.repo or "/" not in args.repo:
            raise CoordinationError("--repo owner/name or GITHUB_REPOSITORY is required")
        now = _now(args.now)
        if args.command == "handle-comment":
            result = handle_comment(
                args.repo,
                args.issue,
                args.comment,
                now=now,
                workflow_sha=_workflow_sha(args.workflow_sha),
            )
        elif args.command == "expire":
            sha = _workflow_sha(args.workflow_sha)
            result = (
                expire_issue(args.repo, args.issue, now=now, workflow_sha=sha)
                if args.issue
                else expire_all(args.repo, now=now, workflow_sha=sha)
            )
        elif args.command == "audit-issue":
            result = audit_issue(args.repo, args.issue, now=now)
        else:
            result = audit_pr(args.repo, args.pr, now=now)
    except CoordinationError as exc:
        result = {"ok": False, "findings": [{"code": "invalid_data", "message": str(exc)}]}
    return _print(result)


if __name__ == "__main__":
    raise SystemExit(main())
