from __future__ import annotations

import datetime as dt
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from coordination.github_claims import (
    COMMAND_MARKER,
    RECEIPT_MARKER,
    CoordinationError,
    IssueRef,
    audit_resource_overlaps,
    authorize_command,
    build_receipt,
    decide_command,
    expire_if_due,
    format_timestamp,
    parse_command_comment,
    parse_receipt_comment,
    reduce_receipts,
    render_block,
    sign_command,
    validate_command,
    validate_receipt,
)


NOW = dt.datetime(2026, 8, 1, 18, tzinfo=dt.timezone.utc)
ISSUE = IssueRef("AlterMundi/daimon-matrix", 6)
CLAIM_ID = "11111111-1111-4111-8111-111111111111"
WORKFLOW_SHA = "a" * 40
BOT = "github-actions[bot]"


def registry() -> dict:
    return {
        "schema": "daimon-coordination-principals/v0",
        "receipt_authors": [BOT],
        "principals": {
            "codex@localhost": {
                "enabled": True,
                "github_logins": ["nicoechaniz"],
            },
            "compaii@localhost": {
                "enabled": True,
                "github_logins": ["nicoechaniz"],
            },
        },
    }


def command_body(
    *,
    action: str = "claim",
    command_id: str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    claim_id: str = CLAIM_ID,
    principal: str = "codex@localhost",
    at: dt.datetime = NOW,
    lease_seconds: int | None = 6 * 60 * 60,
    resources: list[str] | None = None,
    branch: str = "issue-6-claim-automation",
    pull_request: int | None = None,
    previous_receipt_id: str | None = None,
    previous_receipt_hash: str | None = None,
) -> dict:
    return {
        "schema": "daimon-claim-command/v0",
        "action": action,
        "command_id": command_id,
        "claim_id": claim_id,
        "issue": {"repository": ISSUE.repository, "number": ISSUE.number},
        "principal": principal,
        "session_id": None,
        "session_key": None,
        "at": format_timestamp(at),
        "lease_seconds": lease_seconds,
        "resources": resources
        or ["issue:AlterMundi/daimon-matrix#6", "path:coordination/**"],
        "branch": branch,
        "pull_request": pull_request,
        "previous_receipt_id": previous_receipt_id,
        "previous_receipt_hash": previous_receipt_hash,
        "note": None,
    }


def signed_command(
    key: Ed25519PrivateKey,
    **overrides: object,
):
    return validate_command(sign_command(command_body(**overrides), key))


def receipt_comment(wrapper: dict, comment_id: int = 2) -> dict:
    stamp = "2026-08-01T18:00:00Z"
    return {
        "id": comment_id,
        "created_at": stamp,
        "updated_at": stamp,
        "user": {"login": BOT},
        "body": render_block(RECEIPT_MARKER, wrapper),
    }


class CommandValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.key = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))

    def test_signed_claim_round_trips_from_slash_comment(self) -> None:
        wrapper = sign_command(command_body(), self.key)
        stamp = "2026-08-01T18:00:00Z"
        comment = {
            "id": 1,
            "created_at": stamp,
            "updated_at": stamp,
            "user": {"login": "nicoechaniz"},
            "body": render_block(COMMAND_MARKER, wrapper, "claim"),
        }
        parsed = parse_command_comment(comment)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.action, "claim")
        self.assertEqual(parsed.comment_author, "nicoechaniz")
        authorize_command(parsed, registry())

    def test_shared_login_sessions_are_cryptographically_distinct(self) -> None:
        other = Ed25519PrivateKey.from_private_bytes(bytes(range(33, 65)))
        left = signed_command(self.key)
        right = signed_command(
            other,
            command_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            claim_id="22222222-2222-4222-8222-222222222222",
            principal="compaii@localhost",
        )
        self.assertNotEqual(left.session_id, right.session_id)
        self.assertNotEqual(left.session_key.kid, right.session_key.kid)

    def test_modified_signed_body_is_rejected(self) -> None:
        wrapper = sign_command(command_body(), self.key)
        wrapper["body"]["branch"] = "issue-6-tampered"
        with self.assertRaisesRegex(CoordinationError, "invalid detached"):
            validate_command(wrapper)

    def test_session_key_substitution_is_rejected(self) -> None:
        wrapper = sign_command(command_body(), self.key)
        wrapper["body"]["session_key"]["public_key"] = "A" * 43
        with self.assertRaises(CoordinationError):
            validate_command(wrapper)

    def test_disabled_or_wrong_login_cannot_onboard_session(self) -> None:
        command = signed_command(self.key)
        command = command.__class__(**{**command.__dict__, "comment_author": "intruder"})
        with self.assertRaisesRegex(CoordinationError, "cannot onboard"):
            authorize_command(command, registry())

    def test_issue_resource_and_sorted_narrow_resources_are_required(self) -> None:
        with self.assertRaisesRegex(CoordinationError, "sorted"):
            signed_command(
                self.key,
                resources=["path:coordination/**", "issue:AlterMundi/daimon-matrix#6"],
            )
        with self.assertRaisesRegex(CoordinationError, "must include issue"):
            signed_command(self.key, resources=["path:coordination/**"])

    def test_lease_is_bounded(self) -> None:
        with self.assertRaisesRegex(CoordinationError, "60..86400"):
            signed_command(self.key, lease_seconds=86401)

    def test_release_requires_null_lease(self) -> None:
        with self.assertRaisesRegex(CoordinationError, "null lease"):
            signed_command(self.key, action="release")

    def test_review_requires_pull_request(self) -> None:
        with self.assertRaisesRegex(CoordinationError, "requires pull_request"):
            signed_command(self.key, action="review")

    def test_note_is_printable_ascii_only(self) -> None:
        body = command_body()
        body["note"] = "private snowman \u2603"
        with self.assertRaisesRegex(CoordinationError, "ASCII"):
            sign_command(body, self.key)

    def test_edited_command_comment_fails_closed(self) -> None:
        wrapper = sign_command(command_body(), self.key)
        comment = {
            "id": 1,
            "created_at": "2026-08-01T18:00:00Z",
            "updated_at": "2026-08-01T18:01:00Z",
            "user": {"login": "nicoechaniz"},
            "body": render_block(COMMAND_MARKER, wrapper, "claim"),
        }
        with self.assertRaisesRegex(CoordinationError, "edited"):
            parse_command_comment(comment)


class ClaimStateMachineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.key = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))

    def claim(self):
        return signed_command(self.key)

    def accept_claim(self):
        wrapper = decide_command(
            self.claim(),
            None,
            now=NOW,
            workflow_sha=WORKFLOW_SHA,
            issue_ready=True,
        )
        return validate_receipt(wrapper)

    def next_command(self, current, **overrides):
        defaults = {
            "command_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            "previous_receipt_id": current.receipt_id,
            "previous_receipt_hash": current.receipt_hash,
            "at": NOW + dt.timedelta(hours=1),
        }
        defaults.update(overrides)
        return signed_command(self.key, **defaults)

    def test_ready_issue_accepts_one_claim(self) -> None:
        receipt = self.accept_claim()
        self.assertEqual(receipt.decision, "accepted")
        self.assertEqual(receipt.state, "in_progress")
        self.assertEqual(receipt.lease_until, NOW + dt.timedelta(hours=6))

    def test_non_ready_issue_rejects_claim(self) -> None:
        wrapper = decide_command(
            self.claim(), None, now=NOW, workflow_sha=WORKFLOW_SHA, issue_ready=False
        )
        receipt = validate_receipt(wrapper)
        self.assertEqual(receipt.decision, "rejected")
        self.assertEqual(receipt.reason, "issue_not_ready")

    def test_second_live_claim_is_rejected_and_chained(self) -> None:
        current = self.accept_claim()
        other_key = Ed25519PrivateKey.from_private_bytes(bytes(range(33, 65)))
        other = signed_command(
            other_key,
            command_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            claim_id="22222222-2222-4222-8222-222222222222",
            principal="compaii@localhost",
            previous_receipt_id=current.receipt_id,
            previous_receipt_hash=current.receipt_hash,
        )
        receipt = validate_receipt(
            decide_command(other, current, now=NOW, workflow_sha=WORKFLOW_SHA, issue_ready=False)
        )
        self.assertEqual(receipt.decision, "rejected")
        self.assertEqual(receipt.reason, "already_claimed")
        self.assertEqual(receipt.claim_id, current.claim_id)

    def test_heartbeat_renews_same_session_with_bounded_lease(self) -> None:
        current = self.accept_claim()
        heartbeat = self.next_command(current, action="heartbeat", lease_seconds=86400)
        renewed = validate_receipt(
            decide_command(
                heartbeat,
                current,
                now=NOW + dt.timedelta(hours=1),
                workflow_sha=WORKFLOW_SHA,
                issue_ready=False,
            )
        )
        self.assertEqual(renewed.state, "in_progress")
        self.assertEqual(renewed.lease_until, NOW + dt.timedelta(hours=25))

    def test_another_session_cannot_heartbeat(self) -> None:
        current = self.accept_claim()
        other_key = Ed25519PrivateKey.from_private_bytes(bytes(range(33, 65)))
        heartbeat = signed_command(
            other_key,
            action="heartbeat",
            command_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            previous_receipt_id=current.receipt_id,
            previous_receipt_hash=current.receipt_hash,
            at=NOW + dt.timedelta(hours=1),
        )
        receipt = validate_receipt(
            decide_command(
                heartbeat,
                current,
                now=NOW + dt.timedelta(hours=1),
                workflow_sha=WORKFLOW_SHA,
                issue_ready=False,
            )
        )
        self.assertEqual(receipt.reason, "claimant_session_mismatch")

    def test_release_returns_ready_and_is_auditable(self) -> None:
        current = self.accept_claim()
        release = self.next_command(current, action="release", lease_seconds=None)
        released = validate_receipt(
            decide_command(
                release,
                current,
                now=NOW + dt.timedelta(hours=1),
                workflow_sha=WORKFLOW_SHA,
                issue_ready=False,
            )
        )
        self.assertEqual(released.decision, "accepted")
        self.assertEqual(released.state, "ready")
        self.assertIsNone(released.lease_until)

    def test_expiry_posts_content_bound_ready_receipt(self) -> None:
        current = self.accept_claim()
        wrapper = expire_if_due(
            current,
            now=NOW + dt.timedelta(hours=7),
            workflow_sha=WORKFLOW_SHA,
        )
        self.assertIsNotNone(wrapper)
        expired = validate_receipt(wrapper)
        self.assertEqual(expired.decision, "expired")
        self.assertEqual(expired.reason, "lease_expired")
        self.assertEqual(expired.state, "ready")

    def test_expiry_is_not_early(self) -> None:
        self.assertIsNone(
            expire_if_due(
                self.accept_claim(),
                now=NOW + dt.timedelta(hours=5),
                workflow_sha=WORKFLOW_SHA,
            )
        )

    def test_review_binds_pull_request_and_renews(self) -> None:
        current = self.accept_claim()
        review = self.next_command(
            current,
            action="review",
            pull_request=68,
            lease_seconds=6 * 60 * 60,
        )
        receipt = validate_receipt(
            decide_command(
                review,
                current,
                now=NOW + dt.timedelta(hours=1),
                workflow_sha=WORKFLOW_SHA,
                issue_ready=False,
            )
        )
        self.assertEqual(receipt.state, "in_review")
        self.assertEqual(receipt.pull_request, 68)

        heartbeat = signed_command(
            self.key,
            action="heartbeat",
            command_id="cccccccc-cccc-4ccc-8ccc-cccccccccccc",
            at=NOW + dt.timedelta(hours=2),
            previous_receipt_id=receipt.receipt_id,
            previous_receipt_hash=receipt.receipt_hash,
        )
        heartbeat_receipt = validate_receipt(
            decide_command(
                heartbeat,
                receipt,
                now=NOW + dt.timedelta(hours=2),
                workflow_sha=WORKFLOW_SHA,
                issue_ready=False,
            )
        )
        self.assertEqual(heartbeat_receipt.state, "in_review")
        self.assertEqual(heartbeat_receipt.pull_request, 68)

    def test_stale_command_head_is_rejected(self) -> None:
        current = self.accept_claim()
        heartbeat = signed_command(
            self.key,
            action="heartbeat",
            command_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            at=NOW + dt.timedelta(hours=1),
        )
        receipt = validate_receipt(
            decide_command(
                heartbeat,
                current,
                now=NOW + dt.timedelta(hours=1),
                workflow_sha=WORKFLOW_SHA,
                issue_ready=False,
            )
        )
        self.assertEqual(receipt.reason, "stale_receipt_head")

    def test_clock_skew_is_rejected(self) -> None:
        command = signed_command(self.key, at=NOW - dt.timedelta(hours=1))
        receipt = validate_receipt(
            decide_command(command, None, now=NOW, workflow_sha=WORKFLOW_SHA, issue_ready=True)
        )
        self.assertEqual(receipt.reason, "command_clock_skew")

    def test_global_resource_conflict_rejects_otherwise_ready_claim(self) -> None:
        receipt = validate_receipt(
            decide_command(
                self.claim(),
                None,
                now=NOW,
                workflow_sha=WORKFLOW_SHA,
                issue_ready=True,
                conflict_reason="resource_conflict",
            )
        )
        self.assertEqual(receipt.decision, "rejected")
        self.assertEqual(receipt.reason, "resource_conflict")

    def test_rejected_receipt_preserves_live_effective_claim(self) -> None:
        current = self.accept_claim()
        attacker = signed_command(
            Ed25519PrivateKey.from_private_bytes(bytes(range(33, 65))),
            command_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            claim_id="22222222-2222-4222-8222-222222222222",
            principal="compaii@localhost",
            previous_receipt_id=current.receipt_id,
            previous_receipt_hash=current.receipt_hash,
        )
        rejected = validate_receipt(
            decide_command(
                attacker,
                current,
                now=NOW,
                workflow_sha=WORKFLOW_SHA,
                issue_ready=False,
            )
        )
        self.assertTrue(rejected.is_live(NOW))
        self.assertEqual(rejected.claim_id, current.claim_id)


class ReceiptAuditTests(unittest.TestCase):
    def setUp(self) -> None:
        self.key = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
        self.command = signed_command(self.key)
        self.first_wrapper = decide_command(
            self.command, None, now=NOW, workflow_sha=WORKFLOW_SHA, issue_ready=True
        )

    def test_receipt_round_trips_only_from_bot_comment(self) -> None:
        parsed = parse_receipt_comment(receipt_comment(self.first_wrapper), registry())
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.comment_author, BOT)
        self.assertEqual(reduce_receipts([parsed], ISSUE), parsed)

    def test_non_bot_receipt_is_rejected(self) -> None:
        comment = receipt_comment(self.first_wrapper)
        comment["user"]["login"] = "nicoechaniz"
        with self.assertRaisesRegex(CoordinationError, "not authorized"):
            parse_receipt_comment(comment, registry())

    def test_modified_receipt_body_is_rejected(self) -> None:
        self.first_wrapper["body"]["state"] = "ready"
        with self.assertRaisesRegex(CoordinationError, "ID/hash"):
            validate_receipt(self.first_wrapper)

    def test_deleted_or_reordered_receipt_breaks_chain(self) -> None:
        first = validate_receipt(self.first_wrapper, comment_id=1)
        heartbeat = signed_command(
            self.key,
            action="heartbeat",
            command_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            at=NOW + dt.timedelta(hours=1),
            previous_receipt_id=first.receipt_id,
            previous_receipt_hash=first.receipt_hash,
        )
        second = validate_receipt(
            decide_command(
                heartbeat,
                first,
                now=NOW + dt.timedelta(hours=1),
                workflow_sha=WORKFLOW_SHA,
                issue_ready=False,
            ),
            comment_id=2,
        )
        with self.assertRaisesRegex(CoordinationError, "chain"):
            reduce_receipts([second], ISSUE)

    def test_global_resource_overlap_is_reported(self) -> None:
        left = validate_receipt(self.first_wrapper)
        other_key = Ed25519PrivateKey.from_private_bytes(bytes(range(33, 65)))
        other_issue = IssueRef("AlterMundi/daimon-matrix", 10)
        body = command_body(
            command_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            claim_id="22222222-2222-4222-8222-222222222222",
            principal="compaii@localhost",
            resources=[
                "issue:AlterMundi/daimon-matrix#10",
                "path:coordination/**",
            ],
        )
        body["issue"] = {"repository": other_issue.repository, "number": other_issue.number}
        other_command = validate_command(sign_command(body, other_key))
        right = validate_receipt(
            decide_command(
                other_command,
                None,
                now=NOW,
                workflow_sha=WORKFLOW_SHA,
                issue_ready=True,
            )
        )
        findings = audit_resource_overlaps([left, right], now=NOW)
        self.assertEqual(findings[0].code, "overlapping_claims")

    def test_receipt_builder_rejects_unknown_fields(self) -> None:
        body = dict(self.first_wrapper["body"])
        body["secret"] = "no"
        with self.assertRaisesRegex(CoordinationError, "not closed"):
            build_receipt(body)


if __name__ == "__main__":
    unittest.main()
