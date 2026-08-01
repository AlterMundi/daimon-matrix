# Signed GitHub work coordination

GitHub Issues, pull requests, and AlterMundi Project 9 are the work
coordination plane. This protocol is orthogonal to `/tribe`, `/me`, `/we`, and
runtime presence. A coordination label such as `codex@localhost` is not a
transport principal or Daimon identity.

## Trust boundary

The public issue log contains two append-only records:

1. an agent posts a slash command plus a canonical
   `daimon-claim-command/v0` body signed by a dedicated ephemeral Ed25519
   session key; and
2. the default-branch GitHub workflow serializes all mutations, re-reads the
   current receipt chain, and posts a content-bound
   `daimon-claim-receipt/v0` acceptance, rejection, release, or expiry.

The allowlist in [`coordination/principals.json`](../coordination/principals.json)
controls which GitHub logins may onboard a fresh session under a logical
coordination principal. The command's content-derived `session_id` then makes
two sessions using the same GitHub account distinguishable: heartbeat, review,
and release MUST use the exact claim session key.

This is work attribution, not `/me` proof. The shared GitHub account can still
onboard a new allowed session, GitHub administrators can alter repository
state, and GitHub availability remains an external dependency. Receipt hashes
and predecessor links make edits, deletion gaps, reordering, and forks
detectable; they do not create an independent timestamp or transparency log.

## State machine

```text
ready --claim--> in_progress --review--> in_review
  ^                    |                    |
  |                    +----release--------+
  +-----------------expiry-----------------+
```

- A claim is accepted only when the issue has `status:ready`, its required
  issue resource is present, no live receipt owns the issue, and no other live
  claim overlaps an exact resource.
- All claim mutations share one workflow concurrency group. A second command
  is evaluated only after the first receipt is visible.
- A lease lasts from 60 seconds through 24 hours. `/heartbeat` renews from the
  workflow's trusted current time and preserves `in_review` when applicable.
- `/release` posts a terminal ready receipt. The scheduled expiry job checks
  ready, claimed, and review issues every ten minutes, posts an expiry receipt,
  restores `status:ready`, and reconciles label drift from the authoritative
  receipt chain.
- Label transitions drive the existing Project 9 automation. Receipts remain
  authoritative if the Project view drifts.
- Rejected commands also receive a chained receipt but do not change the
  effective owner, lease, branch, resources, PR, or label.

## Resources

Resources are sorted exact strings. Every claim includes
`issue:AlterMundi/daimon-matrix#N`. Optional narrow resources use `path:`,
`service:`, `project:`, or `protocol:`. There are no globs beyond the literal
text a claimant publishes and no semantic overlap inference: agents must name
the shared collision boundary explicitly.

## Creating a command

Generate a dedicated session key outside the repository. Do not reuse a
Daimon root, operational, transport, SSH, signing, or encryption key.

```bash
openssl genpkey -algorithm ED25519 -out /protected/path/coord-session.pem
```

Create a closed JSON command body with `session_id` and `session_key` set to
`null`; the signing tool fills them from the private key. A first claim has
null predecessor fields:

```json
{
  "action": "claim",
  "at": "2026-08-01T18:00:00Z",
  "branch": "issue-6-claim-automation",
  "claim_id": "11111111-1111-4111-8111-111111111111",
  "command_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
  "issue": {"number": 6, "repository": "AlterMundi/daimon-matrix"},
  "lease_seconds": 21600,
  "note": "Implement DM-003.",
  "previous_receipt_hash": null,
  "previous_receipt_id": null,
  "principal": "codex@localhost",
  "pull_request": null,
  "resources": [
    "issue:AlterMundi/daimon-matrix#6",
    "path:coordination/**"
  ],
  "schema": "daimon-claim-command/v0",
  "session_id": null,
  "session_key": null
}
```

Render the complete comment and paste it without editing:

```bash
python tools/github_coordination.py sign \
  --body /path/to/command.json \
  --private-key /protected/path/coord-session.pem
```

For `/heartbeat`, `/review`, and `/release`, retain the claim ID, principal,
session key, resources, and branch, use a fresh command UUID/time, and cite the
exact latest receipt ID/hash. Review also names the PR. Release has null
`lease_seconds` and `pull_request`; the receipt retains historical PR linkage.

## Automation and audit

The workflow handles only newly created, unedited comments whose slash command
matches the signed action. It checks the current default-branch registry and
workflow SHA, verifies the detached signature, re-reads every bot-authored
receipt, detects a broken chain, checks global resources, posts one receipt,
and then changes the status label.

Operators can audit without mutation:

```bash
python tools/github_coordination.py \
  --repo AlterMundi/daimon-matrix audit-issue --issue 6

python tools/github_coordination.py \
  --repo AlterMundi/daimon-matrix audit-pr --pr 68
```

The PR body must contain `Closes #N`, the canonical UUID `Claim-ID`, an exact
deployment declaration, and a non-empty `## Tests` section. The effective
receipt must be live, `in_review`, and bind the same branch and PR number.

## Recovery and rollback

- A missing, edited, reordered, or forked receipt fails closed. Repair by
  restoring the append-only evidence or by an explicit maintainer-reviewed
  coordination recovery; never silently rewrite a comment.
- An agent that loses its session private key cannot heartbeat or release.
  The lease expires automatically; a new session can then submit a fresh claim
  citing the ready receipt.
- Workflow failure leaves the signed command pending and changes no authority.
  Re-run the workflow after repair; do not hand-edit a receipt.
- Disable `.github/workflows/coordination.yml` to stop mutations. Existing
  receipts remain auditable. Reverting DM-003 returns to manual claims but does
  not erase public comments or branch/PR evidence.

DM-003 itself is the bootstrap exception: its pre-automation manual claim and
PR cannot have been accepted by a workflow that does not yet exist. The PR
workflow skips only branch `issue-6-claim-automation`; no future issue or branch
inherits that exception.
