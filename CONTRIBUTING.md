# Contributing

## Language

Use English for documentation, issues, comments, commits, PRs, schemas, APIs,
and project metadata.

## One issue, one claim, one PR

An issue is claimable only when:

- it has `status:ready`;
- every `Blocked by` item is closed;
- no active lease exists;
- its acceptance criteria are complete.

Claims are processed by the signed GitHub coordination protocol in
[`docs/github-coordination.md`](docs/github-coordination.md). Generate and post
the complete signed comment; its visible first line is:

```text
/claim
```

The automation verifies the explicit enabled coordination principal, GitHub
login, detached per-session attestation, exact issue/resources, branch, and
current receipt head. Its content-bound receipt records the session, branch,
start, resources, and UTC expiration. Renew with a signed `/heartbeat` for at
most 24 hours, enter review with signed `/review`, and relinquish with signed
`/release`. Expired leases are released automatically with an auditable
receipt. A plain slash line or old manual receipt grants no post-DM-003
ownership.

Use `issue-<number>-<slug>` branches. A PR must identify its primary issue and
include `Closes #N`. Do not combine unrelated issues or silently expand scope.

## Cross-repository work

The central Project may contain work from several repositories. The
implementation issue must live in the repository that owns the changed code.
Link it to its Daimon Matrix parent issue and the `daimon-matrix` Project.

## Concurrent work

Before beginning implementation:

1. inspect active sessions, branches, and worktrees;
2. record overlapping files and contracts;
3. prefer preserving and adapting existing work;
4. do not ask another session to stop until the relevance audit has evidence;
5. release the claim when ownership or scope becomes uncertain.

## Review

Security, identity, cryptography, migrations, and persistent-state changes
require an independent review. Tests must assert behavioral invariants and
real I/O paths, not only mocked snapshots.

## Delivery cadence

One accountable owner carries a coherent change through implementation,
qualification, review, and its authorized rollout. A handoff transfers that
work; it does not restart design or erase previously verified evidence.

- Read current remote heads and the installed release separately. A stale local
  checkout, an approved PR, a merge, and a healthy deployment are different facts.
- Plan the complete implementation/test/documentation resource set in the signed
  claim. Renew a live lease; do not release/reclaim for each routine edit. If the
  protocol requires a successor for a real scope change, make one coherent scope
  update. Never impersonate the previous owner or ignore an active conflicting claim.
- Run focused regressions while editing and the relevant complete gates on the
  finished candidate. Use `python tools/qualify.py --help` for the isolated unit
  runner and exact contract preflight. Keep build, secrets, and external contract
  jobs: the unit runner does not replace them or prove a live deployment.
- Request independent review on a qualified exact head. Re-review fixes and
  affected invariants; do not restart an unrelated full-stack audit each round.
  New evidenced blockers still need correction. Optional improvements belong in
  follow-up issues, not an indefinitely expanding release scope.
- Before merge, require current-head approval and relevant CI success. Pending,
  cancelled, timed-out, or skipped checks are not successful qualifications.
- For a rollout, identify the actual deployment branch, exact dependency pin,
  startup configuration, required state migration, health probe, and rollback
  before changing the service. Bundle already-authorized steps. Ask again only
  for a material change of scope, risk, recipient, or authority.
- Maintain one short current-state handoff: installed/candidate SHAs, evidence,
  remaining blockers, next executable action. Link detailed logs instead of
  duplicating progress narratives. Report milestones and material risks to the
  human, not each claim heartbeat or command.

GitHub is the durable development coordination channel. Do not require Tribe
delivery or a new identity/custody ceremony merely to develop its replacement.
This does not change runtime identity, consent, or disclosure requirements.
