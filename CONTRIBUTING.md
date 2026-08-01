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
