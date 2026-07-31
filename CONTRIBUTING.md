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

Claim with:

```text
/claim agent=<agent/session identity> lease=6h branch=issue-<number>-<slug>
```

The claim receipt records the claimant, branch or worktree, start time, and UTC
expiration. Renew with `/heartbeat lease=<duration>` up to 24 hours. Release
with `/release`.

Until automation is implemented, a human- or agent-posted receipt using the
same format is authoritative.

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

