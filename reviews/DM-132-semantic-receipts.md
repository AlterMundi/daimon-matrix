# Issue 132 semantic receipts — implementation handoff

**Author self-review / implementation record, not independent approval.**
Base: `acb131f18c200bb028ee86fa3a8ef9a2f6c040a3`.
Worktree: `/home/debian/dm-milestone2-issue132`.
Accepted public successor scope: `3bb82bbf-ecc5-4345-9349-6b5537788575`.
No commits, pushes, GitHub mutations, production/custody access or service changes.
Only synthetic test custody and loopback listeners were used.

## Implemented boundary

- Explicit application V2; V1 application/binding contracts unchanged. The V1
  operator-binding domain already signs the exact V2 application digest; no new
  binding format was needed.
- New V2 sends sign their expected recipient being. Receipt validation binds that
  original being, original message/resolution ID+hash, membership, embodiment,
  thread, signed timestamp and complete nested signature. No origin-label shortcut.
- Reply-triggered, delivered/intake-only receipt authoring in the recipient's own
  Ledger. Existing application correlation and null canonical reply remain.
- Request-conflict reservation precedes private receipt authoring. Stable
  once-per-original receipt intent/time uses the existing outbox's disjoint owner
  namespace; no outbox catalog or new Python module was needed. Different reply
  operations reuse the same receipt. Original request expiry is not renewed.
- Foreign proof storage and ID/origin-position collision checks are separate from
  canonical events. Both V1/V2 terminal paths quarantine competing evidence.
  Terminal result reads reverify full proof and canonical projection bindings.
- Inbox retention and reduction are separate transactions. Exact intake replay
  and explicit current-authorized startup reconciliation converge without sending.
- Offline predecessor-bound signed publication migration, unexpired V1 authoring
  drain, expired-reservation preservation, unchanged transport retry digest,
  schema-only atomic transition, genuine fresh-runtime restart/continuation.
- V2 projection mutations journal exact pre/post snapshot hashes and counters
  around anchor/DB commits. Exact pending states recover; unrelated tampering
  fails closed. V1 commit behavior is unchanged.
- No changes to Ledger, weave, runtime.py, sealing, transport wire schemas,
  capabilities, grant validity, endpoints or autonomous scheduling.

## Verification record

Environment: read-only `/home/debian/dm-milestone2-test-venv/bin/python`,
`PYTHONPATH=src`, collective contract at
`/home/debian/dm-milestone2-collective-contract`. No pip/environment mutation.
This environment lacks pytest; tests ran with the repository's unittest suites.

- TDD red/green slices: missing foreign reducer; retained-proof corruption;
  reply carrier/terminal journey; explicit migration; missing foreign table;
  anchor-before-DB crash; projection binding tampering; pre-sign request conflict;
  unexpired/expired V1 authoring migration.
- First broad bounded cohort: 131 tests, one skip, only DM-041 generated-artifact
  drift failed. Source-hash-derived provenance/profile/launch/index artifacts
  subsequently regenerated using the existing generator. One redundant broad
  rerun was intentionally stopped during follow-up authoring-order correction;
  it is not passing evidence.
- Post-correction receipt + DM-052 + native send/reply RPC cohort: 39 tests passed.
- Final frozen focused cohort: PENDING.
- Changed-file Ruff passed; mypy passed all 58 source modules. Three new schemas
  passed Draft 2020-12 meta-validation; the public V2 application equals the
  runtime V1 shape with only its schema version and `$id` changed.
- `generate_dm041_vectors.py --check` and `git diff --check` passed after generation.
- A broad `ruff check src tools tests` also exposed existing violations in
  untouched legacy vector/coordination files; they were not edited or hidden.

## Qualification limits / review focus

This is a bounded software candidate, not issue-wide/live acceptance or release
approval. The parent owns independent exact-candidate review, full suite,
packaging/install gates, commits, PR/merge and deployment.

- The new bidirectional journey uses independent roots/custody/stores, actual
  Unix-socket service calls and the production HTTP handler with server threads.
  It is not a separate-daemon-process V2 journey. Existing process lifecycle tests
  remain unchanged. The same-embodiment-ID A/B/C attack is exercised through the
  real cryptographic reducer, not a complete three-peer HTTP deployment.
- Reply-triggered only; no reply means no receipt. Legacy messages remain
  explicitly untracked. `delivered` is durable intake, never consumption/task success.
- Migration is a trusted Python operator entry point under the existing runtime
  lock, not a new CLI command. No downgrade by deleting successor state is supported.
- Snapshot journaling is O(total communication projection size) per mutation;
  large-store performance and exhaustive OS power-loss/fsync interleavings need
  independent qualification. The new tests exercise pre/post durable boundaries,
  lost returns, fresh runtime restart and tampered pending snapshots.
- V1 conformance fixtures are preserved; successor tests live in the focused
  unittest file, not newly registered conformance scenario IDs.
