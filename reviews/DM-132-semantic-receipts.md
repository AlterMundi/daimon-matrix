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

## Independent-review remediation (B1 / B2 / B3)

This section supersedes the earlier pending focused-cohort entry only for this
follow-up. It is an implementation/self-review record, not independent approval.
The independent review examined `0d623f2a286cbf635b0097cd2117cf42b3b6264e`;
this correction starts from `ea4c324c1f4a4116a9b752de5c4b420898fb1b39` and
preserves that head's two schema `$id` corrections unchanged.

- **B1:** V2 result validation verifies the canonical message and resolution,
  reconstructs the complete expected recipient-key set, and compares the exact
  message projection, leg count, IDs, immutable fields and hashes. Validation
  applies without a receipt, including pending and quarantined legs. Commit and
  replay guards enumerate messages, not only surviving legs, so deletion of every
  leg is also rejected. Mutations validate before changing projections and again
  before arming the commit; corrupted evidence cannot be overwritten into validity.
- **B2:** Local receipt admission and V2 replay share exact message/thread/recipient
  and outcome-specific origin binding. Replay also verifies the canonical event,
  retained receipt projection bytes and columns, and terminal columns. Retained
  local evidence is checked even when the current leg is quarantined. No V1
  receipt wire format or origin policy was changed.
- **B3:** Direct leg reads and cached page, claim, attempt, delivery, ACK and
  consumer-progress paths revalidate canonical vectors and retained proofs before
  returning. Cached page/claim documents are closed and request-bound; item
  immutable fields, sequence ordering, cursor bindings and claimed terminal
  receipt/outcome are checked. Attempts retain exact request-byte/hash/column
  checks. Historical accepted snapshots remain accepted after later delivery and
  compaction; a historical delivered page can survive later quarantine only with
  the original verified proof. Replay does not renew a lease or manufacture a
  new receipt. Read/rebuild validation uses the same SQLite snapshot as the read;
  validators use the caller's connection, without reentrant Ledger/store calls.

The original external review probes were integrated into
`tests/test_cross_being_semantic_receipts.py`, including the signature/carrier,
compaction, restart and real-runtime migration controls. Formatting/import cleanup
and explicitly bound fault-injection closures preserve the original scenarios.
Additional tests cover all pending immutable-field mutations, extra/all-missing
legs, local receipt projection corruption and wrong delivered origin, cached
neighbor routes, historical reads after compaction/quarantine, tampered cache
contents, attempt bytes, and pagination bindings.

Verification at source freeze:

- Reproduced the independent review's five failing assertions before fixes.
- Final bounded cohort: **120 passed**, no skips, exit 0 (404.066 s): the existing
  106-test cohort plus all eight original probe methods and six additional
  regression methods. Command:
  `python -m unittest -q tests.test_cross_being_semantic_receipts tests.test_native_messaging tests.test_operator_messaging tests.test_dm052_communication tests.test_messaging_runtime`.
  An earlier 118-test run had one test-fixture error (an invalid SQLite enum in
  a corruption probe); the valid-but-wrong enum mutation was corrected and the
  complete final cohort rerun. That earlier run is not passing evidence.
- Unmodified external eight-method probe script: **8 passed**, no skips, exit 0.
  Both actual-runtime migration crash subcases passed.
- Changed-source/test Ruff and format checks passed; mypy passed all 58 modules.
- DM-041 check detected exactly the four scope-authorized source-derived artifacts.
  Regenerated only those four after source/format freeze; generator `--check`
  passed. `tests.test_dm041_hermes_body.PublicContractTests`: **2 passed**, no
  skips, exit 0. No package-module inventory or schema-ID change was needed.

Limits remain explicit: V2 validation scans retained projections and cryptographic
proofs, including cached paths; large-store performance is not qualified. This is
not protection against arbitrary coherent replacement of all local state/trust
anchors, nor a new authenticated history of route ACKs or consumer cursors. The
preexisting V1 wire and replay semantics remain. Full CI, independent re-review,
new exact-source wheel/sdist builds and installed-runtime checks remain parent
responsibilities. Prior `0d623f2` artifact checks do not qualify these changed
runtime bytes. No milestone, live-pilot, deployment or release completion is claimed.

## 2026-09-17 F1/F2/F3 repair and migration follow-up

**Author/self-review remediation record; this is not independent approval.** This
section appends to, and does not replace or relabel, the historical failed,
pending, superseded, and passing records above. It records the bytes frozen after
Ruff formatting and the subsequent DM-041 regeneration. No repository-wide suite,
hosted CI result, independent verdict, deployment, or release approval is claimed.

The committed base remains `971239c2cbbdb41ec839715d01788a132ae90d9a`.
Immediately before this Markdown append, `git diff --binary | sha256sum` was
`ae708fbcfebb9a40166fe76291c3d7f7e0f840baafa245970dde8073f0a16bae`.
That receipt-excluded delta included the frozen code/tests and regenerated derived
outputs; the exact file hashes were
`b7c2fbed7caf53b653ce5d19c3de301ab3552341cc731f797866a96ee147d456`
for `src/daimon_matrix/communication.py` and
`f1fc54f2cc3924caeb42e0aec1056aaee63fb87355deddd2990d9e1372603b95`
for `tests/test_cross_being_semantic_receipts.py`. The final serialized delta hash
cannot be embedded in this file without changing that hash; it is returned in the
author handoff after this append and the final hygiene gates.

### Current remediation boundary

For the earlier repair set described by the independent report as the original
F1/F2/F3:

- **Admission/version remediation:** inbox and outgoing-context stores persist an
  `admission_version` per retained row. Existing authenticated rows are
  transactionally classified as version 1 before communication V2 activation;
  admission is resolved before semantic validation and retained in the same
  SQLite transaction as the message. Receipt-looking V1 rows remain readable and
  inert, while only rows admitted as version 2 can reduce a semantic receipt.
  Conflicting replay classification fails closed.
- **Queue, compaction, and persisted-consumer remediation:** V2 validates exact
  queue-to-leg bindings, completeness, durable compaction evidence, and every
  persisted consumer using closed text/integer checks, generation equality,
  high-water bounds, target ownership, and a complete terminal prefix. Equal
  consumer replay does not bypass validation. This follow-up closes the remaining
  independent F1 migration gap: the same `_validate_consumers()` path now runs
  before either V2-only table is created or `schema_version` can change, and
  legacy compaction inference additionally runs `_validate_consumer_position()`
  for every participating consumer rather than relying on
  `min(sequence) >= through`.
- **Constructor-free retry remediation:** migration validates the existing inbox
  and outgoing-context SQLite schemas by path and performs the admission upgrade
  without constructing a store that could create a missing database. A V2 retry
  with a missing inbox returns `messaging_required_store_invalid`; the absent path
  remains absent. Publication order remains successor metadata publication,
  constructor-free store validation/admission classification, communication V2
  transaction, composition/reconciliation, and only then publication selection.

The independent re-review's **F1** is addressed by the pre-DDL persisted-consumer
validation and compaction-participant check above. Every permanent negative test
asserts that failure leaves `communication_meta.schema_version` exactly `1`,
`CommunicationStore.receipts_v2` false, and both
`communication_foreign_receipts` and `communication_compactions` absent after
rollback. The independent re-review's **F2** is addressed by this dated appended
author record; no historical evidence was edited into a later verdict.

### Strict vertical RED -> GREEN evidence

All migration slices use the real `CommunicationStore`, Ledger SQLite database,
normal sender preparation, signed synthetic identities, and real cryptographic
code. The shared command prefix was exactly:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src \
COLLECTIVE_MEMORY_CONTRACT_ROOT=/home/debian/dm-milestone2-collective-contract \
/home/debian/dm-milestone2-test-venv/bin/python -m unittest -v
```

Each named test was added and run before its production slice:

1. `...MigrationReviewProbes.test_v1_consumer_wrong_generation_cannot_commit_v2_schema`
   RED: exit 1, one failure, `ValueError not raised`, 0.991 s. GREEN: included
   in the cumulative two-test run, exit 0.
2. `...MigrationReviewProbes.test_v1_consumer_beyond_highwater_cannot_commit_v2_schema`
   RED: exit 1, one failure, `ValueError not raised`, 1.177 s. GREEN cumulative:
   2 tests, exit 0, 2.355 s.
3. `...MigrationReviewProbes.test_v1_consumer_malformed_type_cannot_commit_v2_schema`
   used a SQLite-representable BLOB `consumer_id`. RED: exit 1, one failure,
   `ValueError not raised`, 0.925 s. GREEN cumulative: 3 tests, exit 0, 3.094 s.
4. `...MigrationReviewProbes.test_v1_consumer_unowned_target_cannot_commit_v2_schema`
   RED: exit 1, one failure, `ValueError not raised`, 1.131 s. GREEN cumulative:
   4 tests, exit 0, 4.107 s.
5. `...MigrationReviewProbes.test_v1_compaction_participant_must_be_terminal_prefix`
   RED: exit 1, one failure, `ValueError not raised`, 1.715 s. GREEN cumulative:
   5 tests, exit 0, 5.408 s.
6. `...MigrationReviewProbes.test_v1_consumer_nonterminal_prefix_cannot_commit_v2_schema`
   was finalized to use a terminal target with an earlier pending leg for the same
   recipient. RED: exit 1, one failure, `ValueError not raised`, 1.493 s. GREEN
   cumulative: 6 tests, exit 0, 7.167 s.

Positive controls were then run together: clean V1 migration and legitimate
compacted-terminal migration, 2 tests, exit 0, 2.196 s. After Ruff formatting,
the complete `MigrationReviewProbes` class ran 11 tests in 30.585 s, exit 0.

### Frozen-byte qualification

- Ruff 0.16.1 formatting changed two of the seven changed Python files; the
  subsequent format check reported all 7 already formatted and Ruff check passed.
- Strict mypy with `MYPYPATH=src` and a fresh cache reported
  `Success: no issues found in 58 source files`.
- Focused five-module cohort:
  `tests.test_cross_being_semantic_receipts`, `tests.test_native_messaging`,
  `tests.test_operator_messaging`, `tests.test_dm052_communication`, and
  `tests.test_messaging_runtime`: **135 tests**, exit 0, 479.574 s, no skips
  reported. This is a focused cohort, not the repository's full suite.
- `tools/generate_dm041_vectors.py --check` detected exactly the four expected
  source-derived paths: `provenance/hermes-agent-0.19.0.json`,
  `vectors/hermes/v1/index.json`,
  `vectors/hermes/v1/valid/launch-receipt.json`, and
  `vectors/hermes/v1/valid/profile-manifest.json`. Only those four were
  regenerated; the next generator check passed.
- `tests.test_dm041_hermes_body.PublicContractTests`: 2 tests, exit 0, 0.338 s.

### Current limitations

Validation is an O(total persisted projection) migration/read cost and has not
received large-store load qualification. The tests cover real SQLite transactions,
real signatures/crypto, restart paths, and application publication boundaries,
but not physical power loss, filesystem faults below SQLite/fsync, a separate
multi-process deployment, hosted CI, package rebuild/install qualification, or
arbitrary coherent replacement of all local state and trust anchors. The V1 wire
and replay contracts remain unchanged. Independent re-review and all merge,
release, live-pilot, and deployment decisions remain parent responsibilities.
