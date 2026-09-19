# DM-136 author evidence — F1 repair

**Status:** local repair complete and independently reproducible; no commit, push, review post, merge, deploy, or live-provider mutation was performed.

## Exact review boundary

- Worktree: `/home/debian/dm-milestone2-issue136`
- Active claim: `6267e9c6-fa42-4d8f-81be-02e5f5873895` (57 resources; supplied lease through `2026-09-20T08:14:27.960308Z`)
- Branch HEAD: `d8e496fc10245f6b4285e102ff0ea2773553751f`
- HEAD tree: `1cb00263e5806c302c09f8416e70bce41e3af9de`
- `origin/main`: `e1df21e5e35c74875fbcc9b43f202b0899be8b24`
- merge base with `origin/main`: `e1df21e5e35c74875fbcc9b43f202b0899be8b24`
- commits over base: `b097bd9`, `1fb0fd2`, `d8e496f`
- Initial tracked+untracked serialization SHA-256 supplied and reproduced before this repair: `0778828f92678eb57a5fb80fb6ab2b27a3909013f8a810f7230f3baec47322a4`
- Independent F1/F2 report: `/home/debian/agents/compaii-daimonmatrix/work/messaging-rollout/reviews/DM-136-F1F2-INDEPENDENT.md`
- Independent report SHA-256: `2837a09e8dcc02f777f21f718a32a7b51d5cdb95444b537fb554fd57209e89bb`
- F2 disposition: the report's expected base was stale/nonexistent. The correct boundary is the one above; no F2 code repair was made.

## Scope

This pass repairs only independent finding F1. It changes the existing uncommitted DM-136 author tree only in:

- `src/daimon_matrix/operator_messaging.py` — journal entry publication/recovery.
- `tests/test_operator_messaging.py` — permanent vertical crash-boundary and residue/conflict regressions.
- this evidence file.

All other changed paths predate this F1 repair and were preserved. The approved F3 paths are byte-identical to `HEAD` (see preservation evidence below).

## Root cause and working reference

The old journal append path called `_write(state_root, authoritative_sequence_name, raw)`. `_write` opened that final name with `O_CREAT|O_EXCL`, then wrote in a loop and fsynced it. An interruption after the first successful `write(2)` therefore left a prefix at the authoritative immutable filename. Restart/retry could neither parse it nor replace it: chain loading failed closed on the malformed final, while another `_write` failed `O_EXCL`.

The repository already had the required Linux no-replace primitive in the same module: `_publish(staging, target)` invokes `renameat2(..., RENAME_NOREPLACE)`. The repair reuses that primitive rather than implementing a check-then-rename substitute.

The replacement path now:

1. recognizes only `<exact-final>.stage-<32 lowercase hex>` residue for the exact entry;
2. bounds recognized residue to eight entries and rejects before deleting if the bound is exceeded;
3. deletes only owner-owned regular `0600`, single-link, bounded-size recognized residue; malformed names, insecure metadata, special files, hardlinks, and excess residue reject and remain untouched;
4. writes complete canonical bytes to a same-directory private staging file and fsyncs the file through existing `_write`;
5. atomically installs the authoritative sequence name through existing `_publish`/`RENAME_NOREPLACE`;
6. fsyncs the containing state directory;
7. treats an already-installed exact final as converged after protected metadata/content validation, while a conflicting final remains immutable and rejects.

The helper is used by genesis (`prepare`), successor replacement (`renew`/`recover`), and revocation. Existing locks, authenticated record construction, sequence/predecessor chain, monotonic revocation, and pointer publication/repair remain the callers around this narrowly changed publication seam.

## Strict vertical RED → GREEN receipts

The permanent tests inject failures through the real public seams and identify the actual journal file descriptor via `/proc/self/fd`; no production-only fault hook was added. Each lifecycle slice was made RED before its production call site was changed.

### Slice 1 — revocation

RED command:

```bash
env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. /tmp/dm136-review-venv/bin/python -B -m unittest -v \
  tests.test_operator_messaging.ProvisioningTests.test_revocation_journal_publication_is_atomic_and_retry_converges
```

RED result: exit `1`; `Ran 1 test in 13.288s`; failures showed the old partial authoritative final was retained (`JSONDecodeError`) and the later no-replace boundary was never reached. Wall time `13.755s`. This is the reported F1, not a synthetic helper-only failure.

After changing only revocation append publication to the staged helper, the same command was GREEN: exit `0`; `Ran 1 test in 15.190s`; `OK`; wall `15.851s`.

### Slice 2 — renewal/recovery

RED command:

```bash
env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. /tmp/dm136-review-venv/bin/python -B -m unittest -v \
  tests.test_operator_messaging.ProvisioningTests.test_replacement_journal_publication_is_atomic_and_recovery_converges
```

RED result: exit `1`; `Ran 1 test in 19.048s`; the old replacement append retained the partial authoritative final and never reached staged/no-replace boundaries; wall `19.561s`.

After changing only replacement append publication, the same command was GREEN: exit `0`; `Ran 1 test in 20.333s`; `OK`; wall `20.831s`.

### Slice 3 — genesis/exact retry

RED command:

```bash
env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. /tmp/dm136-review-venv/bin/python -B -m unittest -v \
  tests.test_operator_messaging.ProvisioningTests.test_genesis_journal_publication_is_atomic_and_exact_retry_converges
```

RED result: exit `1`; `Ran 1 test in 7.094s`; a one-byte authoritative genesis final remained and deterministic exact retry failed on it; wall `7.594s`.

After changing only genesis append publication, the same command was GREEN: exit `0`; `Ran 1 test in 13.700s`; `OK`; wall `14.232s`.

## Permanent F1 coverage

The new tests are:

- `test_genesis_journal_publication_is_atomic_and_exact_retry_converges`
- `test_replacement_journal_publication_is_atomic_and_recovery_converges`
- `test_revocation_journal_publication_is_atomic_and_retry_converges`
- `test_journal_conflicts_and_unsafe_or_unbounded_residue_are_never_deleted`

For genesis, replacement, and revocation, the tests exercise all five boundaries through real `prepare`, `renew`, `revoke_capability`, and `recover` paths:

- after a one-byte staging prefix write;
- after staging-file fsync;
- after no-replace final installation;
- before state-directory fsync;
- after state-directory fsync.

They restart where applicable and prove:

- pre-install failure leaves no partial authoritative final and recognized private residue is cleaned on exact retry;
- post-install failure leaves one canonical immutable final and exact retry/recovery converges;
- replacement recovery selects the already-published application and completes its journal/pointer state;
- revocation remains monotonic and blocks subsequent load after restart;
- an installed conflicting final is not replaced;
- malformed, insecure-metadata, and over-limit residue is rejected without deletion.

Fresh final focused-new result after the bounded-enumeration refactor:

```text
Ran 4 tests in 58.730s
OK
EXIT=0
wall 59.257s
```

## Regression and restart/state evidence

Fresh final prior-focused cohort plus four F1 tests:

```bash
env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. /tmp/dm136-review-venv/bin/python -B -m unittest -v \
  tests.test_operator_messaging \
  tests.test_runtime_relationship_authority \
  tests.test_issue136_permissions \
  tests.test_issue136_migration
```

Result: exit `0`; `Ran 100 tests in 273.309s`; `OK`; wall `273.915s`. The pre-F1 cohort was 96 tests; the count increase is exactly the four permanent F1 tests above.

Relevant restart/state and preservation cohorts, all exit `0`:

- Messaging/runtime restart cohort: `tests.test_messaging_runtime tests.test_native_messaging tests.test_dm024_runtime tests.test_dm024_service` — `Ran 74 tests in 229.173s`, `OK`, wall `229.961s`.
- Issue #132 semantic-receipt cohort: `tests.test_cross_being_semantic_receipts` — `Ran 44 tests in 76.512s`, `OK`, wall `77.024s`.
- F3 runtime/state cohort: `tests.test_operator_runtime_upgrade tests.test_operator_genesis tests.test_operator_first_embodiment tests.test_dm079_authority_epochs` — `Ran 58 tests in 171.383s`, `OK`, wall `172.015s`.
- F3 rebirth cohort: `tests.test_dm078_rebirth tests.test_dm078_recovery_rebirth` — `Ran 24 tests in 16.416s`, `OK`, wall `16.938s`.

## Preservation evidence

- `git diff --binary HEAD -- src/daimon_matrix/operator_rebirth.py tests/test_issue136_migration.py docs/runbooks/messaging-permissions-v2-migration.md` emitted zero bytes.
- The approved `upgrade_semantic_receipts` source span is byte-identical between `HEAD` and the worktree: SHA-256 `3eba8bd968555d29fbae22658d2e27fd0f7c58aef0688dc11a7129818576ffd0`, 6,781 bytes on both sides.
- The 100-test focused cohort includes authenticated chain, revocation monotonicity, pointer rollback/repair, relationship authority/lock serialization, finite transport freshness, V2 large-clock behavior, and DM-136 migration/restart coverage.
- The separate 44-test issue #132 cohort and 82 F3 runtime/rebirth tests remained green.

## Static, schema, generator, and hygiene gates

All commands used the declared `/tmp/dm136-review-venv` environment.

- Ruff check on all seven changed Python paths: exit `0`, `All checks passed!`.
- Ruff format check on all seven changed Python paths: exit `0`, `7 files already formatted`.
- Strict mypy: `MYPY_CACHE_DIR=/tmp/dm136-mypy-cache PYTHONPATH=src:. ... -m mypy --strict src/daimon_matrix` — exit `0`, `Success: no issues found in 58 source files`.
- Compile: `PYTHONPYCACHEPREFIX=/tmp/dm136-pycache PYTHONDONTWRITEBYTECODE=1 ... -B -m compileall -q -f src tests tools` — exit `0`.
- JSON duplicate-key parse + draft-2020-12 schema validation: `JSON_OK=608 TRACKED_JSON; META_SCHEMA_OK=95`.
- `tools/generate_dm082_vectors.py --check`: exit `0`.
- `tools/generate_dm041_vectors.py --check`: expected repository baseline exit `1` naming exactly four pre-existing generated drifts (`provenance/hermes-agent-0.19.0.json`, two valid vectors, and the index). A clean `git archive HEAD` reproduces the identical four-path drift, so this repair introduced no new DM-041 drift.
- Secret scanner over all ten changed/evidence paths: exit `0`; each path reported one clean scan.
- `git diff --check`: exit `0`.
- No debug-only production fault hook or temporary worktree artifact was added.

## Final freeze

The exact final tracked+untracked serialization digest, changed-path list, per-path hashes, staged count, and boundary recheck are recorded in the final handoff generated after this evidence file's final bytes. This avoids a self-referential digest claim inside the artifact being hashed.
