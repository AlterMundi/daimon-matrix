# Human-triggered memory synchronization

`daimon-owner-memory-sync` prepares and applies explicit host-local operations.
It never polls messages, stops services, loads custody, or calls a model. Several
embodiments can belong to the same being; pool lineage labels are descriptive
provenance, not signed Matrix authorship. Skills installation is a separate
operation and is not performed by this command.

## Prepare and compare

Use owner-private directories (0700) and regular private artifacts (0600). Keep
plans and provenance outside the repository: they contain memory content. Pin
the installed SDK interpreter and the clean HMK checkout at the SDK's
`HMK_COMMIT`. Do not use an editable installation for activation.

```sh
daimon-owner-memory-sync drift --left LEFT_LIBRARY --right RIGHT_LIBRARY
daimon-owner-memory-sync prepare-native \
  --source SOURCE_LIBRARY --target TARGET_LIBRARY \
  --source-label SOURCE_LINEAGE --target-label TARGET_LINEAGE \
  --state PRIVATE_PROVENANCE --output PRIVATE_PLAN
```

Preparation does not adopt memory. Retain the resulting packet and its reported
SHA256. Native reconciliation preserves receiver rows and imports source edits
as additional variants. Protected signed projection rows are excluded. Native
links are added through HMK; conflicting receiver links remain recorded in
private provenance. Original snapshots and auxiliary histories remain available.

`drift` emits counts and digests without memory text. It compares native table
state and claimed projection origin/head/content metadata, excluding local
chapter IDs from projection comparison. Query and embedding histories can
legitimately differ between hosts. Different digests do not establish different
memory meaning, and equal digests do not verify signed authority or writer
quiescence. Its flags explicitly leave those properties unverified.

## Approval, cutoff and backup

Before applying to a live pool, obtain approval for the exact destination,
source selection, installed release, consumer configuration, cutoff, backups and
rollback. Stop all writers, including harness consumers and the target Matrix
daemon. The runtime lock below excludes the Matrix owner; it cannot exclude
independent HMK writers. HMK's maintenance lock alone is not a writer fence.

Capture consistent pool images, opaque auxiliary files, runtime projection
journals, private provenance and original consumer configuration while writers
are stopped. Verify recovery before changing a live binding. Do not treat a
private test, successful preparation, or an earlier migration approval as
approval for memory adoption.

Signed source intake must use the existing supported owner-client operation,
with its own authorized exact selection. Do not scan conversation history or
import unsigned content as signed experience. A missing accepted head must be
resolved through supported intake before projection.

## Apply native memory

```sh
daimon-owner-memory-sync apply-native \
  --packet PRIVATE_PLAN --sha256 PLAN_SHA256 \
  --binding PRIVATE_RUNTIME_BINDING --binding-sha256 BINDING_SHA256 \
  --state PRIVATE_PROVENANCE --native-root PINNED_HMK_CHECKOUT \
  --python EXACT_SDK_PYTHON --isolated-home PRIVATE_EMPTY_HOME
```

The binding identifies `target_runtime_root`, `same_being_ref`,
`expected_current_manifest_hash`, `target_origin`, `target_pool_proposal`,
`target_instance`, and `exact_sdk_release` (the venv directory). These must match
the current public runtime authority and exact interpreter destination. The
operator obtains the official runtime lock and preserves the source ledger.
The native worker uses an isolated installed Python process, stripped environment
and native API; it does not inherit provider keys or load harness configuration.
Its worker deadline is 15 minutes, allowing the durable per-entry checkpoints
of a full pool reconciliation to finish on slower storage. The deadline remains
bounded; it does not authorize retries or relax the writer cutoff.

Retain the exact packet and provenance after failure. A commit can succeed before
its response is lost. Reapply the same plan to recover by native source URI and
durable receipts; do not discard provenance or prepare a replacement plan merely
because the response failed. Baseline drift or changed protected signed rows
requires inspection, not overwriting. Apply unsigned reconciliation before an
initial signed projection, or prepare it against the already projected baseline.

## Signed projection and namespace recovery

Initial `project-selected` takes `--packet`, `--sha256`, `--profile-root`,
`--content-root`, `--native-root`, `--python`, `--isolated-home`, and
`--initial-pool-sha256`. Its selection packet includes the runtime binding and
exact accepted signed heads with pinned projection profiles and content.
All selections are verified before projection effects. Assertion origin defines
the namespace even when another embodiment later corrects the assertion.

The initial pool digest is an initial-state guard, not arbitrary retry authority.
After partial effects, keep writers stopped. Preserve the failed pool and
journals, then use the approved restore/reapply procedure or inspect and reconcile
the retained journals through the supported SDK before continuing.

For existing namespace corrections and retractions, use `prepare-rebuild` with
the same common arguments and `--saved PRIVATE_SAVED_PLAN`. Save the reported
plan digest. Preparation exclusively publishes a 0600 packet and never replaces
an existing destination. Apply with `apply-rebuild`, the same selection and
`--saved PRIVATE_SAVED_PLAN --saved-sha256 SAVED_SHA256`.

Recovery loads the saved SDK plan, not a newly prepared plan. Selection,
authority, common checkpoints, profiles and content must still pass preflight.
Retry with the retained packet after uncertain commits; matching receipts are
reused. Namespace effects are individually transactional, not a transaction
covering every namespace. Keep consumers stopped throughout partial failure and
recovery.

## Operational acceptance

Before restarting consumers, verify preserved history, expected native and signed
heads, integrity, consumer bindings and their native discovery/recall behavior.
Restore only services that were previously running. Verify the real two-body
sync and drift results after the approved operation. Installed tests and private
recovery proofs alone do not establish deployed operational acceptance.
