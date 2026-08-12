# DM-078 verification ledger

This ledger distinguishes completed contract evidence from the still-pending
operational rebirth gate. It contains no production identity, key, endpoint,
personal memory or writable database bytes.

## Contract checkpoint

```json
{
  "schema": "dm.verification.dm078/v1",
  "checkpoint": "additional-embodiment-and-recovery-contracts",
  "result": "pass",
  "scope": "synthetic-local",
  "private_material_published": false,
  "matrix_org_contacted": false,
  "root_and_body_custody_co_resident": false,
  "completed": [
    "target-embodiment-and-transport-possession",
    "descriptor-only-two-process-ceremony",
    "offline-root-threshold-authorization",
    "exact-one-row-manifest-successor",
    "historical-event-verification",
    "fresh-ledger-ingest-and-new-origin-append",
    "loadable-v7-target-with-empty-writable-stores",
    "public-peer-forward-update",
    "deterministic-positive-and-negative-vectors",
    "complete-old-embodiment-revocation",
    "recovery-threshold-to-fresh-root-rotation",
    "old-root-seeds-dropped-from-replacement-custody",
    "recovery-target-only-loadable-v7-runtime",
    "self-contained-old-authority-history",
    "ordinary-enrollment-and-recovery-compose-in-both-orders",
    "canonical-history-restore-after-recovery",
    "recovery-custody-roles-in-distinct-processes",
    "required-release-conformance-scenario",
    "cluster-journaled-install-and-authenticated-start",
    "remote-disposable-three-process-native-sync"
  ],
  "rejected": [
    "root-threshold-shortfall",
    "expired-request",
    "request-or-transport-signature-tamper",
    "existing-embodiment-replay",
    "unrelated-manifest-delta",
    "activation-origin-substitution",
    "transition-hash-tamper",
    "incomplete-old-embodiment-revocation",
    "recovery-signature-tamper",
    "old-root-reuse-after-recovery"
  ],
  "pending": [
    "disposable-incus-or-distinct-host-journey",
    "journey-a-full-fault-matrix",
    "journey-b-true-volume-relocation",
    "journey-c-disposable-backup-restore-and-fault-matrix",
    "content-addressed-live-preflight",
    "same-plan-human-go",
    "live-canary-and-forward-rollback"
  ]
}
```

## Local recovery checkpoint

The recovery contract was exercised without contacting any host. A synthetic
recovery threshold rotated the old control chain into fresh root custody,
revoked every active predecessor and authorized one separately keyed target.
The four custody phases (`recover`, `prepare-recovery`, `authorize-recovery`,
`activate-recovery`) ran in distinct subprocesses with passwords passed only by
inherited descriptors. Captured stdout and stderr contained none of those
passwords.

The generated V7 runtime loaded with one active fresh embodiment, no peer
targets and an empty writable ledger. Its enriched historical authority
verified the pre-recovery manifest and accepted an old canonical signed event
restored from the source ledger. Schema validation, a recovered-authority
known-source parse, transition tampering tests and deterministic public vector
regeneration also passed. This proves the local protocol boundary; it does not
claim a backup archive, a distinct host, service cutover or rollback rehearsal.

## Installed remote checkpoint

Cluster draft PRs #80 and #82 pin Matrix commit
`1452bf6f7cea841ee1f1757f3b001708f8e72c84`. Their local gate passes 452
tests with 2 intentional skips. The exact H8 candidate was installed into a
fresh Python 3.13 environment under one unique temporary root on the authorized
`daimonmatrix` host. `direct_url.json` proved the Matrix pin before import;
changed-source lint/types and all 16 rebirth scenarios passed.

The installed journey used three real Matrix daemon processes and three
separate encrypted custody roots. The fresh embodiment authenticated as the
same being and signed initial incarnation, exchanged one harmless event in each
direction with an old peer through native encrypted peer pull, replayed one
exact request without a second import, and retained both remote events as
pending. The target password was absent from argv, environment and diagnostics.

This is a same-host process-isolation checkpoint, not the final fresh physical
host or Incus journey. Ports 18686, 19686 and 20686 were free before and after;
all children stopped, the exact temporary root was removed and installed
`clusterd` remained active. No production runtime, authority or custody changed.

Reproduce the checkpoint from a clean checkout with:

```bash
python tools/generate_dm078_vectors.py --check
python tools/generate_dm078_recovery_vectors.py --check
PYTHONPATH=src python -W error::ResourceWarning -m unittest \
  tests.test_dm078_rebirth tests.test_dm078_recovery_rebirth -v
python -m ruff format --check \
  src/daimon_matrix/authority_epochs.py \
  src/daimon_matrix/operator_rebirth.py \
  src/daimon_matrix/runtime.py \
  tools/generate_dm078_vectors.py \
  tools/generate_dm078_recovery_vectors.py \
  tests/test_dm078_rebirth.py tests/test_dm078_recovery_rebirth.py
python -m ruff check \
  src/daimon_matrix/authority_epochs.py \
  src/daimon_matrix/operator_rebirth.py \
  src/daimon_matrix/runtime.py \
  tools/generate_dm078_vectors.py \
  tools/generate_dm078_recovery_vectors.py \
  tests/test_dm078_rebirth.py tests/test_dm078_recovery_rebirth.py
MYPYPATH=src python -m mypy \
  src/daimon_matrix/authority_epochs.py \
  src/daimon_matrix/operator_rebirth.py \
  src/daimon_matrix/runtime.py \
  tools/generate_dm078_vectors.py \
  tools/generate_dm078_recovery_vectors.py \
  tests/test_dm078_rebirth.py tests/test_dm078_recovery_rebirth.py
```

The disposable and live reports will be appended as separate checkpoints with
exact public commits, artifact digests, redacted host roles, accepted heads,
backup cutoff, fault outcomes and final rollback state. Contract success must
not be represented as completion of GitHub issue DM-078.
