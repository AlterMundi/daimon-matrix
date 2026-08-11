# DM-078 verification ledger

This ledger distinguishes completed contract evidence from the still-pending
operational rebirth gate. It contains no production identity, key, endpoint,
personal memory or writable database bytes.

## Contract checkpoint

```json
{
  "schema": "dm.verification.dm078/v1",
  "checkpoint": "additional-embodiment-contract",
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
    "public-peer-forward-update",
    "deterministic-positive-and-negative-vectors"
  ],
  "rejected": [
    "root-threshold-shortfall",
    "expired-request",
    "request-or-transport-signature-tamper",
    "existing-embodiment-replay",
    "unrelated-manifest-delta",
    "activation-origin-substitution",
    "transition-hash-tamper"
  ],
  "pending": [
    "disposable-installed-three-host-journey",
    "journey-a-full-fault-matrix",
    "journey-b-true-volume-relocation",
    "journey-c-recovery-quorum-rebirth",
    "content-addressed-live-preflight",
    "same-plan-human-go",
    "live-canary-and-forward-rollback"
  ]
}
```

Reproduce the checkpoint from a clean checkout with:

```bash
python tools/generate_dm078_vectors.py --check
PYTHONPATH=src python -W error::ResourceWarning -m unittest \
  tests.test_dm078_rebirth -v
python -m ruff format --check \
  src/daimon_matrix/authority_epochs.py \
  src/daimon_matrix/operator_rebirth.py \
  tools/generate_dm078_vectors.py tests/test_dm078_rebirth.py
python -m ruff check \
  src/daimon_matrix/authority_epochs.py \
  src/daimon_matrix/operator_rebirth.py \
  tools/generate_dm078_vectors.py tests/test_dm078_rebirth.py
MYPYPATH=src python -m mypy \
  src/daimon_matrix/authority_epochs.py \
  src/daimon_matrix/operator_rebirth.py \
  tools/generate_dm078_vectors.py tests/test_dm078_rebirth.py
```

The disposable and live reports will be appended as separate checkpoints with
exact public commits, artifact digests, redacted host roles, accepted heads,
backup cutoff, fault outcomes and final rollback state. Contract success must
not be represented as completion of GitHub issue DM-078.
