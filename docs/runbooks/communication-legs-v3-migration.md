# Communication legs v3: explicit migration and recovery

Tracker: #202 (DM-092). This operator command upgrades the communication store,
not a being, credential, capability, harness or messaging application. It does
not send a message. The installed runtime subsequently selects the persisted
schema without an additional configuration flag.

The history-preserving library prerequisite #204 is delivered by PR #206.
Legacy versions 1 and 2 migrate to physical storage schema 4, which retains
canonical per-body rows and validated historical aliases. Attempts, signed
receipt proofs, cached pages and claims, and conflict evidence retain their
original bytes and exact-retry bindings. This operator rehearses and validates
those histories before any live DDL, using the same foreign-authority resolver
as the active store. A corrupt or unverifiable history refuses rather than being
discarded or silently repaired.

## Preview and approval

Run the read-only preview against the existing body:

```bash
daimon-communication-migration plan --state-root /owner-only/runtime
```

The report names the existing schema, required steps, logical state digest and
`plan_sha256`. Version 1 requires receipts v2 followed by the history-preserving
legs upgrade; version 2 requires that legs upgrade. Both target schema 4.
Existing versions 3 and 4 report `already-current` and retain their actual
physical version. Unknown versions refuse. A no-op preview does not certify
semantic health: the normal runtime still validates retained signed history.
Already damaged version-3 histories need separately justified recovery; this
command does not infer missing historical mappings.
Preview opens no custody, creates no file and does not initialize the store.
Its schema/version and digest are read from one SQLite snapshot.

Obtain approval for this exact plan before changing a live store. Stop the
daemon, messaging application and every administrative, backup or other writer
that can reach this root. Retain the existing release and configuration. The
command takes the same nonblocking root lock as the daemon and refuses if it is
held. Cooperating locks do not exclude a hostile process with the same UID:
quiescence and the operator account's filesystem access boundary are required.

```bash
daimon-communication-migration apply \
  --state-root /owner-only/runtime \
  --expected-plan-sha256 APPROVED_PLAN_SHA256 \
  --backup-dir /owner-only/new-migration-snapshot \
  --password-fd 3 3</owner-only/body-password
```

The backup directory must not exist. Files are owner-only. The command makes a
consistent SQLite backup of the complete ledger and copies the communication
anchor; it does not copy runtime private keys. Backups contain private history
and stay local. The upgrade is rehearsed on a separate snapshot before live DDL.
A durable `prepared.json` records the exact source, intermediate and target
logical digests. Live migration runs only after these snapshots and the journal
are fsynced and the approved source state is rechecked.

The existing library performs both upgrades. Per-body legs widen recipient
identity to include the receiving embodiment. Schema 4 binds historical
locators to canonical projected IDs without rewriting immutable documents or
their hashes. Original locators remain valid for lookup and exact recorded
retries; fresh attempts using historical spellings refuse. Signed message,
resolution and receipt history and leg sequence numbers are preserved.
Reopening and re-accepting an in-flight message does not accept a second message.

Success reports `migrated` and writes `completed.json`. Preview again; repeat
apply with the current plan to obtain an explicit `already-current` no-op.
Restart the matching installed release, verify runtime health and exercise an
exact in-flight retry before resuming ordinary operation. Do not declare a real
participant exchange verified from the isolated test journey alone.

## Interruption and recovery

If interrupted before `prepared.json` is durable, live DDL has not started.
Preserve the incomplete snapshot for inspection; repeat preview and use a fresh
backup directory. Do not overwrite a partial artifact.

After preparation, the library's schema transactions leave the source, the
receipts-v2 intermediate or the physical-schema-4 target state. While writers remain
stopped, preview the current state and approve its `state_sha256` for recovery:

```bash
daimon-communication-migration recover \
  --state-root /owner-only/runtime \
  --backup-dir /owner-only/migration-snapshot \
  --expected-state-sha256 APPROVED_CURRENT_STATE_SHA256
```

Recovery verifies snapshot checksums, the unchanged anchor and the complete
current logical database digest against the rehearsed states. It restores through
SQLite's backup API and verifies the original logical digest. It opens no custody.
Recovery refuses new events, receipts, queue changes or any other later logical
work with `migration_recovery_would_discard_work`; restoring an old snapshot is
not authorized rollback of accepted history. A changed anchor or backup also
refuses. Preserve all snapshots and receipts; do not delete evidence to force a
retry. After recovery, preview, reopen the prior schema with the matching release
and re-accept the same in-flight message before returning it to service.

## Qualification

`tests.test_operator_communication_migration` runs actual SQLite files and signed
events, both legacy entry versions, original schema-3 and schema-4 no-ops,
historical attempts and cached page/claim/conflict replay, foreign proof
verification without ledger import, two receiving bodies with distinct signed
terminal receipts, recovery after the first transaction or failed completion publication,
refusal after later accepted history, backup tamper/hard-link controls, and
separate-process preview, custody-backed apply, daemon-lock refusal and recovery.
The ordinary communication, messaging and hosted-runtime regressions remain
required. No live service is migrated by those tests.
