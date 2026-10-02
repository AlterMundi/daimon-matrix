# Communication legs v3: explicit migration and recovery

Tracker: #202 (DM-092). This operator command upgrades the communication store,
not a being, credential, capability, harness or messaging application. It does
not send a message. The installed runtime subsequently selects the persisted
schema without an additional configuration flag.

Candidate status: complete live-store acceptance is blocked by #204. The current
library invalidates historical attempts, local receipts, cached pages/claims and
conflict references while rewriting projected leg IDs. Snapshot semantic
validation detects attempt and receipt failures before live DDL. Cached pages,
claims and conflicts are explicitly refused with
`migration_history_requires_library_fix`, because ordinary validation does not
cover them. These refusals preserve the source store. Do not deploy this draft
as a remedy for historical stores until #204 and its exact-retry tests are
resolved. Prior leg IDs also lose addressability in the delivered library.

## Preview and approval

Run the read-only preview against the existing body:

```bash
daimon-communication-migration plan --state-root /owner-only/runtime
```

The report names the existing schema, required steps, logical state digest and
`plan_sha256`. Version 1 requires receipts v2 followed by legs v3; version 2
requires legs v3; version 3 reports `already-current`. Unknown versions refuse.
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

The existing library performs both upgrades. Legs v3 widens recipient identity
to include the receiving embodiment and recomputes legacy projected leg IDs,
updating child references. Signed message, resolution and receipt history and
leg sequence numbers are preserved. Reopening and re-accepting an in-flight
message uses the new projected ID without accepting a second message.

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
receipts-v2 intermediate or the legs-v3 target state. While writers remain
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
events, both schema entry versions, an in-flight exact retry, two receiving bodies
with distinct signed terminal receipts, recovery after the first transaction,
refusal after later accepted history, backup tamper/hard-link controls, and
separate-process preview, custody-backed apply, daemon-lock refusal and recovery.
The ordinary communication, messaging and hosted-runtime regressions remain
required. No live service is migrated by those tests.
