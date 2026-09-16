# Bounded human execution — shared core (issue #138)

## Delivery boundary

This implements the **shared instruction, SQLite journal, operator control API,
and typed runner/controller contract**, not installed Codex/Hermes execution.
There is no default review job, background scheduler, message-arrival callback,
model client, new embodiment, service installer, or credential-copy path.
`tests/test_passive_messaging_execution.py` tests a **bounded fake runner** and
core dispatch counters only. Despite its reserved filename, it does not prove
passive real inbox/MCP/mirror composition or real Codex/Hermes dispatch.

The separately included Codex generated-schema parser fix accepts finite numbers
in vendor JSON Schema without changing Matrix signed-artifact canonicalization,
the Codex version, schema pin, profile policy, or tool inventory. It does not
implement a Codex review runner.

## Authority and deployment prerequisites

An instruction is a closed `execution/v1` object. It binds a fresh journal UUID,
immutable ID/revision, approving human principal, existing being/embodiment,
registered runner/session identifiers, provider/model, exact UTF-8 task SHA-256,
finite Unix-second start/end, cycle/cleanup/token/tool budgets, and exact
channel/thread/tool/action tuples. Wildcards, shell, delegation, schedule
administration, arrival mode, unknown fields, missing ends and boolean integer
budgets are rejected. Manual mode permits one cycle with no interval; periodic
mode requires a positive interval. One inference submission is permitted per
cycle; `max_effects` bounds all native submissions, including inbox reads.

`ApprovalVerifier` accepts only Ed25519 signatures under explicitly configured
**human frontend** public keys. The frontend MUST authenticate direct human
confirmation of the complete request independently of the model. A runtime
client key, signed peer message, Telegram projection, Unix UID, CLI flag,
`human=true` field, or model output does not provide this provenance.

The signature covers these exact fields (signature itself excluded):

- `purpose`: `execution/v1/approve` or `execution/v1/cancel`;
- `event_id`: unique frontend event identifier;
- `principal`: configured approving human principal;
- `payload_sha256`: SHA-256 of the entire approved request/cancellation payload.

Encoding is `json.dumps(value, sort_keys=True, separators=(",", ":"),
ensure_ascii=True, allow_nan=False).encode("ascii")`. Sign those bytes with
Ed25519 and encode the signature as 128 lowercase hexadecimal characters.
There is deliberately **no signing helper in the production API or CLI**.
Approval event IDs are consumed transactionally across all actions in the
journal. The UUID audience prevents an old proof from authorizing a new journal.
Proofs are reverified on persisted instruction reads, including reservation.
A frontend must not reissue old event IDs or repurpose a lost journal UUID.

The owner MUST isolate public trust configuration, journal, controller and
transport credentials from model-controlled code. File mode 0600 alone is not
isolation from a same-UID shell. No agent-selected shell/files/alternate MCP
route is allowed. A Python object or Protocol is not an OS security boundary.
This core does not provision an authenticated frontend, isolation, or runner
supervisor. Without those external components a target is **not qualified for
periodic execution**; do not expose activation in its human frontend. An active
journal row records verified approval, not installed runner readiness.

## Operator API and module CLI

Python callers use `ExecutionStore.create(path, verifier)` once, then
`ExecutionStore(path, verifier)` to reopen. Existing-path construction never
creates a missing journal; creation uses exclusive creation and a new UUID.

- `propose(instruction)`: persist a non-executable pending proposal.
- `approve(instruction, proof)`: independently verify and consume proof.
- `cancellation_payload(id, revision)`: exact payload for external confirmation.
- `cancel(id, revision, proof)`: signed cancellation and generation tombstone.
- `status(id, revision=None)`, `statuses()`: public scope/lifecycle evidence.
- Renewal: call `approve` with the next revision, exact latest predecessor
  instruction digest, a new finite window and a fresh human proof. Principal
  and existing embodiment/runner binding cannot silently change. Newly approved
  scope may change; a changed scope with an old proof cannot.

An operator-only CLI is available without changing package console scripts:

```sh
python -m daimon_matrix.operator_execution --store /isolated/review.sqlite \
  --trust /isolated/human-public-keys.json init
# trust JSON maps frontend human principal -> raw Ed25519 public-key hex.
# Prepare instruction.json with the returned store_id; obtain approval externally.
python -m daimon_matrix.operator_execution --store /isolated/review.sqlite \
  --trust /isolated/human-public-keys.json propose instruction.json
python -m daimon_matrix.operator_execution --store /isolated/review.sqlite \
  --trust /isolated/human-public-keys.json approve instruction.json approval.json
python -m daimon_matrix.operator_execution --store /isolated/review.sqlite \
  --trust /isolated/human-public-keys.json status
# cancellation-payload ID REVISION -> external frontend -> cancel-proof.json
# cancel ID REVISION cancel-proof.json
# renew successor-instruction.json fresh-approval.json
```

The caller-selected trust path is an **operator provisioning interface**, not a
human authentication mechanism. A deployed frontend must pin it outside model
control. `init`, proposals and approvals do not launch anything. No keys or
proofs are printed in status. Invalid JSON duplicate members are rejected.
With no active instruction the summary is:
**passive inbox; no agent review scheduled**.

Cancellation stops execution authority only. It does not change communication
grants, delete messages, stop intake, or disable projection. The core never
writes messaging, relationship, transport or mirror stores.

## Durable admission and uncertainty

`reserve(id, revision, binding)` uses SQLite `BEGIN IMMEDIATE`, durable FULL
synchronization, a unique `(id, revision, slot)` constraint, and a partial unique
index for the bound `(runner, session)`. Manual and periodic instructions share
that single-flight fence. Slot numbers derive from current time, not callback
arrival metadata; missed slots are skipped, not replayed. Max-cycle budgets
count attempts, including uncertain attempts. There is no force/retry/lease
reclaim API. Old revisions and cancellation tombstones cannot be revived.

Reservation records an `intent` before any protocol I/O. Each inference/native
operation also commits an intent before submission. Final admission and bounded
transport submission are serialized against cancellation; cancellation takes
effect at its transaction order, not when a caller begins waiting for the lock.
Submit primitives must return within their supplied timeout and MUST NOT reenter
the journal. Never run an entire model/tool loop while holding its lock.

`intent` means outstanding, possibly dispatched work; after a crash it is
**uncertain**, not permission to resend. Submission exceptions explicitly mark
the cycle `ambiguous`. Both states block the session indefinitely, including on
reopen, expiry, renewal and later timer callbacks. `cycle_status` exposes
operation IDs/kinds/scopes and intent/returned evidence, never capability tokens.
A returned technical response is not proof of human reading or task success.

`finish(cycle, "completed"|"stopped")` is a trusted adapter reconciliation API,
not a model tool. It requires the exact host-held cycle capability and external
evidence that the exact runtime turn and all admitted effects are settled.
Timeout alone, an interrupted local thread, or an unknown remote send outcome
cannot justify `finish`. With a lost capability this first core deliberately
leaves the session blocked; an independently reviewed recovery interface is
future work. Never clear a journal or fabricate a new send UUID to unstick it.

Wall time has a durable high-water and a latched rollback/nonfinite-clock fault.
Reopen cannot clear it. There is no unsafe clock reset override; trusted recovery
is separate work. Cancellation remains available with a faulty clock. Runtime
contexts independently fence monotonic rollback and deadlines. Database backups
must not be rolled back into active use without external reconciliation; this
journal is not an anti-rollback hardware counter or a defense against its owner.

## Typed harness integration

`ReviewController(store, runner, broker).run_due_once(id, revision, task)` returns
a host-only `CycleContext` or no work. It checks approval, exact task digest,
current binding, window, slot and single-flight state, then gates the single
`ReviewRunner.start(ReviewRequest, context, timeout)` inference submission.
`ReviewRequest` contains the immutable instruction, task, cycle ID and absolute
action deadline. The deadline is the earlier of finite instruction end and
approved cycle duration; queue time also consumes the monotonic budget.

`CycleContext.native(Scope, payload)` checks cancellation, wall/monotonic
boundaries, exact scope, independent current communication authorization and
the durable native-submission budget. `NativeBroker.submit` must bind the
actual destination/action/tool to that scope, reject payload overrides, and
retain native idempotency evidence. The model must have no alternative route.
All token/provider/model restrictions are part of the typed runner obligation;
this library does not tokenize prompts or claim to constrain a bypassing
provider client. Multi-inference model loops require a reviewed successor to
this deliberately single-inference-per-cycle contract.

The adapter MUST supervise ongoing work independently and call
`ReviewController.enforce(context)` at deadline/cancellation notifications.
It must provide bounded `interrupt(cycle_id, cleanup_seconds)` for that cycle
only, returning `stopped` only with complete reconciliation; otherwise `unknown`.
Cleanup cannot invoke models or new native effects. The library does not create
watchdog threads or pretend that cooperative cancellation kills arbitrary code.
Late provider responses are evidence only. Already transmitted effects cannot
be recalled. Adapters without hard bounded submission/supervision must not be
registered for periodic operation.

## Parent integration / exact follow-up paths

No generated inventory or profile policy was changed in this lane. The parent
owns DM-041 inventory updates and real Hermes wiring/qualification.

Codex compatibility/profile follow-up in this repository:

- `src/daimon_matrix/codex_body.py` (existing exact-policy/rendering boundary);
- `schemas/codex/v1/contracts.schema.json`;
- `provenance/codex-cli-0.146.0.json` (unchanged existing schema pin);
- `profiles/harness/v0/codex-cli.json` (six-tool, proposal-only profile);
- `templates/codex/v1/AGENTS.md`, `templates/codex/v1/lifecycle_hook.py`;
- `tools/generate_dm040_vectors.py`, `vectors/codex/v1/index.json` and
  affected individual `vectors/codex/v1/valid/*.json`;
- `tests/test_dm040_codex_body.py`, future `codex_review.py` and runner tests.

The parent's read-only genuine public bundle is
`/home/debian/dm-milestone2-codex-probe/schema/`. Exact protocol files needed for
registered-session follow-up are `v2/TurnStartParams.json`,
`v2/TurnStartResponse.json`, `v2/TurnStartedNotification.json`,
`v2/TurnCompletedNotification.json`, `v2/TurnInterruptParams.json` and
`v2/TurnInterruptResponse.json`. This lane tested its full normalized bundle
against the unchanged 275-file pin; it did not launch Codex or authenticate.
The parser fix does not prove a messaging-capable restricted profile, supported
existing-session attachment, supervised cancellation or real harness execution.

## Validation

From repository root, using the parent's existing read-only test environment:

```sh
PYTHONPATH=src python -m unittest tests.test_execution_instruction \
  tests.test_execution_store tests.test_passive_messaging_execution -v
CODEX_GENERATED_SCHEMA_ROOT=/path/to/genuine/generated/schema PYTHONPATH=src \
  python -m unittest tests.test_dm040_codex_body -v
```

Tests use synthetic signing keys, real SQLite reopen, process contention and
process crash, clock advance/rollback, cancellation serialization, proof
replay/tamper, renewal tombstones, exact scope/grant gates and fake invocation
counters. The optional genuine-bundle test skips when its environment variable
is absent; it was explicitly enabled in this delivery. Installed acceptance,
real Codex/Hermes model loops and independent security review remain outstanding.
