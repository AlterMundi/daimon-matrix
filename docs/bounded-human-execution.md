# Bounded human execution — shared core and Codex adapter (issue #138)

## Delivery boundary

This implements the **shared instruction, SQLite journal, operator control API,
typed runner/controller contract, single-inference Codex App Server adapter and
single-inference Hermes adapter**. The adapters are exercised with exact pinned
fixtures and loopback synthetic providers, not installed/paid execution. See the
separate registrations below. There is no default review job, background
scheduler, message-arrival callback, default model client, new embodiment,
service installer, or credential-copy path.
`tests/test_passive_messaging_execution.py` composes the actual native
receive/store and explicit mirror paths with both runner/controller types and
instrumented model, tool and automatic-reply boundaries. The exact fixture suites
repeat that passive arrival assertion with fully constructed Codex and Hermes
runners. Execution remains a separate explicit scheduled-controller call.

The separately included Codex generated-schema parser fix accepts finite numbers
in vendor JSON Schema without changing Matrix signed-artifact canonicalization,
the Codex version, schema pin, profile policy, or tool inventory. The separate
`codex_review.py` runner does not reinterpret that old profile as its registration.

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
`human_execution_frontend.py` and `HumanExecutionOperator` provide the host-only
challenge/proof and Codex/Hermes controller integration, but the embedding owner
still provisions the direct-human authenticator, external signer, filesystem
isolation and runner supervisor. Without that external isolation a target is
**not qualified for periodic execution**; do not expose activation to a model or
message-arrival path. An active journal row records verified approval, not
installed runner readiness.

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
the runner registration's expected human principal, current binding, window,
slot and single-flight state, then gates the single
`ReviewRunner.start(ReviewRequest, context, timeout)` inference submission.
Principal mismatch is rejected before `reserve`: it creates no cycle, operation
or runner-runtime intent and cannot consume a cycle budget or single-flight slot.
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

The controller also owns a thread-safe registry keyed by exact instruction ID,
revision and cycle ID. It registers each context after reserve but before the
startup dispatch crosses `runner.start`, and successful terminal settlement
removes it. This registry applies equally to review-now and to explicit
`run_due_once` calls made by an external finite-periodic scheduler; it does not
install a scheduler or arrival hook. After a cancellation challenge is consumed,
`HumanExecutionOperator.confirm_cancel` first writes the durable tombstone, then
asks the controller to enforce every exact active context within the single
approved cleanup budget. Its closed result contains only `instruction_id`,
`revision`, `state`, `interruption` and `cycles`. `interruption="stopped"` means
every exact admitted cycle is durably reconciled; any timeout, missing stop
evidence, persistence fault or transmitted-but-unreconciled provider/effect is
`unknown`. The controller snapshots only contexts it actually owns, releases its
context lock, boundedly enforces that snapshot, and then compares the result with
the journal's exact instruction/revision `intent`/`ambiguous` evidence. The final
audit selects only those two unresolved states in SQL; it does not fetch or
materialize exact terminal history. One absolute monotonic deadline is captured
before the snapshot and shared across all owned contexts, cancellation-only
journal checks/writes and the final exact audit. Those cancellation store
operations use a zero busy timeout rather than inheriting the ordinary journal's
ten-second SQLite wait. Remaining time is read again immediately before every
interrupt and immediately after every cancellation-only store operation whose
result could otherwise produce `stopped`, including the final audit. An expired,
non-finite, backward or unreadable monotonic budget starts no further cleanup
step and forces `unknown`, even when an audit found no unresolved row.
Thus a restart or lost ownership cannot turn an unresolved durable cycle into a
stopped acknowledgement. Such an unowned cycle is listed and forces `unknown`,
but the controller neither invents its secret capability nor
interrupts/finishes it.
Unrelated instructions and revisions do not affect the result; no admitted exact
cycles, or only durably completed/stopped exact cycles, may return `stopped`.
Store calls and bounded interruption occur outside the context-registry lock so a
terminal callback cannot deadlock behind a reservation or cancellation audit.
The cancellation tombstone is retained in either case.

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


## Explicit Codex review registration (separate from DM-040 V1)

`codex_review.CodexReviewRunner(payload, proof, verifier, existing_body=...,
 binary=..., catalog=..., authorization=...)` is an operator-only Python API.
It launches **nothing** during construction and installs no scheduler. Only an
admitted `ReviewController.run_due_once` starts work. The owned registration
profile must already be an isolated, empty mode-0700 directory; this API does
not enroll a body, take over a TUI, mint credentials, or copy an existing home.

The closed public shape is `$defs/codex_registration` in the execution schema:
`schema=execution/v1/codex-registration`, human principal, execution store UUID,
existing being/embodiment/runner/session, exact provider/model/upstream Responses
endpoint, owned profile, SHA-256 of the reviewed single-model text-only catalog,
finite expiry, `mode=ephemeral-review`, and response byte ceiling. The ordinary
human-frontend `execution/v1/approve` proof signs this **distinct entire object**.
It is not an instruction and cannot pass instruction approval. Registration
alone never admits a cycle. Its digest is pinned in the separate runtime journal;
no implicit registration migration, renewal, stale-state recovery or replay into
a different execution store is provided.

`existing_body` must independently validate the current Matrix/Cluster binding,
exclusive ownership of this execution session, the actual existing provider and
model selection, and approval for fresh ephemeral review threads **within that
same body**. Returning a model-supplied boolean is not an implementation. It is
rechecked during supervision. All host callbacks must be bounded; the callback
and public trust root must be unreachable by the model. The tests use synthetic
verifiers/keys and do not establish an installed human frontend or body binding.

### Implemented request/action slice

1. `start` validates signed registration, exact instruction binding, task hash,
   model/provider/window, pinned native binary, catalog digest and owned-profile
   inventory. It durably records cycle intent and returns without calling the
   context reentrantly under the controller's dispatch lock.
2. A supervised worker rechecks current authority and reads each explicitly
   approved inbox scope through `CycleContext.native`. Results are untrusted
   context; there is no workspace, predecessor history or context-volume sharing.
3. The pinned App Server runs with a private ephemeral HOME/CODEX_HOME, cleared
   environment, never/read-only, startup-only text/no-patch/no-shell catalog,
   disabled shell/apps/browser/computer/plugins/hooks/memories/multi-agent/goals,
   no MCP configuration, and no provider credentials. The named provider/model
   selection is retained; its transport is explicitly redirected to a host gate.
4. Supported `initialize`, `thread/start`, `turn/start`, completion and
   `turn/interrupt` messages are used. Cycle, process, thread and turn IDs are
   durably correlated. The registration explicitly permits ephemeral review
   threads; this is not attachment to a previously interactive Codex thread.
5. The host gate admits only one Responses request. Immediately before enqueuing
   upstream bytes, `CycleContext.inference` performs a **second durable provider
   admission** serialized against cancellation. Controller startup remains the
   `inference` intent; actual upstream dispatch is the separately bounded
   `provider` operation. Neither kind permits retries/continuations. This closes
   the asynchronous startup-to-provider race without holding SQLite over a turn.
6. The complete request has a conservative canonical-UTF8-byte input ceiling,
   `tools=[]`, `tool_choice=none`, and an actual provider `max_output_tokens` cap.
   Returned usage is validated; output text also has a conservative byte ceiling.
   These bounds require qualification of a byte-BPE Responses model and provider
   enforcement of `max_output_tokens`; they are not a universal tokenizer claim.
   Bodies are bounded before parsing, including chunked HTTP responses. Redirects,
   WebSockets, compression, ambiguous framing, trailers and model-selected routes
   are not supported. No retry follows rejection or uncertain dispatch.
7. Provider events are fully buffered, checked and reconstructed before reaching
   Codex. Hidden/unadvertised function/custom tools, images and other effect
   output never reach its router. Inert reasoning is stripped (its tokens still
   count). Every App Server request for tools/approval/elicitation is denied.
8. The final text must be exactly a JSON no-op (`{"action":"none"}`) or one
   scope-indexed proposal: `{"scope":0}` for an inbox or
   `{"scope":1,"text":"..."}` for send/reply. No destination/action/tool override
   fields are accepted. The exact approved Scope goes through `context.native`;
   the host NativeBroker supplies daemon authorization, fixed reply target,
   native send UUID/idempotency and technical receipt. There is no second model
   request after that result. All inbox reads and the optional action consume
   the same approved native-operation budget.

### No-copy provider authentication and supervision

The supported local `base_url`/`requires_openai_auth=false` configuration applies
**only to the local gate**. `authorization()` is an existing host provider broker
callback supplying its current Authorization header for the approved upstream
endpoint. That header never enters Codex, its environment, profile, model input
or public registration. The adapter neither logs in nor reads/copies `auth.json`,
issues tokens, refreshes OAuth, or changes the ordinary body's config. Native
messaging credentials similarly remain solely in the NativeBroker. This is a
no-copy integration seam, not a claim that the target's existing ChatGPT/OAuth
account and its refresh/extra-header requirements are already integrated.

Async supervision closes provider streams, sends exact turn interruption and
kills/reaps only the owned process group. Linux `/usr/bin/timeout --signal=KILL`
provides an independent finite process deadline even if Python is blocked on a
journal lock or the parent dies; this is an explicit trusted host dependency,
not model-selected shell execution. Native/provider-auth/body-verifier callbacks
remain trusted bounded host primitives; a Python API does not sandbox a malicious
or unbounded broker. Socket closure does **not** prove a remote provider stopped:
if its completed response was not reconciled, interrupt returns `unknown` and
both journals retain ambiguity. No restart reissues such a cycle or kills a PID
from historical evidence. Known successful completion is recorded only after
runtime reaping and native receipt reconciliation.

### Qualification boundary and executable offline tests

This is a concrete, tested adapter slice, **not full #138 acceptance**. Pending:
installed authenticated human frontend and existing-body/lifecycle binding;
qualified real provider/auth/model/tokenizer integration (including OAuth if
applicable); OS/user isolation of brokers, registration and loopback gate from
other local principals; installed wheel and generated inventories owned by the
parent; live separately authorized invocation; Hermes and passive native intake/
MCP/mirror composition. Do not enable production periodic execution before those
requirements are satisfied. Same-UID arbitrary code is outside this boundary.

```sh
PYTHONPATH=src \
CODEX_REVIEW_BINARY=/path/to/exact/0.146.0/native/codex \
CODEX_REVIEW_CATALOG=/path/to/reviewed/text-only-catalog.json \
python -m unittest tests.test_codex_review -v
```

These tests use the real SHA-pinned native binary with a localhost fake provider
and a mocked native broker. `gpt-5.4` is only their public vendor-catalog fixture,
not a change to the real configured provider/model/auth. They cover actual thread/
turn completion, scoped inbox context and reply, hidden tools, token ceilings,
wrong bindings, inactive/cancelled/expired instructions, config drift, finite
process deadline with a blocked journal, cancellation, and restart ambiguity.

## Independent core findings corrected after ffdce00

F1: transaction savepoints separate authority mutations from clock observations.
On failed admission, only high-water/fault metadata survives rollback. Context
wall-clock observations use `observe_clock`, which joins an already-held bounded
dispatch transaction without reentrant SQLite; observed deadline/fault fences are
irreversible in the context. Failing an approval never commits its event/authority.

F2: `ReviewController.enforce` fences a retained context and attempts its exact
bounded interrupt even if status/check/ambiguity writes fail. Persistence errors
are propagated after the stop attempt; no journal is recreated and no terminal
receipt is fabricated. The original independent probes and new unavailable,
corrupt, missing-row, rollback-atomicity and direct-context-clock cases are now
standard unittest regressions. These are implementer fixes, pending independent
re-review of the new delta.
