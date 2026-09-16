# DM-138 — bounded execution core implementation review record

Status: **historical core self-review below; corrected core + Codex adapter delta
recorded in the final section; independent delta review pending**.
This record does not close #138 or certify installed Codex/Hermes integration.

## Scope and provenance

- Worktree: `/home/debian/dm-milestone2-issue138`.
- Base: `acb131f18c200bb028ee86fa3a8ef9a2f6c040a3`.
- Supplied accepted claim: `2835e208-9e56-4fd9-9cfe-4eec996615ba`.
- Shared core, execution schema, focused tests and documentation only; plus the
  parent's explicitly requested existing Codex schema-parser correction inside
  `codex_body.py` / `test_dm040_codex_body.py`.
- No generated inventories, profile policies, schema pins, messaging stores,
  services, dependency installations, real model runs, real credentials,
  GitHub writes, commits or pushes. Existing regression tests ran isolated
  synthetic subprocesses/temporary runtime fixtures, not installed services.

## Implemented and checked

| Boundary | Evidence |
|---|---|
| Human authority, not an origin/boolean | Ed25519 complete-payload verification; wrong key, purpose, tampered payload, replay and `human=true` negatives |
| Finite, closed instruction | Runtime validation and public JSON Schema; explicit window, revision/predecessor, exact scope, provider/model/task digest and budgets |
| Passive proposals / absent permission | Empty/pending journal produces zero fake inference/native calls |
| Immutable cancellation/renewal | Signed cancellation tombstones; fresh predecessor-bound signed renewal; old revisions and stale predecessor rejected |
| Durable concurrency | Real SQLite reopen, two OS processes racing for a slot, common manual/periodic session fence |
| Crash uncertainty | Child process exits during dispatch after durable intent; reopened store retains unresolved operation and refuses later slots |
| Dispatch cancellation ordering | Real SQLite transaction lock against concurrent signed cancellation; post-cancel guard denied |
| Deadlines | Absolute end, queue delay crossing end, monotonic deadline and rollback; wall-clock rollback latched across reopen |
| Scope / grant mediation | Exact scope rejection, separately revoked communication authorization, native budget exhaustion, host token forgery rejection |
| Cancellation under clock fault | Signed cancellation remains durable and returns its cancellation receipt without requiring a valid clock |
| External Codex schemas | Genuine 275-file generated bundle matches unchanged pinned digest after parser repair; finite float/Unicode fixture, duplicates/nonfinite/invalid JSON negatives |
| Matrix artifact separation | Existing signed-artifact JSON loader still rejects `0.0`; external parser is not reused by signed-artifact code |

Initial missing-capability tests and the genuine Codex parser regression were
run RED before implementation and GREEN afterward. Additional regression tests
exercise existing implemented invariants. The supplied environment has no
pytest; tests use the repository's unittest style without installing anything.

## Verification commands and outcomes

With `/home/debian/dm-milestone2-test-venv/bin/python`:

```sh
CODEX_GENERATED_SCHEMA_ROOT=/home/debian/dm-milestone2-codex-probe/schema \
PYTHONPATH=src python -m unittest tests.test_execution_instruction \
  tests.test_execution_store tests.test_passive_messaging_execution \
  tests.test_dm040_codex_body -v
```

Outcome: **48 tests run, 2 existing private/live smoke tests skipped**, all other
tests successful. The genuine generated-schema test was enabled and passed.
The skips were the private installed-binary smoke and the opt-in real Codex
Matrix body smoke; neither was bypassed or relabeled as passing.

```sh
PYTHONPATH=src python -m unittest tests.test_native_messaging -q
```

Outcome: **48 existing native-messaging regression tests passed**. This is a
regression check, not new invocation-counter evidence for real harnesses.

Focused Ruff checks passed for all changed Python files; strict mypy passed for
the four new core modules and modified Codex module (five source files).
`git diff --check` and the operator module's real `--help` invocation passed.
Full-suite clean-wheel qualification and DM-041 generated inventory updates
remain with the parent integrator and are not asserted here.

## Security/integration limitations retained explicitly

1. **No human frontend deployed.** The configured public keys must belong to an
   isolated independently authenticating frontend. The CLI consumes proofs; it
   does not authenticate a human by UID, chosen key file or an approval flag.
2. **No real runner implemented.** The bounded fake runner proves the common
   gate only. Existing Codex policy remains six-tool/proposal-only and cannot
   be relabeled a restricted native-messaging execution profile.
3. **Adapter enforcement remains required.** Token budgets, provider/model
   selection, hard timeouts, exact native payload destination, communication
   policy, and exclusive credential/tool routes must be enforced by trusted
   adapters. The controller is not a sandbox or background watchdog. Authorized
   callbacks must be bounded and non-reentrant into the journal.
4. **Intent is uncertain, not retryable.** `intent`/`ambiguous` sessions remain
   single-flight blocked even across renewal. `finish` is an isolated trusted
   adapter API requiring evidence of exact-turn/effect settlement, not a model
   completion flag. No recovery API for lost capabilities or clock faults was
   invented; those cases remain blocked pending reviewed reconciliation.
5. **One inference per cycle.** No arbitrary model loop or additional provider
   request is silently included. The allowed native operations consume the
   approved per-cycle submission budget. Multi-inference support requires an
   explicit contract successor.
6. **Cancellation order is transaction order.** Already admitted bounded
   submissions may finish before the cancellation transaction acquires the
   lock. Already transmitted remote effects cannot be recalled. Technical
   receipts, model review and semantic completion remain distinct.
7. **Persistence assumes owner isolation.** Signature revalidation detects
   request mutation, but SQLite is not tamper-proof against its owner and an
   old whole-store snapshot is not trusted recovery. Never expose the journal,
   trust keys or arbitrary Python/native-client credentials to the model.

## Codex parser repair, separately bounded

The parent supplied a credential-free public schema bundle generated from its
exact npm 0.146.0 probe. The old loader passed vendor JSON Schema through Matrix
canonicalization and failed on finite float schema constraints. The new
`_normalized_external_schema` parser rejects duplicate keys, invalid Unicode,
invalid/nonfinite JSON and oversized documents, while sorting JSON keys with
UTF-8/`ensure_ascii=False` and compact separators. Path/NUL framing and the
existing schema count/hash checks remain unchanged.

The full genuine bundle now returns the unchanged tuple:

```text
275
146a56d701ccd97a76ad1a461d51fc454f32df6c5b4d338ea65968331ccc8b7a
```

No compatibility successor or new pin is needed **for this parser defect**.
A review-runner/profile successor remains separate work. Exact follow-up
repository and public generated-schema paths are listed in
`docs/bounded-human-execution.md`.


## Follow-up: core findings and executable Codex slice (uncommitted delta)

Base for this follow-up is the parent's immutable core commit
`ffdce0090579aaa8b92afbe1e0cf8ab3f3cb4b90`. The independent reviewer found F1
(clock observations rolled back with rejected authority) and F2 (journal failure
preventing interruption). The original no-runner statements above describe that
older slice, not the new adapter. No independent approval is claimed here.

### Core corrections

- Savepoint rollback retains only observed high-water/fault metadata, never failed
  approval events or authority mutations. `observe_clock()` safely joins the
  currently held transaction for checkpoints; other reentrant journal calls are
  rejected. Context expiry/fault is irreversible.
- Enforcement always attempts retained exact-cycle interruption after durable
  validation fails. It reports persistence failures without recreating a journal
  or inventing a terminal receipt. Corrupt SQLite opening also closes its handle.
- Actual asynchronous provider submission has its own one-request `provider`
  intent through `CycleContext.inference`, rechecking current authority under the
  cancellation serialization lock. Startup remains a separate `inference` intent.

### Adapter delivered

`codex_review.py` implements the typed binding/start/interrupt seam against the
real SHA-pinned Codex 0.146.0 App Server. It uses separately signed explicit
`execution/v1/codex-registration`, owner-only runtime correlation journal and
lock, fresh authorized ephemeral threads, startup-only restricted catalog,
cleared private profile, guarded single Responses request, conservative byte
ceilings plus real upstream output-token cap, bounded chunked/Content-Length
response parsing, hidden-tool suppression before the Codex router, scoped inbox
prefetch and one closed native-action proposal. NativeBroker remains the only
native effect route. There is no tool/schedule administration, auth copying,
new-body enrollment, default job, startup-on-arrival, automatic retry or ambiguous
cycle recovery. Linux GNU timeout supplies an independent process deadline;
exact interruption and process-group reaping handle active local cancellation.

No ordinary provider/model/auth config or old DM-040 profile/contracts/provenance
was changed. The no-copy auth seam uses the existing host provider broker's header
only on its registered upstream connection; no credential reaches Codex. The
actual installed account/OAuth integration, human/body verifier and OS isolation
are **not deployed/qualified**. Remote inference is explicitly unresolved when a
completed provider response is absent; closing its socket is not a stop receipt.
See `docs/bounded-human-execution.md` for the complete supported slice and gates.

### Verified follow-up evidence

Using the read-only shared test venv, exact pinned native binary and public
text-only fixture catalog from `/home/debian/dm-milestone2-codex-probe`:

- Combined Codex adapter, instruction, store, passive-core and DM-040 suite:
  **77 tests, OK, 2 existing private/live smokes skipped**. The real-binary adapter
  tests and genuine schema bundle test ran. Final run emitted no resource warnings.
- Original unmodified independent probe script against the new source:
  **11 tests, all assertions passed**, including all four former failures.
- Existing native messaging suite: **48 tests, OK**. The first attempt hit its
  60-second command timeout; rerunning with a 240-second bound completed in
  approximately 176 seconds. This is regression evidence, not new passive real
  harness/mirror integration evidence.
- Focused Ruff and strict mypy for the changed three source modules, plus
  `git diff --check`, pass. No full repository/wheel/inventory claim is made.

Tests demonstrate actual App Server turns with loopback synthetic Responses,
scoped mocked-broker inbox/reply, denied builtin tool outputs (including patch,
image, shell, delegation, web and messaging bypass), budget enforcement, wrong
body/model, no requests with inactive/cancelled/expired authority, startup config
drift, denial of provider retry, chunked responses, reasoning suppression,
interruption, blocked-journal OS deadline, and restart uncertainty. They use no
paid inference, production credentials or real messages. The fake gpt-5.4 catalog
is not a real configured model selection.

Remaining gates: independent delta review; installed authenticated human and
existing-body registration frontend; real provider/auth/tokenizer qualification;
local principal/network isolation; production NativeBroker integration; Hermes
and passive intake/MCP/mirror composition; parent-owned generated inventories,
wheel qualification and separately authorized live acceptance. Full #138 remains
open. This lane makes no commits, pushes, GitHub writes or service deployments.
