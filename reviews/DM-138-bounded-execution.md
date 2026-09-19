# DM-138 — bounded execution core implementation review record

Status: **historical core and rejected repair evidence below; the DM-138
large-history final-audit deadline repair is implemented and author-qualified in
the uncommitted candidate, pending independent exact-byte re-review**.
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

## Follow-up: repair of independent HIGH findings (uncommitted)

The independent frozen-candidate review at
`work/messaging-rollout/reviews/DM-138-REPAIR-INDEPENDENT.md` requested changes
for two in-scope HIGH findings. This section records implemented behavior and
local evidence only; it does not convert that verdict to approval.

1. `ReviewRunner.expected_principal` is now part of the trusted controller
   contract. Codex and Hermes expose the principal from their signed
   registrations, and `ReviewController.run_due_once` compares it before
   `reserve`. Real-controller negative fixtures prove that a separately trusted
   wrong principal creates zero cycle rows, operation rows, runner-runtime rows,
   worker/provider/native calls or single-flight poison. Same-principal controls
   still enter each fully constructed runner.
2. `ReviewController` now owns exact active contexts under a thread-safe
   instruction/revision/cycle key. Registration precedes startup dispatch, and
   successful completion removes the context. Signed operator cancellation
   consumes the challenge, writes the durable tombstone, then boundedly enforces
   every exact active context within one cleanup budget. The closed response
   reports `stopped` only if every admitted context is durably reconciled;
   otherwise it reports `unknown` while retaining the tombstone.
3. Executable regressions cover cancellation during blocked startup, Codex
   review-now cancellation after provider submission (`unknown` with local
   process reaped and no later submission), and a Hermes finite-periodic cycle
   started by an external scheduler (`stopped` before provider/native submission).
   Replay remains denied. This installs no scheduler or arrival hook.

The existing OS-isolation limits remain: Python callbacks and same-UID process
boundaries are not isolation, real authenticators/signers/provider credentials
and native brokers remain deployment obligations, and transmitted remote work
cannot be recalled. DM-041/package generated inventories are outside this claim,
were not modified or regenerated, and remain a publication blocker until their
own claimed lane updates and independently qualifies them.

## Follow-up: cancellation restart/lost-context correction (uncommitted)

Parent audit found a further cancellation acknowledgement gap in the frozen
candidate: after controller/process restart, a signed cancellation still wrote
its tombstone but an empty in-memory context map caused `cancel_active` to return
`stopped` even while the exact journal retained `intent` or `ambiguous`. A new
real-store/operator regression was first run against those bytes and failed with
`'stopped' != 'unknown'`.

`cancel_active` now snapshots only owned exact contexts, releases the context
lock, spends the same single bounded cleanup budget enforcing those contexts,
and finally correlates the result with durable exact instruction/revision
in-flight evidence. Any remaining exact `intent`/`ambiguous` cycle or failed
journal read forces `unknown`; its public cycle ID is reported without inventing
the lost capability, invoking an unrelated runtime, or marking it stopped.
Durably terminal exact cycles and the no-cycle case still permit `stopped`, and
other instruction IDs/revisions are ignored. Reservation no longer holds the
context-registry lock across the SQLite call; a deterministic barrier regression
proves a terminal callback can complete while another reservation is paused.

Final-byte local evidence for this micro-repair:

- Focused instruction/store/controller/frontend suite: **48 tests, OK**, zero
  skips. This includes restart `intent`, restart `ambiguous`, mixed terminal and
  unowned exact cycles, unrelated instruction/revision controls, no-cycle/all-
  terminal positive controls, normal owned bounded cancellation and lock order.
- Exact pinned Codex plus DM-040 contract suite: **25 tests, OK**, zero skips.
- Exact pinned Hermes fixture suite: **50 tests, OK**, zero skips. The first run
  encountered host `/tmp` exhaustion (`ENOSPC`) and a consequent fixture startup
  miss; after removing one stale 407 MiB prior-review fixture, the one justified
  full rerun passed cleanly. This is recorded as environment evidence, not hidden.

This remains author evidence only. It does not replace independent re-review,
resolve the separately owned DM-041/package publication drift, deploy a human
frontend, or authorize any live model/message/service operation.

## Follow-up: end-to-end cleanup deadline correction (uncommitted)

The next independent exact-byte review found one remaining in-scope defect:
SQLite cycle checks, ambiguity writes and the final exact audit were outside the
nominal cleanup accounting. A permanent production-path regression was added
first with a real `BEGIN IMMEDIATE` writer held for 1.2 seconds. Against the
rejected bytes, its 1.0-second budget took **1.236474 seconds** and interruption
still received **0.999989 seconds** despite **0.000000 seconds** remaining. The
test failed on both the 0.120-second wall-clock tolerance and stale timeout, as
intended.

The controller now creates one absolute monotonic deadline before snapshotting
contexts and shares it across every exact context and the final audit. Remaining
time is recomputed before every cancellation store call and immediately before
every interrupt. Cancellation-only store methods use zero SQLite busy timeout;
ordinary store methods retain their ten-second wait and transaction semantics.
Exhausted, non-finite or backward cleanup time skips subsequent work and returns
`unknown`. SQLite busy state after a bounded stop likewise remains conservative
rather than being promoted to durable reconciliation. `stopped` still requires
the final exact instruction/revision audit to find no `intent` or `ambiguous`
cycle.

On the final bytes the same `BEGIN IMMEDIATE` regression completed
`cancel_active` in **0.001763 seconds**; the interrupt received
**0.999053 seconds** when **0.999040 seconds** remained, returned `unknown`,
retained the cancellation tombstone and left unresolved cycle evidence
nonterminal. An unlocked positive control returned `stopped` only after exact
durable settlement. Additional permanent controls cover an exclusive-lock final
audit and exhausted or unreadable monotonic budgets.

Final local qualification for this correction:

- focused instruction/store/controller/frontend suite: **52 tests, OK**, zero
  skips, 12.058 seconds;
- exact pinned Codex plus DM-040 contract suite: **25 tests, OK**, zero skips,
  57.200 seconds;
- exact pinned Hermes fixture suite: **50 tests, OK**, zero skips, 315.099
  seconds;
- Ruff check/format over all 12 candidate Python artifacts, strict mypy over all
  seven candidate source modules, compileall, both execution schemas and diff
  whitespace: clean.

During qualification, three broader controls exposed and drove narrow
corrections: cancellation checkpointing had to retain the context's independent
monotonic deadline; an already-held runner transaction had to become bounded
`unknown` rather than an escaped SQLite busy error; and an all-terminal,
non-interrupting controller audit had to remain a valid positive control even
when called outside the signed operator tombstone path. No DM-041 inventory,
generated provenance, package output or deployment artifact was changed. This
record remains author evidence pending another independent exact-byte review.

## Follow-up: large-history final-audit deadline repair (uncommitted)

The repair4 candidate remained unsafe: `ExecutionStore.cancellation_status`
selected and materialized every exact historical cycle before filtering terminal
states in Python, while `ReviewController.cancel_active` did not re-read its
shared absolute deadline after the final audit. The same missing checkpoint also
existed after terminal `cancellation_cycle_status` and successful
`cancellation_finish` calls. Therefore an all-terminal audit could exceed its
budget and still report `stopped`.

### Preserved RED

The permanent regression uses the real `ReviewController.cancel_active`, real
`ExecutionStore`, a signed/cancelled instruction and 750,000 schema-valid exact
terminal cycle rows. Before production changes, this exact command was run:

```sh
PYTHONPATH=src /home/debian/dm-milestone2-test-venv/bin/python -m unittest tests.test_execution_store.IndependentReviewRegressions.test_cancel_large_terminal_history_finishes_final_audit_within_budget -v
```

Exact RED output:

```text
test_cancel_large_terminal_history_finishes_final_audit_within_budget (tests.test_execution_store.IndependentReviewRegressions.test_cancel_large_terminal_history_finishes_final_audit_within_budget) ... FAIL

======================================================================
FAIL: test_cancel_large_terminal_history_finishes_final_audit_within_budget (tests.test_execution_store.IndependentReviewRegressions.test_cancel_large_terminal_history_finishes_final_audit_within_budget)
----------------------------------------------------------------------
Traceback (most recent call last):
  File "/home/debian/dm-milestone2-issue138/tests/test_execution_store.py", line 716, in test_cancel_large_terminal_history_finishes_final_audit_within_budget
    self.assertLess(
    ~~~~~~~~~~~~~~~^
        elapsed,
        ^^^^^^^^
        budget,
        ^^^^^^^
        "final cancellation audit returned stopped after its shared deadline",
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    )
    ^
AssertionError: 1.8812800627201796 not less than 1.0 : final cancellation audit returned stopped after its shared deadline

----------------------------------------------------------------------
Ran 1 test in 3.589s

FAILED (failures=1)
LARGE_TERMINAL_HISTORY_AUDIT rows=750000 budget=1.000000 elapsed=1.881280 result=stopped
```

A second pre-change RED ran three deterministic real-store checkpoint tests. It
failed all six assertions: expired, non-finite, backward and exception-raising
post-audit reads each returned `('stopped', ())`, and post-terminal-status plus
post-finish expiry each returned `stopped` instead of `unknown`.

### Minimal correction and final evidence

`cancellation_status` now applies exact `id`, exact `revision` and
`state IN ('intent','ambiguous')` in SQL, so terminal rows are never returned to
Python. The controller re-reads the one `_CleanupBudget` after the final audit,
after terminal-cycle status reads and after durable cancellation finish. Expired,
non-finite, backward or exception-raising reads return `unknown`; discovered
unresolved exact cycle IDs are retained. Ordinary store APIs and their ten-second
busy behavior are unchanged, while cancellation-only calls retain zero-busy
behavior.

The four focused regressions passed in **2.196 seconds**; the final core run's
750,000-row audit returned `stopped` within budget in **0.272713 seconds**.
Final-byte qualification after test-only lint cleanup recorded:

- core instruction/store/controller/frontend: **56 tests, 0 skips, OK**, 15.187
  test seconds / 15.553 wall seconds;
- exact pinned Codex plus DM-040 contract focus: **25 tests, 0 skips, OK**,
  62.810 test seconds / 63.435 wall seconds;
- exact pinned Hermes fixture: **50 tests, 0 skips, OK**, 347.255 test seconds /
  348.024 wall seconds;
- expanded Codex plus complete DM-040 module: **46 tests, 2 explicit private/live
  smoke skips, OK**, 60.375 test seconds / 61.148 wall seconds.

The core run includes unlocked owned cancellation, no-cycle/all-terminal restart,
unresolved intent/ambiguous exact IDs, tombstone-before-interrupt, unowned-cycle
non-interference, exact instruction/revision scoping, one shared cleanup budget,
no journal access while holding the context registry lock, and the repair4 SQLite
lock regression. Codex and Hermes fixtures retain principal mismatch rejection
before reservation. Ruff check and format passed for all 12 candidate Python
artifacts; strict mypy passed seven source modules; compileall, both execution
schemas, and the repository secret scan passed; all 16 changed paths remain claim
covered with zero staged or DM-041/package paths; real and temporary-index diff
hygiene passed. No commit, push, post, merge or deployment is authorized or
claimed. DM-041/package-generated drift and all previously stated live
isolation/provider/credential limitations remain outside this repair.

## Successor qualification: DM-041/package drift over approved source

This section is later author evidence for the separately claimed package and
generated-state repair. It supersedes only earlier statements that the
DM-041/package drift is still unresolved; it does not rewrite the historical
source-repair evidence above and is not an independent approval.

### Frozen boundary and authorization

- Immutable base HEAD:
  `ddc33c5fba0001271e5592f7215c065adb619da5` (tree
  `83de143a1f70c8c57e51a34cdad7f1db76622531`). The worktree was clean and
  unstaged before the RED replay.
- Accepted successor claim:
  `c48c9307-1c11-4d3b-81a9-00043ab0b74b`, state `in_progress`, 32 exact
  resources, lease through `2026-09-20T06:05:40.925244Z`. Every package
  candidate path below is claim-covered.
- Interpreter: `/home/debian/dm-milestone2-test-venv/bin/python`, Python
  3.13.5. No generator logic, `src/daimon_matrix/*.py`, dependency metadata,
  service, credential, live message, paid model, or deployment state was changed.

### Preserved four-test RED before edits

The following exact command ran first against the clean base:

```sh
PYTHONPATH=src /home/debian/dm-milestone2-test-venv/bin/python \
  -W error::ResourceWarning -m unittest \
  tests.test_dm041_hermes_body.ContractAndProfileTests.test_profile_is_deterministic_exclusive_and_native_memory_free \
  tests.test_dm041_hermes_body.PublicContractTests.test_vectors_schemas_templates_and_provenance_are_deterministic \
  tests.test_package_scaffold.ArtifactBoundaryTests.test_closed_inventories_cover_actual_package_modules \
  tests.test_package_scaffold.ArtifactBoundaryTests.test_real_artifacts_bind_all_package_bytes_to_source \
  -v
```

Result: **4 tests run, 4 failures, 0 skips**, 12.991 test seconds / 14 wall
seconds, exit 1. The exact failures were:

1. profile module count: `AssertionError: 66 != 58`;
2. deterministic generated output: first mismatch at
   `provenance/hermes-agent-0.19.0.json`;
3. package closed-inventory count: `AssertionError: 66 != 58`;
4. built artifact import:
   `ModuleNotFoundError: No module named 'daimon_matrix.codex_review'`.

The complete captured RED log is `/tmp/DM-138-package-red.txt`, 5,670 bytes,
SHA-256 `f83d1a227a560c586a9d19f37adeacea0e6e83932903940aa7418d735e62141c`.
That temporary path is local evidence, not a durable repository artifact; the
command and determinations are therefore recorded here.

### Minimal repair and canonical generation

The exact package allowlists in `tools/check_distribution.py`,
`tools/reproducible_build.py`, and their frozen expectations in
`tests/test_package_scaffold.py` now include only these eight already-approved
modules:

```text
codex_review.py
execution_instruction.py
execution_store.py
hermes_review.py
hermes_review_worker.py
human_execution_frontend.py
operator_execution.py
review_runner.py
```

Both exact module-count expectations changed from 58 to 66 and explicitly
assert the eight names. Before generation,
`tools.generate_dm041_vectors.outputs()` reported exactly four stale paths:

```text
provenance/hermes-agent-0.19.0.json
vectors/hermes/v1/valid/profile-manifest.json
vectors/hermes/v1/valid/launch-receipt.json
vectors/hermes/v1/index.json
```

`PYTHONPATH=src .../python tools/generate_dm041_vectors.py` changed exactly
those four outputs. The generator remained byte-identical at SHA-256
`5741088d594f473401d3292e2da8a1d3b02b7974e74e90db6550b67351846345`;
its subsequent `--check` exited 0.

### RED to GREEN and complete focused suites

The exact four-test command above was rerun unchanged: **4 passed, 0 skipped**,
55.853 test seconds / 56 wall seconds, exit 0. Complete log SHA-256:
`6e4bb8ab403d3a89e941769bee329633be9cd43deb2391ca440f34d736a42cbb`.

Additional final-byte gates:

- `tests.test_dm041_hermes_body`: **27 tests, 26 passed, 1 explicit skip**,
  4.232 test seconds / 4 wall seconds, exit 0. The skip was the pre-existing
  real Hermes 0.19.0 source-import test because
  `DAIMON_DM041_HERMES_SOURCE` was not supplied in that invocation. The exact
  skipped test was then run separately with a securely extracted public source
  tarball at commit `5c8870c1625761956a56fd2b225720dbe9083e45`, the fresh
  wheel venv, `cryptography==50.0.0`, and all exact
  `requirements-hermes-contract.txt` dependencies: **1/1 passed, 0 skips**,
  1.986 test seconds / 3 wall seconds. Supplemental log: 654 bytes, SHA-256
  `c1f8cb40bb06b7cab95842449004d53780680ff331aa188396b22828dc92bde7`.
- `tests.test_package_scaffold`: **12/12 passed, 0 skips**, 55.146 test
  seconds / 56 wall seconds, exit 0.
- `tools/generate_dm041_vectors.py --check`: exit 0.
- Combined focused log: 7,993 bytes, SHA-256
  `c29438993693752c7100d8045ee7575570de7275bb1d7501dccdba2838b95241`.

### Reproducible distributions and installed-wheel proof

The canonical `tools/reproducible_build.py` was invoked twice into separate
output directories; each invocation itself performed two clean isolated builds,
reported `builds: 2`, `byte_identical: true`, and exited 0 in 21 wall seconds.
The two invocations produced byte-identical pairs and identical reports:

| Artifact | Bytes | SHA-256 |
|---|---:|---|
| `daimon_matrix-0.1.0rc1-py3-none-any.whl` | 616,204 | `4fb80f3e3649ec18a188767f2a9293d50274c52066013d8bd0f5653d112739dd` |
| `daimon_matrix-0.1.0rc1.tar.gz` | 565,689 | `d2b4a87076b2e4f1ff14b313f435370d46821686e97a99c0544860063b7ef8d3` |

A fresh `/usr/bin/python3.13` venv installed that wheel normally (not editable),
including declared dependencies. `pip check` reported no broken requirements.
A `python -I` probe from `/tmp` imported the package plus all 65 submodules
(**66 package Python files total**), explicitly found and imported all eight new
modules, and proved every loaded module path was beneath the fresh venv. The
installed distribution had no `direct_url.json`, consistent with a normal wheel
install rather than an editable/VCS install.

### Approved-source behavior replay

No source file was edited. A path-framed digest over all 66 tracked
`src/daimon_matrix/*.py` files was identical for HEAD and the worktree:
`93902e65491c72aad8c0fc82a3f029062db3a25338fa8d83b408c016c7e0baf9`.
`git diff -- src/daimon_matrix` was empty. The approved cohorts were replayed on
these unchanged bytes:

- core (`execution_instruction`, `execution_store`, `human_execution_frontend`,
  `passive_messaging_execution`): **56/56 passed, 0 skips**, 15.082 test
  seconds / 15 wall seconds; internal 750,000-row audit 0.315437 seconds;
- expanded exact Codex plus complete DM-040: **46 tests, 44 passed, 2 explicit
  private/live skips**, 58.525 test seconds / 59 wall seconds. The supplied
  binary and catalog hashes remained respectively
  `2e863156ed35ecc5253b1e2f907a9143077b9f7cb51942070c61996471ff6e04`
  and `c0923563de2cceb85a56b1dd59094fc2e841d777be2b321e51579af7fcd904a5`;
- exact Hermes archive cohort: **50/50 passed, 0 skips**, 323.901 test seconds /
  325 wall seconds. Archive SHA-256 remained
  `09789981423142fec1a26239d5209f96c41453078ff73e2fc4a11e1d45728660`.

The complete core, Codex, and Hermes log SHA-256 values are respectively
`1431fa5170e2a101c94bc1bd3193029c1b8d8ec644243ffbd9eed4e771eb9afa`,
`7fc1875b875d54da9f0c03cfa86f495550ec6063ca83b6ef0cc209be848972a9`,
and `7c0c44e6ffedd13cd28d0f1f503ec1c47bfd9241cb21b26fe8111ae92df8544c`.

### Static, schema, secret, scope, and diff gates

All final package bytes passed:

- Ruff check and Ruff format check on the four changed Python files;
- strict mypy on those four workflow-covered Python files: no issues;
- compileall over `src`, the package tools, generator and focused tests, with
  cache redirected to `/tmp`;
- Draft 2020-12 meta-schema validation for the Hermes schema, strict
  duplicate-key JSON parsing and exact canonical-byte checks for all four
  generated outputs, plus the canonical generator `--check`;
- repository secret scanning over all eight package/generated candidate files
  and both built distributions;
- `git diff --check`, zero staged paths, zero untracked paths, and zero
  `src/daimon_matrix` diff paths;
- accepted-claim readback: all **8/8** pre-report package candidate paths were
  among the claim's 30 path resources.

Before appending this self-report, the exact status contained those eight paths.
Using the same serialization convention as the independent source review:

```sh
{ git diff --binary; while IFS= read -r -d '' f; do
    git diff --no-index --binary -- /dev/null "$f" || test $? -eq 1
done < <(git ls-files --others --exclude-standard -z); } | sha256sum
```

its tracked-plus-untracked package candidate digest was
`563b237b9ff16e49b5ec81815c4c8daa349f49355ecf92548793ce569ad89a33`.
The tracked-only `git diff --binary --full-index` digest was
`93153a3c34ee628be48bfe63fd60583c37a95a915914da41d749cded57254284`.
This review path is itself claim-covered but necessarily excluded from those
pre-report digests to avoid self-reference. The post-report whole-diff digest
must therefore be frozen and reported externally after this final write.

### Limitations and non-actions

The focused DM-041/package suites and all three DM-138 cohorts passed, but a
full repository-wide test discovery run was not requested or represented as
run. The full DM-041 invocation's one source-import skip was discharged by its
dedicated passing run above. Preparing that run exposed two environment-only
attempts before the final green: the existing exact source location was rejected
because group-writable ancestors violated the source trust gate, and the first
secure-source attempt used the DM-138 fixture venv whose `cryptography==46.0.7`
lacked HPKE. No product bytes were changed for either diagnostic; the exact
public source plus dependency-complete wheel venv passed. The two Codex
private/live skips remain explicit; no skip is counted as a pass. No live
provider, human frontend, credential, real message, service, GitHub mutation,
commit, push, merge or deployment was exercised. The installed-wheel venv,
secure external source copy, and build/log files are disposable qualification
evidence, not repository deliverables. This remains author qualification pending
independent exact-byte review of the final package diff.
