# Bounded human execution: Hermes adapter (issue #138)

## Delivery boundary

`hermes_review.HermesReviewRunner` is a host-only Python API for an explicitly
registered **ephemeral review inside an existing embodiment**. It does not enroll
another body, attach to an interactive agent, or modify the DM-041 memory profile.
It adds no cron job, arrival callback, model tool, human-command plugin, service,
credential discovery, or default provider. Construction launches no worker.

This is an implementation slice, **not full issue #138 or production acceptance**.
The tests use actual pinned `AIAgent.run_conversation`, a synthetic local provider,
synthetic human keys, and a test NativeBroker. They do not implement production
human authentication, provider authentication, native daemon integration, or prove
passive native intake/MCP/Telegram-mirror composition. See also
[bounded-human-execution.md](bounded-human-execution.md) for the unchanged core
and Codex contracts.

## Registration and host prerequisites

The public payload in
[`hermes-registration.schema.json`](../schemas/execution/v1/hermes-registration.schema.json)
is separately versioned as `execution/v1/hermes-registration`. A configured,
independently isolated human frontend signs its complete canonical payload with
the existing `execution/v1/approve` proof format. A registration is **not an
instruction** and never itself admits inference or native actions.

It binds the human principal, execution-store UUID, existing being/embodiment,
runner/session, real provider/model/API mode/endpoint, finite expiry, exact Hermes
source archive, interpreter and dependency-environment identities, an owned
runtime directory, explicit `ephemeral-review` permission, a response byte cap,
and the qualified token-accounting policy. No credentials belong in it.

```python
runner = HermesReviewRunner(
    registration_payload, registration_proof, human_public_key_verifier,
    existing_body=qualified_existing_body_verifier,
    source_archive=exact_source_archive,
    python=isolated_dependency_venv_python,
    provider_headers=existing_host_provider_broker,
)
controller = ReviewController(execution_store, runner, native_broker)
# Only an independently approved execution/v1 instruction can admit this call.
context = controller.run_due_once(instruction_id, revision, approved_task)
```

This illustrative wiring names required integrations; it is not an installed CLI
or an invitation to replace them with callbacks returning `True` in production.
`existing_body(payload)` must independently attest current Matrix/Cluster
body/session binding and exclusive execution ownership, current provider/model
selection, ephemeral-worker consent, and qualified accounting. It is rechecked
throughout supervision. Its trust configuration is not model-controlled.

`provider_headers(registration)` must obtain that exact upstream's existing
host-owned credentials and any required extra headers. The worker receives only
a fresh local gate token. Its Authorization header is never forwarded. The
adapter does not read/copy auth files, log in, refresh OAuth, choose a new model,
or silently substitute the synthetic fixture. OAuth, Responses, Anthropic,
Gemini-native, provider aliases with differing wire behavior, and unqualified
models are **not** qualified by these tests. Unsupported modes fail closed.
Current qualification is text-only OpenAI-compatible `chat_completions` with an
exact `/v1/chat/completions` endpoint, HTTPS except explicitly synthetic IPv4
loopback. No redirects, chunked upstream framing, compressed bodies, WebSockets,
partial completions, tool output, reasoning extensions, or multimodal content
are accepted. A real provider with such requirements needs a reviewed successor,
not a fixture-based fallback.

`utf8-bytes-upper-bound-v1` requires host qualification of the exact tokenizer
and provider's hard output-token cap. Canonical request bytes bound input and
UTF-8 final-text bytes additionally bound output; complete integer provider usage
is checked against both budgets and its total. This is not a universal tokenizer
claim or proof of a provider's internal compute. Hidden/reasoning tokens are not
silently omitted from a claimed qualified usage contract.

The dependency venv is read-only in the worker. Its sorted byte inventory and
symlink targets are registration-pinned; the resolved interpreter's bytes are
separately pinned. This is a local content identity, not independently established
dependency provenance. The host must trust and keep immutable its venv/system
library/interpreter/runner and runtime-directory ancestors. Python uses `-I -B`
and `-X pycache_prefix=/tmp/pycache` in fresh tmpfs so excluded ambient bytecode
caches are neither read nor written. Merely setting `-B` would not prevent reads.

## Human controls: implemented API versus unavailable installed UX

The unchanged operator API/CLI supports proposal, authenticated approval,
renewal, cancellation and status. `init`, proposal, approval and status do not
start a model. Human confirmation must cover the complete immutable instruction,
registration, scope, budget and finite time window—not just a command name.

| Human intent | Host behavior |
| --- | --- |
| Review now | Approve a manual instruction with `max_cycles=1`, `interval=null`, finite start/end, exact task digest and scopes; explicitly call `run_due_once`. |
| Review periodically | Freshly approve finite start/end, positive interval, bounded cycle count and budgets. An external qualified host timer may call `run_due_once`; this adapter installs no timer. Missed slots are skipped, not replayed. |
| Renew | New immutable revision, latest predecessor digest, fresh human confirmation/proof and finite window. No incoming message can renew or broaden it. |
| Stop/cancel | Sign the exact `cancellation_payload`. `HumanExecutionOperator.confirm_cancel` durably tombstones first, then asks the controller to enforce every exact active instruction/revision context within one cleanup budget. The result is `stopped` only after durable reconciliation; otherwise it is `unknown`. Cancellation cannot recall already transmitted work. |
| Status | `ExecutionStore.status/statuses` for instruction/schedule state; `runner.status(cycle_id)` for exact runtime correlation. Read-only status grants no authority. `wait` only waits; it is not cancellation. |

With no active instruction: **passive inbox; no agent review scheduled**.
Cancellation does not revoke messaging grants, delete messages, stop passive
intake/storage/projection, or change native relationship governance. Runtime
status/result contains scoped model text and file-name evidence: it is host-only
sensitive execution data, not a public receipt to post verbatim.

There is still no arrival-triggered `/review`, `/periodic` or `/cancel` chat UX.
The host-only `HumanExecutionFrontend` and `HumanExecutionOperator` instead
provide the supported integration seam for both Hermes and Codex: the embedding
owner supplies a direct-human authenticator and external signer, the frontend
displays and durably binds the complete immutable request to a single-use
short-lived challenge, and the operator proposes/approves only through the real
store/controller/runner boundary. The same seam exposes review-now,
finite-periodic activation, authenticated status and signed cancellation.
The controller, not the operator frontend, owns active contexts, so a cycle
started by an external finite-periodic scheduler is discoverable by the same
signed cancellation path. Registration occurs before runner startup dispatch,
closing the concurrent start/cancel discovery gap. No scheduler is installed.
Signing custody and trust configuration remain outside model-accessible runtime
state. Peer messages, forwarded/quoted commands, bots, Telegram
observation-edge/echo projections and model output cannot authorize or confirm a
challenge. There is deliberately no arrival hook from native receipt or mirror
to this host-only API.

## One approved cycle

1. The core compares instruction principal with the signed registration principal
   before reserve, so mismatch creates no cycle, operation, runner intent or
   single-flight fence. It then reserves a durable cycle, registers its active
   context in the controller, and creates the startup operation before `start`.
   The runner checks exact task/instruction/binding and records its
   registration digest, cycle, and explicit `dm-review-<cycle>` Hermes session.
   `start` does not reenter the core journal under its admission lock.
2. A supervised continuation rechecks authority, then uses `CycleContext.native`
   for each approved inbox scope. Inbox results are explicitly untrusted data.
   Every read counts against the same native budget as the optional action.
3. `/usr/bin/timeout --signal=KILL` wraps mandatory `/usr/bin/bwrap --unshare-all
   --die-with-parent --cap-drop ALL`. A new network/PID/mount namespace has fresh
   HOME/HERMES_HOME, tmpfs and cwd, fixed config, pinned source/venv/system libraries
   read-only, and one mounted host-gate Unix socket. Host home, runtime journal,
   credentials, user context, plugins, history and memory are not mounted/copied.
   Sandbox failure is a failure, never a fallback to unsandboxed execution.
4. The fixed child invokes actual pinned `AIAgent.run_conversation`, explicitly
   disables context/persona/memory loading, credential pool, fallback, trajectory
   saving and checkpoints, and checks **resolved** tool lists are empty and
   provider/model/API mode/session unchanged. SDK retry/iteration/compression
   settings are not the security boundary.
5. Pinned startup metadata GET probes and the exact `POST /api/show` with
   `{"name": registered_model}` receive local 404 responses. The gate is not
   Ollama. These probes consult no upstream auth, submit no upstream bytes and
   consume/grant no inference approval. Wrong routes/bodies remain denied.
6. The actual transport gate validates route, credential, model, closed text
   request, strict JSON and token limits. It reserves a one-shot gate before any
   await, and uses **`CycleContext.inference` immediately before upstream write**.
   This second durable admission serializes enqueue against cancellation. SDK,
   application, summary, fallback, concurrent and auxiliary attempts cannot
   submit a second inference. No broad forwarding proxy exists.
7. The upstream response is fully bounded and validated before Hermes sees it.
   Pinned Hermes prefers streaming even without a UI; the gate reconstructs a
   small SSE response from the validated whole completion when requested. It
   never streams unvalidated tool/partial content to the agent.
8. The closed worker result must correlate exact cycle/session/provider/model/
   API mode, empty tools, network isolation, final text and gate evidence. The
   local process is reaped before an optional closed native proposal is applied:
   `{"action":"none"}`, `{"scope":INDEX}` for inbox, or
   `{"scope":INDEX,"text":TEXT}` for send/reply. No destination/tool override is
   accepted. The actual approved Scope is passed to `CycleContext.native`;
   NativeBroker owns current grants, exact destination/reply target, native UUID,
   retry/technical-receipt evidence and daemon authorization. No second model
   pass interprets the native result.

Pinned `load_config` **does seed a fresh default `SOUL.md`**, even when persona
loading is disabled. It is not inherited state. Its SHA-256 must equal
`2765a846e1bb371d78d3b93b403dfb0f8d1ba1a9895edb5f608367abfe81194d`; the result
reports that hash and generated home file names. Tests instrument the real prompt
loader to reject persona loading while the real conversation still completes.
Pinned imports may also create fresh local state/log files. They are discarded
with the sandbox; this is not a claim that Hermes initializes no files.

## Supervision, persistence and ambiguity

The SQLite runtime journal uses FULL synchronization and an exclusive process
flock. Start, close and exact-cycle interruption serialize on a host mutex.
Close timeout retains ownership and can be retried after actual reaping. Failed
construction immediately cleans its extracted source and any opened lock.
The independent OS process timer remains effective if the execution journal
blocks the Python event loop or the parent dies. Under parent death, namespace
children die by the finite deadline; orphan reaping depends on the host init.
A live parent reaps its owned child, not a PID recovered from old history.

`interrupt` returns `unknown` unless local reaping and all admitted provider/native
work are known settled. Socket closure, HTTP errors, timeout and process death
are not remote settlement. Ambiguous or crash-left `intent`/`running` rows remain
single-flight fences across reopen, expiry and new instructions. There is no
restart retry, journal reset, ambiguity timeout or historical-PID kill. Verified
pre-submission cancellation can settle as `stopped`; runtime state is persisted
before the controller frees its own fence. Missing/blocked journals are never
recreated and do not prevent the independent worker kill deadline. First
provisioning creates an exclusive owner-only `hermes.lock` marker and fsyncs
that file and its directory before creating SQLite state. A retained marker
with a missing journal makes reopen fail closed, rather than reprovisioning.
Incomplete initialization requires investigation; never erase the marker to
clear uncertainty. Recovery assumes the trusted marker/directory survives:
there is no claim to recover evidence after deletion of all durable state.

Host body/auth/native callbacks must be bounded trusted primitives. This code is
not a sandbox for a malicious host callback, a hostile root/kernel, mutable
system libraries, malicious local filesystem or rolled-back journals. System
read-only mounts must contain no secrets. No Python timeout can make arbitrary
host filesystem stalls or unbounded callbacks safe.

## Reproducible offline verification

Use the exact local Git object, not the current Hermes checkout:

```sh
fixture=$(mktemp -d /tmp/dm138-hermes-qualification-XXXXXX)
git -C /path/to/hermes-agent archive \
  5c8870c1625761956a56fd2b225720dbe9083e45 > "$fixture/source.tar"
sha256sum "$fixture/source.tar"
# Required: 09789981423142fec1a26239d5209f96c41453078ff73e2fc4a11e1d45728660
mkdir "$fixture/source"
tar -xf "$fixture/source.tar" -C "$fixture/source"
# Provision only the pinned project dependencies in this disposable source tree.
(cd "$fixture/source" && uv sync --locked --no-dev --no-install-project \
  --python /usr/bin/python3.13)
uv pip check --python "$fixture/source/.venv/bin/python"
# Record interpreter hash and environment_digest for this local installation.
# Do not use or modify a live profile/checkout/venv.
HERMES_REVIEW_ARCHIVE="$fixture/source.tar" \
HERMES_REVIEW_PYTHON="$fixture/source/.venv/bin/python" PYTHONPATH=src \
  /path/to/matrix-test-venv/bin/python -m unittest tests.test_hermes_review -v
PYTHONPATH=src /path/to/matrix-test-venv/bin/python -m unittest \
  tests.test_execution_instruction tests.test_execution_store \
  tests.test_passive_messaging_execution tests.test_codex_review.RegistrationTests -v
```

Without both fixture variables, the fixture-backed test class explicitly skips.
With them set, missing dependencies/sandbox support or a wrong pin fail rather
than silently skip. Test classes distinguish strict schema/JSON units, actual
HTTP gate plus real core journals without a worker, and fixture-backed runner
cases. Some runner lifecycle cases deliberately use a controlled thread stand-in
or corrupt a result at the validation seam; they are not additional actual-agent
inference evidence. Actual-provider negative cases use the real worker/AIAgent.
The sandbox negative probe mounts an additional synthetic assertion wrapper,
checks host-only file and direct host-loopback denial, traps SOUL loading and
then runs the unchanged real worker through the Unix gate. Parent death, blocked
journals and restart use real processes/SQLite, not timer mocks. Ordinary
actual-worker fixtures approve a finite 30-second cycle. Dedicated cancellation,
deadline, journal and parent-death probes retain 15-second authority. Serialize
full actual-worker runs on shared hosts. Negative provider cases must reach
exactly one upstream request; zero-submission negatives never count as coverage.

Rejected worker stdout is drained in bounded chunks after termination within
the approved cleanup window, not accumulated with unbounded `communicate()`.
The oversized-worker-output test substitutes a deliberately hostile subprocess
inside the real sandbox: process-supervision evidence, not Hermes inference.
Actual-worker fixtures promote `ResourceWarning` to errors and capture unraisable
finalizers after cleanup; leaked transports, descriptors and fixture SQLite
handles fail the tests.

All broad acceptance claims remain separate: real provider/auth/model/accounting,
existing-body/lifecycle verifier, owner-provisioned authenticator/signer and OS
isolation for the host frontend, real native broker, passive intake/MCP/mirror
counters, installed wheel, authorized live acceptance, and independent review of
the final exact bytes. Parent-owned DM-041 inventory and generated-vector
migration is also pending. Parent's untouched-base full run reported 834 tests,
four failures and 37 skips: DM-041 module inventory and
provenance-vector drift, package-scaffold inventory drift, and artifact import
missing `daimon_matrix.codex_review`; legacy TemporaryDirectory cleanup warnings
also occurred. These precede this lane and must not be silently repaired here.
A focused green suite is not full-repository success or permission for periodic
production activation.
