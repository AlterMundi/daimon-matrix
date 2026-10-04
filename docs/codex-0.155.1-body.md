# Codex 0.155.1 successor qualification

This successor is under qualification. Native initialization and isolated
cryptographic bootstrap checks do not establish deployed lifecycle support.
The historical DM-040 profile and its pinned artifacts retain their semantics.

The successor profile uses explicit requests for Matrix and lifecycle actions.
It installs no hooks. Its versioned runtime journal binds the original Matrix
identity and session to the exact profile, plan, release, certificate and
capability set. Legacy replay and changed bindings refuse without rewriting
saved history.

## Explicit being continuity

The successor may select `dm.codex-continuity/v1` in its plan using
`plan-create --continuity SELECTION.json`. The closed selection contains exactly
`SOUL.md`, `FOUNDATION.md` and `MEMORY-ACCESS.md`, each with a byte count, SHA-256
and source reference. It contains no private text, credentials or automatic
actions. Initial creation takes `--continuity-source PRIVATE_DIRECTORY`; it
verifies private regular files before creating the profile. Missing, changed,
linked, executable or invalid UTF-8 sources refuse creation.

The profile retains the originals byte for byte and includes them in `AGENTS.md`,
the native global instruction surface. The combined instructions must fit the
reviewed 32,768-byte native limit; truncation refuses. All copies are mode 0600
and bound by the manifest and plan. Verification and resume use those copies,
not the mutable originals. Editing a selected copy requires a new explicit
profile selection and retains the prior history; it cannot silently change a
saved session. Profiles without selection retain their previous bytes. The
historical adapter refuses this selection.

For CompAII, select the existing Hermes@daimonmatrix SOUL as the initial source,
the complete foundation document without paraphrasing its memory vision, and
the rendered neutral binding's absolute HMK command and shared pool access
instructions. The pool stays mutable being-level memory; it is not a profile
snapshot or a native Codex memory store. The access document must name the
owner-selected installed binding; this feature does not install, invoke or
verify that external binding. Operational acceptance separately verifies that
the command reaches the reconciled pool from the isolated Codex environment.
Provider settings and credentials are not imported into context.

Hermes descriptions in the SOUL preserve that embodiment's history. The current
Codex boundary expressly retains Matrix-certified identity and capabilities,
human-request-only memory access, no prefetch, hooks, timers, inbox polling or
autonomous replies. Selection changes context, not custody or authority. SOUL
evolution can be recorded in the being's memory and later explicit selections.

## Event-attested bootstrap

`dm.codex-body.bootstrap/v2` retains the complete daemon-signed `dm.we.v1`
event in `attestation`. Its `signature` is that event's signature: verification
uses the existing weave event domain and content hash, never a fabricated
signature over a different bootstrap domain. `matrix_high_water` is the signed
event's content hash. The historical bootstrap/v1 format is unchanged and the
historical profile refuses bootstrap/v2.

An explicit `we.observe` request signs a private `experience.observed` event
whose subject is `codex-body/bootstrap`. Its closed payload is
`dm.codex-body.bootstrap-attestation/v1`, containing:

- `bootstrap`: all bootstrap fields except `attestation`, `signature`, and
  `matrix_high_water`;
- exact `runtime_id`, selected `capability_id`, and `client_id`;
- the current `manifest_hash`.

The signed descriptor preserves the root's being, body, embodiment and
incarnation IDs. Its Matrix session ID is explicit public context; the proof
does not manufacture another being or incarnation. The event occurrence time
equals the descriptor issuance time. Bootstrap expiry must fit inside both
the selected finite capability and the embodiment credential's validity.

`authenticate_matrix_binding` verifies a caller-supplied trusted current
RootAuthority snapshot, active manifest membership, current non-revoked
credential, incarnation authorization, signed runtime capability binding, and
selected capability/client/runtime/validity/method admission. Credential and
capability-set hashes are SHA-256 of their complete canonical public documents;
they differ from the domain-separated operator capability-set identifier.

`bootstrap_attestation_payload` only prepares public request data. It performs
no I/O and cannot sign or send anything. `bootstrap_from_attestation` and
`verify_bootstrap_attestation` verify the complete event signature and recheck
current authority, original identity, exact runtime bindings, hashes and time
interval. Startup requires `runtime.status`, `we.heads` and `we.observe` in the
selected capability. No capability is widened or renewed by this operation.
Messaging-only indefinite capabilities are not startup capabilities.

The proof is local bootstrap evidence. It does not establish canonical active
presence, a resource fence, session recovery, high-water ancestry after further
events, conversational delivery, memory continuity, or participant acceptance.
Those checks must be qualified separately. Current-epoch retrieval must use the
trusted runtime boundary; accepting a cached RootAuthority alone cannot prove
that it is still current. Runtime custody stays inside the daemon; the adapter
uses public artifacts and its already authorized local client.

`check_current_runtime_authority` uses that existing authenticated LocalClient
to request `runtime.status`. It first matches the selected signed capability,
expected server origin and exact runtime identity to the client configuration.
It then requires an intact runtime with the same being, origin and active
manifest as the supplied verified RootAuthority, and consistent epoch metadata.
It reads no conversation or ledger contents. A different active epoch refuses;
this check does not silently adopt another authority snapshot.

`DaemonBootstrapVerifier` performs the metadata check before and after proof
verification. It fits the existing profile bootstrap-verifier interface and
performs work only when explicitly called for startup. The checks detect epoch
drift observed during verification; they do not constitute Cluster lifecycle
authority or a resource fence. The runtime still needs lifecycle checks before
native start or recovery can be declared supported.

## Cluster body observations

[DM-021's retirement map](dm021-migration-map.md) retires the old singleton
Matrix presence leases. [DM-037](dm037-cluster-effect-boundary.md) assigns
physical body lifecycle and resource authority to Cluster. Native admission
must preserve that boundary and allow other embodiments of the being to run.

`observe_native_cluster_body` consumes the trusted host's existing BodyReader
and canonical `dm.cluster-body-snapshot/v1` validator. It requires the exact
body, embodiment and incarnation, a running state, and an observation inside
the caller's configured freshness window. Future, stale, substituted, stopped
or unavailable observations refuse. It never substitutes daemon health or
manifest membership for a Cluster observation.

Its `fresh_until_ms` is a local freshness deadline bounded by the admitted
capability's expiry. It grants no lease, exclusion or resource authority.
Resource-fence advertisements in a snapshot are observations; executing an
effect still requires the existing separate current fence/effect verifier.

Tests compose this check with the pinned Cluster MatrixHostAdapter and its
actual registry in a disposable fixture, preserving registry bytes on reads
and refusing after the fixture registry stops the embodiment. They do not
prove a running live host, deployment effects, signed session ancestry,
durable lifecycle recovery or other participants' acceptance.

## Signed session continuity

An explicitly requested private `we.observe` event with subject
`codex-body/session-witness` carries a closed
`dm.codex-body.session-witness/v1` payload. It names the exact Matrix session,
bootstrap event hash, preceding witness event ID and hash, and the next
session witness counter. Its causal parent is that exact preceding event.
The existing daemon requires that dependency to exist in its accepted ledger
before appending the signed observation.

`verify_session_continuity` verifies the supplied bootstrap and every witness
signature against current identity/capability admission. It checks exact
origin, manifest, session, predecessor, counter, causal parent and ordered
event time/sequence. Payload comparison uses canonical bytes, including the
distinction between a boolean and an integer counter. Unrelated ledger events
may occur between witnesses; this function neither fetches nor reads them.

The caller must supply the independently required saved high-water hash.
Truncated, reordered, incorrectly linked or substituted chains refuse. The
returned terminal event proves the supplied causal lineage, not that it is the
daemon's current head or the only competing lineage. The verifier does not
select between competing tips.

`SessionProofJournal` durably stores the verified witnesses in an owner-only,
single-link file bound to the complete attested bootstrap. Every append locks
the file, verifies the signed history against the independently supplied tip,
and accepts exactly one successor before fsync. Concurrent writers with the
same expected tip cannot accept competing branches. Reopening rechecks the
proofs; truncation, torn or noncanonical records and unsafe files refuse
without rewriting history. The caller supplies the current-authority verifier;
the real Unix-socket fixture verifies both reopen and refusal under a changed
authority epoch. The expected tip must survive independently of this file.

`NativeAdmissionVerifier` connects that storage to the adapter: it requires
the exact requested identity/session binding, authenticates current daemon
metadata, verifies durable ancestry to the requested tip, consumes the trusted
Cluster body reader, and rechecks daemon authority before returning. Its
`expires_at_ms` is a local freshness deadline bounded by the bootstrap and
capability, not a physical lifecycle lease. A stopped Cluster body refuses.

Native App Server transport holds an exclusive nonblocking lock on the local
profile directory inode until its child exits. The native child inherits the
lock descriptor so loss of the parent transport descriptor cannot admit a
competing process while the child is still alive. The isolated native probe
closes that parent descriptor, verifies refusal, then proves the profile can
be opened again after the native child exits. A second process using that
profile refuses before spawning; no lock file is added to the manifest. This
is local resource ownership and permits other profiles and embodiments of
the same being. The historical profile behavior remains unchanged.

This storage does not make native thread creation idempotent. The supported
response-loss recoveries and the unresolved first-start case are described below.

## Native MCP connections

Codex starts more than one MCP connection during native startup. Each child
inherits the same open-file description for the capability source. The native
entry point `native_mcp_main` reads that protected descriptor with `pread`, so
one child cannot consume another child's key by advancing the shared offset.
It gives the existing MCP entry point a separate private pipe per connection.
The installed console entry point is `daimon-codex-mcp`. Its executable and
ancestor directories must be owner-controlled with no group or world write
permission. Install under a restrictive umask and verify those modes before
profile creation; an executable or ancestor left group-writable refuses.

The capability source must be an owner-only, single-link regular file of exactly 32 bytes;
single-consumer pipes and unreviewed descriptor types refuse. Key bytes never
enter arguments, environment, protocol receipts or diagnostics.

The reviewed 0.155.1 inventory adds `runtimeStatus`, `pluginId` and `toolsError`.
Admission requires a connected local Matrix server, no plugin substitution,
no discovery error, the exact server version, all six Matrix tools, and the
eight resources advertised by the existing closed MCP contract. Resource
advertisements are metadata; this check does not read their contents. The
historical inventory rules remain unchanged.

An isolated probe now creates an authenticated event-attested profile, starts
the real pinned native App Server, creates thread metadata without any model
turn, and verifies its policy, complete Matrix MCP inventory and running
profile integrity. A subsequent isolated probe uses `NativeAdmissionVerifier`
with the pinned Cluster `Registry`/`MatrixHostAdapter`, authenticated daemon
and attested bootstrap, and invokes the actual `adapter.start`. Native start,
MCP inventory, concurrent-profile refusal and stopped-body refusal pass. This
proves isolated admission interoperability, not deployed host acceptance.

Cold resume of this empty thread refuses with native error -32600, `no rollout
found for thread id`. The pinned official upstream test
`thread_resume_rejects_unmaterialized_thread` specifies that native rollout
storage does not materialize before the first user message. The adapter
preserves its pending resume handle and does not silently create a replacement
thread or erase history. `thread/read` with turns is not a supported workaround
in this native mode. A real user-input durability probe and full response-loss
recovery cannot be established by zero-turn startup alone.

A subsequent synthetic-input probe sends one fixed fixture message, observes
the native completed user-message item, records its native turn handle and
closes the native process. A fresh native process successfully calls the
actual adapter resume and retains the exact original thread and session IDs,
with the same authenticated Matrix/Cluster admission and complete MCP checks.
The successor resume requests `excludeTurns: true`: no history hydration is
needed to prove these handles. The pinned schema defines nullable opaque
pagination cursors, which are validated as bounded strings and never fetched
or interpreted. Historical cursor refusal remains unchanged.

Provider errors are recognized as the pinned successor `error` notification,
with exact outer fields, thread/turn tokens and a boolean `willRetry`; its
message remains data, never an instruction to retry. The historical
notification inventory is unchanged. The fixture has no provider credentials;
waiting for generation in an earlier probe produced an unauthenticated vendor
401 response, so absence of credentials is not evidence of network isolation.
The successful durability probe closes after native input observation and
does not qualify inference success. The supported recovery and park cases are
qualified below; uncertain first-start resolution and deployed-body acceptance
remain outstanding.

## Explicit response-loss and local park recovery

`recover_resume` admits only a successor journal ending in `resuming`, with
unchanged native thread/session IDs linked to a preceding active or pending
resume handle. It reissues metadata-only resume for those saved IDs, validates
the returned policy and full MCP inventory, and rechecks current admission
after the RPC before appending active. It never calls `thread/start` or guesses
a thread from workspace metadata. A real pinned native probe consumes a resume
response and withholds it from the adapter, verifies pending state, then
successfully reconciles the same native IDs and validates a v2 resume receipt.

Successor `park` is an explicitly requested **local native process** shutdown.
It first appends durable `parking` intent, requests `thread/unsubscribe` with
the saved ID, accepts only the pinned `unsubscribed`, `notSubscribed` or
`notLoaded` statuses, and closes the actual native transport. A zero exit code
and fresh admission are required before the parked handle is appended.
Generic RPC transports cannot claim this shutdown. `recover_park` admits only
an exact linked pending parking handle and safely repeats that bounded
operation. The real native probe withholds the unsubscribe response, preserves
the pending handle, recovers to child exit zero and records a root-verified
Matrix observation carrying the final handle hash. It does not stop a Cluster
host, daemon or sibling, or issue a physical lifecycle lease. Historical park
behavior and wire states remain unchanged.

Successor handle journal reads take a shared lock; append holds the exclusive
lock, fsyncs the record and its containing directory. Hardlinked successor
files refuse. Torn histories remain preserved and unresolved.

Loss of the first start response before saving native IDs is a different case.
The pinned start protocol offers neither client-selected thread IDs nor an
idempotency token. The actual native start-loss probe proves one start only,
preserves the starting handle, refuses blind retry/adoption/recovery and signs
an observation explicitly naming the unknown outcome. This is proven refusal,
not successful reconciliation. Operator-directed resolution remains required;
no matching by folder or fabricated native history is supported.

The first-input/resume-loss proof now runs in a private user/network namespace:
the live child namespace is checked distinct from its parent, Matrix remains
reachable through its filesystem Unix socket, and vendor network endpoints
are unreachable. One synthetic native input is registered and no model turn
completes; the same native thread/session is resumed and reconciled with real
receipts. This qualifies protocol durability and recovery without an external
provider canary, account credentials or personal history.

## Remaining release and deployed-host evidence

Release qualification must reproduce these native admission/lifecycle proofs
with the installed wheel and exact Matrix MCP inventory. Closed v2 schemas, signed bootstrap/session and synthetic profile/launch
vectors, package inventories and pinned provenance are now published as
candidate artifacts. Full source/wheel qualification, independent review and
current-head CI remain required. The separate DM-074 successor profile refuses
admission until its mandatory evidence is complete; the historical profiles
retain their frozen evidence states.
Live installation and communication-store migration require the approved
concrete rollout plan. No live change is implied by the isolated fixtures.

## Installed candidate evidence

The installed candidate wheel reproduces attested startup, exact six-tool and
eight-resource MCP admission, concurrent-profile refusal, pending local park
response-loss recovery, native exit zero and a Root-verified Matrix observation.
All loaded `daimon_matrix` modules in that probe originate in the installed
wheel; the MCP process uses its generated console entry point. This is isolated
fixture interoperability, not live-body acceptance. Its test environment shares
preinstalled qualification dependencies, so it does not prove a fresh dependency
installation. Full release qualification remains required.

The installed entry point also refuses a real native startup when its synthetic
capability source has unsafe permissions: the required Matrix MCP cannot
initialize, App Server rejects the request, and no active handle is committed.
The fixture exits its native child cleanly and uses no model input. Installed
cold resume and response-loss recovery retain the exact thread/session with
real validated lifecycle receipts, in a private network namespace with one
synthetic user input and zero completed model turns.

## Effective configuration admission and remaining qualification

The earlier installed, zero-input fixture needed a diagnostic codec because
native `config/read` encodes its two configured durations as `10.0` and `30.0`.
The successor now requests effective configuration during initialization and
validates all rendered controls before admitting a session. Only those two
pinned values on the exact correlated reply are normalized; canonical Matrix
JSON, other replies, notifications and unknown floats remain unchanged.
Vendor defaults may add nested fields, but configured values retain exact types,
and additional MCP servers or project bindings are refused.

The current wheel is built twice with identical bytes and installed into a new
venv with fresh dependencies; `pip check` passes. Its actual native fixture
passes initialization, effective policy comparisons, start and park recovery
without a diagnostic codec. Installed mandatory-MCP refusal, unknown first-start
refusal and network-isolated known-ID resume recovery also pass; the latter uses
one synthetic input and completes zero model turns. These fixtures assert their
Matrix modules come from the installed wheel. Forty-nine successor tests pass.
Full source/package gates, independent review and current-head CI remain pending.
No live body or provider acceptance is implied.

The fixture adds a workspace `AGENTS.md`, but `thread/start` advertises only the
owner-profile instruction source. Pinned official `agents_md.rs` skips project
instructions when the active project is untrusted; its assembly otherwise puts
host instructions before project entries. This source audit and the observed
profile source do not qualify actual trusted-project precedence or neutral
skills/HMK integration. The successor adoption profile remains refused.

## Explicit owner-local admission preflight

`daimon-codex-body binding-check` accepts `--bundle`, `--client-config`,
`--socket` and `--capability-key-fd`. It verifies the public runtime bundle's
Root chain, signed capability binding and selected finite capability, then
checks that the authenticated running daemon serves that exact current epoch.
The capability key is read from an owner-only regular descriptor without
changing its shared offset; it is never an argument, environment variable or
output field. The command reports only the verified identity, manifest hash
and capability expiry. It does not open custody, load a runtime, fall back when
the daemon is absent, read a ledger/inbox, append an observation or start a
native process.

This preflight is the owner-facing connection to the verified admission APIs.
It does not supply a trusted Cluster observation, create an attested session,
or perform a complete native lifecycle. Those operations and their deployed
acceptance remain required before claiming an operational body.

`open_owner_native_session` composes that authenticated owner-local context
with an existing attested bootstrap, a trusted host `BodyReader`, the durable
session proof journal and the native runtime-handle journal. It checks the
rendered MCP's exact client configuration, socket and key binding, and verifies
current authority and Cluster evidence before profile creation or native
spawn.
When reopening an existing profile, admission verifies the signed ancestry
against the terminal high-water in its validated profile-bound handle history.
Only a fresh start without saved handles uses the bootstrap high-water;
missing or altered ancestry refuses without rewriting either journal.
It returns an initialized process and adapter; the owner explicitly
requests start, resume, recovery or park. Closing the transport does not invent
a park receipt. Failed initialization closes its child and preserves evidence.
The host must supply its actual Cluster reader; cached metadata or daemon
health is not accepted as a physical lifecycle observation. This composition
still requires a deployed host/operator entry point and full acceptance.

The `native-lifecycle` operator entry point exposes `start-park`, `resume-park`,
`recover-resume-park` and `recover-park`. Each invocation performs the named
no-model action and closes its native transport. It consumes an already
attested public plan, exact owner socket/client/key descriptor, profile and
request/proof locations, and the host's existing Cluster state. It does not
register or start a Cluster body. `--create-profile` is explicit; existing
profiles remain intact when creation is refused.

`--cluster-checkout` supplies the four consumed reader source files from
Cluster commit `676495e852e6772a60de8221271ee9fc976f77ce`. Their fixed hashes and
protected paths are checked before any code executes; the verified bytes load
under private module names, without importing an ambient `clusterctl` package.
These hashes establish source integrity, not numerical equivalence between
hosts. `--cluster-state` must already be owner-only, and the reader must report
the exact current body and incarnation. No daemon-health fallback, registry
mutation or resource-fence acquisition is provided.

An explicit alternative is `--cluster-reader-socket ABSOLUTE_PATH` together
with `--cluster-reader-owner-uid UID`. This mode connects to the optional
Cluster-owned local reader delivered by nicoechaniz/daimon-cluster#112 (PR#113).
It permits the native verifier to remain under the Cluster service UID while
Codex retains its own owner UID. Both selectors are required; combining either
with `--cluster-checkout` or `--cluster-state` refuses. A refused socket request
never falls back to an in-process reader or a daemon-health snapshot.

The client verifies protected ancestors, the socket's exact owner and published
inode, and real Linux `SO_PEERCRED` before sending the closed origin request.
Only0600 or explicitly shared0666 sockets are admitted; the caller UID is
separately checked by the server before it consumes a request. Connect, write,
header and response payload share a five-second transport deadline. The returned
snapshot is checked by the existing closed Matrix contract and current native
admission/freshness checks; transport success does not authorize a body.

The service must already have an owner-approved profile naming this exact caller,
body, embodiment and incarnation and must use the native authenticated production
fence verifier. Its registry must truthfully report the body as running. The
reader does not register, start, stop or sign a body, widen capabilities, or open
custody. Installing or activating the optional service remains a separate live
action. Its existing native verifier startup permission/SQLite auxiliary-file
effects must be covered by that plan. Private IPC qualification does not prove
actual cross-UID deployment, registration, lifecycle or operational adoption.

This entry point qualifies a local native lifecycle. It submits zero model
inputs and grants no provider canary, neutral-memory adoption, deployed-host
acceptance or live-supported status. First-start loss without saved IDs still
refuses blind retries. Operator-directed resolution and retained native rollout policy remain
separate acceptance work.

`bootstrap-prepare` records an owner-only, fsynced exact `we.observe` request
after authenticated current-authority queries to the live daemon. It does not
send that saved `we.observe` request or sign its Matrix event, and refuses to
replace an existing retry token. Those authority queries may update the daemon's
request cache: preparation is not offline and requires the applicable live
authorization, particularly before a migration whose source anchor must remain
unchanged. `bootstrap-attest` checks that saved request
against the explicitly supplied session ID and expiry, rechecks the current
daemon epoch, then sends those original bytes. Response loss reports
`owner_bootstrap_response_unavailable` and preserves the token: retry the
attest command with the same token rather than preparing another request.
Successful attestation retains the verified bootstrap in an owner-only file;
an exact repeated proof is accepted and a different existing output is
preserved and refused. Expired or changed authority is refused.

`plan-create` consumes that retained bootstrap and the explicitly selected
model, provider and workspace reference to prepare the closed0.155.1 plan.
Plan preparation performs no native admission or inference; current Root,
capability and Cluster checks still happen at the native boundary. Thus the
explicit no-model sequence is prepare request, attest request, create plan,
then native-lifecycle. Live attestation is a Matrix write and is only executed
within an explicitly approved operation. The source fixture exercises this
entire CLI sequence and the real-socket response-loss regression replays the
same accepted request without manufacturing a new session.

For an ambiguous first start, `native-lifecycle --action launch-state` reports
the validated local pending handle without spawning a process, writing a
journal or discovering native IDs. It needs no Cluster checkout/state or proof
journal location. `unknown-first-start` explicitly means no saved native IDs;
the report does not prove child termination or successful reconciliation.
Preserve the profile and journals, confirm the original process has stopped,
and obtain an explicit operator decision before starting a fresh isolated
session with a new bootstrap/profile. Never reuse the ambiguous profile,
guess a thread from directory contents or convert this report into a park
receipt. Known-ID pending resumes use `recover-resume-park`; pending parks use
`recover-park`. An empty, unmaterialized native thread cannot cold-resume.

### Selected neutral skill packages

The successor owner plan optionally carries `skill_packages`, a closed
`dm.codex-skill-packages/v1` inventory. Each package declares its relative path,
SHA-256 of its canonical sorted file inventory, and files with relative path,
SHA-256, byte length and executable flag. This is an explicit owner selection;
neither a digest nor native discovery supplies adoption consent or Matrix authority.
The historical profile rejects this extension. Plans without it retain their
existing rendered bytes and manifests.

`plan-create --skill-packages INVENTORY` validates and binds that selection.
`native-lifecycle --create-profile --skill-source DIRECTORY` prepares an immutable
local projection of exactly the declared source files under the private profile
HOME's `.agents/skills`. Sources are not changed. Unsafe links, file collisions,
missing roots and changed source bytes refuse before profile creation. The
profile manifest and plan hash bind the inventory and projected file digests;
subsequent verification uses the projected files, without re-importing a changed
source pool. Updating skills requires another explicitly selected profile.

The same neutral discovery renderer disables auxiliary `SKILL.md` documents while
preserving declared nested skill roots. Rendered and effective native configuration
must match those controls. Changed, missing, linked or added projected files refuse
admission. Scripts retain their declared executable flag but are never executed
while preparing or verifying the profile. Package preparation does not establish
live invocation, implicit-invocation enforcement, memory adoption or sync acceptance.
Those operational checks and any pending activation approval remain separate.

### Explicit single-input controller

The successor adapter's `run_turn` API accepts one explicitly selected text input,
canonical request UUID, deadline, response bound and retention date. It reserves
an immutable private intent containing the input digest and byte length, then
persists a `turning` handle before sending `turn/start`. Pre-acknowledgement
notifications are retained and correlated with the acknowledged thread and turn.
Ordinary text, reasoning, item lifecycle, status, plan and token-usage envelopes
use the pinned 0.155.1 contracts. Other native item payloads remain bounded data;
they do not prove a tool effect or Matrix authorization. Historical notification
admission and V1 runtime-handle states are unchanged.

A correlated completed, failed or interrupted native result is retained in the
private profile's `turn-results/UUID.json` before restoring an active handle with
its saved turn ID. The result binds the immutable intent and known pending handle
and carries a content-derived result ID. Failure and interruption retain their own status.
Provider error details are removed from the returned result. Lost acknowledgements,
timeout, malformed items or foreign thread/turn events retain the pending handle
and immutable intent; subsequent input and ordinary resume refuse. Errors at this
input boundary never carry an automatic retry flag. `launch-state` reports
`unknown-turn-outcome`; neither that report nor process shutdown proves completion.
Reusing an intent UUID never dispatches another input.

The input and provider-token FD helpers require bounded, owner-only, read-only,
unshared regular files and preserve descriptor offsets. The native owner session
accepts an explicitly supplied provider token and forwards only `CODEX_ACCESS_TOKEN`
through the existing native environment allowlist. Its default passes no provider
credential. These helpers do not inspect ambient accounts, auth.json, personal
history or canonical memory. Native output is returned to the caller; the API
does not print it or grant permission to publish it.

The intent retention date records a selected recovery interval, capped at thirty
days from preparation. It installs no cleanup task and does not delete native
rollouts, intent history or canonical memory. The accepted operational native
retention policy remains unfinished.
Source tests use real subprocess pipes with synthetic
vendor and presence seams; they do not prove provider authentication, a completed
real model turn or live CompAII acceptance.

`native-turn` shares the owner, plan, native binary, workspace and Cluster-reader
locations of `native-lifecycle`. `--action start-turn` optionally creates a selected
profile with `--create-profile`; `--action resume-turn` reopens the saved active
thread. Both require distinct private `--input-fd`, `--provider-token-fd` and
`--capability-key-fd` descriptors, a canonical `--request-id`, `--timeout-seconds`
(1–300), `--max-response-bytes` (1–65536) and explicit `--retain-until-ms`.
The prompt is limited to 4096 UTF-8 bytes. Aliased descriptors, invalid limits or
a previously reserved UUID refuse before owner admission. The controller checks
the selected result location before submitting input and never overwrites an
existing or torn result. A late write failure retains the pending handle.

The command returns only a path-free status receipt with the saved handle,
request/intent/result IDs, native-result digest, terminal status and child exit
code. Native output remains private in the result file. The CLI returns success
only for a completed native turn and clean native process exit; failed and
interrupted turns return failure while retaining their terminal evidence.
Closing the process does not invent a park receipt. Subsequent explicit resume
preserves the previous known turn ID; cold resume and inference on the actual
host remain operational acceptance checks. The reported `model_inputs` counts
submitted human inputs, not internal provider requests or tool effects.

`--action recover-turn` selects an existing immutable intent by `--request-id`.
It requires the owner/provider descriptors but forbids an input descriptor,
replacement limits, retention date or profile creation. The adapter uses the
saved limits and current presence proof, reads only the saved native thread and
its latest full turn, and checks its input byte length and hash. A known
acknowledgement must match that terminal turn. Without an acknowledgement, the
candidate must be the only turn or the immediate successor of the saved baseline;
the second bounded page reads the preceding ID without loading its items.
Missing, in-progress, foreign or ambiguous history leaves the pending state.
Recovery never calls thread start/resume or submits replacement input.

A proven terminal recovery writes `turn-results/UUID.recovered.json` before
restoring active state, preserving even a torn original result. A retry after
that write reuses the immutable recovered artifact only when the native turn ID,
status, items and pending handle agree; timing annotations may differ. A changed
result refuses rather than replacing the retained evidence. Recovery reports
zero submitted model inputs. Native history and private results are recovery
data, not Matrix authority or canonical memory, and do not establish live
retention or operational acceptance.

Explicit inference frames and private results use unsigned vendor JSON encoding,
preserving UTF-8 text without normalization and finite JSON numbers in opaque
tool payloads. Result IDs and native-result digests use deterministic sorted-key
vendor JSON bytes. Nonfinite numbers, duplicate keys and invalid UTF-8 refuse.
Matrix signatures, bootstrap/plan/profile artifacts and handle/intent journals
retain their strict canonical encoding. The audited native configuration-duration
exception remains restricted to its exact correlated configuration reply.


## Explicit owner execution selection

The successor owner `plan-create` command accepts `--reasoning-effort medium`
and `--full-access`. The latter selects the closed combination
`approval_policy=never`, `sandbox=danger-full-access`, `network=enabled`.
Omitting it retains the original `on-request`/`workspace-write`/disabled-network
policy; historical profiles reject these overrides. Reasoning selection is an
optional `codex.reasoning_effort` field, rendered as `model_reasoning_effort`.

Selection is bound to the plan, private profile/config hashes and launch
receipt. Effective native configuration and start/resume response policy must
match the selected plan; mixed policies and substituted reasoning are refused.
Full filesystem/network access does not authorize Matrix actions, custody,
identity changes, automatic replies, hooks, or peer-directed operations. Those
retain their existing signed authorization and human-request boundaries. A
provider token is still passed privately through the supported descriptor
handoff; never include credentials in a plan, profile instructions or receipt.

`tests.test_codex_execution_policy` exercises private profile creation and
reopening, defaults, historical refusal, policy/effort substitution, native
response verification, start/resume dispatch and resulting launch receipts.
The public `valid/full-access-plan.json` is synthetic conformance evidence,
not consent or evidence of a live rollout.
