# DM-054 root-authorized scope resolution

Status: implemented carrier-independent contract. “Matrix” means
`daimon-matrix`; Matrix.org is absent.

DM-054 turns `/me`, `/we` and `/tribe` into exact runtime documents. It does
not treat DNS, a route profile, the Tribe directory, an Incus instance name or
a display alias as identity. The only same-being roster is the root-bound
`being-manifest/v2`; the only tribe roster is a closed
`dm.tribe-snapshot/v1` accepted by an injected history verifier.

## Local viewpoint and topology

`scope.me` returns the exact hosted origin, current credential and incarnation
authorization references, local heads, and the local effective projection. The
projection contains no event payloads and retains every original origin. An
optional `dm.cluster-body-snapshot/v1` is accepted only when its body,
embodiment and incarnation equal the local Matrix origin. Lifecycle state and
resource-fence observations are evidence; they cannot change identity,
membership, adoption or signing authority.

Matrix owns the snapshot evaluation coordinate. It passes the exact
`evaluated_at_ms` to the owner-local body reader as its fourth argument, and
the adapter binds its registry/fence observation to that value. This prevents
an honest read from becoming intermittently “future” merely because the wall
clock crossed a millisecond between Matrix evaluation and the callback. A
returned timestamp greater than the supplied coordinate still fails closed;
there is no skew tolerance or three-argument compatibility path.

### Compact current identity inspection

For current identity/body-admission inspection without historical projection, use
existing `runtime.status` with `{"view":"receiving"}`. It returns
`dm.runtime.receiving-status/v1`, including the authenticated current `identity`
and selected runtime. The same view is available as
`client.runtime_status(view="receiving")`, CLI
`daimon daemon status --view receiving`, and MCP `daimon_status(view="receiving")`.
It uses the existing runtime-status read grant and checks the current body reader;
it is not a cached identity or a complete integrity audit. The ordinary status
and `/me` views retain their existing behavior. Avoid the full `/me` history
projection when only current identity is needed. No new tool, grant or catalog
is introduced.

Receiving status retains a shared two-second wait budget for its physical reader
fences. That wait starts after group validation and signed-roster reconstruction;
CPU time spent validating a larger roster must not turn an uncontended reader
into `egress_attempt_deadline`. A genuinely contended fence still returns that
retryable error. The caller's operation deadline remains separate.

Explicit reader maintenance has one ten-second native budget for roster
validation, physical/CAS checks and durable recovery. A command's earlier
`effect_not_after_ms` remains authoritative. Persistence failures retain their
uncertain outcome and emit one closed diagnostic per distinct pending failure
through the existing service log; arbitrary exception details stay private.

### Current client's Matrix method permissions

The compact receiving response also reports `client_authority` with schema
`dm.runtime.client-authority/v1`, coverage
`authenticated-client-granted-methods`, and the sorted method names from the
capability that authenticated this exact call. It discloses no keys, capability
descriptors or other clients' grants. Exact status retries authenticate again
and report that same current calling authority through the normal live read.
Ordinary status and scope views are unchanged; no new tool or grant is needed.

This is the Matrix permission slice of an own-body inventory. A permitted method
can still refuse because its feature, resource grant or receiving state is
unavailable. It is not a complete harness tool list, sensor/actuator inventory,
resource allowance, shared capability advertisement or another being's authority.
The configured `/me` `body_capabilities` labels remain a separate description;
an empty list does not establish that this client has no granted Matrix methods.
Use the existing typed tools and their real results for selected work.

### Loaded relationship verification context

`loaded_runtime.relationship_authorities` reports the public being references and
active/accepted manifest hashes actually selected for the native relationship
verifier at process load. It includes explicit trusted-host public context as
well as configured known peers, independently of messaging application enrollment.
The map is empty without a configured relationship context. It is frozen to the
loaded process; changing caller maps or files cannot change that observation.

Receiving observers may combine these epochs with the existing local and
application authority observations when checking the current signed roster.
Absent metadata retains the previous conservative check. This adds no authority,
membership, route, grant, human publication or model attention. Existing signed
bindings, store checks, process/selection pins and reader controls still apply.

### Native surface view

`scope.me` with `{"view":"surface"}` returns `dm.scope.me-surface/v1`:
the exact local being/manifest/origin and an admitted Cluster surface observation.
The ordinary empty-parameter response remains unchanged. The same optional view
is available as `client.scope_me(view="surface")` and through MCP `scope_me`.
It uses the existing own-body read capability and discloses no foreign body.

The qualified native parent's existing body callback must expose its read-only
`surface` method. Matrix owns the evaluation time and requires an exact timestamp,
origin, running state, `native-linux-os` domain and purpose-separated surface
reference. Old callbacks refuse the optional view as unavailable; malformed,
stale or substituted observations are rejected without inferring a surface from
a host label, network or Tribe. No history projection is required for this view.

Cluster's native reference represents a current Linux OS instance, including its
boot identity. A full KVM has its own surface even when sharing a physical host;
a reboot requires a fresh observation. The reference is not a geography,
membership, persistent being identity or an actuation grant. This supplies
`/me.body` evidence, not a completed `/here` roster or `/near` resolver. Keep
source availability, selected receiving code and actual all-three observations
separate in the current #437 checkpoint.

### Native realm status view

`scope.me` with `{"view":"realm"}` returns `dm.scope.realm-status/v1` through
`client.scope_me(view="realm")`, CLI `daimon scope me --view realm` and the
existing MCP `scope_me` tool. It is an
initial own-body `/realm.status` projection in the explicit `native-linux-os`
domain. The admitted parent's existing bounded observation channel must expose
`realm`; missing/old support returns retryable unavailable, never a host-label
or cached-surface substitute. The default view and existing grants are unchanged.

Matrix validates the exact current own-body surface, origin and evaluation
coordinate, plus the closed `dm.cluster-realm-snapshot/v1`. Kernel observations
are integer `uptime_ms`, `memory_total_bytes` and `memory_available_bytes`;
unavailable groups remain null and `resource_state` becomes `partial`. Unknown
fields, booleans, negative/oversized values, inconsistent memory pairs and a
false complete claim are rejected. No private history, process arguments or raw
machine/boot identity is exposed. The native parent reads at most128bytes of
uptime and64KiB of memory metadata without child processes or model/network work.

These are kernel OS observations, **not** a process/cgroup allowance, a future
capacity reservation, a physical hypervisor census or an operation grant. Oliva's
KVM observes its own guest OS, separately from native ITACA. The current surface
changes on reboot and requires a fresh read. This does not create `/here` or
Tribe membership. `controls: not-established` explicitly retains the unfinished
realm-modification-control domain; status alone is not full foundation acceptance.
No service, provider, goal, credential, timer or autonomous attention is added.

### Foreground native OS work controls

For explicitly authorized work in a body's own Linux user session, the existing
systemd user manager provides useful resource modification and a scoped stop.
Use it directly; Matrix does not need a second task scheduler, permission registry
or resource allocator. This is an operator workflow through the body's existing
shell authority, not a new Matrix RPC or a grant to control another body's work.
The authenticated `scope.me` realm read identifies the observed body; it does not
confer the user-manager authority. Keep those two evidence sources distinct.

Launch the selected foreground command once, with an operation-owned unit name:

```sh
systemd-run --user --unit=SELECTED_WORK --service-type=exec \
  --property=MemoryMax=128M --property=CPUQuota=25% \
  --property=TasksMax=16 --property=RuntimeMaxSec=60 \
  --property=TimeoutStopSec=5 --property=KillMode=control-group \
  --property=NoNewPrivileges=yes \
  --property=StandardOutput=null --property=StandardError=null \
  SELECTED_COMMAND
```

These example bounds suit a small metadata read. Choose bounds appropriate to
the actual task and current resource grant; free OS memory is not a grant. This
route limits memory, CPU, process count and service lifetime, not filesystem
writes, network access, provider spending or all host resources. Retain necessary
command output in the task's existing bounded private work record; do not enable
unbounded output, copy credentials into arguments or add recurring activation.

`systemctl --user show SELECTED_WORK.service -p ControlGroup -p MemoryMax
-p CPUQuotaPerSecUSec -p TasksMax -p RuntimeMaxUSec` returns the actual service
properties. Inspect the workload's corresponding `cpu.max`, `memory.max` and
`pids.max` under its current cgroup to establish kernel enforcement. A manager's
configuration alone does not prove a differently placed child is constrained.

The owner may change only that selected task's resource budget, for example
`systemctl --user set-property --runtime SELECTED_WORK.service CPUQuota=50%`,
and inspect the resulting kernel value. Use
`systemctl --user stop SELECTED_WORK.service` to withdraw that task's execution.
Verify its actual exit and descendant/cgroup cleanup. This is neither global Stop
nor authority to stop the native harness, goals, another user's services or an
unrelated task. A disconnected launcher or lost acknowledgment requires inspecting
the same named unit and retained result, not launching the command again.

Initial ITACA acceptance used one genuine authenticated Matrix realm read under
UID1000/NoNewPrivileges,128MiB,16tasks and a60second lifetime. Kernel CPU quota
changed from25% to50% while that same task remained active; the selected owner
stop produced a successful exit and removal of its cgroup, with zero model calls
and no existing-service/goal/heartbeat changes. This proves the own-work operator route
on that receiver. Other receivers, cross-body grants, richer controls and native
Matrix control discovery/dispatch remain separate unfinished integration; the
native status RPC correctly continues to say `controls: not-established`.

### Cluster discovery view

The existing read-only `scope.resolve` capability accepts an explicit
`view:"discovery"` with `scope:"/all"`, a request UUID and `tribe_ref:null`.
CLI: `daimon scope resolve --scope /all --view discovery --scope-request-id UUID`.
MCP uses `scope_resolve` with the same fields; it fills an omitted `tribe_ref`
with null. Existing target-plan calls and the number of tools/grant families
remain unchanged.

This returns `dm.scope.discovery/v1`, not a DM-052 target plan. It discovers
current bodies admitted by the local native parent's existing Cluster authority,
including distinct beings outside `/we` and independent of `/tribe`. Exact local
origin/time/running admission, closed inventory fields, admission-resource
coordinates, ordering, uniqueness, bounds and lease expiry are validated. A
complete inventory must include this body. Missing/old parent support is
retryable unavailable; substituted or inconsistent data is rejected. No host
registry, display label or Tribe roster is used as a fallback.

`authority_observed_at_ms` retains the admission authority's evaluation clock;
`evaluated_at_ms` binds this body's native observation. They are not required to
be equal across hosts. The injected native parent verifies the authority's
current session-bound signed response; a stored document is not an inventory
provider. At most256 members are admitted and `partial` preserves the authority's
truncation. Each member explicitly says `process_response:"not-observed"`:
admission does not prove a model/process answered or that a route is available.
The view projects no private history and creates no message, disclosure,
permission, model turn or automatic attention. Its result has no `targets` or
resolution hash and cannot be used as a messaging plan.

This is the discovery portion of `/all`, not a completed group exchange.
The same explicit view accepts `/we`, filtering the validated inventory by the
current being reference. It returns only that being's current local-Cluster
admissions, never Eko or Oliva merely because they share ancestry or a Tribe.
Active entries in the being manifest absent from this observation are listed as
`unavailable` with `reason:"not-observed-in-local-cluster"`; this means unknown,
not stopped or retired. The result is partial when any such entry is missing or
the authority inventory is truncated. `coverage:"current-local-cluster-admissions"`
keeps this observation distinct from a complete multi-Cluster `/we` roster.
Configured carriers still do not establish process/model presence. Default
`scope.we`, historical topology, sync and target-plan behavior are unchanged.
This reuses the existing inventory read and grants, with no additional calls,
model attention, route probing or identity changes.

The optional native `/here` view below compares current launch-bound reports;
`/near` needs
an explicit distance domain. Neither is silently mapped to this inventory.
Published source, receiving selection and actual domain use remain separate
in the current #437 checkpoint.

`scope.we` enumerates every manifest incarnation in deterministic
`(embodiment_id, incarnation_id)` order. Active, retired, local, available,
unavailable and unconfigured are distinct facts. There may be many active
embodiments, but never two active incarnations for one embodiment in a resolver
view. DM-053 inspection runs only after membership resolution. Its redacted
candidates may select a carrier for an already-authorized target and cannot add
or remove one.

`scope.resolve` emits the exact ordered target rows consumed by DM-052. `/me`
and `/we` use the embodiment recipient lane. `/tribe` uses the relationship
lane: `recipient_id` is the exact `membership_ref`, while
`receipt_origin_embodiment_id` remains the embodiment expected to author a
semantic receipt. Confusing those identifiers is a protocol error.

For same-being messages,
`DisclosureAuthorization.from_resolution_event` verifies the signed DM-052
message and causal resolution event, maps every active embodiment to its
current encryption credential, and binds DM-051 disclosure to the resolution
event hash. For relationship messages, DM-082's
`from_relationship_resolution_event` binds a selected relationship target,
its current verified disclosure and the concrete receipt-origin embodiment to
the same DM-051 authorization. The selected target remains signed DM-052
evidence; route code cannot add a recipient.

## Difference and sync planning

`scope.we.diff` reports the local projection hash, payload-free entries and
per-origin state counts. Remote decisions and receipts remain attributed
information; they never become local adoption or effect.

`scope.we.sync-plan` produces one frozen DM-023 request per active remote
origin. Target request UUIDs are deterministic UUIDv5 children of the plan UUID
and exact embodiment/incarnation pair. Each request carries the same local
heads but has an independent durable replay key. Serving, preview, pull,
cursor, gap, equivocation and receipt behavior remains DM-023: pull imports
known events and performs no automatic adoption.

## Signed partial fan-out

The carrier-neutral protocol uses `dm.scope.request/v1` and
`dm.scope.response/v1`. Both are canonical JSON, signed with the current
embodiment Ed25519 key under purpose-specific domains, and bind the exact
`being_ref`, manifest hash, origin, request ID and deadline. Requests are `/me`
queries only, limited to 60 seconds and 1 MiB responses. Responses retain their
actual body, embodiment, incarnation and transport principal. No algorithm
chooses one response as the voice of the being.

`ScopeExchangeStore` journals requests by direction/requester/request ID and
responses by request ID/responder. Concurrent exact duplicates converge on one
byte-identical response. Changed bytes conflict. A response already frozen may
replay after deadline; a new late request cannot execute. Results return every
validated response plus explicit `missing`, `refused` and `unavailable`
targets. Zero remote responses is a successful partial result, not proof that
no other embodiment exists.

No live peer carrier is selected by DM-054. `ScopeFanout` accepts an injected
peer-call function; loopback tests exercise the signing, deadline and replay
protocol. Tribe Bridge, direct AnyVPN, a hub, or a future Buzz/Telegram gateway
may carry those bytes later without becoming scope authority.

## Tribe snapshots

A tribe declaration contains founder principal, creation time, random nonce
and policy reference; its `tribe_ref` is domain-separated content addressing.
The loader validates closed, bounded, sorted snapshots, active founder,
membership IDs, founder epoch and separately time-bounded grants. It then
requires an injected verifier to prove invitation/acceptance history,
leave/expulsion, founder transfer, fork freedom, revocation and grant-chain
attenuation. Without that verifier the snapshot is unusable. Membership alone
never grants a resource operation.

DM-054 defines consumption and resolution; DM-082 supplies the concrete signed
relationship verifier and a synthetic cross-being intake path. DM-071 still
owns live cross-host discovery, operational consent exchange and the external
canary. A Tribe audience or authenticated carrier contact is insufficient.

## Hosted surfaces and custody

The daemon adds `scope.me`, `scope.we`, `scope.we.diff`,
`scope.we.sync-plan`, `scope.resolve` and `scope.tribe`. The CLI exposes them
under `daimon scope`; MCP exposes six corresponding closed tools. Fan-out
execution, remote serving, sealing, dispatch, adoption and Cluster mutation are
not generic human/model tools.

Runtime bundles contain an explicit nullable `scopes` section. It may declare
sorted body capabilities and an owner-only relationship snapshot filename. A
relationship file without an injected verifier fails startup. Cluster reads
are injected process adapters, not host-wide defaults. No new secret slot is
introduced: scope request signatures reuse embodiment signing custody with a
separate domain.

## Implemented daimon-cluster host adaptation

Daimon Cluster remains the body/lifecycle side. Issue #48 and PR #49 implement
the host/read side of this contract at
`676495e852e6772a60de8221271ee9fc976f77ce`:

1. supervise one `daimon-matrixd` process and owner-only state root per exact
   body/embodiment/incarnation;
2. provide a read-only `dm.cluster-body-snapshot/v1` with exactly `schema`,
   `body_ref`, `embodiment_id`, `incarnation_id`, `observed_at_ms`, `state` and
   `resource_fences`, binding `observed_at_ms` to the evaluation coordinate
   supplied as the body reader's fourth argument;
3. derive those identity bindings from Cluster’s verified registry and current
   incarnation, never from instance names or reachability;
4. expose only resource-scoped fence observations and perform no mutation for
   `/me` reads;
5. install the same root manifest and public credential set at each same-being
   runtime while keeping signing seeds independent;
6. pass carrier bytes without rewriting scope, DM-023 or DM-052 documents; and
7. retire provisional executable `weave/` authority, retaining only frozen
   behavioral migration evidence.

DM-037 now defines the exact fence/effect half of this adapter in
`docs/dm037-cluster-effect-boundary.md`. The merged Cluster adapter consumes
that contract: body snapshots stay read-only, while effect replay separately
requires live Cluster verification of the recorded fence and observed
postcondition.

Cluster must not mint a being, infer `/we` from running containers, collapse
multiple active embodiments, treat presence as a fence, open Matrix custody,
or write Matrix ledgers. The future cross-host rebirth drill must prove a new
incarnation appears as current `/me`, both active embodiments remain visible
under `/we`, fan-out preserves both origins, and DM-023 imports without
adoption.

## Verification and rollback

Executable evidence is in `tests/test_dm054_scopes.py`, the frozen case list in
`conformance/fixtures/dm054-scope-resolution.json`, and the invariant record in
`docs/verification/dm054-invariants.json`. It uses two independent ledgers,
concurrent SQLite calls, fake clocks, signature tamper cases, real Unix daemon
frames, DM-051/052 parity and runtime-loaded Cluster/tribe adapters.

Rollback removes the six safe capability methods and nullable scope bundle
configuration. It does not delete ledger events, DM-023 requests/cursors,
DM-052 resolution events, route attempts, relationship snapshots or frozen
scope exchanges.

### Native `/here` discovery

The same explicit discovery view accepts `/here` when the admitted parent
supports `surface_inventory`. It reports the parent's actual native OS reference
through the existing launch session, then compares all currently reported native
OS surfaces with that local observation. The CLI and existing `scope_resolve`
tool use the same `scope.resolve` read grant. This request publishes only the
opaque OS reference within the admitted Cluster; it creates no background work.

The result retains its actual local `surface` and only matching `members`.
Admitted participants with no current launch-bound report appear in `unavailable`
with `surface-not-reported`; they make the result `partial`, as does a truncated
admission scan. A different known native OS surface is a nonmatch, including a
full KVM on the same physical server. Foreign, malformed, future-dated or
contradictory local reports refuse the read. No host label, Tribe membership,
geographical distance, external address or private history supplies a match.

Remote evidence remains `admitted-launch-report`: it is authenticated cooperative
parent software evidence, not independent physical attestation. Authority restart
or bounded-cache eviction can make a report unknown until that body explicitly
requests another census. No automatic peer/model request occurs. Discovery still
produces no DM052 target plan and observes no process response or message delivery.
Source availability alone is not a completed receiving `/here` rollout.
