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
event hash. Relationship delivery is excluded until DM-071 supplies
cross-being root discovery and live consent.

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

DM-054 defines consumption and resolution. DM-071 must define live cross-being
root discovery, consent ceremonies and the concrete relationship artifact
verifier. A Tribe audience or authenticated carrier contact is insufficient.

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

## Required daimon-cluster adaptation

Daimon Cluster remains the body/lifecycle side. Its follow-up adapter must:

1. supervise one `daimon-matrixd` process and owner-only state root per exact
   body/embodiment/incarnation;
2. provide a read-only `dm.cluster-body-snapshot/v1` with exactly `schema`,
   `body_ref`, `embodiment_id`, `incarnation_id`, `observed_at_ms`, `state` and
   `resource_fences`;
3. derive those identity bindings from Cluster’s verified registry and current
   incarnation, never from instance names or reachability;
4. expose only resource-scoped fence observations and perform no mutation for
   `/me` reads;
5. install the same root manifest and public credential set at each same-being
   runtime while keeping signing seeds independent;
6. pass carrier bytes without rewriting scope, DM-023 or DM-052 documents; and
7. retire provisional `weave/fanout.py` authority once the Matrix adapter is
   wired, retaining it only as behavioral migration evidence.

DM-037 now defines the exact fence/effect half of this adapter in
`docs/dm037-cluster-effect-boundary.md`. Cluster #48 must consume that merged
contract: body snapshots stay read-only, while effect replay separately
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
