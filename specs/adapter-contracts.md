# Runtime adapter contracts

Status: normative.

Adapters expose effects without acquiring identity authority.

## Cluster lifecycle adapter

Cluster returns body, embodiment, incarnation, current state, and concrete
resource fences. A body creation creates a new embodiment. Start/restart opens
a new incarnation. Multiple embodiments sharing a `being_ref` may be running.

Fences are scoped to `resource_ref`, not being or principal. A mutation names
the current fence generation and observed precondition. Stale generations fail
closed. Presence and reachability are never accepted as fences.

The DM-054 read adapter returns exactly `dm.cluster-body-snapshot/v1` with the
requested `body_ref`, `embodiment_id`, `incarnation_id`, observation time,
`running|stopped|unavailable` state and bounded resource-fence observations.
All three identity bindings must match the Matrix local origin. The read has no
mutation or fence-acquisition authority; substitution fails before `/me`
returns. The concrete Cluster implementation checklist is in
`docs/dm054-scope-resolution.md`.

DM-037 adds the mutation-side evidence boundary without moving authority.
`dm.cluster-resource-fence-evidence/v1` binds one body, holder embodiment and
incarnation, resource, epoch, validity interval and opaque verification
reference under a content hash. Matrix accepts it as current only through an
injected Cluster verifier that checks signature, high-water and current holder
state. A signed Matrix projection receipt embeds only the derived closed
`dm.cluster-resource-fence-position/v1`; the historical position is evidence,
not an eternal lease.

## Communication transport adapter

The transport accepts an already-authorized immutable
`dm.sealed-delivery/v1`, authenticates its body-bound route request and returns
durable operational ACK or recipient-intake evidence. Recipient encryption and
audience resolution finish before route selection. The provider cannot parse
adoption semantics, add recipients, assert same-being membership, append the
ledger, issue presence, mint membership or sign as `/me`.

DM-053 orders configured local, anyVPN direct, other direct and opaque hub
bindings deterministically. Endpoints and secrets remain provider-private;
manifests and results expose only opaque references and fix every authority
boolean to false. A route ACK never substitutes for a semantic receipt. The
generic human-gateway edge is disabled by default; Buzz and Telegram remain
unselected implementations rather than protocol dependencies.

For `/we.sync`, the exact payload and authentication binding are specified in
`docs/dm023-tribe-sync-contract.md`. Transport ACK, Matrix sync receipt, local
adoption, and projection effect receipt are four distinct facts.

## Projection adapter

Every projection supports:

1. `preview(event, local_state)` returning semantic diff, impact, required
   authority, reversibility, and redacted target;
2. `apply(preview_hash, confirmation, fence?)` returning an observed
   postcondition and effect receipt;
3. `reconcile(receipt)` checking whether intent, current fence, and
   postcondition still match.

An idempotency key alone cannot replay a stale effect. A cached result is valid
only while intent bytes, fence, and postcondition match. Secret values are
never returned in previews, receipts, logs, or synchronized events.

The exact adapter result is `dm.cluster-effect-receipt/v1`. It is converted to
the canonical `projection.receipted` payload only after validating its target,
decision, preview, intent, actor, optional fence, result, timing and bounded
observed postcondition. Reconciliation returns `verified`,
`effect-truth-discrepancy`, or `effect-truth-unverifiable`; only `verified` can
serve a cached success. The contract and downstream hosting checklist are in
`docs/dm037-cluster-effect-boundary.md`.

Adapters negotiate exact protocol versions. Unknown or downgraded versions
fail closed; this first release has no compatibility mode for prior ontology.

## Local plural-body composition

DM-042 composes the Codex and Hermes adapters without granting either adapter
new authority. Both public state machines must be active under one exact
root-bound `being-manifest/v2`, while their body/embodiment/incarnation,
credential, signing/encryption/transport keys, principal, Matrix session,
capability set, profile and writable SQLite remain distinct.

The composition uses DM-023 requests, deltas and receipts directly. It does not
invent adapter-to-adapter synchronization. Final signed event sets and heads
must converge, but adoption remains local: Codex may adopt a target that Hermes
rejects, and both projections retain the opposite decision as remote evidence.
The path-free `dm.local-we.validation/v1` receipt proves those bounded facts;
its producer additionally verifies filesystem isolation, current profiles,
root membership and plan-bound launch receipts. The normative scenario and
failure matrix are in `docs/dm042-local-we.md`.

## Hermes body adapter

DM-041 adapts Hermes Agent 0.19.0 as a body runtime without moving identity,
memory, presence or lifecycle authority into Hermes. Matrix supplies a signed
bootstrap and an owner-local capability. Cluster supplies placement, body
volume and the authoritative park/handoff committer. The adapter accepts an
active launch only after the exact external Matrix memory provider verifies
`runtime.status`, `/me`, a freshly observed running Cluster body snapshot,
current memory projection and initial Weave high-water. Each projection read is
bracketed by two scope reads and is disclosed only when the manifest and
high-water remain stable.

The managed profile is fresh, owner-only and nonambient. It contains one exact
external provider and public role/skill, disables native/HMK memory and general
plugins, isolates `HOME`, and exposes only `matrix_scope` plus an idempotent
observation proposal. Its profile/launch evidence fixes every loaded Matrix
module plus the reviewed public schema digests. Per-turn data is a bounded
inert current-user sidecar;
hooks and conversation history cannot author personal memory. The append-only
`starting|active|parking|parked|failed` journal prevents blind lifecycle replay,
and park becomes final only with bound Matrix handoff plus relinquished-presence
receipts. The normative contract is `docs/dm041-hermes-body.md`.
The observation receipt validates the complete authenticated daemon event,
rebinds its sensitivity and post-effect high-water, and uses a hash domain
distinct from launch receipts.

DM-031 curator coordination never substitutes for this adapter contract. A
`queue-item` claim is owner-local work ordering only. A `resource-fence` claim
must embed the exact derived fence position accepted from the current injected
Cluster verifier, bind its effect intent and actor, and reconcile the adapter
receipt against current observed postcondition before every cached replay.

### Personal-memory projection

DM-034 specializes the projection boundary for HMK without granting HMK
authority. Its exact DM-018 manifest is `memory-projection/v1`; the target is
HMK merge `f10fd5c3089c0962920314c97e14bc024feffa7a`, API `1.0.0`, schema `1`,
and projector `matrix:personal-memory-projector@1.0.0`.

Only current, linear, locally accepted `/me` heads in the three personal
categories may cross. Stable destination identity is
`(source_instance, subject_me_id, projector_id, projector_version, memory_id)`.
Every effect binds the exact source event/head/content/checkpoint and is freshly
observed before initial or cached success. The owner-local recovery lock and
journal serialize exact requests but confer no authority.

Recall verifies the complete current namespace against Matrix before returning
content. Rebuild re-derives and revalidates the embedded HMK plan immediately
before its atomic namespace-only apply. HMK-native, Wiki and collective records
are outside the selector. The closed contract, crash table, dry-run cutover and
rollback procedure are normative in `docs/dm034-memory-projection.md`.

### Reviewed publication

DM-035 is a distinct outbound projection. Matrix owns source events, exact
policy, independent Ed25519 review, deterministic rendering, queue intent and
accepted receipt. The pinned `compaii-state` publisher owns only one configured
Wiki/state/HMK transaction. Neither Wiki, state nor HMK can author or repair
Matrix canonical state.

The injected transport exposes only `manifest`, `plan`, `acquire`, `apply`,
`reconcile` and `release` over closed logical documents. No path, SQL, Git
handle, endpoint, credential or provider implementation object crosses the
boundary. Matrix validates exact adapter/policy/HMK pins, every plan effect and
the complete content-derived receipt, then requires fresh external
`reconcile=verified` before ledger acceptance or cached replay.

Queue items derive from canonical `publication.requested` events at an explicit
cutoff. Target-scoped generation claims plus an owner-only process lock permit
one writer. Successor, withdrawal and rollback are new reviewed monotonic
transactions; they never erase audit history or lower a high-water. The exact
contracts, crash matrix, private-provider CI split and rollback procedure are
normative in `docs/dm035-publication.md`.
