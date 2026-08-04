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
