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

Adapters negotiate exact protocol versions. Unknown or downgraded versions
fail closed; this first release has no compatibility mode for prior ontology.
