# `dm.we.v1`: plural presence, synchronization, and local adoption

Status: normative V1 protocol.

`/me` is the here-now viewpoint of one embodiment. `/we` is the set of
embodiments of the same being. More than one embodiment may be awake, answer,
remember, and choose at the same time.

## Envelope

Every durable event is a closed JSON object validated by
`schemas/weave/v1/event.schema.json`. The event hash is SHA-256 over JCS of the
object without `content_hash` and `signature`. The signature preimage is:

```text
UTF8("daimon/weave/event/v1") || 0x00 || hex_decode(content_hash)
```

Sequence starts at one for each incarnation. `previous_event_id` is null only
at sequence one and otherwise names sequence minus one from that incarnation.
`causal_parents` may additionally cite events from any configured embodiment.
The same `origin.incarnation_id + sequence` with different bytes is
equivocation. Event IDs, parent IDs, and request IDs are UUIDs.

`being-manifest/v1` is the provisional administrator-installed view used by
the original canary. `being-manifest/v2` is the root-bound view: it names the
current DM-021 control head and exact credential/incarnation artifact IDs for
each configured origin. The manifest selects routes and configured peers; it
cannot add an origin whose credential chain fails Matrix verification.

When a DM-021 binding is activated, a ledger may admit the exact V1 manifest
and complete event closure named by that binding as historical authority. Its
bytes, IDs, signatures and origins remain unchanged. Only the active V2
manifest may authorize newly created events, and reopening the ledger with a
provisional-only authority fails closed.

Registered kinds are:

- `experience.observed`
- `skill.proposed`
- `preference.proposed`
- `configuration.proposed`
- `adoption.decided`
- `projection.receipted`
- `lifecycle.announced`

Unknown kinds fail closed in V1. Secret values are forbidden. A configuration
proposal may name a local secret slot, never its contents.

## Heads, preview, and pull

A head is `(incarnation_id, max_sequence, tip_event_id, tip_hash)`. Peers first
exchange the exact being-manifest hash and sorted heads. Delta pages contain at
most 256 events and 1 MiB canonical plaintext. The receiver validates the
whole page before committing it transactionally.

`incoming` and `preview` never mutate state. `pull` imports valid events into
the `known` ledger and advances a durable cursor. Repeating a page is
idempotent. A same-origin gap, conflicting head, invalid origin, revoked
credential, unbound transport principal, wrong being, oversize page, or bad
signature rejects the complete page. A missing cross-origin causal parent is
stored as `incomplete`; it cannot enter differences, decisions, or projections
until the complete valid dependency closure arrives.

The transport-neutral exchange is closed and typed. `dm.we.sync-request/v1`
contains a UUID, exact requester origin, current complete heads and page limit.
The requester journals those exact bytes before sending. The responder stores
the first `dm.we.delta/v1` result under `(request_id, request_hash)` in the same
SQLite transaction that freezes the offered heads and page. A retry therefore
returns identical bytes even if new events have since been appended. Reusing
the UUID for different request bytes is equivocation.

A delta binds the request hash, sender and requester origins, exact offered
heads, sorted events, `more`, and a domain-separated page hash. The receiver
accepts only a response to one of its durably issued requests. It validates the
whole document before atomically inserting events, advancing receiver-owned
cursors, and storing `dm.we.sync-receipt/v1`. Response loss followed by retry
returns the exact first receipt; no event or cursor transition is repeated.
V1 sync is available only under root-bound authority; provisional history may
be carried only after an active DM-021 binding admits its exact closure.
Transport authentication and integrity MUST bind its authenticated caller to
the request/delta origin. The inner sync hashes are replay/integrity evidence,
not signatures and not a replacement for DM-024/DM-050 channel authentication.

Import is not adoption. The local effective state is a projection of local
`adoption.decided` events. Decisions are `adopt`, `reject`, `defer`, or
`revert`, name the target event, and may supersede an earlier local decision.
Other embodiments may synchronize those decisions as information; they never
inherit their effect.

## Deterministic local projection

`dm.we.projection/v1` is a disposable content-addressed view over causally
complete events. Only `adoption.decided` events authored by the local
embodiment affect it. A later decision explicitly names the prior local
decision for the same target through `supersedes`. Exactly one connected,
non-forking chain is required; multiple roots, multiple successors, and
cross-target references produce `failed`. Timestamps, incarnation names,
arrival order and lexical hashes never choose a decision.

Peer decisions and receipts remain sorted provenance. A local
`projection.receipted` event binds target, adopted decision, adapter,
preview/intent hashes, actor and authority, optional resource-fence evidence,
result, timing, and observed postcondition. It records an effect; it does not
make the effect eternally true. Adapter reconciliation remains mandatory. A
projection cache may be deleted and atomically rebuilt without applying an
external effect or changing canonical ledger bytes.

A supersession edge is itself a causal dependency. Therefore a supersession
cycle can never become causally complete and cannot enter the projection; the
last complete state remains effective (or `pending` if there was none).

## Difference navigation

The canonical diff operation classifies each known item as `pending`,
`adopted`, `rejected`, `deferred`, `reverted`, `inapplicable`, or `failed`.
It supports filters by origin, kind, subject, and target and returns provenance,
the current local decision, remote decisions, and the effective local value.

Preferences and configuration are proposals. Adapters must expose a preview
before application and return whether the effect is reversible. Memory and
low-impact preferences may be accepted by the local daimon. Identity, access,
credential selection, or external side effects require an explicit human
confirmation. A `projection.receipted` event records adapter, intent hash,
resource fence when applicable, observed postcondition, result, and actor.

## Live `/we`

A live request contains `request_id`, `being_ref`, manifest hash, origin,
issued time, deadline, and bounded content. It is sent to every reachable
active embodiment. Responses repeat the request ID and retain full origin.
Zero, one, or multiple responses are valid. Duplicate requests are processed
at most once per incarnation; timeout returns an explicit partial result.
Responses are never collapsed into a fictional single speaker and are not
stored as memory without a later explicit observation.

## Security/control forks

Different experiences, preferences, or decisions merge as an origin-retaining
set. Same-sequence equivocation, incompatible effects against one fenced
resource, malformed lifecycle transitions, and invalid signatures do not
merge. Those lanes remain quarantined until an explicit successor protocol
resolves them.
