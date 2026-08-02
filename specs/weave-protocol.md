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
UTF8("daimon/weave/event/v1") || 0x00 || base64url_decode(content_hash)
```

Sequence starts at one for each incarnation. `previous_event_id` is null only
at sequence one and otherwise names sequence minus one from that incarnation.
`causal_parents` may additionally cite events from any configured embodiment.
The same `origin.incarnation_id + sequence` with different bytes is
equivocation. Event IDs, parent IDs, and request IDs are UUIDs.

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
idempotent. A gap, conflicting head, invalid origin, revoked Tribe principal,
wrong being, oversize page, or bad signature rejects the complete page.

Import is not adoption. The local effective state is a projection of local
`adoption.decided` events. Decisions are `adopt`, `reject`, `defer`, or
`revert`, name the target event, and may supersede an earlier local decision.
Other embodiments may synchronize those decisions as information; they never
inherit their effect.

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

