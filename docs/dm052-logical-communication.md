# DM-052 logical communication

## V2 foreign-reference receipt successor

The V1 receipt payload and canonical-parent requirement below remain unchanged.
`dm.communication.receipt/v2` is a distinct, closed payload for recipient-authored
`delivered` (durable application intake only). It uses `message_being_ref`, exact
`message_ref` and `resolution_ref` ID/hash pairs, thread, relationship recipient,
outcome and observation time. The event timestamp MUST equal the observation
and MUST NOT predate the original message. Foreign references MUST NOT appear in
its local causal parents. Only its author's Ledger allocates its sequence.

A V2 application message signs its expected recipient being in the body. The
foreign reducer MUST bind that being in addition to the signed resolution's
membership and receipt embodiment. It MUST independently verify the complete
receipt signature, all references, thread and outcome. A passed-in being or a
matching embodiment label is not original-leg authority. The application carrier
also binds outer response context and origin to the receipt. V1 messages lacking
this original signed being binding remain explicitly untracked after migration.

The explicit projection-schema successor keeps `communication_receipts` and its
local-event foreign key intact. Foreign proofs live in
`communication_foreign_receipts`, never in `events`. Event-ID and foreign origin
position collisions and distinct terminal evidence quarantine the leg with full
signed evidence. V1 and V2 reducers consult both receipt tables under the same
writer transaction. V2 projection reads and mutations MUST derive the complete
recipient-key set from the verified canonical message/resolution and check every
leg's immutable binding, even without a receipt. Missing or extra legs MUST NOT
turn a partial vector into a terminal result. Retained local receipts MUST match
the exact message, thread, recipient and outcome-specific origin rules used at
admission, including their stored projection bytes and terminal columns. Foreign
proofs MUST be reverified before returning semantic state, including direct leg
reads and cached page, claim, attempt and consumer-progress paths. Missing or
tampered evidence cannot become success. Local Ledger replay alone is not
sufficient to reconstruct foreign proofs.

A cached page or claim remains a historical snapshot, not current delivery or
lease authority. Its request/cursor bindings and immutable item fields MUST
remain valid; any historical terminal claim MUST still match the retained,
verified receipt. Replaying a pre-delivery accepted snapshot after delivery or
compaction does not change that snapshot to terminal. Replaying a delivered
snapshot after later quarantine does not undo quarantine or renew authorization.
Validation and return use the same SQLite transaction without authoring receipts
or performing network effects.

Schema migration is explicit and preserves generation/counter/cursors. V2
mutations add a protected before/after snapshot journal around DB/anchor commit,
so exact crash pre/post states recover without accepting unrelated rollback.
V1 mutation behavior is unchanged. See [native application successor and operator
migration](native-agent-messaging.md#explicit-semantic-receipt-successor-application-v2)
for the reply-only trigger, cross-store reconciliation and qualification limits.


Status: implemented behind the authenticated local daemon boundary; no live
carrier is enabled.

## Contract and ontology

One logical message is one accepted, root-authorized `dm.we.v1` event whose
signed payload is `dm.communication.message/v1`. Its `event_id` is the
`message_id`; its signed `intent.thread_id` is the stable thread. Route,
credential, key, body, adapter, attempt and delivery identifiers can change
without changing either value.

This is the runtime successor to historical DM-011 V0 terminology. It does not
restore `me_id`, `operational_id`, `daimon-sealed-event/v0`, or an identity-wide
singleton. A direct reply is the signed `daimon-reply/v1` member of the message
payload and names `direct_recipient_embodiment_id` plus sorted, non-empty
`reply_parent_event_ids`. Every named parent must also be a signed causal parent
and must already project into the same thread.

Resolution is another verified `dm.we.v1` event with a closed
`dm.communication.resolution/v1` payload. DM-052 consumes that narrow-waist
evidence; it does not decide membership or disclosure. DM-054 will author it
from current being-manifest, relationship and grant evidence. `/we` and direct
targets use stable embodiment IDs, so incarnation, body and recipient-key
rotation do not create another semantic leg. Relationship targets use their
stable relationship principal identifier. The signed target list is sorted and
duplicates fail closed, where a duplicate is two targets agreeing on recipient
type, recipient **and receipt author**: one semantic recipient may be received by
several of a member's embodiments, but never twice by the same one. A store that
has not been upgraded to per-body legs keeps the delivered narrower rule and
refuses several bodies for one recipient with the same closed error, rather than
letting its own uniqueness constraint surface as a database failure.

## Same-ledger projections

`CommunicationStore` adds tables to the existing DM-023 SQLite ledger. It is
not a second writable ledger and it cannot accept an event absent from the
canonical `events` table. The logical tables retain:

1. the message projection and exact signed resolution reference;
2. one content-derived semantic leg for `(message_id, recipient_type,
   recipient_id)`, and in a store upgraded to per-body legs for
   `(message_id, recipient_type, recipient_id,
   receipt_origin_embodiment_id)`, so that several embodiments of one member each
   hold their own leg and each authors its own receipt;
3. any number of disposable route attempts and DM-051 delivery IDs; and
4. one terminal receipt projection whose authority remains its signed
   `dm.we.v1` receipt event.

The upgrade is an explicit offline successor, like the receipts V2 one: it
preserves every stored row, its sequence and its state, recomputes leg identities
under the widened derivation together with the queue, attempt and receipt rows that
reference them, and verifies referential integrity before it reports success. Legs
are a projection of signed events rather than signed history, so recomputing their
identifiers in that successor is legitimate, and it is what keeps a single identity
rule true of every leg in the store instead of tolerating two forever.

Creating the same message or leg again returns the stored projection. Changed
immutable bytes conflict. Direct and hub attempts, retry, forwarding, batching
or DM-051 resealing add operational evidence only. An exact delivery replay is
idempotent; changed bytes beneath one `delivery_id` quarantine the leg.
`rebuild_plan` returns the canonical event, signed resolution and semantic legs
without depending on a still-live sealed wrapper, so an expired ciphertext does
not destroy retry authority.

The only non-terminal state is `accepted`. Terminal outcomes are exactly
`delivered`, `failed:transport`, `refused:policy`, `expired`, and
`resolved:unroutable`. `delivered` requires a receipt event authored by the
resolved receipt embodiment and means intake only. It does not mean validation,
projection, effect, reply, memory admission or trust. A route ACK is stored only
on its attempt and never terminates a leg. Competing terminal receipt events
are retained as conflict evidence and quarantine the leg rather than selecting
an arrival-order winner. The result is always the complete per-recipient
vector; callers requesting a terminal result receive a retryable incomplete
error while any leg is `accepted` or quarantined.

## Queue, claims and cursors

Queue order is a store-assigned integer sequence. Timestamps never order or
advance delivery. The sequence high-water and a random store generation live in
communication metadata and are never decreased or reused.

Page reads bind recipient, consumer, generation, snapshot high-water and last
returned sequence. The public token is 256 bits of CSPRNG entropy; only its hash
and binding are stored. Unknown, changed or cross-consumer tokens fail before a
page is queried. A request UUID binds an exact page operation and repeats its
byte-identical result. New inserts after the first page are outside that
snapshot; the caller follows `next_cursor` until null rather than treating a
page size as end-of-stream.

Claims lease currently accepted queue rows under an exact claim UUID. SQLite's
writer transaction makes concurrent claims disjoint. A query or claim never
advances durable progress. A consumer cursor advances only when every owned row
between its prior position and requested sequence has a terminal semantic
receipt. Lower positions, unowned targets, positions above high-water and
skip-over of accepted, claimed or quarantined rows fail closed.

Compaction deletes only terminal queue rows below every registered consumer's
progress. Messages, signed evidence, semantic legs and terminal receipts remain
queryable and verifiable. A canonical owner-only sidecar binds the store
generation to a monotonic mutation counter. The sidecar is durably armed before
the SQLite commit; a restored or lowered database therefore fails closed as
`communication_state_rollback` instead of silently accepting an old cursor.
Explicit recovery must rotate generation and rebuild from canonical events; it
is intentionally not an ordinary RPC operation.

## Local and carrier boundaries

The installed service exposes dedicated `communication.*` RPC methods to
purpose-limited local capabilities. They are not added to the general human
CLI or MCP surface; DM-054 will expose `/me`, `/we`, `/we.sync` and `/tribe`
operations rather than raw queue mutation.

`RouteProvider.deliver` is the narrow fake/DM-018 boundary. If a provider effect
may have happened but its response is lost, the attempt remains `accepted` and
the same `attempt_id` is retried; ambiguity is never rewritten as failure. Only
an explicit provider ACK changes route-attempt state. DM-053 now implements
disabled-by-default local, direct, hub and store-and-forward providers behind
this interface; its ACK/intake evidence still cannot terminate a leg without
the signed DM-052 receipt event.

Tribe's audited stable IDs, per-recipient rows, leases, ACK separation and crash
retry were independently reimplemented. No Tribe source, schema, writable
database or identifier is imported. Telegram and Buzz remain possible future
edge adapters. Neither is selected or trusted, and Matrix.org remains outside
the MVP.

## Evidence

- `src/daimon_matrix/communication.py`
- `schemas/communication/v1/logical-message.schema.json`
- `schemas/communication/v1/semantic-leg.schema.json`
- `schemas/communication/v1/route-attempt.schema.json`
- `schemas/communication/v1/semantic-receipt.schema.json`
- `conformance/fixtures/dm052-logical-communication.json`
- `tests/test_dm052_communication.py`
