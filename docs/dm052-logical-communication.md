# DM-052 logical communication

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
duplicates fail closed.

## Same-ledger projections

`CommunicationStore` adds tables to the existing DM-023 SQLite ledger. It is
not a second writable ledger and it cannot accept an event absent from the
canonical `events` table. The logical tables retain:

1. the message projection and exact signed resolution reference;
2. one content-derived semantic leg for `(message_id, recipient_type,
   recipient_id)`;
3. any number of disposable route attempts and DM-051 delivery IDs; and
4. one terminal receipt projection whose authority remains its signed
   `dm.we.v1` receipt event.

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
an explicit provider ACK changes route-attempt state. DM-053 will implement
local, direct, hub and store-and-forward providers behind this interface.

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

