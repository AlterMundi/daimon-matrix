# DM-023 transport contract for Tribe integration

Status: implemented by the DM-024 local boundary and required input to
DM-050–DM-055.

DM-023 is deliberately transport-neutral. Tribe Bridge or its absorbed Matrix
implementation carries exact canonical documents and authenticates/encrypts
the route; it never opens or reconstructs their semantic fields.

## Typed payloads

| Matrix document | Suggested media type | Route |
|---|---|---|
| `dm.we.sync-request/v1` | `application/vnd.daimon.we.sync-request+json;v=1` | requester embodiment → one peer embodiment |
| `dm.we.delta/v1` | `application/vnd.daimon.we.delta+json;v=1` | peer embodiment → exact requester |
| `dm.we.sync-receipt/v1` | `application/vnd.daimon.we.sync-receipt+json;v=1` | receiver embodiment → exact page sender |

`dm.we.heads/v1` is also available for status/discovery, but a sync request
already carries the requester's exact heads. All payload bytes are canonical
UTF-8 JSON. Content encoding, chunking or compression requires a future exact
version and cannot silently change V1 bytes.

The sync engine requires active root-bound DM-021 authority. It may carry
provisional events only when an activated history binding admits their exact
closure; a provisional administrator manifest cannot open a V1 sync session.

## Authentication binding

The transport supplies an authenticated `(scheme, principal_id)` and intended
recipient. DM-024/DM-050 MUST verify all of the following before calling
`SyncEngine`:

1. the scheme is the exact negotiated adapter version (`tribe-v1` initially);
2. the authenticated transport sender equals the document's `requester` for a
   request, `sender` for a delta, and `receiver` for a receipt (the receipt
   receiver is the embodiment that authored the ingest result);
3. that principal is bound by the named embodiment's DM-021 credential;
4. the direct recipient equals `requester` for a delta and `sender` for a
   receipt; a request's intended responder is authenticated route metadata and
   must name another active same-being embodiment because the request document
   intentionally does not grant or encode routing authority;
5. the being, manifest and active incarnation match the hosted ledger.

A transport directory, display alias, audience, contact, route, successful
decryption or possession of a Tribe key cannot add a Matrix origin or prove
same-being membership.

## Delivery and replay

Tribe outbox/message IDs are transport identifiers. Matrix `request_id`,
`request_hash`, `page_hash`, and `receipt_hash` are application identifiers.
They MUST remain separate and be logged only in their own bounded diagnostic
fields.

The transport may deliver duplicates and out of order. It forwards every
successfully authenticated complete document to Matrix; Matrix returns the
original cached result for an identical retry and records a reused ID with
different bytes as durable conflict; an inbound page conflict also quarantines
that peer lane. Tribe must not deduplicate only by request UUID and discard a
conflicting body before Matrix can preserve evidence.

A Tribe delivery ACK proves only that encrypted transport state was durably
accepted. A `dm.we.sync-receipt/v1` proves that Matrix atomically validated the
page, inserted/replayed its events, advanced receiver-owned cursors and stored
the exact response. Neither receipt means local adoption or external effect.

## Cursor separation

- Tribe cursors answer which encrypted messages were delivered/acked.
- Matrix peer cursors answer which signed origin positions this ledger has
  validated from a fully attributed peer.
- Projection state answers which known events this embodiment locally chose.

No cursor may be copied into another layer as authority. On recovery, replay
transport messages until Matrix returns its cached receipt, then advance the
transport cursor.

DM-024 exposes these operations over its owner-only authenticated socket. The
Tribe adapter holds a purpose-limited local capability; it never opens the
ledger or keystore. A future Buzz or Telegram adapter may use the same boundary,
but must define a distinct versioned `scheme` and prove an authenticated remote
principal. Matrix.org is not part of this design.

## Encryption and disclosure

DM-051 supplies recipient encryption. Sync pages may contain `personal`,
`private` or `shareable` events; route policy must filter authorization before
delivery, never by letting Tribe parse payload meaning. Secret values are
forbidden in Weave regardless of encryption. Error responses expose stable
classes and identifiers, never event payloads, key material, database paths or
membership oracles.
