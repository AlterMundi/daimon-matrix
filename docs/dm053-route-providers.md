# DM-053 route providers

Status: implemented, disabled unless an exact per-embodiment profile is
configured. Verification is synthetic loopback; no live Tribe, Buzz, Telegram
or Matrix.org transport is activated.

## Boundary

DM-053 moves immutable `dm.sealed-delivery/v1` bytes after DM-054-compatible
scope/disclosure resolution, DM-051 sealing and DM-052 semantic-leg creation.
It does not resolve an audience, add a recipient, choose a being or embodiment,
sign a Weave event, append the ledger, issue presence, mint a relationship,
adopt content or emit a semantic receipt.

The layers are deliberately distinct:

1. a signed `dm.we.v1` message and resolution authorize the logical action;
2. DM-051 seals that exact event for the exact resolved recipient credentials;
3. DM-052 owns message/thread identity, semantic legs and terminal receipts;
4. DM-053 selects a carrier and records disposable route attempts; and
5. recipient intake reopens the complete DM-051 validation/decryption gate.

A provider result is operational evidence. `hub-accepted` means only that an
opaque store retained the bytes. `recipient-intake` means a configured receiver
validated and durably admitted the envelope. Neither is itself the signed
DM-052 terminal `delivered` receipt.

## Explicit profile and private custody

`dm.route-profile/v1` belongs to one exact body and transport principal. It
contains only opaque adapter, credential, provider and route references,
recipient/body bindings, numeric priorities and an explicit enabled flag. An
absent profile returns `route_profile_absent`; a disabled profile returns
`route_profile_disabled`. No process borrows a host-wide identity or route.

An installed runtime may reference one owner-only `dm.route-custody/v1` file.
That private document maps opaque provider references to Unix socket filenames
or HTTP endpoints and purpose-specific `runtime.route.v1:*` secret slots. The
HMAC key remains in the encrypted DM-021 keystore. The loader rejects unknown
fields, missing or extra slots, origin/profile mismatch, binding mismatch,
unsafe files and unsupported provider kinds before constructing a provider.
Paths, URLs and keys never appear in provider manifests, inspections, results,
receipts or diagnostics.

Every `dm.route-provider-manifest/v1` fixes these flags to false:

- `matrix_authority`;
- `may_append_ledger`;
- `may_issue_presence`;
- `may_mint_membership`; and
- `may_sign_as_me`.

Only exact transport version `v1` and operations `inspect` and `submit` are
accepted. Unknown/downgraded manifests fail before effects.

Those two operations are the common outbound provider plane. Hub queue
`claim`, `ack` and terminal-gated `compact` are a separate owner-local custody
plane because direct providers have no queue to claim. V0 deliberately exposes
no provider `cancel`: route-attempt evidence is immutable, while only canonical
DM-052 receipt/policy state may terminate a semantic leg. Disabling a profile
prevents new effects without rewriting already-observed attempts.

## Selection and fallback

Candidates are filtered to the exact DM-052 leg recipient and ordered by this
stable tuple:

1. class: local, anyVPN direct, other direct, hub;
2. configured non-negative priority;
3. adapter ID; and
4. opaque route reference.

Input array order, wall-clock time, DNS order, discovery timing, display names,
hostnames and process state do not choose a route. The returned inspection and
dispatch evidence retains the policy/profile, ordered attempts and selected
provider without exposing its endpoint.

Typed `unavailable` and response-ambiguous outcomes may continue to the next
candidate. An authenticated `refused` response, malformed/tampered response,
unsupported version or recipient mismatch stops the chain. If every configured
route is unavailable, the leg remains DM-052 `accepted` and dispatch reports
`pending`; it is not silently failed. A resolved recipient with no configured
candidate reports `route_unroutable` to the policy layer, which must author any
terminal `resolved:unroutable` receipt.

Attempt and transport request UUIDs derive deterministically from the semantic
leg, delivery, opaque route and caller-supplied deadline. An ambiguous response
leaves the original attempt accepted. Retrying with that deadline repeats the
exact authenticated request; a later explicit deadline creates a new
operational attempt without changing the semantic leg. The same delivery bytes
may travel through direct and hub attempts for the same leg; changed bytes under
one delivery ID quarantine before network effects.

## Authenticated Unix and HTTP exchange

`dm.transport-request/v1` binds the exact:

- request and attempt UUIDs;
- sender transport principal and body;
- provider and route references;
- message, leg, delivery and recipient identifiers;
- envelope SHA-256 and canonical base64url bytes; and
- issuance/deadline window.

The request and `dm.transport-response/v1` are HMAC-SHA-256 authenticated with
the route credential. Authentication happens before recipient, locality or
queue details are disclosed. Invalid authentication has one rejection shape.
An authenticated recipient policy/validation refusal returns a signed
`refused` result, so fallback cannot bypass it. Response loss after intake is
ambiguous and retryable.

Local IPC uses bounded `uint32_be length || canonical JSON` frames over an
owner-configured Unix socket. Direct and hub providers use bounded HTTP POST
with canonical media type. Payload content cannot nominate a URL or socket.
Transport implementations return only opaque evidence references.

## Recipient intake and hub inbox

A non-hub `TransportIngress` requires an intake validator. The installed
integration supplies the DM-051 `open_event` boundary with current sender
authority, exact recipient set, disclosure authorization and recipient private
operation. Only after that succeeds does the provider-owned SQLite inbox admit
the opaque envelope.

The inbox uses owner-only storage, SQLite `DELETE` journal mode and
`synchronous=FULL`. It assigns monotonic integer sequences independent of
timestamps. Delivery IDs and authenticated request IDs have exact replay:
identical bytes are idempotent; changed bytes conflict. Claims are bounded,
leased, stable under exact claim-ID replay and disjoint under concurrent
writers. ACK requires the exact recipient, consumer, delivery and digest.
Compaction removes only an ACKed prefix after an injected validator confirms
canonical terminal evidence for every exact recipient/delivery/digest tuple.
A missing or rejecting terminal proof leaves the transaction unchanged.
Compaction never touches the Matrix ledger, message, leg or receipt.

A hub uses the same opaque inbox but returns no recipient-intake object. A
recipient later claims the bytes and submits them through its own validating
ingress. Consequently direct/hub duplicate arrival yields one recipient inbox
item and one DM-052 semantic leg, without an exactly-once-network claim.

When presence/deployment control is configured, intake requires an injected
validator for the exact presence reference and resource-fence reference before
the recipient validator or durable write. One reference, or both references
without that validator, is invalid. UID, PID, socket ownership, container name
and reachability remain transport checks, never identity evidence. Local IPC
also rechecks an owner-only socket inode and owner UID peer immediately before
sending, but those OS facts do not replace the injected authority validation.

## Localhost rule

A transport principal ending in `@localhost` is permitted only when the whole
resolved message audience is non-empty and every recipient is explicitly
listed local to the same profile body. Any remote or mixed recipient, direct or
hub binding, hostname/alias confusion or empty audience fails before provider
inspection, DNS, socket connection, key wrapping or gateway effect. This rule
does not prove `/me`, `/we`, membership or presence.

## Deferred human gateway

`dm.gateway-policy/v1` is a generic edge contract, disabled by default and not
part of automatic fallback. Constructing an enabled policy requires an injected
authority validator; deployment integration must use it to verify the canonical
signed local policy before any rendering or gateway effect. The resolved policy
then requires exact gateway, destination, operation, classification and
source-scope allowlists. Rendering HTML-escapes untrusted text, adds
source/message attribution and chunks by UTF-8 byte count deterministically.

Inbound `dm.gateway-proposal/v1` is explicitly `external-source-only`. It has
no Daimon origin or signature and cannot become a direct reply, relationship,
receipt or memory admission without later canonical policy. Buzz and Telegram
are merely possible future implementations of this edge. Neither is selected,
linked, called or trusted by DM-053.

## Verification and deployment

The checked-in tests exercise real owner-only SQLite, Unix sockets and
loopback HTTP plus fake-clock faults for deterministic ordering, unavailable
fallback, authenticated refusal, response loss, cross-route duplicates,
delivery/request conflicts, more than 100 equal-time inbox items, lease replay,
compaction, locality, closed schemas, runtime secret custody and gateway
rendering. The installed-wheel conformance registry binds four DM-053 scenarios
and repeats the complete deterministic report.

All providers ship disabled. A live rollout requires explicit endpoint and
secret provisioning, current recipient validation inputs, deployment-specific
presence/fence evidence and a separate reversible canary. DM-054 must first
expose current `/me`, `/we`, `/we.sync` and `/tribe` resolution. Rollback
disables the profile and retains Matrix events, semantic legs, receipts and
high-water evidence; it never restores Tribe v0 or selects another gateway.
