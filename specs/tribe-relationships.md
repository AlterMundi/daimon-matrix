# Bilateral relationships, founded Tribes, and directional grants

Status: normative V1 specification for DM-016 and DM-082.

This document defines the social and resource-authority layer produced by
Daimon Matrix. “Matrix” in this document means the Daimon Matrix component;
Matrix.org is outside V0.

The key words MUST, MUST NOT, REQUIRED, SHOULD, SHOULD NOT, and MAY are to be
interpreted as normative requirements.

## 1. Ontology and authority boundaries

A relationship is explicit bilateral consent between two distinct beings. A
founded Tribe is an explicit collective whose members accepted invitations
from its current founder. A grant is directional authority over exact
resources and operations. These are three independent facts.

The following never create a relationship, membership, or grant:

- `/me`, `/we`, co-embodiment, body or incarnation membership;
- a contact, directory row, route, endpoint, hostname, account, transport ACK,
  successful decryption, message receipt, or shared room;
- a Cluster lease, fence, observed effect, resource listing, process state, or
  deployment;
- a source claim, imported publication, local adoption decision, model output,
  adapter assertion, test harness, or cached projection; or
- a legacy Tribe Bridge audience or group.

Relationships, memberships, grantors, subjects, founders, and invitees are
root-derived `dm:being:v1:*` references. They are never body IDs, embodiment
IDs, transport principals, GitHub identities, usernames, or legal identities.
An embodiment signs on behalf of its being only while its operational
credential and incarnation are root-authorized for the event time.

Daimon Matrix owns signed social history and its deterministic reduction.
Daimon Cluster owns bodies, resources, fences, observed effects, and lifecycle
execution. Cluster may provide a resource descriptor or observed state, but it
MUST NOT decide social consent. Matrix may authorize an exact Cluster
operation, but it MUST NOT report the operation achieved until Cluster returns
effect-truth evidence.

## 2. Canonical event boundary

Every transition is a canonical `dm.we.v1` event signed with an authorized
Ed25519 operational key. Payloads conform to
`schemas/relationships/v1/contracts.schema.json`, reject unknown fields, and
are JCS-canonical before hashing and signing.

The signed event `occurred_at_ms` MUST equal the action timestamp carried in
the payload. Signed time orders claims made by an author; it is not portable
proof of first observation by another being. Receivers retain their own
evidence cursor.

Cross-being references use the closed pair:

```text
{ event_id, event_hash }
```

The hash is the exact `content_hash` of the referenced event. A foreign event
ID is not inserted into another being’s one-writer causal-parent namespace.
The multi-being relationship reducer validates the exact pair instead.

V1 event kinds are:

| Kind | Author |
| --- | --- |
| `matrix/relationship-card` | card being |
| `matrix/relationship-offer` | initiator being |
| `matrix/relationship-acceptance` | responder being |
| `matrix/relationship-close` | either participant |
| `matrix/tribe-declaration` | founding being |
| `matrix/tribe-invitation` | current founder |
| `matrix/tribe-membership-acceptance` | invitee |
| `matrix/tribe-membership-leave` | member |
| `matrix/tribe-membership-expulsion` | current founder |
| `matrix/tribe-founder-transfer` | current founder |
| `matrix/tribe-founder-acceptance` | named successor |
| `matrix/relationship-grant` | grantor |
| `matrix/relationship-grant-acceptance` | subject |
| `matrix/relationship-grant-revocation` | grantor for revoke; subject for relinquish |

Exact event-byte replay is idempotent. The same identifier or origin position
with different signed bytes is retained as equivocation evidence and grants no
authority.

## 3. Relationship cards

A relationship card is a self-authored, public, bounded-lifetime statement. It
contains:

- a being-derived card-series ID, monotonic sequence, and predecessor event;
- the exact current manifest, embodiment, and incarnation position;
- the current recipient-encryption public key;
- opaque route and capability references; and
- zero or more exact public resource descriptors.

Sequence starts at zero. Every later card names the immediately preceding card
event. Gaps, predecessor mismatch, duplicate positions, or forks quarantine
the series. Arrival order, hash order, route quality, or recency never chooses
a winner.

The receiver MUST independently verify that the card’s control position is
current at the evaluation time, the embodiment credential has `messages`
purpose, and the encryption key equals the credential. A private key,
credential secret, endpoint credential, or bearer token MUST NOT appear in a
card.

Card expiry removes current relationship and disclosure authority. It does not
erase the fact that a historical handshake or Tribe admission occurred.

## 4. Bilateral relationship protocol

The initiator creates a fresh 32-byte nonce and derives:

```text
relationship_id = "dm:relationship:v1:" || base64url(SHA-256(
  "daimon/relationship/id/v1" || 0x00 || JCS({
    nonce,
    initiator_being_ref,
    responder_being_ref
  })
))
```

The beings MUST be distinct. The offer binds the exact initiator card, an
optional already-known responder card, roles, terms, proposed grant ceilings,
issuance time, and acceptance deadline. Proposed grants are limits, not active
authority.

The responder accepts by signing the exact offer reference, both participant
references, and both exact cards. Acceptance is valid only within the offer’s
half-open interval and only when all copied fields match. Before acceptance,
the relationship is `offered` and conveys no membership, disclosure, delivery,
or resource authority.

After acceptance the historical relationship is bilateral. It is currently
`active` only while both cited card series have current verified heads. Either
participant may close it by referencing the exact offer and acceptance.
Closure is terminal for that relationship ID. Re-pairing requires a fresh
nonce, offer, acceptance, and grants.

## 5. Founded Tribe protocol

A declaration core contains a creation time, founder being, fresh nonce, and
policy reference. `tribe_ref` is the domain-separated SHA-256 of that closed
core. The declaration gives the founder active membership at epoch zero.

The current founder may invite a distinct being with a fresh invitation nonce,
exact `tribe_ref`, founder epoch, invitee, and bounded acceptance interval. A
valid invitation requires a bilateral relationship between founder and
invitee at issuance. The invitation itself is not membership.

The invitee becomes active only by independently signing the exact invitation
reference before expiry. The acceptance occupies the next position in the
per-`(tribe_ref, invitee_being_ref)` membership series. Position zero has no
predecessor. Every later acceptance references the exact terminal event of the
previous episode. A gap, wrong predecessor, two acceptances at one position,
or more than one terminal event for an episode quarantines that member's lane
without selecting a winner. Re-entry therefore requires a fresh invitation
and the exact prior terminal; a second acceptance while active is invalid.

A later card expiry or relationship closure does not rewrite that historical
membership. Membership ends only through:

- a member-authored leave referencing its exact membership acceptance; or
- a current-founder expulsion referencing that acceptance and founder epoch.

Membership grants no resource access. Leaving or expulsion does not delete
events and makes Tribe-scoped grants involving that member ineffective.

Founder succession is a two-party epoch transition. The old founder signs a
transfer from epoch `N` to `N+1`, naming one active successor. The successor
signs the exact transfer. Until both events exist, the founder and epoch remain
unchanged. Competing transfers at one epoch quarantine succession without a
winner. If founder authority is lost before an accepted transfer, remaining
members MUST found a new Tribe; no adapter reconstructs the old authority.

## 6. Resources and directional grants

A resource descriptor is content-addressed from a fresh nonce, controller
being, kind, classification, allowed operation names, and opaque descriptor
reference. IDs and operation names are byte-exact. V1 has no glob, prefix,
case-folding, alias, implied CRUD, or path-similarity expansion.

A root grant binds:

- one active bilateral relationship whose participants are exactly grantor
  and subject;
- an optional founded Tribe;
- exact permissions, classifications, interval, and issue time;
- a proposed-grant ceiling from the accepted relationship offer; and
- the grantor’s card resource descriptors, whose controller is the grantor.

The grant is only `offered` until the subject signs an exact acceptance during
the grant interval. Silence, transport delivery, decryption, membership, or a
local capability is not acceptance.

An active grant permission is an exact tuple of resource, operations,
classification, delegability, and remaining depth. Empty permissions are valid
and convey zero access. A nondelegable permission has depth zero; a delegable
permission has depth one through sixteen.

## 7. Delegation and attenuation

A child grant has exactly one parent. The parent subject MUST equal the child
grantor. The child’s own relationship MUST be bilateral between its grantor and
subject. Every child permission MUST be present in the parent and may only:

- omit operations or permissions;
- keep the same resource and classification;
- shorten the interval;
- change delegable to false; or
- reduce remaining delegation depth by at least one.

It MUST NOT widen and rely on receiver policy to narrow the result.

Child issuance occupies a sequence in the identity-wide lane under the exact
parent grant event. Sequence zero has no predecessor. Sequence `N+1` names the
exact child grant event at `N`, which must have a valid subject acceptance. A
gap, wrong predecessor, or two distinct child grants at one position
quarantines that position, every later position in the lane, and descendants
whose ancestry passes through it. V1 has no hash-lottery merge for authority
lanes.

The grantor may revoke its own grant. The subject may relinquish it. Terminal
evidence references the exact grant and acceptance. Expiry, relationship
closure or staleness, Tribe membership loss, revocation, relinquishment,
parent invalidity, parent fork, or any ancestor terminal state makes every
descendant ineffective. History remains immutable; reauthorization uses a
fresh grant nonce and acceptance.

Concurrent valid revocation and relinquishment are both retained and reduce to
`revoked+relinquished`; neither event wins and the grant remains terminal.

## 8. Deterministic observer-local reduction

Each observer retains verified variants keyed by `(event_id, content_hash)` and
tracks origin `(being_ref, incarnation_id, sequence)` positions. A different
content hash at one origin position quarantines that position and every later
event from that origin. References to quarantined or absent events remain
incomplete transitively.

A view at time `T` MUST ignore events whose signed occurrence time is later
than `T`. Future evidence cannot change a historical query. Reduction order is
deterministic and independent of database insertion order.

Intrinsic validity and current effectiveness are separate:

- a historical bilateral acceptance remains evidence after cards expire;
- membership persists after its admission relationship becomes stale;
- current relationship, snapshot, grant, and disclosure authority require
  current verified cards and current complete ancestry; and
- no observer claims global non-revocation during a partition. A cursor states
  only which signed evidence that observer retained.

The owner-local SQLite store uses DELETE journal mode, synchronous FULL,
owner-only directories/files, no symlinks, exact canonical bytes, and durable
request replay. Changed bytes under one request ID conflict.

## 9. Snapshot and `/tribe` consumption

The reducer may emit `dm.tribe-snapshot/v1` only from an active unforked Tribe
history with current verified member cards. The snapshot binds declaration,
founder epoch, founder being, lineage head, active/left/expelled memberships,
and currently active Tribe-scoped grants.

DM-054 consumes this verified snapshot. It does not sign invitations, invent
members, widen grants, or treat `/we` as a Tribe. New snapshots use being refs
as principals. Legacy externally verified snapshots may still contain the
previous transport-principal representation during migration; this does not
change the V1 producer contract.

`/tribe` resolution requires the local being to be an active member. It returns
active members and only current grants addressed to that being. A membership
row never becomes a relationship delivery target or resource permission by
itself.

## 10. Disclosure and oracle resistance

Remote resource/status disclosure requires an active accepted grant matching
the requester being, resource, operation, and classification. Success returns
only the bounded authorization evidence needed by the next layer.

Every unauthorized, unknown, expired, revoked, forked, incomplete,
wrong-resource, wrong-operation, wrong-classification, or wrong-requester query
returns the same closed denial:

```json
{
  "schema": "dm.relationship.disclosure/v1",
  "authorized": false,
  "authorization": null
}
```

The denial contains no reason, participant, route, policy, card, Tribe,
membership, grant, or existence signal. Callers MUST NOT add a more specific
fallback error. Deployments SHOULD apply uniform size, timing, and rate limits
at the authenticated carrier boundary.

## 11. Hosted API and bundle V6

Hosted runtime bundle V6 adds an owner-local relationship-store filename and a
sorted list of known being refs. Public root/control/credential material for
those refs is reused from the bundle’s known-authority inventory. Reuse is
verification plumbing only: source records do not become relationship
authority.

Authenticated daemon, CLI, and MCP surfaces expose explicit methods for card,
offer, acceptance, closure, declaration, invitation, membership terminal,
founder transfer, grant, grant acceptance, revoke, relinquish, foreign event
ingest, cursor, status, snapshot, and disclosure. Adapters cannot fabricate a
foreign signature. Local mutation writes the one-being ledger first and then
idempotently indexes the signed event in the relationship store; retry repairs
a lost response without duplicating authority.

## 12. Matrix, Cluster, and carrier integration

Matrix produces authorization intent and social evidence. Cluster maps an
exact resource reference to a concrete resource, validates a resource-scoped
fence, executes a convergent operation, and returns observed postcondition
evidence. A successful Matrix grant is not an achieved Cluster effect. A
Cluster receipt is not consent.

Tribe Bridge or another carrier may exchange signed events and encrypted
messages. Import verifies and retains bytes; it is not adoption. Route ACK
means carrier acceptance only. Semantic delivery requires authenticated
recipient intake under DM-052/DM-053. Buzz, Telegram, Matrix.org, or any future
carrier can replace transport without changing this authority protocol.

The V1 synthetic proof binds one successful relationship disclosure decision
and one selected DM-054 membership target to a signed DM-052 relationship leg.
DM-051 seals the canonical message to the target's exact active credential and
DM-053 moves it through an authenticated direct loopback. The recipient repeats
the current relationship disclosure check before private opening and durable
intake. Carrier ACK leaves the semantic leg accepted; only the recipient's
independently signed receipt changes it to `delivered`.

DM-053 route bindings retain the stable relationship recipient ID while intake
also checks the signed leg's exact receipt-origin embodiment against the sealed
recipient set. This mapping adds no membership authority. After ancestor
revocation, direct replay and hub forwarding of the still-unexpired ciphertext
are refused before another private open. The installed proof claims no external
endpoint or cross-host availability; DM-071 owns that separately authorized
canary.

The companion Cluster adaptation is specified in
`docs/integration/daimon-cluster-relationship-adapter.md`.

## 13. V1 bounds

- 256 known beings per hosted inventory;
- 64 routes, capabilities, resources, roles, proposals, or permissions per
  containing object;
- 256 founded-Tribe members and 1024 snapshot grants;
- 16 maximum delegation depth;
- 30 days maximum card lifetime;
- 7 days maximum relationship-offer or Tribe-invitation acceptance interval;
- 365 days maximum grant interval;
- 256 KiB maximum signed Weave event; and
- safe integers from zero through `2^53-1`.

Every bound has exact-bound and plus-one tests where the implementation owns
the bound. Capacity failure occurs before durable effect.

## 14. V0 exclusions and successors

V1 deliberately excludes Matrix.org federation, legal identity, human-contact
signature schemes, automatic contact import, newborn grant commitments,
global discovery, automatic live-route enablement, and authority-lane merge.
Those require explicit successor protocols and cannot be approximated by
adapters.

The deterministic synthetic journey uses only isolated roots, inert resources,
and an ephemeral loopback HTTP carrier. Operational relationship creation,
external carrier exchange, and host deployment require separate explicit
authorization.
