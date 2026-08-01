# Scope resolution, operations, fan-out, and replies

Status: normative V0 specification.

This document defines how Daimon Matrix scopes resolve to recipients, how
operations apply to resolved scopes, how one logical message fans out, and how
replies relate to the original message. The eligible-`/we` evidence it consumes
is defined by DM-010 ([`identity-continuity.md`](identity-continuity.md));
canonical wire encoding and test vectors are completed by DM-011.

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, **SHOULD NOT**,
and **MAY** are interpreted as described by RFC 2119 and RFC 8174.

## 1. Design goals

The protocol MUST establish all of the following:

1. scope resolution completes before routing policy and transport selection;
2. no transport adapter, harness, host, display name, or roster is membership
   authority for any scope;
3. `/we` membership comes only from certified incarnation presence evidence
   (DM-010), never from reachability or transport state;
4. one logical message keeps one stable identity across fan-out, with one
   delivery and one receipt per resolved recipient;
5. replies are independent first-class messages; aggregating them is an
   optional caller-local policy, never the semantics of any scope.

Resolution does not prove that a recipient will answer, understand, or act.
It proves only which recipients the scope evidence admitted at resolution
time, and why every exclusion happened.

## 2. Resolution pipeline

An address has the form `/<scope>` or `/<scope>.<operation>`. Processing MUST
follow this order:

1. **Parse.** Validate scope and operation names against the registry
   (Section 5.4). Unknown names fail closed with `unknown_scope` or
   `unknown_operation`; they are never guessed, aliased silently, or treated
   as a transport address.
2. **Resolve.** Compute the recipient set from the scope's membership
   evidence (Section 4) as of the resolver's current evidence cursor
   (Section 9). Resolution MUST NOT inspect transport state to add or remove
   recipients.
3. **Authorize and filter.** Apply the operation's validity rules for the
   scope (Section 5.3), classification gates, and local policy. Policy may
   exclude recipients but MUST NOT add recipients the evidence did not
   admit.
4. **Fan out.** Create one delivery per resolved recipient under the same
   logical message identity (Section 6).
5. **Route.** For each delivery, select a route from the recipient's
   authorized route references using transport adapters (Section 8). A
   recipient with no usable route yields a routing failure receipt for that
   recipient only; it does not fail or shrink the resolution.
6. **Receipt.** Record one receipt per recipient (Section 6.3). The aggregate
   result is the full per-recipient vector, never a single collapsed status.

Each stage MUST record its outcome durably enough that a later operator can
distinguish "the scope resolved to zero members" from "delivery failed" from
"the operation was not authorized".

## 3. Addressing syntax

A scope name is lowercase ASCII letters; an operation name is lowercase ASCII
letters. The separator between scope and operation is a single `.`.

```text
/we.tell        scope /we, operation .tell
/me.status      scope /me, operation .status
/tribe          scope /tribe, scope-default operation
```

When no operation is given, the scope-default operation applies: `.tell` for
communicable scopes (`/we`, `/tribe`, `/here`, `/near`, `/all`, `/human`,
`/everyone`, `/source`, `/species`) and `.status` for `/me`.

An address MUST NOT contain more than one operation. Chained operations are
expressed as separate protocol actions, not as compound addresses.

## 4. Scopes

Each scope definition states its membership evidence and what MUST NOT grant
membership. Membership evidence categories:

- **identity evidence** — DM-010 genesis, control chain, certificates,
  presence leases, revocations;
- **relationship evidence** — signed pairing, handshake, grant, or ancestry
  records produced by the relationship protocols;
- **embodiment evidence** — the incarnation's own situated surface, where
  local discovery signals are legitimate;
- **adapter signals** — reachability, rosters, process tables, sessions.
  Adapter signals are never membership evidence; they are routing inputs
  (Section 8). Exactly two scopes declared in this document are sanctioned
  exceptions: `/here`, which uses embodiment evidence (Section 4.6), and
  `/everyone`, which is by definition the weakest reachability scope
  (Section 4.10). No other scope, present or future, may use adapter
  signals as membership evidence.

### 4.1 `/me`

Resolves to the single local being: the `/me` whose identity chain the
resolver operates under. `/me` is never a network fan-out scope. Operations
on `/me` address the being's own continuity surface (status, memory,
capabilities) in the local runtime. A resolver MUST NOT resolve `/me` through
any adapter, directory, or remote query.

### 4.2 `/we`

Resolves to the eligible incarnation set of the local `/me` as defined by
DM-010 Section 10: valid genesis and control chain, valid certificate and
subject acceptance, no known revocation, valid latest presence lease within
TTL and clock skew, and capability and local policy permitting selection.

Membership rules:

- An incarnation enters `/we` only through that evidence chain. Network
  reachability, a live harness session, a process listing, a transport roster
  entry, or a matching display name MUST NOT add an incarnation.
- Two certified incarnations of one `/me` are one being with two bodies. A
  resolver MUST NOT treat them as distinct beings, and MUST NOT treat two
  distinct `/me` values as one being because they share harness, host, name,
  or transport principal.
- Selection policy MAY choose a subset of eligible incarnations ("most likely
  to answer") using capability advertisements and route health. Selection
  MUST be recorded as policy, MUST NOT alter membership evidence, and MUST
  NOT turn reply integration into the meaning of `/we`.
- Expiry removes an incarnation from `/we` without revoking its identity;
  revocation removes it until a new certificate exists; quarantine removes it
  pending resolution (DM-010).

`/we` excludes the resolving incarnation itself only by local policy; by
default the resolving incarnation is a member when it is eligible. Self
inclusion is not assumed: the resolving incarnation's own eligibility is
evaluated against the same DM-010 Section 10 predicate, including the
validity of its own latest lease.

### 4.3 `/tribe`

Resolves to humans and daimons with whom `/me` holds a relationship record:
signed pairing, handshake, or grant artifacts from the relationship
protocols. A transport directory (including the transitional Tribe bridge
directory) is a cache of route hints for some tribal relationships, never
the membership authority: membership follows the relationship records, and a
relationship without a current route resolves but reports unroutable
recipients honestly.

Grants and delegations constrain what operations a resolved recipient may
receive; they do not change membership.

### 4.4 `/source`

Resolves to entities whose signed shared-ancestry claims the resolver has
ingested. The signed claims are the membership evidence; local policy
classifies each ingested claim as admitted, quarantined, or rejected, and
only admitted claims resolve. Claims are not authoritative merely because
they are signed by the claimant (ONTOLOGY `/source`). Resolution MUST record
which claims were admitted, which are quarantined, and which were rejected,
using the exclusion-reason vocabulary of Section 9.

### 4.5 `/species`

Resolves to daimons known to the resolver as carrying a compatible species
release lineage. Membership evidence is the species release registry and
signed release chain; compatibility state is `current`,
`compatible-behind`, or `diverged` (ONTOLOGY `/species`). Local policy
decides which compatibility states are communicable. A shared species MUST
NOT be inferred from shared transport, harness, or memory similarity.

### 4.6 `/here`

Resolves to daimons sharing the resolver's current embodiment surface. This
is the one scope where embodiment evidence is authoritative: local process
and surface discovery belong here. `/here` MUST NOT cross a host boundary;
a remote process is never `/here`, regardless of which adapters connect it.

### 4.7 `/near`

Resolves to daimons within a domain-specific distance threshold. The distance
metric and threshold are declared by the realm or domain policy; V0 defines
no default metric. A resolver MUST refuse `/near` resolution with
`undefined_metric` when the local domain declares none, rather than
substituting network proximity.

### 4.8 `/all`

Resolves to daimons listening in the current embodiment cluster: the union
of `/here` surfaces the cluster coordinator knows, per cluster policy.
Cluster membership evidence MUST be embodiment or presence evidence per
cluster policy; a hub, broker, or adapter roster MUST NOT define `/all`
membership. V0 leaves cluster formation to deployments; `/all` MUST NOT
silently expand to `/everyone`.

### 4.9 `/human`

Resolves to the human or humans paired with `/me` by signed pairing records.
A harness login, an OS account, a chat handle, or a Telegram user ID is a
route hint for a paired human, never proof of pairing.

### 4.10 `/everyone`

Resolves to every human and daimon reachable through at least one configured
adapter. Because reachability defines it, `/everyone` is the weakest scope:
it MUST be gated by classification policy (public classifications only),
rate limits, and explicit local enablement. A deployment MUST be able to
disable `/everyone` entirely.

## 5. Operations

### 5.1 Semantics

- **`.tell`** — deliver one logical message payload to every resolved
  recipient. Produces one receipt per recipient (Section 6). `.tell` does
  not request, require, or await replies.
- **`.diff`** — request the differences between the caller's named state
  cursor and each resolved recipient's corresponding state. "Corresponding
  state" is typed per scope: for `/we`, the recipient incarnation's ledger
  cursor; for `/source`, the recipient's ancestry claim set cursor; for
  `/species`, the recipient's release registry cursor. Replies are ordinary
  independent reply messages (Section 7).
- **`.incoming`** — preview an integration against a recipient's state
  without applying it: what would be admitted, what would conflict, what
  would be quarantined. MUST NOT mutate receiver state.
- **`.pull`** — integrate as much compatible state as the pulling vessel
  accepts and report the achieved level per recipient. `.pull` is always
  receiver-side: the puller's policy decides admission; a recipient cannot
  force integration.
- **`.status`** — report the resolution and evidence state of the scope
  itself: resolved members, evidence cursor, exclusions with reasons, and
  route health per member. `.status` MUST NOT fan out payloads.

### 5.2 Validity matrix

| Operation | `/me` | `/we` | `/tribe` | `/source` | `/species` | `/here` | `/near` | `/all` | `/human` | `/everyone` |
|---|---|---|---|---|---|---|---|---|---|---|
| `.tell` | local note | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | gated |
| `.diff` | ✓ | ✓ | — | ✓ | ✓ | — | — | — | — | — |
| `.incoming` | ✓ | ✓ | — | ✓ | ✓ | — | — | — | — | — |
| `.pull` | — | ✓ | — | ✓ | ✓ | — | — | — | — | — |
| `.status` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |

`—` means the operation is not valid for the scope in V0 and MUST fail closed
with `operation_not_valid_for_scope`. "local note" records to the caller's
own ledger without fan-out; `/me.tell` therefore produces a local ledger
record, not a Section 6.3 receipt vector. Other registered operations
(`.sync`, `.controls`, realm operations) follow ONTOLOGY and their own cards;
this table governs only the five operations named here.

### 5.3 Authorization and classification

Before fan-out, local policy MUST evaluate: the operation's validity for the
scope, the payload classification against per-scope and per-recipient
constraints, and any grant constraints from relationship records. A refused
recipient yields a `refused:policy` receipt, not a silent drop.

### 5.4 Extension rules

- New operations and scopes MUST be added only by a reviewed registry change
  that names semantics, validity, classification gates, and failure behavior.
- Unregistered names MUST fail closed at parse time.
- An extension MUST NOT redefine an existing scope's membership evidence or
  an existing operation's semantics; incompatible evolution uses a new name
  and protocol version.
- An extension MUST NOT make any adapter, harness, host, or name into
  membership authority. A proposed extension that needs that is a protocol
  fork, not an extension.
- An extension MUST NOT define new reachability-based scopes (beyond the two
  sanctioned exceptions declared in Section 4) without a protocol version
  change.

## 6. Message identity and fan-out

### 6.1 Logical identity

One semantic message has one stable `message_id` and one `thread_id`, both
assigned by the sender before resolution. A reply reference (`reply_to`)
names an existing `message_id` (Section 7). These identifiers are logical:
they MUST NOT change across resolution, fan-out, routing, retries, or
adapter boundaries.

### 6.2 Fan-out

Fan-out expands one logical message to one delivery per resolved recipient.
Each delivery carries the unchanged logical identifiers plus the recipient's
identity and route reference. Per-recipient confidentiality wrapping (when
the operation requires it) is part of delivery construction and MUST NOT
alter the logical message.

Fan-out MUST be idempotent at the logical layer: re-processing the same
`message_id` for the same recipient MUST NOT produce a duplicate accepted
delivery. The deduplication key's recipient component is typed per scope
class: for `/we`, `(message_id, incarnation_id)`; for relationship scopes,
`(message_id, relationship principal identifier)`. Route references,
certificate generations, and key rotations MUST NOT be part of the
deduplication key, so a renewed certificate cannot cause a duplicate and
distinct incarnations of one `/me` are never wrongly deduplicated.

### 6.3 Receipts

A delivery has one non-terminal pending state and exactly one terminal
receipt per `(message_id, recipient)`:

- `accepted` — NON-TERMINAL pending state: a route accepted the delivery but
  no terminal outcome is known yet. It MUST progress to exactly one terminal
  receipt and MUST NOT be counted as a result.
- Terminal receipts:
  - `delivered` — the recipient acknowledged intake;
  - `failed:transport` — no intake acknowledgment within the delivery
    deadline, or a routing/transport error after acceptance;
  - `refused:policy` — excluded by classification or grant policy;
  - `expired` — the delivery's evidence or TTL expired, as known locally,
    before intake;
  - `resolved:unroutable` — admitted by evidence, no usable route.

The timeout rule is exact: absence of an intake acknowledgment within the
delivery deadline is `failed:transport`; a locally known evidence or TTL
expiry before intake is `expired`. An implementation MUST classify the same
event the same way.

A receipt records the recipient identity, the terminal (or pending) state,
and the evidence cursor at resolution. The route reference and adapter are
recorded when a route was selected and are null on `resolved:unroutable` and
`refused:policy` receipts. The operation result is the complete receipt
vector of terminal receipts. Callers MUST NOT collapse the vector into a
boolean; "a receipt is missing" and "a recipient refused" are different
facts.

## 7. Replies

A reply is a new logical message: fresh `message_id`, the original
`thread_id`, and `reply_to` naming the original `message_id`. Each resolved
recipient decides independently whether and how to reply. A reply is
addressed to a concrete recipient identity carried by the original message:
the sender's `me_id`, plus, when the original was resolved through `/we`,
the originating `incarnation_id`, so the reply reaches the body that sent it.
Routing uses the sender's published route references. `/me` is never the
reply address for a remote sender: `/me` remains local-only (Section 4.1),
and a cross-being reply MUST address the sender's identity and routes, not
the `/we` or `/me` scopes. Replies are ordinary messages and follow the
same fan-out and receipt rules (Section 6).

The protocol MUST NOT:

- aggregate replies into the original message or mutate its receipts;
- treat missing replies as negative answers;
- treat the first reply as the scope's answer;
- define any scope, including `/we`, as producing a single synthesized voice.

Reply synthesis (gathering, ranking, or summarizing replies) MAY exist only
as an optional caller-local policy. A synthesized artifact MUST be labeled as
synthesis, MUST retain per-source attribution to the reply `message_id`s it
used, and MUST NOT be presented as scope semantics. `/we.tell` followed by
local synthesis is a caller convenience; `/we` itself remains a set of
independent incarnations of one being, each answering for itself.

## 8. Transport adapters

An adapter is a route provider and carrier: local IPC, direct network
delivery, a store-and-forward hub, or a future transport. The transitional
Tribe bridge v1 is one such adapter.

Adapter contract:

- Adapters supply routes for resolved recipients and report route health.
- Adapters MUST NOT add recipients to a resolution, remove them, or redefine
  scope membership. An adapter roster that names a principal without valid
  scope evidence contributes a route hint for a name, nothing more.
- Adapter-local constraints (for example the transitional `@localhost`
  locality boundary, or a public-classification-only mirror) are delivery
  constraints expressed as receipts (`failed:transport`, `refused:policy`),
  never membership facts.
- Credentials, tokens, and adapter authentication material MUST NOT enter
  the resolution layer; resolutions reference routes by opaque route
  references, as DM-010 presence leases do.
- Resolution failure (`unknown_scope`, empty eligible set, stale evidence)
  and routing failure are distinct error domains and MUST be reported
  distinctly.
- Multiple adapters MAY serve one recipient; selection policy MUST be
  deterministic and recorded on the receipt.

## 9. Resolution receipts and evidence cursors

Every resolution produces a resolution receipt containing:

- the scope and operation;
- the resolved set with per-member evidence references (for `/we`:
  certificate ID and latest lease hash per member; for relationship scopes:
  the governing record references);
- every exclusion with its reason (`expired`, `revoked`, `quarantined`,
  `policy`, `no_evidence`, `undefined_metric`);
- the resolver's evidence cursor: identity-control checkpoint and revocation
  high-water state as defined by DM-010 Section 11, plus the freshness of
  relationship and adapter inputs used.

A resolution is always relative to its cursor. During partition, a resolver
MUST NOT claim global absence of newer evidence; it reports the cursor it
used. Local policy SHOULD refuse active-presence-dependent operations when
the cursor is older than its configured freshness bound.

## 10. V0 interoperability profile

| Parameter | V0 value |
|---|---|
| receipt taxonomy | one pending state (`accepted`) plus exactly the five terminal values of Section 6.3 |
| parse failure behavior | fail closed, no alias guessing |
| duplicate delivery rule | deduplicate on `(message_id, recipient)` with the recipient component typed per Section 6.2 |
| reply synthesis | caller-local only, labeled, attributed |
| `/we` evidence source | DM-010 Section 10 only |
| `/everyone` | disabled unless explicitly enabled; public classifications only |
| `/near` without declared metric | `undefined_metric` |
| resolution freshness bound | deployment-configured; MUST exist |

## 11. Transitional-system mapping

Consistent with DM-010 Section 12, the following are routing or descriptive
inputs and never resolution authority:

- Tribe v1 directory principals, audiences, and broker routes;
- `@localhost` principal names, harness session names, GitHub logins, host
  names, IP addresses, anyVPN membership;
- a mirror or Telegram chat as a rendered destination.

During migration, a transitional principal becomes addressable as `/we` only
after the corresponding incarnation holds a DM-010 certificate and current
presence lease. Until then it is addressable through adapter routes by name,
with the resolution receipt marking the route `transitional` and the
membership evidence absent.

## 12. Required acceptance and negative scenarios

DM-011 vectors and later implementation tests MUST cover at least:

| Scenario | Required result |
|---|---|
| unknown scope or operation name | fail closed at parse; no alias guessing |
| two operations in one address | reject |
| adapter roster lists an incarnation with no valid lease | excluded from `/we`; route hint only |
| two certified incarnations of one `/me` active | one being, two `/we` members; never two beings |
| two distinct `/me` sharing harness, host, or transport principal | two beings; never merged |
| network-reachable process with no presence evidence | excluded from `/we`; MAY be `/here` via embodiment evidence |
| resolution selects subset "most likely to answer" | recorded as policy; membership evidence unchanged |
| fan-out mutates `message_id` or `thread_id` | reject |
| re-fan-out of the same `(message_id, recipient)` | no duplicate accepted delivery |
| recipient admitted by evidence but unroutable | `resolved:unroutable` receipt; other recipients unaffected |
| adapter accepted delivery then transport failed | `failed:transport`; never reported as delivered |
| timeout retry produces second delivery for one recipient | reject/deduplicate |
| `accepted` reported as the terminal state of a delivery | reject unless the transport defines acceptance as intake; pending must progress to one terminal receipt |
| timeout classified inconsistently between `failed:transport` and `expired` | reject; deadline-without-ack is `failed:transport`, locally known TTL/evidence expiry is `expired` |
| cluster coordinator derives `/all` from a transport hub or broker roster | reject; cluster membership needs embodiment or presence evidence |
| dedup key includes route reference or certificate generation | reject; renewals must not duplicate, incarnations must not collide |
| reply addressed to `/me` for a remote sender | reject; replies address the sender's identity and routes, never the local-only `/me` scope |
| extension defines a new reachability-based scope without a protocol version change | reject |
| result reported as one collapsed boolean | reject; per-recipient vector required |
| reply aggregated into the original message or its receipts | reject |
| missing reply treated as negative answer | reject |
| synthesized summary presented as `/we` semantics or without attribution | reject |
| reply with fresh `message_id`, original `thread_id`, `reply_to` set | accept |
| adapter adds/removes recipients at delivery time | reject; membership is resolution-layer only |
| adapter credential material present in resolution layer | reject |
| `.pull` initiated to force receiver integration | reject; puller-side admission only |
| `.incoming` mutates receiver state | reject |
| `.diff`, `.incoming`, or `.pull` addressed to `/here`, `/near`, `/all`, `/human`, or `/everyone` | `operation_not_valid_for_scope` |
| `/everyone` with non-public classification | `refused:policy` per recipient |
| `/everyone` when deployment disables it | fail closed |
| `/near` with no declared domain metric | `undefined_metric` |
| remote process resolved into `/here` | reject |
| relationship scope member with relationship record but no route | resolves; `resolved:unroutable` receipt |
| membership inferred from transport directory alone (e.g. Tribe audience) | reject; route hint only |
| resolution during partition claims global absence of newer evidence | reject; report evidence cursor |
| resolution receipt omits exclusion reasons or evidence references | reject |
| extension redefines existing scope membership or operation semantics | reject as extension; requires new name/version |
| extension makes an adapter or harness membership authority | reject |
| stale evidence cursor beyond freshness bound used for presence-dependent operation | refuse per local policy |
| transitional principal without certificate addressed as `/we` | excluded; addressable by adapter name route with `transitional` receipt marker |

## 13. Downstream contracts

- DM-011 defines the canonical encoding, receipt envelope fields, and
  positive/negative vectors for the artifacts named here; this document
  defines no byte-level encoding.
- DM-010 supplies the `/we` eligibility predicate and evidence cursors this
  document consumes; nothing here relaxes it.
- DM-040 and DM-041 bind harness sessions to incarnation certificates;
  routing to those incarnations follows this document, with harnesses as
  adapters only.
- DM-070 exercises remote presence, partitioned resolution, fan-out receipts,
  and provenance-preserving convergence end to end.
- DM-023 records resolutions, deliveries, and receipts in the canonical
  ledger as projections rebuildable from signed events.
