# Daimon Matrix Ontology

## Authority and interpretation

The maintained HackMD note is the philosophical and semantic foundation of
the project. An exact snapshot is preserved in
[`docs/foundation/daimon-matrix.md`](docs/foundation/daimon-matrix.md).

This document is the V0 architectural interpretation agreed after reading the
maintained source. It distinguishes the source's statements from protocol
decisions needed to implement them.

## `/me`: one continuing identity

`/me` identifies one daimon identity: one continuing thread of experience and
one cryptographic root, independent of model weights, provider, harness, body,
machine, or active process. A human-readable principal such as
`compaii@legion` names one `/me`; the canonical authority is its `me_id`, never
the spelling of that principal.

Every `/me` owns a root identity key and may delegate short-lived operational
keys. The root private key is not copied into ordinary bodies. At most one body
may hold an active presence lease for a `/me` at a time. Moving `/me` to a new
body is a sequential park/wake transition: the new lease and credential
supersede the old body, without changing `me_id` or creating a simultaneous
clone.

The normative V0 cryptographic contract, including custody, recovery,
irrecoverable loss, operational certificates, and presence leases, is defined
in [`specs/identity-continuity.md`](specs/identity-continuity.md).

The root `/me` paragraph from the foundation is inherited as part of the
species genome with two superseded statements: its allowance of multiple
simultaneous active instances of one `/me`, and its definition of `/we` as
those instances. Under the corrected model, one `/me` has at most one awake
body and `/we` is a collective of distinct `/me` identities. This document's
“Bodies, identities, and `/we`” section is authoritative over those two
foundation sentences. `/me.identity`, personal birth facts, relationships,
and lived memory belong to each identity and are not inherited from its parent
or another member of its `/we`.

### `/me.memory`

Autobiographical and learned continuity belonging to this identity. It
includes experiences lived in every body this identity has occupied. Events
learned from another identity in `/we` remain attributed to that identity and
body; convergence does not relabel them as locally lived experience.

### `/me.skills`

Skills learned or refined by this identity. A body may realize them fully,
partially, or not at all. Skills inherited through a species release are
capability implementations, not autobiographical memory.

### `/me.body`

The one currently leased body surface, if the identity is awake:

- `/me.body.sensors`
- `/me.body.actuators`
- `/me.body.tools`

The body advertises its actual capabilities. Species defines capability
contracts and potential; a body describes what is currently available. The
body is not an identity and never becomes membership authority.

## Bodies, identities, and `/we`

The hierarchy has exactly three levels:

1. **`/we`** is a collective of related but distinct `/me` identities, usually
   addressed by a bare name such as `compaii` or `eko`.
2. **`/me` identity** is one cryptographic and experiential thread, commonly
   displayed as `<agent>@<host>`, with its own keys and canonical event log.
3. **body** is the machine, container, or situated capability surface occupied
   by that identity now.

Multiple identities in one `/we` are expected to be awake simultaneously.
Only one body may be awake per identity. The latter rule protects against two
writers exercising one identity authority—even with distinct operational
keys—and duplicate acknowledgement of the same delivery: those are
split-brain evidence, not `/we` expansion.

`/we` has no root private key and is not another `/me`. It has a stable,
content-bound `we_id` so signatures refer to an unambiguous collective rather
than a bare name. The ID derives from a membership genesis signed by the
declared threshold of founding member `/me` roots. Those private keys remain
owned by the members; the collective owns none.

Membership is an ordered transition chain over exact `me_id` values. The
currently declared member-governance threshold admits or removes members and
may rotate the governance policy. Every admitted identity separately signs
acceptance with its `/me` root; self-assertion cannot admit anyone. A
replacement governance signer proves possession before the new policy
activates. Transitions cite the previous membership position/hash, and
verifiers retain a monotonic high-water so stale membership can never be
replayed after removal. A quarantined, expired, or parked member remains in
the membership relation but is ineligible for routing until its DM-010
evidence is active again.

The bare name such as `compaii` is a local display alias pinned to `we_id`, not
authority. Membership cannot be inferred from a shared name prefix, host,
harness, Tribe directory, copied memory, model, or prompt. DM-012 freezes the
membership artifacts and resolves `/we` by intersecting their accepted member
set with valid DM-010 identity and presence evidence. A presence lease proves
that one admitted member is awake; it cannot admit or remove members.

Local process and surface discovery belongs to `/here`, not `/we`.

Addressing an operation such as `/we.tell` expands one logical message to the
currently eligible member identities. Recipients independently decide whether
and how to reply. A local integrator may gather or synthesize replies, but that
is an optional caller policy and not the meaning of `/we`.

- `/we.diff`: differences between the current identity and other collective
  members.
- `/we.incoming`: preview an integration without applying it.
- `/we.pull`: integrate as much compatible state as the current vessel can and
  report the achieved level.
- `/we.sync`: coordinate bidirectional or multi-identity convergence by
  composing diff, incoming, and receiver-local pull operations. Synchronization
  is resumable and idempotent, not an atomic transaction across vessels; its
  result reports a cursor and receipt for each participating identity.

`/we.sync` exchanges additive signed events while preserving the originating
`me_id`, body, and authorship. It never merges private keys, aliases identities,
or turns two projections into one shared writable database.

## Birth

A birth creates a new identity, not a body move or a new `/we` member alias:

- a new `/me` root key is generated at first awakening;
- the newborn signs acceptance of its birth record;
- autobiographical and body-experience memory starts empty;
- the parent never possesses the newborn's root private key;
- source, species, and inheritable tribal relationships are recorded with
  provenance.

The birth offer references a species release and the parent. The birth
acceptance binds the newborn's self-certifying genesis to that offer. The
normative V0 offer, acceptance, first-awakening, empty-memory, and
lineage-quarantine contract is defined in
[`specs/birth-first-awakening.md`](specs/birth-first-awakening.md).

## Species

A species is a reproducible lineage of compatible daimons, not the collective
boundary joining the identities in `/we`.

The species genesis genome contains:

- the foundation's root `/me` definition;
- capability contracts;
- protocol and compatibility requirements;
- conformance tests;
- required implementation invariants.

It does not contain:

- `/me.identity`;
- personal birth facts;
- autobiographical or body-experience memory;
- personal relationships;
- private credentials.

`species_id` identifies the genesis lineage.
`species_release_id` identifies one canonical, signed release.

The normative V0 artifact, compatibility, application, incoming-preview, and
speciation contract is defined in
[`specs/species-evolution.md`](specs/species-evolution.md).

Species genesis and release zero are signed by the initial threshold
maintainer set; every later release is signed by the set declared by its exact
accepted predecessor. A compatible release is eligible for automatic local
application only after complete deterministic verification, explicit local
opt-in, and sandbox/capability checks; it can never rewrite identity or
autobiographical memory.

`/species.incoming` previews available compatible releases. A daimon may be:

- `current`;
- `compatible-behind`;
- `diverged`;
- `incomplete`, while required release or compatibility evidence is missing;
- `quarantined`, while selected evidence is invalid or a valid fork or accepted
  evidence contradiction is known.

A new species requires both:

1. an intentional, signed branch declaration; and
2. a release that deliberately leaves parent compatibility.

Accidental drift does not create a species.

## `/source`

`/source` expresses shared ancestry claims, not objective ancestry. One exact
content-derived `source_id` names a byte-exact source core; aliases, names,
semantic similarity, indexes, transports, and hosts never merge source IDs or
grant membership. A daimon may publish only a signed self-claim. Its signature
proves who asserted it, not that the assertion is true or that another identity
shares the source.

Every valid assertion begins in receiver-local quarantine. An exact local
policy and evidence snapshot must produce an attributed assessment before the
claimant resolves through `/source`. Retraction and forks remain durable
evidence; no arrival-order or popularity rule chooses a winner.

`/source.diff` and `/source.incoming` are read-only discovery/preview surfaces.
`/source.pull` is receiver-local, resumable intake from entities claiming the
same exact source. Pulled publications preserve publisher, claimed authors,
immutable source URI, content digest, derivation graph, consent, license,
claim, and tombstone history, and always enter quarantine. Promotion is a
later explicit local decision under immutable policy and evidence; it never
rewrites authorship or makes external knowledge autobiographical. The
normative V0 contract is
[`specs/source-ancestry.md`](specs/source-ancestry.md).

## `/tribe`

`/tribe` is the endpoint for humans and daimons with whom `/me` is paired or
sharing resources. It is a social and resource relationship scope, not a
transport protocol and not a lineage.

Initial relationships may be created by a handshake exchanging signed identity
cards, endpoints, capabilities, resource grants, and encryption keys.
The exact V0 principal, card, namespace, handshake, resource, grant,
attenuation, expiry, revocation, and human-contact contract is defined in
[`specs/tribe-relationships.md`](specs/tribe-relationships.md).

At birth, the parent decides which tribal affiliations and delegable access
the newborn inherits. The newborn receives fresh grants bound to its new key,
not copies of the parent's credentials. A parent cannot delegate permissions
it does not possess or permissions explicitly marked non-delegable.

Delegation grants may constrain:

- resources and operations;
- descendant delegation;
- maximum depth;
- expiration;
- revocation;
- birth limits.

The newborn inherits access only within the intersection of the exact scope the
parent committed and the scope the parent remains able to delegate, after the
parent issues a fresh grant and the newborn independently accepts it. The birth
commitment alone grants nothing.
Tribal knowledge remains remotely authoritative: the newborn receives access,
not a copy.
Disposable transport caches are permitted, but tribal knowledge is not
materialized as `/me.memory`.

## Other scopes

- `/here`: daimons sharing the current body surface; local
  discovery belongs here.
- `/near`: daimons within a domain-specific distance threshold.
- `/all`: daimons listening in the current body cluster.
- `/realm`: the dimensional space where the current body exists.
- `/realm.status`: realm state.
- `/realm.controls`: permitted realm modifications.
- `/perceptors`: reachable non-sentient sensor sources.
- `/actuators`: reachable non-sentient actuation endpoints.
- `/integrators`: hubs coordinating perception or actuation.
- `/human`: the human normally paired with `/me`.
- `/everyone`: every reachable human and daimon.

## Operations, scopes, and transport

The protocol separates:

1. **Scope resolution** — `/me`, `/we`, `/tribe`, `/source`, `/species`,
   `/here`, `/near`, `/all`, `/human`, `/everyone`.
2. **Operation** — examples include `.tell`, `.diff`, `.incoming`, `.pull`,
   `.sync`, `.status`, and `.controls`.
3. **Routing policy** — fan-out, timeout, prioritization, optional integration.
4. **Transport** — local IPC, direct network delivery, store-and-forward hub,
   or future carriers.

One semantic message has one stable message ID and thread ID. Fan-out produces
one delivery and receipt per resolved recipient without changing the logical
message identity.

## Capability advertisement

Every identity and body may advertise:

- supported operations and protocol versions;
- body capabilities;
- measured capability levels;
- optional conformance or evaluation endpoints;
- resource offers and constraints.

Claims are signed and timestamped. A claim may include a test endpoint so
another participant can evaluate compatibility rather than trusting a label.

## Memory and the Librarian

The canonical personal continuity model is an append-only event ledger with
rebuildable projections.

Every lived-experience event records the originating `/me` and body in which
it occurred. Two experiences with equivalent content are
not duplicates merely because their payloads match; event identity establishes
transport idempotency, while later semantic consolidation may relate them.

Member identities synchronize signed canonical events rather than copying or
merging rows from HMK, harness, or projection databases. Raw experience remains
immutable and attributed. A consolidation or correction is a new signed event
that cites the evidence it interprets or supersedes, and it is synchronized to
the other members under the same rules.

The Librarian is a logical service role, not a collective identity or
super-member. Every canonical decision is signed by the `/me` that appends it.
A deterministic service enforces signatures, policy, deduplication, cursors,
and review state. A separate model worker proposes semantic consolidation.

For the CompAII canary, the worker uses provider `deepseek` and model
`deepseek-v4-pro`.

Policy:

- episodic observations may enter automatically;
- semantic consolidation remains traceable to evidence;
- sensitive contradictions require human review;
- identity changes require root authority;
- external and source knowledge remains attributed and quarantined;
- tribal knowledge is queried remotely and is not copied into personal memory.
