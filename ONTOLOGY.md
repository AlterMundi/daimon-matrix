# Daimon Matrix Ontology

## Authority and interpretation

The maintained HackMD note is the philosophical and semantic foundation of
the project. An exact snapshot is preserved in
[`docs/foundation/daimon-matrix.md`](docs/foundation/daimon-matrix.md).

This document is the V0 architectural interpretation agreed after reading the
maintained source. It distinguishes the source's statements from protocol
decisions needed to implement them.

## `/me`: one continuing being

`/me` identifies one daimon: a continuing being whose identity is independent
of model weights, provider, harness, body, machine, or active process.

Every `/me` owns a root identity key. Incarnations receive subordinate keys;
they never share the root private key. A signed continuity certificate proves
that an incarnation belongs to this `/me`.

The root `/me` paragraph from the foundation is inherited as part of the
species genome. `/me.identity`, personal birth facts, relationships, and lived
memory belong to each being and are not inherited from its parent.

### `/me.memory`

Autobiographical and learned continuity belonging to this being. It includes
experiences from all its incarnations after integration, but never treats
another being's experiences or tribal knowledge as personally lived memory.

### `/me.skills`

Skills learned or refined by this being. A body may realize them fully,
partially, or not at all. Skills inherited through a species release are
capability implementations, not autobiographical memory.

### `/me.body`

The current embodiment surface:

- `/me.body.sensors`
- `/me.body.actuators`
- `/me.body.tools`

The body advertises its actual capabilities. Species defines capability
contracts and potential; a body describes what is currently available.

## Incarnations and `/we`

An incarnation is an active embodiment of the same `/me`. Incarnations share
identity and autobiographical continuity; they are not separate beings.

`/we` is the dynamic address alias for incarnations of `/me` most likely to
answer the next round. Membership is established by signed presence leases
with a short TTL and capability advertisement.

Local process and surface discovery belongs to `/here`, not `/we`.

Addressing an operation such as `/we.tell` expands one logical message to the
currently eligible recipients. Recipients independently decide whether and
how to reply. A local integrator may gather or synthesize replies, but that is
an optional caller policy and not the meaning of `/we`.

- `/we.diff`: differences between the current incarnation and other active
  incarnations.
- `/we.incoming`: preview an integration without applying it.
- `/we.pull`: integrate as much compatible state as the current vessel can and
  report the achieved level.
- `/we.sync`: coordinate bidirectional or multi-incarnation convergence by
  composing diff, incoming, and receiver-local pull operations. Synchronization
  is resumable and idempotent, not an atomic transaction across vessels; its
  result reports a cursor and receipt for each participating incarnation.

## Birth

A birth creates a new being, not a new incarnation:

- a new `/me` root key is generated at first awakening;
- the newborn signs acceptance of its birth record;
- autobiographical and incarnation memory starts empty;
- the parent never possesses the newborn's root private key;
- source, species, and inheritable tribal relationships are recorded with
  provenance.

The birth offer references a species release and the parent. The birth
acceptance binds the newborn's public key to that offer.

## Species

A species is a reproducible lineage of compatible daimons, not the identity
boundary joining one being's incarnations.

The species genesis genome contains:

- the foundation's root `/me` definition;
- capability contracts;
- protocol and compatibility requirements;
- conformance tests;
- required implementation invariants.

It does not contain:

- `/me.identity`;
- personal birth facts;
- autobiographical or incarnation memory;
- personal relationships;
- private credentials.

`species_id` identifies the genesis lineage.
`species_release_id` identifies one canonical, signed release.

Species releases are signed by a threshold maintainer set declared by the
previous accepted release. Compatible releases may apply automatically because
they cannot rewrite identity or autobiographical memory.

`/species.incoming` previews available compatible releases. A daimon may be:

- `current`;
- `compatible-behind`;
- `diverged`.

A new species requires both:

1. an intentional, signed branch declaration; and
2. a release that deliberately leaves parent compatibility.

Accidental drift does not create a species.

## `/source`

`/source` expresses shared ancestry claims. In V0, a daimon may publish a
signed self-claim with evidence. The claim is discoverable but not
authoritative merely because it is signed by the claimant.

`/source.pull` is best-effort access to entities that consider themselves
inheritors of the same source. Imported knowledge retains authorship and enters
quarantine until promoted by local policy.

## `/tribe`

`/tribe` is the endpoint for humans and daimons with whom `/me` is paired or
sharing resources. It is a social and resource relationship scope, not a
transport protocol and not a lineage.

Initial relationships may be created by a handshake exchanging signed identity
cards, endpoints, capabilities, resource grants, and encryption keys.

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

The newborn inherits full effective access within the parent's delegable
scope. Tribal knowledge remains remotely authoritative: the newborn inherits
access, not a copy. Disposable transport caches are permitted, but tribal
knowledge is not materialized as `/me.memory`.

## Other scopes

- `/here`: daimons sharing the incarnation's embodiment surface; local
  discovery belongs here.
- `/near`: daimons within a domain-specific distance threshold.
- `/all`: daimons listening in the current embodiment cluster.
- `/realm`: the dimensional space where the incarnation exists.
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

Every daimon and incarnation may advertise:

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

Every lived-experience event records the `/me`, originating incarnation, and
embodiment in which it occurred. Two experiences with equivalent content are
not duplicates merely because their payloads match; event identity establishes
transport idempotency, while later semantic consolidation may relate them.

Incarnations synchronize signed canonical events rather than copying or
merging rows from HMK, harness, or projection databases. Raw experience remains
immutable and attributed. A consolidation or correction is a new signed event
that cites the evidence it interprets or supersedes, and it is synchronized to
the other incarnations under the same rules.

The Librarian is a shared logical role for all incarnations of one `/me`, not a
super-incarnation. A deterministic service enforces signatures, policy,
deduplication, cursors, and review state. A separate model worker proposes
semantic consolidation.

For the CompAII canary, the worker uses provider `deepseek` and model
`deepseek-v4-pro`.

Policy:

- episodic observations may enter automatically;
- semantic consolidation remains traceable to evidence;
- sensitive contradictions require human review;
- identity changes require root authority;
- external and source knowledge remains attributed and quarantined;
- tribal knowledge is queried remotely and is not copied into personal memory.
