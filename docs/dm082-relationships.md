# DM-082 relationship, founded-Tribe and grant runtime

Status: implemented as an isolated V0 producer and verifier. This document
describes Daimon Matrix; Matrix.org is not part of the runtime.

## Authority boundary

DM-082 turns the normative relationship model into signed `dm.we.v1` history.
It keeps three facts separate:

- a relationship is bilateral consent between two distinct root-derived beings;
- founded-Tribe membership is an accepted founder invitation; and
- a grant is directional authority over exact resources and operations.

Cards, routes, delivery, decryption, `/me`, `/we`, Cluster presence and resource
fences cannot manufacture any of those facts. DM-054 consumes the verified
snapshot emitted here and retains no signing or membership authority.

## Runtime contract

Hosted bundle `dm.runtime.bundle/v6` adds a closed `relationships` object with
an owner-local SQLite filename and an explicit list of known being references.
The corresponding exact root authorities are loaded from the shared known-being
inventory. Inventory presence permits signature verification only; it creates no
relationship, membership, route or source trust.

The store verifies every signed event before retention, keeps conflicting
variants, uses `DELETE` journal plus `synchronous=FULL`, rejects symlinks and
non-owner-only state, and persists exact request replay results. Its observer
view is rebuilt deterministically from retained evidence at an explicit
millisecond.

The reducer enforces current root-bound card series, exact bilateral pairing,
predecessor-linked membership episodes, two-party founder epochs, exact grant
acceptance, strict delegation attenuation, terminal cascades and fork
quarantine. Arrival order, label and hash ordering never choose authority.

## Owner surfaces

The authenticated daemon exposes fixed relationship and Tribe methods for card,
offer, acceptance, closure, declaration, invitation, membership terminal,
founder succession, grant acceptance/revocation/relinquishment, foreign-event
ingest, cursor, status, verified snapshot and disclosure. CLI and MCP expose the
same fixed methods without an arbitrary RPC escape hatch. Unauthorized
disclosure always returns the same closed denial object.

The dynamic snapshot provider feeds DM-054 scope resolution. A snapshot requires
current cards for every included member, contains only active memberships and
effective accepted grants, and never turns membership into resource authority.

## Published evidence

- contract and report schemas: `schemas/relationships/v1/`;
- deterministic signed vectors: `vectors/relationships/v1/`;
- generated scenario map: `conformance/relationship-v1-scenarios.json`;
- installed journey fixture:
  `conformance/fixtures/dm082-synthetic-relationships.json`;
- invariant report: `docs/verification/dm082-invariants.json`; and
- executable evidence: `tests/test_dm082_relationships.py`.

The synthetic journey creates three disjoint disposable beings with two
independent relationship stores, establishes two relationships, admits one
founded-Tribe member, and accepts and attenuates a grant. DM-054 resolves the
verified membership, DM-052 freezes its selected relationship leg, DM-051 seals
the canonical event to the member's current credential, and DM-053 carries it
over authenticated loopback HTTP. Recipient revalidation and decryption happen
before durable intake; the route ACK leaves the leg accepted until the member's
independently signed receipt makes it semantically delivered.

The journey then transfers founder authority, revokes the ancestor, and proves
that stale direct intake and a hub-forward attempt are refused without another
private open. Both observers restart with byte-identical cursors and exact
replay creates no duplicate delivery or receipt. The only network socket is an
ephemeral `127.0.0.1` fixture; no live host or external endpoint is contacted.
DM-071 remains the separately authorized cross-host canary, not a missing local
protocol seam.

## Minimal runnable checkpoint

From an installed wheel, the pause-safe functional checkpoint is one command:

```sh
state_dir="$(mktemp -d /tmp/daimon-relationship-demo-XXXXXX)"
daimon-synthetic-relationships --state-root "$state_dir" | python -m json.tool
```

Success exits zero and returns `dm.synthetic-relationship-report/v1` with every
invariant `true`, including authenticated intake, signed semantic delivery,
independent observer convergence and stale direct/hub refusal. The command uses
only disposable owner-local state and an ephemeral loopback socket. Reusing the
same non-empty state directory is intentionally refused; each run represents a
fresh isolated ceremony.

## Rollback and operational boundary

Rollback reverts code and discards only fixture-owned synthetic roots. It never
deletes canonical operational relationship history. Live deployment, external
consent and a two-host message are separate explicitly authorized integration
steps. Cluster hosting obligations are defined in
`docs/integration/daimon-cluster-relationship-adapter.md`.
