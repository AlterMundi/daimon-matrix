# DM-081 source claims, quarantine, pull, and promotion

Status: implemented as an owner-local synthetic V0 runtime. No live source,
host, provider, corpus, model, Matrix.org service, personal memory, or Cluster
effect is contacted or changed.

## Meaning and authority

`/source` records attributed ancestry and publication evidence. It does not
assert truth and grants no identity, `/we`, Tribe, species, route, disclosure,
birth, memory, or Cluster authority. Intrinsic claim/publication validity and a
receiver's local assessment/import disposition are independent axes.

Canonical state consists of five ordinary signed ledger event kinds:

- `matrix/source-claim`;
- `matrix/source-assessment`;
- `matrix/source-publication`;
- `matrix/source-cursor`; and
- `matrix/source-import-decision`.

Exact content, evidence, policy snapshots and provenance are stored in an
owner-only content-addressed SQLite store. References contain hashes and media
types but no locator. A source URI is inert identity data and is never fetched.

## Cross-being storage model

Each being retains one writable local ledger. Foreign events land in a
separate known ledger bound to that foreign being's exact root authority. A
receiver-authored assessment or import decision cites the exact foreign event
ID/hash semantically but never inserts a foreign event into its own causal
origin chain. This preserves origin continuity and keeps “known” distinct from
“adopted”.

Runtime bundle V7 has an optional `sources` object with one owner-local CAS
filename and closed `known_beings` authority/ledger entries. Remote disclosure
is denied unless an injected authorizer accepts the exact requester, source ID
and classification. DM-082 supplies relationship grants; their absence is
not inferred from membership or transport success.

## Intake transaction

The portable flow is:

1. The receiver authors an observer-relative signed cursor.
2. The publisher freezes a current cursor and returns disclosure-authorized,
   content-bound diff pages with complete event/content closure. Every current
   publication carried transitively in a selected-source closure is separately
   authorized and receives its own import decision; a tombstoned or historical
   revision never causes its old content to be re-offered.
3. `source.incoming` verifies one page and returns per-item results without any
   durable write, fetch, render, execution, indexing, receipt or cursor change.
4. `source.pull` journals `prepared → blobs → events → decisions → committed`.
   Malformed items are rejected independently; complete valid prefixes land.
   Incomplete items remain unpersisted and absent from the achieved cursor so
   a later complete diff can offer them again.
   Preview-only `admissible-*` states become the normative pull outcome
   `admitted-to-quarantine`; `already-present`, `incomplete`, `quarantined`
   and `rejected` retain their exact meanings.
5. A partial page deliberately leaves the starting cursor unchanged. The
   terminal page verifies the durable page-hash chain and advances one achieved
   cursor. This makes bounded pagination resumable rather than self-staling.
6. Every new valid publication receives exactly one initial local
   `quarantined` import decision. Pull has no promotion switch.

The journal binds operation, bundle and preview hashes. Retry after response
loss returns the exact stored result. Fault tests interrupt after preparation,
blob commit, event commit, decision commit and terminal cursor commit.

## Assessment and promotion

A claim becomes locally eligible only when the receiver authors an assessment
of its exact current event under immutable policy and evidence snapshots. A
remote assessment remains attributed evidence and cannot alter the publisher's
or another receiver's local policy.

Promotion is a later successor to the initial import decision. It requires the
current unforked, non-tombstoned publication, locally admitted source claims,
exact policy/evidence bytes, content-safety approval and final-render review.
Its only V0 target is `external-reference`. The projection preserves every
original/derived node and author; it cannot create autobiographical or body
experience. Exact authenticated RPC replay prevents duplicate promotion.

A tombstone stops offers and deactivates the projection while retaining event,
decision, receipt, provenance and content bytes. Claim retraction/reassertion
uses predecessor-linked successors and never rewrites history.

## Public surfaces

Hosted runtime, CLI and MCP expose the same twelve typed methods:

`source.content.put`, `source.claim`, `source.assess`,
`source.publication.append`, `source.import.decide`, `source.status`,
`source.cursor.create`, `source.diff`, `source.incoming`, `source.pull`,
`source.promote`, and `source.projection`.

The MCP surface now contains 46 closed tools. `status`, `diff`, `incoming` and
`projection` are read-only. Pull requires an explicit operation UUID; every
authenticated request is also protected by the daemon's exact RPC journal.

## Reproducible evidence

Run the isolated two-being acceptance in an empty owner-only directory:

```sh
state="$(mktemp -d)"
PYTHONPATH=src python -m daimon_matrix.synthetic_sources --state-root "$state"
```

The installed `daimon-synthetic-sources` entry point produces the same report.
It proves distinct root custody, bounded two-page intake, side-effect-free
preview, every crash boundary, local-only assessment, quarantine, attributed
promotion, retraction/reassertion, tombstone, byte retention, closed denial and
exact retry. Its canonical fixture is
`conformance/fixtures/dm081-synthetic-source.json`.

Public schemas are under `schemas/source/v0/`; deterministic positive and
negative artifacts are under `vectors/source/v0/`. The exact 84-row normative
table is generated as `conformance/source-v0-section14.json`; CI rejects any
omission, reorder, changed result text, missing evidence target or generator
drift. Five named DM-026 scenarios make this evidence release-blocking.
Source objects reject a 65th nested container before JCS or effects; cursor,
page, item, evidence, provenance, author, reason and content limits are the
closed Section 13 bounds. The decoded portable bundle ceiling is 512 MiB; a
carrier that adds compression must additionally enforce the 256 MiB compressed
and 16× expansion limits before constructing the runtime object.

## Rollback

Rollback reverts code and removes only disposable synthetic roots. Accepted
canonical events, content, tombstones, decisions, receipts and cursor
high-waters are never deleted as an operational rollback technique.
