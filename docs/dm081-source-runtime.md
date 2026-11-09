# DM-081 source claims, quarantine, pull, and promotion

Status: implemented owner-local native runtime, with selected-source V1 intake
and actual cross-being receiving evidence. The original synthetic qualification
remains test evidence, not the current deployment boundary. See the single
[current initial-Matrix coverage map](https://github.com/AlterMundi/daimon-matrix/issues/437#issuecomment-6597923440)
for deployed receivers and unfinished learning acceptance.

The operations below use the receiving body's authenticated Matrix client and
existing Source/relationship grants. They do not fetch a source URI, execute
published content, install a skill, call a model or modify personal memory merely
by publishing, previewing, pulling or promoting a reference. Actual selective
installation and receiving-model use require their owning supported operations
and observed outcomes; neither is implied by the runtime's implementation status.
Matrix.org is not part of this contract.

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

### Hosted source disclosure through existing resources

When both source and relationship contexts are configured, the hosted loader
connects source export to the existing signed knowledge-resource cards and
accepted grants. No extra bundle field or parallel catalog is needed. The
publisher's current card must advertise a `knowledge` resource controlled by
that publisher, with `descriptor_ref` equal to the exact source ID, the exact
requested classification and the `read` operation. Its ordinary resource hash
is the existing relationship permission's `resource_ref`; a source ID itself
is not a relationship resource ID. The requester must have a current accepted
grant for that resource, classification and operation.

The source contract separately checks `claim`, each publication's classification
(`public` or `tribe-shared`), and any `origin-closure` disclosure required for
causal evidence. Advertise and authorize the exact applicable resources rather
than treating one classification as permission for another. Membership, public
labels, knowledge of a root, and successful transport remain insufficient.

One current relationship authorization view is held through the entire bounded
diff-page construction. Concurrent revocation waits for that already-authorized
read; the next page/read observes the revocation, including after clock rollback.
The callback cannot reuse that view outside its owning export scope. Missing or
invalid current authority, resource mappings or grants produces the same closed
source denial. Without a relationship context the existing default denial for
foreign requesters is unchanged. Source import, local assessment, promotion and
selective skill/configuration application remain separate effects.

The successful disclosure tuples are checked again at scope exit against the
same locked evidence and current time: a lock cannot extend a card or grant's
validity. Authenticated RPC replay also revalidates current source authorization
and page content. An unchanged authorized page keeps its exact original bytes
and expiry. An expired, changed or no-longer-authorized page is refused; the
retained historical success is neither erased nor continuing disclosure authority.

## Selective learning without foreign autobiography

The additive [selected source V1 contract](../specs/source-selective-learning.md)
is available through `source.diff` with `closure_mode: "selected-source-v1"`
(or CLI `--closure-mode selected-source-v1`). Older callers retain full-origin
V0. Select the mode explicitly on every continuation request.

V1 sends original signed claim/publication envelopes and their exact semantic
predecessors, publisher claim, content and provenance. It does not traverse the
body journal. Each carried publication classification still needs its ordinary
resource read grant; this is not a grant to origin history. Sparse envelopes
land in SourceCAS, not in a foreign incomplete Weave autobiography. Incoming is
a read-only preview; pull remains quarantined; assessment, promotion and actual
skill/configuration consumption are separate effects. A passing synthetic test
is not a live peer adoption receipt.

SourceCAS now enforces explicit positive constructor limits: 8,192 selected
source envelopes /64 MiB, 65,536 content entries /256 MiB, 4,096 intake operations /16 MiB retained results.
New writes stop at capacity without deleting accepted evidence. Existing exact
bytes and committed retries remain readable. A selected page's envelopes and
content commit together or roll back together; do not retry with new operation
IDs to hide a capacity error. Stop intake and review the current owning store
and capacity setting. No automatic resizing, historical environment archive,
provider request or background review loop is installed by this change.

## Intake transaction

The portable flow is:

1. The receiver calls `source.cursor.create` with the selector. Its existing
   event/status result also includes `envelope`: the signed observer-relative
   cursor and all exact bounded claim/publication pages. Pass that envelope as
   `requester_cursor`; no owner-local database read is needed, including when
   the source already has rows. Retained RPC responses keep their original bytes.
2. The publisher freezes a current cursor and returns disclosure-authorized,
   content-bound diff pages with complete event/content closure. Every current
   publication carried transitively in a selected-source closure is separately
   authorized and receives its own import decision; a tombstoned or historical
   revision never causes its old content to be re-offered.
3. `source.incoming` verifies one page and returns per-item results without any
   durable write, fetch, render, execution, indexing, receipt or cursor change.
4. `source.pull` journals `prepared → blobs → events → decisions → committed`.
   An unsigned empty cursor is valid for preview only: a new pull refuses it
   before creating a journal or landing data. Existing staged operations retain
   their exact recovery path and historical outcomes.
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

## Navigating already known Sources

The existing authenticated `source.status` read accepts the additive closed
request `{view:"known", limit:32, after:null, expected_snapshot:null}`.
CLI: `daimon source known --limit 32`.
The existing `source_status` MCP tool accepts `view:"known"`; its default
exact-selector form remains unchanged. No new tool or capability is created.

`dm.source-known/v1` returns exact selectors/source cores and retained claim and
publication series counts, sorted by source ID. These are derived from verified
retained Source events in the existing registry, not another index. A source core
can be unknown when only incomplete publication evidence is retained. Counts are
retained series, including retracted or unresolved series; they imply neither
admitted ancestry nor species membership. Follow an exact selector with ordinary
status/assessment and selective preview before any adoption.

Pages contain at most64 source rows and128KiB. `next_after` is null at the end;
otherwise pass that source ID and the exact returned `snapshot_id` as
`expected_snapshot`. A changed retained Source event set refuses continuation
with retryable `source_known_view_changed`; restart navigation instead of merging
pages from different observations. Unrelated private experience does not change
this Source-only snapshot. Invalid bounds/cursors refuse; no capacity is resized.

The view explicitly reports `local-retained-evidence-only` freshness,
`not-implied` ancestry assessment and zero remote reads. It contains no content
blobs, private autobiography, database handles/paths or custody. It starts no
network fetch, assessment, import, promotion, model request, timer or persistent
cursor. Fresh remote discovery and the foundation's ancestry/species aggregation
remain separate work; a known selector does not establish publisher convergence.
