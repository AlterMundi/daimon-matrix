# Selected source learning V1

Status: additive normative exchange mode; receiving rollout is recorded in
CURRENT-STATE.md. Source ancestry V0 remains unchanged and is the default.

## Selection and meaning

`source.diff` MAY select `closure_mode: "selected-source-v1"`; omission or
`full-origin-v0` selects the original full-origin protocol. Invalid values MUST
be rejected. The existing CLI exposes `--closure-mode`; the existing MCP tool
accepts the same optional field. No new authority or messaging scope is created.

V1 bundle and continuation schemas are `dm.source-diff-bundle/v1` and
`dm.source-continuation/v1`; retained pull results use
`dm.source-pull-result/v1`. Durable page prefixes MUST require the same version.
Bundle, page and continuation digest domains use
`/v1`; their field sets and existing item format remain unchanged. A receiver
MUST reject a mode/version substitution, including between continuation pages.
The public shape is `schemas/source/v1/runtime.schema.json`.

Every original source event envelope MUST remain byte-exact and pass ordinary
DM-011 signature, root authority, credential, incarnation and cutoff checks.
V1 MUST carry only the selected source's claims and publications. Its semantic
closure MUST include each exact predecessor in a claim/publication series and
each publication's publisher claim. Predecessor hashes, source, series, author
and publisher/claimant binding MUST match. Missing or unrelated evidence MUST
be rejected; an altered signature MUST NOT be accepted as a partial record.

Body-chain predecessors and other causal parents remain signed fields but are
not traversed in V1. Their omission is explicitly NOT proof of complete origin
history. V1 MUST NOT inject those sparse foreign events into a Weave ledger or
claim autobiography continuity. Claims/publications alone do not authorize a
whole body journal. Existing source/classification read grants still apply;
each carried publish envelope, including historical revisions, requires its
classification grant. V1 never implies an `origin-closure` grant.

## Retention and reduction

Verified foreign envelopes MUST be retained in the existing owner-only SourceCAS
alongside exact content/provenance; they remain attributed evidence. Status,
assessment, cursor and import reduction MUST combine this evidence with known
Weave source events. Exact duplicates MUST reduce once. Conflicting event IDs,
origin positions or semantic series MUST remain visible and MUST NOT become a
silent last-write-wins replacement. A later full Weave sync MUST reconcile exact
evidence and expose conflicting retained positions even while ancestry remains
incomplete. Retained tombstones and successors MUST prevent an older page from
resurrecting a publication or hiding a fork.

The existing signed receiver cursor, bounded pages, exact operation/preview
binding, crash journal and quarantine-only pull remain mandatory. Incoming
preview MUST write nothing. Pull MUST retain a selected page's envelopes and
blobs atomically before advancing its journal. Retry/restart MUST recover the
same operation without a second import decision or automatic promotion.
Separate exact local assessment and promotion/application rules remain intact;
foreign knowledge MUST NOT become private autobiographical memory.

## Resource bounds and operating stop

The owner-local CAS defaults to 8,192 sparse envelopes / 64 MiB envelope bytes,
65,536 content entries / 256 MiB exact content, and 4,096 intake operations /16 MiB retained results.
These are constructor-configurable positive bounds, not automatic resizing.
Limits MUST be checked under the SQLite writer transaction. Exact retries MAY
reuse existing bytes at capacity; new intake MUST stop with an explicit capacity
error. A capacity failure while landing a selected page MUST retain neither a
partial blob prefix nor a partial envelope set. Accepted evidence and unfinished
operations MUST NOT be evicted to make space. Operators stop intake at capacity
and explicitly review the owning store/bounds; this protocol adds no background
job, timer, cleanup of originals, provider call or autonomous peer attention.
