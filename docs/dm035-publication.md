# DM-035 reviewed publication

Status: normative for `dm.publication.* /v1`.

“Matrix” means the `daimon-matrix` component. Matrix.org is unrelated, is not
used by this protocol and remains outside the V0 scope.

## Outcome and authority

DM-035 publishes an explicitly approved immutable rendering of one Matrix
identity summary, decision, release or documentation artifact to either the
LLM Wiki or the protected `compaii-state` projection. Matrix owns the source
events, policy, review decision, queue intent and accepted receipt. The
external publisher owns only the configured Wiki/state/HMK transaction.

The Wiki remains the canonical source for its curated documents;
`compaii-state` remains a protected projection/release repository; HMK remains
a retrieval index. None of them can become `/me`, ledger, memory, membership,
species, presence, deployment or review authority. Published bytes cannot be
copied back to repair or author Matrix history.

The exact provider boundary is `compaii-state` merge
`cf56e9de703f68f44b85fdf21f503d55a5557984`, adapter
`dm:adapter:v0:OnDIAMjSu2T_8EqLG_wxxygVXCPGXaTJsA41-IMcpSo`, API `1.0.0`,
contract `v1`, policy hash
`800929a4d56687ca224c5df767ab05c4c259acc75904530848683a92e2484b88`
and HMK commit `f10fd5c3089c0962920314c97e14bc024feffa7a`. Any other
commit, manifest, operation, policy, plan or result is unsupported.

## Policy and immutable rendering

The artifact class is exactly `identity-summary`, `decision`, `release` or
`documentation`. The target kind is exactly `llm-wiki` or `compaii-state`.
Matrix policy fixes each class, classification and license allowed for each
target. LLM Wiki refuses `private`; the protected state target may accept it.
Consent is always explicit.

One proposal binds:

- subject and author `/me` identity;
- exact source event IDs, content hashes and ledger checkpoint;
- release ID/hash when and only when the artifact is a release;
- content reference, rendered byte length/hash and renderer version;
- classification, consent, license and derivation;
- independent reviewer decision, key and expiry;
- target kind and closed logical ID;
- Matrix and provider policy IDs/hashes; and
- the exact predecessor acceptance/provider receipt for a successor.

The target is derived as
`project/daimon-matrix/<slug>` or
`projection/daimon-matrix/<slug>`. Callers cannot supply paths, filenames,
repositories, Git refs, URLs, commands, SQL, database handles, credentials or
arbitrary metadata.

Rendering is deterministic Markdown with closed frontmatter. The reviewer
signs the proposal containing its exact rendered reference. Immediately before
submission and again before effect, Matrix resolves the content-addressed body,
recreates the final bytes and rejects any length/hash difference. The final
title, frontmatter, links, metadata and body are scanned together. Detection is
reject-only: there is no redaction that could change reviewed bytes. Markup,
templates, shell fragments and prompt-like text remain inert data.

## Signed review and canonical events

The publication reviewer uses a purpose-separated Ed25519 key listed in the
Matrix publication policy and must differ from the publisher principal. The
signature covers a domain-separated canonical proposal hash, decision,
reviewer, issue time and expiry. A missing, altered, unknown, stale or
self-reviewing decision fails closed.

`publication.requested` stores the complete closed request in the canonical
ledger. Its causal dependencies include every source event and, for a
successor, the prior `publication.receipted` event. `publication.receipted`
depends on the request, supersedes only the exact prior acceptance and embeds
the fully verified external receipt. Both payloads are validated at the Weave
event boundary and in the public Draft 2020-12 contract.

## Deterministic queue and writer claim

The queue is rebuilt from accepted request and receipt events at an explicit
event-ID/hash cutoff. Its checkpoint and item order are content-derived.
Replaying a historical cutoff returns the historical pending/completed view;
rebuilding at the current cutoff neither republishes completed items nor hides
failed pending work.

Only one active generation may hold a target namespace. A claim binds request
event ID/hash, target, exact Matrix body/embodiment/incarnation/principal,
generation and bounded lease. Expiry permits a compare-and-swap successor;
stale generations cannot complete.

The recovery journal is owner-local SQLite using `DELETE` journaling,
`synchronous=FULL` and an owner-only process `flock`. The complete parent chain
is checked for symlinks before and after directory creation. Parent, database
and lock file must be owner-owned regular objects without group/other access.
A Python mutex or last-writer policy is insufficient.

Backpressure is the policy's exact bounded `max_pending`. Failure never marks
an item complete, advances its acceptance head or triggers another target.

## External transaction

Only six closed operations cross the injected provider transport:
`manifest`, `plan`, `acquire`, `apply`, `reconcile` and `release`. Host roots,
SQLite, HMK, Git and credentials are constructor-owned provider configuration
and never appear in Matrix requests, plans, errors or receipts.

Matrix requires the exact manifest, then asks the provider for a non-mutating
plan. It validates:

- the complete provider request and request hash;
- exact adapter, policy and HMK pins;
- sequence and predecessor;
- sorted logical effects for artifact, evidence, machine index, audit log and,
  for Wiki, visible index;
- every media type, byte length, before/after hash and logical handle;
- a clean final-byte scan; and
- content-derived plan and expected-result hashes.

Immediately before `apply`, Matrix revalidates source, review, policy,
predecessor, claim and provider lease. The external receipt must bind the same
request, plan, target, sequence, relations, source checkpoint, governance,
review, lease and effects. Matrix recomputes its receipt ID and HMK state hash,
then calls provider `reconcile`. Only `verified` effect truth may become a
`publication.receipted` event or serve a cached replay.

## Crash and retry semantics

| Failure point | Required restart result |
| --- | --- |
| before or during staged external effects | provider recovery restores all-old; Matrix request stays pending |
| after HMK/link work but before provider commit marker | all file/index/log/HMK effects roll back together |
| after provider receipt persistence but before commit marker | stale route/receipt and effects roll back together |
| after provider commit marker or response loss | recovery proves one all-new receipt; exact apply replays it |
| after Matrix stores the provider receipt | provider effect remains verified; retry authors one acceptance |
| after Matrix authors acceptance but before local completion | retry discovers the one ledger event, reconciles and completes the claim |
| target or HMK drift at any replay | `effect-truth-discrepancy`; no blind success |
| provider state unavailable | retryable failure; no acceptance or cursor advance |

The integration suite injects all thirteen provider fault hooks plus both
Matrix acceptance windows. Every case retries to one verified event and one
provider effect while preserving unrelated Wiki content. Exact duplicate
requests return the existing request/event/receipt; changed bytes under a
pending target or idempotency identity conflict.

## Successor, withdrawal, rollback and rebuild

A changed approved source is a monotonic successor and must name the current
Matrix acceptance and provider receipt. Same-cursor target drift blocks rather
than overwrites or merges.

Withdrawal is a separate reviewed successor with no body. It creates a
tombstone and advances both sequences; it never deletes audit history or an
untracked target. Rollback is also a newer reviewed successor. V1 permits it to
compensate only its current predecessor, never lower a high-water or restore an
older repository/database snapshot as authority.

Queue and publication state rebuild exclusively from Matrix request and
acceptance events. A completed exact item stays completed without invoking the
provider. External content is evidence for reconciliation, never rebuild input
for canonical Matrix state.

## Public contracts, CI and private-provider gate

Closed contracts are in `schemas/publication/v1/contracts.schema.json`.
Environment-independent interop vectors, including real provider plan and
receipt, are in `vectors/publication/v1/`. Regenerate only with detached exact
provider and HMK checkouts:

```bash
python tools/generate_dm035_vectors.py \
  --provider-root /path/to/compaii-state-cf56e9d \
  --hmk-root /path/to/hmk-f10fd5c
```

The generator refuses a different Git HEAD. Public CI validates every checked-
in hash/schema/vector, all Matrix unit boundaries and the installed wheel
without network or production credentials. `compaii-state` is a private
cross-owner repository, so public/fork CI deliberately does not receive a
cross-repository token and does not misreport a skipped external checkout as a
real integration pass. The release gate separately runs the installed Matrix
wheel against detached exact provider/HMK commits and temporary real Wiki,
state, runtime and HMK SQLite roots. Its report must record the explicit real
integration count and pins.

No provider source is copied into the Matrix package. MPL-2.0 file/commit/hash
provenance and the no-copy decision are recorded in
`provenance/compaii-state-publisher-v1.json`.

## Deployment and rollback

Deployment is `N/A` for DM-035. All effects use synthetic isolated roots; no
live Wiki, state repository, Git remote or HMK database is changed.

Before any later canary, rollback disables the adapter and removes only unused
local queue/recovery state. After a publication exists, disable the writer and
issue a reviewed successor/tombstone or forward rollback through the same
transaction. Never delete Matrix request/receipt events, erase external audit
history, force-push, or restore a stale Wiki/state/HMK snapshot as authority.
