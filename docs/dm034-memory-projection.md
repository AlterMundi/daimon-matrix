# DM-034 personal-memory projection

Status: normative for `dm.memory-projection.* /v1`.

“Matrix” in this document means the `daimon-matrix` component. Matrix.org is
unrelated and is not a dependency.

## Outcome and authority

DM-034 projects the current accepted heads of `/me` personal-memory lanes into
Hermes Memory Kit (HMK) for retrieval. The Matrix ledger remains the sole
authority for the being, author, memory ID, category, event order, corrections,
retractions, classification and policy decision. HMK is an untrusted,
disposable view plus effect evidence.

The projection accepts only these Matrix categories:

- `personal-experience`;
- `personal-insight`; and
- `personal-skill`.

The event subject and `author_me_id` must both equal the hosted being. Peer,
external, tribal, species and incarnation records never enter this namespace.
An HMK row, title, tag, search rank, model output or matching text cannot create
or alter Matrix memory.

The exact supported HMK dependency is merge commit
`f10fd5c3089c0962920314c97e14bc024feffa7a`, API `1.0.0`, schema `1`, projector
`matrix:personal-memory-projector@1.0.0`. A different commit, API, schema,
projector or unknown field is unsupported rather than compatible by guess.

## Closed boundary

The DM-018 manifest advertises contract `memory-projection/v1` and these
capabilities:

```text
advance, inspect, project, rebuild-apply, rebuild-plan, retract, verify
```

The public adapter operation `project` maps an accepted Matrix assertion to the
HMK CLI's closed `apply` command. It is not a generic process runner. The
injected transport receives only one operation name and one canonical document;
it receives no path, SQL, database handle, endpoint, credential, private key,
session, prompt or unrelated evidence body.

Statement bytes cross the artifact boundary only after exact content-reference
validation. They must be NFC UTF-8 `text/plain` or `text/markdown`, between one
byte and 16 MiB, with the declared length and SHA-256. They remain inert data.

The stable HMK namespace identity is exactly:

```text
(source_instance, subject_me_id, projector_id, projector_version)
```

Projection identity adds `memory_id`. Domain-separated SHA-256 over canonical
JSON derives both IDs. Titles, slugs, shelves, tags, local chapter IDs, paths,
body sessions and semantic similarity never participate.

## Mapping and effect proof

An accepted Matrix `assert` maps to HMK `project`; `correct` maps to `advance`;
`retract` maps to `retract`. Every request binds:

- adapter and exact target versions;
- deterministic request ID and caller idempotency key;
- source instance, subject and author;
- memory ID and personal category;
- event ID, event content hash, sequence and exact predecessor;
- content reference or explicit retraction;
- projector identity; and
- the personal-memory-only Matrix checkpoint.

The checkpoint is derived from all known accepted personal-memory event
IDs/hashes for this being. Unrelated ledger events do not change it. A fork,
gap, regression, invariant change or incorrect predecessor makes the complete
personal lane unusable; the adapter never chooses a winner.

HMK returns a content-derived receipt. Matrix validates the complete request
hash, idempotency key, operation, target, namespace, projection, predecessor,
head, statement, checkpoint and HMK receipt ID. It then performs a fresh
`inspect` and compares current effect truth before persisting local success.

The resulting `dm.memory-projection.receipt/v1` repeats the source instance and
subject so its namespace and projection IDs can be recomputed without ambient
profile state. Its own ID content-addresses every field. Shape-valid substituted
IDs, heads or statement references fail before receipt-ID comparison.

## Recovery journal and concurrency

The owner-local SQLite journal stores exact canonical intent/request bytes and
either `pending` or `completed` state. It is recovery state, never memory
authority. Its parent, database and process-lock file must be regular,
owner-owned and inaccessible to group/other users.

An advisory file lock serializes projection/rebuild effects across threads and
processes sharing the journal. The operating system releases it after a crash.
SQLite uses `BEGIN IMMEDIATE`, `DELETE` journaling and `synchronous=FULL` for
durable state transitions.

| Failure point | Durable state | Recovery |
| --- | --- | --- |
| before journal reservation | no request | rebuild exact request from current head |
| after reservation, before HMK | `pending` | replay the byte-identical request |
| after HMK commit, before response | `pending` | HMK idempotency/effect truth, then fresh Matrix observation |
| after HMK response, before journal completion | `pending` | replay and re-observe; never trust cached response |
| after journal completion | `completed` | re-observe HMK and Matrix before returning cached receipt |
| HMK contradiction | either | return discrepancy; do not claim success |
| HMK unavailable | either | return retryable unverifiable state; do not claim success |

The same idempotency key with different event/intent/request bytes is a durable
conflict. An exact duplicate returns the same receipt only while current effect
truth still matches.

## Verified recall

Recall first verifies the complete namespace manifest against current Matrix
lanes, then inspects the requested projection and rechecks its current head.
Only an active exact match is presented. The returned origin states
`daimon-projection` and retains source instance, subject, author, memory,
category, event head, classification and projector.

Missing, stale, deleted, extra, content-drifted, checkpoint-ahead or
manifest-mismatched rows fail closed. Retrieval scores and embeddings do not
participate in verification. HMK keeps projection rows embedding-disabled and
generic HMK mutation/publication paths refuse them at the pinned boundary.

## Deterministic rebuild

`rebuild-plan` is non-mutating. It resolves current Matrix content, sorts active
heads by memory ID and asks HMK to produce a closed plan for one exact
namespace. The Matrix wrapper binds its checkpoint, expected manifest hash,
the canonical HMK plan hash and a content-derived Matrix plan ID.

Immediately before `rebuild-apply`, Matrix:

1. revalidates the wrapper and embedded HMK plan;
2. reconstructs the expected HMK request from the current ledger and content;
3. requires the same Matrix checkpoint and manifest;
4. recomputes target, namespace, entries and HMK plan identity;
5. applies through HMK's atomic namespace transaction; and
6. verifies the resulting complete namespace again.

An identical checkpoint/projector produces the same logical manifest even when
HMK's local generation advances. Rebuild replaces only the exact Daimon
namespace. It does not select a shelf, author, database or filesystem root and
does not touch HMK-native, Wiki-index, collective-memory or other projector
records.

## Existing-HMK dry run and cutover

DM-034 performs no live migration. Before a later canary, an operator uses an
isolated copy or synthetic workspace and follows this order:

1. Verify that the HMK checkout contains the pinned commit and that the logical
   target instance is the configured instance.
2. Initialize/upgrade HMK through its supported command, then capture
   `memoryctl.py stats`. Do not publish its `db_path`.
3. Take a SQLite backup through the backup API. On the backup, require
   `integrity_check=ok`, no foreign-key violations, record count-only origin
   classes and compute only backup byte length/SHA-256 for evidence.
4. Confirm the HMK projection `verify` query returns either the expected exact
   namespace or `projection_namespace_unknown`. On a fully initialized pinned
   database, both `stats` and an unknown-namespace `verify` leave database bytes
   unchanged; the integration test asserts this property.
5. Keep the LLM Wiki authoritative paths and the generated HMK projection-vault
   path disjoint. Refuse unresolved origin, title/namespace or path overlap.
6. Build the Matrix/HMK rebuild plan. `prior=null` is the expected first
   cutover. Planning must leave the source database digest unchanged.
7. Apply only into the dedicated derived namespace, verify the full manifest,
   and query a synthetic projected item through verified recall.
8. Re-run native/Wiki retrieval and count/integrity checks. No pre-existing row
   may disappear, change authority class or become a Daimon projection.

Existing HMK-native and Wiki-index rows are deliberately not imported into
personal lanes: they lack canonical `/me` authorship. A future import must use
the separate quarantine/source-decision protocol; it cannot be hidden in this
cutover.

Public evidence contains counts, booleans, stable IDs and hashes only—never
private statement text, paths, credentials, live database bytes or host
configuration. The checked-in vectors use synthetic text and identities.

## Rollback

Before any projection, rollback disables the adapter and retains/restores the
verified pre-cutover SQLite backup. After a projection has existed, do not drop
or reinterpret its HMK provenance/history tables. Disable the writer, preserve
the database as audit evidence and use a forward migration. If retrieval must
be cleared, apply a verified empty rebuild to the exact namespace or explicit
Matrix retractions; never delete by shelf/path/title.

Restoring the pre-cutover backup affects only HMK's disposable view. Matrix
events and decisions remain unchanged and can rebuild later. A failed or
partial rollback never makes HMK authoritative.

## Public artifacts and verification

Closed Draft 2020-12 contracts are in
`schemas/memory-projection/v1/contracts.schema.json`. Deterministic Matrix/HMK
interop vectors are in `vectors/memory-projection/v1/` and bind the HMK commit
in their index. Regenerate with:

```bash
python tools/generate_dm034_vectors.py
```

The real integration test invokes the pinned HMK CLI against temporary SQLite;
there is no mock or direct-SQL success path. Fault injection uses deliberate
SQLite corruption/deletion only to prove detection and repair. It covers
assert/correct/retract/recall, response loss, concurrent duplicates, conflicts,
effect-truth drift, rebuild deletion, pre-cutover backup/restore, native-row
survival, closed schemas and environment-independent vectors.

This card's deployment status is `N/A`: synthetic isolated HMK integration
only. Live CompAII state/cutover remains gated by later canary cards.
