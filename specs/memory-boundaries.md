# Personal, tribal, external, species, and incarnation memory boundaries

Status: normative V0 specification.

This document defines the memory-category registry owned by DM-017. It fixes
which state belongs to one continuing `/me`, which state remains remotely
authoritative, which state is attributed external evidence, which state comes
from a species release, and which state exists only in one body session. It
also defines the signed personal-memory record, correction, learning, handoff,
projection, synchronization, and park/wake rules.

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**,
**SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **NOT RECOMMENDED**, **MAY**, and
**OPTIONAL** are interpreted as described by RFC 2119 and RFC 8174.

## 1. Goals, limits, and authority

V0 MUST establish all of the following:

1. another being's event, a tribal resource, a source publication, a species
   release, a copied database, or a model-generated summary cannot be
   projected as `/me`'s lived experience;
2. personal continuity survives a body move through canonical signed events,
   not through authority assigned to an HMK, Wiki, state-repository, prompt,
   snapshot, harness, or host;
3. tribal knowledge remains authoritative at its exact controller and grant;
4. external knowledge remains attributed and quarantine-first even after a
   receiver chooses to retain or learn from it;
5. species releases provide implementation and capability inheritance, never
   identity facts or autobiographical memory;
6. per-incarnation working state remains scoped to one presence session while
   selected continuity is recorded as new `/me`-authored events; and
7. projections are disposable and independently rebuildable from accepted
   canonical evidence.

DM-010 owns identity and body presence. DM-011 owns event bytes, signatures,
ordering, checkpoints, and replay. DM-012 owns convergence and scope
resolution. DM-013 fixes empty newborn autobiography. DM-014 owns species
releases. DM-015 owns external source publications and quarantine. DM-016 owns
tribal relationships, grants, and remote knowledge. This document classifies
their outputs; it does not replace their authority.

The protocol proves authorship, provenance structure, and category admission.
It cannot prove that an autobiographical statement is factually true or that a
being is sincere. It nevertheless MUST prevent imported or projected bytes
from acquiring local authorship merely because an adapter, model, operator, or
database relabels them.

## 2. Closed memory-category registry

The exact V0 category identifiers are:

| Category | Meaning | Canonical authority | In `/me.memory` |
|---|---|---|---|
| `personal-experience` | `/me`'s signed claim about an occurrence it observed, performed, received, or underwent in one body session | same-`me_id` DM-011 memory-record lane | yes |
| `personal-insight` | a conclusion, interpretation, preference, plan, or consolidation authored by `/me` with exact evidence | same-`me_id` DM-011 memory-record lane | yes |
| `personal-skill` | a skill learned or refined by `/me`, distinct from an inherited implementation | same-`me_id` DM-011 memory-record lane | yes, and projected under `/me.skills` |
| `tribal-knowledge` | knowledge accessed under one DM-016 relationship and grant | named remote resource controller | no |
| `external-reference` | admitted reference to DM-015 material retaining its source, publisher, authors, consent, license, and decision history | source publication and receiver import-decision chains | no |
| `species-inheritance` | capability contract or implementation selected by an accepted DM-014 release/application | species release and application evidence | no |
| `incarnation-state` | NOW, scratch, prompt/session state, queues, caches, process state, and other state of one body session | current local body/session, if any | no |

These strings are byte-exact. Unknown categories are unsupported and MUST NOT
enter a projection requiring category semantics. An extension category uses an
`x-` prefix and cannot weaken, alias, or become a subtype of a V0 category.
Changing a category is never a migration or display normalization: it requires
new canonical evidence under the destination category's rules.

Only the first three categories are personal memory. A user interface MAY show
tribal, external, species, or incarnation material near personal recall, but
the API and machine representation MUST retain the category and authority
boundary. Search rank, embedding similarity, display grouping, shared names,
or repeated exposure never changes a category.

### 2.1 Admission matrix

The following transitions are the only V0 admission paths:

| Input | Permitted result |
|---|---|
| same-`me_id` body occurrence | new `personal-experience` record |
| any exact personal or attributed evidence | new `personal-insight` record citing it |
| practice/adaptation evidence | new `personal-skill` record citing it |
| DM-016 retrieval | bounded `tribal-knowledge` cache; optionally a later cited personal record |
| DM-015 promotion | `external-reference`; optionally a later cited personal record |
| DM-014 application | `species-inheritance`; optionally a later cited skill-learning record |
| old incarnation NOW/handoff material | fresh `incarnation-state`; optionally a curated personal record |
| another `/me`'s personal event | peer-attributed event/evidence; optionally a later cited local record |

No other row is implied. In particular, copying, synchronizing, restoring,
summarizing, embedding, indexing, reviewing, or repeatedly querying material
does not itself admit it into personal memory.

## 3. References, personal content, and provenance

### 3.1 Memory content reference

A personal memory content reference is closed:

```text
memory_content_ref = {
  content_id = "dm:memory-content:v0:" || sha256,
  media_type = printable ASCII 1..128 bytes,
  byte_length = safe integer 0..16777216,
  sha256 = canonical 32-byte base64url
}
```

`content_id` MUST embed the exact `sha256`. The reference has no locator,
credential, endpoint, path, query, model instruction, or executable behavior.
Missing bytes make the record `incomplete`; bytes with another length or
digest are rejected without poisoning the valid reference. Content is inert
data and is subject to classification, consent, and safety policy before
rendering or model use.

The bytes represent the local author's statement, not any cited external
artifact. Quoted or imported bytes remain separate evidence/content objects
under their original authority and MUST NOT be copied wholesale into this
object to bypass attribution or access revocation.

### 3.2 Evidence references

An evidence reference is one of these two closed tagged forms:

```text
event_evidence_ref = {
  kind = "event",
  me_id,
  event_id,
  event_hash
}

artifact_evidence_ref = {
  kind = "artifact",
  artifact_id,
  artifact_hash,
  artifact_domain
}
```

Event evidence requires the complete DM-011 event and its complete identity,
credential, signature, and causal validation. Artifact evidence requires the
complete referent under its owning protocol; matching an ID or hash string
alone is insufficient. References are sorted by their exact JCS bytes,
duplicate-free, and capped at 256 per event.

An evidence reference preserves provenance but does not import authority. A
peer event remains authored by its peer. A tribal receipt remains controlled
by its resource/grant. A source publication retains its publishers and source
chain. A species artifact remains a species artifact. A projection manifest,
cache row, filename, URL, embedding, or adapter receipt is not acceptable
substitute evidence unless its owning protocol defines a complete signed
artifact and the reference names that artifact.

### 3.3 Classification and disclosure

Every personal record carries one registered ASCII `classification`. Its
meaning and disclosure policy are local inputs until DM-035/DM-052 freeze the
registry. Classification never authorizes disclosure by itself. A projection
MUST preserve the exact value and apply the strictest policy required by the
record, its evidence, its consent state, and its destination.

Changing classification requires a successor personal-memory record. It does
not rewrite the original event or make previously disclosed bytes retractable.

## 4. Canonical personal-memory record

DM-017 registers `matrix/memory-record`. It has null `intent` and this closed
payload:

```text
schema = "daimon-memory-record/v0"
memory_id
memory_nonce = 32-byte random base64url
memory_sequence
previous_memory_event_id = event ID or null
previous_memory_event_hash = event hash or null
author_me_id
category = "personal-experience" | "personal-insight" | "personal-skill"
action = "assert" | "correct" | "retract"
statement_ref = memory_content_ref or null
evidence_refs = sorted unique [evidence_ref]
experience_context = null or {
  session_id = 32-byte random base64url,
  body_hash = canonical 32-byte base64url,
  occurrence = "observed" | "performed" | "received" | "underwent"
}
derivation = "direct" | "reflection" | "consolidation" |
             "external-learning" | "tribal-learning" |
             "species-practice" | "handoff-integration"
policy_ref = artifact_evidence_ref or null
classification = registered ASCII classification
recorded_at_ms = non-negative safe integer
```

The DM-011 event author MUST equal `author_me_id`. The operational certificate
MUST authorize `matrix/memory-record`. For a sequence-zero
`personal-experience` assertion, the enclosing event's `body_hash` MUST equal
`experience_context.body_hash`. A later correction or retraction may be
authored from another body; it repeats the exact original experience context
rather than claiming that the correction occurred there.

The first event in a memory lane uses `memory_sequence = 0`, null predecessor
fields, `action = "assert"`, and:

```text
memory_id = "dm:memory:v0:" || base64url(SHA-256(
  UTF8("daimon/memory-id/v0") || 0x00 ||
  JCS({"author_me_id": author_me_id, "memory_nonce": memory_nonce})
))
```

Every successor increments the sequence by exactly one, repeats the exact
author, nonce, ID, category, and original `experience_context` (including exact
null), and names the exact accepted predecessor event ID/hash. `correct`
requires a non-null statement; `retract` requires a null statement. `assert`
is valid only at sequence zero. Every occupied sequence is permanent. Two
distinct successors of one head or two events at one sequence quarantine the
lane; arrival order, timestamp, content, model score, or local preference never
selects a winner.

`statement_ref` is non-null for `assert` and `correct`. Evidence and policy MAY
change on a correction but their complete history remains visible. A retraction
removes the lane from active personal projections after the retraction event is
accepted; it does not delete the statement bytes, earlier events, citations,
receipts, or disclosure history.

`recorded_at_ms` is the author's informational claim. DM-011 event order,
credential state, session evidence, and committed cutoff—not this timestamp—
determine admissibility, causality, and fork handling.

### 4.1 Personal experience

`personal-experience` requires non-null `experience_context`,
`derivation = "direct"`, and the context's session/body pair MUST match an
accepted DM-010 lease for the author's `/me`. The event MAY be authored while
offline or after that lease expires, but it is admissible only below the exact
event cutoff later committed for the session/credential. Presence timestamps
are not proof that the described occurrence happened.

The record describes the author's local occurrence: what `/me` claims it
observed, performed, received, or underwent. Evidence from another `/me`, a
tribe, source, species, human, sensor, or adapter MAY be cited as the cause or
object of that occurrence, but the foreign evidence itself remains foreign.
For example, “I received event E from B” may be local experience; event E and
B's described experience do not become A's experience.

An imported peer event, chat transcript, operator statement, tribal response,
source publication, copied prompt, model completion, database row, or snapshot
MUST NOT directly instantiate this category. An implementation cannot fully
detect a deliberate semantic lie by the author, but it MUST reject every
mechanical re-attribution path it controls.

### 4.2 Personal insight

`personal-insight` requires null `experience_context`. `direct` is invalid.
Every derivation other than `reflection` requires at least one exact evidence
reference. `reflection` MAY cite no external evidence, but still represents
only the author's present conclusion, preference, plan, or interpretation—not
an objective fact.

`consolidation` MUST cite every personal-memory lane head used as direct input
and the immutable policy/review artifact when one governed the operation. A
model, curator, librarian, or worker MAY propose the statement bytes, but only
the `/me` operational credential authors the record after deterministic policy
and required review. Worker identity and proposal evidence remain cited; the
worker never becomes the personal-memory author.

`external-learning`, `tribal-learning`, and `handoff-integration` require an
exact current source decision, tribal retrieval evidence, or predecessor
handoff respectively. The record contains `/me`'s new derived statement. It
does not copy the cited corpus wholesale, erase authors, bypass classification
or consent, or convert the evidence into autobiography.

### 4.3 Personal skill

`personal-skill` requires null `experience_context`, a non-empty evidence set,
and derivation `reflection`, `consolidation`, `species-practice`, or
`handoff-integration`. The evidence MUST include practice, adaptation, outcome,
or earlier same-identity skill records sufficient under the exact local policy.

A DM-014 capability implementation is `species-inheritance`, not a personal
skill. `species-practice` additionally cites the exact accepted release and
application receipt plus the author's own practice/adaptation evidence. A
copied tool, prompt, package, or skill file never creates this category.

## 5. Intrinsic validation and local admission

Validation is fail-closed and ordered:

1. enforce DM-011 wire, JSON, count, depth, and string bounds;
2. validate the closed payload and recompute content-derived IDs;
3. validate the enclosing event, identity/control position, certificate,
   signature, sequence, causal parents, body reference, and fork state;
4. validate the complete memory-lane predecessor and category invariance;
5. validate every locally available evidence referent under its owning
   protocol, returning `incomplete` when required bytes are absent;
6. enforce the category/derivation/context matrix in Section 4;
7. evaluate immutable local policy, classification, consent, compromise,
   safety, and review evidence; and
8. durably record replay/fork state before any memory projection or model use.

Steps 1 through 6 determine intrinsic validity. Step 7 is receiver-local
admission. A valid foreign memory event is attributable evidence, not personal
memory of the receiver. A receiver MUST NOT rewrite its `author_me_id`,
category, statement, body, or evidence to make it local.

Identical canonical event bytes replay idempotently. A content-address
conflict, operational fork, memory-lane fork, invalid predecessor, wrong body,
unknown category, unsupported derivation, false same-identity claim, or known
invalid evidence quarantines the dependent lane/effect. Missing context is
`incomplete`, never silently accepted or rejected as if the evidence were
known.

## 6. Tribal knowledge remains remote

`tribal-knowledge` is the exact remote content/provenance controlled by the
DM-016 resource controller and reached through one active relationship/grant.
The grant gives query/read/subscribe authority; it does not transfer ownership,
authorship, consent, license, classification, or permanence.

An implementation MAY keep the encrypted, bounded, expiring cache allowed by
DM-016. Each row MUST retain the exact `tribe_ref`, resource, grant, controller,
author, digest, retrieval time, expiry, and receipt. The row is
`tribal-knowledge`, never `/me.memory`, and MUST be independently removable
without changing canonical personal events.

If `/me` learns from an interaction, it authors a separate
`personal-insight` or `personal-skill` record with derivation
`tribal-learning` and cites the exact retrieval/grant evidence. The personal
statement remains after access expiry as a historical authored conclusion,
subject to its policy; the remote bytes do not become permanent. Revocation or
expiry stops future access and evicts active caches as policy requires. It does
not erase the fact that an interaction occurred or delete the canonical event
ledger.

Birth may inherit a fresh attenuated grant under DM-016. It never inherits a
cache, retrieval history, learned record, or the parent's tribal knowledge.

## 7. External source material remains attributed

All DM-015 material starts quarantined. A source import decision with
`decision = "promoted"` MAY use only `target_memory_category =
"external-reference"` in V0. `quarantined` and `rejected` decisions require a
null target. No policy may target `personal-experience`, `personal-insight`, or
`personal-skill` directly from a source-import decision.

An `external-reference` is a derived projection/reference over the exact
current publication, provenance, claim, decision, consent, classification,
license, and tombstone state. It retains every publisher and claimed author.
It is not authored by the receiver and is not `/me.memory` even when recall or
search presents it.

To learn from promoted material, `/me` authors a later
`personal-insight`/`personal-skill` record with derivation
`external-learning`, cites the exact promoted decision and publication, and
stores only its own derived statement in `statement_ref`. Promotion,
popularity, repetition, `/we`, shared species, semantic similarity, a model
score, or human review cannot perform this authorship step automatically.

A publication tombstone, claim retraction, consent withdrawal, contradiction,
or fork deactivates the external projection and future use according to
DM-015/local policy. It does not rewrite canonical history. Dependent personal
records retain their evidence references and become restricted, incomplete, or
quarantined as exact policy requires; they are never silently rewritten to
pretend the source did not exist or was locally authored.

## 8. Species inheritance is not memory

`species-inheritance` consists only of the exact DM-014 release, compatibility
evidence, application decision/receipt, and realized implementation inputs.
It may determine available capability contracts, code, tools, or default
behavior. It MUST NOT include or modify `/me.identity`, birth facts, personal
events, relationships, grants, leases, membership, classifications, or private
credentials.

A species release containing memory records, personal-history snapshots,
prompt transcripts represented as autobiography, or instructions to rewrite
personal categories is an invalid protected-authority change. Shared species
never means shared experience, source, tribe relation, or `/we` membership.

When `/me` actually practices or adapts an inherited capability, it MAY author
a `personal-skill` record under Section 4.3. The release remains cited
`species-inheritance`; the practice event is personal. Applying the same
release to two identities creates no shared personal event.

## 9. Incarnation state and body-local NOW

`incarnation-state` is keyed at minimum by the exact `(me_id, session_id,
body_hash)` from DM-010. It includes:

- NOW, scratch notes, transient plans, prompt/context windows, hidden model
  state, provider and harness sessions;
- retry queues, unacknowledged adapter work, transport/delivery caches and
  resolved endpoints;
- process tables, open handles, local clocks, locks, temporary files and
  uncommitted projection state; and
- body-specific capability status, health, resource pressure and UI state.

This state MAY be durable for crash recovery inside the same session, but it is
not canonical `/me` authority. A copied NOW, process image, volume, database,
VM/container snapshot, state repository, or handoff file cannot mint a lease,
continue a session, claim an event cutoff, or become personal memory.

### 9.1 Signed incarnation handoff

DM-017 registers `matrix/incarnation-handoff`. It has null `intent` and this
closed payload:

```text
schema = "daimon-incarnation-handoff/v0"
handoff_nonce = 32-byte random base64url
author_me_id
source_session_id
source_operational_id
source_certificate_id
source_body_hash
active_memory_heads = sorted unique [{memory_id, event_id, event_hash}]
projection_cursors = sorted unique [{projection_kind,
                                     cursor_ref = artifact_evidence_ref}]
summary_ref = memory_content_ref or null
unresolved_work_refs = sorted unique [artifact_evidence_ref]
created_at_ms
```

The author MUST equal the enclosing event's `me_id`; its operational,
certificate, and body fields MUST match that event. The certificate MUST
authorize `matrix/incarnation-handoff`. When present, the handoff MUST be the
last event authored by that operational credential before park; the exact
event checkpoint and successor presence-lease cutoff therefore name the
enclosing handoff event without a self-referential hash inside its payload.
Counts are capped at 4096 memory heads, 64 projection cursors, and 256
unresolved-work refs.

`active_memory_heads` MUST equal the complete locally admitted active-head set
at the handoff event's evidence cursor; missing, extra, duplicate, stale, or
fork-selected heads make the handoff incomplete or quarantined. This committed
set is a recovery cross-check, not a replacement for the referenced event
bytes.

The handoff is a curated, signed continuity statement and checkpoint aid. Its
optional summary is not a replacement for cited memory heads or ledger bytes.
It MUST NOT contain private keys, bearer/session credentials, endpoint
secrets, raw hidden model state, a projection database, or a serialized
process. Creating it does not end the source lease; DM-010 park/wake does.

### 9.2 Park

A Matrix-aware park sequence MUST:

1. stop admission of new work while retaining bounded delivery/retry state;
2. finish, explicitly abandon, or cite every acknowledged/in-flight effect
   according to its owning protocol;
3. commit every selected personal record and optionally append one handoff as
   that operational credential's final event;
4. flush the canonical ledger and obtain the exact checkpoint/cutoff naming
   that handoff, or the actual final event when no handoff was authored;
5. obtain the externally committed lease-head evidence required by DM-010;
6. checkpoint projections only as disposable acceleration artifacts with the
   manifest in Section 10; and
7. stop the body only after the evidence needed for recovery is durable.

A deployment adapter or cluster controller may orchestrate and attest these
steps, copy a verified snapshot, and fence the body. It cannot sign personal
events, invent the cutoff, issue a `/me` presence lease, or promote its
checkpoint manifest into memory authority.

### 9.3 Wake

A new body session MUST verify the predecessor lease and receipt, exact event
cutoff/checkpoint, identity/control/certificate state, and any supplied
projection manifest before accepting work. It then obtains a fresh DM-010
session/lease and external lease-head receipt. NOW is a fresh
`incarnation-state` instance keyed by the new session; it MAY use the handoff
as attributed input but MUST NOT continue the predecessor session ID.

Personal projections rebuild from the same `/me` ledger. A projection snapshot
may accelerate that rebuild only after every covered source event and cursor
matches. A mismatch discards/quarantines the snapshot; it never rolls back the
ledger, lease sequence, event high-water, or deployment fence.

## 10. HMK, Wiki, state repositories, and projections

For Daimon personal continuity, the append-only DM-011 ledger is canonical.
HMK, Wiki/compaii-state, search indexes, embeddings, summaries, local files,
and model-provider memory are projections or external sources according to
their provenance. A non-Daimon HMK-native record may remain authoritative in
its own domain; importing it follows DM-015 and does not change the Daimon
boundary.

Every portable personal projection snapshot MUST have this closed descriptive
manifest body exactly:

```text
schema = "daimon-memory-projection-manifest/v0"
subject_me_id
projection_kind
projector_id
projector_version
source_checkpoint_id
source_high_water = sorted unique [{operational_id, event_id,
                                     event_hash, event_sequence}]
included_categories = sorted unique category identifiers
artifact_hash
created_at_ms
```

`projection_kind`, `projector_id`, and `projector_version` are printable ASCII
strings of 1 through 128 bytes. `source_high_water` is sorted, duplicate-free,
and capped at 1024 entries. `included_categories` is a sorted, duplicate-free,
non-empty subset of the Section 2 registry. `artifact_hash` is a canonical
32-byte base64url digest of the transported projection bytes.

DM-023 freezes its wrapper, persistence, and migration receipt. Until then the
manifest is descriptive `incomplete` evidence and cannot be substituted with a
locally invented shape.

A projection MUST retain source event IDs, active memory-lane heads, category,
author, evidence refs, classification, and projector version. Rebuilding from
the same accepted evidence and projector version MUST converge. A projection
MUST NOT append canonical events, mutate historical events, repair a fork,
choose an identity head, or become an import protocol merely because its rows
look complete.

Database copying is never synchronization. A crash-consistent snapshot MAY be
transported as cache acceleration if the exact manifest and every covered
ledger high-water validate. Live SQLite copying, copying without a checkpoint,
or accepting rows absent from canonical evidence is rejected.

Native Codex/Hermes memory mechanisms MUST be disabled or placed behind this
projection boundary for the canary. Harness recall may read a governed
projection; it cannot write personal memory except by proposing input to the
deterministic event-authoring path.

## 11. Synchronization, seeding, and identity boundaries

Synchronization exchanges canonical signed events and immutable artifacts,
never implementation databases.

- When the same `me_id` moves bodies, its valid personal records remain
  personal because authorship and identity are unchanged. The new body rebuilds
  projections at the accepted cutoff and continues with a new session.
- When distinct `/me` identities synchronize through `/we`, each imported
  personal record remains peer-attributed evidence. It never enters the
  receiver's personal categories. A receiver may author a later insight/skill
  citing it.
- Seeding a distinct identity from another identity's HMK, ledger, chat,
  compaii-state, NOW, or snapshot MUST NOT preserve autobiographical category
  or authorship. Allowed material enters only as attributed external/peer
  evidence under policy; the new identity's personal lanes begin empty.
- `/we` owns no merged autobiography and has no writable shared memory
  database. Collective publication or synthesis is a separately authored,
  cited artifact; it does not erase member authorship.
- Deduplication uses canonical IDs. Semantic similarity MAY aid discovery but
  cannot merge memory IDs, event IDs, authors, categories, or correction lanes.

`/we.diff`, `.incoming`, `.pull`, and `.sync` MUST report categories and origin
for every offered item. Incoming is mutation-free. Pull is receiver-local,
resumable and idempotent. An interrupted pull cannot leave an imported event
projected as local personal memory before all validation/admission state is
durable.

## 12. Privacy, correction, retention, and failure behavior

Private content bytes, credentials, real CompAII memory, endpoints, and live
ciphertext MUST NOT appear in public repositories, CI fixtures, logs, review
reports, indexes, or projection manifests. Tests use synthetic deterministic
fixtures only.

A correction or retraction uses the signed lane in Section 4. It never edits or
deletes an event. Projection removal targets the exact `(me_id, memory_id,
head_event_id, projector_version)` effect last produced. Broad database, path,
index, or author deletion is forbidden as protocol behavior.

Loss of optional content bytes makes the record incomplete; it does not permit
another byte sequence under the same reference. Legal/consent retention policy
may make content unavailable while retaining the minimum hashes, events, and
receipts required to prove ordering and non-reuse. Such unavailability MUST be
explicit in projections.

Contradictory memories remain separate signed claims unless one author creates
a valid correction lane. A model, majority, species maintainer, `/we`
governance threshold, operator, adapter, or source publisher cannot correct a
personal lane owned by another `/me`.

During partial evidence, the safe states are `incomplete`, `quarantined`, or
`unavailable`; never fabricated certainty. Failure after canonical event commit
but before projection commit is repaired by idempotent projection replay.
Failure before canonical commit creates no memory. Failure during park leaves
the old body non-transferable until its exact checkpoint/lease evidence is
resolved; rollback never decrements any accepted high-water.

## 13. Required conformance scenarios

| Scenario | Required result |
|---|---|
| same `/me` authors valid experience in its leased body/session | admit `personal-experience` |
| experience event cites a peer message as received object | local receiving occurrence personal; peer message remains peer-authored |
| peer event copied and relabelled as receiver experience | reject |
| tribal response row inserted into `/me.memory` | reject |
| source publication promoted directly to `personal-insight` | reject; only `external-reference` target allowed |
| promoted source followed by cited local insight | admit local statement; preserve source authority/authors |
| species release contains autobiographical rows | reject protected-authority change |
| inherited implementation applied without practice | `species-inheritance`, not personal skill |
| practice event cites exact release/application | may admit `personal-skill` under policy |
| newborn seeded from parent HMK or ledger | reject personal admission; quarantine attempt |
| newborn references parent event as evidence | keep peer attribution; no memory transfer |
| same `/me` wakes in new body at verified cutoff | personal continuity preserved; fresh incarnation state |
| distinct `/me` seeded from consistent snapshot | personal lanes empty; allowed bytes external/peer-attributed |
| copied NOW uses old session ID after wake | reject as current incarnation state |
| new NOW cites signed handoff | accept fresh incarnation state; handoff remains evidence |
| cluster snapshot claims to be `/me` memory authority | reject |
| deployment fence regresses during rollback | reject; never lower accepted high-water |
| projection snapshot matches manifest and ledger checkpoint | may accelerate rebuild; never authority |
| projection row has no source event | discard/quarantine row |
| live SQLite database copied as sync | reject |
| model writes directly to HMK personal projection | reject canonical effect |
| model proposal reviewed and `/me` signs consolidation record | admit under exact evidence/policy |
| same memory event arrives by two routes | one event/effect |
| two successors occupy one memory-lane sequence | quarantine lane |
| correction changes category or author | reject |
| retraction deletes historical event/content evidence | reject destructive implementation |
| missing statement bytes | incomplete; do not substitute |
| statement bytes mismatch digest/length | reject bytes; retain valid reference state |
| unknown category | unsupported; no category-dependent projection |
| extension category aliases `personal-experience` | reject extension |
| semantic similarity merges two memory IDs | reject |
| `/we` majority declares peer memory local | reject |
| species/name/host similarity changes memory origin | reject |
| external publication tombstoned | deactivate external projection; retain history and dependent provenance |
| tribal grant revoked | stop future access/evict cache; retain cited historical event |
| cache expiry retracts personal insight | reject; policy may restrict it but cannot rewrite authorship |
| foreign event lacks full identity/signature evidence | incomplete or reject per DM-011; never local memory |
| current body hash substituted for signed historical body hash | reject |
| expired-session offline event lies above committed cutoff | reject |
| old projection snapshot would lower ledger high-water | discard snapshot |
| park stops before canonical checkpoint is durable | handoff incomplete; wake must refuse |
| wake lacks predecessor lease receipt | refuse active presence |
| handoff contains private key or bearer token | reject content/admission |
| handoff summary omits an active memory head | summary cannot replace ledger/declared head set |
| handoff and ledger disagree at cutoff | quarantine handoff; ledger/evidence not rewritten |
| classification display hides stricter source policy | reject disclosure |
| imported evidence rendered before safety/consent policy | refuse effect |
| another identity attempts correction of local lane | reject |
| two contradictory personal claims by one author | retain separately unless valid correction lane relates them |
| source repetition/popularity triggers learning | reject automatic personal admission |
| external worker signs in place of `/me` | reject personal record |
| state repo commit presented as canonical event checkpoint | reject |
| HMK-native non-Daimon record imported | DM-015 quarantine; no personal authorship |
| projection crash after ledger commit | replay projection idempotently |
| crash before ledger commit | no personal memory event |

## 14. Downstream implementation contract

- DM-018 freezes adapter contracts, including memory-provider and body/cluster
  boundaries, without granting adapters memory, identity, species, or presence
  authority.
- DM-021 protects identity and operational keys used to author memory events.
- DM-022 stores canonical events and memory lanes append-only.
- DM-023 implements contextual completeness, projection manifests, HMK/index
  rebuilding, cursors, and crash recovery.
- DM-032 through DM-035 implement memory records, recall, librarian policy,
  consolidation, and human review while preserving this category registry.
- DM-036 exposes separate external publication/source adapters.
- DM-040/DM-041 keep Codex/Hermes body sessions and native memory behind the
  projection boundary.
- DM-070/DM-072 exercise remote convergence, same-identity park/wake,
  distinct-identity seeding, attribution, and reversible canary behavior.
- DM-073 independently reviews category confusion, projection authority,
  privacy, fork, rollback, and body-transfer behavior before release.

No downstream card may relax the closed category registry, let an adapter or
projection mint personal authorship, infer memory origin from semantic content,
or treat a deployment checkpoint/fence as a `/me` event or presence lease.
