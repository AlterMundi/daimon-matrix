# Origin-retaining memory policy

Status: normative for `dm.memory.* /v1` and `memory.recorded`.

This specification describes the Daimon Matrix component. It has no dependency
on, and does not refer to, the Matrix.org communication protocol.

## 1. Authority and scope

Daimon Matrix owns immutable memory-policy artifacts, deterministic admission,
the append-only memory lane and its exact local execution. It does not own the
bytes named by a content reference, a body's lifecycle, a Tribe's membership,
a species source, a human review, or an external publication effect.

The terms have these exact meanings:

- `known`: valid canonical evidence is present in the Weave ledger;
- `eligible`: the v1 policy permits an automatic local append at one exact
  checkpoint;
- `recorded`: an authorized `memory.recorded` event was durably appended;
- `effective` and `projected`: later projection decisions and adapter receipts,
  respectively. A record does not imply either state.

Transport, synchronization, database copy, restore, model output, prompt state,
an HMK/Wiki row, semantic similarity, repetition, popularity, a `/we` majority,
or a Cluster snapshot never creates memory authority.

## 2. Logical categories

The closed v1 category set is:

| Category | Required derivation | Author rule | Logical destination |
| --- | --- | --- | --- |
| `personal-experience` | `body-occurrence` | subject `/me` | `/me.memory` candidate |
| `personal-insight` | `local-synthesis` | subject `/me` | `/me.memory` candidate |
| `personal-skill` | `local-synthesis` | subject `/me` | `/me.memory` candidate |
| `peer-attributed` | `peer-origin` | retained peer | attributed knowledge |
| `external-reference` | `external-source` | retained source | attributed knowledge |
| `tribal-knowledge` | `tribe-retrieval` | retained Tribe authority | bounded cache |
| `species-inheritance` | `species-application` | retained species authority | inherited input |
| `incarnation-state` | `incarnation-observation` | retained subject/origin | embodiment state |

`memory.recorded` is the generic immutable lane record. It is not, by name
alone, proof of personal memory. Only the first three categories, with author
equal to subject and all other checks satisfied, may later enter a
`/me.memory` projection. The other five stay attributed under their original
authority and may only evidence a separately authored local insight or skill.

`local-synthesis` is valid only for `personal-insight` or `personal-skill`.
Every other derivation has the one-to-one category mapping in the table. There
are no aliases or extension categories in v1.

## 3. Closed artifacts

Every artifact is RFC 8785 canonical JSON, closed to unknown fields and bounded
before evaluation. Public schemas live in `schemas/memory/v1/`.

### 3.1 Policy

`dm.memory.policy/v1` binds the subject `/me`, monotonically increasing version,
exact predecessor policy ID, sorted automatic categories, sorted review
classifications, content ceiling and plan TTL. Its `policy_id` is SHA-256 over
the complete policy body under the `daimon/memory/policy/v1` domain.

Safety, consent, provenance, category mapping, fork behavior and reason
precedence are protocol invariants, not policy switches. A policy therefore
cannot disable review, introduce code, expressions, callbacks or aliases, lower
cryptographic rules, or hide provenance.

Version one has no predecessor. A successor has the same subject, version
`N+1`, and exact version `N` policy ID as predecessor. Succession never changes
the meaning or bytes of a prior candidate, decision, plan or event.

### 3.2 Content reference

`dm.memory.content-ref/v1` contains only a content ID, SHA-256, byte length,
media type and classification. The content ID is domain-separated over those
fields. Length is 1 through 16 MiB. A policy may impose a smaller ceiling.

It contains no path, URL, endpoint, query, credential, token, secret, executable
template, prompt or provider instruction. Retrieval belongs to the DM-018
artifact boundary. Consumers verify hash, length, media type and classification
before rendering or model use. Missing bytes remain explicitly unavailable;
they are never replaced by a summary or guessed content.

### 3.3 Candidate

`dm.memory.candidate/v1` binds subject, author, category, derivation, context,
content reference, complete sorted evidence references, classification,
consent, safety, contradiction, effect, body evidence and lane operation. Its
`candidate_id` content-addresses the complete body.

A successor candidate carries `predecessor_decision_id`. It is mandatory for
every correction/retraction and optional for an explicit reevaluation of a
sequence-one assertion. Thus a new decision never implies which earlier
decision it supersedes from timestamps or storage order.

Candidate data is evidence, not authority. A worker, model, Librarian, reviewer,
operator, adapter, projection, Cluster controller or remote embodiment cannot
become the personal author by writing its own identifier or the subject's name.

### 3.4 Checkpoint

`dm.memory.checkpoint/v1` is derived from one real Matrix ledger snapshot. It
binds being, active manifest, local origin, complete accepted ledger-state hash,
projection hash, available candidate evidence, body-evidence state, memory-lane
state and event IDs, optional exact linear head, and capture time.

`ledger_state_hash` covers the accepted authority epochs and every known or
incomplete event ID, content hash and status. RPC journal rows are deliberately
excluded: authenticating an evaluation or execution does not itself stale the
plan. Any canonical evidence or authority change does.

### 3.5 Decision and transition plan

The evaluator derives a `dm:memory-decision:v1:*` ID from the policy, candidate,
subject, checkpoint, evaluation/expiry times, outcome and reason codes. A
`dm.memory.transition-plan/v1` adds the exact event preview and content-addresses
the whole plan as `dm:memory-plan:v1:*`.

The decision ID is embedded in every eligible/review event preview and eventual
record, together with its predecessor decision when one exists. This gives the
canonical record a stable decision chain without a self-referential plan ID. A
plan contains no content bytes, secret or signature and grants no authority by
itself.

## 4. Body occurrence evidence

A `personal-experience` requires all of the following:

1. author equals subject `/me`;
2. derivation is `body-occurrence`;
3. body, embodiment and incarnation equal the hosted Matrix local origin;
4. a non-null committed cutoff event is in the candidate's evidence set and is
   known at the checkpoint;
5. that event was signed by the same exact origin and its payload binds the same
   `session_ref` and `lease_ref`.

An absent known cutoff is incomplete. A known origin/session/lease
substitution is invalid. A peer event may prove “I received E”; it cannot prove
that the receiving body experienced E. Cluster hosts and fences resources, but
Cluster evidence never becomes Matrix identity or memory authority.

## 5. Deterministic evaluation

The evaluator is pure. It performs no filesystem, database, network, clock,
randomness, model, subprocess, key, prompt, embedding, rendering or locale
operation. Policy, candidate, checkpoint and evaluation time are explicit.

After closed artifact validation, exactly one outcome is selected in this
normative precedence:

1. wrong subject: `rejected / wrong-memory-subject`;
2. content/candidate classification mismatch: `rejected /
   classification-mismatch`;
3. unavailable evidence: `deferred:incomplete / evidence-incomplete`;
4. false personal author: `rejected / false-personal-author`;
5. category/derivation mismatch: `rejected /
   category-derivation-mismatch`;
6. body/cutoff/session/lease mismatch: `rejected / body-evidence-mismatch`;
7. forked or inconsistent lane: `quarantined / memory-lane-*`;
8. unsafe content: `quarantined / unsafe-content`;
9. denied consent: `rejected / consent-denied`;
10. unknown consent, uncertain safety, sensitive contradiction, configured
    classification, public/destructive effect, or non-automatic category:
    `review-required` with its exact reason;
11. otherwise: `eligible` with no reasons.

A content reference above the policy ceiling is always rejected as
`content-limit-exceeded`. Evaluation time cannot precede checkpoint capture.
Inputs and reason lists are canonical, sorted where sets are represented, and
independent of database order, process hash seed, timezone and locale.

## 6. Memory lanes

A lane is named by a stable UUID `memory_id`.

- `assert` is sequence 1 with null predecessor event/hash and non-null content;
- `correct` is sequence `N+1`, names the exact sequence `N` event and content
  hash plus its policy decision, retains category/author/context, and supplies
  new content;
- `retract` has the same successor rules and null content.

Every `memory.recorded` successor also names the prior event through the Weave
`supersedes` field. History is never edited or deleted. Retraction changes only
the new head's active content semantics; all events, provenance and disclosure
history remain.

The checkpoint rebuilds the lane from every known embodiment/incarnation event
for the being. A lane is `empty`, `linear`, or `forked`. Duplicate roots,
duplicate sequence, gaps, wrong predecessor ID/hash, invariant drift or wrong
supersession make it forked. A fork retains all sorted event IDs, exposes no
head and quarantines every automatic successor. Arrival order, timestamp,
score, lexical ID/hash, policy preference and majority never select a winner.
An explicit successor protocol is required to resolve it.

## 7. Transactional execution

Only an `eligible` unexpired plan may enter `memory.execute`. The executor:

1. validates the complete plan, policy and candidate;
2. regenerates the exact plan at the recorded checkpoint and requires byte
   equality;
3. verifies that the subject is the hosted ledger being;
4. begins one SQLite `BEGIN IMMEDIATE` transaction;
5. compares the current complete ledger-state hash to the checkpoint hash;
6. signs and appends the exact `memory.recorded` preview with deterministic
   event UUID, causal evidence and supersession; and
7. records the local-operation idempotency receipt in the same commit.

Any state change before a new append returns `memory_plan_stale` without a
signature or event. The same exact request after commit returns the original
event even if later state changed. Changed bytes under one authenticated RPC ID
are a durable conflict. Loss of the response, daemon restart and exact retry
produce exactly one event and the stored authenticated response.

`review-required`, `deferred:incomplete`, `quarantined` and `rejected` plans
cannot be coerced through the automatic executor. DM-033 must later author a
separate content-bound review decision; editing creates a new candidate/plan.

## 8. Hosted interfaces

The owner-local authenticated runtime exposes only:

- `memory.evaluate {policy, candidate}`; and
- `memory.execute {policy, candidate, plan}`.

They are also available through typed `LocalClient` methods, `daimon memory
evaluate|execute`, and closed MCP tools `memory_evaluate|memory_execute`.
Capability methods remain explicit; adding these server methods does not expand
an existing Cluster capability. The Matrix host adapter's exact five-method
Cluster capability therefore remains unchanged.

Human input documents are bounded canonical JSON with duplicate-key rejection.
Durable CLI/MCP request files are owner-only exact retry tokens, not editable
queues or generic RPC escape hatches.

## 9. Projection and external effects

`memory.recorded` is canonical evidence. The generic DM-023 projection may list
it, but DM-030 performs no HMK/Wiki/database/publication effect. DM-034 now
projects only current, linear, locally authored personal heads through the
pinned HMK contract. It binds exact event head, content, Matrix checkpoint,
projector, target and idempotency bytes, then observes current HMK effect truth
before initial or cached success. Its HMK namespace is disposable and cannot
write back into this policy or ledger.

Public or destructive candidate effects always require review. Adapter ACK,
cached idempotency state or a prior receipt is insufficient if the current
observed postcondition contradicts it. Cluster remains responsible for body and
resource truth; Matrix remains responsible for the decision and canonical
event. Tribe transports exact envelopes and preserves origin; it does not adopt
or project them.

## 10. Privacy and limits

Policy explanations expose only stable outcome/reason codes and redacted
metadata. Plans, decisions, errors, logs, vectors and conformance reports
contain no private content bytes, credentials, paths, URLs, prompts, hidden
model state or unauthorized identity/membership detail.

V1 bounds are 16 MiB referenced content, 256 evidence references, 256 lane event
IDs, 86,400,000 ms maximum plan TTL, canonical safe integers and the existing
DM-011/DM-022 frame/event ceilings. Evaluation never follows evidence
recursively; the checkpoint reports only directly requested referents.

## 11. Successor policy and rollback

Creating a successor policy does not invalidate or reinterpret a prior plan.
Executing a plan with different policy bytes fails exact regeneration. Operators
may choose to stop accepting plans issued under an older policy through a later
policy-activation protocol, but cannot mutate historical bytes.

Before canonical use, rollback may remove unused code/schemas. After a decision
or record exists, rollback is another explicit successor/migration. It may not
delete decision history, rewrite lanes, lower checkpoints, choose a fork winner,
resurrect retracted/revoked content, or reinterpret an old record under a new
policy.

The DM-034 recall path verifies the complete HMK namespace against current
Matrix truth before presentation. Its rebuild is namespace-only and atomic;
HMK-native, Wiki-index and collective records remain under their original
authority and are never inferred as `/me` memory. See
`docs/dm034-memory-projection.md`.

## 12. Implementation boundary

DM-030 implements the pure evaluator, immutable artifact validators, exact
checkpoint builder, guarded ledger append, daemon/client/CLI/MCP surfaces,
schemas, vectors and synthetic tests. It does not implement a model worker,
human review queue, content store, memory renderer, HMK adapter, public
projection or live deployment. DM-031 now supplies only resource-scoped
curator coordination: immutable items, local generation CAS, exact actor origin
and Cluster-verified effect-truth replay. DM-032 through DM-036 consume both
boundaries without adding a being-wide lease or broadening memory authority.
DM-034 supplies the exact HMK projection/rebuild/verified-recall library and
synthetic installed integration; it does not perform a live CompAII cutover.

## 13. Normative conformance scenarios

Every row is release-blocking in `conformance/registry-v1.json` and names its
automated evidence there.

| Scenario | Required proof |
| --- | --- |
| `memory_body_authority` | exact body/session/lease/cutoff; substitution rejects |
| `memory_category_provenance` | every category retains derivation and author |
| `memory_deterministic_vectors` | schemas/vectors and environment-independent bytes |
| `memory_installed_surface` | installed CLI outcomes and durable exact retry |
| `memory_lane_fork` | correction/retraction history and no implicit fork winner |
| `memory_projection_effect_truth` | pinned HMK apply/replay plus fresh observed postcondition |
| `memory_projection_rebuild` | deterministic namespace rebuild and checkpoint-drift refusal |
| `memory_projection_migration` | read-only plan/backup, native preservation and reversible restore |
| `memory_policy_succession` | exact non-retroactive successor linkage |
| `memory_review_precedence` | total fail-closed outcomes; no automatic review bypass |
| `memory_stale_exact_once` | atomic stale guard and response-loss/restart exactly once |

Public deterministic vectors live in `vectors/memory/v1/`; their index binds
every artifact SHA-256. CI regenerates them and executes all scenarios against
source and the built wheel.
