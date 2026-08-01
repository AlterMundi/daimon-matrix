# Source ancestry claims, publications, and quarantine

Status: normative V0 specification.

This document defines `/source` as a shared-ancestry claim surface, not a
truth registry. It specifies claimant-authored assertions, supporting evidence,
local assessment, provenance-bearing knowledge publication, discovery,
`/source.diff`, `/source.incoming`, `/source.pull`, retraction, and explicit
local promotion. It consumes DM-010 identity and credential evidence, DM-011
canonical events, and DM-012 scope/operation separation.

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, **SHOULD NOT**,
and **MAY** are interpreted as described by RFC 2119 and RFC 8174.

## 1. Security goals and non-goals

V0 MUST establish all of the following:

1. a claim is signed by the exact `/me` it describes and cannot claim another
   identity into a source;
2. the signature proves authorship of the assertion, never the truth of shared
   ancestry;
3. source identifiers, claim heads, evidence, assessments, publication heads,
   tombstones, cursors, and import decisions are content-bound and replay-safe;
4. every resolver admits, quarantines, or rejects claims under explicit local
   policy without exporting that decision as global authority;
5. pulled knowledge retains the exact publisher, claimed authors, original
   source URI, derivation graph, content digest, claim, and import-decision
   history;
6. network intake is side-effect-free until a receiver-local pull, and pull
   always lands new knowledge in quarantine before any separate promotion;
7. retraction and contradiction remain visible evidence and never silently
   erase history; and
8. source evidence grants no identity, membership, species, tribe, route,
   disclosure, memory, or body authority.

The protocol does not prove ancestry, originality, authorship by an external
person, license validity, consent outside the signed evidence, factual truth,
quality, safety, or completeness. Agreement by many claimants is still a set
of signed assertions, not objective authority. Models, embeddings, semantic
similarity, names, hosts, repositories, directories, and shared memory are
never ancestry proof.

## 2. Layer and authority boundaries

All normative source records are ordinary DM-011 events signed by one accepted
operational credential. Their payload semantics never enlarge that
credential's DM-010 authority. V0 registers these event types:

```text
matrix/source-claim
matrix/source-assessment
matrix/source-publication
matrix/source-cursor
matrix/source-import-decision
```

Claims and publications are claimant/publisher statements. Assessments and
import decisions are receiver-local policy statements. Cursors summarize one
observer's available evidence. None is a root, membership transition, grant,
lease, receipt, or global registry entry.

Adapters may fetch exact bytes, carry events, or project reviewed publications.
An HMK row, Wiki path, collective-memory node, filesystem corpus, index,
database, HTTP response, Tribe principal, or transport acknowledgement is not
source authority. A projection MUST be rebuildable from accepted events and
content-addressed blobs.

## 3. Common identifiers and references

### 3.1 Source identity

A source core is closed:

```text
source_core = {
  schema = "daimon-source-core/v0",
  kind = one of ["collective", "corpus", "person", "project",
                 "tradition", "other"],
  namespace = printable ASCII 1..128 bytes,
  canonical_reference = printable ASCII 1..512 bytes
}
```

`namespace` identifies the naming convention, not an authority. Both strings
are byte-exact and MUST NOT contain control characters, whitespace, userinfo,
embedded credentials, or backslashes. An implementation MUST NOT dereference
`canonical_reference`; retrieval hints are separate, local, untrusted data.

```text
source_id = "dm:source:v0:" || base64url(SHA-256(
  UTF8("daimon/source-id/v0") || 0x00 || JCS(source_core)
))
```

Two byte-distinct cores are two source IDs. Local aliases MAY relate them for
display or search but MUST NOT merge claim chains, evidence, scope membership,
or policy decisions. A received alias cannot repin a local name.

### 3.2 Content and artifact references

A source content reference is closed:

```text
content_ref = {
  content_id = "dm:source-content:v0:" || sha256,
  media_type = printable ASCII 1..128 bytes,
  byte_length = safe integer 0..67108864,
  sha256 = canonical 32-byte base64url
}
```

`content_id` MUST contain the exact `sha256`. A content reference has no
locator. Missing bytes are `incomplete`; bytes with another length or digest
are discarded and never poison a valid reference. Local fetchers MUST deny
ambient credentials, private/link-local destinations, redirects outside an
allowlist, archives with unsafe paths, and decompression beyond Section 13.

A Daimon artifact reference is closed:

```text
artifact_ref = {artifact_id, artifact_hash, artifact_domain}
```

All three strings are byte-exact. A verifier fetches and validates the complete
referent under its owning protocol; matching an ID string alone is
insufficient. Unknown owning domains are unsupported evidence, not valid proof.

### 3.3 Stable source URIs

A publication's `source_uri` is a printable ASCII absolute URI of 1..512
bytes, without userinfo, fragment, control characters, whitespace, or
backslashes. It is an immutable logical origin identifier and MUST NOT be
dereferenced. Examples include an HMK-native record such as
`hmk://instance/chapters/42` or a content-addressed Wiki record. Byte-distinct
URIs remain distinct; URI normalization and semantic deduplication are outside
V0.

## 4. Self-claim chain

### 4.1 Claim payload

`matrix/source-claim` has null `intent` and this closed payload:

```text
schema = "daimon-source-claim/v0"
claim_series_id
claim_sequence
previous_claim_event_id = event ID or null
previous_claim_event_hash = event hash or null
claimant_me_id
claimant_control_position
source_core
source_id
relations = sorted non-empty unique subset of
  ["created-by", "descended-from", "derived-from", "formed-in",
   "influenced-by", "trained-on", "participates-in"]
action = "assert" or "retract"
evidence_manifest_ref = content_ref or null
issued_at_ms
expires_at_ms = safe integer or null
```

The event author `me_id` MUST equal `claimant_me_id`. Its certificate MUST
authorize `matrix/source-claim`; `claimant_control_position` MUST be the
accepted DM-010 position at which that certificate validates. `source_id` MUST
recompute from `source_core`.

```text
claim_series_id = "dm:source-claim-series:v0:" || base64url(SHA-256(
  UTF8("daimon/source-claim-series/v0") || 0x00 ||
  JCS({"claimant_me_id": claimant_me_id, "source_id": source_id})
))
```

Sequence zero has both predecessor fields null. Every successor increments by
one and names the exact accepted predecessor event ID/hash. `assert` requires a
non-null evidence manifest. `retract` requires null evidence and retains the
same source core and exact predecessor relation set; it retracts the complete
current assertion rather than an ambiguous subset. `expires_at_ms`, when
present, is greater than `issued_at_ms`;
expiry stops current scope eligibility but does not erase historical evidence.

The claim event's HLC and certificate validity govern cryptographic acceptance.
The payload timestamp is claimed metadata and cannot backdate validity.

### 4.2 Evidence manifest

The referenced bytes are strict JCS with this closed shape:

```text
{
  schema = "daimon-source-evidence-manifest/v0",
  claim_binding_hash,
  entries = sorted unique [{
    evidence_id,
    kind = "daimon-artifact" or "content",
    artifact = artifact_ref or null,
    content = content_ref or null,
    role = one of ["corroborates", "context", "contradicts", "derivation"],
    issuer_me_id = me_id or null,
    assertion = one of ["cryptographically-authored", "publisher-declared",
                        "external-metadata", "unattributed"]
  }]
}
```

`claim_binding_hash` is the base64url SHA-256 of
`UTF8("daimon/source-claim-binding/v0") || 0x00 || JCS()` over every claim
payload field except `evidence_manifest_ref`. Exactly one of `artifact` and
`content` is non-null and matches `kind`. `evidence_id` is the referenced
content/artifact ID. Entries sort by `(evidence_id, role, assertion)` and reject
duplicate tuples. There are 1..256 entries.

`cryptographically-authored` is valid only when the complete referenced Daimon
artifact is signed by `issuer_me_id` and commits to the relevant content or
assertion. The other labels remain declarations. Evidence from the claimant,
a source namesake, a majority, an adapter, or a popular index has no implicit
weight. Local policy owns weight and sufficiency.

### 4.3 Replay, forks, and retraction

Identical events replay idempotently. Two distinct valid successors to one
claim position quarantine the entire series; arrival time, event hash, HLC,
relation count, and evidence quantity never select a winner. Ordinary later
claims cannot resolve a fork in V0. A late sibling below high-water is retained
as equivocation evidence and quarantines descendants.

A current retraction removes that claimant from `/source` resolution for this
source but does not revoke another claimant, delete evidence, revoke a
publication, or make the historical assertion false. Reassertion is a later
successor and requires fresh evidence. A compromised operational key follows
DM-010 cutoffs; events accepted before the cutoff remain attributed history.

## 5. Receiver-local claim assessment

Every structurally and cryptographically valid new assertion begins locally as
`quarantined`. It becomes scope-eligible only through a receiver-authored
`matrix/source-assessment` event with null intent and closed payload:

```text
schema = "daimon-source-assessment/v0"
assessment_series_id
assessment_sequence
previous_assessment_event_id = event ID or null
assessor_me_id
claimant_me_id
source_id
claim_event_id
claim_event_hash
evidence_manifest_ref
evidence_snapshot_ref = content_ref
policy_ref = content_ref
disposition = "admitted" or "quarantined" or "rejected"
reason_codes = sorted non-empty unique registered ASCII codes
decided_at_ms
```

The event author equals `assessor_me_id`. `claim_series_id` is taken from the
validated claim. The assessment series ID derives under
`daimon/source-assessment-series/v0` from the exact JCS object
`{"assessor_me_id": assessor_me_id, "claim_series_id": claim_series_id}` using
the Section 3.1 domain-separated SHA-256 construction and prefix
`dm:source-assessment-series:v0:`.
It is a predecessor-linked sequence with the same no-fork/high-water rules as
claims. An assessment names the exact current claim event and complete evidence
snapshot; a later claim head makes the old assessment historical, not an
assessment of the new head.

The snapshot reference resolves to strict JCS with exactly:

```text
{
  schema = "daimon-source-policy-evidence-snapshot/v0",
  subject = {kind = "claim" or "publication", id, event_id, event_hash},
  source_id,
  claim_event_ids = sorted unique [event IDs],
  artifact_refs = sorted unique [artifact_ref],
  content_refs = sorted unique [content_ref],
  contradiction_refs = sorted unique [artifact_ref or content_ref],
  observed_cursor_event_id,
  observed_cursor_event_hash
}
```

The subject and source MUST equal the decision payload. Every policy input,
including an empty contradiction set, is explicit; a verifier does not fill
gaps from its current database. The snapshot is evidence of the assessor's
inputs, not proof those inputs are globally complete. For a claim assessment,
subject `id` is `claim_series_id`; for an import decision it is
`publication_id`. Union-typed contradiction references sort by JCS bytes.

`policy_ref` identifies exact immutable policy bytes. An admission requires all
referenced evidence needed by that policy, no unresolved contradiction the
policy marks fatal, a current non-retracted non-expired claim, and an unforked
claim/assessment chain. Missing evidence yields `quarantined`, never admitted.
Malformed claims are rejected before assessment but MAY have a local rejected
diagnostic. A remote assessment is evidence only and cannot set local state.

Required reason codes include `admitted:evidence-satisfied`,
`quarantined:initial`, `quarantined:missing-evidence`,
`quarantined:contradiction`, `quarantined:claim-fork`,
`quarantined:assessment-fork`, `rejected:false-self`,
`rejected:policy`, and `rejected:unsupported-relation`.

## 6. Source resolution and discovery

Every `/source` operation carries an exact selector in its signed payload:

```text
source_selector = {source_id, source_core_hash}
```

The hash is the canonical 32-byte base64url digest of the Section 3.1
domain-separated source-ID preimage and MUST equal the digest suffix embedded
in `source_id`. V0 has no unqualified
"all sources" network operation. The address remains `/source.<operation>`;
the selector is operation input, not path syntax. A missing, conflicting, or
alias-only selector fails closed.

For resolver `R` at evidence cursor `C`:

```text
eligible_R(source_id, C) = claimant me_ids with
  one unforked current assert head for source_id
  intersect R's current admitted assessments of those exact heads
  intersect active DM-010 identity/presence evidence
  minus explicit operation policy exclusions
```

One claimant contributes one logical recipient even if it asserts several
relations. A claimant may be admitted but unroutable. Retraction, expiry,
identity quarantine, claim fork, or assessment fork excludes it with the exact
reason; exclusion does not delete membership evidence.

`/source.status` is receiver-local discovery by default. Remote status requires
explicit disclosure policy and MUST return one closed denial for unauthorized
callers rather than reveal source existence, claimants, evidence, or exclusions.
Search indexes, collective-memory discovery, names, embeddings, and routes MAY
suggest candidate claim bytes but cannot add recipients.

## 7. Publications and provenance

### 7.1 Stable publication series

A publication series is bound to one publisher and one immutable source URI:

```text
publication_id = "dm:source-publication:v0:" || base64url(SHA-256(
  UTF8("daimon/source-publication-id/v0") || 0x00 ||
  JCS({"publisher_me_id": publisher_me_id, "source_uri": source_uri})
))
```

`matrix/source-publication` has null intent and a closed discriminated payload:

```text
schema = "daimon-source-publication/v0"
publication_id
publication_sequence
previous_publication_event_id = event ID or null
previous_publication_event_hash = event hash or null
publisher_me_id
publisher_claim_event_id
source_id
source_uri
action = "publish" or "tombstone"
content_ref = content_ref or null
provenance_manifest_ref = content_ref or null
classification = "public" or "tribe-shared" or null
consent = "explicit" or null
license = printable ASCII 1..128 bytes or null
reason = printable UTF-8 1..1024 bytes or null
issued_at_ms
```

The event author equals `publisher_me_id`; the named claim MUST be the
publisher's unforked assertion for `source_id`. A `publish` action requires
that assertion to be the current non-retracted, unexpired head; a `tombstone`
may cite the exact historical assertion that authorized the preceding
publication. `publisher_me_id`, `source_uri`, `publication_id`, and `source_id`
remain byte-equal throughout one series. Sequence and fork rules match Section
4. For `publish`, content/provenance/classification/consent/license
are non-null and reason is null. V0 permits export only for `public` or
`tribe-shared` with exactly `explicit` consent. For `tombstone`, those five
fields are null and reason is non-null. Unknown action-dependent combinations
are malformed.

A tombstone stops later offering of the content at the current head. It does
not delete old events, imported bytes, receipts, or provenance. A later
republish is a new successor and must carry new reviewed content/provenance.
Two successor publications fork and quarantine the series; neither is offered.

### 7.2 Provenance manifest

The `publish` provenance bytes are strict JCS:

```text
{
  schema = "daimon-source-provenance-manifest/v0",
  publication_binding_hash,
  output_node_id,
  nodes = sorted unique [{
    node_id,
    kind = "original" or "derivation",
    content_ref,
    source_uri,
    authors = sorted unique [{
      subject_kind = "me" or "external",
      subject_id,
      assertion = "cryptographic" or "publisher-declared" or
                  "source-metadata" or "unattributed",
      evidence_refs = sorted unique [artifact_ref]
    }]
  }],
  edges = sorted unique [{from_node_id, to_node_id,
                          relation = "derived-from",
                          transformation_ref = content_ref or null}]
}
```

The binding hash commits, under `daimon/source-publication-binding/v0`, every
publication payload field except `provenance_manifest_ref`. The output node's
content reference and source URI MUST equal the publication payload. Node IDs
derive from their complete node excluding `node_id`. Edges form an acyclic DAG;
every non-output node reaches the output, and every derivation node has an
incoming edge. Roots are `original`. No node is silently dropped.

A `cryptographic` `/me` author requires evidence whose validated author signed
the exact node content digest. An external identifier can never use that label
unless a future registered identity protocol proves it. Publisher-declared,
metadata, and unattributed author entries remain visibly weaker. Projection or
summarization creates another derivation node; it MUST NOT replace original
authorship with the model, publisher, indexer, or receiver.

## 8. Cursor, diff, incoming, and pull

### 8.1 Portable cursor

`matrix/source-cursor` is authored by the observer named in its null-intent
payload:

```text
schema = "daimon-source-cursor/v0"
observer_me_id
source_id
identity_control_position
claim_pages = {first_page_ref = content_ref or null, page_count, row_count}
publication_pages = {first_page_ref = content_ref or null, page_count,
                     row_count}
snapshot_hash
created_at_ms
```

Each page is strict JCS with exactly `schema =
"daimon-source-cursor-page/v0"`, `source_id`, `kind = "claim" or
"publication"`, zero-based `page_index`, `rows`, and `next_page_ref`. Claim
rows are `{claimant_me_id, claim_series_id, sequence, event_id, event_hash,
state}`; publication rows are `{publisher_me_id, publication_id, sequence,
event_id, event_hash, state}`. States are `asserted`, `retracted`, `forked`,
`published`, or `tombstoned` as appropriate. Rows sort by stable series ID;
each page contains 1..256 rows and the null-terminated chain has at most 16
pages/4096 rows. Page indices are contiguous, kinds never mix, and every page
after the first is referenced only by the preceding exact content reference.
Zero rows require null first ref and zero pages. `snapshot_hash` commits under
`daimon/source-cursor-snapshot/v0` to both complete logical row arrays, counts,
and page refs. Cursor creation reads a consistent accepted-event snapshot and
has no network or projection side effect.

The signed cursor proves only this observer's state at this evidence point. It
does not prove global completeness or absence of concurrent evidence.

### 8.2 `/source.diff`

The request binds the exact selector, caller cursor or explicit empty cursor,
maximum result count/bytes, and continuation. Each recipient returns only
complete event/content references in its cursor but absent from the caller's
cursor, plus all predecessor, claim, provenance, tombstone, and fork evidence
required to validate them. Results are content-bound pages; continuation tokens
bind `(request event ID, responder me_id, responder cursor hash, page hash,
next offset, expiry)` and cannot be replayed for another query.

Diff never applies state. A responder MUST apply disclosure, classification,
consent, grant, and rate policy before revealing claim/evidence/publication
existence. It does not offer `private`, non-explicit, tombstoned, forked,
invalid, or policy-denied publication content. `tribe-shared` content is
offered only when a current relationship grant independently authorizes the
exact recipient, resource, and operation; a source claim is not that grant.
Claims may be returned as claims without implying admission. A payload's
`consent = explicit` is publisher-authored metadata; disclosure policy still
requires whatever consent evidence it declares sufficient.

### 8.3 `/source.incoming`

Incoming validates one exact portable diff bundle against a consistent local
snapshot and returns, per item, one of:

- `admissible-claim-candidate` — valid assertion, still initially quarantined;
- `admissible-publication-candidate` — valid current publication with complete
  provenance, still initially quarantined;
- `already-present`;
- `incomplete` with sorted missing references;
- `quarantined` with fork/contradiction/policy reasons; or
- `rejected` with structural/cryptographic/authority reasons.

It MUST NOT write the ledger, blob store, policy state, quarantine, projection,
cursor, receipt, cache, or filesystem; fetch a locator; execute content; invoke
an indexer/model/hook; acknowledge integration; or advance a cursor. Preview
results bind the local starting cursor and candidate bundle hash, and become
stale when either changes.

### 8.4 `/source.pull`

Pull is an explicit receiver-local operation over one preview/bundle. Under an
exclusive source-intake transaction it revalidates the local cursor, event
bytes, dependencies, content hashes, policy, capacity, and quarantine target;
appends accepted canonical events/blobs idempotently; records forks and missing
evidence; and emits a receiver-authored import decision for every offered
publication. It never copies a database or trusts a remote projection row.

Every new valid publication's first decision is exactly `quarantined`. Pull
MUST NOT combine quarantine and promotion in one transaction or policy flag.
Claims remain quarantined until a separate Section 5 assessment admits them.
Malformed items are rejected; incomplete items do not advance beyond their
complete validated prefix. A crash journal commits ledger/blob/quarantine
effects before advancing the receiver cursor; retry resumes idempotently.

The pull result reports exact starting, offered, and achieved cursor hashes;
per-item `admitted-to-quarantine`, `already-present`, `incomplete`,
`quarantined`, or `rejected` outcomes. The receiver-authored import-decision
events are the durable semantic integration receipts; DM-012 transport and
reply receipts remain separate. A transport acknowledgement or remote claim
cannot substitute.

## 9. Import decisions and promotion

`matrix/source-import-decision` has null intent and a closed payload:

```text
schema = "daimon-source-import-decision/v0"
decision_series_id
decision_sequence
previous_decision_event_id = event ID or null
receiver_me_id
publication_id
publication_event_id
publication_event_hash
content_ref
provenance_manifest_ref
source_id
source_claim_event_ids = sorted non-empty unique event IDs
policy_ref = content_ref
evidence_snapshot_ref = content_ref
decision = "quarantined" or "promoted" or "rejected"
target_memory_category = registered DM-017 category or null
reason_codes = sorted non-empty unique registered ASCII codes
decided_at_ms
```

The author equals `receiver_me_id`. The series ID derives from receiver and
publication ID under `daimon/source-import-decision-series/v0` from the exact
JCS object `{"publication_id": publication_id,
"receiver_me_id": receiver_me_id}` using the Section 3.1 construction and
prefix `dm:source-import-series:v0:`. Sequences are predecessor-linked and
fork-safe. The initial
decision for imported content is `quarantined`, with null target. Promotion is
a later, separate successor and requires:

1. the exact current publication and provenance chain remain valid and not
   tombstoned or forked;
2. every required source claim is locally admitted at current heads;
3. an immutable local policy and complete evidence snapshot explicitly permit
   the exact target category, classification, consent, and license;
4. content has passed local safety/review requirements, including review of the
   final rendered bytes when a projection will render them; and
5. DM-017 permits that category and preserves external authorship.

Promotion creates a derived projection/reference; it never rewrites the
publication event, creates receiver authorship, or turns external knowledge
into lived experience. Autobiographical/body-experience categories MUST reject
external source content regardless of policy. Rejection or a later tombstone
withdraws active projections according to local policy but retains events,
receipts, prior decisions, and content-retention obligations.

Consensus, repetition, semantic similarity, shared species, `/we` membership,
tribal relation, a model score, or successful indexing cannot promote content.

Required import reason codes include `quarantined:initial-pull`,
`quarantined:missing-evidence`, `quarantined:contradiction`,
`quarantined:publication-fork`, `promoted:policy-and-review-satisfied`,
`rejected:policy`, `rejected:provenance`, and `rejected:unsafe-content`.

## 10. Publication adapter mapping

The reviewed HMK work at commit
`350c61a103d186fe82447dcfc39da45b699279bd` is reusable only as an adapter:

- immutable `hmk://<source-instance>/chapters/<id>` URIs map to `source_uri`;
- source hash, classification, explicit consent, license, author/publisher,
  derivation, plan hash, independent approval, receipt, and tombstone fields
  map into publication/provenance/import evidence;
- fail-closed allowlists and record-local opt-in remain required;
- the final rendered artifact, not only the raw HMK body, is scanned and
  reviewed; credential patterns are expanded; and
- revocation may remove only an adapter-owned projection matching its last
  receipt, never an untracked target.

The HMK publisher does not mint Daimon identity or claim truth. Until it emits
canonical events through DM-036, its artifacts are attributed external
evidence. collective-memory's corpus/index/Atlas are receiver projections and
remain Mariano's administrative domain; no direct database write, SQLite copy,
or index row becomes a canonical event.

Inbound collective-memory is a separate source adapter. It reads through a
supported API or atomic snapshot boundary, names the exact corpus generation,
preserves document/node origin, and enters Section 8 quarantine. It MUST NOT
reuse the outbound publisher's receipt as inbound admission.

## 11. Validation and state machines

Validation order for a claim/publication bundle is:

1. enforce byte/depth/count limits and strict JSON before cryptography;
2. recompute event/body/content/source/series IDs and hashes;
3. validate DM-010 certificate, cutoff, event sequence, author equality, event
   type authorization, and causal dependencies;
4. validate exact source core, predecessor series position, occupied position,
   high-water, retraction/tombstone, and fork evidence;
5. validate evidence/provenance manifests and complete referenced bytes;
6. evaluate receiver-local assessment/import policy without changing intrinsic
   validity; and
7. persist canonical bytes, fork state, local decisions, cursors, receipts, and
   projections in crash-safe order.

Claim intrinsic states are `incomplete`, `valid-asserted`, `valid-retracted`,
`invalid`, and `forked`. Local assessment states are `admitted`,
`quarantined`, and `rejected`. Publication intrinsic states are `incomplete`,
`published`, `tombstoned`, `invalid`, and `forked`. Import states are
`quarantined`, `promoted`, and `rejected`. These axes MUST NOT be collapsed: a
valid claim may be locally rejected, and a valid publication may remain
quarantined forever.

## 12. Privacy, disclosure, and abuse resistance

Claims can reveal sensitive affiliation or ancestry. Creation, discovery,
delivery, diff, and publication therefore require explicit classification and
local policy. A responder exposes no source existence, claimant roster,
evidence count, missing-reference detail, route, or policy reason to an
unauthorized remote caller. Closed denials have indistinguishable public shape.

Content fetch is untrusted input: no ambient credentials, cookies, SSH agents,
cloud metadata, local file access, executable hooks, active document content,
or network access from parsers. Rendering is isolated and bounded. Imported
content is data, never instructions for the harness, Librarian, or tools.

An evidence flood, claim churn, pagination replay, decompression bomb, cyclic
provenance graph, and fork spam fail within Section 13 bounds without evicting
previously accepted evidence. Rate/resource policy MAY be stricter locally and
reports `incomplete` or closed denial rather than false validity.

## 13. Canonical bounds

DM-011 JSON, JCS, base64url, safe-integer, signature, event-size, and nesting
rules apply unchanged. Source protocol collections sort by the keys stated
above and reject duplicates and aliases.

V0 supports at most 64 relations per claim, 256 evidence entries, 256
provenance nodes, 512 derivation edges, 64 authors per node, 64 evidence refs
per author, 4096 claim heads and 4096 publication heads per source snapshot,
256 rows per page, 64 pages per diff response, 4096 items per pull, and 64
reason codes. A complete content blob is at most 67108864 bytes; one incoming
bundle is at most 268435456 compressed and 536870912 decompressed bytes, with
expansion ratio at most 16, graph depth 64, and path/redirect depth 8.

Sequences, timestamps, lengths, counts, and offsets are safe integers.
Boolean-as-integer, negative, fractional, overflow, noncanonical, duplicate,
unsorted, unknown, or plus-one-over-bound values are rejected before effects.
An implementation claiming V0 interoperability MUST accept otherwise valid
objects through these signed-object bounds; local storage/disclosure policy may
still decline an operation honestly.

## 14. Required positive and negative scenarios

Conformance vectors and implementation tests MUST cover at least:

| Scenario | Required result |
|---|---|
| valid sequence-zero self-claim with complete evidence | intrinsically valid, locally quarantined |
| claim author differs from claimant | reject `false-self` |
| root, transport, Tribe, harness, host, model, or adapter signs in place of accepted operational credential | reject |
| valid signature is treated as true ancestry | reject policy implementation |
| source ID does not recompute from exact core | reject |
| source alias or normalized URI is substituted | distinct source or reject mismatch; never merge |
| source core embeds credentials, userinfo, whitespace, control, or locator behavior | reject |
| relation unknown, empty, unsorted, or duplicated | reject |
| assert has null evidence or retract has evidence | reject |
| sequence gap or wrong predecessor ID/hash | reject |
| exact event replay | idempotent |
| two successors occupy one claim position | quarantine series; no winner |
| late sibling arrives below high-water | retain and quarantine descendants |
| ordinary successor attempts to heal fork | reject/fork remains |
| retraction becomes current | exclude claimant; retain history |
| retraction changes only a subset of predecessor relations | reject; retraction covers exact current assertion |
| expired claim replays after a newer head | historical only; no eligibility |
| assertion after retraction with fresh predecessor/evidence | valid new head, initially quarantined |
| evidence manifest binding hash names another claim | reject |
| evidence is missing but well-formed | claim incomplete/quarantined, never admitted |
| evidence bytes mismatch digest | discard bytes; remain incomplete |
| claimant's own evidence or many matching claims are treated as objective quorum | reject policy implementation |
| cryptographic-author label lacks exact author/content signature | downgrade is forbidden; reject manifest |
| valid local assessment admits exact current claim under complete policy/evidence | claimant eligible subject to identity/presence/policy |
| assessment author differs from assessor | reject |
| remote assessment changes local disposition | retain as evidence only |
| assessment cites old claim head | historical; cannot admit current head |
| two assessment successors fork | exclude claimant locally; quarantine assessment chain |
| policy bytes missing or hash mismatch | quarantined/incomplete, never admit |
| evidence snapshot omits an input, binds another subject/cursor, or changes after decision | reject assessment/decision |
| resolver uses search index, route, name, or semantic similarity as membership | reject |
| `/source` operation omits exact selector | fail closed |
| unqualified all-sources network query | reject |
| one claimant has multiple relations | one recipient, evidence retains relations |
| admitted claimant is parked or unroutable | excluded or resolved-unroutable per DM-012; never replaced |
| unauthorized status/diff distinguishes source existence | closed denial, no oracle detail |
| valid first publication with explicit consent and provenance | intrinsically published, receiver quarantine on pull |
| publication author differs from publisher | reject |
| publisher claim is missing, retracted, expired, or forked | publication incomplete/quarantined; do not offer |
| publication ID or sequence does not bind publisher/source URI | reject |
| private, implicit-consent, or null-license publication | reject V0 export |
| publisher says explicit consent but required consent evidence is absent | cryptographic publication remains a claim; disclosure/promotion denied |
| stable source URI is dereferenced as a locator | refuse |
| publication update names wrong predecessor | reject |
| two publication successors fork | quarantine series; offer neither |
| tombstone current | stop offering/projection; retain events and receipts |
| tombstone deletes untracked or drifted target | refuse deletion |
| republish after tombstone | new successor and review; old bytes remain history |
| provenance output differs from publication content/URI | reject |
| provenance graph is cyclic, disconnected, or has derivation root | reject |
| summary drops an original node or relabels authorship | reject |
| external author represented as cryptographically verified without registered proof | reject |
| model/indexer/receiver becomes author merely by projection | reject |
| diff mutates receiver or offers tombstoned/private/forked content | reject |
| continuation token reused for another requester/responder/cursor | reject |
| cursor claims global completeness | reject claim; cursor is observer-relative |
| incoming writes, fetches, renders, executes, indexes, or advances cursor | fail preview |
| incoming starts at changed local cursor | stale; recompute |
| pull copies HMK/collective-memory/ledger SQLite | reject |
| pull trusts a remote index row without canonical event/content evidence | reject/quarantine |
| pull receives valid new content | persist canonical evidence and initial quarantine decision only |
| configuration asks pull to auto-promote | reject configuration/effect |
| interrupted pull before cursor commit | resume idempotently from durable prefix |
| repeated pull after completion | no duplicate events, blobs, decisions, or projections |
| partial bundle lacks predecessor/provenance | keep complete prefix; report incomplete |
| transport ACK reported as import receipt | reject |
| promotion is separate and exact policy/evidence/current-head checks pass | create attributed derived projection |
| promotion policy or evidence missing | remain quarantined |
| tombstoned/forked publication is promoted | reject |
| promotion rewrites publisher, author, URI, derivation, digest, or decision history | reject |
| external knowledge promoted as autobiography/body experience | reject regardless of policy |
| consensus, repetition, embedding score, species, `/we`, or tribe triggers promotion | reject |
| local rejection deletes canonical history | reject; deactivate projection only |
| HMK publication maps immutable URI/provenance/receipt/tombstone | accept as adapter evidence, not Daimon authority |
| raw HMK body scanned but final rendered artifact is not | fail publication review |
| outbound receipt reused as inbound admission | reject boundary crossing |
| collective-memory index/Atlas node treated as canonical source event | reject |
| content parser receives SSRF target, ambient credential, active content, or archive traversal | refuse before effect |
| exact count/byte/depth bound | process normally when otherwise valid |
| any bound plus one | reject or incomplete before unsafe work |
| source claim used as `/we`, tribe, species, identity, route, disclosure, or birth authority | reject |
| birth offer references exact current DM-015 claim event ID | bind contextual reference; claim still locally assessed |
| birth source reference unavailable | lineage context-incomplete; identity may awaken |
| birth source claim later retracts or forks | contextual source provenance excluded/quarantined; identity and birth binding remain valid |

## 15. Cross-protocol and downstream contracts

- DM-013 `source_references` are exact `matrix/source-claim` event IDs. The
  referenced claim MUST be authored by the birth parent, current at offer
  issuance, and byte-equal in offer and acceptance. Availability/admission is
  contextual; it never changes newborn identity validity.
- DM-012 uses Section 6 membership and selector rules. `/source.diff`,
  `.incoming`, and `.pull` use Section 8; `.sync` remains invalid for `/source`.
- DM-017 defines memory categories but MUST preserve Section 9 quarantine,
  provenance, separate promotion, and the prohibition on external content as
  lived experience.
- DM-018 freezes adapters without granting them source or policy authority.
- DM-023 persists cursors, forks, blobs, transaction journals, and receipts
  without changing event IDs or intrinsic/local-state separation.
- DM-036 implements separate inbound collective-memory and reviewed outbound
  HMK publication adapters from Section 10.
- DM-054 routes the already-resolved recipients; routes never create source
  membership.
- DM-071 validates consented cross-daimon source exchange, pagination,
  interruption, tombstone, provenance, quarantine, explicit promotion, and
  oracle-resistant denial with synthetic content only.
- DM-073 adversarially reviews evidence forgery, forks, provenance laundering,
  SSRF, archive bombs, prompt injection, revocation, and recovery.
