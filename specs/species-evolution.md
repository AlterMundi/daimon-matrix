# Species genomes, compatible releases, and speciation

Status: normative V0 specification.

This document defines a species as a compatible reproductive lineage, its
signed genome releases, deterministic compatibility and local application, the
read-only `/species.incoming` projection, and intentional incompatible
branching. It consumes DM-010 identity boundaries, DM-011 canonical artifacts,
DM-012 authority separation, and DM-013 birth enrollment without replacing any
of them.

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, **SHOULD NOT**,
and **MAY** are interpreted as described by RFC 2119 and RFC 8174.

## 1. Security goals and taxonomy

V0 separates three decisions that MUST NOT be collapsed:

1. **release validity** — signatures, chain position, governance, referenced
   bytes, and fork state;
2. **compatibility** — deterministic satisfaction of the predecessor's
   requirements plus the immutable DM-010 through DM-013 safety profile; and
3. **local application** — an explicit local policy decision over a compatible
   release and one exact content-addressed implementation bundle.

A maintainer signature proves authorization of artifact bytes, not
compatibility, safe execution, truth, popularity, or local consent. A package
registry, Git tag, CI result, harness, model, transport, host, filename, or
version display string proves none of those three decisions.

The protocol MUST establish:

- one stable `species_id` for one self-certifying genesis core;
- one ordered release chain with content-derived `species_release_id` values;
- predecessor-defined compatibility evidence that cannot rewrite `/me`, `/we`,
  personal history, memory, keys, credentials, leases, grants, relationships,
  body provenance, routes, authorship, or protocol authority;
- fail-closed maintainer rotation, replay, downgrade, fork, and resolution;
- side-effect-free incoming previews and transactional, reversible local
  activation of already verified compatible bytes; and
- a new species only from both parent-authorized intent and a deliberately
  incompatible child genome.

Species is lineage, not audience or identity. Shared species never grants
routing, disclosure, membership, relationship, source, tribe, birth, or
communication authority.

## 2. Canonical primitives, artifacts, domains, and roles

All signed objects use the DM-011 strict JSON/JCS model, generic mergeable
wrapper, content-derived key IDs, distinct-key threshold counting, and
authorization/possession separation.

| Artifact | ID | Domain | Authorization |
|---|---|---|---|
| species genesis | `dm:species-genesis:v0:<artifact-hash>` | `daimon/species-genesis/v0` | `species-genesis-authorization`, initial maintainer threshold |
| species release, including branch declaration and fork resolution | `dm:species-release:v0:<artifact-hash>` | `daimon/species-release/v0` | `species-release-authorization`, predecessor policy threshold |
| maintainer-key possession | no independent artifact ID | the enclosing genesis or release domain | `species-maintainer-possession`, every initial or replacement key |

The stable lineage ID is not a wrapper ID:

```text
species_id_preimage = UTF8("daimon/species-id/v0") || 0x00 || JCS(genesis_core)
species_id = "dm:species:v0:" || base64url(SHA-256(species_id_preimage))
```

Signed artifact IDs and hashes follow DM-011 Section 3 with their table domain.
Endorsement subsets over one body merge. The same typed ID with another body is
a content conflict.

Species maintainer keys are an Ed25519 role separate from every DM-010 root,
recovery, operational, transport, DM-013 birth-awakening capability key, and
member-identity root role.
Public-descriptor reuse is rejected. Cross-algorithm reused seed material is not
wire-detectable and remains a custody/conformance prohibition.

DM-014 registers `matrix/species-release-application` as an ordinary DM-011
event type. `/species.incoming` is a read-only operation result, not a new
signed authority artifact or event type.

## 3. Content references and genome

Every external byte set is named by this closed reference:

```text
content_ref = {
  content_id = "dm:species-content:v0:" || sha256,
  media_type = printable ASCII 1..128 bytes,
  byte_length = safe integer 0..67108864,
  sha256 = 32-byte base64url
}
```

Here `sha256` is the canonical unpadded base64url encoding of the raw 32-byte
SHA-256 digest, so `content_id` MUST equal that exact typed hash form. The
closed reference contains no locator. Locators, mirrors, and retrieval hints
stay outside canonical lineage artifacts, are non-authoritative, MUST NOT
contain credentials, and MUST NOT be dereferenced with ambient credentials.
Hash and length, not location, identify bytes. Missing well-formed bytes are
`incomplete`; wrong locator responses are discarded and leave the reference
incomplete. Only an internally contradictory signed reference/artifact is
invalid evidence.

The closed genome object is:

```text
genome = {
  root_me_definition = content_ref,
  capability_contracts = sorted non-empty unique [{contract_id, version, contract_ref}],
  protocol_requirements = sorted non-empty unique
    [{requirement_id, version, requirement_ref, bounds_ref}],
  compatibility_requirements = {
    required_suites = sorted non-empty unique [{suite_id, suite_version, suite_ref}],
    required_invariants = sorted non-empty unique
      [{invariant_id, invariant_version, invariant_ref}],
    required_contract_ids = sorted non-empty unique [contract_id],
    forbidden_authority_changes = sorted non-empty unique [invariant_id],
    resource_profile = content_ref
  },
  conformance_suites = sorted non-empty unique
    [{suite_id, suite_version, suite_ref}],
  implementation_invariants = sorted non-empty unique
    [{invariant_id, invariant_version, invariant_ref}]
}
```

IDs and versions are printable ASCII 1 through 128 bytes and sort by ASCII
bytes. Object arrays sort by their named ID; content-reference arrays by
`content_id`; files by normalized `path`; cases by `case_id`; release refs by
numeric epoch/sequence then ASCII artifact ID; and otherwise by canonical JCS
bytes. Every array rejects duplicates and aliases.

The root definition MUST commit to the maintained ontology, including the
corrected `/we -> distinct /me -> one active body per me_id` interpretation; a
raw superseded foundation paragraph alone is insufficient.

Every required contract ID MUST name a declared contract. Required suites and
invariants MUST be present in the corresponding conformance/implementation
sets. The non-empty forbidden set includes the DM-010 identity/history,
DM-011 event/authorship, DM-012 membership/authority, and DM-013 birth/memory
boundary invariants; a syntactically non-empty placeholder cannot replace them.

The genome MUST NOT contain `/me.identity`, a `me_id`, birth facts, personal or
body-experience events or memory, relationships, credentials, private keys,
leases, grants, memberships, body claims, routes, endpoints, ambient secrets,
or harness/provider state. A capability contract may describe code behavior; it
cannot confer protocol authority.

### 3.1 Closed executable manifests

Every JSON content object below uses strict DM-011 JSON/JCS, rejects unknown
fields, and is fetched only through its exact `content_ref`. Its media type is
`application/vnd.daimon.` followed by the shown schema with `/` replaced by
`.`, then `+json` (for example,
`application/vnd.daimon.species-suite-manifest.v0+json`). All `version` strings are
non-empty printable ASCII of at most 128 bytes.

An implementation bundle is a deterministic WASI file manifest:

```text
{
  schema = "species-implementation-bundle/v0",
  module = content_ref with media_type "application/wasm",
  entrypoints = sorted unique [{entrypoint_id, export_name}],
  files = sorted unique [{path, mode = "read-only", content = content_ref}],
  dependencies = sorted unique [content_ref of this same schema]
}
```

Paths are normalized relative UTF-8 paths; empty segments, `.`/`..`, absolute
paths, backslashes, aliases and Unicode normalization alternatives are
rejected. The dependency graph is acyclic and its complete closure is included
in the Section 12 limits. Dependencies are mounted read-only under
`/deps/<content_id>/`, with the typed prefix encoded as ASCII; they are never
merged into `/bundle`, never contribute implicit exports, and cannot shadow
root files. Duplicate dependency IDs or effective mount paths are rejected.
Testing and activation use this identical namespace.

The predecessor-selected resource profile is:

```text
{
  schema = "species-resource-profile/v0",
  execution_model = "wasm32-wasi-preview1-deterministic/v0",
  cpu_fuel = safe integer 1..1000000000,
  aggregate_cpu_fuel = safe integer 1..64000000000,
  case_count = safe integer 1..4096,
  wall_timeout_ms = safe integer 1..600000,
  aggregate_wall_timeout_ms = safe integer 1..3600000,
  memory_bytes = safe integer 1..1073741824,
  process_count = 1,
  thread_count = 1,
  stdout_bytes = safe integer 0..8388608,
  stderr_bytes = safe integer 0..8388608,
  filesystem_bytes = safe integer 0..536870912,
  file_count = safe integer 0..4096,
  network = "denied",
  clock = "fixed-zero",
  randomness = "denied",
  environment = []
}
```

Wall time is only a safety deadline: reaching it yields `incomplete`, never a
pass; the aggregate deadline bounds the complete verification run. CPU fuel,
memory, output and filesystem limits are deterministic failure
boundaries. A runner profile has exactly:

```text
{
  schema = "species-runner-profile/v0",
  runner_version,
  wasi_semantics_ref = content_ref,
  runner_conformance_ref = content_ref,
  resource_profile_ref = content_ref of species-resource-profile/v0,
  result_encoding = "daimon-test-result-jcs/v0"
}
```

A suite manifest has exactly:

```text
{
  schema = "species-suite-manifest/v0",
  suite_id,
  suite_version,
  runner_profile_ref = content_ref of species-runner-profile/v0,
  cases = sorted non-empty [{
    case_id,
    entrypoint_id,
    input_ref = content_ref,
    expected_result_ref = content_ref of daimon-test-result-jcs/v0
  }]
}
```

An invariant manifest has exactly:

```text
{
  schema = "species-invariant-manifest/v0",
  invariant_id,
  invariant_version,
  definition_ref = content_ref,
  runner_profile_ref = content_ref of species-runner-profile/v0,
  cases = sorted non-empty [{
    case_id, entrypoint_id, input_ref = content_ref,
    expected_result_ref = content_ref of daimon-test-result-jcs/v0
  }]
}
```

An execution result is the JCS encoding of the closed object
`{schema="daimon-test-result-jcs/v0", case_id, exit_code, stdout_base64,
stderr_base64}`. No host metadata, wall time, locale, clock, network result,
filesystem order, or random source enters it. The actual result bytes are put
in CAS and named by `actual_result_ref`; equality means byte equality with the
expected result. Runner/profile conformance is checked before candidate tests.

For each case the runner creates a fresh instance, mounts the declared bundle
files read-only under `/bundle`, supplies the exact `input_ref` bytes as stdin,
passes no argv or environment, invokes the bundle export named by
the unique manifest mapping for `entrypoint_id`, and captures exit
code/stdout/stderr into the result object. An absent, duplicate, or non-exported
mapping rejects the case.
No state survives between cases. Module traps are a deterministic failure;
wall-deadline exhaustion is `incomplete`; fuel, memory, output, or filesystem
limit exhaustion is `fail`. The exact WASI and runner conformance refs make any
implementation disagreement a runner failure rather than candidate success.

The genome's suite, invariant, protocol-bound, and resource-profile references
MUST resolve to the schemas above or to a closed requirement schema named by
their exact media type. A bare hash, CI URL, command line, image tag, package
version, mutable dependency resolver, or prose claim is not executable
compatibility evidence.

## 4. Species genesis

### 4.1 Genesis core and body

The closed genesis core is:

```text
genesis_core = {
  protocol_version = 0,
  cryptographic_suite =
    "DM0_HPKE_X25519_HKDF_SHA256_CHACHA20POLY1305_ED25519_JCS",
  domain_version = 0,
  species_nonce = 32-byte random base64url,
  genome,
  initial_maintainers = {keys: sorted Ed25519 descriptors, threshold},
  maintainer_floor = {minimum_key_count, minimum_threshold},
  origin = {
    kind = "primordial" | "branch",
    parent_branch_release = null or
      {artifact_id, artifact_hash, epoch, sequence},
    branch_foundation = null or Section 9 branch_foundation
  }
}
```

The closed signed body is:

```text
{
  schema = "daimon-species-genesis/v0",
  genesis_core,
  species_id,
  created_at_ms
}
```

`species_id` MUST recompute from the core. A primordial origin requires both
origin fields null and is a root fixture, not a claim of ancestry. A branch
origin requires both non-null and the referenced parent release MUST be a valid
`branch-declaration` release whose committed foundation is byte-equal. The
foundation is independent of the future declaration release ID, so the parent
release can commit its hash while the child core safely includes the resulting
parent release reference without a hash cycle.

Initial-maintainer endorsements sign the complete body. Genesis is accepted
only at release position `(epoch=0, sequence=0)` together with the Section 5
genesis release. Different threshold-valid genesis bodies for one core and
`species_id` quarantine that species; signature subsets over the same body
merge.

In addition to satisfying the initial authorization threshold, every declared
initial maintainer key MUST prove possession under
`daimon/species-genesis/v0` by signing that label, `0x00`, and the
raw genesis artifact hash. An unpossessed initial key leaves genesis pending
rather than installing a policy that may be impossible to operate.

Both floor values are safe integers from 1 through 32, the minimum threshold is
not greater than minimum key count, and the initial policy satisfies the floor.
Every later policy MUST continue to satisfy it.

For the genesis possession proof, `raw genesis artifact hash` means the raw
32-byte digest from the DM-011 body-hash computation, before base64url
encoding. The signed preimage is exactly:

```text
UTF8("daimon/species-genesis/v0") || 0x00 ||
base64url_decode(genesis_artifact_hash)
```

## 5. Ordered species releases

### 5.1 Body

The closed release body is:

```text
{
  schema = "daimon-species-release/v0",
  species_id,
  genesis = {artifact_id, artifact_hash},
  position = {epoch, sequence},
  previous_release =
    null or {artifact_id, artifact_hash, epoch, sequence},
  release_kind = "genesis" | "compatible" |
                 "branch-declaration" | "fork-resolution",
  release_label = printable ASCII 1..128 bytes,
  genome,
  implementation_bundle = content_ref of species-implementation-bundle/v0,
  compatibility_report,
  authorizing_policy_hash = 32-byte base64url,
  next_maintainers = {keys: sorted Ed25519 descriptors, threshold},
  branch_declaration = null or Section 9 branch_foundation,
  fork_resolution = null or {
    closed_epoch,
    common_predecessor = {artifact_id, artifact_hash, epoch, sequence},
    closure_cursor = {
      epoch,
      max_sequence,
      occupied_count,
      occupied_manifest_ref = content_ref of species-fork-closure-root/v0
    },
    competing_heads = sorted unique
      [{artifact_id, artifact_hash, epoch, sequence}]
  },
  issued_at_ms
}
```

The genesis release is `(0,0)`, has null predecessor, kind `genesis`, exact
genome equality with `genesis_core.genome`, genesis initial maintainers as both
authorizing and next policy, null branch declaration/fork resolution, and the genesis
compatibility report form in Section 6. Its `authorizing_policy_hash` equals
canonical base64url of
`SHA-256(JCS(genesis_core.initial_maintainers))`; its compatibility report has
null `base_release`, empty delta arrays, the exact genome hash, every
genesis-required suite/case and invariant result passing against the exact
release-zero bundle under its closed runner/resource profiles, and
`overall_verdict = "genesis"`. A failing, skipped, missing, indeterminate, or
nonconformant bootstrap run leaves release zero invalid/incomplete by the same
rules as Section 6. Genesis release endorsements are made by the
initial policy; the genesis artifact's all-key possession proofs establish
custody for that same initial policy before release zero becomes active.

A normal compatible release keeps the epoch, increments sequence by exactly
one, names the exact accepted predecessor, has null `branch_declaration` and
`fork_resolution`, and is authorized by the predecessor's `next_maintainers`.
`release_label`, timestamps, semantic versions, arrival order, chain length,
and hashes never choose a head. Section 9 defines the only valid non-null
`branch_declaration` form.

### 5.2 Maintainer rotation

`authorizing_policy_hash` MUST equal canonical base64url of
SHA-256(JCS(predecessor.next_maintainers)), or the genesis initial policy at
`(0,0)`. That predecessor policy authorizes the
complete candidate. Replacement keys cannot authorize their own installation.

If `next_maintainers` differs, every key in the replacement set MUST provide a
`species-maintainer-possession` proof over:

```text
UTF8("daimon/species-release/v0") || 0x00 ||
SHA-256(UTF8("daimon/species-release/v0") || 0x00 || JCS(release_body))
```

Possession proves control, not authorization. Missing any replacement proof is
pending/incomplete and never active. Duplicate/aliased keys, impossible
thresholds, cross-role reuse, authorization replayed as possession, and
possession replayed across bodies/domains are rejected. A threshold reduction
is valid only when explicit in the prior-quorum-authorized signed body and the
resulting key count and threshold remain at or above the immutable genesis
`maintainer_floor`; it is never inferred or relaxed by local policy.

Once a successor is durably accepted, its predecessor policy is retired for new
unoccupied release positions of every kind. Backdated timestamps do not reopen
it. A threshold-valid sibling at an already occupied historical position is
still retained as equivocation/fork evidence regardless of arrival time; it
never becomes current merely because it validates cryptographically.

The sole exception is Section 7's `fork-resolution` at a new epoch: the unique
last-unforked predecessor policy authorizes that specialized closure body even
though ordinary successors already occupied the forked epoch. Its closure
manifest, fresh all-key possession, and epoch rules are mandatory; the
exception cannot authorize an ordinary release or branch declaration.

## 6. Deterministic compatibility

### 6.1 Report schema

The closed compatibility report is:

```text
{
  schema = "daimon-species-compatibility-report/v0",
  base_release = null or {artifact_id, artifact_hash, epoch, sequence},
  candidate_genome_hash = 32-byte base64url,
  contract_delta = {
    added = sorted unique [contract_id],
    removed = sorted unique [contract_id],
    changed = sorted unique [contract_id]
  },
  protocol_delta = sorted unique
    [{requirement_id,
      prior_hash = 32-byte base64url or null,
      candidate_hash = 32-byte base64url or null,
      classification = "added" | "removed" |
                       "compatible-change" | "breaking-change"}],
  test_evidence = {row_count, root_ref = content_ref},
  invariant_evidence = {row_count, root_ref = content_ref},
  overall_verdict = "genesis" | "compatible" | "incompatible"
}
```

Evidence rows live in bounded CAS pages so a valid large suite cannot make the
signed 262144-byte release unrepresentable:

```text
evidence_root = {
  schema = "species-evidence-root/v0",
  kind = "compatibility-test" | "invariant" | "branch-test",
  row_count,
  pages = ordered [{page_index, row_count, first_key, last_key,
                    page_ref = content_ref of species-evidence-page/v0}]
}
evidence_page = {
  schema = "species-evidence-page/v0", kind, page_index,
  rows = sorted unique [kind-specific row; maximum 64]
}
compatibility_test_row = {
  suite_id, suite_version, suite_ref, case_id, runner_profile_ref,
  implementation_bundle_ref, input_ref, expected_result_ref,
  actual_result_ref,
  verdict = "pass" | "fail" | "skipped" | "indeterminate"
}
invariant_row = {
  invariant_id, invariant_version, invariant_ref, case_id,
  runner_profile_ref, expected_result_ref, actual_result_ref,
  verdict = "pass" | "fail" | "indeterminate"
}
```

Every `*_ref` in a row is the exact Section 3 `content_ref` required by its
name. Page indices start at zero and are contiguous; row counts and first/last
keys match. Test/branch keys are
`{suite_id,suite_version,case_id}` and invariant keys are
`{invariant_id,invariant_version,case_id}`. Concatenated rows sort by suite/version/case for tests and
invariant/version/case for invariants. The report count equals the root and
complete page count, and its root kind matches the report field. Missing pages
are `incomplete`; duplicate, omitted, extra, misordered, or cross-kind rows
reject evidence. Total compatibility-test plus invariant rows, and separately
branch-test rows, MUST NOT exceed the selected resource profile's `case_count`
or 4096.

### 6.2 Compatibility authority

Every hash is the unpadded base64url encoding of SHA-256 over the exact named
canonical bytes. `candidate_genome_hash` is `SHA-256(JCS(candidate genome))`
in canonical base64url and policy hashes are canonical base64url of
`SHA-256(JCS(policy))`; every executable input, output,
runner, bundle, suite, invariant and bounds object is carried as the Section 3
closed `content_ref`, not a bare digest. A report whose redundant hash or
reference does not recompute is invalid.

For each `protocol_delta`, hashes are canonical base64url SHA-256 of the exact
prior/candidate requirement entry JCS bytes; an absent side is null and both
null is invalid. Classification must agree with presence and the recomputed
manifest delta.

For a normal successor, the accepted predecessor's genome requirements and the
immutable DM-010 through DM-013 safety profile select the required contracts,
suites, expected outputs, bounds, and invariants. The candidate cannot select a
weaker suite, expected output, or policy to judge itself.

Compatibility requirements ratchet monotonically in V0. A compatible
candidate MUST retain every predecessor required contract, suite/version/ref,
invariant/version/ref, protocol requirement/bounds ref, forbidden-authority
entry, conformance suite, implementation invariant, the exact
`root_me_definition`, and the exact resource profile. It MAY add sorted new
requirements. Reusing an ID/version with changed
bytes, removing an entry, weakening a bound, or changing the resource profile
is incompatible and requires deliberate branching. Immutable DM-010 through
DM-013 safety invariants cannot be branched at all. This prevents release N
from deleting the checks that judge N+1.

`compatible` is valid only when a verifier:

1. recomputes every manifest, delta, dependency, and report hash;
2. obtains the exact immutable content-addressed bytes;
3. runs every predecessor-required deterministic suite in the Section 8
   sandbox against those same bytes;
4. obtains byte-equal expected and actual result bytes with only `pass`
   verdicts;
5. verifies every predecessor-required invariant; and
6. finds no protected authority, identity, history, memory, or schema change.

Missing well-formed bytes or a non-terminal run is `incomplete`. Bytes returned
by an untrusted locator that do not match a signed `content_ref` are discarded
as unauthenticated retrieval junk and leave that reference `incomplete`; they
do not poison the lineage. An internally inconsistent signed manifest,
substitution among valid signed refs, omitted actual changes,
failing/skipped/flaky/network-dependent or resource-exhausted tests, and
protected-invariant changes reject compatibility.
Maintainer signatures, remote CI, package metadata, and local override cannot
waive failure into compatibility.

Changing an identity/control/event/membership/memory/grant authority schema,
cryptographic domain or algorithm, or requiring new ambient privilege is never
a compatible update. Immutable identity/history/authority invariants are not
valid speciation deltas either.

## 7. Release state, high-water, forks, and resolution

Each verifier durably stores for each `species_id`:

- the last unambiguous accepted
  `(epoch, sequence, release_id, release_hash)` head;
- the greatest observed position and the closed-epoch high-water;
- the set of all valid artifacts observed at every occupied position;
- the last applied release and application receipt.

Replay of identical bytes is idempotent. A second valid body occupying one
normal position quarantines that epoch, every descendant, and local application
above the last unforked release. A late sibling below the apparent head has the
same result. No arrival, length, label, timestamp, or hash preference wins.

A release-zero/genesis fork has no unambiguous predecessor policy and is
terminal for that `species_id`; fork resolution cannot manufacture one. A new
attempt uses a fresh genesis/species nonce and therefore a new `species_id`,
while retaining the failed evidence.

A normal single-predecessor release cannot resolve a fork. A fork-resolution
release MUST:

- be authorized by the policy at the exact last unforked common predecessor;
- set `position = (closed_epoch + 1, 0)` and name that common predecessor;
- carry the closed signed manifest from the release body, whose
  paged occupied-position closure contains each selected fork path;
- provide a compatible report against the common predecessor for its resulting
  genome and bundle; and
- obtain fresh possession from every resulting maintainer key, even when the
  policy is byte-identical to the common predecessor's.

`competing_heads` contains at least two entries. `closed_epoch` is exactly the
forked open epoch and equals `closure_cursor.epoch`. The common predecessor is
the unique last unambiguous head immediately before every manifest path; it MAY
be in an earlier epoch when the fork occupies sequence zero. Every occupied
entry has that species/closed epoch and a sequence at most `max_sequence`. If
the common predecessor is in the closed epoch, every entry sequence is strictly
greater. If it is in an earlier epoch, every manifest root is sequence zero and
names that exact predecessor; descendants then increment normally inside the
closed epoch. Every non-root predecessor is another manifest entry.
`occupied_count` equals the complete page-set length and `max_sequence` equals its greatest
sequence. `competing_heads` is exactly the
sorted set of maximal manifest entries and each is valid/reachable. A healthy
chain, cross-species entry, nonmaximal head, gap, or fewer than two distinct
heads rejects the resolution.

Acceptance closes the old epoch: later old-epoch artifacts remain attributed
superseded evidence and cannot reopen it, whether a verifier saw them before or
after the closure. The manifest is an authorized closure decision over its
explicit inputs, not an unverifiable claim to contain globally known data; its
validity therefore never depends on local arrival order. Missing named bytes
are `incomplete`. Two resolution bodies for the same new epoch position fork
and quarantine the new epoch. Resolution never erases fork evidence.

The closure root and pages are exact Section 3 content objects:

```text
{
  schema = "species-fork-closure-root/v0",
  species_id, epoch, common_predecessor, occupied_count,
  pages = ordered [{
                    page_index, entry_count,
                    first_key = {epoch, sequence, artifact_id},
                    last_key = {epoch, sequence, artifact_id},
                    page_ref = content_ref of species-fork-closure-page/v0}]
}
{
  schema = "species-fork-closure-page/v0",
  page_index,
  entries = sorted unique [{artifact_id, artifact_hash, epoch, sequence,
                            previous_release}]
}
```

Pages contain at most 256 entries, indices start at zero and are contiguous,
ranges cannot overlap or gap in the concatenated entry order, and root/page
counts must match. The root's `species_id`, `epoch`, `common_predecessor`, and
`occupied_count` are byte-equal to the enclosing release species,
`closed_epoch`/cursor epoch, common predecessor, and cursor count; the cursor's
`occupied_manifest_ref` is the exact root content ref. Each first/last key is
byte-equal to that page's first/last entry ordering key. Sorting is numeric
epoch/sequence then ASCII artifact ID. Every page is fetched and its full predecessor closure is
validated before resolution; a missing page is `incomplete`. This permits a
late fork after thousands of releases without embedding the closure in the
262144-byte signed wrapper.

Before activation, ingestion and application MUST share one local transaction
or exclusive lock: persist occupied positions and fork state, recheck the head,
then switch the applied pointer. A sibling discovered after application freezes
at or rolls code back to the last unforked applied release without changing the
accepted evidence high-water or canonical personal history.

## 8. `/species.incoming` and compatible application

### 8.1 Read-only preview

`/species.incoming` is an unsigned deterministic projection, not release or
identity authority. The following references are closed:

```text
release_ref = {species_id, artifact_id, artifact_hash, epoch, sequence}
application_ref = {event_id, event_hash, application_sequence}
missing_ref =
  {kind = "content", content = content_ref} |
  {kind = "genesis", artifact_id, artifact_hash} |
  {kind = "release", release = release_ref} |
  {kind = "compatibility-evidence", content = content_ref}
conflict_ref =
  {kind = "release-position", epoch, sequence,
   artifacts = sorted unique [{artifact_id, artifact_hash}]} |
  {kind = "application-position", application_sequence,
   events = sorted unique [{event_id, event_hash}]}
```

One preview page is exactly:

```text
{
  schema = "daimon-species-incoming-result/v0",
  snapshot_core = {
    subject_me_id,
    species_id,
    enrollment_release_id,
    effective_applied_release = null or release_ref,
    application_head = null or application_ref,
    registry_cursor = {
      accepted_head = null or release_ref,
      greatest_observed = null or {epoch, sequence},
      closed_epoch_high_water = null or
        {closed_epoch, resolution_release = release_ref},
      occupied_positions_hash = 32-byte base64url
    },
    selected_candidate = null or release_ref,
    path_page = {
      page_index = safe integer,
      start_release = null or release_ref,
      releases = ordered contiguous [release_ref; maximum 64],
      end_release = null or release_ref,
      continuation_release = null or release_ref
    },
    evidence_closure_hash = 32-byte base64url,
    state = "current" | "compatible-behind" | "diverged" |
            "incomplete" | "quarantined",
    application_eligible = boolean,
    missing_refs = sorted unique [missing_ref],
    conflict_refs = sorted unique [conflict_ref],
    reason_codes = sorted unique [
      "application-fork" | "fork" | "invalid-selected" |
      "local-veto" | "missing-content" | "missing-release" |
      "missing-suite" | "not-opted-in" | "other-lineage" |
      "path-continues" | "stale-cursor" | "unmanifested-runtime"
    ]
  },
  snapshot_hash = 32-byte base64url
}
```

Release and event references validate their typed ID/hash and exact position.
Tagged missing/conflict unions sort by ASCII `kind` then JCS bytes and reject
duplicates; path arrays alone preserve predecessor order.

`snapshot_hash` is
`base64url(SHA-256(UTF8("daimon/species-incoming-snapshot/v0") || 0x00 ||
JCS(snapshot_core)))`; it never includes itself. `occupied_positions_hash`
uses the same formula with domain `daimon/species-observed-positions/v0` and
the sorted occupied release refs. `evidence_closure_hash` uses domain
`daimon/species-evidence-closure/v0` and the sorted exact content refs actually
verified. These three labels are registered DM-011 separation domains.

For portable application evidence, the occupied refs behind that hash are
stored as content-addressed pages:

```text
{
  schema = "species-observed-positions-root/v0",
  species_id, occupied_count,
  pages = ordered [{page_index, entry_count,
                    first_key = {epoch, sequence, artifact_id},
                    last_key = {epoch, sequence, artifact_id},
                    page_ref = content_ref of species-observed-positions-page/v0}]
}
{
  schema = "species-observed-positions-page/v0",
  page_index,
  entries = sorted unique [release_ref; maximum 256]
}
```

Indices/counts/ranges follow Section 7's exact page rules. Concatenated entries
recompute `occupied_positions_hash`; missing pages make application evidence
incomplete.

Pages are not offsets. Page zero starts at the effective applied release (or
the enrollment release when no application exists); each continuation names
the exact next release and repeats the same registry cursor, selected candidate,
and evidence-closure hash. Any cursor change invalidates the page set. The
`start_release` is the exclusive predecessor anchor; `releases` contains its
successors. `page_index` starts at zero and increments by one; `end_release` is
the last listed release or equals the start for an empty current/bootstrap
page; `continuation_release` is the exact next successor and the next page
starts at the prior end. Null start is allowed only while enrollment release
evidence is missing. The complete path is the ordered concatenation through a
null continuation. Application is
ineligible while `path-continues` is present. Before any decision, the verifier
stores exact preview pages and evidence as this closed content object:

```text
{
  schema = "species-application-verification/v0",
  mode = "bootstrap" | "forward" | "rollback",
  subject_me_id, species_id, enrollment_release_id,
  from_release = null or release_ref,
  to_release = release_ref,
  implementation_bundle_ref = content_ref,
  forward = null or {
    snapshot_page_refs = ordered non-empty
      [content_ref of daimon-species-incoming-result/v0],
    observed_positions_manifest_ref =
      content_ref of species-observed-positions-root/v0,
    evidence_refs = sorted unique [content_ref]
  },
  rollback = null or {
    reason = "runtime-failure" | "release-fork",
    current_snapshot_ref = content_ref of daimon-species-incoming-result/v0,
    observed_positions_manifest_ref =
      content_ref of species-observed-positions-root/v0,
    current_application = application_ref,
    target_application = application_ref,
    target_runtime_manifest_ref = content_ref
  }
}
```

`bootstrap` and `forward` require non-null `forward` and null `rollback`;
`rollback` requires the inverse. Snapshot page contents, hashes, cursor,
continuations, selected target, bundle, occupied-position pages and
evidence-closure hash all recompute;
`evidence_refs` is the exact sorted preimage behind that closure hash. The
verification manifest's own `content_ref` makes the historical decision
portable after registry state advances. Bootstrap is restricted to the exact
enrollment target. Rollback additionally proves that `target_application` is a
prior accepted `applied` event for the retained target/runtime and that the
fresh current snapshot matches the reason. `runtime-failure` requires a
nonforked valid snapshot. `release-fork` requires its quarantined fork/conflict
refs and targets exactly the last-unforked previously applied ancestor.

State precedence is total: a cryptographically valid sibling, unresolved fork,
accepted-evidence contradiction, invalid selected candidate, or application
fork → `quarantined`; else missing required bytes/evidence → `incomplete`;
else a valid other deliberate lineage or unmanifested local implementation →
`diverged`; else exact effective applied head → `current`; else a strict
fully verified compatible descendant path → `compatible-behind`. Rejected
unauthenticated or structurally invalid junk does not poison an otherwise valid
lineage. Local veto changes `application_eligible`, not compatibility state. A
response below durable high-water cannot report current or behind.

Preview performs no install, hook, test side effect, network fetch with ambient
credentials, ledger write, cursor advance, or policy mutation. Authorization
for the request may restrict disclosure; errors MUST NOT become a lineage or
capability oracle. A remote result is carried as data in an ordinary DM-012
signed `matrix/reply`; that event authenticates the responder and reply binding,
but does not turn the projection into species-release authority.

### 8.2 Application

Compatible auto-application additionally requires explicit local opt-in. The
verifier runs with no keystore, identity ledger, HMK, grants, routes, network,
ambient credentials, device nodes, or host-write access. It enforces declared
CPU, wall-time, memory, process, output, file-count, path-depth, dependency-depth,
fan-out, compressed/decompressed byte, and expansion-ratio limits. Archives
with traversal, absolute paths, symlinks, hardlinks, devices, cycles, or bombs
are rejected before execution.

Testing and activation MUST use the same CAS digests. The activated code remains
inside the same capability-brokered runtime: no raw keystore, ledger, HMK,
grant, membership, route, network, ambient credential, device, or host-write
access, and only the subject's exact pre-existing body capability grants. A
release cannot expand that profile; requested expansion is incompatible and
requires separate non-species authorization.

Activation switches one local code/config pointer and retains a rollback
pointer. It runs no irreversible migration or install hook and writes no
canonical state except one ordinary DM-011 event of type
`matrix/species-release-application`:

```text
{
  schema = "daimon-species-release-application/v0",
  subject_me_id,
  species_id,
  enrollment_release_id,
  application_sequence,
  previous_application = null or {event_id, event_hash, application_sequence},
  from_release = null or release_ref,
  to_release = release_ref,
  implementation_bundle_ref = content_ref,
  verification_manifest_ref = content_ref of species-application-verification/v0,
  local_policy_ref = content_ref of daimon-species-local-application-policy/v0,
  prior_runtime_manifest_ref = null or content_ref of species-runtime-manifest/v0,
  resulting_runtime_manifest_ref = null or content_ref of species-runtime-manifest/v0,
  result = "applied" | "vetoed" | "rolled-back" | "failed",
  applied_at_ms
}
```

The event author MUST equal `subject_me_id`; its DM-011 `causal_parents` MUST
include the previous application event ID when non-null. `enrollment_release_id`
is constant and byte-equal to the subject's DM-010 genesis
`species_release_id`; `species_id` is constant and recomputes from that exact
DM-014 release. Sequence is monotonic per subject/species, begins at
zero with null predecessor, and increments by one while naming the exact
predecessor. A content-addressed runtime manifest contains the exact release,
bundle, code/config pointer digest, and capability-grant-set hash. Its closed
JCS object is `{schema="species-runtime-manifest/v0", release=release_ref,
implementation_bundle_ref=content_ref, code_config_pointer_digest,
capability_grant_set_hash}`. The local policy is the closed JCS object
`{schema="daimon-species-local-application-policy/v0", auto_apply,
allowed_species=sorted unique [species_id], resource_profile_ref,
policy_version}`. Both digest/hash fields are 32-byte canonical base64url;
`code_config_pointer_digest` equals the exact implementation-bundle ref's
SHA-256 digest, and `capability_grant_set_hash` is SHA-256 over JCS of the
sorted exact pre-existing capability grant IDs/refs exposed by the broker.
`policy_version` is printable ASCII 1..128 bytes. The policy is not species
authority; its exact content reference only
makes the local decision auditable. Both objects use the Section 3 strict JCS
and media-type rules and reject unknown fields. Automatic application requires
`auto_apply=true`, the exact species in `allowed_species`, and a local resource
profile able to enforce every signed predecessor ceiling.

The deterministic transition table is:

| Result | Required transition | Effective release after event |
|---|---|---|
| first `applied` | `from_release=null`; target is exact enrollment release and runtime is actually active | enrollment release |
| later `applied` | from current effective release to selected same-species strict compatible descendant bound by the complete forward verification manifest | target |
| `vetoed` or `failed` | target is the verified candidate; prior/resulting runtime manifests are byte-equal; pointer unchanged | prior effective release |
| `rolled-back` | rollback manifest binds current head and prior target/runtime; runtime failure needs a valid snapshot, release fork needs its quarantined conflict snapshot and last-unforked target; never below enrollment | rollback target |

Until the first applied enrollment event exists, the identity is
`incomplete` or `diverged` for `/species` resolution even if its independent
identity is active. A child species cannot enter this chain through application
in V0. Wrong species/enrollment, gaps, downgrade outside rollback, target not
bound by the verification manifest, bundle mismatch, or effective-runtime mismatch rejects
the event. Sibling application events quarantine only this realization chain,
never `/me`; the operational key does not authorize releases.

Filesystem and ledger durability use a fenced recovery journal: stage and
fsync bytes; durably write a prepared local journal; switch and fsync the
pointer while the candidate remains non-serving; append and fsync the signed
application event; then mark committed and un-fence. A crash before pointer CAS
leaves the prior runtime. A crash after CAS but before the event rolls back on
recovery (or deterministically completes the exact prepared event before any
serving). A crash after the event completes commit/un-fence idempotently. The
event ledger is authoritative for external projection; no unrecorded candidate
serves requests. Exact replay is idempotent. Rollback never regresses release
evidence/high-water or rewrites genesis, enrollment, events, memory, or
authorship. Old release replay never reruns effects.

## 9. Ordered branch declarations

Intentional branch declarations occupy the parent's single total release chain;
there is no arrival-ordered side-chain. The closed foundation object is:

```text
branch_foundation = {
  schema = "daimon-species-branch-foundation/v0",
  parent_species_id,
  parent_base_release = release_ref,
  branch_nonce = 32-byte random base64url,
  child_species_nonce = 32-byte random base64url,
  child_genome,
  child_implementation_bundle = content_ref of species-implementation-bundle/v0,
  child_initial_maintainers = {keys: sorted Ed25519 descriptors, threshold},
  child_maintainer_floor = {minimum_key_count, minimum_threshold},
  breaking_delta = sorted non-empty [{
    delta_id,
    target =
      {kind = "contract", contract_id} |
      {kind = "protocol", requirement_id} |
      {kind = "bound", requirement_id} |
      {kind = "required-output", suite_id, suite_version, case_id},
    parent_hash = 32-byte base64url or null,
    child_hash = 32-byte base64url or null,
    reason_code = "added-breaking" | "removed" | "changed-contract" |
                  "changed-protocol" | "changed-bound" |
                  "changed-required-output"
  }],
  incompatibility_report = {
    parent_requirements_hash = 32-byte base64url,
    child_candidate_hash = 32-byte base64url,
    test_evidence = {row_count, root_ref = content_ref of
                     species-evidence-root/v0 kind "branch-test"},
    overall_verdict = "deliberately-incompatible"
  }
}
```

Each `branch-test` evidence row in the Section 6 paged format is exactly
`{suite_id, suite_version, suite_ref, case_id, runner_profile_ref,
child_implementation_bundle_ref, input_ref, expected_parent_result_ref,
actual_child_result_ref, delta_ids=sorted unique [delta_id],
verdict="same-as-parent"|"incompatible-as-declared"}`. Its sort key is
suite/version/case and every reference is a complete `content_ref`.

A declaration is a normal next parent release with
`release_kind="branch-declaration"`, this exact object in
`branch_declaration`, null `fork_resolution`, and `previous_release` equal to
the four artifact/position fields of `parent_base_release`, whose `species_id`
equals the enclosing parent species. Its genome, implementation bundle, next-maintainer
policy are byte-equal to the predecessor. It carries a freshly computed
compatible report whose `base_release` is that exact predecessor, deltas are
empty, and every predecessor-required test/invariant passes against the
unchanged bundle. The predecessor policy authorizes it like every other release. A concurrent
compatible or branch-declaration successor occupies the same release position
and creates the ordinary Section 7 fork at every verifier, independent of
arrival order. A retired policy cannot create a declaration at a later
position because it is not the exact predecessor policy.

The signed parent release body commits the complete foundation directly. The
child genesis core includes both the accepted parent branch-release reference
and this exact foundation; its own genome,
species nonce, initial policy, floor, and release-zero bundle MUST copy the
foundation values.
Because the foundation does not contain the future parent declaration ID or
child `species_id`, this creates no hash cycle. Child initial maintainers
separately authorize genesis/release zero and prove possession; parent release
authorization is never child-key possession.

The parent predecessor requirements select every exact branch test, runner,
input and expected parent result, and the report contains every required case.
`child_candidate_hash` is
`SHA-256(JCS({genome=child_genome,
implementation_bundle=child_implementation_bundle}))`. The child cannot select
a weaker test to manufacture incompatibility. At least one deterministic
parent-required capability/protocol observation MUST differ as declared,
without violating an immutable identity/history/authority invariant.
`parent_requirements_hash` is SHA-256 over the exact predecessor
`genome.compatibility_requirements` JCS bytes; both hashes use canonical
base64url encoding.

For each delta, globally unique `delta_id` and its tagged target name the exact
predecessor/child contract, protocol, bound, or suite/version/case required
output entry. Deltas sort by ASCII `delta_id`, target kind, then JCS bytes and
reject duplicate IDs or targets. A present entry hash is SHA-256 of
that target's JCS bytes: the complete capability-contract entry for `contract`,
the complete protocol-requirement entry for `protocol`, its exact `bounds_ref`
for `bound`, and the suite case's exact `expected_result_ref` for
`required-output`. Absence is null; both null is invalid. `added-breaking`
requires null parent, `removed` requires null child, and changed reasons require
both. Every actual incompatible manifest difference appears exactly once,
every delta ID is covered by at least one report row, and every differing test
row names all deltas it demonstrates. An undeclared failing observation or a
declared delta without matching deterministic evidence rejects the branch.
Byte-equal cases use `same-as-parent` with empty `delta_ids`; differing cases
use `incompatible-as-declared` with a non-empty matching set.

## 10. Speciation validity and adoption

A child species validates only when all are true:

1. the parent `branch-declaration` release and its predecessor chain are valid
   and unforked;
2. the declaration release was authorized by its exact predecessor policy;
3. foundation, child genesis core, derived species ID, genome, release-zero
   bundle, policy, floor, parent reference, branch nonce, child species nonce,
   and breaking delta match byte-for-byte;
4. the breaking delta is non-empty and deterministic tests demonstrate at least
   one capability/protocol incompatibility permitted to branch; and
5. child initial maintainers authorize genesis/release zero and prove custody.

An incompatible package without declaration, a declaration without an
incompatible child, a compatible sibling labelled branch, local patch, missing
evidence, or failed tests alone creates no species. Identity, authorship,
personal-memory, key, credential, lease, grant, membership, and authority
invariants cannot be relaxed by branching; such a child is invalid.

Two sequential valid declarations may intentionally create two child species.
Concurrent declarations are parent-release siblings and remain quarantined
until Section 7 resolution. Child bytes and their derived ID remain attributable
while the parent relation is incomplete or quarantined, but they are not
accepted as a new species until that exact relation validates.

Branch intent never applies child code to existing carriers. An existing `/me`
requires explicit local incompatible-adoption consent recorded by a future
protocol; V0 does not auto-apply child releases. A child release may enroll a
newborn through DM-013. Genesis `species_release_id` remains immutable historical
enrollment; later compatible application is a separate projection.

## 11. Birth integration and authority boundaries

DM-013 `species_release_id` MUST match the exact
`dm:species-release:v0:<32-byte-canonical-base64url>` grammar. Validation binds
the exact release and full genesis/predecessor/evidence chain.

DM-010 intentionally retains `species_release_id = string or null` so its
published synthetic/legacy identity vectors remain valid. A non-null value that
does not match the DM-014 typed grammar grants no species authority, cannot
start an application chain, and leaves only species context unavailable; it
does not invalidate the independently self-certifying `/me`. Every DM-013 birth
offer/acceptance remains strict and therefore produces a typed value.

Missing release bytes leave birth species context `context-incomplete`; the
newborn identity may awaken. Malformed, wrong-ID, invalid, or forked evidence
quarantines species provenance only, never the newborn `me_id`, genesis,
cryptographic birth binding, memory boundary, credential, or presence.

A parent birth offer may name the parent's immutable enrollment release, any
valid unforked compatible descendant of that objective floor, or a valid
deliberate child release whose branch declaration descends from that parent
lineage. A later parent update never retroactively turns an earlier valid offer
into a downgrade. An ancestor below the enrollment floor, unrelated lineage,
forked release, or unbranched child quarantines context. Birth itself never
creates a species, applies a release, grants `/we`/tribe/source authority, or
copies implementation state.

Species artifacts and keys never authorize `/me` control, operational events or
leases, `/we`, birth acceptance, source/tribe claims or grants, body capability,
routes, memory, or disclosure.

## 12. Validation order and resource bounds

A verifier processes genesis or release artifacts in this
order:

1. reject complete wire bytes over 262144, nesting over 64, malformed strict
   JSON, unknown fields, invalid strings/numbers/base64, and collection bounds;
2. canonicalize, recompute typed body hash/ID and `species_id` where applicable;
3. validate referenced genesis, predecessor, branch-foundation,
   occupied-position, and
   high-water evidence without fetching unbounded graphs;
4. validate authorizing policy at that exact position, signature roles/domain,
   threshold, and every required replacement possession proof;
5. validate genome/content manifests and exact referenced byte hashes;
6. evaluate compatibility or speciation under predecessor requirements;
7. durably record replay, occupied positions, fork, branch relation, and evidence state;
8. under the application lock, recheck state before any optional activation.

Collections contain at most: 32 maintainer keys, 128 wrapper signatures, 64
capability contracts, protocol requirements, compatibility suites, invariants,
deltas, branch deltas, competing heads, candidate releases per incoming page,
missing/conflict refs, and dependencies per node; 256 entries per fork-closure
or observed-position page; 262144 page refs per root; and 4096 files per bundle closure.
The referenced-blob and aggregate-closure byte ceilings below apply
independently and usually bind first. IDs/reason codes are 1..128 printable
ASCII bytes; noncanonical
external retrieval hints are at most 512 bytes. One referenced blob is at most
67108864 bytes, one candidate closure at
most 268435456 compressed and 536870912 decompressed bytes, expansion ratio at
most 16, dependency depth 32, total dependency nodes 4096, file path depth 32,
and total test output 16777216 bytes. Local policy MAY be stricter but MUST NOT
claim V0 interoperability if it rejects otherwise valid artifacts within the
signed-wrapper bounds; application resource ceilings are advertised local
capabilities and may yield `incomplete`, never false compatibility.

Epoch, release sequence, application sequence, byte counts,
and timestamps are safe integers in `0..9007199254740991`; fields whose schema
requires a positive value additionally reject zero. Arithmetic overflow,
boolean-as-integer coercion, negative zero, fractional values, and alternate
numeric spellings are rejected before chain comparison.

## 13. Transitional mapping

None of these is species authority: Tribe directories/keys/audiences/routes;
Git branches, tags, releases, Actions or package versions; compaii-state
manifests, generations, binders or restores; HMK/Wiki/collective-memory rows or
snapshots; host, harness, model, provider, profile, body advertisement or display
name; or a live/synthetic CompAII clone. They remain attributed evidence only and
MUST NOT receive fabricated species signatures.

Synthetic fixtures MUST say synthetic and MUST NOT claim Agent 0, the first real
species, or the first real speciation has occurred.

## 14. Required positive and negative scenarios

DM-061 and later implementation tests MUST cover at least:

| Scenario | Required result |
|---|---|
| valid genesis and release zero with complete initial quorum | accept one species and release head `(0,0)` |
| release-zero bundle fails or omits a genesis-required suite/invariant | reject or `incomplete`; no active release zero |
| initial maintainer threshold signs but any declared key lacks genesis possession | pending; no active genesis/release zero |
| partial genesis/release endorsements later complete | pending then accept; same artifact ID |
| alternate valid quorum subsets over one body | merge endorsements; no fork |
| same genesis core with different threshold-valid body | quarantine species genesis |
| release-zero/genesis fork asks for resolution | terminal for that species ID; retain evidence and use fresh genesis for another attempt |
| modified body, ID, hash, domain, or role | reject |
| unknown, duplicate, unsorted, or noncanonical field/value | reject |
| signed content reference embeds a locator or retrieval hint | reject unknown field; locator stays out of lineage |
| boolean, negative, unsafe, or overflow release position | reject |
| invalid threshold or duplicate/aliased maintainer key | reject |
| normal release with exact predecessor and sequence +1 | accept compatible head |
| sequence gap or wrong predecessor ID/hash/species | reject |
| exact release replay | idempotent; no application effect |
| older head replay below durable high-water | historical only; never downgrade |
| two valid releases occupy one position | quarantine epoch and descendants |
| late sibling appears below advanced head | quarantine head and descendants |
| retired predecessor signs a sibling at an already occupied release position | retain as late fork evidence; never current |
| longer, newer-label, earlier, or lower-hash fork | never preferred |
| descendant of one fork sibling | remains quarantined |
| ordinary successor claims to resolve fork | reject |
| fork-resolution lists fewer than two competing heads or an unforked epoch | reject |
| resolution manifest has cross-species, nonmaximal, unreachable, gapped, or wrong-epoch head | reject |
| valid fork-resolution closes epoch and lists committed heads | accept new epoch `(old+1,0)` |
| resolution manifest omits a predecessor needed to reach a listed head | reject |
| resolution names missing well-formed head bytes | `incomplete` |
| resolution names invalid bytes | reject/quarantine resolution |
| two resolutions occupy new epoch zero | quarantine new epoch |
| later resolution closes two sibling resolutions at epoch zero | accept when their prior-epoch common predecessor and closure validate |
| old-epoch sibling appears after valid closure | retain superseded evidence; no reopen |
| unchanged-policy resolution lacks fresh possession from any resulting key | pending/incomplete |
| old policy signs normal successor after rotation | reject; never current |
| replacement policy self-authorizes without prior quorum | reject |
| replacement set lacks any key possession proof | pending/incomplete |
| authorization replayed as possession or cross-domain | reject |
| explicit floor-respecting threshold reduction | accept only with old quorum and all new possession |
| replacement key count or threshold falls below genesis maintainer floor | reject |
| undeclared policy mutation or unrepresentable quorum | reject |
| candidate declares compatible but omits predecessor suite | `incomplete`; no apply |
| candidate substitutes weaker suite or expected output | reject compatibility |
| release N removes a required check and N+1 relies on its absence | reject N by monotonic ratchet |
| exact suite ref missing | `incomplete` |
| mirror returns bytes that mismatch exact suite ref | discard bytes; remain `incomplete` |
| signed suite manifest internally mismatches ID/version/ref | reject selected candidate evidence |
| runner, input, expected result, bounds, or dependency manifest is absent/open/mutable | `incomplete` or reject; never pass |
| successor or branch has exactly 4096 paged evidence rows within byte/fuel limits | representable; evaluate normally |
| successor or branch requires 4097 evidence rows | reject unrepresentable predecessor/genesis profile |
| declared delta omits actual manifest change | reject |
| protected identity/event/memory/membership/authority change | invalid, never compatible or branchable |
| algorithm/domain/bound change mislabelled compatible | reject |
| failed, skipped, flaky, timed-out, nondeterministic, network, or exhausted test | not compatible |
| remote CI/registry pass without local exact verification | insufficient |
| report replayed for another bundle/runtime/candidate | reject |
| bytes swap between testing and activation | digest mismatch; refuse |
| omitted, substituted, mutable, cyclic, or over-deep dependency | reject or `incomplete` as evidence dictates |
| verified compatibility with local policy veto | no apply; compatibility unchanged |
| local override attempts to waive crypto/test failure | cannot classify compatible |
| incoming preview attempts install, network, test hook, or write | fail preview |
| sandbox reads keys/HMK/ledger/grants/routes or writes host | fail and quarantine bundle |
| activated bundle probes raw host/authority state or expands capability grants | deny at broker; classify release incompatible |
| archive traversal, absolute path, symlink, hardlink, device, or bomb | reject before execution |
| crash before pointer CAS | prior pointer remains active; cursor truthful |
| crash after pointer CAS before event fsync | candidate remains fenced; recover by rollback or exact completion |
| crash after event fsync before un-fence | finish commit/un-fence idempotently |
| retry exact application event | idempotent |
| first application goes null to exact enrollment release with matching runtime | accept bootstrap realization |
| no first enrollment application event | identity active but excluded as incomplete/diverged from `/species` |
| two application events occupy one subject/species application position | quarantine only that realization chain, never `/me` |
| application event author differs from subject or lacks valid operational authority | reject event; release validity unchanged |
| application changes species/enrollment, skips path, mismatches bundle/snapshot, or names wrong effective from-release | reject event |
| verification manifest/page/evidence ref is missing or does not recompute | `incomplete` or reject event; never infer application |
| failed/vetoed event claims pointer/runtime change | reject event |
| rollback targets release never previously applied or below enrollment | reject event |
| rollback after runtime failure | restore code pointer; never regress evidence/history |
| late valid sibling forks an already applied path | rollback via `release-fork` proof to last-unforked applied ancestor; `/me` unchanged |
| old release replay asks to rerun effects | refuse |
| compatible catch-up path lacks intermediate edge/evidence | `incomplete` |
| valid head has forked intermediate position | `quarantined` |
| candidate asks for new privileges or ambient credentials | incompatible/manual-only; never auto-apply |
| concurrent sibling ingestion races auto-apply | serialize, persist fork, freeze at last unforked release |
| incoming cursor exactly equals applied accepted head | `current`, no mutation |
| strict fully verified descendant path exists | `compatible-behind` |
| compatible path exceeds 64 releases | return content-bound pages; no apply until complete null continuation |
| snapshot hash includes itself or page changes registry cursor | reject preview/page set |
| incoming misses required blob or release | `incomplete` |
| incoming selects invalid candidate or knows valid sibling/fork | `quarantined` |
| unauthenticated or structurally invalid junk targets a valid position | reject junk without poisoning valid lineage |
| local unmanifested patch or valid deliberate other species | `diverged` |
| stale/offset/omitted-position cursor below high-water | cannot report current/behind |
| partitioned preview claims globally newest | reject claim; result is cursor-relative |
| unauthorized preview probes lineage/capabilities | deny without oracle detail |
| retrieval hint attempts SSRF or ambient credential use | refuse fetch |
| exact resource bound | accept when every other rule passes |
| any count/byte/depth/time bound plus one | reject or `incomplete` before unsafe work |
| valid branch-declaration release with no-op parent state | accept as next parent release |
| branch declaration directly follows release zero | fresh report names release zero and passes unchanged bundle |
| branch declaration races a compatible parent successor | ordinary parent release fork regardless of arrival order |
| retired policy mints branch declaration at a later unoccupied position | reject wrong predecessor policy |
| two branch declarations occupy one release position | quarantine parent epoch and both relations |
| incompatible release without declaration | no new species |
| declaration without incompatible child | no new species |
| compatible sibling labelled branch | parent release fork, not species |
| accidental patch, failed test, or missing evidence | diverged/incomplete, not species |
| child core foundation or parent branch-release ref mismatches declaration release | reject relation |
| same branch release reused with another child species nonce or derived ID | reject relation |
| child release zero substitutes another implementation bundle | reject child relation/release zero |
| breaking delta uses ambiguous/duplicate target or test cites unknown delta ID | reject declaration |
| parent authorization or child initial quorum missing | reject/pending; no species |
| child attempts to relax immutable identity/history/authority invariant | reject child |
| two valid distinct child declarations | two child species; neither selected as winner |
| parent declaration relation is forked/incomplete | child bytes attributable but no accepted new species |
| existing carrier receives child release without explicit consent | never apply |
| birth references missing exact release | `context-incomplete`; identity may awaken |
| birth references malformed/wrong-ID release | quarantine species provenance only |
| legacy/synthetic DM-010 genesis carries non-DM-014 species string | `/me` remains valid; no species authority/application |
| later release fork discovered | quarantine provenance/application, not `/me` or presence |
| successor application attempts to rewrite enrollment release | reject |
| parent offers unrelated release or ancestor below its enrollment floor | quarantine species context |
| later compatible parent release appears after historical birth offer | earlier valid offer remains valid; no retrospective downgrade |
| species payload injects memory, keys, grants, membership, routes, or body claim | reject; newborn remains independent |
| species/branch used as `/we`, tribe, source, routing, or disclosure authority | reject |
| shared species alone used to address recipients | reject |
| synthetic fixture claims Agent 0 or first real speciation | reject test claim |

## 15. Downstream contracts

- DM-018 registers canonical body adapters and capability implementations; an
  adapter never becomes species or identity authority.
- DM-023 persists release/branch cursors, occupied positions, evidence closure,
  and idempotent application receipts; it does not invent their semantics.
- DM-032 may let a model propose bundles or deltas, but only the deterministic
  isolated verifier and local policy classify/apply them.
- DM-061 implements compatible incoming updates and synthetic branching against
  this contract. It must not require a real Agent 0 event.
- DM-072 canaries consume only validated DM-061 evidence; transitional live
  state is never retroactively promoted into species authority.
