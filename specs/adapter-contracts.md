# DM-018 adapter contracts, versioning, and migration

Status: normative V0 specification.

This document freezes the provider boundary used by Daimon Matrix. It covers
harness, memory projection, artifact-store, transport, source, curator-worker,
capability/species, and body/deployment providers. An adapter realizes an
effect or returns evidence; it is never an authority merely because Matrix
invoked it.

The normative machine-readable schemas are in
[`schemas/adapters/v0/contracts.schema.json`](../schemas/adapters/v0/contracts.schema.json).
The independent conformance corpus is in
[`vectors/dm018/`](../vectors/dm018/).

Normative keywords MUST, MUST NOT, REQUIRED, SHOULD, SHOULD NOT, and MAY have
their RFC 2119 meanings.

## 1. Authority boundary

Matrix owns and validates:

- `me_id`, identity-control state, operational credentials and revocations;
- canonical event bytes, causal order, checkpoints and accepted high-waters;
- `daimon-presence-lease/v0` plus its external witness receipt;
- `/we` membership, tribe grants, source decisions and species releases;
- the DM-017 memory categories and canonical personal-memory events; and
- every canonical append or acceptance decision.

A provider may own only the effect surface assigned to its provider kind:

| provider kind | allowed effect surface |
|---|---|
| `harness` | model/session invocation and body-local prompt state |
| `memory-projection` | rebuildable indexes, summaries and caches |
| `artifact-store` | byte storage, retrieval and retention evidence |
| `transport` | routing and carriage of already-authorized bytes |
| `source` | attributed discovery and retrieval |
| `curator-worker` | schema-bounded proposals and evaluations |
| `capability-species` | execution and measurement of pinned DM-014 suites |
| `body-deployment` | realization, resources, lifecycle, backups and local execution fencing |

Every adapter manifest sets all five authority booleans to `false`: it cannot
act as Matrix authority, sign as `/me`, append the ledger, mint membership, or
issue presence. A result is input to Matrix validation, not a canonical
decision. Successful storage, transport, deployment, model execution, or
snapshot restore does not prove acceptance.

Implementation database handles, table names, filesystem paths, host sockets,
private keys, bearer tokens, prompt/session dumps and raw secrets MUST NOT be
protocol fields. Providers exchange immutable content references and opaque
route/secret handles scoped to their local custody boundary. A handle conveys
location or retrieval capability only; it never changes the referenced
content's identity or authority.

## 2. Common closed records

Every JSON record defined here uses DM-011 strict I-JSON and JCS rules, its
schema is closed, and its complete wire form is at most 262,144 bytes. Integer
positions are non-negative I-JSON safe integers. Digests are unpadded
base64url-encoded SHA-256 values.

Every content-derived record ID uses the DM-011 construction with the domain
listed below and the JCS body obtained by removing the record's ID field and,
for a signed deployment fence, its `signature` field. The deployment issuer
signs that same domain-separated preimage.

| record | domain | ID prefix |
|---|---|---|
| adapter manifest | `daimon/adapter-manifest/v0` | `dm:adapter:v0:` |
| adapter result | `daimon/adapter-result/v0` | `dm:adapter-result:v0:` |
| capability/species evaluation | `daimon/capability-species-evaluation/v0` | `dm:capability-evaluation:v0:` |
| body realization | `daimon/body-realization/v0` | `dm:realization:v0:` |
| activation bundle | `daimon/activation-bundle/v0` | `dm:activation:v0:` |
| park evidence | `daimon/park-evidence/v0` | `dm:park:v0:` |
| wake evidence | `daimon/wake-evidence/v0` | `dm:wake:v0:` |
| deployment fence | `daimon/deployment-fence/v0` | `dm:deployment-fence:v0:` |
| migration receipt | `daimon/adapter-migration-receipt/v0` | `dm:migration-receipt:v0:` |

An invocation is intentionally caller-named by its UUID and its complete JCS
digest is bound by the result. Conformance fixtures use syntactically valid
placeholder IDs/signatures to test shape and cross-record rules; production
validators MUST recompute IDs and verify signatures.

An `artifact_ref` is:

```text
{
  artifact_id,
  sha256,
  media_type,
  bytes
}
```

The consumer MUST retrieve bytes, enforce the declared ceiling and media type,
recompute `sha256`, and validate the artifact's own schema and content-derived
ID before use. The reference is not proof that bytes exist, are authorized, or
are current.

Named ID fields are nominally typed: `me_id`, adapter, result, realization,
activation, park, wake, deployment-fence, presence-lease, volume, deployment
key and migration-receipt fields accept only their exact registered prefix.
A syntactically valid ID from another domain is rejected before lookup; no
cross-authority substitution is resolved by inspecting the referenced bytes.

An `adapter_manifest` has schema `daimon-adapter-manifest/v0`, a
content-derived `adapter_id`, exactly one `provider_kind`, sorted unique
`contracts`, sorted unique descriptive `capabilities`, bounded integer
`limits`, and the five false authority flags. Each contract row names an exact
`contract` and sorted unique exact `versions`; ranges and implicit minor-version
compatibility are forbidden.

An `adapter_invocation` has schema `daimon-adapter-invocation/v0` and binds an
exact contract/version, operation, request ID, idempotency key, adapter ID,
optional Matrix subject, immutable input references, bounded execution limits,
and an extension-free V0 context. Repeating the same idempotency key with the
same invocation bytes MUST return the same terminal result or its exact prior
receipt. Reusing it with different bytes MUST be refused as a conflict.

An `adapter_result` has schema `daimon-adapter-result/v0` and binds the exact
invocation hash. Its status is `accepted`, `refused`, `incomplete`, or
`failed`. Outputs and effect evidence are content references. `accepted` means
only that the provider completed its assigned effect; Matrix still validates
every output and authority precondition. `incomplete` names missing immutable
inputs. `refused` is a policy or contract refusal. `failed` is a provider
failure. Retrying may create a new request, but cannot rewrite the old result.

## 3. Negotiation and rejection

The caller begins with a locally configured, ordered allowlist of exact
contract versions. It intersects that allowlist with the provider manifest and
selects the first local preference present in the intersection. Selection MUST
NOT be derived from lexical or numeric “highest version” ordering.

The V0 manifest parser accepts bounded, well-formed exact version labels so it
can inspect a future provider offer without interpreting that contract. A
provider offering only versions absent from the caller's allowlist yields an
empty intersection and a safe pre-effect refusal. Parsing an advertised label
does not mean the caller supports or may invoke that version.

An endpoint MUST reject before effects when:

- the record schema, contract name, exact version, operation or provider kind
  is unknown;
- the selected version is absent from either party's exact allowlist;
- a field, enum value, extension, authority flag, content hash or ceiling is
  invalid;
- required input evidence is missing, incomplete, revoked, stale or forked;
- an idempotency key is reused for different invocation bytes; or
- applying the request would lower, delete, reuse, or ambiguously restore a
  Matrix or deployment high-water.

Unknown major or minor versions are both unsupported. An implementation MUST
NOT ignore unknown fields in authority-bearing records, guess a predecessor,
silently downgrade, translate an unknown record as V0, or perform a partial
effect and then report negotiation failure. Experimental data travels only as
an immutable artifact behind an explicitly negotiated future contract.

The accepted-version high-water is keyed by `(adapter_id, contract)`. Once a
deployment has accepted a newer version, selecting an older version requires a
locally authorized migration plan that explicitly declares the downgrade,
proves the target can represent all accepted state, and emits a successor
migration receipt. Otherwise downgrade is rejected.

## 4. Schema evolution

A compatible implementation update may change code while emitting identical
V0 records. Any field addition/removal, new enum value, changed default,
changed canonicalization, changed authority, loosened validation, or changed
effect meaning requires a new exact contract version. No V0 field is optional
unless its schema explicitly permits `null`.

Adapters MUST preserve the original bytes and version of received evidence.
Translation produces a new content-addressed artifact and a migration receipt;
it never edits the source. Consumers validate the source under its original
schema and the target under its target schema.

Capability/species adapters are especially non-authoritative. Their closed
`daimon-capability-species-evaluation/v0` record receives exact DM-014 release,
genome, compatibility requirements, suite and local policy references. It
returns measured outputs plus a report reference, fixes `authority` to
`evidence-only`, and fixes `application_receipt` to null.
Matrix recomputes or validates the DM-014 compatibility report and application
receipt. An adapter's capability label, exit code, container image, benchmark,
or provider result cannot create a `species_id`, `species_release_id`,
compatibility decision, application receipt, branch, or membership.

## 5. Migration protocol

Migration is a five-stage state machine:

1. `export`: freeze an exact source high-water and emit a content-addressed,
   secret-free portable artifact; a live database or directory is invalid.
2. `plan`: bind source and target contract versions, source artifact, expected
   target hash, every Matrix and deployment high-water, and loss policy.
3. `apply`: create target bytes without mutating or deleting source evidence.
4. `verify`: validate target schema/hash and prove every covered high-water is
   equal or greater and every identity/source/category remains distinct.
5. `commit`: emit `daimon-adapter-migration-receipt/v0` and advance the local
   migration receipt sequence.

The receipt binds adapter, provider kind, contract transition, source and
target artifacts, predecessor receipt, monotonic `migration_sequence`, the
covered high-waters, outcome, and optional rollback-of receipt. A first receipt
has sequence zero and null predecessor; each successor increments by exactly
one and names the predecessor.

Rollback is a new migration from the failed target representation to another
valid representation. Its receipt has a strictly newer sequence and names the
receipt it compensates. Rollback MUST NOT delete receipts, restore earlier
accepted bytes as if new, lower any high-water, reactivate revoked evidence, or
make a failed partial target authoritative. If lossless representation cannot
be proven, the operation is `refused` or `incomplete`; operators must choose a
newer contract or an explicit authority-approved transformation.

Crash recovery replays the last committed receipt and idempotently verifies
content hashes. Uncommitted target bytes are quarantined. Garbage collection
retains receipts, revocation/fork evidence, and sufficient signed high-water
history to reject stale restore forever.

## 6. Matrix–deployment profile

A body is a realization occupied by a Matrix identity, never the identity
itself. The deployment controller owns instance/volume lifecycle, resources,
placement, backups, storage transport and a local execution fence. Matrix owns
all identity, membership, species, memory and presence authority listed in
Section 1.

The profile defines five closed exchanges.

### 6.1 Body realization

`daimon-body-realization/v0` binds a content-derived realization ID to the
deployment adapter, instance, image, profile, durable-volume descriptor,
resource limits and capability-description artifact. `me_id` is absent: a
realization is unoccupied until separately activated. Image names and a
deployment `species` label are descriptive only.

### 6.2 Activation bundle

`daimon-activation-bundle/v0` flows Matrix → deployment/body. It binds:

- exact `me_id`, accepted operational certificate and acceptance references;
- body and capability-description references;
- the last accepted Matrix presence lease and external lease-head receipt;
- event checkpoint and exact event cutoff;
- nullable DM-014 species-release reference;
- a secret-free projection manifest and opaque route-handle references; and
- the predecessor deployment-fence position.

Private root, recovery, signing, encryption and symmetric keys never appear.
They remain in Matrix custody and are made usable through locally protected
key operations, not transport records.

A deployment `create` or `provision` operation may realize an empty body. It
MUST NOT create `/me`, `/we`, species membership, operational credentials, or
autobiographical memory. The body may host an existing activation bundle or a
separately validated DM-013 birth/first-awakening ceremony.

### 6.3 Park evidence

`daimon-park-evidence/v0` proves: admission is quiesced; canonical events are
flushed; the exact final checkpoint/cutoff is durable; current presence lease
and external receipt are named; optional DM-017 handoff and projection
manifest are content-bound; and the current deployment fence is named. The
controller MUST NOT stop/move the source before all required evidence
validates. The handoff, when present, is the credential's final event and does
not embed its own eventual event hash.

### 6.4 Wake evidence

`daimon-wake-evidence/v0` binds the same identity and predecessor cutoff to a
fresh operational/session position, successor Matrix presence lease, new
independent external receipt, target realization, verified body/capability and
projection descriptions, and a strictly newer deployment fence. Projection,
NOW, harness, HMK, state-repository, volume and snapshot data are only rebuild
acceleration. A mismatch discards or quarantines them; it never rolls back the
ledger, presence or fence.

### 6.5 Deployment fence

`daimon-deployment-fence/v0` is issued by the deployment authority and binds
one `me_id` as subject metadata to an exact realization, durable volume,
holder, monotonic `generation`, monotonic `fencing_token`, predecessor fence,
state (`prepared`, `active`, `parked`, or `revoked`), `issuer_key_id`, the
matching Ed25519 `issuer_public_key`, and its signature. The consumer recomputes
the key ID by the DM-011 descriptor formula and accepts the key only when local
deployment policy authorizes it. The record authorizes only deployment effects.

`daimon-presence-lease/v0` and `daimon-deployment-fence/v0` are separately
named, versioned, signed and validated records. Their IDs, issuers, sequences,
signatures and authorities are not interchangeable. Neither may satisfy a
missing check for the other.

For one deployment-fence lane, the first accepted position is `(0, 0)` with a
null predecessor. Every later accepted record names the exact prior fence;
`generation` and `fencing_token` never decrease and at least one strictly
increases. Entering a new holder, realization, volume, or reactivation after
expiry/failure requires a strictly higher generation and token. Positions are
never reused. Release/expiry/GC preserves the high-water tombstone.

## 7. Activation, park, wake and rollback algorithm

Activation and wake MUST execute in this order:

1. validate identity/control and the exact event checkpoint/cutoff;
2. validate the predecessor presence lease and external head receipt;
3. validate body/capability/projection descriptions by content hash;
4. reserve a strictly newer deployment fence in `prepared` state;
5. obtain and externally receipt a successor Matrix presence lease;
6. atomically mark the reserved fence `active`; and
7. expose the body to delivery/effects only after both gates are current.

If any step fails, the reserved fence position remains consumed. The target is
destroyed/quarantined or the source is reactivated through strictly newer
presence and fence positions. Restoring the prior lease/fence snapshot is
forbidden.

Park MUST stop admission, drain/refuse in-flight effects, append the optional
handoff, flush canonical events, obtain the final checkpoint/lease evidence,
emit park evidence, advance the fence to `parked`, and only then stop or move
the body.

All identity-control generations, operational generations, event sequences,
memory sequences, presence lease sequences, external witness sequences,
migration receipt sequences, deployment-fence generations and fencing tokens
are high-waters. Expiry, release, failed wake, restore, rollback and garbage
collection never reset, delete, reuse or lower them.

## 8. Dual delivery/effect gate

When no deployment controller is configured, DM-010 Matrix presence remains
the required admission gate. When one is configured, accepting delivery,
starting work, acknowledging semantic intake, or committing an external effect
requires both:

1. the exact current active Matrix presence lease plus valid external
   lease-head receipt; and
2. the exact current `active` deployment fence for the named realization and
   holder.

The broker/adapter compares both record IDs and high-water positions with its
locally accepted heads. Missing, expired, stale, forked, mismatched, prepared,
parked or revoked evidence causes queue/refusal. It MUST NOT choose the newest
timestamp, query an adapter roster as authority, fall back to one gate, or
guess that a host/container name denotes the identity. An ACK/effect receipt
binds both accepted record IDs so a later audit can prove the dual check.

Transitional principals like `<agent>@<host>` are route/authentication
principals only. They cannot substitute for `me_id`, operational credentials,
Matrix membership, presence, or a deployment fence.

## 9. Distinct continuity cases

- **Same-identity relocation:** the exact `me_id` and canonical history
  continue; source park precedes target wake; no active presence overlaps; both
  deployment and Matrix positions advance.
- **Distinct-identity seeding:** a DM-013 newborn has a distinct root and
  `me_id`; imported material remains attributed external/peer evidence;
  personal lanes and incarnation state start empty. Snapshot/key/database copy
  cannot manufacture continuity.
- **Multi-member `/we`:** every member retains a distinct root, event
  authorship, presence lane and (when deployed) fence lane. Shared image,
  volume source, provider, host, name or species does not merge members.

The conformance corpus contains one accepted fixture for each case and rejects
same-identity overlapping activation, seeded identity reuse, `/we` identity
collapse, a single-gate delivery, fence regression, presence-as-fence
substitution, secret/path leakage, unknown versions and migration rollback
regression.

## 10. Conformance requirements

An independent adapter implementation conforms only if it:

1. validates every positive fixture and rejects every negative fixture in the
   checked-in index with the stated reason class;
2. rejects unknown schemas, versions, properties and enums before effects;
3. implements byte-exact invocation idempotency and immutable results;
4. verifies content hashes rather than trusting references;
5. enforces migration and all covered high-waters monotonically;
6. keeps presence and deployment-fence validation independent; and
7. passes provider-specific authority-boundary tests without access to Matrix
   implementation databases or private keys.

The fixtures test the wire contract and critical cross-record invariants. They
do not confer trust on a provider, prove a model output true, or replace
DM-010–DM-017 validation.

## 11. Required scenarios

| scenario | required result |
|---|---|
| exact mutually allowed V0 contract | select and proceed |
| unknown `v1` or unknown V0 field | reject before effects |
| same idempotency key, different invocation | refuse conflict |
| capability runner reports success without DM-014 evidence | incomplete; no compatibility/application authority |
| body provision returns host identity as `me_id` | reject |
| valid presence, missing/stale deployment fence | queue/refuse |
| valid fence, missing/stale Matrix presence | queue/refuse |
| presence lease supplied where fence is required | reject schema/authority |
| expired lease/fence followed by acquisition at zero | reject regression |
| failed wake then restore old lease/fence bytes | reject; consume successor positions |
| projection hash mismatch after restore | discard/quarantine projection only |
| same `/me` park then wake in another body | accept only with no overlap and newer positions |
| seeded distinct `/me` from projection | keep source attribution; empty personal lanes |
| two `/we` members on one cluster | distinct identity, presence and fence lanes |
| migration target cannot preserve a high-water | refuse/incomplete |
| rollback emits newer compensating receipt | accept without deleting failed receipt |
| adapter record exposes path/database/private key/secret | reject |
| release/GC removes high-water history | non-conforming |

## 12. Downstream implementation boundary

DM-019–DM-024 implement this narrow waist. DM-025–DM-030 implement providers
against it. DM-031–DM-034 integration tests MUST use the fixtures rather than a
shared database. DM-035 and DM-052 add policy/privacy enforcement without
loosening the authority boundary.

For `daimon-cluster`, its lifecycle decomposition, resource controls,
prepare/confirm operations, audit intent, checkpoint verification, failure
injection plan and broker-fencing objective are reusable. Before production it
must replace fake/placeholder signing, non-CAS lease writes, epoch reset,
history deletion, regressing transfer rollback and intent-only volume attach.
Cluster lease code becomes deployment-fence implementation evidence; it does
not become Matrix identity or presence authority.
