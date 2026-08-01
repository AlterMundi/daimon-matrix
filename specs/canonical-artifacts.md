# Canonical artifacts, events, and cryptographic vectors

Status: normative V0 specification.

This document completes the deterministic encoding contract handed off by
DM-010. It defines canonical JSON, identifiers, hashes, signatures, event
ordering, checkpoint evidence, and recipient-encrypted delivery. Scope
resolution and operation behavior belong to DM-012; storage and state-machine
implementation belong to DM-021 through DM-023.

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, **SHOULD NOT**,
and **MAY** are interpreted as described by RFC 2119 and RFC 8174.

## 1. Layer and authority boundaries

V0 separates three objects:

1. a signed **canonical artifact**, which is durable evidence and may enter the
   append-only ledger;
2. a signed **canonical event**, which is authored by one `/me` operational
   credential with causal and per-credential ordering;
3. a **sealed delivery**, which encrypts already signed canonical bytes for a
   concrete recipient set and is disposable transport state.

Encryption, routing, receipt, projection, and storage MUST NOT change an
artifact or event ID. A transport acknowledgement proves only transport state.
It is not a semantic reply, event acceptance, memory integration, or identity
checkpoint.

Tribe principals, directory epochs, audiences, host names, harnesses, models,
providers, HMK rows, GitHub identities, and route credentials MUST NOT appear
as `/me`, operational-credential, body, or `/we` authority. A sealed delivery
resolves recipients only to certified Daimon operational encryption keys.

## 2. Strict JSON and canonical bytes

### 2.1 Accepted data model

Wire objects are UTF-8 JSON conforming to I-JSON and RFC 8785 JCS, restricted
further as follows:

- duplicate property names are rejected while parsing;
- top-level and protocol-owned objects are closed: unknown properties are
  rejected;
- property names defined by this protocol are printable ASCII;
- values are `null`, booleans, strings, arrays, objects, or integers in
  `[-(2^53-1), 2^53-1]`;
- floating-point values, exponent notation, and negative zero are forbidden;
- invalid Unicode and unpaired surrogates are rejected;
- strings are not Unicode-normalized; their exact scalar sequence is data;
- binary values use unpadded RFC 4648 base64url and must survive a
  decode/re-encode canonicality check.

Type-defined event payload objects MAY define their own keys, but every value
still obeys this data model. Every conforming implementation MUST support a
nesting depth through 64 levels and MUST reject a deeper value. Before parsing
or performing cryptography it MUST reject a complete wire artifact larger than
its V0 ceiling: 262144 bytes for an identity or species genesis, control,
certificate, acceptance (operational or birth), species release (including a
branch declaration or fork resolution),
lease, lease-head receipt, or checkpoint wrapper;
1048576 bytes for an event wrapper; and 2097152 bytes for a sealed-delivery
wrapper. It MUST NOT configure
a smaller ceiling and still claim V0 interoperability.

Resource-bearing arrays are bounded before cryptographic evaluation: at most
32 keys per threshold set, 128 detached signatures per wrapper, 256 embedded
revocations per recovery transition, 1024 high-water entries per control
artifact, 64 each of routes, certificate event-type prefixes, birth-offer
source references, tribal commitments, and commitment resource/operation
entries, 64 causal parents, and 256 sealed-delivery recipients. Subject to the
complete-wire ceiling,
implementations MUST accept values through those bounds when every other
requirement is met and MUST reject larger arrays.

### 2.2 Canonicalization

`JCS(value)` is the UTF-8 encoding produced by RFC 8785 for the accepted data
model, with no byte-order mark, whitespace, or trailing newline. There is one
canonicalizer and one strict parser for every V0 artifact. A subsystem MUST NOT
substitute a convenient serializer, pretty printer, manifest canonicalizer, or
database JSON function.

Canonical artifact and sealed-delivery wire bytes MUST equal `JCS(parsed_value)`
byte for byte. A parser rejects otherwise valid JSON containing alternate
whitespace, escape spelling, key order, or number spelling. Human-facing tools
may render copies, but those renderings are never signed or ingested as
canonical artifacts.

All arrays whose semantic meaning is a set are sorted and duplicate-free:

- key descriptors and signatures: by UTF-8 `kid`, with signatures secondarily
  sorted by `role`;
- IDs and hashes: by their ASCII wire value;
- concrete recipients: by `(me_id, operational_id, encryption_kid)`.

Event high-water arrays sort by `operational_id` and reject a repeated
operational stream. The identity-wide lease high-water is a singleton rather
than an array. Route arrays sort by `(kind, route_id)`. Protocol-owned string
sets, including purposes and event-type prefixes, sort by their ASCII bytes.
Revocation entries sort by their JCS bytes and reject a repeated
`(target.kind,target.id,target.kid)` tuple.

Order-sensitive arrays such as causal paths or application payload lists retain
their declared order.

Every V0 validity interval is half-open: an instant `t` is within it exactly
when `not_before_or_issued_at <= t < expires_at`. Expiry instants themselves
are never valid.

## 3. Cryptographic suite and domains

The only V0 suite is:

```text
DM0_HPKE_X25519_HKDF_SHA256_CHACHA20POLY1305_ED25519_JCS
```

It uses SHA-256, RFC 8032 Ed25519, RFC 9180 HPKE base mode with
DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, and ChaCha20-Poly1305. DM-013 also
uses a fresh Ed25519 capability key for its publicly verifiable one-use
awakening proof; that key is never identity authority. Algorithms are not
negotiated. A different suite requires new protocol/domain versions and MUST
NOT reinterpret V0 bytes.

The registered V0 cryptographic and protocol-separation labels are:

```text
daimon/genesis/v0
daimon/root-transition/v0
daimon/recovery-transition/v0
daimon/recovery-policy/v0
daimon/operational-certificate/v0
daimon/operational-acceptance/v0
daimon/birth-acceptance/v0
daimon/birth-awakening-challenge/v0
daimon/species-id/v0
daimon/species-genesis/v0
daimon/species-release/v0
daimon/species-observed-positions/v0
daimon/species-evidence-closure/v0
daimon/species-incoming-snapshot/v0
daimon/source-id/v0
daimon/source-claim-series/v0
daimon/source-claim-binding/v0
daimon/source-assessment-series/v0
daimon/source-publication-id/v0
daimon/source-publication-binding/v0
daimon/source-import-decision-series/v0
daimon/source-cursor-snapshot/v0
daimon/we-membership-genesis/v0
daimon/we-membership-transition/v0
daimon/we-membership-acceptance/v0
daimon/sync-leg/v0
daimon/member-ledger-cursor/v0
daimon/revocation/v0
daimon/presence-lease/v0
daimon/lease-head-receipt/v0
daimon/event/v0
daimon/event-checkpoint/v0
daimon/sealed-event/v0
daimon/sealed-event/payload-aad/v0
daimon/sealed-event/cek-wrap/v0
```

For an artifact domain `D` and canonical body `B`:

```text
artifact_preimage = UTF8(D) || 0x00 || JCS(B)
artifact_hash_raw = SHA-256(artifact_preimage)
authorization_signature = Ed25519.sign(key, artifact_preimage)
possession_preimage = UTF8(D) || 0x00 || artifact_hash_raw
possession_signature = Ed25519.sign(replacement_key, possession_preimage)
```

Authorization signatures and possession proofs are therefore not
interchangeable even when produced by the same test key. A signature or proof
valid for one domain or body MUST be invalid for every other.

## 4. Common descriptors and wrapper rules

### 4.1 Keys, thresholds, and signatures

A signing-key descriptor has exactly:

```json
{"alg":"Ed25519","kid":"<content-derived key id>","public_key":"<32-byte base64url>"}
```

An encryption-key descriptor substitutes `"alg":"X25519"`. A threshold set
has exactly `{"keys":[...],"threshold":N}`. `N` is an integer from one through
the key count. An explicit no-recovery set has `mode:"none"`, an empty key
array, and threshold zero; no other zero threshold is valid.

Key IDs are content-derived:

```text
kid = "dm:key:v0:" || base64url(SHA-256(JCS({
  "alg": algorithm,
  "public_key": canonical_public_key
})))
```

A `kid` MUST never resolve to another descriptor. Threshold arrays reject
duplicate key IDs and duplicate `(alg,public_key)` descriptors, including one
public key presented under several aliases. Thresholds count distinct public
keys, not names or signature records. Cross-role key-reuse rejection compares
public descriptors, not only `kid` strings. A wire verifier cannot prove that
different Ed25519 and X25519 public keys were derived from reused private seed
material; independent generation is a custody/conformance requirement and the
vectors use independent synthetic seeds.

A signature record has exactly:

```json
{"alg":"Ed25519","kid":"<key id>","role":"<role>","value":"<64-byte base64url>"}
```

Allowed roles are artifact-specific. Duplicate key IDs in a key set or duplicate
`(role,kid)` signatures are rejected. Thresholds count distinct authorized
public keys, never signature records.

V0 implementations MUST reject non-canonical Ed25519 encodings, invalid or
small-order Ed25519 points, non-canonical `S` scalars, and X25519 exchanges that
produce the all-zero shared secret. Merely accepting byte lengths is not
cryptographic validation.

### 4.2 Signed wrapper

Except where an exact specialized wrapper is defined below, a signed artifact
has exactly:

```json
{
  "artifact_hash":"<32-byte base64url>",
  "artifact_id":"<typed content ID>",
  "body":{},
  "signatures":[]
}
```

`artifact_hash` is base64url of `artifact_hash_raw`. `artifact_id` uses the
type prefix specified below plus that same digest. Both are derived and are
outside the body and signature input. A verifier recomputes them before
signature validation. Signatures authenticate the body; the ID and hash are
unambiguous renderings of its domain-bound digest.

For threshold artifacts, signatures are mergeable detached endorsements of the
same domain/body/ID. Different valid quorum subsets or later additional valid
endorsements do not create a different artifact, fork, or content conflict.
Verifiers union valid authorized `(role,kid,value)` endorsements, sort the union,
and evaluate thresholds over distinct public keys. Wrapper bytes with the same
body/ID but different endorsement subsets represent one artifact; wrapper bytes
with a different body for the same ID are a content conflict. Events,
operational subject acceptances, leases, checkpoints, and sealed deliveries
require exactly one artifact-specific signer and do not use endorsement
merging. DM-012 collective membership acceptances, DM-013 birth acceptances,
and DM-014 species genesis plus every species release kind are threshold
artifacts and therefore use the mergeable-endorsement rule above.

### 4.3 Timestamps

All `*_at_ms` fields are non-negative Unix milliseconds encoded as integers.
They are signed claims, not trusted ordering or compromise evidence. Local
verified time applies DM-010 certificate and lease bounds. Identity control,
causality, replay, and compromise cutoffs use signed sequence/hash positions.

## 5. Exact identity artifact bodies

All bodies in this section are closed. Optional fields are explicitly named;
an omitted optional field and a field set to `null` are different encodings.

### 5.1 Genesis

The genesis core has exactly:

```text
protocol = "daimon"
version = 0
suite = the Section 3 suite
domain_version = 0
genesis_nonce = 32-byte base64url
root = threshold signing-key set
recovery = {mode: "none"|"threshold", keys: [...], threshold: N}
```

Its identifier deliberately follows DM-010 without a domain prefix inside the
hash:

```text
me_digest = SHA-256(JCS(genesis_core))
me_id = "dm:me:v0:" || base64url(me_digest)
```

The genesis statement body has exactly:

```text
schema = "daimon-genesis/v0"
core = genesis_core
me_id
policy = {max_certificate_lifetime_ms, max_presence_ttl_ms,
          max_clock_skew_ms, nonrecoverable}
created_at_ms
species_release_id = string or null
birth_offer_id = string or null
recovery_generation = 0
control_sequence = 0
```

A non-null `birth_offer_id` names the exact DM-013 `matrix/birth-offer` event
ID whose newborn root-threshold acceptance completes this genesis's lineage
binding. It is signed personal provenance and grants no identity authority.

The wrapper uses `artifact_id = dm:ctl:v0:<artifact-hash>` and
`root-authorization` signatures under the genesis domain. When recovery mode is
`threshold`, it also includes `recovery-possession` proofs from the declared
recovery threshold over the genesis artifact hash. Initial root signatures
prove root possession themselves. Distinct threshold-valid statements for one
core are the genesis fork defined by DM-010.

### 5.2 Control bodies

Every non-genesis control body contains `schema`, `me_id`,
`recovery_generation`, `control_sequence`, and predecessor evidence. Every
non-fork artifact contains `previous_control_hash`. A fork-resolving recovery
contains `competing_control_hashes` instead, sorted and complete; it MUST NOT
also contain a single preferred predecessor.

Genesis is `(0,0)`. Root transitions, recovery-policy changes, and standalone
revocations retain the accepted recovery generation and increment control
sequence by exactly one. A recovery transition increments recovery generation
by exactly one and sets control sequence to zero, regardless of the predecessor
sequence. Its body records that new position, not the superseded position.

The root-transition body adds exactly:

```text
schema = "daimon-root-transition/v0"
replacement_root = threshold signing-key set
certificate_disposition = {
  mode: "invalidate_all"|"carry_forward",
  carried_forward_certificate_ids: sorted IDs
}
```

`invalidate_all` requires an empty carried-forward list. `carry_forward`
requires an explicit list; the phrase “all prior certificates” is not an
encoding. Signature roles are `root-authorization` from the current threshold
and `root-possession` from the replacement threshold.

The recovery-transition body adds exactly:

```text
schema = "daimon-recovery-transition/v0"
post_recovery_root = threshold signing-key set
compromise = {
  mode: "none"|"suspected"|"confirmed",
  control_cutoff: {recovery_generation, control_sequence, control_hash}|null,
  preserved_certificate_ids: sorted IDs,
  event_high_waters: sorted [{operational_id, sequence, event_id, event_hash}]
  lease_high_water: null or {lease_sequence, lease_id, lease_hash,
                              commit_receipt_id}
}
revocations = sorted revocation entries
```

Signature roles are `recovery-authorization` from the previously accepted
recovery threshold and `root-possession` from the post-recovery root threshold.
A compromise mode other than `none` requires a cutoff and replaces every
compromised root key. Preserved certificates are explicit; omission preserves
none. A suspected recovery-key compromise is not repaired by a transition that
the same suspect recovery key authorizes: while the root is valid, the dual
root/recovery policy-change ceremony replaces recovery keys; without a trusted
root and recovery threshold, identity control fails closed.
Every included revocation entry is authenticated by the recovery-transition
signature and takes effect at that transition's derived control position.
The compromise cutoff MUST name an existing position on a predecessor or
competing branch; it cannot name the recovery artifact's not-yet-derived hash.
A recovery transition is invalid if the same certificate is both preserved and
targeted by an effective embedded revocation, or if two entries assign
incompatible outcomes to the same target.

The recovery-policy body adds exactly:

```text
schema = "daimon-recovery-policy/v0"
replacement_recovery = {mode, keys, threshold}
```

Signature roles are `root-authorization`, `recovery-authorization` when an
existing recovery set exists, and `recovery-possession` for every replacement
threshold. Establishing the first recovery policy after an explicit genesis
`none` omits only `recovery-authorization`.

The reusable revocation entry has exactly:

```text
reason = registered ASCII reason code
target = {kind, id, kid|null}
effective = {
  mode: "on_acceptance"|"at_prior_position",
  prior_control_position: {recovery_generation, control_sequence,
                           control_hash}|null
}
event_high_waters = sorted [{operational_id, sequence, event_id, event_hash}]
lease_high_water = null or {lease_sequence, lease_id, lease_hash,
                             commit_receipt_id}
replacement_artifact_id = string or null
```

V0 target kinds are `certificate`, `operational-signing-key`,
`operational-encryption-key`, `root-key`, `recovery-key`, and
`certificates-from-control-cutoff`. V0 reason codes are `planned-rotation`,
`key-retired`, `key-compromise`, `key-loss`, `operational-fork`,
`policy-violation`, `operator-request`, and `unspecified`. New values require a
later registry/version and are not silently accepted by a V0 validator.

The valid target-field combinations are closed: `certificate` uses its
certificate ID and null `kid`; either operational-key kind uses its
`operational_id` and exact non-null key ID; either root/recovery-key kind uses
the control artifact ID that installed the set and the exact non-null key ID;
and `certificates-from-control-cutoff` uses the cutoff control artifact ID and
null `kid`. Every ID and hash MUST use its referenced type's exact grammar.
Event high-waters sort by `operational_id` and name exact event IDs and hashes.
The optional lease high-water is a singleton for the enclosing `me_id`, binds
its accepted external receipt, and is never keyed by operational credential.
A credential change never creates another lease namespace.

`on_acceptance` requires a null prior position; the effective position is the
derived position/hash of the enclosing standalone-revocation or recovery
wrapper after it validates.
`at_prior_position` requires an already verifiable position on the accepted
chain. The body never embeds its own not-yet-derived control hash, avoiding a
circular encoding.

A standalone revocation body adds the ordinary control fields plus
`schema = "daimon-revocation/v0"` and `revocation = <entry>`. A recovery
transition embeds the same entry shape in its `revocations` array, without a
second control position or separate signature. Entries are sorted by canonical
JCS bytes and duplicate targets are rejected.

The standalone signature role is `root-authorization`; recovery entries are
authorized by the enclosing recovery signatures. Standalone root/recovery-key
revocation is invalid outside the transition that installs its successor.

All four non-genesis control wrappers use
`artifact_id = dm:ctl:v0:<artifact-hash>` and their corresponding Section 3
domain.

### 5.3 Operational certificate and acceptance

The certificate body has exactly:

```text
schema = "daimon-operational-certificate/v0"
me_id
operational_id
operational_nonce = stable 32-byte base64url for this operational credential
certificate_nonce = fresh 32-byte base64url for this certificate generation
certificate_generation
previous_certificate_id = certificate ID or null
signing_key = Ed25519 descriptor
encryption_key = X25519 descriptor
issuing_control_position = {recovery_generation, control_sequence,
                            control_hash}
issuing_root_kids = sorted key IDs
issued_at_ms
not_before_ms
expires_at_ms
purposes = {
  signing: sorted subset of ["event", "presence-lease",
                             "event-checkpoint", "lease-head-receipt",
                             "sealed-delivery"],
  encryption: sorted subset of ["sealed-event-recipient"]
}
constraints = {
  max_event_bytes: integer from 1 through 1048576,
  event_type_prefixes: sorted non-empty event-type prefixes
}
initial_body_hash = 32-byte base64url or null
```

An empty signing/encryption purpose list grants no use of that key for the
corresponding protocol operations. An empty `event_type_prefixes` list grants
no event type. Prefix matching is byte-exact ASCII and does not confer resource,
relationship, scope, or transport authorization.

`issuing_root_kids` is the complete sorted set of key IDs in the active root
set at `issuing_control_position`, never the variable quorum subset whose
endorsements happen to be attached. The threshold is evaluated from that
active root descriptor.

The operational identifier is:

```text
operational_input = JCS({
  "operational_nonce": operational_nonce,
  "me_id": me_id,
  "signing_key": signing_key
})
operational_digest = SHA-256(
  UTF8("daimon/operational-id/v0") || 0x00 || operational_input
)
operational_id = "dm:op:v0:" || base64url(operational_digest)
```

Within one `/me`, an accepted operational signing public key MAY identify only
one `operational_id`; attempting to certify the same signing descriptor under a
different operational nonce/ID is a key-reuse conflict, not a second key.

The certificate identifier deliberately follows DM-010:

```text
certificate_digest = SHA-256(JCS(certificate_body))
certificate_id = "dm:cert:v0:" || base64url(certificate_digest)
```

Certificate generation zero requires `previous_certificate_id = null`. Every
renewal names the directly preceding accepted certificate, increments
generation by exactly one, reuses `operational_nonce` when the signing key is
unchanged, and draws a new `certificate_nonce`. Changing the operational
signing key requires a new operational nonce and ID. Two certificates for one
operational ID and generation are a certificate fork.

A certificate becomes active only after its certificate and subject acceptance
validate. Activation of generation `N+1` supersedes generation `N` for new
events and leases and durably advances the verifier's per-operational-ID
certificate high-water. Later arrival of evidence under an older generation
MUST NOT restore its broader purposes or constraints. Such evidence is timely
only when a prior durable acceptance record, a valid event checkpoint, or a
root/recovery high-water proves acceptance before supersession; otherwise it
remains attributable but is not admitted as current canonical evidence.

The certificate wrapper has exact fields `body`, `certificate_id`,
`certificate_hash`, and `signatures`; `certificate_hash` is base64url of the
certificate digest. Its signature role is `root-authorization` under the
certificate domain.

The acceptance body has exactly `schema = "daimon-operational-acceptance/v0"`,
`me_id`, `operational_id`, `certificate_id`, and `certificate_hash`. Its wrapper
uses `dm:accept:v0:<artifact-hash>` and one `subject-acceptance` signature from
the certificate's operational signing key.

### 5.4 Presence lease

The lease body has exactly:

```text
schema = "daimon-presence-lease/v0"
me_id
operational_id
certificate_id
session_id = 32-byte random base64url
lease_sequence
previous_lease_hash = 32-byte base64url or null
previous_lease_receipt_id = lease-head receipt ID or null
supersedes_session_id = 32-byte base64url or null
supersedes_operational_id = operational ID or null
superseded_event_cutoff = null or {
  operational_id, certificate_id, event_sequence, event_id, event_hash,
  checkpoint_id
}
issued_at_ms
expires_at_ms
body_hash = 32-byte base64url
capability_hash = 32-byte base64url
routes = sorted [{kind, route_id}]
```

Every certificate `initial_body_hash`, lease `body_hash`, and event
`body_hash` uses the same content reference defined in Section 6.1. A
lease capability reference is likewise exact:

```text
capability_hash = base64url(SHA-256(JCS(capability_body)))
```

DM-018 freezes both closed descriptive bodies. Until their canonical bytes are
available, description/capability detail is `incomplete`; implementations MUST
NOT substitute a locally generated advertisement that happens to describe the
same runtime.

`kind` is the closed enum `local`, `direct`, or `hub`. `route_id` has the exact
grammar `dm:route:v0:<32-byte-canonical-base64url>` and contains no endpoint or
credential. Route objects have exactly `kind` and `route_id`, sort by their
byte-exact `(kind,route_id)` pair, and reject duplicates. A route is a signed
reachability hint, not authorization; DM-053 defines its separately protected
endpoint resolution.

Only the `/me` identity's first-ever lease uses null predecessor and receipt
fields. Every successor increments the identity-wide sequence by exactly one,
names the previous signed lease hash and its accepted external receipt, and
never resets after operational-key or body change. A new session names the
superseded session and operational ID. If body or operational ID changes, it
also copies the exact receipt-bearing event cutoff for the superseded
credential. A purely local predecessor is not an accepted head.

The wrapper uses `dm:lease:v0:<artifact-hash>` and one
`operational-authorization` signature. Two successors of the same accepted
predecessor, two unexpired body claims for one `me_id`, or a retired credential
attempting to extend any later head are split-brain evidence and quarantine the
identity. Acceptance of a superseding head immediately makes its prior session
ineligible. It makes the prior operational credential ineligible only when the
new head changes `operational_id`; a same-body restart may reuse the credential
under its new committed session as allowed by DM-010.

### 5.5 External lease-head receipt

A signed receipt proves that an independent designated verifier durably stored
one lease head outside the subject body. Its body has exactly:

```text
schema = "daimon-lease-head-receipt/v0"
subject_me_id
lease_id
lease_hash
lease_sequence
session_id
operational_id
certificate_id
body_hash
event_cutoff = null or {
  operational_id, certificate_id, event_sequence, event_id, event_hash,
  checkpoint_id
}
subject_identity_control_position = {recovery_generation, control_sequence,
                                     control_hash}
witness_me_id
witness_operational_id
witness_certificate_id
witness_identity_control_position = {recovery_generation, control_sequence,
                                     control_hash}
accepted_at_ms
```

The wrapper uses `dm:lease-receipt:v0:<artifact-hash>`, the
`daimon/lease-head-receipt/v0` domain, and exactly one
`witness-authorization` signature. The witness must be a distinct `me_id`, its
accepted certificate must carry `lease-head-receipt` purpose, and local policy
must designate it as a wake verifier. A valid signature without that policy is
attributed storage evidence, not authority to move the identity. A
root/recovery control artifact committing the same lease high-water is an
authoritative alternative.

The signature proves only that the witness made this durable-retention claim;
it cannot prove physical storage durability. Relative to a verifier, a lease
becomes `committed` exactly when that verifier has durably accepted the lease,
its receipt, the witness designation, and all referenced identity/cutoff
evidence. Before then the signed lease is only `uncommitted` candidate evidence
and is never an active routing head.

Every copied lease field must equal the validated referenced lease. A non-null
event cutoff must equal a validated event checkpoint for the named operational
credential. Receipt time must fall within the subject lease and witness
certificate validity intervals. A wake lease is accepted only when its
`previous_lease_receipt_id` resolves to such an accepted receipt for its exact
predecessor. Receipt forks do not choose a lease branch: conflicting
receipt-bearing successors quarantine `/me`.

A lease may have more than one independently valid accepted receipt. Those
receipts form an unordered set keyed by receipt ID; accepting another receipt
for the same lease MUST NOT replace an earlier one or change the committed
head. A successor may cite any accepted receipt in that set and, when a body or
operational ID changes, MUST copy that cited receipt's exact `event_cutoff`,
including an exact null-to-null copy when the predecessor authored no
checkpointed events. Receipt arrival order therefore cannot change successor
validity.

## 6. Canonical event

### 6.1 Event body and identifiers

An event body has exactly:

```text
schema = "daimon-event/v0"
event_nonce = 32-byte random base64url
me_id
operational_id
certificate_id
event_sequence
previous_event_id = event ID or null
logical_time = {physical_ms, counter}
causal_parents = sorted event IDs
body_hash = 32-byte base64url
event_type = registered or extension ASCII identifier
intent = null or {thread_id, scope, operation}
payload = type-defined JSON value
```

An `event_type` is 1 through 128 ASCII bytes and matches
`^[a-z][a-z0-9]*(?:[./-][a-z0-9]+)*$`. DM-015 registers
`matrix/source-claim`, `matrix/source-assessment`,
`matrix/source-publication`, `matrix/source-cursor`, and
`matrix/source-import-decision`. A certificate prefix is 1 through 128
ASCII bytes, matches `^[a-z][a-z0-9./-]*$`, and is compared as a byte-exact
prefix of the complete event type. Empty prefixes, consecutive separators in
an event type, and unregistered bare names are rejected. DM-012 registers its
closed `matrix/` communication and convergence names; DM-013 through DM-017
register additional protocol names. Names beginning `x/` are extensions and
remain subject to certificate constraints and local semantic policy.

The event digest and ID are:

```text
event_preimage = UTF8("daimon/event/v0") || 0x00 || JCS(event_body)
event_digest = SHA-256(event_preimage)
event_hash = base64url(event_digest)
event_id = "dm:event:v0:" || event_hash
```

The event wrapper has exactly `body`, `event_id`, `event_hash`, and
`signature`. `signature` is one signature record with role
`operational-authorization`; its preimage is `event_preimage`.

`event_nonce` makes independently authored occurrences distinct even when their
semantic payloads are equal. Event identity establishes authorship, ordering,
and transport idempotency; it does not establish semantic equivalence or
admission into personal memory. DM-013 through DM-017 classify payloads,
including which event types represent lived experience.

For an event with non-null `intent` that DM-012 admits as a communication,
`event_id` is also its stable logical `message_id`. Fan-out, retry, forwarding,
and re-encryption MUST NOT create another message ID. A reply is a new event
with a new event/message ID. `thread_id` is an independently generated
`dm:thread:v0:<32-byte-random-base64url>` value. Replies in the same conversation
retain it; a thread ID is never derived from or substituted for a message ID.

At this layer `scope` and `operation` are inert signed strings. Cryptographic
acceptance MUST NOT be interpreted as scope validity, audience resolution,
sender authorization, operation execution, reply acceptance, semantic receipt,
or memory admission. DM-012 binds a direct reply target and the exact replied
message subset in its signed `matrix/reply` payload, retains `thread_id`, and
also cites those messages in `causal_parents`; it MUST NOT add an unsigned reply
identifier in the delivery layer.

`body_hash` identifies the exact canonical body-description body
claimed by the author:

```text
body_hash = base64url(SHA-256(JCS(body_description_body)))
```

The event signature authenticates this content reference. DM-018 freezes the
closed descriptive body and any independently signed body artifact;
DM-011 does not invent a second incomplete signature domain. Harness, model,
provider, host, tools, sensors, and actuators remain provenance claims, never
identity authority. Missing description bytes make detailed provenance
`incomplete`; the receiver MUST NOT substitute its own body, the latest lease,
or harness-derived metadata. Presence is not required for offline event
authorship. Offline evidence remains eligible only through the event cutoff
later committed by park/wake. After a superseding lease is accepted, any event
from the retired credential above that exact sequence/hash is inadmissible
regardless of its claimed timestamp; the event at the cutoff must match the
exact committed ID and hash.

### 6.2 Per-operational-credential sequence and causal order

Event sequence is one domain-specific counter per operational ID. It starts at
zero and increments by exactly one. Sequence zero has a null
`previous_event_id`. Every later event names the previous event from that
operational ID, and that ID also appears in `causal_parents`.

`causal_parents` is the author's signed causal-provenance claim. The author MUST
include every event it identifies as a direct observed cause, but a verifier
cannot prove that no cause was omitted. Parents MAY be events of another `/me`
or operational ID; each validates against its own genesis, control, certificate,
and signature proof. Cross-`/me` causality grants no identity, scope, disclosure,
or memory authority. The set is duplicate-free and capped at 64.

For sequence zero, non-null `previous_event_id` is malformed. For every sequence
greater than zero, an absent or null `previous_event_id` is malformed; a validly
formed reference whose target bytes are not yet available makes the event
cryptographically attributable but contextually `incomplete`. Any unavailable
causal-parent bytes have the same incomplete result. The event MAY be retained
immutably as pending evidence, but MUST NOT feed projections or effects requiring
the missing context. Once the predecessor arrives, the verifier enforces the
exact sequence increment, predecessor link, parent inclusion, and HLC relation.
A known predecessor whose sequence or ID conflicts is invalid or fork evidence;
mere out-of-order arrival is not.

`logical_time` is a hybrid logical clock whose `physical_ms` and `counter` are
non-negative safe integers. Tuples compare lexicographically. To author an
event, let `p` be the maximum of local wall-clock milliseconds, the previous
local event's physical component, and every known causal parent's physical
component. If `p` comes only from wall clock, counter is zero; otherwise counter
is one plus the maximum counter among known previous/parent tuples whose
physical component equals `p`. The emitted tuple is therefore strictly greater
than the previous local tuple and every known parent tuple.

If incrementing the counter would exceed `2^53-1`, the author MUST wait until a
strictly larger physical millisecond is available and emit counter zero; it
MUST NOT wrap, saturate, or encode an unsafe integer.

The physical component is informational and HLC order is a deterministic
projection aid, not proof of real-world time or a substitute for causal parents.
If a late predecessor/parent makes the signed tuple non-increasing, the event
becomes invalid causal evidence and its dependent projections are quarantined;
same-operational-ID sequence equivocation still follows the fork rule below.

Two different valid events with the same `(operational_id, event_sequence)` are
an operational fork. A verifier quarantines the `/me`, both branches, and their
descendants until the DM-010 root/recovery process selects a cutoff and
replacement credential. Longest chain,
arrival order, wall clock, route, and host preference never choose a winner.

### 6.3 Validation and replay

Validation order is:

1. enforce byte/depth limits and strict JSON;
2. validate the closed wrapper/body and canonical binary forms;
3. recompute event hash and ID;
4. validate genesis, control head, certificate, subject acceptance, and
   revocation state at the verifier's named checkpoint;
5. verify the Ed25519 signature under the event domain;
6. enforce certificate purposes and every sequence, predecessor, causal, and HLC
   invariant decidable from available evidence; return `incomplete` rather than
   accept or reject when required predecessor evidence is absent;
7. durably record replay/fork state before projection or external effects.

The replay key is `(me_id,event_id)`. Identical canonical bytes are idempotent.
The same ID with different bytes is a content-address conflict. The same
operational credential/sequence with different IDs is a fork. A replay received through
another route or sealed delivery does not create another event.

## 7. Event checkpoint evidence

An event checkpoint attests that a verifier or authorized witness claims to
have accepted a specific operational credential event prefix by a stated local time. Its
signature proves the source and coverage of that claim, not objective time.

Its body has exactly:

```text
schema = "daimon-event-checkpoint/v0"
subject_me_id
subject_operational_id
subject_certificate_id
high_water_sequence
high_water_event_id
high_water_event_hash
subject_identity_control_position = {recovery_generation, control_sequence,
                                     control_hash}
witness_me_id
witness_operational_id
witness_certificate_id
witness_identity_control_position = {recovery_generation, control_sequence,
                                     control_hash}
accepted_at_ms
```

The wrapper uses `dm:checkpoint:v0:<artifact-hash>` and the checkpoint domain,
with one `witness-authorization` signature. The complete subject prefix and
subject certificate state validate relative to
`subject_identity_control_position`. The witness certificate, subject
acceptance, `event-checkpoint` signing purpose, and revocation state validate
relative to `witness_identity_control_position`. A portable signed witness
MUST be a distinct `me_id` from the subject; another credential of the same
identity is not independent off-body evidence. A root/recovery control artifact containing the same
subject high-water is authoritative checkpoint evidence without a separate
witness artifact.

The named high-water event MUST have exactly `subject_me_id`,
`subject_operational_id`, and `subject_certificate_id` from the checkpoint body,
and its recomputed sequence, event ID, and event hash MUST equal all three
high-water fields. `accepted_at_ms` MUST fall within the subject certificate's
validity interval for local or witness timeliness; that signed-time condition is
necessary but is not sufficient evidence of objective time. A checkpoint cannot
pair an old event with a newer certificate or cross a certificate generation
implicitly.

A checkpoint covers only the subject operational ID's contiguous prefix obtained
by following `previous_event_id` back from the named high-water. A causal parent
authored by another operational ID requires its own checkpoint evidence. The
checkpoint does not make descendants timely. For an event first observed after
its certificate expired, a verifier may establish timeliness from exactly one of:

1. its own durable record that it accepted the event/checkpoint before expiry;
2. a root/recovery control artifact that commits the covered high-water; or
3. an explicit local policy that trusts the named witness as a time attestor.

The third result is `attested-timely`, not objective cryptographic time, and its
proof bundle identifies the policy and witness checkpoint. With none of these,
the signature remains attributable but the event is not automatically canonical
lived experience. A newly seeded verifier MUST NOT treat any signed witness
timestamp as trusted merely because the witness is another operational ID.
A checkpoint first observed only after the witness certificate expired is also
attributable but not automatically portable time evidence without a prior local
record or another policy-authorized time attestation.

## 8. Recipient-encrypted sealed delivery

### 8.1 Purpose and protected metadata

A sealed delivery encrypts the canonical UTF-8 bytes of one complete event
wrapper. It is not itself a ledger event. It has exactly:

```text
schema = "daimon-sealed-event/v0"
delivery_id = "dm:delivery:v0:" + 32-byte random base64url
event_id
event_hash
sender = {me_id, operational_id, certificate_id, signing_kid}
disclosure_authorization_id = signed resolution/grant/event ID
issued_at_ms
expires_at_ms
suite
recipients = sorted [{me_id, operational_id, certificate_id,
                      encryption_kid, enc, wrapped_cek}]
payload = {nonce, ciphertext}
signature
```

The protected metadata is the same object with `recipients` reduced to their
identity/key descriptors, and without `payload`, HPKE `enc`/`wrapped_cek`, or
`signature`. It therefore binds the delivery, inner event, sender, expiry,
suite, and exact concrete recipient/key set.

The recipient array contains from 1 through 256 unique certified operational credentials;
duplicate recipient triples or encryption keys are rejected. The sender
certificate requires `sealed-delivery` signing purpose and every recipient
certificate requires `sealed-event-recipient` encryption purpose. Delivery TTL
is at most 24 hours. For each receiver, effective expiry is the minimum of
wrapper expiry, sender-certificate expiry, and that receiver's certificate
expiry; one short-lived recipient does not expire another recipient's delivery.

Every delivery requires a DM-012/DM-016 signed resolution, grant, or event that
binds the exact `event_id`, sender certificate/signing key, and concrete
recipient certificate/encryption-key set; its ID is mandatory as
`disclosure_authorization_id`. Author equality proves who sealed/authored data,
not permission to disclose it. A different certified operational credential may reseal
only when that same evidence also authorizes forwarding. DM-011 does not invent
the authority. Until it validates, a receiver MUST reject semantic processing
even when signatures and decryption succeed. The inner event signature remains
its authorship authority. A hub without plaintext, recipient keys, and explicit
authority cannot rewrap or expand readership.

After decryption, the outer `event_id` and `event_hash` MUST equal the recomputed
inner values. The disclosure evidence determines whether the outer sender must
equal the inner author or is authorized as a resealer.

An opaque carrier MAY relay a byte-identical sealed delivery without plaintext
and without becoming its sender. Resealing is attributable to the new outer
sender. Possession of plaintext, recipient status, `/we` membership, or a valid
certificate never grants forwarding by itself; durable consent, disclosure
audit, and semantic forwarding receipts are downstream canonical events, not
claims inferred from disposable delivery state.

### 8.2 Encryption and signatures

For every new sealed delivery the sender draws a fresh 32-byte CEK and 12-byte
payload nonce from an operating-system CSPRNG. The payload is:

```text
payload_aad = UTF8("daimon/sealed-event/payload-aad/v0") || 0x00 ||
              JCS(protected_metadata)
ciphertext = ChaCha20Poly1305.encrypt(CEK, nonce,
                                      JCS(complete_event_wrapper), payload_aad)
```

For each recipient, HPKE base-mode Seal encrypts the CEK to the X25519 public
key in its currently valid operational credential certificate. HPKE uses empty AAD and:

```text
hpke_info = UTF8("daimon/sealed-event/cek-wrap/v0") || 0x00 ||
            JCS({"protected": protected_metadata,
                 "recipient": recipient_identity_key_descriptor})
```

The outer signature is Ed25519 over:

```text
UTF8("daimon/sealed-event/v0") || 0x00 ||
JCS(sealed_delivery_without_signature)
```

It is one exact Section 4 signature record with role `delivery-authorization`,
made by `sender.signing_kid`; threshold endorsements are not permitted.

`enc` is the canonical 32-byte HPKE encapsulated key and `wrapped_cek` is the
canonical 48-byte HPKE ciphertext for the 32-byte CEK with a 16-byte AEAD tag.
The payload nonce is exactly 12 bytes and ciphertext is at least 16 bytes.

The receiver validates the strict wrapper, sender certificate/revocation,
outer signature, its exact recipient entry, and key ownership before HPKE open
or payload decryption. It then validates the decrypted canonical event from
scratch; an outer signature never blesses an invalid inner event.

### 8.3 Retry, replay, and key change

Route retries retain byte-identical sealed delivery and `delivery_id`.
Re-encryption, a changed recipient set, or recipient-key rotation creates a new
delivery ID, CEK, nonce, ciphertext, and signature while retaining the same
inner `event_id`. A new delivery MUST use each recipient's latest accepted
certificate/encryption key. Pending ciphertext to a compromised recipient key
is treated as exposed and MUST NOT be silently declared safe by rewrapping.

A durable outbox MUST retain the canonical event and its disclosure evidence,
not only one expiring ciphertext, until DM-012 records either a terminal
semantic receipt or an explicit canonical cancellation/expiry-policy event.
Absent one of those terminal events, an authorized sender MUST keep the item
eligible for retry and issue fresh sealed deliveries as transport envelopes
expire, with new delivery IDs while retaining the event/message ID. A changed
concrete sender or recipient certificate/key requires a fresh or explicitly
revalidated disclosure authorization binding that new concrete set. Offline
backlog therefore does not depend on a single 24-hour transport envelope and
local ephemeral retry policy cannot silently discard it.

The delivery replay key is `delivery_id`; semantic ingestion still deduplicates
on `(me_id,event_id)`. Delivery expiry limits transport processing only and
does not expire or delete the canonical event.

An exact duplicate delivery is idempotent. The same delivery ID with different
canonical bytes is a delivery conflict and is rejected before decryption.
For planned key retirement, an already authorized delivery to the old key
remains processable only until the minimum of wrapper expiry and that old
certificate's expiry. The recipient MUST retain the old private decryption key
through that window. A fresh delivery to a new certificate/key requires the
fresh or revalidated concrete disclosure authorization above. Revocation for
compromise rejects pending old-key processing immediately; planned retirement
and compromise are never conflated. Destroying an old private key early may
make ciphertext undecryptable and does not authorize identity rollback or
fallback to another key.

This suite offers no sender/recipient metadata hiding, post-compromise secrecy,
anonymous messaging, deniable authentication, or exactly-once effects.

## 9. Conformance vectors

The repository vector set is normative. It contains only synthetic test keys
and public fixtures. Implementations MUST consume the checked-in bytes rather
than regenerate random fields and compare whole files.

Deterministic golden vectors cover:

- strict JSON/JCS and canonical base64url;
- Ed25519 seed-to-public-key;
- genesis core to `me_id`;
- operational input to `operational_id`;
- certificate body to certificate ID/hash;
- one valid signed wrapper for every identity domain;
- genesis to root transition, recovery policy/transition, certificate,
  acceptance, revocation, identity-wide lease, external receipt, and park/wake
  linkage;
- event zero and a causal successor with exact JCS bytes, hash, ID, signature,
  HLC, parents, and message/thread intent;
- checkpoint coverage and control high-water binding;
- sealed-delivery protected metadata, AAD, HPKE info, signature preimage, and
  successful decryption.

HPKE encryption is randomized. Checked-in sealed vectors are fixed fixtures
whose decryption is normative; regeneration need not produce identical
encapsulation/ciphertext. Independent implementations MUST additionally pass
the RFC 9180 known-answer tests for the Section 3 suite.

Executable or explicitly documented entries cover every DM-010 Section 13
scenario whose wire artifacts are frozen by DM-010/DM-011. Collective
membership ceremony scenarios remain assigned to DM-012 rather than being
simulated with transport or operational authority. The DM-011 negatives also
cover:

- escaped duplicate keys such as `"a"` plus `"\u0061"`, unknown properties,
  invalid UTF-8, float, negative zero, safe-integer exact boundaries, unsafe
  integer, excessive depth/size at every exact ceiling, non-canonical wire JSON,
  and non-canonical base64url; NFC and NFD strings remain distinct signed data;
- derived ID/hash mismatch and modified canonical body;
- derived key-ID mismatch, one public key under aliases, missing/duplicate/short
  threshold signatures, partial quorum then completion, and merge of different
  valid quorum subsets;
- non-canonical Ed25519 `S`, invalid/small-order Ed25519 points, and X25519
  low-order/all-zero-DH inputs;
- authorization signature used as possession proof or cross-domain replay;
- reused public key across root, recovery, operational signing/encryption, or
  transport roles, including two operational IDs claiming one signing key;
- certificate-generation gap, predecessor mismatch, fork, rollback, and replay
  of an older broader certificate after renewal;
- a certificate simultaneously preserved and effectively revoked by one
  recovery transition;
- lease sequence reset after operational rotation, unreceipted wake, wrong
  receipt binding or witness, conflicting receipt-bearing body successors, and
  old-credential lease/event evidence after the accepted handoff cutoff;
- an operational certificate attempting to grant `/we` membership authority;
- known event sequence gap, wrong known predecessor, missing local predecessor
  from causal parents, HLC regression, duplicate parents, and more than 64
  parents; out-of-order unknown predecessors produce `incomplete`, not reject;
- identical experience payload with distinct nonces remains two events;
- same event replay is idempotent, same sequence/different event is a fork;
- unknown causal parent yields incomplete quarantine, not silent projection;
- late parent revealing an HLC regression, HLC counter overflow, and a valid
  cross-`/me` causal parent with no imported authority;
- post-expiry event not covered by a pre-expiry checkpoint is not timely;
- checkpoint claiming a descendant beyond its high-water does not cover it;
- checkpoint certificate, ID, hash, or sequence mismatch is rejected;
- subject checkpoint does not cover another operational ID merely because its
  event is a causal parent;
- witness checkpoint first seen after expiry without explicit attestor policy
  remains attributable but not timely;
- sealed delivery with missing, wrong-event, wrong-sender, or wrong-recipient
  disclosure authorization is rejected;
- empty, duplicate, unsorted, or oversized recipient sets are rejected;
- outer/inner event ID or hash mismatch is rejected;
- same delivery ID with different bytes is a conflict; exact retry is idempotent;
- delivery TTL/certificate bounds and recipient-key retirement/revocation are
  enforced;
- planned old-key decryption versus compromised-key rejection, authorization
  refresh after certificate/key rotation, and independent per-recipient expiry;
- 24-hour transport expiry mandates durable reseal under a new delivery ID while
  retaining the event/message ID until a canonical terminal decision;
- tampered recipient descriptor, AAD, HPKE info, encapsulation, wrapped CEK,
  nonce, ciphertext, outer signature, or inner event;
- retired/revoked sender or recipient certificate/key and control-head rollback;
- same inner event re-encrypted under a new delivery remains one event.

Stable validation outcomes are `accept`, `uncommitted`, `committed`,
`attested-timely`, `idempotent`, `incomplete`, `expired`, `revoked`,
`quarantined`, and `unverifiable`.
Implementations MAY expose local diagnostic subcodes, but V0 does not claim an
interoperable exhaustive reason-code registry. Remote errors MUST NOT expose
identity membership to an unauthorized caller.

## 10. Reuse and rejection record

From Tribe v1 PR 14 at
`10a1d8bc535dfc1404174d2265f2a7a123329c62`, V0 reuses after adaptation:

- strict I-JSON/JCS and base64url canonicality patterns;
- Ed25519 domain-separated whole-object signatures;
- RFC 9180 X25519/HKDF-SHA256/ChaCha20-Poly1305 HPKE CEK wrapping;
- signature-before-decryption validation order;
- positive/negative vector organization, replay conflicts, and stable errors.

V0 explicitly rejects or leaves behind:

- Tribe agent IDs, static audiences, allowed-sender lists, and governance roots
  as identity or scope authority;
- `@localhost` strings as cryptographic locality or identity proof;
- UUID timestamps and wall-clock replay windows as event identity/order;
- transport acknowledgements as semantic receipts;
- any v0 group-key construction or history;
- the divergent newline-appending manifest canonicalizer;
- runtime keys, credentials, real CompAII memory, or live ciphertext in fixtures.

## 11. Downstream contract

- DM-012 defines scope/operation registries, resolution, authorization, fan-out,
  independent replies, thread participation, and semantic receipts over intent.
  DM-011 owns event/message ID, thread ID wire syntax, and cryptographic binding.
- DM-013 through DM-017 define the payload schemas for birth, species, source,
  tribe, and memory-boundary events and decide which accepted events represent
  lived experience, consolidation, or another semantic class.
- DM-018 freezes the canonical body-description body and adapter bindings.
- DM-021 implements identity artifact validation and key custody.
- DM-022 stores canonical event bytes and intrinsic replay/fork evidence without
  rewriting.
- DM-023 manages contextual completeness, checkpoint availability, projections,
  cursors, and idempotent `/we.sync` convergence. It never changes event IDs,
  invents body provenance, or turns cryptographic acceptance into semantic
  admission.
- DM-050 and DM-051 adapt Tribe routing and recipient encryption to sealed
  deliveries without importing Tribe authority.
- DM-073 independently verifies parser, canonicalization, crypto, rollback,
  checkpoint, replay, and compromise behavior before release.
