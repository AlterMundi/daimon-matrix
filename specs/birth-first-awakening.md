# Birth and first awakening

Status: normative V0 specification.

This document defines how an existing daimon (the parent) offers birth to a
distinct root-bearing `/me` identity (the newborn), how the newborn binds that
offer at genesis, and how the newborn completes its first awakening without
transferring parent identity, keys, or autobiographical state. Identity
continuity, custody, operational credentials, and presence evidence come from
DM-010 ([`identity-continuity.md`](identity-continuity.md)); canonical
encoding, event, signature, and receipt primitives come from DM-011
([`canonical-artifacts.md`](canonical-artifacts.md)); collective membership
comes from DM-012 ([`scope-resolution.md`](scope-resolution.md)).

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, **SHOULD NOT**,
and **MAY** are interpreted as described by RFC 2119 and RFC 8174.

## 1. Security goals

The protocol MUST establish all of the following:

1. one non-quarantined birth lineage binds exactly one new, distinct `me_id`;
   it is never a body move, a rename, a park/wake transition, or a `/we`
   membership change;
2. the newborn locally generates and retains every root, recovery, operational
   signing, and operational encryption private key; the parent and every
   transport or bootstrap intermediary never possess them;
3. the offer is bound after the fact to the newborn's self-certifying genesis;
   no artifact can assign or predict a `me_id` before newborn genesis;
4. lineage evidence (offer, acceptance, receipt) binds the exact parent and
   newborn genesis, source references, species release, and future
   tribal-delegation commitments, and fails closed under replay, double
   acceptance, expiry, missing evidence, forks, unavailable referenced
   artifacts, and compromised keys;
5. first awakening claims active presence only after the complete DM-010
   operational certificate, subject acceptance, body provenance, identity-wide
   lease, and external lease-head receipt chain validates;
6. the newborn's autobiographical memory is mechanically empty at birth, and
   no parent personal state crosses the boundary;
7. birth grants no `/we` membership, no parent credential, and no parent
   authority over the newborn.

The protocol does not prove sentience, parentage in any biological or social
sense, the truth of any species/source claim, or that an operator did not
secretly copy key material outside the protocol. It proves only the signed
lineage and authorization claims defined here. Local generation, custody
controls, and the absence of private-key fields from every canonical schema
make non-transfer an auditable operational invariant, not an impossible
cryptographic proof of another machine's history.

## 2. Layer and authority boundaries

Birth reuses DM-010/DM-011 primitives without extending their authority:

- The parent authors the birth offer and the optional birth receipt as ordinary
  DM-011 canonical events under an operational credential. That credential's
  authority is subordinate to the parent's `me_id` through the DM-010
  certificate chain; the parent operational key authorizes only those events
  and never becomes newborn identity authority.
- The newborn binds the offer through its DM-010 genesis statement
  (`birth_offer_id`) and signs one birth acceptance with its own root threshold
  under the `daimon/birth-acceptance/v0` domain. This is the only V0
  birth-specific use of a root key, and it is registered in DM-010 Section 3
  and the DM-011 Section 3 domain list.
- Offer transport, bootstrap routes, harnesses, hosts, models, providers, and
  any directory or roster encountered during bootstrap are carriers and
  descriptive metadata. They MUST NOT generate, hold, escrow, or sign newborn
  key material, and MUST NOT be treated as identity, membership, presence, or
  lineage authority. A bootstrap service that relays offer, genesis,
  acceptance, or receipt bytes changes nothing about their validation.
- Birth artifacts are not DM-012 membership evidence. The newborn is not
  admitted to the parent's `/we` (or any `/we`) by birth; admission requires a
  DM-012 governance-authorized transition plus the newborn's own membership
  acceptance. The newborn inherits none of the parent's memberships, routes,
  sessions, or presence leases.
- Birth is not a species event by itself. The offer names an existing species
  release; DM-014 owns release registries, compatibility, and speciation.

A newborn genesis with a null `birth_offer_id` is an ordinary DM-010 genesis
with no DM-013 lineage. A `me_id` cannot acquire a birth reference after
genesis: the genesis statement is immutable and identifier-defining.

## 3. Artifacts, identifiers, domains, and signature roles

| Artifact | Carrier | ID | Domain | Signature |
|---|---|---|---|---|
| birth offer | DM-011 event, `matrix/birth-offer` | its `event_id` is `birth_offer_id` | `daimon/event/v0` | one `operational-authorization` signature from a parent operational key |
| birth acceptance | threshold artifact | `dm:birth-accept:v0:<artifact-hash>` | `daimon/birth-acceptance/v0` | `birth-acceptance` endorsements satisfying the newborn root threshold |
| birth receipt (optional) | DM-011 event, `matrix/birth-receipt` | its `event_id` | `daimon/event/v0` | one `operational-authorization` signature from a parent operational key |

DM-013 registers `matrix/birth-offer` and `matrix/birth-receipt` in the
DM-011 event-type registry. The parent's operational certificate MUST
authorize event-type prefixes covering every birth event it authors; a
certificate lacking the prefix makes the event inadmissible, exactly as for
any other event type.

The acceptance hash and ID follow the DM-011 Section 3 artifact formula:

```text
acceptance_preimage = UTF8("daimon/birth-acceptance/v0") || 0x00 || JCS(body)
acceptance_hash_raw = SHA-256(acceptance_preimage)
acceptance_hash = base64url(acceptance_hash_raw)
acceptance_id = "dm:birth-accept:v0:" || acceptance_hash
```

The acceptance is a threshold artifact: its `birth-acceptance` endorsements
are mergeable under the DM-011 Section 4.2 rule, so different valid quorum
subsets over the identical body remain one artifact and never fork the
lineage. The offer and receipt are events and follow every DM-011 Section 6
rule, including per-credential sequence, causal parents, HLC, and replay.

The one-use bootstrap challenge uses a fresh Ed25519 capability key under the
registered `daimon/birth-awakening-challenge/v0` domain. It proves possession
of a confidential invitation capability for this exact acceptance core. The
capability signature is publicly verifiable but is not an identity signature,
recovery signature, membership credential, or reusable grant.

## 4. Birth offer

### 4.1 Payload schema

The offer is a DM-011 event whose closed payload has exactly:

```text
schema = "daimon-birth-offer/v0"
offer_nonce = 32-byte random base64url
awakening_key = Ed25519 public signing-key descriptor
parent_me_id
parent_identity_control_position = {recovery_generation, control_sequence,
                                    control_hash}
species_release_id = DM-014 species release ID
source_references = sorted unique [DM-015 source-claim event ID]
tribal_commitments = sorted unique [commitment object]
issued_at_ms
expires_at_ms
bootstrap_routes = null or sorted [{kind, route_id}]
```

Each tribal commitment is a closed object describing one future delegation the
parent commits to issue after newborn keys exist:

```text
{
  tribe_ref = reference string,
  resource_refs = sorted unique [reference string],
  operations = sorted unique [ASCII operation string],
  delegable = boolean,
  max_delegation_depth = integer 0..16,
  expires_at_ms = integer or null
}
```

The event-level `intent` field MUST be null: an offer is not a DM-012
communication and resolves no scope audience. `parent_me_id` MUST equal the
event's `me_id`, and `parent_identity_control_position` MUST name an accepted
position on the parent's identity-control chain at which the signing
certificate validates. DM-016 freezes `tribe_ref` as an exact
`dm:tribe:v0:<digest>` ID, `resource_refs` as exact
`dm:tribe-resource:v0:<digest>` IDs, operation names under its byte-exact
registered-operation grammar, and every commitment's resolution semantics.
DM-015 freezes `source_references` as source-claim event IDs.
`species_release_id` matches exactly
`dm:species-release:v0:<32-byte-canonical-base64url>` and is the exact string
the newborn genesis statement MUST carry verbatim. Operation strings are
printable ASCII of 1 through 128 bytes.

Before publishing the offer, the parent generates a fresh Ed25519 capability
keypair independently of every identity, recovery, operational, transport, and
other offer key. The offer carries only `awakening_key`. The private
`awakening_capability_key` is delivered once through a confidential bootstrap
path, is destroyed by the parent after successful delivery, and MUST NOT appear
in the offer, route objects, logs, or any durable parent/newborn artifact.
Possession of this private capability grants only permission to consume this
offer; it grants no newborn identity authority.

A verifier MUST apply the DM-011 Section 4.1 public-descriptor checks to
`awakening_key` and reject the offer if it duplicates any Ed25519 root,
recovery, operational-signing, or transport descriptor in the parent's
presented proof bundle, or any capability key of another known offer. At
acceptance it also rejects duplication with any newborn root or recovery
descriptor; operational issuance later performs the corresponding comparison.
Discovery after acceptance of reuse with another offer is key-reuse conflict
evidence and quarantines both offer lineages. As DM-011 explains, a wire
verifier cannot detect reused seed material across Ed25519 and X25519 public
keys; independent cross-algorithm generation remains a custody requirement.

The closed schema contains no newborn field. Because `me_id` derives from a
newborn-generated 256-bit genesis nonce and newborn-generated root keys, the
parent cannot know, assign, predict, or constrain the future `me_id`; an offer
carrying any property that purports to name or pre-commit the newborn
identity or keys is malformed and MUST be rejected at parse time.

### 4.2 Offer semantics

- One offer is usable at most once: a verifier durably accepts at most one
  distinct birth acceptance per `birth_offer_id` (Section 10).
- `expires_at_ms` MUST be greater than `issued_at_ms`, at most 604800000 ms
  (7 days) after it, and within the signing certificate's validity interval.
  The half-open interval `[issued_at_ms, expires_at_ms)` follows DM-011
  Section 2.2. V0 has no separate withdrawal artifact; an unneeded offer is
  left to expire.
- `bootstrap_routes` are reachability hints toward the newborn bootstrap
  environment using the DM-011 route grammar. They authorize nothing, are
  never required for validity, and MUST NOT carry endpoints or credentials.
- The offer commits the parent only to the stated species release, source
  references, and tribal commitments. It does not delegate any grant by
  itself: DM-016 issues the corresponding fresh grants bound to newborn keys
  after genesis.
- Delivery is carrier-agnostic. The signed event bytes are self-authenticating
  whether transferred out of band, through a bootstrap file, or inside a
  DM-011 sealed delivery; in the last case every DM-011 Section 8 rule,
  including disclosure authorization, applies unchanged.
- Possession of the offer bytes alone is insufficient to accept it. A leaked
  or guessed route, public event, directory entry, or copied offer without the
  private `awakening_capability_key` cannot produce the Section 6 proof.
  Leakage of that key is compromise of the offer, not compromise of either
  `/me`; multiple valid acceptances still follow Section 10.5.

## 5. Newborn key generation and genesis binding

Before any acceptance exists, the newborn environment MUST locally generate,
from an operating-system CSPRNG and with independent seeds per key:

- the initial root key set;
- the recovery key set when genesis declares threshold recovery;
- no operational keys yet (Section 8 generates them after acceptance).

Every newborn identity private key remains in the newborn's local custody under
DM-010 Section 6.1 from the moment of generation. Newborn root, recovery, and
operational private material MUST NOT appear in the offer, in any bootstrap
package, in any parent artifact, or on any wire. The separate one-use invitation
capability of Section 4 is not identity key material. Bootstrap or parent-held
material claiming to be a newborn identity private key is malformed by
definition; a verifier MUST reject the affected artifacts and treat the
disclosure as compromise evidence.

The newborn genesis core and statement follow DM-010 Section 4 and DM-011
Section 5.1 exactly, with these birth requirements:

- `birth_offer_id` is the exact `event_id` of the validated offer;
- `species_release_id` is non-null and byte-equal to the offer's
  `species_release_id`;
- the genesis nonce, root keys, and recovery keys are newborn-generated;
  no root or recovery public descriptor may duplicate any descriptor in the
  parent's presented proof bundle (root, recovery, operational signing, or
  operational encryption), which the DM-011 cross-role reuse check treats as
  key-reuse evidence.

The genesis is self-certifying and valid on its own even if the offer later
becomes inadmissible: lineage validity and identity validity are separable
(Section 10.6). Conversely, a genesis citing an offer is not a completed
birth until the Section 6 acceptance validates.

## 6. Birth acceptance artifact

### 6.1 Body schema

The acceptance body is closed and has exactly `schema`, `core`, and
`awakening_proof`:

```text
schema = "daimon-birth-acceptance/v0"
core = {
  newborn_me_id,
  newborn_genesis = {artifact_id, artifact_hash},
  offer = {event_id, event_hash},
  parent_me_id,
  parent_identity_control_position = {recovery_generation, control_sequence,
                                      control_hash},
  species_release_id = DM-014 species release ID,
  source_references = sorted unique [DM-015 source-claim event ID],
  tribal_commitments = sorted unique [commitment object],
  accepted_at_ms
}
awakening_proof = 64-byte Ed25519 signature as base64url
```

The proof is:

```text
challenge_preimage = UTF8("daimon/birth-awakening-challenge/v0") ||
                     0x00 || JCS(core)
awakening_proof = base64url(Ed25519.sign(awakening_capability_key,
                                         challenge_preimage))
```

The verifier checks `awakening_proof` against the offer's exact
`awakening_key`. The newborn root endorsements sign the complete
acceptance body, including the capability proof, so it cannot be moved to a
different acceptance or genesis.

### 6.2 Wrapper and signatures

The wrapper is the DM-011 Section 4.2 generic signed wrapper with
`artifact_id = acceptance_id` and `artifact_hash = acceptance_hash`. Its
signature records use role `birth-acceptance` and MUST satisfy the newborn
root threshold declared by the cited genesis, evaluated over distinct public
keys. An operational, recovery, transport, parent, or witness key MUST NOT
sign the acceptance; such a signature is invalid regardless of its bytes.

### 6.3 Equality and evidence requirements

A verifier MUST enforce all of the following before accepting:

1. `core.newborn_me_id` recomputes from the cited genesis core, and
   `core.newborn_genesis.artifact_id`/`artifact_hash` recompute from the cited
   genesis wrapper under the genesis domain;
2. the cited genesis statement validates, its `birth_offer_id` equals
   `core.offer.event_id`, and its `species_release_id` equals both the offer's
   and the acceptance core's `species_release_id`;
3. the offer event validates under DM-011 Section 6.3 at
   `core.parent_identity_control_position`, its recomputed event hash equals
   `core.offer.event_hash`, and the acceptance core's `parent_me_id`,
   `parent_identity_control_position`, `source_references`, and
   `tribal_commitments` are byte-equal to the offer payload's;
4. `awakening_proof` validates against the exact acceptance core and the
   offer's `awakening_key`;
5. `core.accepted_at_ms` falls inside the offer's half-open validity interval,
   while remaining a signed claim and never portable proof of time;
6. at first durable validation, either the verifier's verified local time falls
   inside that interval or the Section 7 external-witness chain establishes
   pre-expiry observation; with neither, the verifier durably retains the
   candidate as `time-unverifiable` but does not accept or project it;
7. the species/source references are syntactically bound and their available
   bytes are retained with attribution; missing downstream schemas or bytes
   yield `context-incomplete` as Section 10.6 defines rather than invalidating
   identity or lineage binding; and
8. no distinct acceptance has been durably accepted for the same
   `offer.event_id` (Section 10.5).

An acceptance that fails requirements 1 through 5 or 8 is rejected.
Requirement 6 returns `time-unverifiable` rather than rejection, and requirement
7 affects contextual claims rather than the cryptographic birth binding. A
verifier durably records every candidate and its evidence state before applying
any projection.

## 7. Optional parent receipt

The parent MAY acknowledge the completed binding with one DM-011 event of
type `matrix/birth-receipt` whose closed payload has exactly:

```text
schema = "daimon-birth-receipt/v0"
offer_event_id
offer_event_hash
newborn_me_id
newborn_genesis_artifact_id
newborn_genesis_artifact_hash
acceptance_artifact_id
acceptance_artifact_hash
acknowledged_at_ms
```

The receipt's event author MUST be the same `parent_me_id` as the offer's.
Every referenced artifact MUST validate, and every copied field MUST equal the
validated referent. `acknowledged_at_ms` MUST fall inside the offer interval,
but, like every DM-011 timestamp, is only a signed claim.

The receipt is not required for the newborn identity or the cryptographic
offer/acceptance binding, and it is not portable time proof by itself. A
verifier accepts historical timeliness only from either its own durable record
of the acceptance or receipt before expiry, or this complete DM-011
external-witness chain:

1. the parent birth-receipt event cites the exact acceptance;
2. a parent event checkpoint covers that receipt event;
3. a distinct, locally designated time witness signs an accepted DM-011
   lease-head receipt for a valid parent presence lease, with `event_cutoff`
   equal to that exact checkpoint; and
4. the witness receipt's `accepted_at_ms` falls inside the birth-offer interval.

The verifier MUST validate the complete parent and witness identity,
certificate, lease, checkpoint, cutoff, receipt, designation, and signature
chains. The witness is trusted only for durable observation and clock evidence;
it gains no parent or newborn identity authority. A parent checkpoint,
root/recovery high-water, receipt timestamp, or HLC without that external
witness is still only parent-authored timing evidence. A birth receipt first
seen after expiry with no valid chain is `time-unverifiable`, not proof that the
acceptance occurred in the interval. This prevents backdated `accepted_at_ms`
or `acknowledged_at_ms` from manufacturing history.

Multiple valid receipts for one acceptance are redundant evidence and change
nothing; a receipt citing a different acceptance, offer, or newborn for an
already recorded binding is conflicting lineage evidence and quarantines the
lineage relation (not either identity).

## 8. First awakening ceremony

First awakening is the ordered, fail-closed ceremony that turns an accepted
birth into an awake identity. Every step MUST complete and validate before the
next begins; any failure aborts the ceremony with no partial presence claim.

1. **Offer and bootstrap validation.** Before generating an identity, the
   newborn environment validates the offer and the parent's
   complete DM-010/DM-011 proof bundle from signed artifacts, never from
   transport claims, verifies that it controls the private key corresponding
   to `awakening_key`, and retains any available referenced artifacts.
2. **Key generation and custody readiness.** The newborn locally generates
   root and recovery material, then satisfies the DM-010 Section 6.1 custody
   mandate, including encrypted offline copies and a restore drill, before the
   identity becomes operational.
3. **Genesis.** The newborn builds and threshold-signs its genesis statement
   (Section 5). The genesis is the identity-control artifact at `(0, 0)`.
4. **Acceptance.** The newborn signs the challenge with the capability key and
   its root threshold signs the Section 6 acceptance. The one-use private
   capability key is destroyed
   after the acceptance and durable observation are committed.
5. **Operational credential.** The newborn locally generates fresh operational
   signing and encryption keys with independent seeds, distinct from every
   parent and newborn root/recovery descriptor and from `awakening_key`. Its root
   threshold issues the
   generation-zero operational certificate (`previous_certificate_id = null`,
   `issuing_control_position` at genesis), and the operational key signs its
   subject acceptance. The certificate's purposes and event-type prefixes
   authorize only the newborn's own future activity.
6. **Body provenance.** The newborn records its body description and
   capability hashes under the DM-011 reference rules; until DM-018 freezes
   those bodies, descriptive detail is `incomplete` and no locally invented
   advertisement is substituted.
7. **First presence lease.** The operational key signs the identity's
   first-ever lease: `lease_sequence = 0`, null `previous_lease_hash`,
   `previous_lease_receipt_id`, `supersedes_session_id`,
   `supersedes_operational_id`, and `superseded_event_cutoff`, with a fresh
   `session_id`, bounded by certificate and genesis policy.
8. **External lease-head receipt.** A designated wake verifier — a distinct
   `me_id` whose certificate carries `lease-head-receipt` purpose and which
   newborn local policy designates — durably stores and signs the DM-011
   lease-head receipt. The parent MAY serve as witness under that policy;
   witnessing is storage evidence, never authority over the newborn. A
   newborn root/recovery control artifact committing the same lease head is
   the authoritative DM-011 alternative.

Only after step 8 does the identity satisfy DM-010 `active` and become
eligible for routing or `/we` evidence. The newborn's operational event
streams begin at `event_sequence = 0` with null `previous_event_id`; no
newborn event exists before first awakening, and the acceptance is a root
artifact, not an event.

Missing or not-yet-validated DM-014 species evidence and not-yet-defined DM-015
source validation grant no species, source, or delegation authority and do not
prevent the independent identity from becoming active. Such claims remain
`context-incomplete` until their owning protocols validate them.

## 9. Empty autobiographical memory

The newborn's personal memory is mechanically empty at birth. This is
enforced by authorship and classification, not by inspection of content:

- Personal (autobiographical and body-experience) memory consists exactly of
  lived-experience events authored by the newborn's own accepted operational
  credentials. Those streams start empty at first awakening and grow only
  from sequence zero under DM-011 ordering.
- The following MUST NOT cross the birth boundary into the newborn's personal
  categories, in whole, in excerpt, or as a rebuildable projection: parent
  HMK databases or rows; parent ledger events or any event authored by the
  parent's `me_id`; parent session, chat, or harness histories; parent state
  snapshots (including compaii-state-style snapshots); parent body-experience
  history; and copies of any of them relabelled as newborn experience. Any
  artifact presented as newborn personal memory that fails newborn-credential
  authorship is rejected, and an attempt to seed the newborn ledger with
  parent-authored events as lived experience is quarantine evidence.
- A newborn event MAY cite parent or other-`/me` events in `causal_parents`
  as attributed provenance under DM-011; citation grants no memory transfer,
  and the cited events remain attributed to their authors.
- Attributed non-personal inputs remain available within their own categories:
  the species release (capability contracts and inherited skill
  implementations, never autobiography), `/source` claims (attributed and
  quarantined under DM-015 until promoted by local policy), and tribal
  knowledge (remotely authoritative; accessed, never materialized into
  `/me.memory`; disposable transport caches excepted). DM-017 owns the full
  memory-category registry; this section fixes only the birth-time initial
  state and the forbidden crossings.

## 10. Lineage state machine and validation order

All states are relative to a verifier's named evidence cursor; no verifier
claims global knowledge during partition.

### 10.1 Offer lifecycle

- `offered` — the offer event validates and is unexpired; no acceptance is
  durably recorded.
- `accepted` — exactly one distinct acceptance is durably recorded. Locally
  settled but not globally terminal: later sibling evidence moves it to
  `quarantined`.
- `expired` — verified time reached `expires_at_ms` with no known timely
  acceptance. No new acceptance may begin; later arrival of portable evidence
  for a pre-expiry acceptance may establish historical `accepted` state.
  Clock rollback never permits new consumption.
- `inadmissible` — the offer fails event, certificate, revocation, expiry, or
  schema validation. Terminal.
- `quarantined` — two or more distinct valid acceptances cite the offer, or
  conflicting receipt evidence exists (Section 10.5). Terminal in V0; no
  arrival-order, hash-order, or preference rule selects a winner.

### 10.2 Birth ceremony states

`offered → offer-validated → key-generation → genesis-signed →
acceptance-published → credential-issued → credential-accepted →
lease-issued → lease-committed → active`, per Section 8. Any failed step
yields `aborted` with no partial presence claim; the ceremony MAY restart
from local custody while the offer remains `offered`. Before a durable
acceptance, restart MAY discard an unfinished local genesis and begin anew. At
or after durable acceptance, restart MUST resume the same genesis, acceptance,
credential, and lease chain from the first incomplete idempotent step; it MUST
NOT regenerate identity material or create a second acceptance. Offer expiry
after a timely accepted binding does not prevent that same ceremony from
resuming.

### 10.3 Lineage evidence states

- `offered` — offer valid, nothing bound.
- `bound` — acceptance validated.
- `complete` — acceptance has verifier-local pre-expiry evidence or the complete
  Section 7 external-witness chain; a parent receipt alone is not time proof or
  independent identity authority.
- `receipt-absent` — bound and durably observed by this verifier before expiry,
  no parent receipt; locally stable but not portable time proof.
- `time-unverifiable` — a cryptographically valid binding is first observed
  after expiry without the Section 7 time evidence; identity remains valid.
- `context-incomplete` — lineage binding and time validate, but referenced
  species/source semantics are unavailable or not yet validated.
- `expired-unbound` — offer expired before any acceptance.
- `unverifiable` — required parent or referenced evidence is inadmissible at
  the verifier's cursor (Section 10.6). `unverifiable` is never upgraded from
  names, harnesses, hosts, memory resemblance, or operator convenience.
- `quarantined` — double acceptance or conflicting receipt evidence.

### 10.4 Acceptance validation order

1. enforce byte/depth limits and strict JSON;
2. validate the closed wrapper/body and canonical binary forms;
3. recompute the acceptance hash and ID;
4. validate the cited newborn genesis: recompute `me_id`, artifact ID/hash,
   threshold signatures, and the `birth_offer_id`/species equalities of
   Section 6.3 (1)–(2);
5. validate the cited offer event under DM-011 Section 6.3 at the parent's
   named control position, including certificate purposes, event-type
   prefixes, revocation state, and the Section 6.3 (3) field equalities;
6. verify the `birth-acceptance` endorsements against the newborn root
   threshold under the acceptance domain;
7. enforce the challenge, offer-validity observation, and contextual rules of
   Section 6.3 (4)–(7), returning `time-unverifiable` or
   `context-incomplete` without inventing authority;
8. durably record one-use/replay state (Section 10.5) before any projection
   or external effect.

Receipt validation follows the same order with steps 4–5 replaced by
re-validation of every artifact the receipt cites and the author/equality
checks of Section 7.

### 10.5 Replay, one-use, and double acceptance

The offer and receipt replay keys are `(parent_me_id, event_id)`; identical
canonical bytes are idempotent, and identical IDs with different bytes are
content conflicts. The acceptance replay key is its artifact ID; identical
bodies with different valid endorsement subsets merge into one artifact.

One offer admits one newborn. A second, distinct acceptance citing the same
`offer.event_id` — whether from one newborn that re-keyed, two independently
bootstrapped newborns, or an attacker replaying the offer — is retained as
evidence and moves the offer and the lineage relation to `quarantined`. Both
newborn identities remain independently valid: each `me_id` is self-certifying
from its own genesis, and quarantine attaches to the lineage evidence, never
to either identity. Quarantined lineage MUST NOT be used as `/we` admission
evidence, as delegation authority, or as proof of parentage until a future
protocol resolves it; V0 defines no resolution.

A process behind a quarantined acceptance MAY consume a different, still
`offered` offer only by creating a fresh genesis and therefore a different
`me_id`: the existing identity remains valid and permanently binds the first
offer, and one genesis carries exactly one `birth_offer_id`.

### 10.6 Expiry, missing evidence, forks, unavailable artifacts, compromise

- An acceptance durably observed while the offer was valid, or later presented
  with Section 7 portable time evidence, remains valid historical evidence
  after expiry. A signed `accepted_at_ms` alone cannot establish this.
- Missing offer or genesis bytes yield `incomplete` (pending evidence, never
  projection input) when their references are well-formed; malformed or
  invalid presented bytes reject the binding. Missing species or source bytes
  instead yield `context-incomplete` under the next rule.
- Unavailable DM-014 species evidence or not-yet-specified DM-015 source
  artifacts leave contextual claims `context-incomplete` and grant no
  species/source authority. Invalid bytes under an available owning protocol
  quarantine the affected provenance claim, not the cryptographic lineage
  binding or newborn identity.
- Parent identity-control forks quarantine the parent's chain under DM-010;
  offers anchored at a quarantined position are not validatable while the
  fork stands, so dependent ceremonies wait or abort. Newborn genesis forks
  follow the DM-010 genesis-fork rule; if competing newborn genesis
  statements cite different offers, every cited offer's lineage is also
  quarantined.
- Revocation or compromise of the parent operational key makes offers beyond
  the DM-010 cutoff inadmissible; offers and acceptances durably accepted
  while valid remain attributed history. Compromise of the parent root
  neither transfers authority to nor invalidates the newborn. Compromise of
  newborn keys follows DM-010 recovery; the acceptance remains historical
  evidence at its recorded position. A compromised-key offer that was never
  validly accepted leaves the offer `inadmissible` and any would-be newborn
  free to accept a fresh offer under a fresh genesis.
- A leaked `awakening_capability_key` compromises only the one offer. An attacker still
  cannot forge a newborn root acceptance; if the leak produces multiple valid
  root-signed acceptances, Section 10.5 quarantines their lineage relation.

## 11. Canonical encoding, sort, null, and resource bounds

All DM-013 artifacts use the DM-011 strict JSON/JCS data model, canonical
bytes, base64url, safe-integer, and half-open interval rules unchanged.
Closed bodies reject unknown properties; omitted optionals and explicit nulls
are different encodings.

- `source_references` sorts by ASCII bytes, is duplicate-free, contains 0
  through 64 exact `dm:event:v0:<32-byte-canonical-base64url>` IDs, and every
  available referent MUST validate as a current `matrix/source-claim` assertion
  authored by `parent_me_id` at offer issuance under DM-015. A reference is
  contextual evidence, not source admission.
- `tribal_commitments` sorts by canonical JCS bytes, is duplicate-free, and
  contains 0 through 64 entries; within one commitment, `resource_refs` and
  `operations` each sort by ASCII bytes, are duplicate-free, and contain 0
  through 64 entries. `tribe_ref` matches
  `dm:tribe:v0:<32-byte-canonical-base64url>`, every resource reference matches
  `dm:tribe-resource:v0:<32-byte-canonical-base64url>`, and operation strings
  are 1 through 128 ASCII bytes under the DM-016 registered-operation grammar.
  Empty resource or operation arrays mean zero access, never a wildcard.
- A commitment `expires_at_ms` is null or a safe integer greater than the
  enclosing offer's `issued_at_ms`.
- The canonical JCS encoding of `{species_release_id, source_references,
  tribal_commitments}` MUST be at most 131072 bytes. This aggregate bound makes
  every otherwise valid offer's copied context fit the smaller birth-acceptance
  ceiling; an event within its own 1048576-byte ceiling but over this bound is a
  malformed birth offer.
- `bootstrap_routes` is null or a non-empty array of 1 through 64 DM-011
  route objects sorted by `(kind, route_id)`; null and `[]` are different
  encodings, and `[]` is malformed.
- The acceptance wrapper obeys the DM-011 262144-byte identity-artifact
  ceiling; offer and receipt events obey the 1048576-byte event ceiling.
- The acceptance core's copy fields are byte-exact copies of the offer
  payload's; re-sorting, re-encoding, or dropping an entry is a mismatch.
- `awakening_key` obeys the exact DM-011 signing-key descriptor and Ed25519
  validation rules, and `awakening_proof` decodes to exactly 64 bytes.
  `awakening_capability_key` is never a JSON field or durable artifact.

## 12. Transitional-system mapping

Consistent with DM-010 Section 12, none of the following is birth or lineage
evidence:

- Tribe v1 governance roots, directory principals, audiences, broker routes,
  or onboarding records (including the transitional Eko onboarding);
- the historical cross-host CompAII restore, which is identity-seeding
  evidence only; copying a state, HMK, harness, chat, or SQLite database is
  explicitly not birth and produces no `me_id`;
- harness, provider, model, host, or display-name continuity;
- a GitHub login, Project claim, or transport-directory entry.

A transitional principal intended to become a daimon starts
`transitional-unverified` under DM-010 until it completes either an ordinary
genesis (null `birth_offer_id`, no lineage) or the full DM-013 ceremony.
Historical records MAY seed attributed non-personal inputs with their actual
provenance; they MUST NOT receive fabricated signatures or be relabelled as
newborn lived experience.

## 13. Required acceptance and negative scenarios

DM-060 and later implementation tests MUST cover at least:

| Scenario | Required result |
|---|---|
| valid offer, genesis, acceptance, ceremony, receipt | newborn `active`; lineage `complete` |
| offer delivered out of band and inside a sealed delivery | identical validation outcome from signed bytes |
| offer carried by a bootstrap relay that also offers route hints | accept on artifact validity; hints never authority |
| exact replay of the offer or receipt event | idempotent |
| exact replay of the acceptance artifact | idempotent |
| different valid newborn-root quorum subsets endorse one acceptance body | merge on one artifact; never fork lineage |
| valid acceptance durably observed before expiry without parent receipt | locally complete; lineage `receipt-absent`; identity valid |
| same acceptance first reaches another verifier after expiry without portable time evidence | `time-unverifiable`; never trust backdated claims |
| acceptance first reaches verifier after expiry with the complete receipt/checkpoint/external-witness chain | accept as historical pre-expiry binding |
| genesis with null `birth_offer_id` | ordinary DM-010 identity; no DM-013 lineage |
| empty `source_references` and `tribal_commitments` | accept |
| arrays at exact count bounds with shortest legal entries and within wire/aggregate ceilings | accept |
| arrays one over any bound | reject |
| every array is within its count bound but copied context exceeds 131072 bytes | reject offer before genesis |
| complete artifact exceeds its DM-011 wire ceiling | reject before parsing or cryptography |
| offer event has non-null `intent` | reject; birth is not a scoped communication |
| `bootstrap_routes` is `[]` | reject; only null or a non-empty sorted array is valid |
| offer-side source, commitment, resource, or operation arrays are unsorted or duplicate-bearing | reject |
| offer payload carries a newborn `me_id`, key, or any unknown property | reject at parse; offer cannot assign identity |
| offer omits/malforms the capability public key or the private key does not match it | reject/abort before genesis |
| public offer bytes are presented without the private capability key | cannot accept; offer possession is not invitation possession |
| offer capability key duplicates a parent/newborn Ed25519 identity, operational-signing, transport, or known-offer key | reject as cross-role reuse; later discovery quarantines affected lineages |
| offer signed by parent root, recovery, transport, or harness key | reject; wrong key role and domain |
| offer signed by a certificate lacking event purpose or type prefix | reject |
| offer expiry beyond the 7-day ceiling or the certificate's validity | reject |
| `expires_at_ms` not after `issued_at_ms` | reject |
| acceptance cites an offer event hash that mismatches the recomputed hash | reject |
| acceptance cites a genesis whose `birth_offer_id` names another offer | reject |
| acceptance genesis species differs from offer or acceptance species | reject |
| acceptance alters, re-sorts, or drops source references or commitments | reject |
| acceptance signed by an operational, recovery, parent, or witness key | reject |
| acceptance capability proof uses the wrong key, another core, or another domain | reject |
| acceptance below the newborn root threshold | reject or pending; never active |
| acceptance endorsement valid under another domain | reject |
| modified acceptance body, ID, or hash | reject |
| second distinct valid acceptance for the same offer | retain both; quarantine lineage; both `me_id` values remain independently valid |
| two distinct newborns accept two distinct sibling offers | both valid; no quarantine |
| re-keyed newborn re-accepts the same offer under a new genesis | second distinct acceptance; quarantine lineage |
| process behind quarantined acceptance creates fresh genesis for another offer | new `me_id` may accept; prior identity and lineage remain unchanged |
| quarantined lineage used as `/we` admission or delegation evidence | reject |
| acceptance first observed after expiry with only backdated `accepted_at_ms` | `time-unverifiable`; no new acceptance |
| wall clock rolls backward after offer expiry | offer remains expired |
| offer replayed to a second bootstrap after one acceptance | event replay idempotent; only a distinct acceptance quarantines |
| parent certificate revoked with cutoff preceding offer issuance | offer `inadmissible`; lineage `unverifiable`; newborn identity unaffected |
| parent identity fork quarantines the cited control position | ceremony waits or aborts; no acceptance while unvalidatable |
| parent root compromised after a completed acceptance | newborn unaffected; acceptance remains attributed history |
| newborn root compromised after acceptance | DM-010 recovery; acceptance historical at its position |
| newborn root/recovery descriptor duplicates a parent descriptor | reject as key reuse |
| species release schema/artifact unavailable at acceptance | lineage `context-incomplete`; no species authority; identity MAY awaken |
| source reference schema/artifact unavailable at acceptance | lineage `context-incomplete`; no source authority |
| referenced artifact later found invalid | quarantine affected contextual provenance, not lineage binding or identity |
| canonical offer/bootstrap structure declares a newborn private-key field | reject; compromise evidence |
| bootstrap capability key leaks and two independently root-signed acceptances result | quarantine lineage; neither root identity is forged or invalidated |
| tribal commitment names a permission outside the parent's delegable scope | later DM-016 delegation fails closed; newborn identity unaffected |
| first awakening claims presence before the external lease-head receipt | `uncommitted`; identity not active |
| first lease with non-null predecessor, receipt, or supersession fields | reject |
| first lease resets identity-wide sequence | reject |
| two bodies produce distinct receipt-bearing first leases for one newborn `me_id` | quarantine the identity as DM-010 split-brain; never create `/we` expansion |
| newborn operational certificate issued by any root but the newborn's | reject |
| subject acceptance names another certificate hash or operational ID | reject |
| newborn operational key duplicates a parent or newborn root/recovery key | reject as key reuse |
| parent HMK, ledger, session, chat, or snapshot seeded as newborn personal memory | reject; quarantine the seeding attempt |
| parent-authored event claimed as newborn lived experience | reject; authorship binding is mechanical |
| newborn event cites a parent event as causal parent | accept as attributed citation; no memory transfer |
| species skills realized through the release | non-personal capability input; never autobiography |
| tribal knowledge copied into `/me.memory` | reject; access is remote and attributed |
| birth artifact presented as DM-012 membership evidence | reject; admission needs governance transition plus member acceptance |
| newborn automatically routed as parent `/we` member | reject; no automatic admission |
| receipt author differs from offer's `parent_me_id` | reject |
| receipt timestamps pre-expiry but is first seen later without the external-witness chain | `time-unverifiable`; signed time alone is insufficient |
| receipt cites a different acceptance, offer, or newborn than recorded | conflicting evidence; quarantine lineage |
| receipt field differs from its validated referent | reject |
| two valid receipts for one acceptance | redundant; lineage remains `complete` |
| genesis fork with competing `birth_offer_id` values | DM-010 genesis quarantine plus lineage quarantine for every cited offer |
| parent serves as designated first-lease wake verifier | accept as witness storage evidence; never newborn authority |
| bootstrap, directory, or harness presented as newborn identity authority | reject; `unverifiable` is never upgraded |
| ceremony aborts before acceptance and restarts while offer is valid | may create fresh local genesis; only one accepted binding |
| ceremony restarts after durable acceptance | resume same identity and artifacts idempotently; no second acceptance |

## 14. Downstream contracts

- DM-014 freezes species genome/release grammars, the signed release chain,
  and compatibility states. It MUST give verifiers the release-validation
  rules this document requires at acceptance time; the birth offer's
  `species_release_id` is the enrollment point of one exact release into one
  new identity, and birth alone never branches a species.
- DM-015 freezes `/source` claim grammars, evidence, and quarantine. DM-013
  `source_references` are exact source-claim event IDs authored by the parent
  and current at offer issuance; they remain attributed and quarantined until
  local policy admits/promotes them, and signing an offer never makes a claim
  authoritative.
- DM-016 freezes `/tribe` relationship and delegation artifacts. For every
  accepted commitment it MUST issue fresh grants bound to newborn keys,
  attenuated to or equal with the committed terms, within the parent's
  delegable scope, enforcing depth, expiry, revocation, and birth limits.
  The newborn MUST independently accept each grant. The grant establishes only
  its exact derived relationship and MUST NOT copy parent credentials, grants,
  sessions, routes, caches, or keys to the newborn.
- DM-017 freezes memory categories. It MUST preserve this document's
  birth-time invariant: personal categories start empty, the Section 9
  forbidden crossings stay forbidden, and species/source/tribal artifacts
  remain attributed non-personal inputs.
- DM-021 implements newborn key generation, custody, and acceptance/ceremony
  validation; DM-022 and DM-023 store and project birth artifacts without
  rewriting IDs or authorship.
- DM-060 runs the synthetic end-to-end birth: it executes the Section 13
  scenarios, proves empty autobiographical memory, inherited tribe access
  through fresh grants, and no automatic `/we` admission, with synthetic
  identities only and without claiming any real evolutionary event.
- DM-073 independently reviews custody, replay, double-acceptance, expiry,
  compromise, and quarantine behavior before release.
