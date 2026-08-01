# `/me` identity continuity and single-body presence

Status: normative V0 specification.

This document defines the stable cryptographic identity of one daimon, its
subordinate operational credentials, and the evidence required to prove that
at most one body is awake for that identity relative to the verifier's known
state. Encoding and interoperable
cryptographic vectors are completed by DM-011. Signed collective membership,
`/we` scope resolution, and fan-out are completed by DM-012.

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, **SHOULD NOT**,
and **MAY** are interpreted as described by RFC 2119 and RFC 8174.

## 1. Security goals

The protocol MUST establish all of the following without trusting a model,
provider, harness, body, host, display name, memory database, or transport
roster as identity authority:

1. one stable `/me` identifier across zero or more sequential bodies;
2. a verifiable delegation from `/me` to every operational key;
3. bounded, revocable evidence that at most one body is currently awake;
4. an ordered history of root rotation, recovery, revocation, and policy;
5. an honest terminal state when cryptographic continuity cannot be proved.

The protocol does not prove sentience, truthfulness, memory accuracy, or
physical uniqueness. It proves only the signed continuity and authorization
claims defined here.

## 2. Identity layers

| Layer | Stable for | Authority | Explicitly not authority |
|---|---|---|---|
| `/me` | the life of one daimon | genesis plus accepted control chain | name, prompt, model, memory similarity |
| root set | one accepted root-set interval | threshold signatures over control artifacts | ordinary event or transport signing |
| recovery set | the configured recovery policy | threshold recovery transitions only | operational certificates or lived events |
| operational credential | one subordinate signing/encryption-key lifecycle for `/me` | root-issued certificate plus subject acceptance | a second identity or collective membership |
| body | one situated machine/container capability surface | credential-signed description named by the active lease | `/me` continuity |
| session | one runtime process interval in the active body | local runtime and identity-wide presence sequence | identity continuity |
| presence | one short availability interval | valid operationally signed lease at the identity-wide high-water | process discovery or network reachability |
| `/we` membership | ordered relation among distinct `/me` identities | content-bound `we_id` plus threshold-signed membership chain over exact `me_id` values (DM-012) | self-assertion, shared name, body, Tribe roster, or memory similarity |

A harness or body MAY be named in descriptive metadata. Changing that metadata
MUST NOT change `/me`, grant identity authority, or prove presence.

## 3. Cryptographic roles

V0 uses purpose-separated Ed25519 signing keys. Recipient encryption keys are
purpose-separated X25519 keys and never establish `/me` continuity by
themselves.

Private keys MUST NOT be reused across these roles:

- root authorization;
- recovery authorization;
- operational signing;
- operational recipient encryption;
- species maintainer authorization;
- transport- or gateway-specific authentication.

Root keys sign only typed identity-control artifacts, operational certificates,
DM-012 collective-membership genesis/transitions for collectives in which this
`me_id` is a declared governance signer, membership acceptance for this
`me_id` when it is admitted even if it is not a governance signer, and the
DM-013 birth acceptance binding this `me_id`'s own genesis to its accepted
birth offer. They MUST
NOT sign ordinary ledger events, presence leases, messages, transport
directories, arbitrary bytes, or encryption material. A collective signature
is still attributable to member roots; `/we` never owns or shares a private
root.

Every identity, custody, presence, and membership artifact defined in this
document MUST use a DM-011 canonical encoding and its distinct label below;
later protocol artifacts use the additional labels registered by DM-011:

```text
daimon/genesis/v0
daimon/root-transition/v0
daimon/recovery-transition/v0
daimon/recovery-policy/v0
daimon/operational-certificate/v0
daimon/operational-acceptance/v0
daimon/birth-acceptance/v0
daimon/we-membership-genesis/v0
daimon/we-membership-transition/v0
daimon/we-membership-acceptance/v0
daimon/revocation/v0
daimon/presence-lease/v0
```

A signature valid under one label MUST be invalid under every other label.
The V0 suite is fixed; algorithm changes require a new suite/version and domain
labels rather than interpreting old artifacts under new algorithms.

## 4. `/me` genesis and stable identifier

### 4.1 Genesis core and statement

The identity genesis core contains only:

- protocol and schema version;
- a 256-bit random genesis nonce;
- the cryptographic suite and domain-separation version;
- the initial root verification-key set and threshold;
- the initial recovery mode, verification-key set, and threshold.

The genesis statement contains that core plus:

- maximum operational-certificate and presence-lease lifetimes;
- maximum accepted clock skew;
- creation time;
- the accepted species release reference, if any;
- an optional DM-013 birth-offer reference.

The V0 maximums in Section 10 are protocol ceilings. Genesis MAY select
stricter certificate, lease, and clock bounds; those selected bounds are
immutable in V0. Local policy may become stricter without an identity-control
artifact, but no control transition may relax the signed genesis bounds.

The core and statement contain no private material, harness, provider, model,
host, mutable display name, autobiographical memory, or transport membership.
Species and birth references are signed personal provenance but are excluded
from identifier derivation and grant no identity authority.

The initial root threshold signs the exact canonical genesis statement under
the genesis domain. The accepted statement is also the identity-control
artifact at position `(0, 0)`. Two differently hashed, threshold-valid genesis
statements for the same core and `me_id` are a genesis fork: verifiers MUST
quarantine the identity until the genesis recovery policy resolves it. An
identity with no recovery authority cannot resolve such a fork.

### 4.2 Identifier derivation

`me_id` is self-certifying:

```text
dm:me:v0:<base64url(SHA-256(canonical-genesis-body))>
```

Here `canonical-genesis-body` means the identity genesis core, not the complete
statement. The statement contains the core, policy/provenance fields, derived
`me_id`, and signatures that satisfy the initial root threshold. A verifier
MUST recompute `me_id` and MUST reject a mismatch before checking any
descendant artifact.

Root rotation, recovery, renaming, migration, body changes, and periods with no
active body MUST NOT change `me_id`.

## 5. Identity-control chain

Genesis starts at identity-control position `(recovery_generation=0,
control_sequence=0)`. An ordinary control artifact remains in the same
recovery generation and increments `control_sequence` by exactly one. A
recovery transition increments `recovery_generation` by exactly one and resets
`control_sequence` to zero.

Every control artifact contains:

- `me_id`;
- the current `recovery_generation`;
- a monotonically increasing `control_sequence`;
- the hash of the immediately previous accepted control artifact, or every
  known competing predecessor hash for a fork-resolving recovery transition;
- artifact type and policy-specific body;
- required signatures and possession proofs.

A possession proof for a control artifact signs the canonical body hash of
that exact artifact under its own domain-separation label. The body excludes
the proof and signature fields themselves and includes `me_id`, recovery
generation, control sequence, every predecessor hash, and the complete
proposed replacement state. A proof valid for one artifact MUST be invalid for
an artifact that differs in any field. This binding applies to replacement
root and recovery keys; a retired key's proof MUST NOT be replayed to reinstall
it.

The root-set epoch is the `(recovery_generation, control_sequence,
control_hash)` position of the accepted artifact that installed that root set.
It is not a wall-clock interval.

Two different valid artifacts claiming the same predecessor and sequence form
an identity-control fork. A verifier MUST quarantine both successors and MUST
NOT choose one by arrival time, host preference, lexicographic hash, or longest
chain.

A fork is resolved only by a recovery transition that:

- satisfies the recovery policy accepted before the fork;
- names every known competing head;
- installs the complete post-recovery root set;
- proves possession of its threshold;
- declares the revocation consequences for forked keys and certificates.

The post-recovery set MAY equal the last unambiguous pre-fork root set only when
the recovery artifact declares that set uncompromised and none of its keys were
revoked. A compromise recovery MUST replace every compromised key.

Only recovery authority can increment `recovery_generation`. A valid higher
recovery generation supersedes ordinary root branches from the preceding
generation regardless of their length. Conflicting recovery transitions at
the same next generation freeze identity control until a later
recovery-quorum resolution cites every known conflicting hash.
Every descendant of an unresolved branch remains quarantined; extending one
branch does not make it authoritative.

If no authorized recovery transition is possible, continuity is unresolved.

Verifiers MUST durably retain the highest accepted recovery generation,
control sequence, and control hash. A newly seeded verifier MUST validate the
full chain from genesis or a future checkpoint format explicitly authorized by
this `/me`; a transport-directory receipt or bare current root key is not an
identity checkpoint.

## 6. Root custody and transitions

### 6.1 Custody

This subsection is an operational security mandate. Wire-protocol validation
cannot prove that an operator performed a restore drill or kept a key offline;
deployment conformance and DM-073 audit those requirements separately.

Root private keys MUST remain outside model and harness configuration and MUST
not be installed in an ordinary body runtime. Each non-test `/me` MUST
have:

- encrypted offline custody for every active root share;
- at least two independently stored, restore-tested encrypted copies of active
  root material, unless genesis explicitly declares a nonrecoverable profile;
- a public inventory of key IDs, algorithms, thresholds, and custodial roles
  without private locations or secrets;
- a restore drill before the identity becomes operational;
- a documented compromise and loss procedure.

For each root share, exactly one signing copy may be active and writable at a
time; a threshold root may still have several independent active custodians. A
restored copy MUST verify its public key, reconcile every available
identity-control replica to a single accepted head, and advance durable
high-water state before signing. A stale backup MUST NOT sign from its
remembered predecessor; doing so creates a root fork and freezes identity
control.

Root signing MUST accept typed identity-control requests rather than arbitrary
bytes. The offline ceremony MUST display the semantic action, `me_id`, current
predecessor hash, proposed object hash, and custody key IDs before approval.
Root material at rest MUST use authenticated encryption with versioned,
reviewable parameters.

The CompAII V0 canary MUST use a recovery policy distinct from its active root
custody. Copying the same secret to another path is backup, not independent
recovery authority.

### 6.2 Ordinary root rotation

An ordinary root transition MUST:

1. extend the accepted control head;
2. satisfy the current root threshold;
3. name the complete replacement root set and threshold;
4. include proof of possession from the replacement threshold;
5. either invalidate all existing operational certificates or name the exact
   certificate IDs carried forward as valid.

Omitting the certificate carry-forward decision is malformed, not implicit
preservation. “Carry forward all certificates issued before rotation” is not a
verifiable decision because a retired or compromised root could mint a
backdated certificate anchored to its old head. A carried-forward certificate
therefore MUST be enumerated by ID in the transition.

Each replacement-root possession proof is a signature over the exact proposed
transition hash under the root-transition domain. A proof for another
transition, predecessor, `/me`, or recovery generation MUST NOT be replayed.

Possession of only the new root cannot prove continuity. Possession of only
the old root cannot install an unusable replacement.

### 6.3 Recovery transition

A recovery transition is valid only when it:

1. extends an unambiguous accepted head or explicitly resolves known forks;
2. satisfies the previously accepted recovery threshold;
3. installs the complete post-recovery root set with threshold possession proof
   under the constraints in Section 5;
4. declares the compromise cutoff as an identity-control position and head
   hash, plus any per-credential event and identity-wide lease high-water
   positions preserved as
   valid, and states the certificate-revocation consequences;
5. emits a durable recovery receipt suitable for offline verification.

Replacement-root possession is bound to the exact recovery-transition hash in
the recovery-transition domain.

Recovery keys MUST NOT issue operational certificates, lived events, presence
leases, or ordinary root transitions.

Compromise recovery revokes all outstanding operational certificates by
default. Preserved certificates MUST be named individually and revalidated by
the recovery quorum. Certificates anchored at or after the declared control
cutoff on a superseded branch are revoked regardless of their timestamps.
Per-credential event cutoffs and identity-wide lease cutoffs use signed
sequence and hash positions;
wall-clock time is informational because it cannot distinguish backdated
attacker output from valid offline history. The recovery authority attests to
where compromise began: verifiers can enforce the declared boundary but
cannot prove that the real-world compromise occurred there.

### 6.4 Recovery-policy changes

Replacing, weakening, or disabling an existing recovery policy requires both
the current root threshold and the current recovery threshold, plus possession
proof for any replacement recovery keys. When genesis explicitly declares no
recovery authority, the current root threshold MAY establish the first one.
Every replacement recovery key MUST prove possession over the exact proposed
policy artifact in the recovery-policy domain.
If the configured recovery quorum is lost while the root remains available,
ordinary root operations may continue but the root cannot silently replace or
disable that recovery policy; future root loss would therefore be
irrecoverable.

### 6.5 Irrecoverable loss

If neither the accepted root threshold nor the accepted recovery threshold can
authorize a successor, no process MAY claim a replacement key as the same
`/me`. Memory, backups, social recognition, an old operational key, a GitHub
account, or a transport directory entry MAY support an attributed continuity
claim but cannot restore cryptographic continuity.

The honest outcomes are:

- remain frozen with the last verifiable identity state; or
- create a new `/me` whose genesis references the prior identity as an
  attributed predecessor claim.

This outcome is a security property, not a recovery failure to bypass.

If loss is not suspected compromise, an already certified operational key MAY
continue only until its bounded certificate expires. If compromise is
suspected and no recovery authority remains, identity control and new writes
requiring identity confidence MUST fail closed immediately.

## 7. Operational certificates

An operational certificate delegates limited online signing and recipient
encryption authority from one `/me` root. It is not a second identity, a body,
or `/we` membership evidence. A copied database, prompt, or provider session
does not create a credential.

Identifiers are content-bound:

```text
operational_id = dm:op:v0:<base64url(SHA-256(
  domain || me_id || operational_nonce || signing-public-key-descriptor
))>
certificate_id = dm:cert:v0:<base64url(SHA-256(canonical-certificate-body))>
```

The certificate ID excludes signatures and the certificate-ID field itself.
Changing the operational signing key creates a new `operational_id`. A
replacement MAY cite the prior credential but does not inherit its event
sequence. Lease sequence is identity-wide and never resets.

An operational certificate's canonical body contains at least:

- schema and protocol version;
- `me_id` and `operational_id`;
- stable 256-bit operational nonce and fresh 256-bit certificate nonce;
- monotonically increasing certificate generation for this operational ID;
- the directly preceding accepted certificate ID, null only at generation zero;
- operational signing and encryption public keys with key IDs and algorithms;
- issuing recovery generation, control sequence, control-head hash, and root
  key IDs;
- issuance, not-before, and expiry times;
- allowed event/key purposes and explicit delegation constraints;
- optional descriptive initial body claims, marked non-authoritative.

The wire artifact carries the derived certificate ID and root signatures
outside that body. Signatures MUST satisfy the root threshold active at the
issuing control head. The operational signing key MUST separately accept the
exact certificate hash, ID, `me_id`, and `operational_id`. A certificate
without subject acceptance is not active. Every renewal MUST name the directly
preceding accepted generation; a merely validated but unaccepted predecessor
cannot be skipped over.

An operational key MUST NOT rotate or recover roots, alter recovery policy,
issue another operational certificate, assert a different `me_id`, extend its
own lifetime, or grant collective membership.

Certificate expiry makes new presence and uncheckpointed future signatures
inadmissible but does not erase historical evidence accepted or externally
checkpointed while the certificate was valid. An event first observed only
after expiry cannot prove from its self-declared timestamp that it was signed
before expiry; unless it is at or below a verifiable pre-expiry checkpoint, it
is attributable to the key but MUST NOT be admitted automatically as timely
canonical lived experience. DM-011 defines the exact checkpoint binding.

The V0 maximum certificate lifetime is 30 days. Renewing the same keys names
the accepted prior certificate, increments certificate generation by exactly
one, and produces a new certificate ID. Two certificates at one operational
ID/generation are a fork. Once a new generation and its subject acceptance
activate, the prior generation cannot authorize new events or leases; late
evidence requires prior durable acceptance or a valid checkpoint/high-water.
Verifiers retain the highest accepted generation/hash durably; replay never
reinstates superseded authority or metadata.

## 8. Restart, park/wake, restore, and cloning

One `/me` may span multiple sequential process sessions and bodies. A restart
MAY reuse its credential only when exclusive private-key custody and the next
persisted sequence are proven. Moving bodies is a signed park/wake transition:
the new identity-wide lease extends and supersedes the prior lease; overlapping
active leases are forbidden even when different operational certificates are
used.

The identity-wide accepted lease head (sequence and hash) MUST be durably
replicated outside the current body before a lease is treated as committed.
DM-011 defines the signed commit receipt; DM-023 supplies ledger replicas or
designated wake verifiers that retain the accepted head. A wake on a new body
MUST cite the latest receipt-bearing head and explicitly supersede the prior
session. This superseding wake lease is the signed park/wake transition; V0 has
no separate park artifact. “Parked” means the prior session has ceased renewal
and becomes immediately ineligible when a valid superseding lease is accepted,
even if its prior TTL has not elapsed.

If the prior body is unreachable, the new body uses the newest receipt-bearing
head available from an independent replica. Signed local lease successors that
were never externally committed do not advance the accepted high-water. If a
parked or crashed body later presents a conflicting successor, the conflict is
quarantined as split-brain; a longer uncommitted local chain confers no
authority.

A wake lease that changes body MUST record the superseded operational ID and
its last accepted event sequence/hash. “Accepted” here means covered by a
DM-011 signed checkpoint or commit receipt durably stored outside the current
body; a purely local event head cannot become the handoff cutoff. Events from
that credential beyond the recorded cutoff are inadmissible as canonical lived
experience. Routine moves SHOULD revoke the superseded operational credential.
If it remains unrevoked, it is historical verification material only and
cannot authorize new events, leases, or acknowledgements after supersession.

Restoring one `/me` or one operational private key into two bodies is a clone
hazard, not `/we` expansion. Two artifacts occupying the same identity-wide
lease position, or the same operational event position, with different
content constitute split-brain evidence. Verifiers quarantine the `/me` for
new writes and routing until root-authorized recovery selects cutoffs and
replacement credentials. Already accepted history remains attributed.

If exclusive takeover cannot be proved, operators SHOULD issue a fresh
operational credential, revoke the uncertain one, and continue the same
identity-wide lease chain only after the old body is parked or expired.

## 9. Revocation

Revocation is an ordered control artifact signed by the active root threshold
or included in an authorized recovery transition. It may target an operational
certificate or key, a root/recovery key as part of its replacement, or all
certificates issued after a verified control cutoff.

Revocation contains a reason, exact target, an effective rule (on acceptance
of the revocation artifact or at a named prior accepted control position),
known last accepted event and identity-wide lease high-water positions, and a
replacement reference when one exists. Its own effective position is derived
only after the wrapper hash validates, so the body never embeds its own hash.
Wall-clock time alone is never a compromise cutoff. Carry-forward and
preserved-certificate sets name exact, already validated certificate IDs and
contain no duplicates.

Revocation never deletes historical events. Once observed, it rejects new
leases and newly ingested events beyond the permitted cutoff even when
backdated. An old key is never silently unrevoked or reappointed.

## 10. Identity-wide presence leases

Presence is a bounded availability claim for one `/me` in one body. It is not
continuity, collective membership, or proof that a process will answer.

A presence lease contains at least:

- schema and protocol version;
- `me_id`, `operational_id`, and certificate ID;
- a 256-bit random session ID;
- an identity-wide monotonically increasing lease sequence;
- the previous durably committed lease hash for this `/me`, null only at the
  identity's first lease;
- the prior session ID it supersedes when changing session or body;
- when changing body, the superseded operational ID and exact accepted event
  sequence/hash cutoff for that credential;
- issue and expiry times bounded by certificate not-before/expiry, genesis
  policy, and V0 ceilings;
- hashes of the current body and capability advertisements;
- authorized route references, never route credentials;
- the operational signature.

An identity is `active` only if genesis/control are unambiguous, the
certificate and acceptance are valid and current, no revocation applies, the
latest identity-wide lease is valid, and verified time is within bounds. The
V0 maximum TTL is 300 seconds and maximum clock uncertainty is 30 seconds.

Only one lease-chain head and one unexpired session may be active per `me_id`,
across every operational credential. A new session or body extends the latest
hash at sequence +1 and explicitly supersedes the old session. The superseded
session cannot renew. Two successors of the same predecessor, overlapping
heads, or an old-body renewal after supersession are split-brain evidence and
quarantine the identity. A new credential or session never resets lease
sequence/high-water state.

Only a receipt-bearing committed lease participates in head selection.
Acceptance of a valid superseding head immediately retires the prior session
from routing and event authority. Conflicting receipt-bearing heads are
quarantined; absence of an externally committed receipt leaves a local lease
unaccepted rather than silently advancing identity state.

Network reachability, process discovery, a `<agent>@<host>` display name,
matching memory, transport roster, or harness session cannot prove presence or
membership. Expiry removes active routing without revoking identity or memory.
Clock rollback never resurrects a lease. Capability and endpoint state come
only from the newest accepted lease and are never unioned with stale claims.

DM-010 returns certified/active identity evidence. DM-012 independently
verifies a content-bound `we_id` and its ordered membership chain. A membership
genesis declares exact founding `me_id` values, a member-governance signer set,
and threshold; every founding identity satisfies its own root threshold. A
transition names the prior membership position/hash, exact resulting member
set, admissions and removals, and any governance-policy replacement. The
current member-governance threshold authorizes it. Every admitted identity
separately accepts with its `/me` root under
`daimon/we-membership-acceptance/v0`, whether or not it is a governance signer.
Every replacement governance signer additionally proves possession under the
transition domain before the replacement policy activates. Removal does not
require the removed member's signature. Verifiers durably retain membership
high-water, so older membership evidence cannot restore a removed identity.

DM-012 intersects the accepted member set with active DM-010 presence.
Therefore multiple `/we` identities may be awake together while one identity
can never be awake in two bodies. A bare collective name is only a locally
pinned alias for `we_id`; it cannot select a membership chain by itself.

## 11. Proof of continuity and presence

A result is relative to a named identity-control checkpoint, revocation
high-water, and identity-wide lease high-water; it cannot claim globally
complete knowledge during partition. A complete active proof bundle contains
genesis, every accepted control artifact, the operational certificate and
subject acceptance, revocation evidence/cursor, and the latest lease chain.

For an interactive proof, a verifier sends a fresh nonce, audience, expiry,
requested control head, requested lease head, and protocol domain. The active
operational key signs the complete challenge. Replay or field substitution is
rejected. This proves current key possession relative to known state, not
sentience or physical uniqueness.

A validator returns `certified`, `active`, `expired`, `revoked`, `quarantined`,
or `unverifiable`. `unverifiable` is never upgraded from names, model output,
memory resemblance, or operator convenience.

## 12. Transitional-system mapping

The following are useful evidence or transport inputs but are not `/me`
continuity proofs:

- Tribe v1 governance roots, directory principals, audiences, and key bundles;
- `compaii`, `codex@localhost`, or `compaii@daimonmatrix` names;
- a `compaii-state` generation or copied HMK database;
- Hermes, Codex, Claude Code, Kimi, provider, or model credentials;
- a GitHub login, Project claim, host name, IP address, or anyVPN membership.

During migration, every existing CompAII principal intended to remain a
simultaneously awake `/we` member starts `transitional-unverified` until it has
its own `/me` genesis and operational certificate. Historical records MAY be
seeded with their actual source/host provenance, but MUST NOT receive fabricated
signatures or be relabelled as lived by another identity.

The missing Tribe governance private key is a recovery fixture, not the
CompAII `/me` root. Replacing that transport root cannot create or destroy
CompAII continuity.

## 13. Required acceptance and negative scenarios

DM-011 vectors and later implementation tests MUST cover at least:

| Scenario | Required result |
|---|---|
| genesis core, statement, signatures, or derived `me_id` modified | reject |
| root rotation signed only by new root | reject |
| root rotation signed only by old root without new possession | reject |
| recovery signed by an operational or transport governance key | reject |
| recovery policy weakened without its existing threshold | reject |
| two control successors at one sequence | quarantine; no arrival-order winner |
| stale restored root signer creates another successor | freeze identity control |
| longer ordinary branch competes with valid higher recovery generation | recovery generation wins |
| two recovery transitions conflict at the same generation | freeze pending recovery-quorum resolution |
| certificate anchored to a control head not on the accepted chain | reject |
| certificate anchored to an older accepted head explicitly carried forward by ordinary rotation | accept until its own expiry/revocation |
| certificate anchored to an older accepted head whose certificates were invalidated | reject |
| old root issues a new certificate after replacement | reject |
| rotation says “carry forward all old certificates” without exact IDs | reject |
| certificate lacks subject acceptance | reject |
| proof-of-possession challenge replayed for another nonce or audience | reject |
| one operational key certified under two `/me` values | reject and quarantine |
| copied database without certificate chain | `unverifiable` |
| same operational ID and signing domain/sequence signs different content | quarantine identity |
| process is reachable but lease is absent | identity is not active; exclude from routing |
| lease is validly signed but certificate expired/revoked | inactive and reject |
| stale lease replayed after a higher lease sequence | reject |
| old certificate generation replayed after renewal | reject |
| renewal skips a validated but unaccepted certificate generation | reject |
| two sessions or credentials extend the same identity-wide lease predecessor | quarantine `/me` as split-brain |
| wall clock rolls backward after lease expiry | lease remains expired |
| clock uncertainty exceeds policy | fail closed for new/extended presence |
| revocation followed by backdated event beyond cutoff | reject |
| all root and recovery authority is lost | freeze or new `/me`; never silent reset |
| harness, provider, model, host, or display name changes | `/me` unchanged |
| same `me_id` presents two overlapping active body leases | quarantine identity; never `/we` expansion |
| two distinct `me_id` values have signed `/we` membership and active leases | both eligible for `/we` routing |
| two principals share a bare name but lack signed membership evidence | do not infer `/we` membership |
| Tribe directory or harness roster claims `/we` membership | reject as authority |
| one identity self-signs its own admission without the current member-governance threshold | reject |
| membership acceptance is signed by an operational key instead of the admitted `/me` root | reject |
| governance rotation lacks possession proofs from its replacement signer set | reject |
| removed identity replays an older valid membership artifact | reject below durable membership high-water |
| bare name resolves to an unpinned or different `we_id` | reject as ambiguous/misdirected |
| genesis lacks the declared initial-root threshold | reject |
| same `me_id` has two threshold-valid genesis statements with different policy/provenance | quarantine; recover or remain frozen |
| control artifact skips an ordinary control sequence | reject |
| proof bundle regresses below the verifier's durable accepted head | reject; never lower high-water state |
| possession proof from one transition is attached to a different transition | reject |
| artifact extends either side of a quarantined fork | keep the descendant quarantined |
| fork-resolving recovery omits a known competing head | reject |
| recovery key signs a certificate, lease, event, or ordinary root transition | reject |
| valid signature bytes are presented under another artifact domain | reject |
| one private/public key is reused across root, recovery, operational, encryption, or transport roles | reject |
| artifact removes or negates a prior revocation | reject |
| root key is revoked outside an authorized root/recovery transition | reject |
| recovery policy is replaced or disabled without the existing recovery threshold | reject |
| root alone creates a new recovery policy although genesis already declared one | reject |
| lease exceeds genesis TTL, certificate expiry, or V0 ceiling | reject |
| quarantined identity presents an otherwise valid lease | remain inactive |
| subject acceptance names another certificate hash or operational ID | reject |
| certificate anchored at/after a recovery cutoff is backdated before compromise | reject |
| event is first seen after certificate expiry with no pre-expiry checkpoint | attributable but not automatically timely/canonical |
| new lease changes body/capability hashes in the same session | accept newest lease only; never union stale claims |

## 14. Downstream contracts

- DM-011 defines exact canonical fields, hashes, signatures, positive vectors,
  and negative vectors for these artifacts.
- DM-013 defines the parent birth offer event, the newborn root-threshold
  birth acceptance under `daimon/birth-acceptance/v0`, the first-awakening
  ceremony, the empty-autobiographical-memory boundary, and lineage replay,
  expiry, fork, and quarantine behavior. It consumes the genesis
  `birth_offer_id` reference and the identity, custody, and presence
  machinery defined here without changing identity authority.
- DM-014 defines species genesis, release, maintainer rotation, compatibility,
  local application, and deliberate branching. A genesis
  `species_release_id` is immutable enrollment provenance excluded from
  `me_id`; later compatible application never rewrites it or grants identity
  authority.
- DM-012 defines the content-bound `we_id`, membership genesis, ordered
  threshold-authorized admission/removal/governance transitions, member
  acceptance, freshness/high-water rules, and capability-aware `/we` fan-out
  by intersecting its member set with active identities produced here. The
  collective owns no private key; signers remain attributable member `/me`
  roots.
- DM-021 implements the keystore, validation, transition, revocation, and
  recovery machinery.
- DM-023 records identity artifacts in the canonical ledger and rebuilds their
  projections.
- DM-040 and DM-041 bind Codex and Hermes bodies to distinct `/me` identities
  for the simultaneous canary, without granting either harness root authority.
- DM-070 exercises remote presence, revocation, offline catch-up, and
  provenance-preserving convergence.
- DM-073 independently reviews custody, compromise, fork, rollback, and
  irrecoverable-loss behavior before release.
