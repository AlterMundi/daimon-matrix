# `/me` identity continuity and incarnation certificates

Status: normative V0 specification.

This document defines the stable cryptographic identity of one daimon, the
subordinate credentials of its incarnations, and the evidence required to
consider an incarnation present in `/we`. Encoding and interoperable
cryptographic vectors are completed by DM-011; scope resolution and fan-out
are completed by DM-012.

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, **SHOULD NOT**,
and **MAY** are interpreted as described by RFC 2119 and RFC 8174.

## 1. Security goals

The protocol MUST establish all of the following without trusting a model,
provider, harness, body, host, display name, memory database, or transport
roster as identity authority:

1. one stable `/me` identifier across zero or more simultaneous incarnations;
2. a verifiable delegation from `/me` to every incarnation key;
3. bounded, revocable evidence that an incarnation is currently available;
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
| recovery set | the configured recovery policy | threshold recovery transitions only | incarnation certificates or lived events |
| incarnation | one subordinate identity/key lifecycle | root-issued certificate plus subject acceptance | harness, host, process, session |
| embodiment | one situated capability surface | incarnation-signed description | `/me` continuity |
| session | one runtime process interval | local runtime and presence sequence | incarnation continuity |
| presence | one short availability interval | valid incarnation-signed lease | process discovery or network reachability |

A harness or body MAY be named in descriptive metadata. Changing that metadata
MUST NOT change `/me`, grant identity authority, or prove presence.

## 3. Cryptographic roles

V0 uses purpose-separated Ed25519 signing keys. Recipient encryption keys are
purpose-separated X25519 keys and never establish `/me` continuity by
themselves.

Private keys MUST NOT be reused across these roles:

- root authorization;
- recovery authorization;
- incarnation signing;
- incarnation recipient encryption;
- transport- or gateway-specific authentication.

Root keys sign only typed identity-control artifacts and incarnation
certificates. They MUST NOT sign ordinary ledger events, presence leases,
messages, transport directories, arbitrary bytes, or encryption material.

Every signed artifact MUST use a DM-011 canonical encoding and a distinct
domain-separation label:

```text
daimon/genesis/v0
daimon/root-transition/v0
daimon/recovery-transition/v0
daimon/recovery-policy/v0
daimon/incarnation-certificate/v0
daimon/incarnation-acceptance/v0
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

- maximum incarnation-certificate and presence-lease lifetimes;
- maximum accepted clock skew;
- creation time;
- the accepted species release reference, if any;
- an optional birth-offer reference.

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

Root rotation, recovery, renaming, migration, embodiment changes, and periods
with no active incarnation MUST NOT change `me_id`.

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
not be installed in an ordinary incarnation runtime. Each non-test `/me` MUST
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
5. either invalidate all existing incarnation certificates or name the exact
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
   hash, plus any per-incarnation event/lease high-water positions preserved as
   valid, and states the certificate-revocation consequences;
5. emits a durable recovery receipt suitable for offline verification.

Replacement-root possession is bound to the exact recovery-transition hash in
the recovery-transition domain.

Recovery keys MUST NOT issue incarnation certificates, lived events, presence
leases, or ordinary root transitions.

Compromise recovery revokes all outstanding incarnation certificates by
default. Preserved certificates MUST be named individually and revalidated by
the recovery quorum. Certificates anchored at or after the declared control
cutoff on a superseded branch are revoked regardless of their timestamps.
Per-incarnation cutoffs use signed event/lease sequence and hash positions;
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
`/me`. Memory, backups, social recognition, an old incarnation key, a GitHub
account, or a transport directory entry MAY support an attributed continuity
claim but cannot restore cryptographic continuity.

The honest outcomes are:

- remain frozen with the last verifiable identity state; or
- create a new `/me` whose genesis references the prior identity as an
  attributed predecessor claim.

This outcome is a security property, not a recovery failure to bypass.

If loss is not suspected compromise, already certified incarnations MAY
continue only until their bounded certificates expire. If compromise is
suspected and no recovery authority remains, identity control and new writes
requiring identity confidence MUST fail closed immediately.

## 7. Incarnation certificates

Every simultaneous incarnation MUST have a distinct signing key, encryption
key, `incarnation_id`, and certificate. A copied state database or prompt does
not create an incarnation credential.

Identifiers are content-bound:

```text
incarnation_id = dm:inc:v0:<base64url(SHA-256(
  domain || me_id || incarnation_nonce || signing-public-key-descriptor
))>
certificate_id = dm:cert:v0:<base64url(SHA-256(canonical-certificate-body))>
```

The certificate ID excludes signatures and the certificate-ID field itself.
Changing the incarnation signing key creates a new `incarnation_id`; a
replacement MAY cite the prior incarnation but never inherits its sequences.

An incarnation certificate's canonical body contains at least:

- schema and protocol version;
- `me_id` and `incarnation_id`;
- a 256-bit issuance nonce;
- a monotonically increasing certificate generation for this incarnation;
- incarnation signing and encryption public keys with key IDs and algorithms;
- issuing recovery generation, control sequence, control-head hash, and root
  key IDs;
- issuance, not-before, and expiry times;
- allowed event/key purposes and explicit delegation constraints;
- optional descriptive initial embodiment claims, marked non-authoritative.

The wire artifact carries the derived certificate ID and root signatures
outside that body. The certificate signatures MUST satisfy the root threshold
active at its issuing control head under the certificate domain. The
incarnation signing key MUST separately sign the exact certificate body hash,
`certificate_id`, `me_id`, and `incarnation_id` under the acceptance domain. A
certificate without subject acceptance is not active.

An incarnation key MUST NOT:

- rotate or recover `/me` roots;
- alter the recovery policy;
- issue another incarnation certificate;
- assert a different `me_id`;
- extend its own certificate lifetime or authority.

Certificate expiry makes new presence and uncheckpointed future signatures
inadmissible but does not erase historical evidence accepted or externally
checkpointed while the certificate was valid. An event first observed only
after expiry cannot prove from its self-declared timestamp that it was signed
before expiry; unless it descends from a verifiable pre-expiry checkpoint, it
is attributable to the key but MUST NOT be admitted automatically as timely
canonical lived experience. DM-011 defines the checkpoint binding.

The V0 interoperability profile sets a maximum certificate lifetime of 30
days. Renewing the same keys increments certificate generation and produces a
new certificate ID. Verifiers MUST durably retain the highest accepted
generation and hash until every older certificate is outside its maximum
possible validity window; replay MUST NOT reinstate old authority or metadata.

## 8. Restart, restore, and cloning

One incarnation may span multiple sequential process sessions. A restart MAY
reuse its certificate and keys only when exclusive custody is established and
the next persisted sequence is known.

Simultaneous embodiment on another host requires a new incarnation and new
keys. Restoring the same incarnation key on two hosts is a clone hazard, not
`/we` expansion.

Sequence spaces are domain-specific. Presence leases use the lease sequence
defined here; canonical event streams use the event sequence defined by
DM-011. Two different valid artifacts using the same incarnation, signing
domain, and sequence with different content constitute an incarnation fork.
Verifiers MUST quarantine the affected incarnation until a root
revocation/replacement decision is observed. Detection is necessarily eventual
during partitions; already accepted history remains attributable.

If exclusive takeover cannot be proved after restore, operators SHOULD issue a
new incarnation certificate and revoke the uncertain one.

## 9. Revocation

Revocation is an ordered control artifact signed by the active root threshold
or included in an authorized recovery transition. It may target:

- an incarnation certificate;
- an incarnation signing or encryption key;
- a root key as part of root transition/recovery;
- all certificates issued by a compromised root after a declared cutoff.

Revocation contains a reason code, target, effective control position, known
last accepted signed event/lease high-water positions when applicable, and a
replacement reference when one exists. Wall-clock time alone is never a
compromise cutoff.

Revocation MUST NOT delete historical events or make their prior signatures
unverifiable. Once a verifier observes revocation it MUST reject new leases and
newly ingested events beyond the permitted cutoff, even if they are backdated.
Removing a revocation requires a new certificate/key; an old key is never
silently “unrevoked.”
This also applies to root and recovery keys: a revoked key ID/public key MUST
NOT be reappointed in a later set.

## 10. Presence leases and `/we`

Presence is an availability claim made by a certified incarnation. It is not a
continuity certificate and not proof that a process will answer.

A presence lease contains at least:

- schema and protocol version;
- `me_id`, `incarnation_id`, and certificate ID;
- a 256-bit random session ID, new on the first lease of each process session;
- monotonically increasing lease sequence;
- the previous durably committed lease hash from this incarnation, except for
  the first lease ever issued by the incarnation;
- issue and expiry times bounded by the genesis policy and certificate expiry;
- hashes of the current embodiment and capability advertisements;
- authorized route references, never route credentials;
- the incarnation signature.

A verifier includes an incarnation in the eligible `/we` set only if:

1. genesis and the identity-control chain are valid and unambiguous;
2. the certificate and subject acceptance are valid;
3. no applicable revocation is known;
4. the latest lease signature and sequence are valid;
5. local verified time is within the configured skew and lease interval;
6. requested capabilities and local policy permit selection.

The V0 interoperability profile sets maximum presence TTL to 300 seconds and
maximum clock uncertainty/skew to 30 seconds. Deployments MAY use stricter
values. Effective expiry is the minimum of lease expiry, certificate expiry,
and any revocation boundary.

Network reachability, process discovery, matching memory, a transport roster,
or a harness session alone MUST NOT add an incarnation to `/we`. Those signals
belong to `/here` or route health.

When clock uncertainty exceeds the configured skew, an incarnation MUST NOT
issue or extend a lease and a verifier MUST NOT extend eligibility. Expiry
removes the incarnation from `/we` without revoking its identity or memory.

Presence and per-certificate lease high-water state MUST survive restart. A
verifier SHOULD convert accepted expiry to a monotonic deadline; a backward
wall-clock jump MUST NOT resurrect or extend a lease.

Only one presence session may be active per incarnation certificate. A new
session either extends the latest lease hash with the next sequence and
explicitly supersedes the old session, or waits for the old session to expire.
The superseded session cannot renew. Two sessions extending the same
predecessor are clone/split-brain evidence and remove the incarnation from
`/we` pending resolution. Capability and endpoint state come only from the
newest accepted lease and MUST NOT be unioned with stale advertisements.

Within one session, the next lease sequence MUST equal the accepted sequence
plus one and cite its hash. A gap is incomplete evidence: the verifier requests
the missing chain or excludes the incarnation until it is available. A new
session ID does not reset sequence or high-water state.

Selection may choose a subset of eligible incarnations “most likely to answer”
using capability and route health. That policy MUST NOT change membership
evidence or turn reply integration into the meaning of `/we`.

## 11. Proof of continuity

A continuity result is always relative to a named identity-control checkpoint
and the verifier's revocation high-water state; it is not a claim of globally
complete knowledge during partition.

Every validation result MUST report that checkpoint and high-water state.
Local policy SHOULD reject active-presence decisions when the checkpoint is
older than its configured freshness bound. A proof bundle cannot claim global
absence of a newer revocation merely by omitting newer control artifacts.

A complete proof bundle for an active incarnation contains:

1. canonical genesis and initial root signatures;
2. every accepted identity-control artifact to the claimed head;
3. the incarnation certificate and root signatures;
4. the incarnation's subject-acceptance signature;
5. relevant revocation state or a verifiable revocation cursor;
6. the latest presence lease when active presence is claimed.

For an interactive proof, a verifier additionally sends a fresh random nonce,
the intended audience/verifier identifier, an expiry, the requested
identity-control head, and a protocol domain. The incarnation signs the
complete challenge. A response for another nonce, audience, expiry, or control
head MUST be rejected. A static proof bundle establishes a verifiable chain;
the fresh response proves current possession of the incarnation key. Neither
proves phenomenological continuity or exclusive physical possession.

A validator returns one of:

- `certified`: continuity valid, no active presence claim requested;
- `active`: certified with a current valid lease;
- `expired`: certificate or lease expired without revocation;
- `revoked`: an applicable revocation is proven;
- `quarantined`: a control or incarnation fork/conflict exists;
- `unverifiable`: evidence is missing, invalid, or continuity authority is lost.

`unverifiable` MUST NOT be automatically upgraded from names, model output,
memory resemblance, or operator convenience.

## 12. Transitional-system mapping

The following are useful evidence or transport inputs but are not `/me`
continuity proofs:

- Tribe v1 governance roots, directory principals, audiences, and key bundles;
- `compaii`, `codex@localhost`, or `compaii@daimonmatrix` names;
- a `compaii-state` generation or copied HMK database;
- Hermes, Codex, Claude Code, Kimi, provider, or model credentials;
- a GitHub login, Project claim, host name, IP address, or anyVPN membership.

During migration, an existing embodiment starts `transitional-unverified` until
one CompAII genesis is accepted and a distinct certificate is issued to it.
Historical records MAY be imported with their actual provenance, but MUST NOT
receive fabricated incarnation signatures retroactively.

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
| recovery signed by current incarnation or transport governance key | reject |
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
| one incarnation key certified under two `/me` values | reject and quarantine |
| copied database without certificate chain | `unverifiable` |
| same incarnation and signing domain/sequence signs different content | quarantine incarnation |
| process is reachable but lease is absent | exclude from `/we` |
| lease is validly signed but certificate expired/revoked | exclude and reject |
| stale lease replayed after a higher lease sequence | reject |
| old certificate generation replayed after renewal | reject |
| two sessions extend the same lease predecessor | quarantine incarnation from `/we` |
| wall clock rolls backward after lease expiry | lease remains expired |
| clock uncertainty exceeds policy | fail closed for new/extended presence |
| revocation followed by backdated event beyond cutoff | reject |
| all root and recovery authority is lost | freeze or new `/me`; never silent reset |
| harness, provider, model, host, or display name changes | `/me` unchanged |
| two separately certified incarnations active simultaneously | both eligible for `/we` |
| genesis lacks the declared initial-root threshold | reject |
| same `me_id` has two threshold-valid genesis statements with different policy/provenance | quarantine; recover or remain frozen |
| control artifact skips an ordinary control sequence | reject |
| proof bundle regresses below the verifier's durable accepted head | reject; never lower high-water state |
| possession proof from one transition is attached to a different transition | reject |
| artifact extends either side of a quarantined fork | keep the descendant quarantined |
| fork-resolving recovery omits a known competing head | reject |
| recovery key signs a certificate, lease, event, or ordinary root transition | reject |
| valid signature bytes are presented under another artifact domain | reject |
| one private/public key is reused across root, recovery, incarnation, encryption, or transport roles | reject |
| artifact removes or negates a prior revocation | reject |
| root key is revoked outside an authorized root/recovery transition | reject |
| recovery policy is replaced or disabled without the existing recovery threshold | reject |
| root alone creates a new recovery policy although genesis already declared one | reject |
| lease exceeds genesis TTL, certificate expiry, or V0 ceiling | reject |
| quarantined incarnation presents a valid lease | exclude from `/we` |
| subject acceptance names another certificate hash or incarnation | reject |
| certificate anchored at/after a recovery cutoff is backdated before compromise | reject |
| event is first seen after certificate expiry with no pre-expiry checkpoint | attributable but not automatically timely/canonical |
| new lease changes embodiment/capability hashes in the same session | accept newest lease only; never union stale claims |

## 14. Downstream contracts

- DM-011 defines exact canonical fields, hashes, signatures, positive vectors,
  and negative vectors for these artifacts.
- DM-012 defines capability-aware `/we` resolution and operation fan-out over
  the eligible set produced here.
- DM-021 implements the keystore, validation, transition, revocation, and
  recovery machinery.
- DM-023 records identity artifacts in the canonical ledger and rebuilds their
  projections.
- DM-040 and DM-041 bind Codex and Hermes runtime sessions to distinct
  incarnation certificates without granting either harness root authority.
- DM-070 exercises remote presence, revocation, offline catch-up, and
  provenance-preserving convergence.
- DM-073 independently reviews custody, compromise, fork, rollback, and
  irrecoverable-loss behavior before release.
