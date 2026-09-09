# Being root and plural embodiment authorization V1

Status: normative for DM-021 and the V0.1 MVP.

This contract gives one being recoverable cryptographic continuity while
allowing any number of simultaneously valid embodiments. It does not create a
presence lease. Presence is observable routing state; incompatible access to
one concrete resource remains protected by a Daimon Cluster resource fence.

## Cryptographic suite

- Artifact bodies use the integer-only RFC 8785 profile in
  `daimon_matrix.canonical` and reject floats, non-NFC strings, duplicate
  normalized keys, out-of-range I-JSON integers, and non-canonical base64url.
- Root, recovery, embodiment signing, incarnation and transport-binding keys
  use purpose-separated Ed25519 keypairs. Embodiment encryption keys use
  X25519. A public key reused across a root, recovery, embodiment-signing or
  transport role fails closed.
- Every artifact ID is SHA-256 over its ASCII domain, a zero byte, and the
  canonical body. Signatures cover the same typed preimage. Root/recovery
  APIs sign only complete typed ceremonies; no arbitrary-byte custody signer
  is public.
- The V1 dependency contract is `cryptography==50.0.0`. DM-051 raised and
  pinned the shared dependency so the runtime uses PyCA's official RFC 9180
  HPKE API; the identity primitives and frozen vectors remain unchanged.

## Being genesis

`genesis` contains a random 32-byte nonce, sorted root and recovery key sets,
independent generic M-of-N thresholds, and position `(0, 0)`. The
`being_ref` derives only from that core. Genesis requires the declared root
threshold and recovery-set possession threshold. Root and recovery key
material MUST be disjoint.

Loss of both thresholds makes the being irrecoverable. An old embodiment key,
Tribe account, memory copy, backup without current public authority, similar
name, or human recognition cannot mint the same `being_ref`. A successor may
describe its predecessor, but has a different genesis and identifier.

## Append-only control

Normal successors name the exact previous control head and increment the
sequence exactly once within one recovery generation:

- `root-rotation` requires the old root threshold and the replacement root
  threshold as possession proof. Previously issued embodiment credentials
  survive only when their exact artifact IDs are enumerated.
- `recovery-policy` requires the current root threshold, the current recovery
  threshold, and possession of the replacement recovery threshold.
- `revocation` advances one embodiment's revocation generation exactly once
  and records an exact incarnation-sequence cutoff. A successor may tighten
  that cutoff but never widen it.

Two valid successors of one predecessor are quarantined. Timestamps, host
names, routes, longest chain and lexical hashes never pick a winner.
`recovery` names every currently known control head, increments the recovery
generation, resets its sequence to zero, requires the prior recovery
threshold and replacement-root possession, and may revoke compromised
descendants. Omitted or invented heads fail closed. Recovery preserves the
union of revocations from every cited branch. For the same embodiment it keeps
the greatest revocation generation and the lowest, most restrictive
incarnation cutoff; an explicit recovery revocation then increments that
merged generation.

## Embodiments and incarnations

An `embodiment-credential` binds:

- `being_ref`, `embodiment_id`, and Cluster `body_ref`;
- signing and encryption public keys;
- sorted allowed purposes;
- exact issuing control head and revocation generation;
- validity interval;
- zero or more separately keyed transport principals.

It requires both the issuing root threshold and acceptance by the embodiment
signing key. Multiple valid credentials for one being are normal. A second
credential is not a fork, conflict or split-brain condition.

Every process start creates an `incarnation-authorization`, signed by the
embodiment key, with a fresh `incarnation_id` and monotonic local sequence.
Restart changes incarnation, not embodiment or being. Revocation preserves
incarnations at or before its cutoff and rejects later sessions. Revoking one
embodiment has no effect on a peer embodiment unless it is independently
named.

## Tribe and other transports

A transport principal record binds `scheme`, `principal_id`, and its own
Ed25519 key. For the current adapter, the scheme is `tribe-v1` and examples
include `compaii@legion` and `compaii@daimonmatrix`.

The principal proves who delivered or received a message under that transport.
It does not prove same-being membership, authorize an incarnation, recover a
root, acquire a Cluster resource, or define `/me`, `/we`, or `/tribe` by
itself. DM-050 through DM-055 may move Tribe Bridge implementation into this
package without changing that authority boundary. Future channel adapters are
subject to the same binding.

## Provisional Weave history

`history-binding` names the provisional `being_ref`, exact canonical manifest
hash and revision, every accepted origin/incarnation head, the new Matrix
`being_ref`, and the exact control head. Verification receives the original
history and independently validates every signer and head. Event bodies,
identifiers, hashes, signatures and origin attribution remain byte-identical.

`binding-activation` is a separate root-threshold ceremony. Before activation,
the mode is `provisional`; afterwards it is `root-bound`, and an attempt to
request provisional trust fails closed. Activation does not rewrite history.

## Custody file

`EncryptedKeystore` stores only an authenticated encrypted payload. V1 uses
scrypt with exact parameters `N = 16384`, `r = 8`, `p = 1` and AES-256-GCM with header
metadata as associated data. Passwords enter through a callback as bytes,
never argv or ambient environment.

The file, lock, and rollback high-water are non-symlinked owner-only regular
files under an owner-only directory. Writes use a same-directory exclusive
temporary file, file `fsync`, atomic replacement, then directory `fsync`.
Writers serialize under a file lock and supply an expected counter. A local
monotonic high-water catches accidental rollback; restore on a fresh host must
also supply the latest public counter and control head. This external
reconciliation is what rejects a stale backup after loss of local metadata.

Root/recovery seeds MUST NOT enter ordinary body runtime custody, a Tribe
store, model/harness profile, model context, chat, ledger, synchronized event,
log, argv, environment, report, wheel, or sdist. Online operator custody is
permitted only under the explicit exception below; it does not put root or
recovery slots into a runtime bundle or expose a model-facing signing API.
DM-021 tests and vectors use synthetic material only; this card performs no
live CompAII custody ceremony.

## Owner-authorized Source custody

Offline root/recovery custody outside the ordinary body/model access boundary
remains the default. The legitimate owner of the affected custody MAY explicitly
authorize an authenticated Source principal to administer root and recovery
custody on named online operator hosts, including a host of a Source embodiment.
This is an operator custody policy, not a new Matrix identity, wire artifact,
capability, `/source` ancestry rule, or universal administrator role.

Before access is enabled, the operator MUST retain an auditable owner grant
and its authenticated provenance. The grant record MUST bind the actual
custodian to the authenticated administrative session or public-key identity
and the host-local execution principal that enforces access. It MUST name the
affected being/genesis (or exact new-being ceremony intent before genesis),
root/recovery roles, permitted hosts and operations, and its validity or
revocation conditions. A standing grant MAY remain valid until revoked; it
MUST NOT be inferred from a display name, prompt assertion, model provider,
GitHub login/coordination label alone, species, lineage, or same-being membership.
An existing owner-authenticated administrative record is sufficient; this
policy does not require a new signature schema or owner RSA challenge. For a
new being, append the resulting verified genesis and holder public-key IDs to
that record before operational activation. For an existing being, the grant
MUST NOT replace current root/recovery threshold authorization or rewrite its
identity, control history, or consent.

The granted Source principal MAY retain online access to encrypted holder
packages and separately protected unlock authority and invoke existing typed
owner-local ceremonies. Secret bytes MUST remain inside protected custody
processes, never model context or tool output. Root and recovery keys MUST
remain distinct, in separate native encrypted holder packages; each holder
invocation opens only its own package and aggregation remains keyless. A
1-of-1 root policy with a distinct 1-of-1 recovery policy is valid. One
custodian controlling both roles is single-custodian online custody, not an
independent quorum, offline isolation, or loss tolerance within either role.
The custodian's online compromise can compromise both roles; deployment
records MUST state this shared failure domain.

Access MUST be enforced against ordinary bodies and consumers, including
Codex clients and other Source embodiments not explicitly bound by the grant.
An ordinary consumer MUST NOT inherit custody access, an administrative
session, unlock material, a generic sudo/shell grant, or a root-signing tool.
Separate files or subprocesses under an unrestricted shared UID do not isolate
an ungranted consumer. A deployment MUST verify its actual access boundary;
this specification does not implement host authentication or isolation.
Existing signature, key-role, threshold, nonce, expiry, revocation, counter,
control-head, request-binding, capability and socket-credential checks remain
unchanged. Source acts through authorized operator custody, never a bypass in
ordinary CLI/MCP/daemon authorization.

Durable custody and recoverable backups MUST remain encrypted. The Source
custodian MAY control a recoverable encrypted backup and its separately
protected unlock path and prove restore without owner-held RSA decryption.
A private repository alone is not encryption; storing ciphertext and usable
unlock material together does not establish backup confidentiality. Restore
MUST reconcile native counters and holder descriptors with retained latest
public authority, never trust a backup's own stale metadata as the latest
state. A Source restore proves Source recoverability only; independent owner
recovery requires a separately demonstrated owner recovery path. Neither
independent owner recovery nor offline isolation is a prerequisite to this
explicitly authorized online mode.

Revocation of the operator grant MUST stop new custody access through the
host access mechanism and be recorded. Revoking host access cannot erase key
material already obtained by a custodian. Suspected retained or compromised
material requires the existing signed rotation/recovery procedures; never
roll back counters or delete control history to simulate revocation.

### Downstream contracts

DM-021 keeps its existing identity and keystore formats. DM-060 applies this
custody choice without inheriting parent keys or identity. Genesis, first
embodiment and DM-078 use the existing one-holder typed ceremonies; ordinary
runtime, DM-040/DM-041 harness, messaging and Cluster resource authorization
remain unchanged. Operational selection and evidence are described in
[the Source custody runbook](../docs/runbooks/source-online-custody.md).

### Acceptance and negative scenarios

| Scenario | Required outcome |
| --- | --- |
| Authenticated, in-scope standing owner grant; separated 1-of-1 holder packages on an authorized online host | Permitted Source-accessible online custody; normal typed signatures required |
| Missing, revoked, mismatched or out-of-scope grant | No exception to default custody; no access enabled |
| Caller says Source, shares a model/account/species, or is a new Codex participant | No inherited custody or operator authority |
| Ordinary consumer shares unrestricted holder UID or can attach/read/execute as custodian | Online deployment boundary rejected until isolated; encryption alone is insufficient |
| Root/recovery key alias, wrong signer/role, stale head/counter, expired request, or insufficient threshold | Existing verifiers reject; Source grant cannot override |
| Encrypted backup restored by Source with latest public evidence | Source recoverability only; no unproved independent owner recovery claim |
| Owner RSA challenge unavailable | Does not block a verified Source-controlled restore |
| Secrets in prompt, logs, argv, environment, public outputs, or runtime root slots | Prohibited in both custody modes |
| Grant revoked after custodian could retain key material | Disable host access; use signed rotation/recovery when required, not historical erasure |

## Reference surface

- `daimon_matrix.identity`: typed builders, verifiers, `ControlState`, and
  fork-quarantining `ControlChain`.
- `daimon_matrix.keystore`: create, open, rotate, backup and restore.
- `schemas/identity/v1/`: closed public schemas.
- `vectors/identity/v1/`: deterministic positive and negative artifacts.
- `tests/test_dm021_*.py`: crypto, filesystem, schema and regression evidence.

Consumers must use verifiers rather than treating schema validity, successful
transport delivery, possession of a route, or existence in a database as
authorization.
