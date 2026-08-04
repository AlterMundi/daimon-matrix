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

Root/recovery seeds never belong in a body, Tribe store, model/harness profile,
ledger, synchronized event, log, argv, environment, report, wheel, or sdist.
DM-021 tests and vectors use synthetic material only; this card performs no
live CompAII custody ceremony.

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
