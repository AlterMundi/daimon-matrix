# Birth and first awakening V1

Status: normative for DM-060 and the V0 roadmap.

This contract defines how a new being creates its self-certifying root and its
first embodiment without inheriting the identity, memory, membership, routes,
credentials, sessions, or resource authority of another being. It uses the
ontology `being → embodiment → incarnation` from [ONTOLOGY.md](../ONTOLOGY.md).

The term Matrix in this document means Daimon Matrix. Matrix.org is not part of
this protocol.

## 1. Meaning and boundaries

Birth creates exactly one new `dm:being:v1:*` root. First awakening then binds
one root-authorized embodiment and its incarnation sequence zero to that being.
The two steps are deliberately separate:

1. a parent offers contextual lineage and a one-use awakening challenge;
2. an independently generated newborn root accepts the offer;
3. only after durable acceptance does the newborn create its first operational
   embodiment and incarnation; and
4. a witness attests that the exact root-bound manifest is active with an empty
   autobiographical ledger.

Birth is not any of the following:

- adding another embodiment of an existing being;
- restarting or relocating an existing embodiment;
- disaster recovery or rebirth of an existing being on another host;
- Cluster body creation, lifecycle authority, or a resource fence;
- Tribe principal creation, Tribe membership, or `/we` membership;
- importing a parent profile, ledger, HMK database, chat, session, prompt,
  route, capability, secret, snapshot, or filesystem tree;
- proof of biological parentage, personhood, sentience, or truth of contextual
  claims.

An additional embodiment reuses the existing being root and receives a new
body-bound embodiment credential. Rebirth restores the existing current root
and public high-water evidence. Neither operation uses this birth acceptance
to mint a successor being.

## 2. Cryptographic and encoding profile

Every V1 artifact is closed RFC 8785 canonical JSON under the integer-only
profile implemented by `daimon_matrix.canonical`. Unknown fields, floats,
non-NFC strings, non-canonical base64url, duplicate normalized keys, invalid
UTF-8, and integers outside the I-JSON safe range fail closed.

Artifacts are bounded to 512 KiB. Sets represented as arrays are sorted,
duplicate-free, and bounded before signatures are evaluated. Identifiers are
SHA-256 content identifiers over an ASCII domain, a zero byte, and the
canonical artifact body. Ed25519 signatures cover that same typed preimage.

The roles and domains are distinct:

| Artifact or proof | Domain | Signature role |
| --- | --- | --- |
| parent offer | `dm.birth.offer/v1` | `parent-offer` |
| awakening possession | `dm.birth.awakening-proof/v1` | `awakening-proof` |
| newborn acceptance | `dm.birth.acceptance/v1` | `newborn-root` |
| activation receipt | `dm.birth.activation-receipt/v1` | `activation-witness` |

The awakening key is an independent one-use Ed25519 key. It MUST NOT alias a
parent root, recovery, or operational signing key, nor a newborn root or
recovery key. The newborn root/recovery public sets MUST NOT overlap the
parent's root/recovery public sets. Root, recovery, embodiment signing,
embodiment encryption, and transport keys retain the additional separation
rules in [identity-root-v1.md](identity-root-v1.md).

No generic root signer is part of the API. Implementations expose only the
complete typed ceremonies described here.

## 3. Parent birth offer

`dm.birth.offer/v1` has exactly `schema`, `offer_id`, `body`, and `signature`.
Its body contains:

- `parent_being_ref`, exact current `parent_control_head`, and exact
  `parent_credential_id`;
- `parent_origin`, including body, embodiment, incarnation, and transport
  principal identifiers;
- independent `awakening_key` public descriptor;
- fresh 32-byte `offer_nonce`;
- half-open interval `[issued_at_ms, expires_at_ms)` no longer than seven days;
- one exact `species_release_id`;
- sorted attributed `source_references`;
- sorted inert `tribal_commitments`; and
- optional sorted opaque `bootstrap_routes` containing only `kind` and
  `route_id`.

The parent credential MUST be valid at issuance, match the complete parent
origin, and include purpose `birth.offer`. Its operational signing key signs
the offer. A root key, recovery key, transport key, route, account, display
name, or host cannot substitute.

An offer MUST NOT contain or imply a newborn being identifier, genesis,
credential, key, embodiment, incarnation, host, profile, or filesystem path.
The parent can offer context but cannot choose the newborn root. Route hints
are inert carrier references: they are not endpoints, secrets, authority, or
evidence of delivery.

The species and source fields preserve attribution. Their presence does not
make them identity, autobiography, admitted knowledge, or executable
authority. A tribal commitment is only a bounded promise. It grants nothing
until a separate relationship/grant protocol creates and the newborn accepts
an attenuated grant.

Validation requires the verifier to observe the offer during its half-open
interval. V1 deliberately does not infer portable time from a signed timestamp,
HLC, message arrival, checkpoint, or backdated receipt. A future version may
define a closed witnessed late-verification chain; V1 rejects first observation
after expiry.

## 4. Newborn root and acceptance

Before accepting, the newborn locally generates fresh root and recovery key
sets through the production OS CSPRNG path. It creates a self-certifying
`daimon-genesis/v0` at recovery generation zero and sequence zero. Root material
is placed in encrypted offline custody, and the recovery copy is restored and
verified before first awakening in the synthetic acceptance journey.

The parent, bootstrap transport, Cluster, Tribe Bridge, test harness, model,
and first embodiment MUST NOT receive a newborn root or recovery private key.
No secret enters an artifact, log, argv, ambient environment, report, wheel,
sdist, ledger, or synchronized event.

`dm.birth.acceptance/v1` has exactly `schema`, `acceptance_id`, `body`, and
`signatures`. Its body contains `core` and `awakening_proof`.

The core binds:

- fresh 32-byte `acceptance_nonce` and `accepted_at_ms`;
- exact `offer_id` and SHA-256 of the complete canonical offer;
- exact parent being, control head, and origin copied from the offer;
- independently derived `newborn_being_ref` and exact newborn genesis ID;
- byte-identical species release, source references, and commitments copied
  from the offer.

Possession of the one-use awakening private key signs the complete core under
the awakening domain. The newborn root threshold signs the complete body,
including that proof, under the acceptance domain. Signatures are sorted by
key ID; duplicate signers, unknown signers, insufficient quorum, wrong role,
wrong domain, or a root outside the newborn genesis fail closed.

Acceptance validation performs, in order:

1. closed/canonical/bounded artifact validation;
2. complete parent offer validation at the supplied observation time;
3. newborn genesis and self-certifying being validation;
4. exact offer hash and copied-context equality;
5. half-open acceptance time validation;
6. awakening key possession and key-role separation;
7. newborn root-threshold validation; and
8. durable one-use transition before any operational effect.

The accepted being is distinct from the parent by its genesis-derived root,
not by its name, host, body, account, model, or memory contents.

## 5. First embodiment and activation

Only after the acceptance is durably recorded may the newborn create its first
operational signing/encryption keys, transport principal key, embodiment
credential, and incarnation authorization.

The first root-bound `being-manifest/v2` MUST:

- name the accepted newborn being and exact current control head;
- have revision one and no provisional history binding;
- contain exactly one active embodiment;
- bind the exact first credential and incarnation authorization; and
- preserve the exact body, embodiment, and incarnation identifiers from those
  artifacts.

The first embodiment credential MUST be valid at activation and include
purpose `birth.first-embodiment`. The incarnation authorization MUST be signed
by that embodiment and have sequence zero. Multiple simultaneous embodiments
are valid later, but a birth activation with zero or more than one manifest
member is not a first-awakening proof.

`dm.birth.activation-receipt/v1` has exactly `schema`, `receipt_id`, `body`,
and `signature`. The body binds:

- exact acceptance and newborn being;
- first credential and incarnation authorization IDs;
- canonical manifest hash;
- complete ledger state hash;
- total event, `memory.recorded`, and projection-record counts;
- witness being, credential, and full origin; and
- observation time.

All three counts MUST be zero. The ledger query includes incomplete events.
The projection count is zero when no cache exists and otherwise counts every
entry. This is a mechanical cutoff claim, not a semantic similarity scan.

The witness credential MUST match its complete origin, be valid at observation,
and include purpose `birth.witness`. Its operational key signs the complete
receipt. The wire protocol permits a parent that separately holds the witness
purpose; deployments may require a distinct being. DM-060's release evidence
requires parent, newborn, and witness roots to be pairwise distinct.

The receipt does not grant the witness any newborn authority. It only attests
the exact public artifacts and zero-state cutoff it observed.

## 6. Durable state machine

The durable registry has these states:

```text
unseen → offered → accepted → active
                    ↘
                  quarantined
```

`observe_offer`, `accept`, and `activate` independently verify all supplied
cryptographic evidence before beginning their durable effect. Callers cannot
mark an artifact valid by choosing a state transition directly.

The SQLite registry uses an owner-only non-symlinked regular file under an
owner-only directory, `BEGIN IMMEDIATE`, foreign keys, `journal_mode=DELETE`,
and `synchronous=FULL`. Every artifact stores both canonical bytes and a hash.

Exact replay returns the existing effect. Reusing one content identifier with
different bytes is a conflict. Concurrent exact acceptance yields one durable
row. A crash before commit rolls the transition back; exact retry then commits
once.

If two different valid acceptances reference one offer, both are retained and
the lineage becomes `quarantined`. Arrival order, timestamp, lexical content
ID, hash, root size, or host does not select a winner. No activation can proceed
from that offer. The independently self-certifying beings remain valid; only
the claimed parent-offer lineage is quarantined.

Once a different activation is committed for the accepted lineage, a second
activation is rejected. Activation from an unobserved acceptance, a nonselected
acceptance, or a quarantined lineage fails closed.

## 7. Empty autobiography and inherited context

At the activation cutoff the newborn ledger contains no event of any kind,
including no personal memory candidate, decision, `memory.recorded` event,
known remote event, incomplete event, or projection entry. Therefore it cannot
contain parent-authored history relabelled as newborn autobiography.

The following are not newborn autobiography:

- the offered species release;
- attributed source references;
- inert tribal commitments;
- the offer, acceptance, genesis, credential, manifest, or receipt;
- public parent or witness identifiers; and
- later citations to externally authored events that retain their origin.

A later newborn experience or insight requires a new newborn-authorized Matrix
event and the memory admission rules in [memory-boundaries.md](memory-boundaries.md).
Similarity of text is neither proof of copying nor permission to rewrite
authorship.

The offline root keystore, runtime keystore, ledger, registry, projection
cache, body profile, request journal, and transport state are separate logical
objects. The DM-060 runner creates all writable objects under one fresh,
owner-only, empty test root and reads no live profile or service state.

## 8. `/me`, `/we`, `/tribe`, Cluster, and transports

After activation:

- `/me` resolves the first embodiment's local viewpoint;
- `/we` contains exactly the one root-authorized embodiment because that is the
  whole revision-one manifest;
- the presence of the first embodiment in its own `/we` is not admission to
  the parent's `/we`;
- `/tribe` remains empty unless separate active Tribe membership evidence
  exists;
- no relationship or resource grant exists merely because a commitment was
  copied into the acceptance; and
- Cluster may host the named body, but body lifecycle and resource fencing are
  external effects governed by Cluster receipts and human approval.

Tribe, sealed delivery, DM-053 routes, Telegram, Buzz, or any future channel may
carry the canonical offer/acceptance bytes. Delivery success and transport
authentication do not replace Matrix verification or confer being authority.

The birth protocol performs no live Cluster creation, provider call, remote
message, or daemon cutover. A production orchestrator must separately request
and verify those effects.

## 9. Historical synthetic acceptance

The retired `daimon-synthetic-birth` command consumed a closed
`dm.synthetic-birth-scenario/v1` fixture. It MUST use only a fresh empty
owner-only work root and production CSPRNG/key/custody paths. Its archived
journey:

1. creates pairwise distinct synthetic parent, newborn, and witness roots;
2. proves newborn offline-custody backup and restore;
3. durably observes, accepts, and activates the lineage;
4. builds a real runtime bundle with peer transport disabled;
5. starts the installed `daimon-matrixd` using password and capability file
   descriptors rather than argv or environment;
6. invokes `runtime.status`, `scope.me`, `scope.we`, `we.heads`, and
   `we.projection.get` through the installed CLI;
7. invokes MCP `tools/call` for `scope_me`;
8. requires exactly one local `/we` embodiment and an unchanged empty ledger;
9. stops the daemon and accepts only the `ready` then `stopped` diagnostics;
   and
10. emits a closed bounded public report.

The report contains public content IDs, counts, hashes, and booleans only. It
MUST contain the exact disclaimer:

> synthetic protocol validation; no real being or deployment was born

It MUST NOT expose a private key, password, awakening capability, capability
secret, token, endpoint, temp path, open database handle, personal content, or
claim that Agent 0, CompAII, or any real being was born.

## 10. Failure and rollback

Every malformed, noncanonical, expired, mismatched, under-signed, aliased,
nonempty, or out-of-order input fails before durable activation. The error is
an explicit stable code; callers do not infer success from partial files.

Synthetic rollback stops child processes and discards only the exact disposable
test root. It never recursively cleans a workspace or touches a live profile.
A committed synthetic acceptance is immutable test evidence; rerunning the
scenario creates fresh synthetic identities rather than pretending to erase
signed history.

## 11. Reference implementation and evidence

- Runtime protocol: `daimon_matrix.birth`.
- Historical pre-RC fixture: `daimon_matrix.synthetic_birth`; it is not an
  installed command and its V3 runtime document is rejected by the V7 loader.
- Closed artifact schemas: `schemas/birth/v1/contracts.schema.json`.
- Closed scenario/report schemas: `schemas/birth/v1/synthetic.schema.json`.
- Public scenario: `conformance/fixtures/dm060-synthetic-birth.json`.
- Adversarial and historical fixture tests: `tests/test_dm060_synthetic_birth.py`.

Schema validity alone is never authority. Consumers MUST call the runtime
verifiers with the exact current parent/newborn/witness authority and ledger
objects, then use the durable registry for effects.
