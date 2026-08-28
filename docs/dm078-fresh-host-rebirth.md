# DM-078 additional-embodiment rebirth

Status: implemented V0 public-request/offline-root contracts for both an
additional embodiment and recovery-quorum rebirth. Installed distinct-host,
true relocation and disposable restore journeys remain operational gates.

Rebirth in this contract means creating a new embodiment of the same being. In
the ordinary path it adds that body beside the existing active embodiments. In
the recovery path a recovery quorum revokes every old active embodiment,
rotates root authority and authorizes exactly one fresh replacement body. Both
paths begin with a fresh embodiment ID, first incarnation, empty local writable
stores and independent signing, encryption, transport and capability custody.
Neither copies an old body's private keys, local decisions or writable
database, relocates an existing embodiment, or creates another being. The new
body may ingest the same being's accepted signed history.

## Split-custody ceremony

The target and offline-root halves exchange public canonical artifacts:

1. The fresh target generates independent Ed25519 embodiment and transport
   keys plus an X25519 encryption key. It creates
   `dm.operator.embodiment-request/v1`, signed independently by the embodiment
   and transport keys. The request contains no private key.
2. The offline holder verifies the exact being, control and manifest heads,
   expiry, nonce, new identifiers, partial embodiment acceptance, first
   incarnation and both proofs of possession. It never receives target
   custody.
3. A current root threshold completes the embodiment credential and signs one
   `dm.we.embodiment-enrollment/v1` successor. The transition binds the request,
   body, embodiment, incarnation, native peer principal, credential,
   authorization and exact previous/successor manifests.
4. The target validates the activation against its original request before it
   installs anything. Existing peers validate the same root transition and
   advance their public bundles without gaining target secrets.

No process or artifact in this flow requires root seeds and embodiment private
keys together. Root custody cannot impersonate the embodiment acceptance or
transport proof; target custody cannot reach the root threshold.

The installed `daimon-rebirth` interface keeps that boundary executable.
`prepare` runs on the target and writes only target custody. Each
`enrollment-share` invocation opens exactly one holder package; the intent and
aggregation steps are keyless. Passwords use inherited descriptors and no
command accepts private key bytes through arguments or environment:

```bash
python -m daimon_matrix.operator_rebirth prepare \
  --authority /public/current-authority.json \
  --profile /public/fresh-target-profile.json \
  --output /target-owner/rebirth-preparation \
  --password-fd 3 3</target-owner/password

daimon-rebirth create-enrollment-intent \
  --authority /public/current-authority.json \
  --request /public/enrollment-request.json \
  --output /public/enrollment-intent.json

daimon-rebirth enrollment-share \
  --authority /public/current-authority.json \
  --request /public/enrollment-request.json \
  --intent /public/enrollment-intent.json \
  --holder /offline/root-a \
  --password-fd 3 \
  --output /public/root-a.share.json 3</offline/root-a.password

daimon-rebirth aggregate-enrollment \
  --authority /public/current-authority.json \
  --request /public/enrollment-request.json \
  --intent /public/enrollment-intent.json \
  --share /public/root-a.share.json \
  --share /public/root-b.share.json \
  --output /public/activation.json

python -m daimon_matrix.operator_rebirth activate \
  --base-runtime /public/current-runtime.json \
  --preparation-dir /target-owner/rebirth-preparation \
  --request /public/enrollment-request.json \
  --activation /public/activation.json \
  --output /target-owner/rebirth-package \
  --password-fd 3 3</target-owner/password
```

Preparation is a one-shot, fsynced owner-only directory. It contains encrypted
body custody, separately encrypted transitional transport custody, ten public
least-authority operator descriptors, two dedicated host-bound descriptors, the target peer profile and the public
request. Every operator role has an independent random key and custody slot;
the default client is the non-mutating `observe` role and no descriptor spans
the full service surface. Root activation is an owner-only public artifact. The
target-only `activate` process reopens and revalidates its custody against the
root-signed activation, emits a loadable V7 runtime with empty writable stores,
and retains only hashes in its public receipt. Cluster still owns authenticated
transfer, journaled installation, target start and peer update. Cluster H7/H8 now
implement and remotely rehearse that boundary: installation is crash-resumable
and activation-idempotent, then a foreground supervisor admits only the signed
initial incarnation, supplies the password by inherited descriptor and
authenticates status, `/me` and `/we` before reporting `running-ready`.

Operator capabilities have a fixed 30-day lifetime. Preparation and activation
receipts bind a reprovision instant seven days before hard expiry. Before that
instant, repeat the split-custody rebirth ceremony to create a fresh
root-authorized embodiment with a completely new twelve-key role set, cut over, and
park or revoke the predecessor. Rebirth never regroups the roles and never
copies capability keys. Expired or revoked descriptors are rejected at runtime
load as well as at request authentication; in-place rotation of a live bundle,
custody and plaintext client directories is intentionally unsupported.

## Only permitted manifest delta

The enrollment validator accepts exactly one new active manifest row while
preserving every prior row byte-for-byte. The being reference, control head,
history binding and all old embodiments are immutable, and the revision
advances by exactly one. The new credential must be current, root-threshold
authorized, accepted by the new embodiment, usable for `dm.we`, bound to the
declared body and native peer principal, and paired with incarnation sequence
zero.

Reusing any prior embodiment ID, combining retirement or relocation with the
enrollment, changing an old row, skipping the revision, substituting a request
or principal, presenting duplicate root signatures, or signing below threshold
fails closed. A root control rotation is a separate control successor and must
be completed before generating the request.

`RootHistoryAuthority` recognizes this transition alongside the existing
same-embodiment authority epoch. Historical events continue to select their
original manifest hash. A fresh empty ledger may ingest those immutable events
and append its first event with the new origin and successor hash; it never
becomes a clone of another embodiment's local decisions or effective state.

## Recovery-quorum rebirth

The recovery path is a separate forward-only transition,
`dm.we.recovery-rebirth/v1`. It first verifies a threshold recovery artifact
against the old control chain. The artifact must revoke the complete set of old
active embodiment IDs and install a fresh root threshold. No operational body
is active in that intermediate control state.

The public distributed ceremony keeps every custody role separate. Repeat the
holder/share commands once per required participant; the abbreviated paths
below show one recovery holder and one replacement-root holder:

```bash
daimon-rebirth create-replacement-root-holder \
  --authority /public/old-authority.json \
  --password-fd 3 \
  --output /holders/new-root-a 3</holders/new-root-a.password

daimon-rebirth create-recovery-intent \
  --authority /public/old-authority.json \
  --holder-descriptor /holders/recovery-a/descriptor.json \
  --holder-descriptor /holders/new-root-a/descriptor.json \
  --threshold 2 \
  --output /public/recovery-intent.json

daimon-rebirth recovery-share \
  --authority /public/old-authority.json \
  --intent /public/recovery-intent.json \
  --holder /holders/recovery-a \
  --password-fd 3 \
  --output /public/recovery-a.share.json 3</holders/recovery-a.password

daimon-rebirth recovery-share \
  --authority /public/old-authority.json \
  --intent /public/recovery-intent.json \
  --holder /holders/new-root-a \
  --password-fd 3 \
  --output /public/new-root-a.possession-share.json \
  3</holders/new-root-a.password

daimon-rebirth aggregate-recovery \
  --authority /public/old-authority.json \
  --intent /public/recovery-intent.json \
  --share /public/recovery-a.share.json \
  --share /public/new-root-a.possession-share.json \
  --output /public/recovery-artifact.json

daimon-rebirth prepare-recovery \
  --authority /public/old-authority.json \
  --recovery /public/recovery-artifact.json \
  --profile /public/recovery-target-profile.json \
  --output /target/recovery-preparation \
  --password-fd 3 3</target/password

daimon-rebirth create-recovery-authorization-intent \
  --authority /public/old-authority.json \
  --recovery /public/recovery-artifact.json \
  --request /public/recovery-enrollment-request.json \
  --output /public/recovery-authorization-intent.json

daimon-rebirth recovery-authorization-share \
  --authority /public/old-authority.json \
  --recovery /public/recovery-artifact.json \
  --request /public/recovery-enrollment-request.json \
  --intent /public/recovery-authorization-intent.json \
  --holder /holders/new-root-a \
  --password-fd 3 \
  --output /public/new-root-a.authorization-share.json \
  3</holders/new-root-a.password

daimon-rebirth aggregate-recovery-authorization \
  --authority /public/old-authority.json \
  --recovery /public/recovery-artifact.json \
  --request /public/recovery-enrollment-request.json \
  --intent /public/recovery-authorization-intent.json \
  --share /public/new-root-a.authorization-share.json \
  --output /public/recovery-activation.json

daimon-rebirth activate-recovery \
  --base-runtime /public/old-runtime.json \
  --preparation-dir /target/recovery-preparation \
  --request /public/recovery-enrollment-request.json \
  --activation /public/recovery-activation.json \
  --output /target/recovered-package \
  --password-fd 3 3</target/password
```

Each old recovery holder and each new root holder opens only its own package.
The intent and both aggregators are keyless; no process or store owns a quorum
of seeds. Target preparation happens only after the public recovery artifact
verifies. The activation binds the recovery artifact, old and new control
heads, old and successor manifests, the full revocation set, and the fresh
body's credential, incarnation and peer principal. It is signed by independent
shares from the new root threshold. The `synthetic-single-store-*` commands are
fixtures only and are deliberately absent from this operational procedure.

The recovered V7 bundle has only the fresh embodiment active and therefore may
have an empty peer target list. Its `authority_history` carries a self-contained
snapshot of the previous control artifacts, credentials and incarnations so
old signed events remain verifiable even though none of those credentials is
active. The bundle contains no old private key and starts with an empty writable
ledger; restoring canonical signed history is a distinct, auditable step.

## Forward-only runtime update

`apply_activation_to_runtime_bundle` produces a public, non-mutating update for
an existing V7 peer: it appends the old manifest plus signed successor to
`authority_history`, installs the successor public authority and adds the new
configured endpoint. Body custody, ledgers, projection stores and endpoint
reachability are not authority and are not copied by this function.

The target runtime package must be assembled on the target host from its own
encrypted custody and fresh stores. Cluster owns the surrounding host-level transaction:
quiescence when needed, body registration, owner-only directory creation,
release installation, durable-volume semantics, resource fences, service
start, backup and rollback. Tribe/AnyVPN supplies authenticated reachability;
it does not create Matrix identity.

## Operational gates

The vectors and local process journeys are synthetic evidence only. DM-078 is
not complete until the issue's distinct-host/Incus additional-embodiment, true
relocation and disaster-recovery restore journeys pass with installed Matrix,
Cluster and transport components and their fault matrix.

Disposable Incus rehearsal may proceed autonomously. A live CompAII authority
change still requires one exact preflight naming:

- source and target hosts and content-addressed Matrix/Cluster/Tribe heads;
- current root and recovery thresholds, without publishing keys;
- verified backup cutoff and retained recovery locations;
- exact being/control/manifest and accepted Weave heads;
- target body, embodiment, incarnation and transport bindings;
- park/revoke/route-removal rollback and honest terminal states; and
- confirmation that no last recoverable body, quorum or backup is at risk.

The GO authorizes that one plan only. Rollback is forward state: park or revoke
the canary and remove its route with a signed successor. It never deletes
canonical events, control artifacts, revocations, fence high-waters or the sole
backup.

The wire schemas are `schemas/weave/v1/embodiment-enrollment.schema.json` and
`schemas/weave/v1/recovery-rebirth.schema.json`. Deterministic positive and
tampered vectors are under `vectors/weave/v1/embodiment-enrollment/` and
`vectors/weave/v1/recovery-rebirth/`, generated by the corresponding
`tools/generate_dm078*_vectors.py` scripts. Contract and ledger evidence is in
`tests/test_dm078_rebirth.py` and `tests/test_dm078_recovery_rebirth.py`; the
current verification boundary is recorded in
`docs/verification/dm078-fresh-host-rebirth.md`.
