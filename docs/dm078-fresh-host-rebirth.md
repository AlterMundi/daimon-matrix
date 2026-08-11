# DM-078 additional-embodiment rebirth

Status: implemented V0 public-request/offline-root contract; disposable and
live multi-host journeys remain operational gates.

Rebirth in this contract means adding a new embodiment of the same being. It
does not copy an old body's private keys or writable database, relocate an
existing embodiment, or create another being. The new body begins with a fresh
embodiment ID, first incarnation, empty local writable stores and its own
signing, encryption, transport and capability custody. It may then ingest the
same being's accepted signed history.

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

The installed-module interface keeps that boundary executable even before a
dedicated console alias is published. `prepare` runs on the target and writes
only target custody; `authorize` runs at the offline root and receives only the
public request. Passwords use inherited descriptors and neither command accepts
private key bytes through arguments or environment:

```bash
python -m daimon_matrix.operator_rebirth prepare \
  --authority /public/current-authority.json \
  --profile /public/fresh-target-profile.json \
  --output /target-owner/rebirth-preparation \
  --password-fd 3 3</target-owner/password

python -m daimon_matrix.operator_rebirth authorize \
  --authority /public/current-authority.json \
  --request /public/enrollment-request.json \
  --root-custody /offline/root-custody.json \
  --root-password-fd 3 \
  --output /public/activation.json 3</offline/root-password
```

Preparation is a one-shot, fsynced owner-only directory. It contains encrypted
body custody, separately encrypted transitional transport custody, public
operator/status capability descriptors, the target peer profile and the public
request. Activation is an owner-only public artifact. Cluster still owns
authenticated transfer, runtime assembly, target start and peer update.

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

## Forward-only runtime update

`apply_activation_to_runtime_bundle` produces a public, non-mutating update for
an existing V7 peer: it appends the old manifest plus signed successor to
`authority_history`, installs the successor public authority and adds the new
configured endpoint. Body custody, ledgers, projection stores and endpoint
reachability are not authority and are not copied by this function.

The target runtime itself must be assembled on the target host from its own
encrypted custody and fresh stores. Cluster owns that host-level transaction:
quiescence when needed, body registration, owner-only directory creation,
release installation, durable-volume semantics, resource fences, service
start, backup and rollback. Tribe/AnyVPN supplies authenticated reachability;
it does not create Matrix identity.

## Operational gates

The published vectors and unit journey are safe synthetic evidence only. DM-078
is not complete until the issue's additional-embodiment, relocation and
disaster-recovery journeys pass with installed Matrix, Cluster and transport
components and their fault matrix.

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

The wire schema is
`schemas/weave/v1/embodiment-enrollment.schema.json`. Deterministic positive and
tampered vectors are under `vectors/weave/v1/embodiment-enrollment/` and are
generated by `tools/generate_dm078_vectors.py`. Contract and ledger evidence is
in `tests/test_dm078_rebirth.py`; the current verification boundary is recorded
in `docs/verification/dm078-fresh-host-rebirth.md`.
