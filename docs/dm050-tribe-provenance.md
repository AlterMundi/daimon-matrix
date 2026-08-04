# DM-050 Tribe Bridge provenance and no-copy gate

Status: implemented as build-time evidence. No Tribe source, schema, fixture,
runtime dependency, state, credential, message or configuration is imported.

## Decision

The reusable target is behavior, not the upstream authority model or codebase.
DM-051 through DM-053 independently implement recipient encryption, logical
communication state and routes under the already frozen Daimon contracts.
Tribe Bridge remains the reversible transitional transport until those gates
and DM-054/DM-055 complete; it is not a permanent third authority.

The reviewed upstream snapshot is
`nicoechaniz/tribe-bridge@b81a6838dd81167f7a8ffcae82cd7ebaadfa21e2`,
tree `1fc32b48867b8068a3ce6949bd84694bfd34177f`. GitHub reports no
detected license and the exact tree has no `LICENSE` path. Consequently the V1
manifest sets every copy flag false. Source adaptation stays prohibited until
an explicit compatible license or owner authorization is recorded in a future
manifest revision.

This is not merely a prose warning. The canonical
`provenance/tribe-bridge-v1.json` records 23 exact Git blob identities, byte
sizes and SHA-256 values, pins the no-copy policy, and classifies each input as
`behavioral_reference_only` or `superseded`. The independent verifier pins the
complete canonical manifest digest
`68acd3655763c6db04aa694965bccdc56b253062d949398c47c28b9aa62e2eaf`.
JSON alone therefore cannot add a file, change a hash, reclassify authority or
enable copying.

Run the offline check from the repository root:

```bash
python tools/check_tribe_provenance.py provenance/tribe-bridge-v1.json
```

The check performs no GitHub, network, filesystem discovery or live-host
query. Re-verifying upstream bytes is an explicit human/release audit against
the pinned commit, separate from deterministic CI.

## Reimplementation boundary

Behavioral references cover strict parsing and negative cases, fresh content
keys with independent recipient wrapping, opaque-hub behavior, replay and
conflict handling, durable queues and leases, ascending cursors, ACK-loss
recovery, direct/hub duplicate tolerance, deterministic fallback, explicit
profiles, fail-closed locality and optional duplicate-send warnings.

They do not authorize copying algorithms or wire types. DM-011 remains the
sealed-event and canonical artifact contract; DM-012 resolves recipients and
disclosure; DM-016 owns founded Tribe membership/grants; DM-018 bounds private
adapters; DM-023 owns canonical ledger/projection/cursor primitives. Later
implementations use reviewed cryptographic libraries and independently
generated Daimon vectors.

Superseded inputs include the Tribe directory, roster/membership, transitional
Weave payload, daemon selector/concept inventory, and GitHub coordination
implementation. A Tribe principal, route, directory row, ACK, DB row or cursor
proves neither being identity nor embodiment authority. One being may have
multiple awake embodiments, each with its own keys, state and origin.

## Safety and future licensing

No live secrets or state are candidates under any license. If source reuse is
later authorized, a successor card must record the authorization, exact files,
license obligations and resulting provenance before bytes enter the tree. It
must not mutate this V1 evidence or silently reinterpret
`behavioral_reference_only` as copy permission.

Buzz, Telegram and other gateways remain optional future route adapters. This
gate evaluates none of them and adds no carrier.
