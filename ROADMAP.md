# Roadmap

## Historical RC closeout

The V0 Matrix baseline is merged. The historical cross-repository `0.1.0rc1`
qualification used clean local/CI and disposable end-to-end evidence. Its
three-repository pins, manifests and tools remain historical reproducibility
evidence, not stable runtime or cutover inputs. No infrastructure is presumed
active or removed.

Completed software milestones: V7/V3-only Matrix, separated recovery holders,
shared Cluster admission/fencing, fresh-embodiment recovery, disposable
backup/restore/rebirth/rollback journeys, reproducible Matrix artifacts and a
non-executing content-addressed physical preflight.

The Matrix software boundary and reachable-Hermes package closeout are merged.
The historical RC handoff contract avoided predicting its own merge or downstream
Cluster/Bridge metadata heads: it required Cluster to pin the actual Matrix
merge, Bridge to record the resulting Cluster merge, and an external
content-addressed manifest to verify all three exact heads and clean artifact
installations.
That three-repository contract does not govern the stable successor.

## Native stable successor qualification

[TRIBE-MIGRATION.md](TRIBE-MIGRATION.md) is current policy, following the Bridge
[retirement decision #71](https://github.com/nicoechaniz/tribe-bridge/issues/71),
merged [PR #72](https://github.com/nicoechaniz/tribe-bridge/pull/72) and Cluster's
merged [PR #103](https://github.com/nicoechaniz/daimon-cluster/pull/103) and
[retirement boundary](https://github.com/nicoechaniz/daimon-cluster/blob/main/docs/tribe-bridge-retirement.md).
Bridge is superseded; stable qualification requires native Matrix+Cluster,
not Bridge provisioning, rotation or retention. No Bridge operational state
is migrated and no Bridge compatibility, downgrade, fallback or dual-run is
preserved. Matrix's native tribe/relationship governance is not retired.

Prepare a new external content-addressed Matrix+Cluster freeze under
[#72](https://github.com/AlterMundi/daimon-matrix/issues/72), with exact clean
heads, tested cross-pins, reproducible artifacts and clean installations.
Native continuity, authenticated intake, retry/restart, revocation and
foreign-being signed semantic receipts must qualify without Bridge. This is a
required successor checkpoint, not a claim that its manifest/tool already
exists. Keep the freeze external to avoid a self-referential metadata hash
cycle; historical RC tools do not establish stable qualification.

## Release invariants

- A being may have multiple legitimate simultaneous embodiments.
- One embodiment credential cannot be admitted concurrently in two bodies.
- Being root, `embodiment_id` and incarnation are distinct.
- Root, recovery and runtime signing custody remain purpose-separated.
- No new embodiment copies another embodiment's private keys, custody or
  writable databases.
- Canonical transfer is descriptor-stable, hash-exact, retry-safe and
  rollback-capable.
- Cluster fences resources; Matrix authorizes identity and semantic state.
- Bridge ACKs do not create Matrix intake or semantic receipts.
- Local tests are not represented as proof about physical hosts or real
  custodians.

## Human gates

- Native continuity/cutover, real custody distribution, physical target
  selection/execution, and cross-being participant consent and independent
  custody ([#40](https://github.com/AlterMundi/daimon-matrix/issues/40)) require
  their explicit scoped authorizations; operational consent is not protocol
  acceptance.
- Live Bridge removal requires a separately reviewed exact deletion inventory
  and matching GO; repository changes do not stop services or delete live state.
- Stable publication ([#44](https://github.com/AlterMundi/daimon-matrix/issues/44))
  requires independent exact-candidate approval and the release owner's GO.
- The later final Bridge source-only release and repository archive
  ([#73](https://github.com/AlterMundi/daimon-matrix/issues/73)) preserve public
  Git provenance and require their own exact preflights and owner GOs after
  native continuity and stable publication. Archive is not runtime deletion.

These authorizations are separate; none grants another by implication.
