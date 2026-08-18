# Roadmap

## RC closeout contract

The V0 Matrix baseline is merged. The nearest milestone is a reproducible,
cross-repository `0.1.0rc1` candidate proved entirely with clean local/CI and
disposable end-to-end evidence. No infrastructure is presumed active.

Completed software milestones: V7/V3-only Matrix, separated recovery holders,
shared Cluster admission/fencing, fresh-embodiment recovery, disposable
backup/restore/rebirth/rollback journeys, reproducible Matrix artifacts and a
non-executing content-addressed physical preflight.

The Matrix software boundary and reachable-Hermes package closeout are merged.
The merge containing this documentation handoff deliberately does not predict
its own commit or future Cluster/Tribe metadata heads. The cross-repository
successor sequence is accepted only when Cluster pins that actual Matrix merge,
Tribe records the resulting Cluster merge, and an external content-addressed
manifest independently verifies all three exact heads and clean artifact
installations.

The external manifest is the authoritative cross-repository checkpoint; another
Matrix metadata commit after downstream pinning would recreate the hash cycle.
Publication/cutover still requires its corresponding human authorization, and
Tribe retirement still requires native replacement evidence plus its separate
owner gate.

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
- Tribe ACKs do not create Matrix intake or semantic receipts.
- Local tests are not represented as proof about physical hosts or real
  custodians.

## Human gates

Real custody distribution, physical target selection, physical execution,
cross-being consent and custody, publication/cutover, and Tribe retirement are
outside autonomous qualification. Each needs explicit, scoped authorization.
