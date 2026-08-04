# Implementation cards

The GitHub project is the live board. Every card names its owning repository,
public contract, invariants, dependencies, tests, and acceptance evidence.

## Matrix-owned

- Canonical ontology and cross-runtime authority map.
- Being-root custody/recovery, plural embodiment credentials, incarnation
  authorization, and binding of provisional history in the V0.1 MVP.
- `dm.we.v1` events, heads, deltas, decisions, projection receipts, and live
  request/response schemas.
- Installed per-embodiment Weave ledger engine, synchronization mechanics,
  decisions, projections, and communications service.
- Scope, memory, Tribe, and adapter conformance vectors. DM-030 memory policy,
  schemas, vectors, hosted methods and exactly-once executor are implemented;
  DM-031 through DM-036 own its actors and effects.
- Root-authorized additional-embodiment, relocation, and disaster-rebirth
  acceptance on a fresh host (DM-078).

## Cluster-owned

- Embodiment/incarnation registry integrated with lifecycle.
- Resource-scoped fences and effect-truth idempotency.
- Hosting the Matrix Weave process/state volume, backup/quiesce integration,
  lifecycle evidence, and resource-fenced projection effects. The pinned
  installed host adapter is merged; real Incus rebirth and hardened production
  supervision remain acceptance work.
- HMK and external-identity adapters.
- Dashboard, runbook, and two-host acceptance.

## Transitional Tribe-owned

- Typed encrypted Weave payloads.
- Founder-only invitation, acceptance, expulsion, leave, and founder transfer.
- Direct-principal routing and conformance fixtures.
- Explicit separation of audience, `tribe_ref`, and `being_ref`.

DM-050 through DM-055 move these responsibilities into `daimon-matrix` and
remove the standalone Tribe runtime dependency before release. Cluster's old
`weave/` behavior now survives only as frozen migration fixtures; the merged
host adapter runs the installed Matrix engine. Matrix.org is not an
implementation target or dependency.

Closed cards whose acceptance encoded identity-wide body exclusion must be
rewritten and reopened. Completion is evaluated only against current
contracts.
