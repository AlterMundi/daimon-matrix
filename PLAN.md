# Daimon Matrix delivery plan

## Product boundary

The V0.1 MVP is a coordinated `daimon-matrix` + Daimon Cluster release.
`daimon-matrix` owns the being root, canonical state, scopes, synchronization,
memory policy, and communication runtime. Cluster owns bodies, incarnations,
resource fences, storage, and lifecycle effects.

Tribe Bridge v1 is the transitional transport while DM-050 through DM-055
absorb its reusable secure-delivery behavior into `daimon-matrix`; it is not a
third permanent authority. Matrix.org is an unrelated external protocol and
is explicitly outside the MVP.

## Delivery sequence

1. Freeze ontology, lifecycle identifiers, the being manifest, `dm.we.v1`,
   Tribe membership, and resource-fence semantics.
2. Publish shared schemas and positive/negative conformance vectors.
3. Implement Matrix root custody, plural embodiment credentials, recovery,
   revocation, and explicit binding of provisional history (DM-021).
4. Implement the installed local Matrix narrow waist: canonical ledger,
   projections/cursors, authenticated daemon, CLI/MCP, and adversarial
   crash/rebuild invariants (DM-022 through DM-026).
5. Integrate personal-memory policy/projections and Codex/Hermes embodiment
   adapters without granting harnesses identity authority (DM-030 through
   DM-042). DM-030's evaluator/transactional executor and DM-031's
   resource-scoped curator coordination are implemented; DM-032 onward consume
   those frozen boundaries without an exclusive being-wide lease. DM-032
   through DM-042 now provide the worker, human-review, personal/publication
   adapters and locally validated Codex/Hermes embodiments; DM-036 remains
   integration-blocked only on its external collective-memory dependency.
6. Absorb Tribe Bridge's reusable implementation into Matrix: recipient
   encryption, typed messages, cursors, routes, and `/me`/`/we`/`/tribe`
   resolution; then remove the standalone runtime dependency (DM-050 through
   DM-055). DM-055's native encrypted peer implementation is complete behind
   bundle V3; its authorized two-host cutover remains an operational gate.
7. Complete birth/species/source behavior and their synthetic acceptance
   journeys. DM-060, DM-061 and DM-081 now implement those isolated journeys;
   DM-082 relationship grants precede the DM-071 external source canary.
8. Bind Matrix embodiment evidence to Cluster lifecycle and resource fences;
   retain the reconciled effect-truth guarantees (DM-037). The installed host
   adapter and DM-080 evaluation-time binding are merged; real Incus/rebirth is
   still completion evidence rather than inferred from the synthetic adapter.
9. Run local, cross-host, recovery, revocation, and rebirth journeys with real
   processes, cryptography, encrypted state, transport, Cluster bodies, and
   separately authorized synthetic/live evidence.
10. Freeze, audit, publish, and independently reinstall the V0.1 release.

## Release invariants

- Multiple embodiments of one being can be awake.
- Every event and response retains origin.
- Preview is read-only; pull is idempotent; pull does not adopt.
- Decisions are local and reversible through successor events.
- Secret values never enter synchronized bytes.
- High-impact projections require a human confirmation.
- Resource fences reject stale writers only for the exact resource.
- No shared writable database is copied between embodiments.
- Matrix.org is not installed, contacted, or required.
- A fresh host can receive a new root-authorized embodiment credential and
  recover accepted history without copying another embodiment's private key.

## Completion evidence

Completion requires green conformance, installed-process, fault-injection and
cross-repository suites; removal of the standalone Tribe runtime dependency;
and real multi-host runs proving simultaneous embodiments, rebirth/recovery,
paginated sync, navigable differences, independent adoption, reversal,
fan-out, revocation, restart-resume, and resource-fence rejection. CI and
self-audit are the review gate; no recursive review ceremony is required.
