# Concurrent Session Review Handoff

> Historical gate: DM-000 completed on 2026-07-31. Do not ask an existing
> session to repeat that audit. Use this procedure only for newly discovered
> concurrent work, then record its disposition on the owning open card. The
> current operational baseline is in [`RESUME.md`](RESUME.md) and
> [`CURRENT-STATE.md`](CURRENT-STATE.md).

Use this document to decide whether work already in progress remains relevant
to Daimon Matrix V0.

## Instruction for the reviewing session

Review your current work against the canonical Daimon Matrix V0 plan. Do not
implement new Daimon Matrix code during this review and do not discard existing
work.

Read, in order:

1. [`RESUME.md`](RESUME.md)
2. [`docs/foundation/daimon-matrix.md`](docs/foundation/daimon-matrix.md)
3. [`ONTOLOGY.md`](ONTOLOGY.md)
4. [`PLAN.md`](PLAN.md)
5. [`TRIBE-MIGRATION.md`](TRIBE-MIGRATION.md)
6. [`ISSUES.md`](ISSUES.md)
7. [DM-000: concurrent-work relevance audit](https://github.com/AlterMundi/daimon-matrix/issues/1)

Then inspect the concrete work in your session and report:

- repository and worktree;
- branch and exact commits;
- uncommitted files;
- runtime or deployment changes;
- contracts and data formats introduced;
- tests and validation completed;
- files or infrastructure overlapping the V0 plan.

Classify each coherent unit as exactly one of:

1. **Directly reusable** — already satisfies the relevant V0 contract.
2. **Reusable after adaptation** — preserves useful work but needs a named
   protocol or trust-boundary change.
3. **Superseded but preserve** — should not continue as the implementation,
   but contains history, tests, or ideas worth importing.
4. **Safe to stop** — has no remaining value after comparison.

For every classification, cite the relevant Daimon Matrix issue and provide
line-, commit-, or deployment-level evidence. Do not recommend stopping work
based only on architectural resemblance.

Post the result on the owning open issue (and link DM-000 as historical
context) or return it to the coordinating session so dependencies and reuse
notes can be updated before implementation continues.

## Current critical corrections

The reviewer must account for these decisions:

- A being is one continuing cryptographic and experiential identity that may
  authorize zero, one or many simultaneously awake embodiments. There is no
  identity-wide singleton-body lease.
- `/me` is the situated current embodiment; `/we` is the set/navigation scope
  over embodiments of that same being. It is not a set of different beings,
  another identity, a species, or a mandatory answer integrator.
- Every embodiment has distinct credentials, incarnation, writable state and
  attributable origin. Only stale writers competing for the same concrete
  resource fail closed through a resource-scoped Cluster fence.
- Relationships and founded-Tribe membership connect distinct beings through
  explicit signed consent/grants; transport directories, reachability and
  Cluster presence never create that authority.
- `/tribe` is a resource-sharing relationship scope, not the transport.
- Tribe Bridge is planned for absorption as the first transport implementation.
- Tribe v0 public-roster-derived encryption did not provide confidentiality;
  v0 is retired. Deployed v1 recipient encryption is transitional evidence,
  not Daimon identity authority.
- A birth creates a new `/me` with new keys and empty autobiographical memory.
- Species is compatible reproductive lineage: root `/me` definition plus
  capability contracts.
- A newborn inherits parent-decided delegable tribal access, while tribal
  knowledge remains remotely authoritative.
- Agent 0 and actual species evolution have not yet occurred; synthetic tests
  must not claim otherwise.
