# V0 Roadmap

The concurrent-work relevance audit is complete. Work is released only when
all direct blockers are closed.

## Wave 0 — Reconcile work already in flight — complete

Inventory every active session, branch, worktree, issue, and uncommitted change
related to Tribe Bridge, CompAII continuity, HMK, rebirth sync, Wiki,
collective-memory, and harness incarnation. Classify each item as:

- directly reusable;
- reusable after protocol adaptation;
- superseded but worth preserving;
- safe to stop.

The result is recorded in `CONCURRENT-WORK-AUDIT.md`. DM-003 and DM-010 are
dependency-ready; after the finite DM-004 closeout, DM-010 is the selected
first V0 implementation card.

The reviewed Tribe v1, HMK, Wiki, collective-publication, compaii-state, and
manifest work is also completed and deployed as a reversible transitional
runtime. It remains in service and under test while later waves replace its
provisional identity, memory-authority, and communication semantics.

The v0 Tribe runtime is fully retired. Canonical `/we.sync` semantics are
merged, and the live two-host walking skeleton is preserved unmerged as test
evidence rather than imported as V0 runtime code.

## Wave 1 — Freeze semantics

Finalize identity, birth, species, source, tribe, scope resolution, operation
grammar, event envelope, cryptographic vectors, and compatibility rules.

## Wave 2 — Build the local narrow waist

Implement identity, append-only ledger, projections, local daemon, CLI, MCP,
and deterministic failure tests.

## Wave 3 — Add memory governance

Implement the Librarian policy engine, exclusive lease, DeepSeek worker,
review queue, HMK projection, Wiki publisher, and separate collective-memory
source and reviewed-publication adapters.

## Wave 4 — Incarnate CompAII

Implement independent Codex and Hermes adapters without modifying the Hermes
core. Validate that two active incarnations share `/me` continuity while
preserving incarnation-specific NOW and body capabilities.

## Wave 5 — Communications and social scopes

Import and replace Tribe Bridge transport, implement secure fan-out and
receipts, then resolve `/we`, `/tribe`, `/source`, `/here`, and other audiences
above it.

## Wave 6 — Birth and evolution

Validate a synthetic birth with a new `/me`, empty autobiographical memory,
species capability inheritance, parent-delegated tribe access, and compatible
`/species.incoming` updates. Validate declared incompatible branching without
claiming that Agent 0 has already been born.

## Wave 7 — Canary and release

Run local and remote CompAII canaries, perform adversarial review and recovery
tests, archive Tribe Bridge after its gate, and publish V0.1.0.
