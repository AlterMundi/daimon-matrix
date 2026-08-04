# Roadmap

## V0.1 MVP

- Canonical ontology and cross-runtime contracts.
- Being-root genesis, offline custody, recovery, rotation, revocation, and
  provisional-history binding.
- Plural embodiment credentials and per-start incarnation authorization.
- Installed Matrix ledger, daemon, CLI/MCP, deterministic projections, and
  crash/rebuild invariants.
- `dm.we.v1` schemas, vectors, and conformance runner.
- Cluster embodiment/incarnation registry and resource-scoped fences.
- Weave ledger, preview/pull, difference navigation, local decisions, and
  projection receipts.
- Live `/we` fan-out with origin-marked partial results.
- Founded Tribe membership and typed recipient-encrypted transport absorbed
  from Tribe Bridge.
- HMK and external-identity adapters.
- Codex/Hermes embodiment adapters.
- Dashboard, runbooks, provisional two-host evidence, and root-authorized
  rebirth/recovery evidence on a fresh host (DM-078).

## Component boundary

- `daimon-matrix` owns identity continuity, canonical state, scopes, memory
  policy, synchronization, and communication semantics/runtime.
- `daimon-cluster` owns body/container lifecycle, storage, deployment evidence,
  and resource-scoped exclusion.
- Tribe Bridge is a transitional source/runtime and is archived after
  DM-050–DM-055 replacement gates and the release handoff.
- DM-050 preserves a hash-pinned behavioral/provenance inventory only; source
  copying is prohibited unless a successor records explicit compatible
  authorization. DM-051–DM-053 implement the replacement independently.
- Matrix.org is not used by the MVP.

The provisional Cluster/Tribe canary is retained as prior evidence, not as a
reason to defer the Matrix runtime. Runtime authentication must not restore
single-body exclusion or turn `/we` into a set of different beings.
