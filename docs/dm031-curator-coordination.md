# DM-031 implementation record

DM-031 implements resource-scoped curator coordination on the frozen DM-030
memory-policy and DM-037 Cluster effect-truth boundaries.

## Observable result

- `src/daimon_matrix/curator.py` provides closed content-addressed item, claim
  and result artifacts plus a durable SQLite coordinator.
- Different resources claim concurrently. Same-item workers use a monotonic
  generation CAS; expiry/reclaim invalidates the previous worker.
- Claims/results retain body, embodiment, incarnation and principal. No global
  being or presence lease exists.
- `resource-fence` claims require current injected Cluster verification, and
  successful completions bind the exact actor, intent, fence and observed
  postcondition.
- External-effect receipts are reconciled again before every replay, including
  a cached DM-024 RPC success.
- Human-authority work can only become `review-required`, `deferred`, or
  `failed`; DM-031 exposes no human approval operation.
- Authenticated daemon, typed client, CLI and MCP expose only enqueue, claim,
  complete and inspect.
- Programmatic hosts inject current Cluster/effect observers through
  `load_runtime`; absent adapters make resource-fenced operations fail closed.

## Durable state

The operational tables live in each embodiment's existing owner-only Matrix
SQLite database. They are not canonical memory and must not be copied as a
shared writable database. Mutations and their inner exact-retry records commit
in one `BEGIN IMMEDIATE` transaction. The outer RPC journal then protects the
wire response; the inner journal covers a daemon failure between semantic
commit and response persistence.

## Evidence

- closed schemas: `schemas/curator/v1/`;
- deterministic vectors: `vectors/curator/v1/`;
- generator: `tools/generate_dm031_vectors.py`;
- core, concurrency, fence, replay, schema, vector and real-daemon tests:
  `tests/test_dm031_curator.py`;
- normative release scenarios: `curator_resource_cas`,
  `curator_review_actor`, `curator_effect_truth`, and
  `curator_installed_retry`.

All fixtures are synthetic. No personal memory, provider credential, live
endpoint, Matrix.org dependency, Cluster mutation, or production deployment is
included.

## Downstream use

DM-032 consumes queue items as a least-authority worker and returns immutable
proposal references. DM-033 performs separate cryptographic human review.
DM-034 through DM-036 use resource-fenced claims only when they perform a real
projection/publication effect and can supply a current observer. This contract
does not alter the already merged Cluster host adapter or its exact Matrix
version pin.
