# DM-030 deterministic memory policy

DM-030 turns explicit canonical evidence into an auditable transition plan and,
only when the plan is still eligible at the same ledger state, one signed
`memory.recorded` event.

The normative contract is [the memory boundary](../specs/memory-boundaries.md).
Schemas are in `schemas/memory/v1/`, public vectors in `vectors/memory/v1/`, and
release scenarios in `conformance/registry-v1.json`.

## Operator flow

Prepare a closed policy and candidate as ordinary JSON files. Evaluation reads
the daemon's current ledger/projection checkpoint; callers cannot supply or
weaken that checkpoint.

```text
daimon ... --json memory evaluate \
  --policy policy.json \
  --candidate candidate.json
```

Keep the exact returned plan. Automatic execution accepts only `eligible`:

```text
daimon ... --json \
  --request-file private-requests/execute.json \
  memory execute \
  --policy policy.json \
  --candidate candidate.json \
  --plan plan.json
```

The request-file directory and file must be owner-only. If the connection is
lost, repeat the exact command. The stored request is authenticated again and
returns the first durable response. Do not regenerate or edit it.

`review-required` waits for DM-033. `deferred:incomplete` waits for the named
evidence. `quarantined` needs explicit conflict/fork handling. `rejected` is a
final result for those exact candidate bytes; remediation creates a successor
candidate, never edits the old one.

## Runtime contract

The authenticated local methods are:

```json
{"method":"memory.evaluate","params":{"candidate":{},"policy":{}}}
{"method":"memory.execute","params":{"candidate":{},"plan":{},"policy":{}}}
```

The same methods are exposed by `LocalClient.memory_evaluate()` and
`LocalClient.memory_execute()`. MCP names are `memory_evaluate` and
`memory_execute`. All surfaces are closed and capability-gated.

## What to inspect

For an evaluation, retain identifiers rather than private bytes:

- `policy_id`, `candidate_id`, `decision_id`, and `plan_id`;
- `predecessor_decision_id` for explicit reevaluation/correction history;
- outcome and stable reason codes;
- checkpoint ledger/projection hashes and lane state;
- event preview kind, subject, sensitivity and content reference.

For execution, verify the returned event carries the same policy, candidate and
decision IDs. `runtime.status` should remain `integrity: ok`. A stale error means
reevaluate from current evidence; retrying with changed bytes is not recovery.

## Local verification

```text
PYTHONPATH=src python -W error::ResourceWarning \
  -m unittest tests.test_dm030_memory_policy -v
python tools/generate_dm030_vectors.py --out /tmp/dm030-vectors
diff -ru vectors/memory/v1 /tmp/dm030-vectors
```

The full release gate additionally runs Ruff, strict mypy, all prior tests,
reproducible source/wheel builds, installed-wheel scenarios, conformance twice,
license checks and secret scans.

## Matrix, Cluster and Tribe

`daimon-matrix` decides and records. `daimon-cluster` hosts the owner-only state,
supplies body/resource observations and preserves the state volume across
relocation. Tribe transports exact signed artifacts. Neither Cluster nor Tribe
may manufacture a policy decision, rewrite category/author, execute a review
plan, or treat delivery as adoption.

The Cluster matrix-host adapter remains pinned to an exact Matrix commit and its
five-method host-control capability. Memory access belongs to a separately
issued least-authority client capability; DM-030 does not silently expand the
Cluster controller.
