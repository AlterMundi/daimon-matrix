# DM-026 local conformance

Status: implemented for the released local narrow waist through DM-054,
DM-079 and DM-033. This is
release evidence for `daimon-matrix`; it is not a remote transport, deployment,
Cluster lifecycle, external-effect, or rebirth certification.

## Closed evidence registry

`conformance/registry-v1.json` is the canonical
`dm.conformance.registry/v1`. Its 64 scenario identifiers are closed in both
directions: a missing scenario, an unknown scenario, duplicate identifier,
unknown field, unregistered evidence reference, or non-required release
scenario fails validation. Each scenario names its owner cards,
specifications, real stimulus/fault, expected invariant, exact unittest
evidence, cleanup boundary, platform and CI lane. The installed runner pins the
complete canonical registry SHA-256, so JSON alone cannot redirect execution;
any registry revision requires a deliberate suite/code version change.

The runner validates evidence paths statically before starting them, then runs
each distinct test in a separate interpreter. Loading the registry therefore
cannot import test modules, open databases, or initialize runtime state. Test
processes run from the registry's source root against the installed package.
The fixture seed deterministically orders that exact eligible evidence set and
the report publishes the order. Concurrency barriers, queue load and partition
steps remain inside their named real-I/O tests. Test stdout and stderr never
enter the public report. A stable diagnostic fingerprint records only the test
identifier and outcome.

The registry deliberately describes the implementation that exists:

- plurality is concurrent root-authorized embodiments, never a global awake
  lease;
- ordering is signed sequence/previous plus explicit causal parents, never an
  HLC or arrival-time winner;
- import makes content known but does not adopt it;
- “exactly once” means one canonical event, RPC response, or sync receipt; and
- DM-051 recipient encryption and DM-053 local/direct/hub behavior are
  synthetic loopback evidence; a live route rollout remains a later
  integration obligation;
- the generic human gateway is disabled and neither Buzz nor Telegram is
  selected; and
- DM-033 human-review evidence uses synthetic purpose-separated keys and local
  protected custody only; and
- live remote Cluster effects remain later integration obligations.

## Running the installed gate

Build the deterministic artifacts and install the wheel into a disposable
environment. From the repository root run:

```bash
daimon-conformance \
  --registry conformance/registry-v1.json \
  --source-commit "$(git rev-parse HEAD)" \
  --seed dm026-v1 \
  --output reports/dm026.json \
  --artifact wheel=dist/daimon_matrix-0.0.0-py3-none-any.whl \
  --artifact sdist=dist/daimon_matrix-0.0.0.tar.gz
```

The command uses only fixture-owned temporary roots and public artifacts. It
does not discover ambient identities, credentials, daemons, sockets, Cluster
volumes, routes, messages or user home state. The output file is atomically
created with mode `0600` and may replace only the exact explicit path.

CI runs the installed command twice in the same environment and requires the
canonical reports to be byte-identical. Python 3.11–3.14 continue to run the
full source test matrix; the complete installed conformance lane runs on Linux
with real AF_UNIX, subprocess, filesystem and SQLite boundaries.

## Report semantics

`dm.conformance.report/v1` separates measured environment facts from its
deterministic transcript. It binds the exact 40-hex source commit, registry
SHA-256, fixture seed, artifact SHA-256 values, schedule, evidence identifiers
and outcomes. It contains no raw logs, temporary paths, keys, message content,
environment variables or tracebacks.

Every scenario in the release registry is required. Any failure or platform
skip makes `release_ready` false and the command exits nonzero. Linux is the
release evidence platform because AF_UNIX process and custody scenarios are
required; another platform may inspect the partial transcript but cannot
produce a release-ready claim.

The JSON schemas are `schemas/conformance/v1/registry.schema.json` and
`schemas/conformance/v1/report.schema.json`. The static implementation index is
`docs/verification/dm026-invariants.json`; the runtime report is a CI artifact,
not committed synthetic state.
