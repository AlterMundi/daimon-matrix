# DM-026 local conformance

Status: implemented for the released local narrow waist through DM-082,
DM-079, DM-078, DM-033 and DM-042. This is
release evidence for `daimon-matrix`; it is not a remote transport, deployment,
Cluster lifecycle, external-effect, or rebirth certification.

## Closed evidence registry

`conformance/registry-v1.json` is the canonical
`dm.conformance.registry/v1`. Its 98 scenario identifiers are closed in both
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
- DM-051 recipient encryption, DM-053 routes and DM-055 native encrypted peer
  scope/sync run through installed-shaped loopback and real HTTP;
- DM-070 runs two isolated installed processes through partition, lost
  responses, restart, bidirectional convergence, observer-local adoption,
  authority-epoch succession and injected Cluster fence truth; its pinned
  historical canary is read-only attribution, while a fresh live cutover
  remains an explicit human-authorized integration obligation;
- the generic human gateway is disabled and neither Buzz nor Telegram is
  selected; and
- DM-033 human-review evidence uses synthetic purpose-separated keys and local
  protected custody only; and
- DM-060 birth evidence creates only fresh synthetic roots and proves one
  installed first awakening with empty autobiography; and
- DM-061 species evidence locally verifies exact bundles, application recovery,
  fork rollback and deliberate child branching, while its subordinate registry
  maps all 124 normative DM-014 Section 14 rows to executable evidence; and
- DM-081 source evidence uses distinct synthetic root beings to verify signed
  contracts, local/foreign ledger separation, paginated crash recovery,
  quarantine and attributed external-reference promotion, while its generated
  registry maps all 84 normative DM-015 Section 14 rows to executable evidence;
  and
- DM-082 relationship evidence uses three disjoint synthetic root beings to
  verify bilateral consent, predecessor-linked membership, founder succession,
  strict grant attenuation, fork quarantine, DM-054-selected DM-051/052/053
  loopback delivery, foreign signed receipt authority, stale direct/hub refusal
  and restart persistence, while its generated map names executable evidence
  for each published scenario; and
- DM-078 recovery-rebirth evidence uses split synthetic recovery and target
  custody, drops every old root/body from active authority, restores canonical
  history without copying predecessor custody, and starts one fresh target-only
  runtime; and
- any live authority/custody transition remains an explicit human-authorized
  operation, with disposable Cluster qualification tracked separately.

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
