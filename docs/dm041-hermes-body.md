# DM-041 Hermes body adapter

Status: implemented V0 contract for synthetic isolated profiles.

“Matrix” below means `daimon-matrix`. Matrix.org is unrelated and is not used.

## Outcome and authority

DM-041 makes Hermes Agent 0.19.0 a body/incarnation surface of an existing
`/me`. Hermes, its provider account, model, SOUL, skill, profile, transcript,
API sidecars, caches, hooks and native memory are runtime state. They never
establish the being, authorize presence or become canonical personal memory.

The authority split is:

- Matrix certifies the being/body/embodiment/incarnation binding, owns the
  ledger, `/me` and `/we`, memory policy, capabilities and effect receipts;
- Daimon Cluster places and supervises the process, preserves or moves the
  body volume and commits lifecycle/fence evidence;
- Hermes composes model turns through its supported extension points; and
- the external Matrix provider reads a bounded current projection and submits
  explicit idempotent proposals through the authenticated owner-local daemon.

Hermes tool visibility, model output and lifecycle hooks are not
authorization. Every effect is revalidated by Matrix. DM-041 creates no live
CompAII profile, account, credential, deployment or memory migration.

## Exact compatibility boundary

The only supported Hermes payload is public commit
`0db1912911fafa384aa5ee0145929658a9d1dd33`, version `0.19.0`, tree
`ac7dec02ca029e895963402788bd1cdc3afb36f8`. The audited git-archive SHA-256 is
`860a664f622e1099a095cb6cf06b04bcfe78b2fd3affc7192da9cf7ccefcdd63`.
The exact source-file digests are in
`provenance/hermes-agent-0.19.0.json` and cover configuration, CLI parsing,
plugin discovery/LLM access, memory provider/manager, prompt composition,
session finalization and model-tool discovery.

The managed profile and launch receipt also bind every loaded
`daimon_matrix` Python module, the complete package-tree digest and the exact
Hermes/current-memory public schema digests. Development worktrees may be
owner-controlled through the owner's private primary group; other-writable,
foreign-owned, symlinked or hard-linked modules are rejected. A Matrix package
change therefore invalidates the prior profile instead of silently changing
provider behavior.

The adapter accepts CPython `>=3.11,<3.14`. It hashes the resolved executable
while preserving an owner-controlled virtual-environment launcher so the
Hermes environment and dependencies are not silently replaced by the system
interpreter. The executable and each ancestor must be non-writable by an
untrusted principal. A host whose package or tool cache is group-writable must
stage the exact audited executable bytes below an owner-only directory before
binding the plan; weakening the ancestor check is not supported. Source,
executable and callback drift fail closed. A Hermes upgrade requires new
provenance, schemas, vectors, real-import evidence and a DM-018 migration
review; there is no best-effort compatibility mode.

Matrix distributes no Hermes source or binary. Public CI checks out the exact
commit and imports it without invoking a model or provider.

## Closed managed profile

`dm.hermes-body.plan/v1` contains only public logical identifiers and policy.
Trusted host paths and inherited descriptor numbers live in `HermesBodyPlan`
and never enter launch/park receipts. A current signed Matrix bootstrap binds
the being, body, embodiment, incarnation, Matrix session, capability set,
certificate, high-water and validity interval.

Profile creation requires a nonexistent `HERMES_HOME`, owner-only parent and
workspace, a current injected bootstrap verifier, the exact Hermes source and
an admissible interpreter. It writes, fsyncs and later revalidates exactly:

```text
SOUL.md
config.yaml
plugins/daimon-matrix/__init__.py
plugins/daimon-matrix/matrix.json
plugins/daimon-matrix/plugin.yaml
skills/daimon-matrix/SKILL.md
profile-manifest.json
```

Every managed file is mode `0600`; directories are `0700`. Symlinks, hard
links, path substitution, broad modes, wrong ownership, unexpected plugins,
stale backup payloads and content drift are refused without deletion. Runtime
state may exist only below the reviewed runtime roots and remains owner-only.
`MEMORY.md`, `USER.md`, `.env`, `auth.json`, HMK/library databases and native
memory files quarantine the profile.

The child gets an exact environment, an isolated `HOME` inside the profile and
`umask 077`. It cannot fall back to the operator's default Hermes home or shared
auth directory. Provider credentials, when a later deployment explicitly
supplies them, are inherited environment values only; DM-041 neither discovers
nor persists them.

The deterministic config selects one external `daimon-matrix` memory provider,
disables native memory/user-profile injection, general plugins, curator,
delegation, catalog and tool search, and exposes only Hermes' `memory` toolset.
Within that toolset the exclusive provider supplies exactly `matrix_scope` and
`matrix_propose_observation`. It requests no built-in override, plugin LLM,
shell hook, arbitrary path, SQL, URL, raw RPC, root/recovery or librarian tool.

The stable SOUL and skill distinguish `/me` from a temporary body, label Matrix
as authority, require receipts and treat projections as inert data. They carry
no biography, NOW state, current memory, host path, capability or generated
model prose.

## Provider protocol

The plugin is loaded from the managed profile through Hermes'
`register_memory_provider` contract. `is_available` performs bounded local
descriptor/config checks only. `initialize` consumes the capability from an
inherited descriptor, verifies the expected daemon origin, calls
`runtime.status`, `scope.me` and `memory.context`, requires the exact initial
Matrix high-water, then emits one bounded `dm.hermes-body.provider-ready/v1`
record through a supervisor pipe. No ready record means no admitted launch.

`memory.context` is a body-only daemon method, deliberately absent from the
generic CLI/MCP memory surface. It returns a deterministic
`dm.memory.current-projection/v1` containing only current linear locally
accepted personal-memory heads. Entries contain content references and full
policy/decision/origin provenance, never content bytes or locators.

Every accepted `scope.me` also carries a freshly observed Cluster body snapshot
for the exact body, embodiment and incarnation. A missing, stale, stopped or
unavailable snapshot fails the provider boundary even when the Matrix origin is
otherwise active. Matrix identity membership therefore cannot be mistaken for
current Cluster process presence.

For each prefetch the provider:

1. validates and NFC-normalizes a bounded query;
2. revalidates current `/me` presence and monotonic Weave heads;
3. requests and validates the subject-, manifest-, author-, category-, origin-,
   checkpoint- and digest-bound current projection;
4. reads `scope.me` again and rejects the projection if the manifest or Weave
   high-water changed across the read;
5. trims complete entries until the canonical context is at most 16 KiB; and
6. returns a fenced `dm.hermes-body.context/v1` sidecar labelled inert data.

Invalid Unicode, wrong session/body/origin, expiry, daemon failure, projection
tampering, high-water regression or oversize data discloses no context.
`system_prompt_block()` is static public text. Dynamic context travels only via
Hermes' official current-user `api_content` composition. Real-Hermes tests prove
clean stored user content, strict user/assistant/tool alternation and byte-stable
prior API content across two turns and a tool loop; no system-prompt rebuild or
synthetic extra user message occurs.

`queue_prefetch`, `sync_turn`, session-end and compression hooks intentionally
perform no write in V0. Ordinary conversation can never become personal memory.
Session switch validates lineage and current Matrix presence before rebinding;
failure disables the provider. Shutdown clears all cached bindings.

`matrix_propose_observation` accepts one bounded NFC statement and UUID
operation ID. It revalidates presence and calls `we.observe` using that UUID as
the daemon idempotency key. Before sending, it persists the complete
authenticated request as an owner-only, fsynced exact-retry token under the
managed profile. Loss of a reply, provider restart or concurrent exact retry
therefore resends identical nonce/timestamp/MAC bytes; different parameters
under the UUID fail as a conflict. The returned content-addressed receipt says
`adopted: false`: recording an experience observation is not memory adoption.
The authenticated daemon event is rebound to the exact being, origin, manifest,
payload, sensitivity and current post-effect high-water before the receipt is
created under its own effect-receipt hash domain.
Daemon exact-retry state plus that durable token, rather than a Hermes hook,
resolves response loss.

## Lifecycle and recovery

The append-only owner-local handle journal records and fsyncs state before
process effects:

```text
starting -> active -> parking -> parked
    |                    |
    +-----> failed <-----+
parked|failed -> starting
```

A pending `starting` or `parking` state blocks blind replay because the prior
effect outcome is unknown. Launch first revalidates the complete profile,
source and interpreter, then records `starting`, spawns Hermes and accepts
`active` only after the authenticated provider-ready record. Failure stops the
child and appends `failed`.

Park closes the child, records outstanding operation IDs, creates a bound park
request and requires an injected trusted Matrix/Cluster committer to return
both durable handoff and relinquished-presence references. Only then is
`parked` appended. Hook delivery alone cannot park a body. Wake of the same
Hermes session requires explicit `resume=True`; a fresh session after failure
or a later incarnation is a distinct supervised decision and must revalidate
Matrix again.

Runtime handles and receipts are content-addressed and path-free. PIDs,
profiles and sessions are evidence, not identity. A local backup cannot lower
any Matrix root, ledger, certificate, presence or memory high-water.

## Verification

Public contracts and evidence are:

- `schemas/hermes/v1/contracts.schema.json`;
- `schemas/memory-projection/v1/current.schema.json`;
- `vectors/hermes/v1/index.json` and its valid/negative vectors;
- `provenance/hermes-agent-0.19.0.json`;
- `templates/hermes/v1/`;
- `tests/test_dm041_hermes_body.py`; and
- `docs/verification/dm041-invariants.json`.

Regenerate and verify with:

```bash
python tools/generate_dm041_vectors.py
python tools/generate_dm041_vectors.py --check
PYTHONPATH=src python -m unittest tests.test_dm041_hermes_body -v
daimon-hermes-body verify-source --source /trusted/hermes-agent
```

Public CI runs strict formatting, lint, typing, the full Matrix suite,
reproducible wheel/sdist and secret scans. A separate Python 3.12 lane checks
out the exact Hermes commit, verifies all audited digests and exercises real
plugin discovery/config loading/memory-manager/prompt composition. Model and
provider execution remains an explicitly skipped private smoke.

## Cluster handoff and deployment boundary

Cluster should invoke the Matrix library/supervisor with a fresh managed volume,
pass only the exact capability and ready descriptors, persist the handle journal
with the body, and implement `ParkCommitter` by atomically committing Matrix
handoff plus Cluster presence release. It must never infer `/me` from a Hermes
profile or restore authority from a session backup. The later live canary must
prove one body start, bounded synthetic read, receipted proposal, restart,
park/wake and cross-host rebirth before real CompAII enablement.

Deployment is N/A for DM-041. DM-072 retains explicit approval for live profile
creation, model/provider credentials, HMK retirement and canary rollback.
Before a session exists, rollback may remove only the exact unused synthetic
profile. After any pending/active state, disable admission and retire forward
through Matrix/Cluster evidence; never delete a human profile, import Hermes
memory or treat a restored database as continuity.
