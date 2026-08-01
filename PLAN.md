# Daimon Matrix V0 Plan

## Goal

Deliver the first reference implementation of the Daimon Matrix: a
harness-neutral continuity, memory, communication, birth, and evolution layer
that allows one daimon to inhabit multiple simultaneous bodies and later give
birth to distinct beings.

The V0 canary will embody CompAII in Codex and Hermes. The design must also
support future Claude Code, Grok, Kimi, Antigravity, physical, virtual, and
custom bodies without making any harness authoritative.

## Fixed decisions

- Official repository: `AlterMundi/daimon-matrix`.
- GitHub Project: `daimon-matrix`, owned by AlterMundi.
- Milestone: `V0`.
- Working language: English.
- License: MIT.
- Stack: Python 3.11+, SQLite, MCP, canonical signed JSON.
- The maintained HackMD note is the philosophical and semantic foundation.
- `/me`, not a harness or model, is the identity boundary.
- `/we` dynamically routes to active incarnations of `/me`.
- `/tribe` is a resource-sharing relationship scope.
- `/source` represents shared ancestry claims.
- `/species` represents compatible reproductive lineage, not current
  incarnation membership.
- Tribe Bridge becomes the first internal communications transport and its old
  repository is archived after migration.
- The canonical personal state is an append-only event ledger; HMK, Wiki,
  collective-memory, and harness state are projections or external sources.
- The CompAII Librarian uses `deepseek-v4-pro` through provider `deepseek`.
- The concurrent-work audit is recorded in `CONCURRENT-WORK-AUDIT.md`.
  Implementation follows the dependencies and released-card decisions there.
- The reviewed pre-Daimon stack is deployed as a reversible transitional
  runtime and remains operational while Daimon Matrix is implemented. Running
  it does not claim that `/me`, `/we`, the ledger, or DM-072 already exist.

## Architecture

### Identity and birth

Each daimon owns a stable `/me` identity root. Active bodies receive
revocable incarnation certificates and signed presence leases. A birth creates
a new `/me`, new keys, empty autobiographical memory, and a signed relationship
to its parent, source, species release, and inherited tribal grants.

The newborn generates and retains its own root key at first awakening.
The protocol must define root-key custody, offline recovery, rotation,
compromise, and irrecoverable-loss behavior before the keystore is implemented.

### Species and capability evolution

The species genome contains the root `/me` definition and capability
contracts, not personal identity or memory. Threshold maintainers publish
signed releases. Compatible releases may apply automatically through
`/species.incoming`.

Speciation requires an intentional signed branch and an incompatible release.
Agent 0 and its first real evolutionary branch remain future events; V0 tests
the mechanics with synthetic identities and must not claim that event has
already occurred.

### Dynamic scopes and operations

Scopes resolve audiences or resources independently from operations:

- identity and continuity: `/me`, `/we`;
- ancestry and evolution: `/source`, `/species`;
- relationships: `/human`, `/tribe`, `/everyone`;
- topology: `/here`, `/near`, `/all`, `/realm`;
- machine interfaces: `/perceptors`, `/actuators`, `/integrators`.

Operations include `.tell`, `.diff`, `.incoming`, `.pull`, `.sync`, `.status`,
and `.controls`. V0 will define an extensible operation registry rather than
hard-coding every scope/operation pair.

`/we.tell` fans out to active leased incarnations. Recipients independently
attempt replies. Integration of replies is an optional local policy.

`/we.sync` coordinates resumable convergence among active incarnations of one
`/me`. It exchanges signed ledger heads or cursors, previews each receiver's
compatible incoming events, and causes each participant to pull the missing
events it accepts. It composes `/we.diff`, `/we.incoming`, and `/we.pull`; it
does not create an atomic distributed transaction. A partial run reports a
per-incarnation cursor and receipt so a later run can continue idempotently.

### State and memory

The local daemon is the single writer for an append-only SQLite ledger. WAL is
enabled only on a runtime containing the applicable WAL-reset corruption fix;
otherwise the daemon uses rollback journal `DELETE` with full durability or
fails closed. Events carry protocol version, ID, `/me`, originating
incarnation and embodiment, logical time, causal parents, type, payload, hash,
and signature. Synchronization exchanges canonical events, never private rows
from an HMK or harness implementation database.

Rebuildable projections include:

- identity and certificate state;
- incarnation presence and body capabilities;
- per-incarnation NOW;
- personal memory candidates and consolidated memory;
- relationships and capability grants;
- messages, threads, deliveries, and receipts;
- source and species releases;
- review and synchronization cursors.

The Librarian combines deterministic policy with a replaceable model worker.
The model produces schema-validated proposals; only the deterministic service
may append canonical decisions.

Raw lived-experience events remain immutable and retain their originating
incarnation and embodiment after synchronization. Consolidation is itself a
signed event that cites its evidence. It is distributed to every incarnation
like any other compatible event, so all deterministic projections converge
without erasing where an experience occurred.

Tribal knowledge remains remotely authoritative. A newborn inherits access and
full delegable tribal membership from its parent, but does not copy tribe
knowledge into `/me.memory`.

### Communications

The communications subsystem has separate layers for:

1. scope resolution;
2. logical message and thread identity;
3. fan-out and per-recipient receipts;
4. authorization and capability grants;
5. signing and per-recipient encryption;
6. local, direct, and hub routes;
7. optional human-facing gateways.

The current Tribe Bridge code is migrated as a starting implementation.
Legacy v0 encryption is replaced because its key is derivable from public
roster material. Draft Tribe v1 recipient encryption, signing, replay,
delivery, and recovery tests are adapted to Daimon identity and event
contracts rather than discarded or promoted unchanged.

GitHub Issues, pull requests, and the Project own work coordination. They are
not `/tribe` membership or message authorization. Claim principals eventually
bind `/me` and incarnation identity to the GitHub-authenticated event.

### Harness integration

Codex receives an isolated `CODEX_HOME`, stable AGENTS instructions, the
correct prompt hook, and MCP. Native Codex memory is disabled for the canary.

Hermes receives a standalone external plugin/skill and uses its existing
memory-provider extension point. No Daimon Matrix code is added to Hermes core,
and the adapter must preserve prompt-cache and message-alternation invariants.

Each harness keeps incarnation-specific runtime state while integrating
authorized personal continuity through `/we`.

## Public interfaces

### CLI

The `daimon` CLI will expose:

- `daimon identity`
- `daimon daemon`
- `daimon me`
- `daimon we`
- `daimon source`
- `daimon species`
- `daimon tribe`
- `daimon memory`
- `daimon review`
- `daimon sync`

### MCP

Keep the model-facing surface small:

- context and recall;
- observation;
- scope-aware communication;
- synchronization;
- review.

Identity, capability manifests, and protocol documents are MCP resources rather
than permanent tools.

### Local service

Use a permission-restricted Unix socket as the default local RPC transport and
an authenticated loopback endpoint as the documented portability fallback.

## Delivery phases

### 0. Concurrent-work audit and transitional runtime

Inventory every related active session and classify its work before any
implementation starts. Update issue dependencies and reuse notes with exact
branches, commits, and paths.

Fix the independent review findings, merge in dependency order, deploy the
transitional HMK/Wiki/compaii-state/Tribe v1 stack, and keep it reversible.
Use its production evidence while Daimon Matrix progressively replaces its
provisional authority and identity contracts.

### 1. Protocol freeze

Publish normative schemas, cryptographic vectors, identity and birth
semantics, scope resolution, operation registry, species compatibility,
delegated tribal grants, and migration rules.

### 2. Local narrow waist

Implement identity, ledger, projections, daemon, CLI, MCP, and invariant tests.

### 3. Librarian and projections

Implement policy, DeepSeek worker, human review, HMK, Wiki/compaii-state, and
separate collective-memory source and reviewed-publication adapters.

### 4. CompAII incarnations

Implement Codex and Hermes adapters and validate local convergence without
sharing implementation databases. Seed a new incarnation from a consistent
personal-memory snapshot, then synchronize subsequent canonical events rather
than copying live SQLite files.

### 5. Communications

Import Tribe Bridge, replace encryption, implement typed messages, cursors,
fan-out, receipts, and scope-aware routing.

### 6. Birth and species mechanics

Run synthetic birth, inherited tribe access, compatible species update, and
declared species-branch tests.

### 7. Canary and release

Run remote CompAII tests, adversarial review, recovery, Tribe Bridge archival,
and V0.1.0 release.

## Global acceptance criteria

- Codex and Hermes embody the same `/me` with separate incarnation keys.
- `/we` includes only active signed presence leases and routes one logical
  message without conflating replies.
- Two incarnations seeded from one consistent memory snapshot can each append
  a distinct lived-experience event, preview both directions with
  `/we.incoming`, converge through `/we.sync`, and retain the correct
  originating incarnation and embodiment in both projections.
- Repeating `/we.sync` after convergence is idempotent, creates no duplicate
  memories, and reports matching synchronization cursors. An interrupted run
  resumes to the same result without requiring shared implementation databases.
- The ledger reconstructs every projection deterministically.
- No model can write canonical state directly.
- A newborn starts a distinct life with no parent autobiographical memory.
- Compatible species releases preserve species identity; declared incompatible
  branches create a traceable new species.
- Parent-delegated tribe access uses fresh keys and attenuated grants.
- Tribal knowledge is not silently copied into personal memory.
- Direct and hub duplicates ingest once.
- Public roster material cannot decrypt confidential messages.
- Offline backlogs and same-second bursts do not lose messages.
- No secret or private CompAII memory appears in the public repository or CI.
- Every implementation issue is dependency-aware, independently claimable,
  and backed by a verifiable PR.
