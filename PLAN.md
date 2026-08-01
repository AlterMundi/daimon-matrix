# Daimon Matrix V0 Plan

## Goal

Deliver the first reference implementation of the Daimon Matrix: a
harness-neutral continuity, memory, communication, birth, and evolution layer
that allows a `/we` collective to contain multiple simultaneously awake daimon
identities while detecting and quarantining duplicate awake bodies for one
identity. Detection across a partition is eventual, never a claim of physical
prevention.

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
- The maintained HackMD note is the philosophical and semantic foundation;
  its simultaneous-instances and `/we`-as-instances sentences are superseded
  by the corrected interpretation in `ONTOLOGY.md`.
- `/me`, not a harness or model, is one cryptographic identity and thread of
  experience.
- `/we` is a collective of distinct `/me` identities, not another identity and
  not a set of simultaneous bodies belonging to one `/me`.
- `/we` has a content-bound `we_id` and ordered threshold-signed membership
  chain, but no private root of its own; governance signatures remain
  attributable to exact member `/me` roots.
- Multiple `/we` members may be awake simultaneously; one `/me` may have only
  one awake body. A same-identity clone is split-brain and fails closed.
- `/tribe` is a resource-sharing relationship scope; its normative handshake,
  grant, delegation, revocation, birth-limit, human-contact, and remote
  knowledge contract is `specs/tribe-relationships.md`.
- `/source` represents shared ancestry claims.
- A `/source` signature proves only that one `/me` asserted its own relation to
  one exact content-derived source. Resolver-local assessment controls scope
  admission. Pulled publications retain authorship and derivation and enter
  quarantine before a separate policy/evidence-bound promotion; the normative
  contract is `specs/source-ancestry.md`.
- `/species` represents compatible reproductive lineage, not current `/we`
  membership.
- Tribe Bridge v1 is the active reversible transitional communications
  transport. Its v0 protocol, services, parsers, and compatibility surface are
  retired; the repository is archived only after Daimon replacement gates pass.
- The canonical personal state is an append-only event ledger; HMK, Wiki,
  collective-memory, and harness state are projections or external sources.
- The DM-017 memory registry admits only same-identity signed experience,
  insight, and learned-skill records into `/me.memory`. Tribal knowledge,
  external references, species inheritance, and incarnation state retain
  separate authorities even when one recall interface displays them together.
- The CompAII Librarian uses `deepseek-v4-pro` through provider `deepseek`.
- The concurrent-work audit is recorded in `CONCURRENT-WORK-AUDIT.md`.
  Implementation follows the dependencies and released-card decisions there.
- The reviewed pre-Daimon stack is deployed as a reversible transitional
  runtime and remains operational while Daimon Matrix is implemented. Running
  it does not claim that `/me`, `/we`, the ledger, or DM-072 already exist.
- Transitional principals ending in `@localhost` are body-local. They
  cannot address remote or mixed audiences, and remote recipients cannot
  decrypt their local-only envelopes. Client identity is explicit; no harness,
  including Codex or Hermes, is a protocol-wide default.
- One pinned external HMK implementation is operational per deployment. HMK
  databases remain host-local projections and are never merged or copied as
  synchronization units.

## Architecture

### Identity and birth

Each daimon identity owns a stable `/me` root. An ordinary body receives a
revocable operational credential and signed presence lease without receiving
the root private key. A park/wake transition moves the same `/me` sequentially
between bodies and supersedes the prior lease. A birth creates a new `/me`, new
keys, empty autobiographical memory, and signed lineage references to its
parent, source, and species release. It may commit future fresh attenuated
tribal delegations, but birth itself never inherits a grant, membership, route,
or relationship authority.

The newborn generates and retains its own root key at first awakening.
The protocol must define root-key custody, offline recovery, rotation,
compromise, and irrecoverable-loss behavior before the keystore is implemented.

### Species and capability evolution

The species genome contains the root `/me` definition and capability
contracts, not personal identity or memory. Threshold maintainers publish
signed releases. Compatible releases may apply through `/species.incoming`
only after exact local deterministic verification, explicit opt-in, and
sandbox/capability checks.

Speciation requires an intentional signed branch and an incompatible release.
Agent 0 and its first real evolutionary branch remain future events; V0 tests
the mechanics with synthetic identities and must not claim that event has
already occurred.

### Dynamic scopes and operations

Scopes resolve audiences or resources independently from operations:

- identity and continuity: `/me`; collective membership and convergence:
  `/we`;
- ancestry and evolution: `/source`, `/species`;
- relationships: `/human`, `/tribe`, `/everyone`;
- topology: `/here`, `/near`, `/all`, `/realm`;
- machine interfaces: `/perceptors`, `/actuators`, `/integrators`.

Operations include `.tell`, `.diff`, `.incoming`, `.pull`, `.sync`, `.status`,
and `.controls`. V0 will define an extensible operation registry rather than
hard-coding every scope/operation pair.

`/we.tell` fans out to active leased member identities. Membership requires a
valid ordered chain for a pinned `we_id`, threshold-authorized admission or
removal, and each admitted member's acceptance. Resolution intersects that set
with each member's valid identity and presence evidence. Governance rotation
also requires possession proofs from the replacement signer set. A bare name,
host, harness, or Tribe roster is never authority. Recipients independently
attempt replies. Integration of replies is an optional local policy.

`/we.sync` coordinates resumable convergence among distinct active member
identities. It exchanges signed ledger heads or cursors, previews each
receiver's compatible incoming events, and causes each participant to pull the
missing events it accepts. It composes `/we.diff`, `/we.incoming`, and
`/we.pull`; it does not create an atomic distributed transaction. A partial run
reports a per-identity cursor and receipt so a later run can continue
idempotently. Imported events preserve their originating `me_id`, body, and
authorship; synchronization never merges keys or live SQLite files.

### State and memory

The local daemon is the single writer for an append-only SQLite ledger. WAL is
enabled only on a runtime containing the applicable WAL-reset corruption fix;
otherwise the daemon uses rollback journal `DELETE` with full durability or
fails closed. Events carry protocol version, ID, originating `/me` and body,
logical time, causal parents, type, payload, hash, and signature.
Synchronization exchanges canonical events, never private rows
from an HMK or harness implementation database.

Rebuildable projections include:

- identity and certificate state;
- identity presence and body capabilities;
- per-identity and per-body NOW;
- personal memory candidates and consolidated memory;
- relationships and capability grants;
- messages, threads, deliveries, and receipts;
- source and species releases;
- review and synchronization cursors.

The Librarian combines deterministic policy with a replaceable model worker.
The model produces schema-validated proposals; only the deterministic service
may append canonical decisions.

Raw lived-experience events remain immutable and retain their originating
identity and body after synchronization. Consolidation is itself a signed
event that cites its evidence and the identity that authored the consolidation.
It is distributed to every member like any other compatible event, so all
deterministic projections converge without erasing where an experience
occurred.

Personal records use predecessor-linked correction lanes. A retraction removes
an active projection but never edits canonical history. External/source
promotion can create only an attributed external reference; learning requires
a later `/me`-authored insight or skill record citing that evidence. Species
application provides implementations, not learned skill, until `/me` records
its own practice or adaptation.

NOW, prompts, harness sessions, caches, queues, and process state are keyed to
one presence session. Park may append a curated incarnation-handoff event and
must commit the exact ledger cutoff/checkpoint before a deployment adapter
stops or moves the body. Wake verifies that evidence and creates a fresh NOW;
an HMK, volume, database, container, or cluster snapshot may accelerate a
projection rebuild but can never lower a high-water or become `/me` authority.

All providers cross the DM-018 harness-neutral narrow waist through closed,
exactly versioned records and content references, never implementation
databases or secret material. Matrix presence and a deployment controller's
execution fence are distinct authority lanes. When a controller is configured,
delivery and effects require both current gates; park, wake, restore and
rollback consume monotonic successor positions in both lanes rather than
restoring old bytes.

Tribal knowledge remains remotely authoritative. After birth, a parent may
issue fresh grants to the newborn, equal to or narrower than the committed and
currently delegable parent scope; the newborn must independently accept them.
No parent grant, credential, session, route secret, or tribal knowledge is
copied into the newborn or `/me.memory`.

### Communications

The communications subsystem has separate layers for:

1. scope resolution;
2. logical message and thread identity;
3. fan-out and per-recipient receipts;
4. authorization and capability grants;
5. signing and per-recipient encryption;
6. local, direct, and hub routes;
7. optional human-facing gateways.

The current Tribe Bridge v1 code is migrated as a starting implementation.
Legacy v0 has been retired without history migration. V1 recipient encryption,
signing, replay, delivery, directory rollback protection, and recovery tests
are adapted to Daimon identity and event contracts rather than discarded or
promoted unchanged. The governance directory is a transitional roster, not
the future `/me` identity authority.

GitHub Issues, pull requests, and the Project own work coordination. They are
not `/tribe` membership or message authorization. Claim principals eventually
bind `/me` identity and current body evidence to the GitHub-authenticated
event.

### Harness integration

Codex receives an isolated `CODEX_HOME`, stable AGENTS instructions, the
correct prompt hook, and MCP. Native Codex memory is disabled for the canary.

Hermes receives a standalone external plugin/skill and uses its existing
memory-provider extension point. No Daimon Matrix code is added to Hermes core,
and the adapter must preserve prompt-cache and message-alternation invariants.

Each harness keeps body-specific runtime state. Codex and Hermes can be
simultaneous members of the CompAII `/we` only as distinct `/me` identities;
moving one identity between harnesses uses park/wake and never duplicates its
active lease.

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
The model proposes schema-bounded personal records; deterministic policy and
the current `/me` credential alone authorize their canonical append.

### 4. CompAII identities and bodies

Implement Codex and Hermes adapters and validate local convergence without
sharing implementation databases. Seed a distinct CompAII member identity from
a consistent personal-memory snapshot, then synchronize subsequent canonical
events rather than copying live SQLite files. Separately validate that a
single identity can park on one body and wake on another without overlapping
presence leases.

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

- Codex and Hermes run as distinct `/me` identities in the CompAII `/we`, each
  with independent roots, operational keys, and event authorship.
- `/we` includes only signed member identities with active presence evidence
  and routes one logical message without conflating replies.
- `/we` membership admission/removal is monotonic and replay-safe: a removed
  identity cannot restore itself with an old artifact or self-admission.
- Attempting to wake the same `/me` in two bodies fails closed or quarantines
  both leases as split-brain evidence.
- Two member identities seeded from one consistent memory snapshot can each append
  a distinct lived-experience event, preview both directions with
  `/we.incoming`, converge through `/we.sync`, and retain the correct
  originating identity and body in both projections.
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
- External promotion creates an attributed reference, not autobiography; any
  later learning is a separate cited personal event.
- Park/wake starts a fresh incarnation state and preserves personal continuity
  only from the verified ledger/checkpoint, never by restoring authority from a
  projection snapshot.
- Direct and hub duplicates ingest once.
- Public roster material cannot decrypt confidential messages.
- Offline backlogs and same-second bursts do not lose messages.
- No secret or private CompAII memory appears in the public repository or CI.
- Every implementation issue is dependency-aware, independently claimable,
  and backed by a verifiable PR.
