# Concurrent Work Relevance Audit

Status: complete for the work observed on 2026-07-31.

> Semantic correction, 2026-08-01: references below to several simultaneous
> CompAII principals as “incarnations of one `/me`” are historical audit
> language and are superseded. They are candidate distinct `/me` identities in
> one `/we`; each identity may have at most one awake body. The reuse evidence
> remains valid under that corrected boundary. Other uses of “incarnation” in
> credential, body-resource, or adaptation guidance below likewise map to
> operational credentials, identities, or bodies according to context and are
> not current normative terminology.

This audit is the evidence record for DM-000. It applies the classifications
defined in `REVIEW-HANDOFF.md` to the active Tribe Bridge, HMK,
collective-memory, compaii-state, Wiki, and CompAII deployment work.

## Decision summary

- Continue Daimon Matrix as the canonical architecture and repository.
- Absorb useful Tribe Bridge v1 behavior behind Daimon Matrix protocol and
  transport boundaries. Before that replacement exists, deploy and exercise
  Tribe v1 as the reversible transitional runtime.
- Treat the Daimon ledger as the authority for personal continuity. HMK, Wiki,
  collective-memory, and compaii-state remain projections, publishers, or
  attributed external sources according to artifact class.
- Preserve `mccompaii` as an intentional DaemonCraft/Minecraft body profile,
  but do not treat its bundled HMK database as a second `/me` authority.
- Do not migrate Tribe v0 messages or preserve v0 wire compatibility.
- Tribe v0 containment was temporary and is now superseded by complete v0
  retirement and the v1 production cutover.

## Repository and worktree inventory

All listed worktrees were clean at audit time. The pull requests were open
drafts under the shared `nicoechaniz` GitHub account and had no GitHub reviews
before the independent CompAII review described below.

| Repository and worktree | Branch / exact commit | Classification | V0 destination |
|---|---|---|---|
| `tribe-bridge`, `/home/nicolas/sandbox/tribe-bridge-issue-4` | `security/v0-containment-4` / `aa58a62d1fff70ae60efa9660e450557535b2382` (PR 13) | Reusable after adaptation | Temporary DM-050/DM-073 containment evidence only |
| `tribe-bridge`, `/home/nicolas/sandbox/tribe-bridge-issue-6` | `protocol/v1-spec-6` / `10a1d8bc535dfc1404174d2265f2a7a123329c62` (PR 14) | Reusable after adaptation | DM-011, DM-012, DM-016, DM-018, DM-050, DM-051 |
| `tribe-bridge`, `/home/nicolas/sandbox/tribe-bridge-issue-7` | `runtime/v1-broker-7` / `2516978416a1ec7383e45a3b55f4b5fc0fe1d356` (PR 15) | Reusable after adaptation | DM-022, DM-050, DM-052, DM-073 |
| `tribe-bridge`, `/home/nicolas/sandbox/tribe-bridge-issue-8` | `clients/v1-cutover-8` / `4ed63514b7d003624314957203672633ef57ecb3` (PR 16) | Reusable after adaptation | DM-050 through DM-053 |
| `tribe-bridge`, `/home/nicolas/sandbox/tribe-bridge-ci-fixture-18` | `ci/v1-http-fixture-18` / `1147cebd4fd6d788de107c9ed56e10d3d263a8f4` (PR 19) | Reusable after adaptation | DM-050 through DM-053 and DM-073 |
| Tribe v1 transitional production cutover | Reversible promotion from the v0 port while Daimon Matrix is implemented | Reusable after adaptation | Operate and test now; later replace its identity and semantic layers through DM-050 through DM-054 |
| `tribe-bridge`, `/home/nicolas/sandbox/tribe-bridge-issue-9` | `coordination/github-leases-9` / `7e1cd907abde69f111f45121ad2eaafbfad3e61d` (PR 17) | Reusable after adaptation | DM-003; retarget Project 8 to Project 9 and separate work ownership from `/tribe` |
| `tribe-bridge`, `/home/nicolas/sandbox/tribe-bridge-issue-12` | `architecture/daimon-manifest-12` / `c283821138e50abd82c95a74a6e684211cc93fe4` (PR 20 head; merged as `32294f2ede5556a81bac3f3dfa3cf578e28ab365`) | Reusable after adaptation | DM-010, DM-012, DM-018, DM-040, DM-041, DM-054 |
| `hermes-memory-kit`, `/home/nicolas/sandbox/hermes-memory-kit-issue-1` | `memory/canonical-contract-1` / `892998cfae639a0bcb7f43f06cbfc14aa945a7f9` (PR 2) | Reusable after adaptation | DM-017, DM-034, DM-035 |
| `hermes-memory-kit`, `/home/nicolas/sandbox/hermes-memory-kit-collective-3` | `memory/collective-publication-3` / `350c61a103d186fe82447dcfc39da45b699279bd` (PR 4) | Reusable after adaptation | Outbound publication half of DM-036 |
| `compaii-state`, `/home/nicolas/sandbox/compaii-state-issue-5` | `safety/stage-restore-5` / `87cbc7b32e65aa0e7c875db363f95ef9f3da62f9` (PR 1) | Reusable after adaptation | DM-018, DM-035, DM-073 |
| `compaii-state`, `/home/nicolas/sandbox/compaii-state-issue-2` | `memory/external-hmk-dependency-2` / `533e5478201dece985faf3ba730be515fff25d23` (PR 3) | Directly reusable | Keep one pinned external HMK implementation |
| `compaii-state`, `/home/nicolas/sandbox/compaii-state-daimon-4` | `identity/daimon-binding-4` / `0f762eab84fa29836051c4300c8f908608c15e52` (PR 5) | Reusable after adaptation | Use as a transitional provenance binding now; later recast it as a ledger projection/publication receipt rather than identity authority |
| `compaii-state`, `/home/nicolas/sandbox/compaii-state-wiki-gate-10` | `wiki/project-bootstrap-gate-10` / `43c43b63c14d5f622237bad2e37716af0a38d2d6` (PR 6) | Reusable after adaptation | DM-035 and DM-073 |
| `compaii-state/identity/profiles/mccompaii` | Intentional DaemonCraft/Minecraft profile | Reusable after adaptation | Body/incarnation state for DM-041/DM-042; bundled memory is not canonical personal continuity |

## Contracts worth importing

### Tribe v1

Retain the canonical JSON and negative parsing tests, Ed25519 signatures,
X25519/HPKE per-recipient content-key wrapping, governance-signed directory
snapshots, rotation/revocation tests, stable message IDs, replay protection,
delivery leases, signed acknowledgements, durable outbox, direct/hub fallback,
cross-route deduplication, mirror policy, backup, and integrity tests.

Adapt the contracts so that:

- sender and recipient identities reference `/me` and certified incarnation
  keys rather than independent `compaii` and `codex@localhost` beings;
- messages reference the canonical event envelope, logical thread, scope,
  operation, causal parents, and ledger event IDs;
- a transport acknowledgement is not a semantic receipt or memory integration;
- the governance directory consumes Daimon identity, relationship, grant, and
  presence projections instead of defining them independently.

### GitHub coordination

Retain append-only claim events, bounded leases, resource collision detection,
PR linkage, and recovery checks. GitHub remains the work-coordination plane,
orthogonal to `/tribe`. Retarget the implementation to
`AlterMundi/daimon-matrix` and Project 9. A future claim should bind the
GitHub-authenticated comment to `/me`, incarnation, and a detached incarnation
signature because the current shared GitHub account cannot distinguish agents
cryptographically.

### Manifests and selectors

Retain closed schemas, immutable evidence references, secret references,
concept maturity, and the rule that selection never grants authorization.
Replace the candidate subject `compaii@localhost` with separate `/me`,
incarnation, body, capability, presence, and release resources. The selector
must enforce task trust domains against each matched capability's
`trust_domains`, not only the manifest registry.

### Memory and publication

Retain HMK/Wiki artifact-class ownership, forbidden Wiki/projection overlap,
provenance, rebuildable indexes, snapshots, rollback, and idempotency. Add a
`daimon-personal-state` class whose authority is the ledger and whose HMK copy
is a rebuildable projection carrying source event IDs.

The collective-memory work is an outbound reviewed publisher. Retain its
policy, explicit consent, independent review, plan hashes, deterministic
artifacts, rollback, receipts, revocation, and tombstones. Before reuse, scan
the final rendered artifact rather than only the HMK raw body, expand
credential patterns, and prevent revocation from deleting an untracked target.
Inbound collective knowledge is a separate attributed source/quarantine
direction and must use the supported API or an atomic snapshot boundary.

### compaii-state and Wiki

Retain hash-pinned generations, staging, conflict checks, classified artifact
indexes, safe restore, and the single external HMK dependency. compaii-state
publishes or restores incarnation/body configuration; it does not anchor
`/me` identity.

Retain the Wiki gate's atomic file writes, source-path idempotency, taxonomy and
hash validation, HMK provenance edges, database snapshots, audit log, and
rollback. Invoke it from the deterministic DM-035 publisher queue and require
source event and release IDs. Receipts and rollback restores must become
transactionally reliable.

## Deployed state observed

The following supersedes the audit-time canary snapshot:

- Tribe v0 is fully retired on Legion and the hub. No v0 service or port is
  active, and v1 does not parse or negotiate downgrade traffic.
- `tribe-bridge-v1.service` is the transitional runtime. The signed directory
  is at epoch 3 with seven active principals; Legion serves the local/direct
  route and the hub serves the anyVPN-first store-and-forward route.
- `@localhost` principals are enforced as local-only at audience expansion and
  envelope encryption. They cannot address remote or mixed audiences, and a
  remote recipient receives no wrapped content key.
- Tribe repository commit `94d088eb91d3a5a2ae0ae069bad04252f52a7c11`
  contains the v0 retirement and client-side inbox-limit validation. The live
  broker reports build `e02568818000165cf4f299f7be95d534b42daebc`; the later
  commit is CLI-only and does not require a broker restart.
- Hermes integration commit
  `0db1912911fafa384aa5ee0145929658a9d1dd33` is deployed on Legion and
  `daimonmatrix`. Kimi K3 256k remains primary; cheaper DeepSeek auxiliaries
  handle title generation.
- The single operational HMK plugin is pinned to
  `96261b222647a453abe6b6842c9f1d5045d64c63`. Its status dispatcher succeeds
  on both hosts and remote doctor found no duplicate plugin source.
- The live two-host `/we` walking skeleton converged distinct signed events,
  resumed after interruption, preserved incarnation/host/harness provenance,
  projected idempotently into host-local HMK, and rejected tampering. Its code
  remains unmerged evidence; canonical semantics merged in PR 47.
- `eko@amapola` onboarding is prepared as directory epoch 4 but cannot be
  signed until the existing offline governance-root custody procedure is
  recovered. Roots must not be silently rotated as part of onboarding.

No deployed key, secret, database, message history, or private Wiki content is
an import candidate.

## Independent CompAII review

CompAII ran the relevant suites in clean worktrees and reported:

- HMK PR 2: approve, 89 tests passed; minor policy overlap and
  self-referential projection findings remain.
- HMK PR 4: changes requested, 101 tests passed; the final artifact is not
  fully credential-scanned and the reject-only token patterns are incomplete.
- compaii-state PR 3: approve, 20 tests passed, with the ordering gate that HMK
  PR 2 must be deployed first.
- compaii-state PR 5: approve, 27 tests passed; recheck binder/template hashes
  immediately before execution to close a TOCTOU window.
- compaii-state PR 6: approve; receipt publication and rollback atomicity have
  minor gaps.
- Tribe Bridge PR 20: changes requested; capability-level trust domains are
  ignored by selection, and a “reviewed” state commit is only proven to exist
  locally rather than on a reviewed remote ref.

These verdicts govern both transitional deployment and later source reuse.
“Approve” does not make the old repository or its authority model canonical,
and “changes requested” blocks merge or deployment of the affected component
until the named fix is verified.

## Plan corrections produced by the audit

1. No Tribe v0 messages, ciphertext, or client compatibility are migrated.
2. SQLite WAL is conditional on a runtime containing the WAL-reset corruption
   fix; otherwise the daemon uses `DELETE` with full durability or fails closed.
3. DM-036 explicitly covers separate collective-memory import and outbound
   reviewed publication contracts.
4. Personal memory authority moves from HMK to the ledger; non-Daimon
   HMK-native artifact classes may retain their existing authority.
5. The production v1 transitional runtime is not DM-072 continuity until its
   distinct identities have independent `/me` roots, signed `/we` membership,
   and single-body presence evidence.
6. Tribe v0 is retired; rollback repairs v1 and never recreates v0.
7. Root-key custody, compromise, rotation, and recovery are protocol
   requirements before keystore implementation.

## Released next work

With DM-001 and DM-002 already complete, closing DM-000 releases only:

- DM-003, GitHub claim-lease automation adapted from Tribe Bridge PR 17;
- DM-010, `/me` continuity, operational certificate, and single-body presence
  specification adapted from the manifest work without inheriting its identity
  model.

Every other V0 card retains at least one unresolved direct blocker.

## Transitional runtime execution

The sequence above completed through the v1 cutover and two-host evidence
spike. The remaining finite closeout is tracked by DM-004. After it closes,
implementation starts with DM-010 while the transitional runtime stays active
and reversible. Its authority contracts are replaced incrementally; its
message history and experimental `/we` code are not migration inputs.
