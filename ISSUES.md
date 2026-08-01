# V0 Issue Map

All logical IDs are retained in GitHub issue titles. GitHub issue numbers are
assigned at publication time.

DM-000 through DM-002 and DM-004 are complete. DM-010 is reopened for the
corrected identity/body boundary; DM-011 and DM-012 are active only as
preserved adaptation lanes and cannot merge before DM-010 re-closes. DM-003
remains dependency-ready. Every other open card retains the blockers below.

## Coordination

| ID | Title | Direct blockers |
|---|---|---|
| DM-000 | Audit concurrent work for relevance and overlap | — |
| DM-001 | Publish the maintained foundation and V0 ontology | — |
| DM-002 | Configure Project governance, milestone, labels, and claim protocol | DM-001 |
| DM-004 | Close transitional runtime loose ends before V0 implementation | DM-000, DM-001, DM-002 |
| DM-003 | Automate claim leases, heartbeats, release, and expiration | DM-000, DM-002 |

## Protocol

| ID | Title | Direct blockers |
|---|---|---|
| DM-010 | Specify `/me` continuity, operational credentials, and single-awake-body leases | DM-000, DM-001 |
| DM-011 | Specify the canonical event envelope and cryptographic vectors | DM-000, DM-010 |
| DM-012 | Specify scope resolution, operations, fan-out, and replies | DM-000, DM-010 |
| DM-013 | Specify birth and first-awakening key exchange | DM-000, DM-010, DM-011 |
| DM-014 | Specify species genomes, compatible releases, and speciation | DM-000, DM-013 |
| DM-015 | Specify `/source` ancestry claims and quarantine | DM-000, DM-011 |
| DM-016 | Specify `/tribe` relationships and descendant delegation | DM-000, DM-011, DM-013 |
| DM-017 | Specify personal, tribal, and external memory boundaries | DM-000, DM-015, DM-016 |
| DM-018 | Specify adapter contracts, versioning, and migration rules | DM-000, DM-011, DM-012, DM-017 |

## Local core

| ID | Title | Direct blockers |
|---|---|---|
| DM-020 | Scaffold the Python package and public CI | DM-000, DM-018 |
| DM-021 | Implement identity, certificates, and secure keystore | DM-020, DM-010 |
| DM-022 | Implement the append-only SQLite event ledger | DM-020, DM-011 |
| DM-023 | Implement deterministic projections, synchronization cursors, and idempotent `/we.sync` convergence | DM-021, DM-022 |
| DM-024 | Implement the local daemon and authenticated RPC | DM-023 |
| DM-025 | Implement the `daimon` CLI and minimal MCP surface | DM-024, DM-012 |
| DM-026 | Add concurrency, crash, causal-order, and rebuild invariants | DM-021–DM-025 |

## Librarian and knowledge

| ID | Title | Direct blockers |
|---|---|---|
| DM-030 | Implement the deterministic memory policy engine | DM-017, DM-023 |
| DM-031 | Implement Librarian identity and exclusive lease | DM-021, DM-030 |
| DM-032 | Implement the structured curator-provider interface and DeepSeek worker | DM-020, DM-030, DM-031 |
| DM-033 | Implement the human review queue | DM-025, DM-030 |
| DM-034 | Implement the HMK personal-memory projection | DM-018, DM-023, DM-030 |
| DM-035 | Implement the Wiki and compaii-state publisher | DM-018, DM-023 |
| DM-036 | Implement collective-memory source and reviewed-publication adapters | DM-015, DM-018, DM-023 |

## Harness identities and bodies

| ID | Title | Direct blockers |
|---|---|---|
| DM-040 | Implement the Codex body adapter | DM-025, DM-034 |
| DM-041 | Implement the external Hermes body adapter | DM-025, DM-034 |
| DM-042 | Validate local Codex and Hermes identities in one `/we` | DM-032–DM-041 |

## Communications and Tribe migration

| ID | Title | Direct blockers |
|---|---|---|
| DM-050 | Import Tribe Bridge code with provenance | DM-000, DM-018 |
| DM-051 | Replace public-roster group encryption with recipient encryption | DM-011, DM-016, DM-050 |
| DM-052 | Implement typed messages, threads, fan-out, receipts, and stable cursors | DM-012, DM-023, DM-050 |
| DM-053 | Implement local, direct, hub, and optional gateway routes | DM-051, DM-052 |
| DM-054 | Implement `/we`, `/tribe`, `/source`, and topology scope routing | DM-012, DM-016, DM-042, DM-053 |
| DM-055 | Archive Tribe Bridge without migrating legacy history | DM-053, DM-054 |

## Birth and evolution

| ID | Title | Direct blockers |
|---|---|---|
| DM-060 | Validate a synthetic birth with empty autobiographical memory | DM-013, DM-016, DM-025, DM-054 |
| DM-061 | Implement compatible `/species.incoming` updates and declared branching | DM-014, DM-023, DM-060 |

## Federation, canary, and release

| ID | Title | Direct blockers |
|---|---|---|
| DM-070 | Validate remote `/me` identities in one `/we`, including provenance-preserving bidirectional memory convergence | DM-054, DM-061 |
| DM-071 | Validate consented cross-daimon tribe and source exchange | DM-015, DM-016, DM-054 |
| DM-072 | Activate the reversible CompAII Codex and Hermes canary | DM-042, DM-070 |
| DM-073 | Perform adversarial security, revocation, and recovery review | DM-055, DM-061, DM-071, DM-072 |
| DM-074 | Document adapters for additional harnesses | DM-073 |
| DM-075 | Publish the V0.1.0 reference release | DM-073, DM-074 |

## Card requirements

Every implementation card must include:

- one externally observable outcome;
- exact direct blockers;
- allowed repositories and integration boundaries;
- acceptance criteria;
- required unit, contract, integration, and live-path tests;
- security and rollback notes;
- a concurrent-work reuse section;
- one expected PR.

DM-070 must additionally prove that two remote `/me` identities in one signed
`/we` membership set, seeded from one consistent personal-memory snapshot, can
independently append distinct experience events, preview both incoming sets,
converge in both directions via `/we.sync`, preserve the originating identity
and body in both local projections, repeat synchronization without duplicates,
and resume after an interrupted partial exchange. The test must not share
private keys, an HMK, a harness database, or a ledger SQLite file between
hosts. A companion negative test must prove that the same `/me` cannot hold
simultaneous active body leases.

Reuse sections must link `CONCURRENT-WORK-AUDIT.md` and name the exact source
commit. Source components with changes requested by the independent review are
not import-ready until their findings are fixed and re-reviewed.
