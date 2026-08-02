# daimon-matrix

`daimon-matrix` is the reference implementation and protocol workspace for
portable, persistent, multi-identity AI collectives.

The project begins from the maintained
[Daimon Matrix foundation](https://hackmd.io/@nicoechaniz/daimon-matrix).
It separates one continuing identity (`/me`) and its current body from its
collective of distinct identities (`/we`), evolutionary lineage (`/species`
and `/source`), and resource-sharing relationships (`/tribe`).

## Status

V0 planning, the concurrent-work audit, and transitional closeout are complete.
DM-010 through DM-018 now freeze the corrected identity/body hierarchy,
canonical artifacts, scope/reply/sync semantics, birth, species evolution,
source ancestry/quarantine, tribe relationships, and memory boundaries.
DM-018 additionally freezes the harness-neutral provider narrow waist and the
separate Matrix-presence/deployment-fence profile used with body controllers.
DM-003 provides signed claim automation for the remaining implementation
cards.
DM-020 provides the behavior-free, typed Python package scaffold and its
reproducible build/inspection pipeline; it deliberately contains no protocol
or provider runtime yet.
The reviewed pre-Daimon HMK, Wiki, compaii-state, and Tribe v1 stack is the
reversible transitional runtime used while this implementation is built; it is
not itself the Daimon Matrix runtime. Tribe v0 is retired.

## Canonical documents

- [PLAN.md](PLAN.md) — V0 architecture, delivery plan, and acceptance criteria.
- [ONTOLOGY.md](ONTOLOGY.md) — normative namespace and identity model.
- [Identity continuity specification](specs/identity-continuity.md) — normative
  V0 `/me` roots, operational credentials, recovery, and single-body presence
  evidence.
- [Canonical artifacts specification](specs/canonical-artifacts.md) — normative
  V0 encodings, operational credentials, identity-wide park/wake receipts,
  signed events, causal order, checkpoints, and recipient encryption.
- [Scope resolution specification](specs/scope-resolution.md) — normative V0
  scopes, operations, fan-out, replies, and `/we.sync` convergence.
- [Birth and first-awakening specification](specs/birth-first-awakening.md) —
  normative V0 birth binding, custody, presence, and empty-memory boundary.
- [Species evolution specification](specs/species-evolution.md) — normative V0
  genomes, compatible releases, application, forks, and speciation.
- [Source ancestry specification](specs/source-ancestry.md) — normative V0
  self-claims, evidence, discovery, provenance, pull, and local quarantine.
- [Tribe relationships specification](specs/tribe-relationships.md) — normative
  V0 handshakes, resource grants, descendant attenuation, revocation, birth
  limits, and remote-knowledge boundaries.
- [Memory boundaries specification](specs/memory-boundaries.md) — normative V0
  personal, tribal, external, species, incarnation, projection, learning, and
  park/wake memory categories.
- [Adapter contracts specification](specs/adapter-contracts.md) — normative V0
  provider interfaces, exact version negotiation, migration receipts,
  Matrix–deployment exchanges, monotonic fences, and conformance fixtures.
- [TRIBE-MIGRATION.md](TRIBE-MIGRATION.md) — integration of Tribe Bridge.
- [ROADMAP.md](ROADMAP.md) — dependency-ordered implementation waves.
- [REVIEW-HANDOFF.md](REVIEW-HANDOFF.md) — instructions for evaluating work
  already active in another session.
- [CONCURRENT-WORK-AUDIT.md](CONCURRENT-WORK-AUDIT.md) — evidence, reuse
  classifications, deployed state, and released-card decisions.
- [CURRENT-STATE.md](CURRENT-STATE.md) — live pre-V0 baseline, resolved work,
  explicit deferrals, and the next card.
- [Foundation snapshot](docs/foundation/daimon-matrix.md) — preserved source;
  its simultaneous-instances and `/we`-as-instances sentences are superseded
  by the corrected interpretation in `ONTOLOGY.md`.
- [CONTRIBUTING.md](CONTRIBUTING.md) — claim leases and contribution workflow.
- [Signed GitHub coordination](docs/github-coordination.md) — session-attested
  claims, heartbeats, releases, expiry receipts, and recovery.
- [Package scaffold and reproducible builds](docs/packaging.md) — supported
  Python versions, dependency policy, artifact allowlists, verification, and
  installed-wheel smoke testing.
- [Dependency policy](DEPENDENCIES.md) — empty runtime requirements and bounded
  build/development tooling.

## Governance

- Official repository: `AlterMundi/daimon-matrix`
- GitHub Project: `daimon-matrix`
- Current milestone: `V0`
- License: MIT
- Working language: English
