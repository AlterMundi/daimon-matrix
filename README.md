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
DM-010 is reopened to encode the corrected `/we` → distinct `/me` identities →
one body per identity hierarchy; DM-011 and DM-012 are held for adaptation.
The reviewed pre-Daimon HMK, Wiki, compaii-state, and Tribe v1 stack is the
reversible transitional runtime used while this implementation is built; it is
not itself the Daimon Matrix runtime. Tribe v0 is retired.

## Canonical documents

- [PLAN.md](PLAN.md) — V0 architecture, delivery plan, and acceptance criteria.
- [ONTOLOGY.md](ONTOLOGY.md) — normative namespace and identity model.
- [Identity continuity specification](specs/identity-continuity.md) — normative
  V0 `/me` roots, operational credentials, recovery, and single-body presence
  evidence.
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

## Governance

- Official repository: `AlterMundi/daimon-matrix`
- GitHub Project: `daimon-matrix`
- Current milestone: `V0`
- License: MIT
- Working language: English
