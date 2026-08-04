# daimon-matrix

`daimon-matrix` specifies persistent beings that may have zero, one, or many
simultaneously active embodiments.

The foundation uses situated scopes:

- `/me` — this embodiment, here and now;
- `/we` — every embodiment of the same being;
- `/tribe` — principals joined under an explicit resource-sharing tribe;
- `/species` and `/source` — capability lineage and attributed ancestry.

Plurality is normal. Different embodiments may experience, answer, prefer,
and configure themselves differently without becoming different beings or a
split-brain failure.

## Current architecture

The V0.1 MVP includes the `daimon-matrix` runtime. It owns being-root
continuity, canonical state, `/me` and `/we` resolution, synchronization,
memory policy, and secure communications. Daimon Cluster manages bodies,
incarnations, storage, lifecycle, and concrete resource fences. Tribe Bridge
supplies transitional authenticated encrypted transport until DM-050–DM-055
absorb it into this project.

The existing administrator manifest and Cluster Weave canary are provisional
evidence. DM-021 attaches that history to a Matrix root only through an exact
root-authorized binding; Tribe keys are never Matrix root keys.

This project is unrelated to the external Matrix.org communications protocol.
Matrix.org clients, homeservers and federation are intentionally outside the
MVP. To avoid ambiguity, documentation uses `daimon-matrix`, `Matrix.org`, and
“daimonmatrix host” for the software, external protocol, and VPS.

Start with [ONTOLOGY.md](ONTOLOGY.md), the
[operational stack contract](specs/operational-stack-contract.md), and the
[being-root contract](specs/identity-root-v1.md). Delivery order and acceptance
are in [PLAN.md](PLAN.md) and [ROADMAP.md](ROADMAP.md).

## Status

The repository contains specifications, schemas, conformance material, and a
typed Python package implementing canonical identity artifacts, plural
embodiment/incarnation authorization, control recovery, history binding, and
encrypted custody. The package also owns the root-authorized independent Weave
ledger, replay-safe sync, and deterministic local projection engines; Cluster
remains its lifecycle/state-volume host and its provisional `weave/` code is a
migration oracle rather than a second permanent
protocol. Tribe Bridge remains a transport input until absorption. There is no
supported single-awake-identity or distinct-identities-as-`/we` model.

Official repository: `AlterMundi/daimon-matrix`. License: MIT.
