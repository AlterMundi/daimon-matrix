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

The first operational release does not require a Matrix runtime. Daimon
Cluster manages bodies, incarnations, and resource fences; its isolated
`weave` module implements `/we` and `/we.sync`; Tribe Bridge supplies
authenticated encrypted transport. An identical administrator-installed
being manifest supplies provisional same-being membership.

Matrix remains the canonical specification and future cryptographic identity
layer. The provisional history can be attached to a future Matrix root only by
an explicit root-authorized binding. Tribe keys are never Matrix root keys.

Start with [ONTOLOGY.md](ONTOLOGY.md), the
[operational stack contract](specs/operational-stack-contract.md), and the
[`dm.we.v1` protocol](specs/weave-protocol.md). Delivery order and acceptance
are in [PLAN.md](PLAN.md) and [ROADMAP.md](ROADMAP.md).

## Status

The repository contains specifications, schemas, conformance material, and a
typed Python package scaffold. The operational runtime lives in
`daimon-cluster`; transport lives in `tribe-bridge`. There is no supported
single-awake-identity or distinct-identities-as-`/we` model.

Official repository: `AlterMundi/daimon-matrix`. License: MIT.
