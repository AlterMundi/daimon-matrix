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

Legacy administrator-manifest and Cluster Weave canary bytes remain provisional
history only. DM-021 attaches them to a Matrix root through an exact
root-authorized binding; Tribe keys are never Matrix root keys. The production
Cluster host path runs the pinned installed Matrix package and no longer ships
the provisional executable `weave/` implementation.

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
ledger, replay-safe sync, deterministic local projections, and the installed
`daimon-matrixd` owner-local runtime API. The installed `daimon` CLI and
modern-only `daimon-mcp` stdio adapter now consume that exact authenticated
boundary; neither has direct state or signing authority. The package now also
contains carrier-neutral recipient encryption and the same-ledger logical
message, per-recipient receipt, claim and cursor layer. It also contains
explicit-profile local IPC, authenticated HTTP and opaque hub providers with
durable carrier inboxes; all are disabled until configured and no live carrier
is deployed. DM-054 now provides exact `/me`, `/we`, `/we.diff`, per-origin
`/we.sync` plans, verified `/tribe` snapshots, and signed replay-safe partial
fan-out independent of any live carrier. Cluster remains its
lifecycle/state-volume host; frozen fixtures preserve the old canary as a
migration oracle rather than a second protocol. Tribe Bridge remains a
transport input until absorption. The installed `daimon-conformance` gate binds
the local implementation and reproducible artifacts to a closed 61-scenario
report; its route evidence is synthetic loopback and does not yet certify a
live remote delivery or rebirth. The merged Cluster adapter pins Matrix,
supervises one daemon per embodiment, preserves quiesced relocatable state and
provides exact body/effect evidence. DM-030 supplies the deterministic memory
policy, auditable decisions, fork-safe lanes and transactional exactly-once
executor through daemon/CLI/MCP; external memory projection remains later work.
DM-031 adds resource-scoped curator items, generation CAS claims, explicit
human-review proposals and effect-truth-aware resource-fenced completion. It
does not create a being-wide Librarian lease; different resources remain
independent and Cluster retains all shared-resource authority. DM-032 adds a
replaceable evidence-only curator-worker contract and fixed non-thinking
DeepSeek V4 Pro adapter: closed registration/profile/task/proposal artifacts,
durable retry/defer recovery and an installed owner-local one-shot process. Its
output always remains an inert proposal for DM-033 review; no live provider is
claimed ready without a protected synthetic smoke receipt. DM-033 adds the
purpose-limited human-review narrow waist: separate reviewer custody and
Ed25519 authorization, exact review requests, threshold accept/edit/reject/defer
decisions, authorization-before-disclosure queues, safe inert terminal output,
subject-side revalidation and idempotent execution receipts. MCP cannot decide
or execute, and all checked-in review evidence remains synthetic.
DM-071 consent/root discovery and live DM-055 carrier integration remain. There is no
supported single-awake-identity or distinct-identities-as-`/we` model.

Official repository: `AlterMundi/daimon-matrix`. License: MIT.
