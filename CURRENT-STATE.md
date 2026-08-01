# Current pre-V0 state

Status date: 2026-08-01 (America/Argentina/Cordoba).

This document is the operational handoff between completed planning and V0
implementation. `PLAN.md`, `ONTOLOGY.md`, `TRIBE-MIGRATION.md`, and
`ISSUES.md` remain canonical for architecture and dependencies.

Project 9 contains 50 cards: 10 Done, 1 In Progress, and 39 Todo. The sole
in-progress card is the independent Eko Tribe onboarding card. DM-003, DM-013,
and DM-015 are dependency-ready. These counts replace the original 44-card
planning snapshot.

## Completed foundation and evidence

- DM-000 through DM-004 and DM-010 through DM-012 are complete.
- The initial `/we.sync` refinement merged in PR 47; the closed canonical
  scope, reply, cursor, outcome, and receipt contracts merged with DM-012 in
  PR 53.
- The disposable two-host `/we.incoming`/`pull`/`sync` spike completed its live
  acceptance and is preserved at commits `8c3b92f` and `027b83d`. Its PR was
  closed without merge so manual key pinning, SSH transport, full-history
  exchange, and experimental storage do not become V0 runtime code.
- The spike findings are recorded on DM-011, DM-022, DM-023, DM-034, and
  DM-070.

## Transitional runtime

- Tribe Bridge v1 is active; v0 is fully retired. The live signed directory is
  epoch 3. `@localhost` principals and ciphertext stay on the local body,
  and clients select identity explicitly.
- Hermes commit `0db1912911fafa384aa5ee0145929658a9d1dd33` runs on Legion
  and `daimonmatrix`. Kimi K3 256k is primary; cheaper auxiliaries perform
  title generation.
- HMK commit `96261b222647a453abe6b6842c9f1d5045d64c63` is the one pinned
  operational plugin implementation. HMK databases are host-local projections.
- Tribe CLI limit validation merged in PR 29. Claude's independently reviewed
  commit `cb834f9` is equivalent evidence and must not be republished as a
  duplicate PR.

None of these components is `/me` authority or proof that DM-072 is complete.

## Finite closeout — complete

DM-004 closed on 2026-08-01. The focused compaii-state deployment receipt and
sync-safety change were integrated and the status baseline was published.
`eko@amapola` onboarding remains an independent Tribe Bridge card and does not
reopen or block the Daimon protocol lane.

The unsigned Eko directory candidate changes no live state and contains only
public keys. Root reprovisioning is not part of onboarding: if the existing
private governance root is irrecoverable, that is a separate explicit trust
reset and a concrete DM-010 recovery case.

The unrelated whole-tree compaii-state drift discovered during that receipt is
tracked separately by `nicoechaniz/compaii-state#9`; it is not silently folded
into DM-004 or DM-010.

## Explicit V0 ownership

- DM-010: `/me` root custody, loss, rotation, recovery, operational credentials, and
  single-awake-body presence leases. The current Tribe root-custody gap is a
  direct fixture.
- DM-003: signed per-agent GitHub claim attestations. A shared GitHub login does
  not prove which local agent acted.
- DM-012 and DM-054: signed `/we` membership among distinct `/me` identities
  and remote CompAII audience resolution. Static Tribe directory IDs are not
  the semantic scope.
- DM-023: stable deltas/cursors, bounded batches, crash-safe idempotent
  projection, and resumable convergence.
- DM-034: HMK projection by canonical event ID; never synchronize HMK rows or
  SQLite files.
- DM-036: separate attributed inbound collective-memory source and reviewed
  outbound publication adapters.
- DM-053 and DM-073: structured internal locality rejection without turning
  public errors into a membership oracle.

## Current protocol lane

The corrected hierarchy is merged: `/we` collective → distinct root-bearing
`/me` identities → at most one awake body per identity. DM-010 freezes
identity and presence, DM-011 freezes canonical artifacts and vectors, and
DM-012 freezes scope, reply, and `/we.sync` semantics. DM-013 (birth) and
DM-015 (source) are the next dependency-ready protocol cards. DM-003 remains a
separate dependency-ready coordination card; all proceed only through the
documented GitHub claim protocol.
