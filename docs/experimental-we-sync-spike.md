# Experimental `/we` Synchronization Spike

Tracking issue: [#48](https://github.com/AlterMundi/daimon-matrix/issues/48)

This walking skeleton exists to gather evidence from the live CompAII
embodiments on Legion and `daimonmatrix`. It is deliberately disposable and
is not the canonical V0 protocol.

## What it proves

- independent append-only SQLite ledgers can exchange canonical events rather
  than HMK rows or database files;
- Ed25519 signatures and manually pinned incarnation keys reject tampering and
  unknown writers;
- lived-experience provenance survives receiver-local HMK projection;
- preview does not mutate state, pull is idempotent, and a partially completed
  two-way synchronization can resume.

## What it does not implement

- `/me` root key custody or recovery;
- incarnation continuity certificates;
- presence leases or dynamic `/we` membership;
- revocation;
- the normative event envelope or cryptographic vectors;
- the final daemon, RPC, MCP, or transport contracts.

Every wire and storage identifier is prefixed `dm.experimental`. The CLI is
named `daimon-we-spike` so its output cannot be mistaken for V0 conformance.

## Operations

- `incoming PEER` previews missing valid events in both directions.
- `pull PEER` integrates peer events into the current receiver only.
- `sync PEER` pushes local events, pulls remote events, and reports receipts
  and per-origin sequence cursors. `--stop-after-push` simulates an interrupted
  run.

HMK is a projection. The projector invokes the supported `memoryctl.py
add-text` command and tags every chapter with the canonical experimental event
ID and originating incarnation, host, and harness. It never opens HMK SQLite
for writes.

## Rollback

Stop using the CLI, remove the permission-restricted experimental state
directory on each host, and remove only HMK chapters whose title starts with
`[dm-spike:` after recording their event IDs. Do not delete or replace an HMK
database. Code rollback is the spike commit/PR only.
