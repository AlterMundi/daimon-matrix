# DM-022 Daimon Cluster adaptation contract

Status: implemented downstream. `nicoechaniz/daimon-cluster#48` was closed by
PR #49, merged as `676495e852e6772a60de8221271ee9fc976f77ce`.

The reconciled historical Cluster `weave/` package proved the walking skeleton.
Its frozen fixture remains a compatibility oracle, but executable duplication
was removed. The installed `daimon-matrix` package owns canonical event
validation and SQLite behavior; Cluster hosts the exact pinned package.

## Implemented Cluster contract

1. Pin an exact reviewed `daimon-matrix` artifact and run its ledger/service
   under the embodiment's dedicated owner-only state directory. Do not vendor
   or fork `canonical.py`, `weave.py`, or `ledger.py`.
2. Resolve `body_ref`, `embodiment_id`, and the fresh `incarnation_id` from the
   Cluster lifecycle registry. Load the matching DM-021 credential and
   incarnation authorization through the Matrix custody/service boundary;
   Cluster never receives root/recovery seeds.
3. Replace `clusterd`'s direct imports from the provisional `weave/` package
   with a narrow hosted-service adapter. Status may expose bounded heads,
   cursors, incomplete counts and health; it must not expose payloads, keys,
   database paths or membership oracles.
4. Keep existing per-embodiment volume, quiesce, integrity, snapshot and restore
   behavior. A restored ledger must reopen with the exact active manifest and
   accepted historical-manifest set; metadata mismatch or downgrade fails
   closed.
5. Projection writes to concrete shared resources continue to require Cluster
   `resource-fence/v1` evidence and effect-truth verification. Matrix identity
   or ledger membership never substitutes for a fence.
6. Retain the old implementation read-only until its golden fixture, canary
   event set, heads and cursor evidence import into the Matrix engine without
   rewriting. Remove executable duplication only after that parity receipt.
7. DM-023 upgrades the hosted ledger schema additively from 1 to 2 with
   issued/outbound/inbound sync journals and a disposable projection cache.
   Snapshot/quiesce must preserve all canonical ledger and sync-journal tables;
   the projection cache may be rebuilt but must not be substituted for them.
8. DM-024 upgrades the ledger additively to schema 3 and installs
   `daimon-matrixd`. On the daimonmatrix host (the VPS) and every other host,
   Cluster creates/mounts one `0700` state root per embodiment, passes the
   keystore password through an inherited descriptor, waits for the ready
   descriptor, and supervises the process. It does not proxy a network port or
   parse the local HMAC protocol.
9. Cluster snapshots the public runtime bundle, encrypted custody and complete
   SQLite database together after quiesce. The `.daimon-matrixd.lock` and AF_UNIX
   socket are host-local runtime objects, never portable snapshot contents.
   Restore must let Matrix validate authority, custody high-water and ledger
   metadata before marking the embodiment healthy.
10. A physical restart that changes incarnation uses DM-079's signed
    `dm.runtime.bundle/v2` authority history. Reusing V1, replacing the ledger,
    or merely changing `local_origin` is a downgrade/substitution and fails.
11. DM-031 adds four separately capability-gated curator methods. Cluster's
    existing exact five-method host capability stays unchanged. A future
    projection host may opt into `resource-fence` claims only after pinning the
    reviewed DM-031 Matrix artifact and supplying current fence/effect observers
    through the explicit runtime injection boundary; queue CAS never substitutes
    for Cluster's cross-host fence.

## Required downstream tests

- start two Cluster-hosted Matrix ledgers with distinct DBs/keys and verified
  embodiment/incarnation evidence;
- restart one body through a signed authority epoch and prove a new incarnation
  chain without changing the embodiment or rewriting old events;
- import the reconciled canary fixture byte-identically, then continue under a
  root-bound manifest;
- quiesce/snapshot/restore and resume cursors without duplicate events;
- reject revoked/stale authorization, wrong body binding, manifest downgrade,
  unsafe state paths and stale resource fences;
- keep the live effect-truth tests from reconciliation commit `53a0f75` green.
- start the installed `daimon-matrixd`, prove descriptor-only unlock, owner-only
  socket and second-writer refusal, then quiesce/restart without changing an
  exact cached RPC response;
- ensure Cluster logs, status, snapshots, argv and environment contain no
  password, signing seed or local capability key.

The implementation pins Matrix
`73767504b777d0d0c9132a341959f486afce99f1`, including DM-080's exact body
evaluation time. Its installed two-process relocation/restart suite is the
downstream evidence for this contract. It does not by itself claim the final
real Incus multi-host rebirth drill.

Tribe transport integration is deliberately not part of this adaptation. It
will call the same Matrix sync API in DM-050–DM-055.
