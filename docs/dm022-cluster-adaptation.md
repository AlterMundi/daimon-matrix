# DM-022 Daimon Cluster adaptation contract

Status: required downstream work after the DM-022 Matrix ledger merges.
Tracked in `nicoechaniz/daimon-cluster#48` under hardening umbrella #46.

The reconciled Cluster `weave/` package at main `54a30fa` proved the walking
skeleton and remains the compatibility oracle. It is not a second permanent
ledger implementation. The installed `daimon-matrix` package owns canonical
event validation and SQLite ledger behavior; Cluster hosts it.

## Cluster changes

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

## Required downstream tests

- start two Cluster-hosted Matrix ledgers with distinct DBs/keys and verified
  embodiment/incarnation evidence;
- restart one body and prove a new incarnation chain without changing the
  embodiment or sharing its old private key;
- import the reconciled canary fixture byte-identically, then continue under a
  root-bound manifest;
- quiesce/snapshot/restore and resume cursors without duplicate events;
- reject revoked/stale authorization, wrong body binding, manifest downgrade,
  unsafe state paths and stale resource fences;
- keep the live effect-truth tests from reconciliation commit `53a0f75` green.

Tribe transport integration is deliberately not part of this adaptation. It
will call the same Matrix sync API in DM-050–DM-055.
