# Project resume checkpoint

Status: autonomous V0 completion is active. The operator authorized reversible
local and SSH work on the named systems on 2026-08-10. DM-083 same-being live
dogfood is operationally accepted at exact Matrix runtime `f0181f7` and Cluster
merge `5d3892e`. The active dependency path is now consented cross-being native
delivery followed by fresh-host rebirth/recovery.

Last reconciled: 2026-08-10.

## Proven checkpoint

- Matrix runtime `f0181f7117859f3f9cc4afc7dfbdaf9b06e74754` and Cluster
  merge `5d3892eaca1744e98874cab8d53be46e3eb186de` run on Legion and
  daimonmatrix as two embodiments of one fresh being. Native encrypted peer
  pull, pending intake, observer-local adoption/reversal, ordinary restart,
  ambiguous peer outage and separate Tribe v1 transport evidence succeeded.
- Portable snapshots restored with exact manifests. Encrypted restic backups
  were checked, mirrored off host and rerun through the corrected scheduled
  quiesce/resume path.
- A signed authority epoch advanced Legion to one successor incarnation while
  preserving accepted history on both hosts. Replaying an old exact request
  did not duplicate its event, but the daemon closed the reply because the
  service and client expected only the active server origin.
- The repaired V2 client returned the exact historical CLI output across the
  succession without duplicating the event. A successor-lane event then
  converged both hosts to six known events and one heads digest. Portable
  restores, fresh encrypted backups and final service/integrity checks passed.

## Repositories and authority

| Repository | Recorded state | Role and resume warning |
|---|---|---|
| `AlterMundi/daimon-matrix` | draft PR #112; tested/deployed runtime commit `f0181f7` | Canonical identity, ledgers, scopes, relationship/grant authority, communication semantics and peer runtime. DM-083 runtime acceptance passed; PR #112 still requires independent review. Later documentation commits do not change the exact deployed runtime pin. |
| `nicoechaniz/daimon-cluster` | `main` at `5d3892e`; deployed exact Matrix pin `f0181f7` | Hosts bodies/storage/lifecycle and resource fences. Deployment, whole-pair rollback and checked backup/restore passed. Cluster never gains social, grant or canonical-ledger authority. |
| `nicoechaniz/tribe-bridge` | `main` at `0a465bf`; environment repair branch at `ecb51d8` | V1 remains the transitional deployed human-message carrier. Keep ACK/dedup evidence separate from Matrix intake and semantic receipts, then retire it only after the native live message and migration gates. |

No repository named `tribe-chat` was found in the local project set or the
`nicoechaniz`/`AlterMundi` GitHub repositories at this checkpoint. If
“tribe-chat” means the current chat-facing Tribe runtime, its canonical source
is `nicoechaniz/tribe-bridge`; do not invent a fourth authority or migration
target without first recording the actual repository.

“Matrix” means `daimon-matrix`. Matrix.org remains excluded. “daimonmatrix
host” means the VPS, not a software component or being authority.

## Exact resume order

1. Read this file, `CURRENT-STATE.md`, `ROADMAP.md`, DM-083 issue #111, draft
   PR #112, `reviews/DM-083.md` and `docs/dm083-two-host-dogfood.md`.
2. Preserve `f0181f7` as the exact deployed DM-083 runtime candidate and
   `5d3892e` as its Cluster host pair; documentation-only successors do not
   silently move that pin.
3. Complete the Project 9 consented cross-being canary using Matrix's native
   authenticated intake and signed semantic receipt. Do not infer that result
   from the already-proven Tribe ACK lane.
4. Complete fresh-host rebirth/recovery with a new root-authorized embodiment
   credential, independent private custody and no copied writable database.
5. Complete remaining adapter, collective-memory and adversarial security
   gates, then freeze the exact release candidate and independently reinstall
   it.
6. Remove transitional compatibility and archive Tribe Bridge only after the
   native replacement and explicit migration gates prove it is unnecessary.

## Stop conditions

Do not proceed from preparation to live effects if roots/manifests differ,
custody or writable state is shared, the Matrix/Cluster commits are not exact,
a route is implicit, rollback is incomplete, a backup is unverified, or a
secret/private endpoint would enter public evidence. Transport reachability,
Tribe directory membership, Cluster registry state, successful decryption and
ACKs never create relationship, grant, `/we`, adoption or semantic-delivery
authority.

## Local minimum rerun

From an installed current Matrix artifact:

```bash
state_dir="$(mktemp -d /tmp/daimon-relationship-demo-XXXXXX)"
daimon-synthetic-relationships --state-root "$state_dir" | python -m json.tool
```

Success requires every reported invariant to be true. This command remains
local and uses disposable state plus loopback networking.
