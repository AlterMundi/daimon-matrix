# Project resume checkpoint

Status: autonomous V0 completion is active. The operator authorized reversible
local and SSH work on the named systems on 2026-08-10 and the final reboot on
2026-08-11. DM-083 same-being live dogfood is operationally accepted; its
host-qualified successor pair is exact Matrix runtime `915c56c` and Cluster
runtime `94d80ba`. The active dependency path is now consented cross-being
native delivery followed by fresh-host rebirth/recovery.

Last reconciled: 2026-08-11.

## Proven checkpoint

- Matrix runtime `915c56c8899fd53d683bd7c7c81c3465b600bed9` and Cluster
  runtime `94d80baca05f468287b7d2bf99c577350d654a36` run on Legion and
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
  converged both hosts; later bounded live-canary work left both views at nine
  known events and zero incomplete events. Portable
  restores, fresh encrypted backups and final service/integrity checks passed.
- Matrix bootstrap now emits a separate owner-only status client with a
  distinct key and exactly five read methods. Authenticated host status is
  configured and healthy without giving Cluster mutation authority.
- The final daimonmatrix reboot changed boot ID and recovered every enabled
  service and all three containers without intervention. Audit and idempotency
  hashes were byte-identical, the five known reconcile findings were unchanged,
  `clusterd` started once after its private-bridge preflight, and neither an
  `EADDRNOTAVAIL` bind failure nor a service restart occurred.
- Restic snapshot `89d801b1` passed repository verification and its encrypted
  repository mirror was pulled to Legion. The prior Cluster 4a release remains
  preserved as an explicit whole-pair rollback.

## Repositories and authority

| Repository | Recorded state | Role and resume warning |
|---|---|---|
| `AlterMundi/daimon-matrix` | draft PR #112; deployed runtime code `915c56c` | Canonical identity, ledgers, scopes, relationship/grant authority, communication semantics and peer runtime. DM-083 plus the host-status/reboot qualification passed; PR #112 still requires independent review. Documentation-only successors do not change the exact deployed runtime pin. |
| `nicoechaniz/daimon-cluster` | PR #77; deployed runtime code `94d80ba`, exact Matrix pin `915c56c` | Hosts bodies/storage/lifecycle and resource fences. CI, deployment, repeated whole-pair rollback, backup/mirror and cold reboot passed. Cluster never gains social, grant or canonical-ledger authority. Documentation-only successors do not change the installed runtime code. |
| `nicoechaniz/tribe-bridge` | PR #61 at runtime-repair code `ecb51d8`; deployed service build `d49bf22` | V1 remains the transitional deployed human-message carrier at directory epoch 5. Keep ACK/dedup evidence separate from Matrix intake and semantic receipts, then retire it only after the native live message and explicit migration/archive gates. |

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
2. Preserve `915c56c` as the exact deployed Matrix runtime candidate and
   `94d80ba` as its Cluster host pair; documentation-only successors do not
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
