# Project resume checkpoint

Status: autonomous V0 completion is active. The operator authorized reversible
local and SSH work on the named systems on 2026-08-10. The same-being DM-083
dogfood reached real succession and exposed one safe, non-duplicating exact
retry failure. The current batch repairs that defect, repins Cluster and must
redeploy the exact candidate before moving to the cross-being/fresh-host gates.

Last reconciled: 2026-08-10.

## Proven checkpoint

- Matrix candidate `bcf6b9f6ef5a46fdd35dfc8036a7a4d458103c7b` and Cluster
  merge `0a4bd1e5769874b4d91f476b1c1942db51ce0f97` ran on Legion and
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
- The current Matrix candidate fixes that exact historical-retry seam with
  authority-history verification plus bounded client config V2. Focused tests,
  typing and generators pass. Exact live redeployment is still required before
  this repair becomes operational evidence.

## Repositories and authority

| Repository | Recorded state | Role and resume warning |
|---|---|---|
| `AlterMundi/daimon-matrix` | draft PR #112 branch at `bcf6b9f`; successor-retry repair in the working tree | Canonical identity, ledgers, scopes, relationship/grant authority, communication semantics and peer runtime. Freeze a new exact candidate after the repair gate. PR #112 still requires independent review. |
| `nicoechaniz/daimon-cluster` | `main` at `0a4bd1e`; deployed exact Matrix pin `bcf6b9f` | Hosts bodies/storage/lifecycle and resource fences. Its deployment/backup path is operationally corrected, but it must be repinned to the repaired Matrix candidate. Cluster never gains social, grant or canonical-ledger authority. |
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
2. Complete the successor-retry source gate, commit and push one immutable
   Matrix candidate, and wait for its full CI.
3. Repin Cluster from `bcf6b9f` to that exact candidate, run its clean installed
   cross-repository gate and merge only after CI.
4. Deploy the exact pair to the two authorized runtimes. Configure the retired
   Legion origin in client config V2, replay the preserved request and require
   its original response hash with no event-count change.
5. Append one harmless successor-lane event, synchronize both directions until
   heads converge, then take fresh checked snapshots/backups and update the
   redacted issue evidence.
6. Continue the V0 dependency path in Project 9: consented cross-being canary,
   fresh-host rebirth/recovery, native logical-message cutover, remaining
   adapter/security gates, release candidate and reference release.
7. Remove transitional compatibility and archive Tribe Bridge only after the
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
