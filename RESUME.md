# Project resume checkpoint

Status: intentionally paused after the local minimum functional slice. This
checkpoint records repository state only; it authorizes no host access,
deployment, service restart, route change, message, key operation, or Cluster
effect.

Last reconciled: 2026-08-06.

## Proven checkpoint

- `daimon-matrix` PR #113 / DM-082 is merged on `main` at `dad012d`. The
  installed synthetic journey covers two distinct beings and ledgers,
  bilateral consent, Tribe membership, a bounded grant, DM-054 resolution,
  DM-051/052 encrypted logical delivery through DM-053 loopback HTTP,
  authenticated intake, an independently signed semantic receipt, revocation,
  stale direct/hub refusal, restart, and exact replay.
- The DM-082 source suite passed 539 tests; the installed wheel suite passed
  420 tests. Two installed conformance runs were byte-identical and reported
  `release_ready: true`. The public implementation/self-audit is
  `reviews/DM-082.md`; the runnable entry point is documented in
  `docs/dm082-relationships.md`.
- DM-082 used disposable local state and loopback only. No real participant,
  account, host, Cluster resource, or live route was contacted or changed.

This is enough to iterate on the minimum protocol locally. It is not evidence
of a live CompAII rebirth or of an ordinary two-host user experience.

## Repositories and authority

| Repository | Recorded state | Role and resume warning |
|---|---|---|
| `AlterMundi/daimon-matrix` | `main` at least `dad012d`; draft PR #112 on `dm-083-two-host-dogfood` | Canonical identity, ledgers, scopes, relationship/grant authority, communication semantics and peer runtime. PR #112 is preparation only and still requires the human gate. |
| `nicoechaniz/daimon-cluster` | `main` `5cc2583` after PR #51 | Hosts the exact installed Matrix runtime, bodies/storage/lifecycle and resource fences. Its current DM-083 pin targets pre-DM-082 Matrix `8145b4c`; repin and reverify before any dogfood. Cluster never gains social, grant or canonical-ledger authority. |
| `nicoechaniz/tribe-bridge` | `main` `b81a683` | Transitional deployed v1 human-message carrier. Keep its ACK/dedup evidence separate from Matrix intake and semantic receipts. Do not archive it until the Matrix release and explicit migration cards authorize that effect. |

No repository named `tribe-chat` was found in the local project set or the
`nicoechaniz`/`AlterMundi` GitHub repositories at this checkpoint. If
“tribe-chat” means the current chat-facing Tribe runtime, its canonical source
is `nicoechaniz/tribe-bridge`; do not invent a fourth authority or migration
target without first recording the actual repository.

“Matrix” means `daimon-matrix`. Matrix.org remains excluded. “daimonmatrix
host” means the VPS, not a software component or being authority.

## Exact resume order

1. Read this file, `CURRENT-STATE.md`, `ROADMAP.md`, DM-083 issue #111, draft
   PR #112, and `docs/dm083-two-host-dogfood.md`.
2. Treat the latest Project 9 item state as authoritative over snapshot counts
   in prose. Confirm that DM-082 remains Done and DM-083 remains the active
   pause/resume card.
3. Freeze one immutable Matrix DM-083 candidate from PR #112 after it contains
   current `main`. Do not change that candidate silently after downstream
   verification.
4. Update Cluster from its stale `8145b4c` Matrix pin to that exact candidate,
   accept the V6 relationship bundle without interpreting it, and run the
   installed cross-repository suite. Record the resulting Cluster commit.
5. Produce the bounded read-only two-host preflight from DM-083. Stop there and
   obtain explicit operator authorization for the named hosts, effects,
   maintenance window and rollback plan.
6. Only after that approval, execute the reversible Legion ↔ daimonmatrix host
   dogfood: installed `/me`, `/we`, diff/sync, observer-local
   adoption/reversal, one separately accounted Tribe v1 inert message,
   successor-incarnation restart, and rollback evidence.
7. Record redacted evidence without changing the already verified runtime
   bytes. If evidence must change a pinned repository commit, repin and rerun
   the exact downstream gate before claiming completion.
8. Continue the V0 dependency path in Project 9: consented cross-being canary
   and fresh-host rebirth, remaining adapter/security gates, release candidate,
   reference release, and only then the explicit Tribe Bridge archive cards.

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
