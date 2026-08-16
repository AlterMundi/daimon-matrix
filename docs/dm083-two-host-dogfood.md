# DM-083 two-host CompAII dogfood

Status: accepted live same-being dogfood executed under operator authorization
on 2026-08-10. The successor-incarnation retry defect it exposed was repaired,
redeployed as Matrix runtime commit `f0181f7`, and confirmed against Daimon
Cluster merge `5d3892e`. A later host-qualification successor is deployed at
exact Matrix `915c56c` with Cluster `94d80ba`; the final section records why
that successor does not rewrite the original dogfood receipt.
Start from [`../RESUME.md`](../RESUME.md).

“Matrix” means `daimon-matrix`; Matrix.org is outside this system. The two
participants are the existing Legion and daimonmatrix host embodiments of one
being, not two beings. Therefore relationship grants are not a prerequisite
for this first session.

## Why this is the next vertical slice

The deterministic DM-070 journey and the historical cross-host receipt prove
the protocol mechanics. DM-083 must now prove the ordinary installed release
and reveal what using it feels like. Changes that directly enable, observe or
reverse that session belong in this batch; unrelated generalization does not.

Initial integration found two concrete release gaps and one downstream pin
that must be refreshed:

1. Cluster was pinned to an older Matrix commit and rejected additive runtime
   bundles after V2. Cluster PR #51 advanced the preparation pin to Matrix
   `8145b4c` and accepts V1 through V5 while preserving exact commit/schema
   refusal. DM-082 subsequently merged as Matrix `dad012d` and introduced V6,
   so that preparation pin is deliberately stale and must be advanced and
   reverified before dogfood.
2. Matrix's atomic Unix-socket publisher used a staging basename longer than
   the public socket. A relocated root could pass Cluster's path check and then
   fail at `bind(2)`. The staging basename is now shorter and an exact 107-byte
   Linux `AF_UNIX` regression test protects the boundary.
3. Read-only host inventory found no current root-bound Matrix being on either
   host. The only remnants are matching all-zero historical fixture manifests
   in trash; they are not migration authority. Matrix therefore now owns the
   fresh plural-being distributed `daimon-genesis` ceremony instead of asking
   Cluster to invent identity. The former one-process bootstrap is now exposed
   only as `daimon-synthetic-bootstrap` and cannot prove separated custody.
4. V6 configured only a local peer listener, forcing an operator to inject a
   remote URL outside the runtime contract. V7 adds exact per-embodiment peer
   targets and `we.sync.peer-pull`, so the ordinary CLI can execute the frozen
   sync plan without receiving endpoint authority.

DM-082 now proves authenticated recipient intake and semantic delivery through
a real loopback DM-053 HTTP carrier between isolated beings. That closes the
local protocol seam but does not configure or authorize a live recipient
service. DM-083 therefore still uses the already-live Tribe v1 direct path for
one human message and the Matrix peer path for `/me`, `/we` and sync. These are
two observed lanes: a Tribe ACK is never reported as Matrix recipient intake
or as a Matrix semantic receipt. A later live Matrix logical-message route
must reuse the DM-082 boundary rather than invent another intake authority.

Before running the preflight, freeze one post-DM-082 Matrix candidate and make
Cluster pin that exact commit with V6 acceptance. If either repository changes
after verification, repeat the exact pin gate; do not wave through a
source-equivalent but commit-different build.

## Read-only preflight to authorize

Run these observations locally on each host and retain private paths/endpoints
only in the operator copy. Publish hashes or opaque references instead:

1. record the full Matrix and Cluster Git commits, installed distribution
   `direct_url.json`, wheel SHA-256 and runtime bundle schema;
2. query authenticated `runtime.status`, `scope.me`, `scope.we`, heads and the
   frozen sync plan through the supported local client;
3. compare being reference, control head and active manifest while proving
   distinct embodiment/incarnation/credential IDs, state roots, ledgers,
   sockets, capability keys and custody files;
4. inspect Cluster's registry row, process state and relevant resource-fence
   positions without acquiring, renewing or releasing a fence;
5. verify the peer listener and the exact configured remote target without
   sending an envelope;
6. verify quiesce, integrity check, backup and restoration destinations, plus
   the exact previously installed release available for rollback; and
7. enumerate every proposed effect: package install, bundle replacement,
   listener change, service restart, one inert message, one novelty, one local
   decision/reversal and one incarnation restart.

Stop before effects if roots/manifests differ, custody or writable state is
shared, an origin is stale, a backup is unverified, a route is implicit, a
secret would enter argv/environment/logs, or rollback cannot restore the whole
previous release without rewriting canonical history.

## Bounded effect plan

After the operator approves the completed private preflight and maintenance
window:

1. quiesce each Matrix process and capture an integrity-checked portable
   snapshot; preserve the host-local client material separately;
2. install one commit-bound Matrix artifact and the compatible Cluster release
   on both hosts;
3. use the Matrix-owned bootstrap ceremony on the trusted bootstrap host, then
   install V7 public bundles atomically, with distinct local custody and
   explicit AnyVPN peer endpoints, and start one process per embodiment;
4. verify local `/me` and `/we` before opening the remote path;
5. exchange one encrypted `/me` request, then append one harmless novelty and
   synchronize bounded pages in both directions until heads converge;
6. make one observer-local decision and reversal, proving the other observer's
   effective projection never changes implicitly;
7. send one inert typed human message over the existing Tribe v1 encrypted
   direct path, prove its own duplicate gate and receipt evidence, and record
   explicitly that no Matrix semantic-delivery claim was made;
8. restart one embodiment through an authorized successor incarnation and
   replay the exact interrupted request, proving no duplicate effect; and
9. execute the stop/rollback path or its exact no-effect dry run, then record
   commands attempted, latency, confusing language, unsafe temptations and
   missing affordances.

## Rollback

Disable listeners and admission first, quiesce both processes, reinstall the
previous whole Matrix/Cluster release and restore only the matching public
bundle plus host-local client material. Preserve canonical ledgers, peer
exchange/outbox databases, message inboxes and receipts for diagnosis. Never
copy one live embodiment's writable database or private keys into the other,
lower a cursor/fence epoch, restore a retired incarnation or re-enable a
fallback wire.

## Evidence and completion

The public result must bind full release commits and artifact hashes while
redacting endpoints, paths and private content. It must prove two independent
origins, usable `/me` and `/we`, additive convergence, observer-local reversible
adoption, duplicate-free restart and rollback. The Tribe message must have its
own authenticated/deduplicated transport evidence. A future Matrix logical
message lane additionally requires authenticated recipient intake and a signed
semantic receipt; DM-083 must name that integration as pending rather than infer
it from Tribe reachability or ACKs.

## Executed candidate milestone

The authorized session used Matrix commit
`bcf6b9f6ef5a46fdd35dfc8036a7a4d458103c7b` and Daimon Cluster merge
`0a4bd1e5769874b4d91f476b1c1942db51ce0f97`. Public evidence deliberately
omits endpoints, custody locations and private content.

- One fresh being manifest produced two independently writable host
  embodiments with distinct origins, custody, state roots and local
  capabilities. Both services reported valid integrity and the same active
  manifest.
- Encrypted native peer pull succeeded in both directions. Each side imported
  exactly one initial foreign event; arrival remained pending and did not
  silently adopt it.
- One observer-local adoption and its explicit reversal changed only that
  observer's projection. The final projection returned to the original state.
- Replaying one exact durable request across an ordinary same-incarnation
  service restart returned the byte-identical authenticated response with
  SHA-256
  `b4b35839e09acb27e3ec5e3e741812d7682cac104fa9099b0e0f76aecb34e215`
  and created no second event.
- A peer outage refused the pull as an ambiguous outcome; known event count
  and heads did not move. The stopped peer and Cluster service recovered.
- One distinct Tribe v1 message produced authenticated transport/dedup
  evidence. It is intentionally not counted as Matrix recipient intake or a
  Matrix semantic receipt.
- Portable snapshots restored to fresh same-host roots with exact manifest
  hashes. Encrypted restic snapshots were checked and mirrored off host. The
  scheduled Cluster backup was then corrected to quiesce and resume the exact
  previously active service set while covering the complete state and deployed
  release.
- A signed authority epoch retired the Legion incarnation and activated one
  exact successor. Both hosts accepted the two-manifest history and retained
  their existing events.

That final succession revealed a real release defect: the daemon journal held
the correct old exact response, but both service and client verified it only
against the current server origin, so the daemon closed the connection. The
candidate repair keeps client config V1 compatible and adds V2 with an exact,
bounded historical-server list and retirement times. The service returns a
cached response only when its origin is a recognized authority-history member
for the same body, embodiment and principal. The client accepts such a response
only for a request issued no later than that incarnation's retirement. The
stored response is never resigned or rewritten.

The repair has focused regression, strict typing and deterministic-generator
coverage. Matrix commit
`f0181f7117859f3f9cc4afc7dfbdaf9b06e74754` passed the full 543-test source
suite, installed cross-repository contract, reproducible build, secret scan and
CI. Daimon Cluster merge
`5d3892eaca1744e98874cab8d53be46e3eb186de` pins that exact runtime and passed
297 tests plus its Python 3.11–3.14 CI matrix.

## Repaired-candidate operational confirmation

The exact pair was deployed to both authorized runtimes. The first remote
attempt used the wrong readiness route and exercised the automated whole-pair
rollback: the prior services and state returned cleanly before a corrected,
bounded `/v1/health` probe allowed the second deployment. This is retained as
rollback evidence rather than hidden as setup noise.

- The preserved pre-succession CLI request replayed through client config V2
  with byte-identical output SHA-256
  `b4b35839e09acb27e3ec5e3e741812d7682cac104fa9099b0e0f76aecb34e215`.
  Known events stayed at five during the retry, so no duplicate effect was
  created.
- One harmless event was then authored on the successor lane. The remote host
  imported the bounded missing page and the final reverse pull imported zero.
  Both hosts finished with six known events across three incarnation lanes and
  the same frozen heads digest
  `509fe38e3a6d0278721b4cc0c2cc4c33a44ece41655ac9b29fcacce1ca8973df`.
- Fresh portable snapshots restored to separate verification roots. Their
  public manifest hashes are
  `4571f69579d85a1f4ebbc3d7045d8624688c4b93f98188c2485e501d903d2406`
  and
  `fb72ee46b921b4a3431eb1be94c5179c8cbae3c9b939fa656336cc78bb460c0c`.
  Fresh encrypted restic snapshots `483c96c2` and `f53e2629` passed repository
  checks and were mirrored off host.
- Final runtime checks found both services active, Cluster health `ok` with
  its audit chain valid, exact Matrix install metadata at `f0181f7`, valid
  runtime integrity and six known events on each host.

DM-083 same-being operational acceptance is therefore complete. Draft PR #112
still requires independent review before merge, and offline root/recovery
escrow remains a physical/governance release gate. Neither condition weakens
the completed runtime evidence. The next roadmap gates are a consented
cross-being native logical-message canary and fresh-host rebirth/recovery;
Tribe Bridge remains transitional until those replacement gates pass.

## 2026-08-11 host qualification successor

The accepted dogfood state was advanced without changing its identity,
transport, adoption or retry authority. Matrix
`915c56c8899fd53d683bd7c7c81c3465b600bed9` adds a separately keyed,
owner-only host status client with exactly five read methods. Cluster
`94d80baca05f468287b7d2bf99c577350d654a36` pins that exact Matrix artifact
and waits boundedly for the private Incus bridge before binding `clusterd`.
Both repositories passed their complete local suites and Python 3.11–3.14 CI.

The exact pair was deployed with the previous release preserved for rollback.
Adaptation mistakes in the deployment wrapper exercised whole-pair rollback
repeatedly; every attempt restored the prior healthy services and state before
the corrected deployment proceeded. A fresh encrypted restic snapshot
`89d801b1` passed `restic check` and the ciphertext repository was pulled to
Legion with an empty rsync dry-run afterward.

The final cold reboot changed the host boot ID and recovered SSH, ZeroTier,
nftables, zram, Incus, three containers, Tribe v1, `clusterd`, Matrix and the
backup timer without manual repair. `clusterd`'s bridge preflight exited zero,
the service started once with `NRestarts=0`, and the boot journal contained no
`EADDRNOTAVAIL`. Pre/post audit and idempotency hashes were byte-identical; the
same five known reconcile findings remained. Authenticated Matrix status
reported configured, integrity `ok`, nine known events, zero incomplete,
authority epoch 2 and non-partial `/we` and sync-plan views. Tribe v1 remained
healthy at directory epoch 5.

This is runtime qualification of the already accepted same-being path, not a
cross-being consent or semantic-delivery claim. Matrix PR #112 and Cluster PR
#77 remain unmerged pending independent review. Fresh-host private custody,
external participant consent and the final human cutover/archive decisions
remain separate gates.
