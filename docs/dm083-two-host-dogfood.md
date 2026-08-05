# DM-083 two-host CompAII dogfood

Status: Fast Forward preparation in progress. No host was contacted and no live
service, route, key, database or Cluster resource was changed by this card yet.

“Matrix” means `daimon-matrix`; Matrix.org is outside this system. The two
participants are the existing Legion and daimonmatrix host embodiments of one
being, not two beings. Therefore relationship grants are not a prerequisite
for this first session.

## Why this is the next vertical slice

The deterministic DM-070 journey and the historical cross-host receipt prove
the protocol mechanics. DM-083 must now prove the ordinary installed release
and reveal what using it feels like. Changes that directly enable, observe or
reverse that session belong in this batch; unrelated generalization does not.

Initial integration found two concrete release gaps:

1. Cluster was pinned to an older Matrix commit and rejected additive runtime
   bundles after V2. Its DM-083 branch now pins the DM-081 release and accepts
   V1 through V5 while preserving exact commit/schema refusal.
2. Matrix's atomic Unix-socket publisher used a staging basename longer than
   the public socket. A relocated root could pass Cluster's path check and then
   fail at `bind(2)`. The staging basename is now shorter and an exact 107-byte
   Linux `AF_UNIX` regression test protects the boundary.

The remaining product gap is explicit: native peer transport can carry
encrypted `/me`, scope and sync requests, while DM-053 has an outbound logical
message route client but the installed daemon does not yet expose a configured
recipient-ingress service. DM-083 therefore uses the already-live Tribe v1
direct path for one human message and the Matrix peer path for `/me`, `/we` and
sync. These are two observed lanes: a Tribe ACK is never reported as Matrix
recipient intake or as a Matrix semantic receipt. The later integration can be
shaped by the actual UX instead of blocking all dogfood on an untested adapter.

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
3. install public bundles atomically, with distinct local custody and explicit
   AnyVPN peer endpoints, then start one process per embodiment;
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
