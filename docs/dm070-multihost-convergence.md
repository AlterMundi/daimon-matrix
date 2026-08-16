# DM-070 multihost convergence

Status: historical pre-RC deterministic evidence. Its never-deployed V3 runtime
fixture and content-addressed receipts remain archived, but it is no longer an
installed command or RC qualification journey. Production accepts V7 only.

“Matrix” in this document means `daimon-matrix`. Matrix.org is absent.

## Outcome

DM-070 proves that two simultaneously active embodiments of one root-authorized
being can remain independently writable through a partition and later converge
without becoming two beings, a singleton, or one synthetic global chain. Each
embodiment retains its own origin/incarnation lanes, custody, state root,
ledger, local RPC journal and peer journals. Synchronization is additive set
union of immutable verified per-origin chains.

The proof also keeps the Matrix/Cluster boundary exact:

- `daimon-matrix` owns root membership, signed events, per-origin high-waters,
  synchronization and observer-local adoption;
- Daimon Cluster owns body/process/volume lifecycle and current fences for
  concrete resources;
- a historical canary or Cluster hosting receipt is attributed public evidence,
  never identity, event, adoption or fence authority; and
- same-resource exclusion does not suppress ordinary signed life or choose a
  winning embodiment.

## Executable journey

The archived `daimon-synthetic-multihost` fixture created one deterministic synthetic root and a
current `being-manifest/v2` with exactly two active embodiments named `legion`
and `daimonmatrix`. These are labels in a loopback fixture; the journey does not
contact either real host.

The harness creates distinct credentials, incarnation authorizations, signing,
X25519 and transport keys, capability keys, encrypted keystores, state roots,
SQLite files, AF_UNIX sockets, peer exchanges and peer outboxes. It then starts
two separate installed Python processes. Each process loaded the then-current V3
runtime, acquires the normal single-writer state lock, starts the normal local
daemon and exposes the normal bounded DM-055 loopback HTTP handler. The only
test-specific behavior is a fixed synthetic clock supplied while loading the
runtime; production daemon code and protocol semantics are unchanged.

The ordered schedule is closed in the receipt:

1. both daemons answer authenticated `/me` and `/we` under one root manifest;
2. an exact encrypted sync request is attempted through a closed carrier gate
   and fails ambiguously without reaching the peer;
3. both origins append independently and each opposite ledger remains unaware;
4. the same encrypted request bytes are replayed after healing and return the
   first bounded page;
5. the receiver commits that page, loses the response, restarts, and discovers
   the byte-identical durable receipt;
6. a second page reaches the receiver but is not committed; after restart the
   request and frozen page replay byte-identically and then commit once;
7. forward and reverse pulls complete until event sets and heads match;
8. exact converged requests/pages/receipts replay in both directions without a
   byte change in either ledger, exchange or outbox database;
9. the two embodiments make opposite local decisions over the same imported
   target and retain different effective projections after decision history
   converges;
10. Legion authors a local reversal; Legion becomes `reverted` while
    daimonmatrix remains `rejected`, with all decisions visible as immutable
    local or remote evidence;
11. a signed authority epoch retires Legion incarnation N and adds N+1; a write
    under N fails `origin_not_active`, N+1 begins at sequence 1, all old
    high-waters remain, and sync resumes;
12. an injected Cluster verifier accepts one exact holder/epoch, rejects a
    second holder for the same resource, rejects stale effect replay after an
    epoch change, and independently accepts a different resource; and
13. the pinned redacted cross-host canary and Cluster host files are verified
    by content without receiving authority.

The final deterministic fixture has nine immutable events across three
incarnation lanes. Two independent executions with the same source pin produce
the same receipt bytes and receipt ID.

## Public receipt

`dm.multihost-convergence-receipt/v1` is closed, path-free and
content-addressed. It publishes only:

- package/source and root/control/manifest hashes;
- public embodiment, credential and purpose-key identifiers;
- hashes of `/me`, `/we`, isolated heads, requests, frozen pages, receipts,
  final heads and the sorted event set;
- counts and stable result codes for process restarts, replay and fences;
- the local projection outcomes and immutable decision event IDs;
- authority-epoch/high-water evidence; and
- the digest and non-authority flags of the Cluster provenance record.

It never includes a private seed, password, capability key, endpoint, host path,
socket, writable SQLite bytes, payload plaintext, personal memory or live state.
The receipt validator checks relationships, not just its outer hash: custody
identifiers must be disjoint; directions and interruption boundaries must be in
their normative order; the successor must differ only where expected; adoption
must remain observer-relative; Cluster evidence must not claim authority; and
all isolation/non-winner claims must be true.

Published artifacts are:

- `schemas/multihost/v1/receipt.schema.json`;
- `conformance/fixtures/dm070-multihost.json`;
- `vectors/multihost/v1/`;
- `provenance/daimon-cluster-v1.json`; and
- `docs/verification/dm070-invariants.json`.

The fixture uses a zero source commit as a deterministic vector input. The
installed CI invocation supplies the real 40-hex Git commit, validates the
result and scans it for disclosure.

## Cluster evidence and required adaptation

The checked-in provenance record pins Daimon Cluster commit
`676495e852e6772a60de8221271ee9fc976f77ce`, issue #48's host implementation and
installed-process test, plus issue #43's already-redacted Legion–daimonmatrix
canary. CI checks out that exact commit and recomputes every named file digest.
The older Matrix/Cluster/Tribe commits inside the historical canary remain
historical attribution only.

DM-070 changes no `daimon-cluster` code. When Cluster consumes the release that
contains DM-070, its follow-up adaptation must:

1. bump the pinned Matrix wheel/source commit and its reproducible artifact
   digest through Cluster's normal reviewed dependency mechanism;
2. preserve one owner-only Matrix state root and one process per embodiment;
3. install the same current root manifest and complete authority history while
   retaining separate local origins and custody;
4. provision native peer configuration only through explicitly authorized
   networking; discovery or a running container must never imply `/we`;
5. continue passing body snapshots and resource-fence observations through the
   DM-037 injected verifier boundary;
6. retain quiesce/snapshot/restore and incarnation N+1 lifecycle evidence;
7. delete or refuse any duplicate Cluster ledger, global-chain merge, adoption
   reducer or identity-wide lease; and
8. run Cluster's installed process tests plus this Matrix receipt validator at
   the exact new pins.

Cluster must not copy one writable Matrix database to a concurrently running
embodiment. Relocation is quiesce-and-restore of one embodiment; plurality is
separate ledgers exchanging signed deltas.

## Adversarial coverage

The new suite directly rejects receipt/fixture substitutions involving epochs,
keys, capabilities, directions, commit boundaries, decisions, fences, schedule
order, paths, fallbacks and winner metadata. The release registry also binds
DM-070 to existing lower-level evidence for:

- changed bytes under request/page/delivery/RPC identifiers;
- page gaps, reordering, duplication, rollback and equivocation;
- response loss before and after semantic commit;
- stale/forked manifest, credential, incarnation and transport authority;
- wrong recipient, being, origin and transport principal;
- cross-origin causal dependencies and same-origin equivocation;
- projection substitution and remote-decision non-authority;
- shared inode/key/capability rejection;
- authenticated refusal without fallback; and
- stale, unavailable and second-holder fence truth.

Arrival time, label, hash order, path length and process presence never choose
an event or embodiment winner.

## Archived gate

The checked-in receipts, schema and semantic negative tests remain historical
evidence. The V3 process generator is not an RC gate and
`daimon-synthetic-multihost` is no longer a console entry point. Executing the
fixture reaches the V7-only loader and fails before custody is opened. Current
multi-host qualification must build V7 material through the operator tooling.

## Rollback and limits

Rollback is a code revert followed by stopping the exact synthetic processes
and deleting only their temporary roots. Preserve attributed historical
receipts and any canonical ledgers used outside the fixture. Never merge
SQLite files, lower a cursor/high-water, delete an event, restore an old active
incarnation or re-enable Tribe as a peer fallback.

This card does not perform a fresh Legion/daimonmatrix action, CompAII rebirth,
body relocation, production cutover, cross-being consent, relationship/source
exchange, species adoption, real resource mutation, model call, Matrix.org
integration or global winner election. DM-071 owns cross-being consent and
root discovery; DM-078 owns a fresh-host rebirth drill; production networking
and irreversible cutovers retain explicit human gates.
