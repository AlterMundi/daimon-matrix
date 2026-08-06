# Current state

## Pause checkpoint — 2026-08-06

DM-082 is merged on `main` at `dad012d` and supplies the first complete local
minimum relationship-to-message journey. Its installed synthetic evidence is
release-ready and byte-reproducible; it contacted no live host or participant.
The project is intentionally paused before DM-083 live effects. The exact
cross-repository state, stale Cluster pin, human gate and resume sequence are
recorded in [`RESUME.md`](RESUME.md). A future agent must read that file before
using the older component-by-component history below.

Draft PR #112 is the active DM-083 preparation branch. It contains the
Matrix-side Unix-socket boundary fix and the dogfood plan, but it is not live
dogfood evidence. Daimon Cluster `main` at `5cc2583` still pins the earlier
Matrix candidate `8145b4c`; that pin must be advanced to the frozen post-DM-082
candidate and reverified before preflight can become an authorized session.
Cluster documentation-only handoff PRs #53–#55 do not change that `5cc2583`
executable baseline. Tribe Bridge documentation-only PRs #51/#54 record the
pause without changing its deployed/runtime `b81a683` baseline; it remains the
transitional human-message lane. Inspect current repository heads rather than
equating a runtime baseline with documentation `main`. There is no separately
identified `tribe-chat` repository in the recorded project set.

The canonical model permits multiple simultaneous embodiments of one being.
The previously documented identity-wide singleton lease is not part of the
supported architecture.

`daimon-matrix` currently supplies specifications, schemas, conformance
vectors, and an installed Python runtime. Its V0.1 MVP owns being-root
continuity, ledgers, scopes, synchronization, memory policy, and secure
communication. Tribe Bridge v1 remains transitional work to be absorbed behind
those contracts. The former isolated Cluster `weave` implementation has been
retired from the executable host path; only frozen compatibility evidence
remains. DM-021 now binds same-being membership to a Matrix
being root; the old administrator manifest is accepted only as explicitly
bound historical evidence.

The external Matrix.org protocol and its homeservers are not an MVP dependency
and are not meant by “Matrix” in this repository. Use `daimon-matrix` for this
software, `Matrix.org` for the unrelated external protocol, and
“daimonmatrix host” when referring to the VPS.

Completed evidence that remains reusable includes canonical JSON/signature
work, append-only event validation, the `/we.sync` walking skeleton, Cluster
snapshot/quiesce/audit/failure drills, and Tribe's durable encrypted transport.
Their authority boundaries are redefined by the current ontology.

The provisional coordinated two-host journey passed. DM-021 implements the
synthetic being-root/control, plural credentials, transport-principal binding,
history binding, and encrypted custody gate. It is followed by the local
runtime narrow waist, Tribe absorption, Matrix↔Cluster integration, and a
root-authorized multi-host rebirth drill.

DM-022 migrates the reviewed per-embodiment ledger mechanics from Cluster into
the installed package. Root-bound ledgers verify DM-021 credential/incarnation
evidence; an activated binding admits only the exact byte-preserved provisional
history it names. Cluster continues to host process/state and resource fences.

DM-023 builds the typed transport-neutral `/we.sync` transaction above that
ledger: issued requests, frozen delta responses, cursor/ingest receipts and
local projections are durable and replay-safe. DM-055 now carries those exact
documents over the native encrypted Matrix peer transport; Tribe is not that
wire.

DM-024 adds ledger schema V3, the closed authenticated local service and the
installed `daimon-matrixd` AF_UNIX process. It loads exact root-bound public
authority plus purpose-separated encrypted runtime secrets, journals exact RPC
responses, and survives retry across semantic-commit/response-write failures.
DM-025 adds the typed authenticated local client, installed `daimon` CLI and
closed MCP `2026-07-28` stdio adapter. Durable retry files preserve exact RPC
bytes, the daemon exposes 83 closed methods, MCP advertises 66 closed tools and
`daimon:` resources, and legacy MCP and Matrix.org transports remain absent.
The merged Cluster host adapter supervises the process. DM-026 closes the local
release gate with a deterministic installed conformance report over the current
97-scenario closed registry; it exercises real process, AF_UNIX, filesystem and
SQLite paths. DM-070 extends that gate with two isolated installed processes,
native encrypted peer exchange, partition/restart convergence, observer-local
adoption, authority-epoch succession and injected Cluster fence truth. Neither
card claims a live host cutover, live Cluster effects or rebirth. DM-037 defines
closed Cluster body/fence/effect evidence and requires current effect-truth
verification before replay. DM-050 begins absorbing
Tribe transport behind the same boundary. DM-050 pins the current public Tribe
head and its relevant blob/hash inventory, but imports no upstream bytes: no
license is detected, so DM-051–DM-053 independently reimplement only classified
behavior under Daimon contracts.

DM-051 now supplies the disabled, carrier-neutral
`dm.sealed-delivery/v1` runtime: root-bound plural sender/recipient authority,
fresh per-delivery payload encryption, independent RFC 9180 HPKE CEK wraps,
typed encrypted-keystore operations and durable exact retry. The old DM-011 V0
wire remains KAT evidence only. No live Tribe route or account is enabled.

DM-052 now supplies the same-ledger logical communication reducer: signed
message/thread identity, per-recipient semantic legs, route-attempt and intake
receipt separation, lossless snapshot pages, disjoint claim leases, contiguous
terminal-prefix cursors, queue compaction and rollback detection. Its dedicated
authenticated RPC methods are available to purpose-limited adapters but no live
carrier is enabled.

DM-053 now supplies explicit per-embodiment route profiles, authority-free
provider manifests, deterministic local/anyVPN/direct/hub selection,
authenticated body-bound Unix/HTTP requests, recipient-validated intake,
opaque durable hub/inbox leases, ambiguous-response retry and a generic
gateway edge disabled by default. Provider endpoints and route secrets remain
in owner-only custody and are absent from results. CI uses loopback providers
only; Buzz and Telegram remain unselected future gateway implementations.
DM-054 now owns current scope resolution and the `/me`, `/we`, `/we.diff`,
per-origin `/we.sync` planning and verified `/tribe` surfaces. It adds
purpose-separated signed partial fan-out with durable exact replay, real daemon
and CLI/MCP reads, DM-051/052 target parity, and an exact read-only Cluster
snapshot contract. DM-055 implements its native root-bound encrypted peer
carrier for scope and sync; cross-being root discovery and consent remain
DM-071.

DM-055 is implemented behind optional runtime bundle V3. It introduces the
closed `dm.peer-envelope/v1` HPKE/Ed25519 narrow waist, durable byte-identical
outbox retry, concurrent inbound leases and exact response replay, direct
DM-054/DM-023 dispatch, a connection-bounded HTTP(S) carrier and one-shot
keystore loading. Fifteen focused tests cover real encrypted scope/sync,
response loss, corruption, takeover, wrong-key and malformed-runtime rejection.
No Matrix.org or Tribe wire is involved. DM-070 now exercises this carrier
between two isolated installed processes and binds the existing redacted
cross-host canary as historical non-authority evidence. A fresh live cutover
remains explicitly human-authorized.

DM-060 implements birth as a new self-certifying being plus its first
root-authorized embodiment/incarnation, not as singleton `/me` enrollment,
Cluster lifecycle, Tribe membership, or rebirth of an existing being. Its
purpose-separated offer, awakening proof, newborn root acceptance and witness
activation receipt are durably one-use and quarantine sibling acceptances
without choosing a winner. The installed `daimon-synthetic-birth` journey
creates only fresh synthetic parent/newborn/witness roots, verifies encrypted
offline custody restore, starts the real daemon, queries CLI and MCP, and proves
one first embodiment over zero canonical events/memory/projection records. It
performs no live birth, host mutation or provider effect. DM-061 continues with
species evolution; later multi-host cards own additional-embodiment and rebirth
evidence for an existing being.

DM-061 implements the frozen species-evolution contract: threshold-maintained
content-addressed genesis/releases, fork-safe high-waters and resolution,
predecessor-selected local deterministic WASI verification, paged read-only
`/species.incoming`, and crash-safe compatible application plus rollback. A
signed parent declaration and independently authorized incompatible child
genesis create a new species, but no existing parent carrier can adopt it in
V0. The 124 normative DM-014 Section 14 rows are frozen in an executable
generated map. Evidence is synthetic; no Agent 0, first real speciation, live
Cluster mutation or cutover is claimed.

DM-081 implements the complete DM-015 source runtime. Five signed event kinds,
an owner-local exact-byte CAS, separate root-bound foreign-being ledgers,
portable cursors/diff, side-effect-free per-item preview, crash-resumable
paginated pull, initial quarantine, receiver-local assessment, attributed
external-reference promotion, retraction/reassertion and tombstone are exposed
through runtime bundle V5 and twelve typed daemon/CLI/MCP methods. The installed
two-being journey recovers at every durable boundary and the generated 84-row
Section 14 registry is release-blocking. It performs no live disclosure,
source fetch, memory admission, host mutation or Cluster effect. DM-082 now
implements the relationship grants plus bilateral consent,
founded-Tribe membership, founder succession and strict delegation. Runtime
bundle V6 feeds DM-054 from verified signed history, publishes fixed owner
daemon/CLI/MCP surfaces and retains forks without an arrival-order winner. Its
installed three-being journey now executes a real local DM-054→DM-052→DM-051→
DM-053 path: authenticated loopback intake stays non-semantic until the foreign
being's signed receipt is verified, while revocation refuses stale direct and
hub-forward traffic. It makes no external route, host or Cluster effect. DM-071
owns the later consented cross-host canary.

DM-079 closes the real-restart gap found by the Cluster #48 installed-process
test. A signed authority epoch now advances one embodiment from incarnation
`N` to `N+1`; hosted bundle V2 retains every prior root manifest, SQLite
expands its accepted epoch set only after exact historical verification, and
the old bundle becomes an explicit downgrade. This is the prerequisite for the
fresh-host rebirth proof in DM-078, not a claim that production supervision or
Incus relocation is already complete.

DM-080 binds every Cluster body snapshot to the exact evaluation millisecond
chosen inside Matrix and removes the check/use race found by installed-process
tests. Daimon Cluster issue #48 was completed by PR #49 at
`676495e852e6772a60de8221271ee9fc976f77ce`: it pins Matrix
`73767504b777d0d0c9132a341959f486afce99f1`, verifies that pin at runtime,
provides the exact body/fence/effect adapters, runs one owner-only daemon per
embodiment, snapshots/restores quiesced portable state, and removed executable
provisional `weave/` code. This is a production-shaped host adapter with
synthetic process evidence, not yet the final real Incus rebirth drill.

DM-070 supplies the deterministic multihost convergence acceptance journey for
the Matrix side. Two root-authorized embodiments remain independently writable
through a partition, converge immutable per-origin chains in both directions,
retain observer-local adoption decisions, advance one incarnation to authority
epoch N+1 and consume injected resource-scoped Cluster fence/effect truth. Its
closed content-addressed receipt is produced by installed entry points and pins
the exact Cluster host adapter and historical canary bytes. The names `legion`
and `daimonmatrix` are fixture labels only: no live host or service is touched.

DM-030 implements the deterministic memory boundary: immutable policies,
content/candidate/checkpoint/decision/plan records, exact body-session-lease
evidence, provenance-preserving categories, fork-safe append-only lanes, and a
transactional stale-state/idempotency guard. `memory.evaluate` and
`memory.execute` are available through the authenticated daemon, typed client,
CLI and MCP. Public vectors, schemas and eight release-blocking conformance
scenarios cover environment determinism, review precedence,
cross-embodiment forks and response-loss/restart exactly once. DM-031 adds a
durable per-item curator queue, generation CAS, exact actor origin, explicit
human-review proposals, Cluster-verified resource-fence mode, and
effect-truth-aware replay through daemon/client/CLI/MCP. It deliberately has no
exclusive being-wide Librarian lease. DM-032 supplies the evidence-only model
worker and DM-033 the purpose-limited cryptographic human-review narrow waist.
DM-034 now supplies the exact-version personal-memory projection library for
HMK: provenance-safe assert/advance/retract, owner-local crash recovery, fresh
effect-truth reconciliation, verified recall, atomic namespace rebuild, closed
schemas/vectors and synthetic real-SQLite backup/cutover/restore evidence. HMK
remains a disposable retrieval view and no live CompAII database is migrated.
External-state and collective publication remain DM-035 and DM-036.
