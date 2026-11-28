# Daimon portability roadmap

The [foundation](foundation/daimon-matrix.md) describes continuity across
embodiments. Our acceptance test is that a person can resume work in the same
conversation after a pause, a host or harness change, or loss of the native
session. The next turn finds the right work, knows what happened and continues
without repeating effects. [Current architecture](current-architecture.md)
describes the stack, and [receiving state](../CURRENT-STATE.md) records actual
deployments. The [technical project contract](project-contract.md) defines the
default for newly created work. This roadmap covers how to qualify continuity
and shared project coordination.

## State and ownership

| Owner | State or responsibility |
| --- | --- |
| Matrix and Cluster | Matrix verifies signed identity, relationships, audience and communication. Cluster owns runtime placement and lifecycle. Same-being coordination uses `/we`. The humans and daimons with whom a being pairs or shares resources are in its `/tribe`. |
| DaimonGateway | Logical conversation identity, accepted originals and attribution, execution binding, handoffs, progress, results and return receipts. |
| Harness adapters | Native resume, execution and intervention. Report capabilities and outcomes so Gateway can distinguish incorporation into the active turn, queued input and uncertain dispatch. |
| DaimonApp and TeleDaimon | Project authorized conversation records from the same originals and retain surface delivery receipts. |
| Observer and the general conversation | Supply sourced observations to a bounded topic checkpoint. Gateway validates its revision and references. The checkpoint is reconstructible from authorized evidence. |
| Git and project records | Version project files, issues, card state and exact review revisions. The system that performed an external action owns its outcome receipts. |
| Holodeck and web viewers | Open the same published deliverable revision under its current audience. Retain view state separately from project and release state. |
| DMK and shared Skills | Preserve being-level memory and published operating knowledge through their existing update and adoption paths. |

Keep the owning source, contract, receiving configuration and regression
test aligned. Record the tested source and runtime revisions in the owning
project. Distinguish queued, incorporated, answered and visible.

## Topic state contract

Each logical topic has a stable identifier, its own workspace and links to
the projects it works on. A workspace provides a base for topic records.
Projects can have several repositories and can be linked from several topics.
Keep the latest revision of each repository link available independently of
the last changed link. Cold startup can select a subset; the catalog retains
the other links and lets an authorized reader fetch them as needed.
The checkpoint records current
roles, work in progress, decisions, explicit next actions and open
dependencies. It links to the exact project revisions, original messages,
attachments and outcome receipts that support it. Its scope follows the topic
and the source audiences.

At the close of a meaningful iteration, the worker can propose a delta with
source references. Observer and the general conversation can contribute their
own attributed observations. Gateway checks the topic, sources and prior
revision before accepting the delta. Conflicting or stale observations remain
inspectable. The system that performed an action is the source for its outcome.

### First delivery: a project link in shadow

Start with one change: attach an authorized repository and immutable commit to
the existing logical topic. Reuse Gateway's permanent workspace binding and
retained source references. Keep the repository locator private to its authorized
audience. The shadow reader compares the proposed link with Git and the cited
source. Keep the shadow result outside the active native context until its
recorded revision and evidence agree.

The proposal binds the logical topic and its current binding, the expected
checkpoint revision, a stable operation ID, the project link and the retained
source references. Gateway derives the actor from the owning session, resolves
the references under their existing audiences, and projects the validated
result. An exact repeated proposal reads its original result. A competing
proposal against an older revision returns a conflict and the current revision.
Reusing an operation ID with different content returns a conflict without a
new revision. Reads and repeats recheck current source access, including after
a workspace rebind or revocation.
Unavailable or unverifiable evidence leaves the proposal unresolved. A reference
to an uncertain effect remains a reference to its owning receipt.

Qualify with two shadow writers, a moved checkout, duplicate delivery, a
missing commit, and a source whose audience excludes the reader initially or
after revocation. A passing fixture resolves the selected project and commit
through the topic after moving its checkout, preserves an unrelated staged
edit and records one accepted revision after competing proposals. Cold recovery and live receiving acceptance are
subsequent tests. The workspace owner supplies the current binding; Observer
and the general conversation may supply existing attributed evidence. This
cut requires no model call and no Gateway deployment.

The [Gateway shadow candidate](https://github.com/AlterMundi/DaimonApp/pull/1137)
adds the revisioned local store and controller action. Its isolated
SQLite/Git test verifies the exact link through a store restart and checkout
move, with matching operation re-reads and concurrent conflict detection.
A synthetic Codex peer exercises the actual Gateway controller and
general-conversation reader. When a human correction supersedes the cited
source, read and repeat fail while the worker's workspace stays available.
The catalog fixture reads three repositories across two projects from the
same topic. Updating one link keeps the other links independently readable.

The [cited work snapshot](https://github.com/AlterMundi/DaimonApp/blob/c2fc8386b922c57ec78a51d337321b7a887528f9/docs/project-checkpoint-shadow.md)
adds decisions, dependencies and next actions on the same repository
checkpoint revision. An exact Observer or general-conversation citation
supports the snapshot. A different snapshot under an existing operation
key conflicts. An edit that omits the existing work cannot silently remove
it. The controller rechecks source access on reads and repeats, and the
ordinary room catalogue still exposes repository metadata only. The selected
cold fixture delivers the cited work and unchanged effect receipts toward
Claude in one loopback provider call, with no duplicate dispatch.

The [checkpoint recovery fixture](https://github.com/AlterMundi/DaimonApp/blob/4b78cd7dbed0ffe0f7a829471841c13a55608782/docs/project-checkpoint-shadow.md#selected-cold-recovery)
uses the existing Codex and Claude startup paths for an
explicitly selected set of verified repository revisions. An isolated
paired-human round trip exercised the actual Gateway and Claude Code 2.1.332
with Agent SDK 0.3.332, a loopback provider, and a synthetic Codex Core.
After the fixture removed the preceding Claude transcript from native lookup,
the new input recovered in a distinct Claude session. It received the three
selected repository revisions across two projects and the same two original
receipt references. One request had a retained result and one remained
unresolved. The recovery used one loopback provider call and zero duplicate
dispatches. A subsequent turn on the existing Codex thread received both
retained Claude exchanges and the same checkpoint. The [reproducible metric
report](https://github.com/AlterMundi/DaimonApp/blob/72f9d7c2697dcf2a25cfd439b5eeca3a9fe73803/docs/project-checkpoint-shadow.md#selected-cold-recovery)
measured 2,901 ms from paired input to the visible cold-recovery answer. The
exact Claude transcript recorded eight simulated input tokens and four
simulated output tokens. The report excludes transcript contents, account
details and native identifiers. It records one loopback call and zero real
provider calls. On 2026-11-28, the active Ítaca worker's scoped capability
read did not advertise the project checkpoint action. The candidate's live
selection stays with Portability and still needs receiving verification.

A separate run simulated Codex Core's missing-rollout error at the first
Claude-to-Codex input. The [Gateway adapter](https://github.com/AlterMundi/DaimonApp/commit/02130aa04d6923e7b4c7f1b393d76843fd74496e)
qualifies the refusal only from the exact thread's metadata resume reply,
before input submission. The paired Conversation fixture retained the
original as unsent, preserved the saved Codex binding and topic generation,
and submitted no native thread or turn. The Telegram fixture also preserved
the original and presented the specific missing-history notice.

The [routed refusal receipt](https://github.com/AlterMundi/DaimonApp/commit/50126307f88be77961a5ca2797048b3b2346f26f)
ties the pre-submission rejection to the paired original, previous native
thread and the exact verified checkpoint digest. Owner input status and the
audit record survived a Gateway restart with the original still unsent.
A recovery reservation can now distinguish this case from other unsent
attempts. The receipt records eligibility evidence for a later writer, with
no native creation or submission.

The [authenticated retry reservation](https://github.com/AlterMundi/DaimonApp/commit/83de8c1644ea3de5d9d2288dd28d9a193ce436f1)
revalidates the selected Git checkout, authority and checkpoint digest. The
existing input writer saves one reservation for the original in the same
transaction as requeue. The fixture verified that equivalent retries
reuse it and a Gateway restart preserves it.

The [Gateway successor first turn](https://github.com/AlterMundi/DaimonApp/commit/1bcd8d99df064b6b410476c78b28e6bf2f3b20d7)
consumes the reservation after a definite missing-history reply. The
controller fixture checked that creation is recorded before the native
write, the original is accepted once on the creating connection with the
same checkpoint and receipts, and the canonical answer appears in
Conversation. The saved binding and logical generation remained intact.
A second fixture withheld the creation acknowledgment. A repeated retry
and a Gateway restart kept the attempt held with no second native creation
or submission.

The [real Codex App Server boundary fixture](https://github.com/AlterMundi/DaimonApp/blob/e5c4f1625eaa8b2f295bfb54969f94d1a249e262/docs/project-checkpoint-shadow.md#native-codex-successor-boundary)
verified that a new native ID cannot resume before its first saved turn.
On the creating connection, one first turn carried the fixture checkpoint,
both receipt IDs and the new original to a loopback provider. The next
connection recovered that exact native turn. The fixture used one loopback
request and observed 218 simulated tokens. That first standalone fixture
did not exercise Gateway's logical binding writer.

The [composed Codex successor test](https://github.com/AlterMundi/DaimonApp/blob/33fa0c2db178901b9e0f7765b9ea5c41443a7efd/docs/project-checkpoint-shadow.md#native-codex-successor-boundary)
now drives the paired Conversation retry through Gateway and the real Codex
App Server for the missing-history response, successor creation and first
turn. Current Core emitted a second thread announcement after the reply;
the earlier collector treated it as ordinary rebinding and failed after
native acceptance. The candidate keeps the reserved binding and waits for
the exact terminal event even when Core announces idle first. The composed
run reached the visible answer 748 ms after retry. The loopback packet
contained the unchanged receipt references, and a later native connection
reopened the one persisted turn. The run observed one loopback call, 218
simulated tokens and zero earlier instructions resubmitted. Earlier Codex
activity and inference remain fixtures. Live receiving acceptance is open.

The [Gateway candidate aligned with master](https://github.com/AlterMundi/DaimonApp/commit/d6594d06fc6bfb607f4a2961e6aa1865eedf77d6)
repeats the paired fixture with Claude Code 2.1.332 and Codex App Server
0.167.0. The cold answers appeared after 2,979 ms and 625 ms respectively.
Each leg made one loopback call and resubmitted zero earlier instructions.
The recorded counts are 8 input and 4 output fixture tokens for Claude and
218 fixture tokens for Codex. Both legs preserve the retained result and the
unresolved receipt. TeleDaimon's package read back as `06965d97`.
Master includes a patch-equivalent version of that head's direct attachment
change. The separately selected Gateway profile is checked below. Portability
owns its composition and verification alongside the checkpoint in the
selected release.

The [owner lineage transition](https://github.com/AlterMundi/DaimonApp/commit/acac086a30422f5ac9aa3ace2041ce5e12f42aab)
advances the topic's native pointer in the same transaction that records the
successor turn's completion. It retains the logical generation and keeps
earlier originals and receipts on their native lineage. The isolated Gateway
fixture restarted the writer, submitted one new original on the same successor,
read the exact old repository checkpoint with its attributed work and
original citation, and observed the new answer in Conversation. The original
effect records were unchanged. An ordinary replacement, explicit clear or
owner revocation still fences the previous generation. Review of the
binding change and live receiving qualification in both directions remain open.

Record a delta when a decision, result, dependency or next action changes.
Routine turns can reuse the prior revision. Reference retained originals and
receipts by ID. Use deterministic readers for routing facts, revisions and
receipt checks. Reuse a summary the worker or Observer already produced when
it is current and sourced. A checkpoint update can be committed alongside the
ordinary turn result without a separate model call or approval round.

On a cold start, use the current turn's authority, the topic workspace, the
latest checkpoint and the relevant retained originals. Read back unfinished
or uncertain effects through their owning systems before continuing. On a warm
start, resume the native session and provide the missing context. Bound the
context by the current task and fetch exact sources on demand. A harness
change keeps the logical topic and its work intact. Validate these rules in
the shadow and cold-recovery milestones below before migrating existing topics.

## Shared project cards

Humans and daimons need a shared view of open work, who is taking it, decisions
and the exact revision under review. The pilot uses a shared Git remote for
project artifacts and one maintained writer for shared cards. Each card has
stable identity, attribution, revision, state and links to relevant branches
or commits.

Start with a narrow Rust implementation, provisionally named **DaimonCards**.
Its first operations are create, list, read, assign, update status and link
evidence. Use [Stage 11's Lattice v2](https://github.com/Stage-11-Agentics/lattice/tree/8736575d11853b1b90c4e49685747a53f13a9e6c)
as a reference for an attributed event log, current card projections and one
writer per board. Reuse upstream code if it fits the same contract and supports
direct A2UI projection with a small maintained footprint. Use existing identity
and project access. Check concurrent claims, state recovery and portable export.
Keep the first implementation focused on the shared card journey.

The [DaimonCards pilot](../components/daimon-cards/README.md) implements
the Rust writer and the A2UI 1.0 spatial projection. The local receiver
test uses Chromium with Proyección and submits a rendered action to the
same writer as a typed daimon action. One claim commits, the other returns
the current revision. The card retains the exact Git revision across a
store reopen. The fixture uses two checkouts of one bare Git remote and
no provider calls. The Home and own-native Holodeck routes also have an
isolated authorization fixture. Hosting both routes for a real
multi-participant project remains receiving work.

The project Git helper prepares a local checkout or a bare remote and
checkout on an already authorized shared mount. The isolated story fixture
publishes a first scene and opens the exact commit from another workspace.
Reopening the first checkout preserves its staged draft. The same operation
refuses a stale workspace claim or a differently bound checkout. See
[repository preparation](project-contract.md#repository-and-revision-binding).
A shared mount and participation by a real human and daimon remain to be
verified in the pilot.

The [DaimonCards edit action](https://github.com/AlterMundi/daimon-matrix/commit/1bace600484de29113fcf00125b5a480d1e53953)
maps a human title edit and a typed daimon edit to the same command.
The [linked-room Chromium fixture](https://github.com/AlterMundi/holodeck/commit/b2615636fa6b61cd4fe1371ae1208ad57a41bef3)
opens the mission on a mobile viewport. A typed edit commits while the human
has a draft open. The stale human write conflicts, refreshes the shared title
and keeps the draft. A later explicit save records the human as author of the
next revision, which the same card writer returns to the daimon side. Revoking
the room link refuses another title write. The fixture uses synthetic actors
and no model call.

The [card projection](https://github.com/AlterMundi/daimon-matrix/commit/f213310ed6e91da12aff902f0ecc5df7014198b9)
and [room receiver](https://github.com/AlterMundi/holodeck/commit/4367a87cb880e1298b6db14e422381447d5f5367)
show the registered repository label and full commit when both identifiers
match the card's evidence and the viewer's currently scoped project page.
The mobile Chromium fixture creates Git objects locally, reads the exact hash
from the mission, excludes evidence from another project, and verifies that
moving the registered revision hides the old hash while the native card
retains its evidence. This read opens no model turn and exposes no repository
locator. The [Gateway historical reader](https://github.com/AlterMundi/DaimonApp/commit/71374efc409d049dd6a1f964992250015a88c4ff)
allows an owned topic with a selected checkout to resolve the exact registered
commit after a newer checkpoint. It requires current link authority, matching
repository identity, retained citation and the actual local Git object.
The [Gateway room reader](https://github.com/AlterMundi/DaimonApp/commit/5ab58ba796f0ccfbdbe08cdcbffb9c9ee5d46469)
resolves up to eight references from the selected mission against that
retained evidence. The [card adapter](https://github.com/AlterMundi/daimon-matrix/commit/c94fa2a3783eaa36c65a2c1889ef1372ee7a8ebd)
and [Holodeck readback](https://github.com/AlterMundi/holodeck/commit/cdc04a555edeb94df42e7d3aac633156d408ab1c)
keep an authorized earlier hash visible after the registry advances.
The Gateway fixture verifies real Git objects, a separate project's
exclusion and rejection of an unregistered object. Chromium verifies the
mission with a synthetic room authority, then drops the hash when the
reader withdraws that historical evidence. The two compositions are
qualified separately. The Git preparer now verifies an initialized bare
repository and checkout before publishing either directory. In an isolated
real-Git run, a failure during initialization left no published remote, a
failure during cloning left the verified remote reusable under the same UUID,
and a concurrently created checkout kept its original directory. Production
adoption and a live shared remote used by both participants remain open.

An authorized visitor can [create the first mission from the Questbook](https://github.com/AlterMundi/holodeck/commit/70b176fb43014a0f4554c283c5d8376525791209).
The human and native daimon paths use the same typed create command. If the
browser loses the response after commit, it reads the caller's original
receipt and opens that exact mission. The
[writer adapter](https://github.com/AlterMundi/daimon-matrix/commit/4acb962eee87ff6960bd419db3c5c506b2586c63)
also opens an exact mission outside the current page without moving that
page's cursor. The isolated Home, native socket and Chromium checks cover
an edit refusal, retained retry, changed operation conflict, a private
receipt and one persisted human-attributed mission after the lost response.

Daimons read the card model and submit typed operations programmatically.
An [A2UI](https://a2ui.org/) surface projects that model to humans as a card,
board or review. Its component tree, selection and drafts are view state.
Both routes use the same card IDs and operation semantics. Writes carry the
expected revision and an idempotency key. The writer returns the resulting
revision or a conflict that the view can show and refresh. Ordinary viewing,
assignment and state changes work without a model turn. Prove that a human
without a forge account and a daimon can act on the same card and see the
result from their respective surfaces.

For A2UI, send ordinary card actions to the same writer and re-read its result
for the displayed revision. A stale assignment refreshes the card from that
writer while preserving the viewer's selection or unsaved draft.

Inside Holodeck, the A2UI view is an MMORPG-style questbook. Players browse
available, active and completed quests, read the selected objective, and
accept a quest or finish an active one. Accepting records the actor and moves
the card into progress in the same write. Selecting another entry is local
view state. A quest keeps the same project and card identity across human and
daimon views. When progress depends on exploring, interacting or changing
the world, show the affected place or object and observe the corresponding
Holodeck receipt before counting that objective. Finish the whole quest only
after its required objectives are satisfied. The Chromium fixture covers the
journal and shared claim and completion. The [Holodeck receiving fixture](https://github.com/AlterMundi/holodeck/pull/40)
uses protected HTTP and the same Rust writer to credit a workshop bridge
objective from its original Room receipt. It verifies pending and credited
progress, refusal of early completion, and stable confirmation after a room
reset. The Holodeck candidate mounts the journal in the workshop with the
existing Proyección renderer. A Chromium visitor accepts a quest, changes
the bridge through ordinary world controls and receives progress. The typed
writer completes that quest and a second narrow Chromium view reads the
same result. The isolated owner path also uses the existing native Unix
return lane and fresh, project-specific permission checks. The fixture
verifies typed completion, read-only receipt recovery, refusal after grant
revocation and same-key conflicts. The [receiving race test](https://github.com/AlterMundi/holodeck/commit/38f4c7abbed5c77bebce701e6594a15ef236a9a2)
sends an authenticated browser action and an owned native claim against the
same card revision. The Rust store records one assignment and refuses the
stale contender. Both readers observe revision two, and only the winning
actor can recover the original operation receipt. The protected HTTP/native
suite and mounted Chromium fixture pass. Live profile selection and
reciprocal verification with real project participants remain open.

The private receiver candidate pairs [Holodeck `9b1f947`](https://github.com/AlterMundi/holodeck/commit/9b1f947c2fe00299b3759c16cf73837ad125e25f)
with [DaimonCards at Matrix `bf40d7a`](https://github.com/AlterMundi/daimon-matrix/tree/bf40d7a08b13e1f3c9fed199603a3ec409f9c3e9/components/daimon-cards).
The installed Home archive validator accepted all 65 files in the
29,265,920-byte package, with SHA-256
`73640c945dc9a4338c7568ac1ca054cb375e98d784f1db2012bd96fa17f209bf`.
The packaged production entry ran in an isolated receiving state on the
installed Node 24.21.0. With a synthetic Home identity it served the exact
health and decoded client bytes, refused anonymous requests, created a
mission, returned its original receipt after restart and refused that receipt
after revoking the view grant. The separately built release card writer
(`e13392eae0b36f9102ff7d71a4b0ad1d075f98443fd7900eb6a382bae266162e`)
passed the protected HTTP and native concurrency fixture. The package and
writer are retained for the existing deployment owner. There was no live
selection or real participant action in this qualification.

The private Questbook Workshop pilot now has its own bare Git repository
served over the existing Ítaca SSH service. CompAII pushed the first
playtest revision and an independent checkout over SSH read the same
commit and files. The pilot's private DaimonCards store holds the open
bridge mission at revision three, with the exact Git revision and an
uncredited Room objective. All three authoring receipts were read back.
The operator record holds the project and repository identities, locator
and receipts. This verifies the owner-side Git and card state. The
project still needs its actual Gateway topic binding, live Holodeck
selection, and a second participant using their own access.

The [paired project receiver](https://github.com/AlterMundi/holodeck/commit/245e4490dfc544e8d7b9cd4bec56720114df89f4)
can use the existing Home pair for this private pilot. The protected bridge
verifies the current pairing for each browser and native access. Projects
with a wider audience continue to use the registered view and edit grants.
The installed Home API confirmed the current pair and its Interaction route.
The Home verifier accepted all 65 files of the updated 29,265,920-byte
candidate, SHA-256
`efc52d8ee3d53f6d23dfb57d78fd5153f8f81847baa5a1a0d5a208fde302700e`.
The exact Node 24 package fixture allowed the paired user's write and own
receipt, refused anonymous access and denied receipt access after revocation.
The paired native policy test refused an unrelated human and being and
rechecked a changed pairing. The exact pilot selections and staged seed
remain in the private operator record. Use by the real pair is still open.

The [exterior receiving composition](https://github.com/AlterMundi/holodeck/commit/1216b9cb991797c012a11f353eb2f0096e2f5fb8)
is based on the live explorer and meadow source `66dad9e`, observed as
archive `6fd9cd26732d` on 2026-11-28. The Home verifier accepted the
40,427,520-byte composed archive, SHA-256
`b19c7b66ac3b81deed7a9c67e208154766c92561bddf0711ad7748cc5c6d6fb3`.
All 75 live art payloads match its inventory. The protected HTTP/native
fixture and 23 receiver regression tests passed. Desktop Chromium claimed
the same card later read in a separate mobile browser context. The current toroidal
terrain keeps the traditional workshop bridge out of the live surface.
The private pilot now also holds an open Git-review mission linked to the
same exact commit; the bridge mission and its uncredited objective remain.
Ítaca selected the composition through the existing Home release writer.
The live archive is `b19c7b66ac3b` and the compatible rollback is
`6fd9cd26732d`. The loaded bridge checked the existing Home pair.
Before any browser action, the current CompAII own-native lane read the
Git-review mission and its exact Git revision, changed its title once
and recovered the original receipt on a separate request. The card is
open at revision three. Anonymous journal access was denied. The private
operator record retains the exact native receipt and release request.
The paired human's actual use and the topic-room binding remain open.

The [installed own-native command](https://github.com/AlterMundi/holodeck/blob/45f27ae2b8fd70acefe821161c56b3bf7d03599a/docs/native-creation-quickstart.md#paired-project-questbook)
now includes `holodeck-world --own questbook` with the same receiving socket
and identity. It read back the exact original live receipt and ordinary
own observation continued to work through the same wrapper. Gateway
PR1137 is ready for integration and identifies this exact private pilot
as the first live checkpoint consumer. Its serving selection remains
with Portability.

A [read-only recovery probe](project-contract.md#repository-and-revision-binding)
now verifies the real pilot with a fresh SSH checkout and the installed
own-native Questbook command. It read the exact original live receipt and
current open card at revision three, with the original Git link still
current. A modified receipt and a checkout with the same commit under a
different origin were refused. This result exercises the receiving Git
and card readers. A later read of the existing checkout also verified that
its HEAD matched the linked commit at the time of the receipt readback. The
probe now reports that check separately from finding the Git object. A
separate branch tip and an unborn HEAD both preserve access to the object
without satisfying checkout alignment. The live harness switch and its
dispatch accounting are still open. A subsequent read from the configured
SSH origin with its pinned host key found the same commit at the advertised
default branch tip. The existing operator account performed that read;
access from a second participant's account is still open.

[Gateway PR1137][direct-gateway] merged on 2026-11-28 at
[`cec753ad`](https://github.com/AlterMundi/DaimonApp/commit/cec753ad1acdee7d467830ac0533584f47840f54).
The merge tree is byte-for-byte identical to the qualified candidate
`d6594d06`. The exact binary passed separate Claude Telegram attachment
and quoted-original fixtures. The active Gateway process on Ítaca reads
back `5c7c6faa`; `06965d97` identifies its separate Telegram poller.
The live Gateway binary passed read-only preflight of its selected profile
and Reports record. In the same environment, the merged candidate rejected
the profile's `agy_cli` field before reaching Reports. The Reports store
and private projection source trees themselves match. A raw source merge
with the actual serving lineage has 12 conflicting paths. Portability's
receiving composition must keep the current Antigravity, Goose, Claude
attachment and scoped interruption behavior. Keep the selected profile
intact and repeat the read-only preflight on that composition before the
live checkpoint canary.

A staged composition on 2026-11-28 also includes the next serving Gateway
revision, `fc5e8dce`, which adds voice transcription to portable Telegram
topics. Candidate source `62aedb3934f62f30b7d06a2d00c3eb9b234a856e` combines
that serving lineage with PR1137. Binary SHA-256
`ffd4d976038733d273b7e090696f2ce1d750b139265cd221daaf27b499bab581`
passed read-only preflight with the actual Ítaca profile and Reports record.
The serving process kept its PID and its selected binary. The composition and
restricted test evidence are retained on Ítaca for the owning deployment route.
The serving lineage is local, so the roadmap records its exact source and
binary digest without publishing the receiving branch.

The same binary passed the signed Codex–Claude–Codex journey using native
Claude Code 2.1.332 and Codex App Server 0.167.0 with loopback inference.
An unavailable Claude transcript led to a visible answer in 2,897 ms and a
missing Codex rollout led to a resumable successor and visible answer in
673 ms after the explicit retry. Each stage made one loopback inference call,
zero real provider calls and zero redispatches of prior instructions. Claude
reported 8 fixture input and 4 output tokens. Codex reported 218 fixture tokens.
These are local fixture measurements. A separate run passed direct Telegram
voice ingress with simulated transcription and preserved the native Claude
session and original audio digest.

The first composition incorrectly treated the journal entry for an owned,
same-thread goal original as a competing route. The serving build passed
that scenario. The successor admits the exact owned direct original or
accepted first-hop original while refusing a competing instruction. All four
goal-control scenarios passed with synthetic native peers, including stale and
withdrawn originals and uncertain outcomes. The Antigravity SDK fixture passed
with the SDK environment selected by
the current profile, using synthetic Matrix authority and loopback inference.
It verified the original and return, uncertainty and retention across restart.
The Antigravity configuration preflight covers profile loading only.

The earlier candidate `5594ed0f` passed paired Conversation voice, native
Claude attachments and the signed cold project round trip with loopback
providers. The receiving candidate `65666c4e463927c3c195b0ab8c0d6a2d5257cd78`
adds the then-serving `61c01d15` Telegram album lineage and
[PR1139](https://github.com/AlterMundi/DaimonApp/pull/1139) at `8236537f`,
including the room work, result and question surfaces. Gateway binary
SHA-256 `34cb5cadb28f2a1cb3700c119b087ac37e6828d95dd46fcf65490f0a08580d9e`
passed read-only preflight on that active Ítaca profile with the same
running service PID. The composed Dashboard passed its Workspace, frame,
request-control and 17 Sonic tests. Signed receiver fixtures passed the
project round trip, both voice surfaces and album rollback across the
same journal. The cold fixture reached visible Claude and Codex answers
in 3,164 and 609 ms, respectively, with one loopback request per leg
and zero earlier instructions redispatched. The album fixture verified a
single native input for the album, a separate late original, and no duplicate
admission of a redelivered member after restarting with the previous binary.
The production selection remains with Portability.

#### Owner handoff for the live checkpoint canary

Portability owns selecting the compatible Gateway package and its dashboard
and adapter. Compare the package with the then-serving lineage and retain
its exact loaded sources and rollback through the existing receiver. The
private candidate record on Ítaca holds the binary digest and fixture
receipts. The running profile already has its workspace root. The private
Holodeck project has its own Git origin, a verified commit and a retained
DaimonCards receipt. The live own-native reader in this cut confirmed the
same receipt and card revision three with the original Git link current.
The combined Holodeck candidate below preserves the serving world.
The loaded bridge lacks the topic-room operation, and the loaded Gateway
does not serve the project reader. The current shared Home profile already
enables workspace access. Select the compatible Gateway and Dashboard
first, then the matching bridge and Holodeck candidate through their
existing owners. Keep the current pair and use the then-serving release
as the rollback reference. The pilot has no accepted topic checkpoint yet.

1. Select an existing authorized workspace for the pilot, or adopt its
   folder through Session Workspace. Confirm the exact Git origin and
   commit with the checkout verifier. Keep the existing project UUID,
   repository UUID, board and audience.
2. Use one real retained Observer or general-conversation citation that
   addresses the pilot topic and names the link and next work. Apply it
   with the `project_checkpoint_shadow` writer. Read the exact resulting
   revision and verify that the unchanged operation returns its original
   attribution. Confirm that the room catalogue projects the same
   repository without exposing the private origin.
3. Use `select_recovery` for that revision and the original effect receipts.
   Observe one result with current canonical coverage and one unresolved
   effect. Confirm zero additional dispatches at their owning writer.
   Qualify the cold path on a canary binding without removing any live
   topic history. Retain provider calls and tokens, observed latency,
   native completion and destination receipts for both directions.
4. In the paired Holodeck room, open the linked project and read the
   existing card and Git revision. A person makes one ordinary journal
   edit and the authorized native reader observes the same change. Check
   the competing claim and original receipt in that shared project.

Live provider measurements, receiving replies in both directions, and
the paired human questbook edit remain open.

Project coordination in Matrix refers to those same card identities. Use the
existing conversation and graph surfaces to find work, announce changes and
return results. One authoritative writer advances each card. Git owns project
files and commit references and may carry card exports. Imported or offline
project edits do not act as a second card writer. Existing projects
keep their selected tracker, and shared views link to it by stable identity.
Run the pilot with a real remote and multiple participants to learn which UI
and workflow support we need to maintain locally.

## References for visible work in topic rooms

- [Star Office UI](https://github.com/ringhyacinth/Star-Office-UI/blob/master/README.en.md)
  maps a few activity states to visible places and poses. Use that readability
  in the default room so a visitor can understand it on first entry.
- [Pixel Agents](https://github.com/pixel-agents-hq/pixel-agents) makes
  tool activity and requests for human input visible. Use a spatial cue
  to bring attention to a real question and open its authorized answer action.
  [PixelOffice](https://github.com/KalebKE/PixelOffice) shows a comparable visual
  vocabulary across Claude and Codex. Reuse Observer and the current native
  observations across harnesses as the source for those cues.
- [OpenClaw Office](https://github.com/WW-AI-Lab/openclaw-office/blob/main/README.en.md)
  combines a spatial overview with timelines and workbenches. Use progressive
  detail in Holodeck. The room shows the latest useful result at the relevant
  project table and opens its actual artifact or revision on selection.
  A visitor may inspect attributed history as needed.

For the initial room, keep the main cues to current work, a question for the
visitor, and a result ready to see. Quiet, stale or missing observations should
stay quiet or show uncertainty. Derive room cues from current authorized
Observer, Conversation, human-task and project events. Render transitions
without model calls or duplicating those event streams. Keep ordinary room
activity distinct from who receives the next human intervention.

## Milestones

1. **One conversation across surfaces.** Use Holodeck to Char Design as the
   receiving test. From an already settled Telegram original in a Codex topic,
   deliver an attributed request and its references to the Claude history that
   handles the person's direct messages. Verify the request and answer in the
   selected views and incorporation of the return at the origin. Include idle
   resume, steering during a turn and recovery from known-unsent and uncertain
   dispatch. Preserve useful work before retiring an incorrectly opened history.
2. **Durable topic state.** Give the logical topic a stable workspace and links
   to projects. Reuse Observer evidence and the general conversation for
   checkpoints of decisions, open dependencies, revisions and receipt links.
   Compare the checkpoint against retained evidence before consuming it.
   Qualify cold recovery in both directions with Codex and Claude, then with
   other adapters. With native history removed in an isolated fixture, the first
   useful turn finds the right workspace and checks the original effect receipt.
   Cover both a receipt that resolves the effect and an outcome that remains
   uncertain. Preserve the original ID, continue independent work, and verify
   zero duplicate dispatches at the component that owns the effect.
3. **Default project creation and shared delivery.** Start from an ordinary
   request for continuing work in a topic. Verify that the daimon creates or
   reuses the linked project, Git repository and issue tracker, and records
   the first actionable issue. Complete this path without a forge account.
   Pilot versioned cards and commit-based review in a real non-code project
   with a shared remote and human and daimon participants. Show assignment,
   attributed review, offline edits, card synchronization and recovery across
   two workspaces. Verify that the Rust writer and A2UI views preserve one
   authority per issue or quest. Publish one deliverable and open the same
   exact revision from its topic room in Holodeck and its authorized web
   viewer. In each view, confirm the current audience and preservation of the
   published revision while later work is a draft. Run the
   [Holodeck topic-room delivery sequence](#holodeck-topic-room-delivery)
   in the same pilot with a pair that starts without a house or authored rooms.
   The [forge-independent issue writer](../components/daimon-cards/README.md#projects-without-a-forge)
   now records the first issue in the project's existing board. The fixture
   creates it through the owner adapter, reads its exact retry receipt and
   projects its description in Questbook. The same issue accepts one of two
   competing assignments and retains its description and Git link after
   reopening. The [Holodeck receiver fixture](https://github.com/AlterMundi/holodeck/commit/b1a9decd66ac5703008e1e8628beeb96d410039e)
   uses that writer at Matrix `1983c43`. In the fixture, the native route
   creates an issue with the receiving actor's access, the authenticated
   web route projects that same issue and revision without caching, and
   the exact retry returns its original receipt with one history event.
   Revoking the native read grant denies receipt access. Desktop and mobile
   Chromium both show the issue description and recover its shared state.
   The [Questbook creation form](https://github.com/AlterMundi/holodeck/commit/fb31304f7457ecb9bf387b001d918f3a787a0882)
   also creates the same typed issue when a person supplies a description.
   Its browser fixture drops the response after the writer commits, reloads
   the scoped form, and confirms the original description and receipt under
   read access with one creation request. Rebuild the browser bundle before
   running the fixture. Live adoption requires the matching issue-capable
   writer. The full topic-to-deliverable path remains open.
4. **Continuity between bodies.** Verify signed `/we` request, reply and
   receiving uptake on the same host and across hosts. In a fresh body verify
   its installed orientation, memory access and published skill versions.
   Attribute the result to its actual body and preserve each audience.
   Publish the maintained contract and orientation through the existing Skills
   and Source/Weave adoption routes. Verify the source revision actually
   loaded on the selected body and retain audience limits. The
   [foundation](foundation/daimon-matrix.md) and its
   [living-in-the-present companion](foundation/living-in-the-present.md)
   orient continuity. The project checkpoint retains work and
   commitments; being-level learning stays with the selected memory and
   skills. `/tribe` project collaboration follows authorized relationships and
   resource access. Verify a distinct authorized Tribe participant can retrieve
   and use the selected guide revision and shared card within that audience.
   Their view must not expose private topic or being-level memory.

   The [portable Gateway guide](https://github.com/AlterMundi/Skills/pull/402)
   is integrated as Skills commit
   [754d2cf](https://github.com/AlterMundi/Skills/commit/754d2cf9f406c4669eb0d23376fa789f2b86d598).
   Selective installation and rollback passed in an isolated receiving root.
   On 2026-11-28, the existing Ítaca skill binding installed `daimon-gateway`
   1.0.4 from that exact commit and its surface check passed. This records
   installed bytes before any fresh harness uptake. The Codex body’s native
   Foundation scope and Source owner reader returned `authentication_failed`
   after its descriptors expired at 07:31 UTC. The separately signed Claude
   body on Ítaca authenticated through its existing Weave writer and published
   a shareable `skill.proposed` offer for that exact Skills commit. The
   authenticated local reader confirmed event
   `0dbb6af6-6a55-531d-ade3-fa8c90cf3fd8` at sequence 41 with content hash
   `8b291ca362cfecf3252d7b280a1694330165e051389fe1374ee9a341b213bc2b`.
   Its causal parent `8371e543-2f51-5f86-9bfc-dee8b6f7c390` retained an
   incorrect documentation URL; the successor corrects that locator and
   references the same package bytes. The Antigravity body authenticated,
   found no copy of the corrected event, and reported the Claude peer
   available. The receiving heads lack the predecessor chain needed by the
   existing sync, which pages intervening events without a subject filter.
   This guide verification did not transfer unrelated events. The Claude
   body also signed the Source claim
   `d563424b-ea95-472c-8cba-c38a220c0b9f` and the `tribe-shared` publication
   `e8811d4e-28be-4a4c-9cb0-fd17a2569694` for this initiative. Authenticated
   `source.status` returned one claim and that exact publication with content
   hash `f770aa47edba1d55f9d918fe14e0be3b336c03e82188505a03553847aa600dc9`.
   The publication carries a locator and release hashes. Its evidence and
   provenance objects use canonical JSON; the first noncanonical claim
   attempt was refused before signing. The serving Claude runtime connects
   Source and the relationship authorizer after constructing the registry.
   An authenticated owner-local read identified 43 full-origin events,
   including 29 unrelated personal events. The legacy full-origin guard and
   its distinct-being fixture preserve those event sensitivities.
   The installed [selected-source V1 exchange](../specs/source-selective-learning.md)
   solved the transport boundary for the existing guide. Claude exported the
   two exact signed Source envelopes and their provenance with zero unrelated
   origin events. CompAII's Antigravity body created its own signed starting
   cursor, previewed and pulled the page into SourceCAS. The first unsigned
   preview could not authorize a pull and landed no data. The successful
   `dm.source-pull-result/v1` retained both envelopes and one quarantine
   decision, `c4e748e6-1d35-4d96-993c-9a2d785e629c`. The authenticated
   Antigravity reader resolved the original publication event. An operator
   verified the signed locator against the upstream Git object and the local
   installed 2,260-byte guide. Both copies have SHA-256
   `02947f30f1c95ca3bf80e8a445ea39979fea2c4da87bbe7df2370a0a2b6470df`.
   Antigravity's owning Source path admitted the exact participation claim
   (`1f21e3d7-6f43-4adf-a0ab-c3d550fb9535`) and then returned an
   active external-reference projection for the original publication under
   decision `4875eb48-d3c9-4e90-9967-072a068200e5`. This confirms operator
   review and Source adoption with zero model calls. A later authenticated
   Antigravity read confirmed that the active external reference still
   resolves to that exact publication, content and decision. The serving
   Claude body independently confirmed the exact Weave offer and Source
   publication hashes through its current read grants. The five
   installed Gateway skill files matched the signed locator's pinned Skills
   commit byte-for-byte, and this Codex turn used its project guidance.
   Antigravity's model uptake remains unobserved. The Source writer profile
   correctly refused a projection read before dispatch, and the CLI now
   returns the documented authentication exit for that case. The same selective
   publisher read for Oliva returned `source_disclosure_denied`. On
   2026-11-28 the loaded Claude owner socket authenticated both
   `source.status` and `relationship.status`. The original publication
   remained current. The publisher's verifier saw 15 complete relationship
   events and one Tribe, with zero resource cards, bilateral relationships
   or grants. Foreign Source disclosure checks for a current signed
   knowledge card matching this Source ID and classification, and a current
   read grant for that resource. The missing resource registration is
   sufficient to explain the refusal on this publisher. Reconcile the
   registration and exact read authority through the relationship owner
   before trying the selected pull again. A later authenticated Codex
   read found current publisher card `e85346b4-0ebe-450f-aff2-0dcca458e210`.
   The card has three knowledge resources and no descriptor for this guide.
   Codex has four active relationship records with Oliva. Its six active
   publisher relationships use the v2 offer format. The exact additive
   candidate registers this Source ID with the existing `tribe-shared`
   classification and only the read operation. The v2 payload validator
   accepted the candidate against the current card and its predecessor
   reference. All three existing entries stayed identical. This was a
   preparation and validation of unsigned data. Keep the current signed
   relationship and grant history intact; verify current publication-side
   adoption and the exact guide read authorization before retrying the pull.
   The current publication candidate checks the signed card predecessor
   before authoring. The authenticated local fixture accepted one of two
   competing proposals. In an interrupted-write fixture, the original
   request recovered its signed event without an additional ledger event
   and the competing request was refused. Live registration needs the
   compatible relationship writer; the unsigned candidate is still retained.
   The first SDK packages qualified the supervisor import environments.
   The authenticated Codex group responder has a separate process. Its
   loaded SDK and the Claude responder's SDK both match all 90 Python
   modules in `e7e5822d187adb3a519ab5750d7161a4749f052a`. Preparing an
   SDK successor for the responder therefore needs a single common
   candidate. Source `db8a086390ff00f420e94a05052b7233d652ff93` applies the
   guard to that exact SDK and passes the signed publication and disclosure
   fixtures. Cluster sealed the 31-wheel candidate with Matrix wheel
   SHA-256 `a258b423c1947a6c4509f5e7bc7cad6fefe0f1245611071ffc61dc2bf3a8cd73`.
   It retains the 30 dependency wheels of the previous qualified SDK.
   Its installation was verified offline in a disposable environment.
   The protected owner route targets the actual Codex group socket, and
   the authenticated process reported the controlled reader active.
   The retained maintenance route's expected values differ from that
   process on all six selection fields. Reconcile the predecessor approval
   with the current signed startup observation before using the scoped
   selection and rollback route. Both responders still use the prior SDK.
   Oliva received the public, immutable Skills locator in a
   directed signed Tribe message, `38c8d27c-0955-43e4-890e-3332653a7f88`.
   The author's authenticated delivery readback proved Oliva's receiving
   copy with the signed terminal receipt
   `e8adbe47-5a62-4f52-8970-7e6a214417c7`. One other Oliva route had no
   confirmed reader and was never attempted. The signed delivery proves
   the route for this guide announcement. Foreign Source intake and use by
   a receiving model remain open.
   After the Codex owner descriptors were renewed, the local signed reader
   returned `dm.scope.we/v1`. The MCP connector in the already-open turn
   still returned `authentication_failed`. Codex's current Source writer
   created its own signed starting cursor, selected the existing publication
   from Claude and pulled the exact claim and publication into quarantine.
   The authenticated readback matched the original publication hash. Pull
   `aa6cbcc2-3423-468f-9696-bc634e1718c4` retained two origin events, zero
   unrelated events, and invoked zero model calls. This is Source intake
   for the Codex body. The installed skill and existing Source adoption
   in Antigravity are separately evidenced above. The Codex cursor and
   Antigravity's retained assessment name the same Source assessor.
   Selected-source intake carries claims and publications. Reuse the
   original signed assessment when reconciling across bodies, without
   opening a competing first assessment in the same series.
   Ítaca preflight found a 1,495,826,432-byte ledger on the active
   runtime, above the previous 512 MiB owner-tool limit. The bounded streaming
   candidate preserves the exact inventory digest, as verified with an
   equal-sized disposable ledger file. A separate signed SQLite fixture
   stages and publishes expired-profile renewal while retaining ledger bytes.
   The [streaming operator](https://github.com/AlterMundi/daimon-matrix/commit/074468fdb97d8eb18f291d904b1212c990ca8672)
   also passed all 24 capability-upgrade tests on an isolated copy of
   Ítaca's selected Matrix SDK (`e7e5822d`). The selected wheel's operator
   matched the patch preimage byte for byte. Ítaca's active visibility
   installation pins the SHA-256 of its current runtime bundle. The live
   renewal must republish that installation through the owning signer and
   verify the new load under the same fence. The existing Cluster Source
   lifecycle's controller-only renewal refuses expired original roles. Its
   predecessor freeze also starts with an authenticated original-role read,
   which cannot supply fresh evidence after that role expires. The isolated
   combined recovery now proves renewed runtime publication, refusal of the
   stale signed visibility installation, rebound visibility load, and an
   authenticated `scope.we` read. Rebinding retains the disclosure and
   publication configuration. An exact retry adds no new generation. The
   [Cluster predecessor observation](https://github.com/nicoechaniz/daimon-cluster/pull/576)
   pins the same-owner socket peer and the exact systemd parent, unit
   fingerprint and invocation before any renewal. Its read-only live run on
   Ítaca identified the existing native child and service parent without
   sending a native RPC. The owning lifecycle still needs this observation
   wired into the signed original-profile transaction, matching visibility
   activation and authenticated post-start read. The service kept running
   throughout that recovery qualification. The guide offer did not invoke
   a model or authorize installation on a receiving body.
5. **Migrate existing work and tidy the environment.** After the contract pilot
   passes, migrate one existing topic and its linked work. Compare a shadow
   migration first. Reuse its logical ID, native binding, repositories, trackers
   and original sources. Backfill links and checkpoints supported by retained
   evidence. Preserve the topic-to-room binding and any existing spatial
   work. Verify that the selected project revision, next action, local
   drafts, permissions and uncertain outcomes remain usable. Use the pilot to
   refine the workflow. Once it works in ordinary use, apply it to a few more
   topics, then to the full inventory in bounded batches.

   Include workspaces, build outputs, caches and copies in the inventory.
   Check what active topics, workers and projects still use. After verifying
   the migrated work, use the existing cleanup tools to retire unused,
   reproducible outputs and redundant copies. Preserve originals, local and
   staged edits, receipts, current dependencies and required recovery data.
   Verify that affected projects can still open or build and record what was
   reclaimed. Existing host and preservation holds remain in force.

   Record the ITACA storage baseline separately from the cleanup inventory.
   On 2026-11-28, Nicolás reported **156 GB free** on ITACA's large disk.
   At 04:47:40 UTC, `df -B1 --output=source,size,used,avail,target /srv`
   identified the filesystem as `/dev/md5` mounted on `/srv` and measured
   **164,422,127,616 available bytes** (153.1 GiB). Use this byte count for
   the like-for-like comparison and preserve the reported figure as observed.
   After all topic batches and their cleanup are verified, rerun the same
   command and record the final free bytes and the difference. Report the
   inventory's reclaimed bytes separately, since concurrent storage changes
   can affect the net difference. This baseline requires only a read.

   Reconcile each batch with the inventory. Keep original dates and authorship.
   Record missing evidence and topics with no continuing project explicitly.
   The final check resolves the current revision and next actionable work
   from the migrated topics without relying on private native history or
   duplicating an earlier effect.

## Holodeck topic-room delivery

This is the implementation sequence for the spatial part of milestone 3.
Each item names the behavior to deliver and what to observe in the pilot.

The [receiving composition](https://github.com/AlterMundi/holodeck/commit/e95652ca52963245bb5d80dff46882ca1aa6d6ba)
brings PR40's topic rooms into the paired Questbook Workshop release from
`45f27ae`. The existing A2UI toolbelt now exposes the project table,
conversation, and return navigation in a topic room. The composition
preserves topic scope on retained machine-context receipts and rechecks
current access on recovery. A topic receipt cannot authorize an action in
the physical world. The HTTP test covers that distinction after release.
The mobile Chromium journey passed on that revision. It entered from
the explorer, opened the project table and a door for the selected project,
and read the selected question and result. It recovered a committed
mission from its original receipt after loss of the response, checked
current project access and concurrent edits, changed Conversation's
recipient in the room, and returned through the spatial minimap. It
verified the exact sequence of work and travel writes independently of
renderer pose presence. The exterior Questbook and reload tests also
passed on the integration branch. This branch is a candidate on the pilot
release base. Live adoption and paired use of the composed surfaces
remain open.


A production comparison on 2026-11-28 found Holodeck archive
`c7a92cd8a6aa` serving source `0679a01`. The [updated topic-room
composition](https://github.com/AlterMundi/holodeck/commit/2486d45e3816080b641bbdad06d2205e1c73e2f5)
includes that source and keeps its flight, locomotion and terrain modules
byte-identical. The installed Home verifier accepted the 96-file,
40,448,000-byte candidate archive, SHA-256
`c3e809dece1c4e0cce996c81009e4b6a1c6851f26579fb650809f142129ad85d`.
The exact archive booted on the installed Node 24.21.0 runtime in
production mode against fixture Home and bridge sockets. It checked
health, protected HTML, room entry, Git revision projection and both
levels of revocation with zero model calls. Eleven tests passed across
the Chromium journeys and associated HTTP and frame checks. The
standard Node suite passed 594 tests with six fixture-dependent skips.
The native bridge suite passed 53 tests.

The issue form is now packaged as a successor candidate. The installed
Home verifier accepted the 96-file archive at Holodeck `fb31304`
(40,458,240 bytes, SHA-256
`d35db05311c4b808d505eae0c7bf18441c54173c988efb87f74b71f7cb90bbb9`).
The manifest retains 92 files from the prior candidate byte-for-byte and
changes only the HTML, packed browser bundle and bundled server. Pair it
with the Matrix `1983c43` issue writer, SHA-256
`f0a60d4838dace536b7638d293f33f3e9bffe8a804344ac4a8c22411f4095425`.
The [packed receiver fixture](https://github.com/AlterMundi/holodeck/commit/9e2a176)
runs the protected HTTP and browser journeys on those files with Node
24.21.0. It verifies receipt recovery after the browser loses the response.
The successor writer also reopened a disposable store from the installed
predecessor and returned the same card, original creation receipt and one
history entry. After an issue has been written, retain that writer when
rolling back the UI. Production candidate selection remains open.

The current own-native route re-read the real Git-review mission at
revision three with its original receipt and Git link. The unselected
bridge source from the updated composition read the current Matrix room
and work status using the existing Home pair and the running Gateway.
The same read could not obtain a project catalogue from the loaded
Gateway at `61c01d15`. The loaded bridge also uses a provider without
the topic reader. The compatible bridge source SHA-256 is
`f5aa77fb00c7e4641269a6738fa40336e92614412af9ca9527d28889944dbfbd`.
The existing pair and workspace grant were sufficient for the room
read. The checks submitted no originals and changed no active services.

1. **Explorer and default rooms.** Add an entry widget that opens the current
   authorized topic catalogue and moves the visitor into the selected virtual
   room. Use the logical topic reference from the existing Session Workspace
   reader. The [Gateway candidate](https://github.com/AlterMundi/DaimonApp/pull/1137)
   has the read-only catalogue and exact-room lookup. The
   [Holodeck candidate](https://github.com/AlterMundi/holodeck/pull/40)
   connects the explorer through the bound Conversation frame. A narrow
   Chromium fixture with no house verifies discovery, exact-room readback
   and refusal after access is withdrawn, with no original submitted.
   The same candidate generates an empty MML interior through the paired
   owner bridge and mounts it in the existing movement and presence flow.
   The narrow Chromium fixture enters from the plaza, renders the room,
   returns to the plaza and refuses a revoked topic. A state test verifies
   return to an authorized physical interior without changing its saved
   location. Navigation sends no human original or model request.
   Selection in the live receiver and use by real participants remain open.
2. **Rooms that grow with the work.** Derive doors, tables and the shared
   questbook from authorized project links and work records. Start with an
   empty room, add two projects and observe the appropriate surfaces appear.
   Enter one project through a door. Use a table to open or combine material
   from both projects, with each edit reaching its actual project revision.
   Open a mission from the same DaimonCards state seen outside Holodeck.
   Keep denied project links private and confirm that ordinary changes and
   re-entry require neither setup work nor a model turn. The candidate
   project table reads the current topic catalogue on opening, groups recent
   repositories by project, and shows their exact Git revisions without
   exposing raw repository locators. The isolated Gateway owner fixture
   checks three links across two projects and omission after correction of
   the cited source. The mobile browser fixture verifies an empty room,
   new links, a changed revision and an omitted repository. The catalogue
   can be browsed across pages. The isolated owner fixture verifies ten
   links and the stale-cursor restart. Mobile Chromium verifies forward,
   back and return to the current first page after a catalogue change.
   The table can open a project-scoped repository view inside the room.
   The owner fixture opens a project whose links are on a later catalogue
   page. Mobile Chromium verifies opening from the table, returning to it,
   and refusal after the selected link is revoked. Holodeck projects a door
   per project on the first catalogue page. A mobile Chromium visitor taps
   the rendered door, opens the same scoped project view and leaves the
   room without retaining its door geometry. Additional projects are
   available through the table pages. The [project-scoped questbooks](https://github.com/AlterMundi/holodeck/commit/66172dfcd8dd486afce5428e365014eac9884a48)
   use each selected project's current room link and its own view and edit
   grants. The isolated mobile fixture opens both journals from the same
   room, reads a daimon-authored mission, accepts it through A2UI, and reads
   the same updated revision through the card writer. The other journal is
   read-only: it refuses that project's card from the first journal, and
   denies access after revocation. The protected native fixture independently
   checks explicit project selection, read-only access and denial of a write.
   The [journal recovery fixture](https://github.com/AlterMundi/holodeck/commit/9b1f947c2fe00299b3759c16cf73837ad125e25f)
   loses the first creation response and its initial receipt read. The same
   browser creates a different mission in the second project, returns to the
   first journal, and confirms the original creation from its exact receipt.
   The first project records one POST and one creation event. The
   [reload recovery fixture](https://github.com/AlterMundi/holodeck/commit/b92fcd78decfc50df8fd155ae9e1d03da70c8bdf)
   extends the same recovery to a reload of the original browser tab. It
   drops the creation response and the first receipt read, then removes
   write access before reload. Chromium recovers the original receipt with
   read access. The real DaimonCards writer reports the same mission at
   revision one and the browser observes a single creation POST. The
   authenticated HTTP fixture refuses a changed actor or default project.
   The local tab retains up to eight entries scoped to actor, project and
   the original linked room and repository. Separate project interiors,
   selected production deployment and real paired human use remain open. See
   [Gateway PR1137][direct-gateway] and [Holodeck PR40][direct-holodeck].
3. **General Conversation in context.** Keep general Conversation selected
   when the visitor enters. Show the current room and recipient. Send a
   human intervention and verify that general Conversation receives the
   exact original once, with the topic, place and selected object captured
   at intake. Move while receipt is pending and verify the original keeps
   its captured context and destination. The Holodeck candidate opens the
   general Conversation frame from the generated room. Its HTTP receiver
   fixture switches topics while preparation is pending and recovers one
   attachment with the original topic under current access. Actual
   canonical original admission and live receipt readback remain open.
4. **Visible work, results and questions.** Use authorized Observer states,
   canonical results and human tasks to show the same daimon at work in the
   room. Keep signals legible without reading a transcript. Observe a real
   work-state change, open a result from its project table, and answer an
   existing pending question through its original writer. Verify stale and
   inaccessible states and retrieve the attributed history on demand.
   [Gateway PR1139](https://github.com/AlterMundi/DaimonApp/pull/1139) projects
   three bounded signals from the existing Session Workspace reader into
   the exact authorized room: observed execution, a pending human question
   and a canonical result. The general catalogue and embedded frame keep
   their original shape. A stale native observation is unknown.
   [Holodeck PR40](https://github.com/AlterMundi/holodeck/commit/4d7331023d2839834f8fca55375a0b863decdbf8)
   validates the observation through the paired bridge and shows it on the
   existing project table. The owner tests cover a binding change and a
   stale observation. The HTTP and browser fixture exercises the same-room
   read, a different-room refusal, a new result after activity becomes
   unknown, and omission of private native metadata. This path reads no
   transcript and sends no model input. The
   [result action](https://github.com/AlterMundi/holodeck/commit/98caff0)
   opens the current result inside Conversation from the same table.
   [The Gateway reader](https://github.com/AlterMundi/DaimonApp/commit/d5637b8b)
   revalidates the room and uses the ordinary selected-session page. It
   declines a mismatched Codex result revision and keeps the result body
   inside Conversation. The Workspace fixture checks the result match and
   refusal after cancellation. Chromium checks the host-to-frame journey,
   unchanged general recipient and dismissal when closing Conversation,
   with a controlled result response. A result outside the current bounded
   page remains unavailable through this shortcut. The
   [question action](https://github.com/AlterMundi/holodeck/commit/b2428b0)
   opens the existing For You dialog inside Conversation. The
   [canonical request reader](https://github.com/AlterMundi/DaimonApp/commit/8236537f)
   filters current actionable questions to the exact room destination.
   Chromium checks that the other topic's question stays out of the
   dialog and the general recipient is preserved. The request-controls
   fixture verifies a single, explicitly chosen answer with the original
   question and revision, and lookup through a later pending page.
   Internal-only questions stay with their owning session. Live paired
   use, its decision receipt, and spatial work cues remain open.
5. **Explicit direct mode.** Add an in-room choice to address the topic
   directly. Show the topic history in canonical Conversation and make the
   active recipient unmistakable. The general avatar can step aside or
   visibly yield. Send one original and confirm receipt in that topic.
   Return to general Conversation while staying in the room, then leave.
   Recover both drafts and unresolved receipts without changing their
   destinations or replaying the original. Gateway's candidate uses the
   existing Session Workspace selector with the current owned destination
   and keeps direct drafts and unresolved original references in a separate
   tab scope. The Holodeck candidate verifies the actual frame protocol in
   mobile Chromium with a controlled destination reader: direct selection,
   confirmed audience, return on departure and a refusal after revocation.
   A new Conversation document returns to the general audience. In the
   mobile browser fixture the paired avatar portrait steps aside when the
   frame confirms the topic and returns when general Conversation is
   reselected in place. This is the local recipient indicator; visible
   topic work has its own acceptance above. Live native admission and
   receipt for a direct original remain open. See
   [Gateway PR1137][direct-gateway] and [Holodeck PR40][direct-holodeck].
6. **Optional return to general Conversation.** Offer a way to speak to the
   general conversation after a visit or share a selected attributed update.
   An automatic handoff is an optional setting using that same route. Check
   delivery and audience for a selected handoff and verify that crossing a
   room boundary by itself produces no send or model turn.
7. **Optional customization and re-entry.** Let the pair add a custom room,
   a house entrance or both when they want them. Re-enter from the explorer,
   the house and a non-spatial client. Check that the logical topic,
   conversation, project revisions, missions and unfinished work are the same
   across all entry points.

## Additional harness pilots on ITACA

Antigravity is the next receiving pilot. Bind its existing topic to the
selected `agy` CLI and qualify the actual end-to-end route. The Antigravity
SDK with a local model is a separate qualification. Then qualify Muse Code
in its existing topic with the selected subscription. Goose remains the
minimum Rust harness candidate. Continue with Qwen and MiniMax CLI after
these pilots. Verify each selected profile and portable embodiment through
the existing admission path before treating the harness binding as ready.

Compare `muse serve` using the Muse Session Protocol with Muse's experimental
ACP v1 route. The native protocol offers exact-turn steering, command IDs,
targeted interruption and session replay. Use these through the same Gateway
harness contract where ACP cannot meet the receiving acceptance test.
[Muse protocol](https://meta-models.github.io/muse-code-sdk/1.4/guides/msp-concepts/)
and [Muse ACP](https://meta-models.github.io/muse-code-sdk/1.4/guides/editors-acp/)
define the provider surfaces.

Portability owns operational repairs, live qualification and these additional
topic admissions. The contract work consumes their attributed evidence and uses
the existing Gateway deployment route. Isolated shadow work can proceed before
those live checks finish.

Use the same test across the pilot topics and the existing Codex and Claude
topics. Admit a request, observe its attributed progress and final return,
recover useful context after a restart, and exercise the available native
steering or queued-input behavior. Verify the actual recipient and visibility
from each surface. Use the same Gateway entry points for those operations.

## Evidence for a Claude engineering partnership

Demonstrate a reproducible case using synthetic project data and a real Claude
Code or Agent SDK session. Show a normal turn, a correction while a tool is
running, a result returned from another harness and resumption after an
interruption. Publish the shareable fixture, version matrix and failure cases.
Record deterministic fixture results, real provider results and live receiving
acceptance separately. Keep private conversations and account details out of
shared evidence.

Measure provider attempts, input and output tokens, time to incorporation and
recovery, preserved references and duplicate external effects. Qualify
transport and failure recovery with deterministic fixtures first. Use Claude
capacity for behaviors that those fixtures cannot establish, including resume,
compaction, steering and cross-harness recovery. Size the sponsorship request
from measured usage and the remaining test matrix, with a bounded run budget
and a published evidence deliverable.

Compare checkpoint overhead with a warm resume and a cold recovery. Track
tokens and provider calls per useful iteration, including retries and manual
reconstruction. Keep a checkpoint step when it measurably reduces repeated
work, lost context or unresolved effects.

[direct-gateway]: https://github.com/AlterMundi/DaimonApp/pull/1137
[direct-holodeck]: https://github.com/AlterMundi/holodeck/pull/40
