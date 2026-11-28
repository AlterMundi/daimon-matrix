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
| Git and project records | Version project files, card state and exact review revisions. The system that performed an external action owns its outcome receipts. |
| DMK and shared Skills | Preserve being-level memory and published operating knowledge through their existing update and adoption paths. |

Keep the owning source, contract, receiving configuration and regression
test aligned. Record the tested source and runtime revisions in the owning
project. Distinguish queued, incorporated, answered and visible.

## Topic state contract

Each logical topic has a stable identifier, its own workspace and links to
the projects it works on. A workspace provides a base for topic records and
can link to several project repositories. The checkpoint records current
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
move, with matching operation re-reads and conflict detection. Canonical
conversation audience changes, the receiving controller, and cold harness
recovery still require their own acceptance evidence.

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
writer while preserving the viewer's selection or unsaved draft. Holodeck uses
the same project and action identifiers for the game or place it projects.

Project coordination in Matrix refers to those same card identities. Use the
existing conversation and graph surfaces to find work, announce changes and
return results. One authoritative writer advances each card. Git owns project
files and commit references and may carry card exports. Imported or offline
project edits do not act as a second card writer. Existing projects
keep their selected tracker, and shared views link to it by stable identity.
Run the pilot with a real remote and multiple participants to learn which UI
and workflow support we need to maintain locally.

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
3. **Shared project collaboration.** Pilot versioned cards and commit-based
   review in a real non-code Git project with a shared remote and a mix of
   human and daimon participants. Show assignment, attributed review, offline
   project edits, card state synchronization and recovery across two workspaces.
   Verify the Rust writer and A2UI projection using that same journey. Add
   further features when the pilot demonstrates a concrete need.
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
5. **Migrate existing work and tidy the environment.** After the contract pilot
   passes, migrate one existing topic and its linked work. Compare a shadow
   migration first. Reuse its logical ID, native binding, repositories, trackers
   and original sources. Backfill links and checkpoints supported by retained
   evidence. Verify that the selected project revision, next action, local
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

## Additional harness pilots on ITACA

After the current continuity and coordination repairs pass live acceptance,
enroll one topic each for Antigravity and Goose. Use real work that suits the
topic. Qualify both before adding separate Qwen and MiniMax CLI topics. Verify
each selected profile and portable embodiment through the existing admission
path before treating its topic as ready.

Portability owns operational repairs, live qualification and these additional
topic admissions. The contract work consumes their attributed evidence and uses
the existing Gateway deployment route. Isolated shadow work can proceed before
those live checks finish.

Use the same test across all four topics and the existing Codex and Claude
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
