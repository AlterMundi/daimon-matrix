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
or commits. Compare a Git-backed card writer with the self-hosted mode in
[Stage 11's Lattice v2](https://github.com/Stage-11-Agentics/lattice/tree/8736575d11853b1b90c4e49685747a53f13a9e6c).
The latter has an event log, task snapshots, a dashboard and an HTTP API. Check
concurrent claims, authenticated attribution with our existing identities,
state recovery and portable export before choosing a writer. Keep paid or
model-driven review automation out of the pilot's ordinary card operations.

Daimons read the card model and submit typed operations programmatically.
An [A2UI](https://a2ui.org/) surface projects that model to humans as a card,
board or review. Its component tree, selection and drafts are view state.
Both routes use the same card IDs and operation semantics. Writes carry the
expected revision and an idempotency key. The writer returns the resulting
revision or a conflict that the view can show and refresh. Ordinary viewing,
assignment and state changes work without a model turn. Prove that a human
without a forge account and a daimon can act on the same card and see the
result from their respective surfaces.

Project coordination in Matrix refers to those same card identities. Use the
existing conversation and graph surfaces to find work, announce changes and
return results. One authoritative writer advances each card. Existing projects
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
   useful turn finds the right workspace and reconciles an uncertain effect
   without reissuing it.
3. **Shared project collaboration.** Pilot versioned cards and commit-based
   review in a real non-code Git project with a shared remote and a mix of
   human and daimon participants. Show assignment, attributed review, offline
   project edits, card state synchronization and recovery across two workspaces.
   Evaluate additional project-service features against the observed gaps.
4. **Continuity between bodies.** Verify signed `/we` request, reply and
   receiving uptake on the same host and across hosts. In a fresh body verify
   its installed orientation, memory access and published skill versions.
   Attribute the result to its actual body and preserve each audience.

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
