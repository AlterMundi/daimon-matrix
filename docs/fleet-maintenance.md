# Provisioning and ordinary fleet maintenance

Selected direction: Nicolas, 9 November 2026, instructions
`9455dcff-e3a2-5dba-a854-faab6e0b0e53` and
`ede8dab8-29c0-552b-8e78-2f5343ecf858`.
Implementation: [#508](https://github.com/AlterMundi/daimon-matrix/issues/508),
within the existing DaimonGateway milestone. This describes the target, not an
installed fleet API. The full objective remains #437/#302.

The [foundation](foundation/daimon-matrix.md) owns scope and identity. `/tribe`
includes humans and shared resources; its group conversation is one application.
Cluster owns provisioning and physical selection; Matrix owns social authority
and message meaning; DaimonGateway owns durable work and client/harness adapters.
Extend these owners rather than adding another router, scheduler or identity store.

## A lifecycle, not only one-command installation

The maintained owner interface must cover these operations. The verbs below are
requirements, not claims that new CLI commands already exist.

| Operation | Required effect |
| --- | --- |
| Provision/join | Complete the original job and signed membership, then apply the selected profile; Telegram remains optional. |
| Status/diagnose | Show desired and loaded releases, functional health, pending operations and actual failures without a model call. |
| Update | Qualify an artifact once per compatibility class, then converge selected bodies independently. |
| Repair/reconcile | Observe the retained operation and resume only its missing effect; preserve uncertain input. |
| Roll back | Select compatible retained code, preserving current data, keys, history and later decisions. |
| Pause/resume | Reuse heartbeat global/lane controls, separate from global Stop and goal changes. |

One versioned profile pins components, compatibility and configuration schema.
Per-being accounts, voice choices, grants, private bindings and history remain
local data. A common release must not require hand-merging source for each member.
Preserve supported extensions and overrides as configuration or qualified profile
differences, rather than untracked variants.

Reuse Cluster's immutable artifacts, jobs and conditional writers. Each local
writer compares desired with observed state, prepares only missing artifacts,
uses the existing voice/work admission, selects and records its outcome. A second
invocation resumes the same operation rather than recreating identities or
repeating uncertain writes. Inspect effective systemd selection, including drop-ins.
Preserve later local configuration instead of restoring a stale whole file.

Pending tasks addressed to the human are durable work, not active execution.
Preserve their identity, content and state across updates. In-progress answers,
turns and capture, and native questions that startup expires, need their actual
owning continuation or an idle boundary. An unanswered human task must not become
an indefinite maintenance lock. This distinction was verified in the current
Noodles update: its pending task was unchanged after selection.

Use existing bounded workers and Alerts. Every operation has a deadline, work/byte
limit, retained result and stop path; current/compatible rollback artifacts have
bounded retirement. Do not add model-driven polling, an unbounded queue or another
inventory database. The recorded authorized human task is the operational authority;
component ownership locates the writer, not another approval ceremony.

The same retained membership/reader-selection operation must update the monitor's
expected cohort from its qualified result. A stale expected list is monitoring
configuration drift, not proof that a native reader failed. In the current Itaca
incident, the monitor expected three readers while the authenticated seven-reader
selection passed its unchanged validation. Updating only that expected cohort
resolved the same incident without a Matrix restart or reader reenrollment.
Do not change a valid native gate to satisfy an obsolete monitoring snapshot.

## Authority and compatibility independent of a whole-fleet ceremony

Current portable group visibility publication verifies a complete participant
signature set. Keep that evidence truthful, but replace routine recollection
with stable owner-selected publication policy, membership-based authority and
explicit audience/resource limits and revocation. Membership changes and software
adoption must not repeatedly ask all models to confer an already authorized
human decision. Preserve original signatures and old obligations during migration.

Compatible members must remain usable while another body is busy, offline or
failed. Replace manual whole-cohort reselection choreography with per-body writers
and explicit compatibility evidence. Never remove an unavailable member from a
frozen audience. This does not assert that every offline peer currently blocks
every ordinary message.

## One logical message, bounded delivery work

[#498](https://github.com/AlterMundi/daimon-matrix/issues/498) owns durable delivery:
one logical message and frozen audience, per-recipient progress and bounded linked
transport attempts, with recipient deduplication covering the retry horizon.
Transport ACK, receiving copy, publication, model action and reply retain distinct
meanings. Historical expired or uncertain carriers are not renewed or replayed.
Keep the current visibility-before-release policy meaning until a qualified
successor is selected.

The current group contract caps targets and sealed recipients at 256 bodies.
Implement authenticated bounded audience pages under one frozen group/message
identity. Preserve every target and one logical group conversation; do not truncate,
create bilateral onboarding or merely raise a global buffer cap. Fan-out grows
with recipients; routine admission and updates must not require every member to
coordinate with every other member.

## Incremental delivery and proof

### Current seven-body cutover

Retain four exact Conversation disclosures once, including their approved
descriptors, local being and membership references, participants, original issue
time and digest. Each genuine owner derives and compares those same bytes before
accepting them. Batch the four acceptances under that owner's one runtime lock,
retain its bindings durably, release the lock and restore its Matrix immediately.
This produces 28 signatures without model calls or reenrollment. Signature
collection does not publish or activate the children's outbound messaging.

After all bindings are retained, publish and select each child's visibility
through its existing owner writer. Inspect the actual predecessor installation;
the initial-installation path is valid only when no installation exists. An
existing installation accepts only its supported unchanged-policy participant
expansion, not arbitrary replacement. Separate short child maintenance windows
are preferable to keeping all daemons stopped while collecting remote signatures.

The bounded driver retains exact intent, per-owner results, predecessor selectors
and publication outcomes independently of the interpreting turn. Restore only
services it actually stopped while their operation-owned state remains unchanged;
later configuration and pause/Stop decisions win. Resume missing effects from
retained results rather than re-signing or replaying uncertain work.

Finish with authenticated loaded-reader acceptance, current cohort selection and
the corresponding monitor projection, then a useful real message/action/reply
journey. Verify that each paired human can read an actual projected Conversation
message; health, assets and anonymous denial alone do not prove that visibility.
Keep original uncertain carriers and unobserved family-device acceptance distinct.

The first #508 implementation deliverable is the maintained resumable owner
command extracted from this demonstrated operation. Provisioning invokes the
same profile-convergence path after original identity/admission. Policy decoupling
and group paging follow as qualified changes, rather than prerequisites for this
delivery.

1. Finish useful messaging on the existing seven living bodies; retain working
   components rather than making a speculative rewrite the next prerequisite.
2. Move demonstrated selection/recovery into maintained commands and common
   profiles. Ordinary operations must need no manual SSH/source patches,
   reenrollment, repeated approval or per-body compilation.
3. Qualify policy decoupling and group paging with a bounded model-free 400-body
   fixture, explicitly separate from real fleet evidence. Measure signatures,
   verification work, bytes, peak memory, elapsed work and partial-failure
   recovery; preserve one frozen audience across membership changes and resume.
4. Prove join, ordinary update, partial outage, lost ACK, later local configuration,
   retained human tasks and compatible rollback on actual receivers. Include
   mixed compatible releases, operator death during maintenance, authenticated
   Conversation visibility and retention saturation. Rollback compatibility must
   be machine-checkable against current schema and signed authority; where
   promised, qualify the predecessor against successor-written state. Measure
   time from qualified release to served state and retain unresolved effects.

Membership/authority revision, protocol/data compatibility and current process
readiness are independent observations. Compatible code replacement updates the
affected receiver without invalidating unrelated readers. Per-body publication
consent must not become quadratic work on every admission or software update.
If pinned uncertain records exhaust a bounded store, expose backpressure and a
repairable incident; never silently delete them. Account for aggregate fleet
storage as well as each local limit.

Reuse #496 for independent visibility, #497 for harness adapters, #499 for heartbeat
and DaimonApp#452 for backend/client extraction. Preserve Cluster's existing
onboarding ownership and jobs. #508 coordinates this acceptance and missing
maintenance interface; it does not duplicate those implementations or introduce
a new rollout approval stage.
