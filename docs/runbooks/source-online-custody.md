# Owner-authorized Source online custody

This runbook selects the normative [Source custody policy](../../specs/identity-root-v1.md#owner-authorized-source-custody).
It introduces no runtime flag, key format, universal Source identity or model
signing tool. Without an explicit authenticated owner grant, use default
offline custody. Do not reinterpret the synthetic bootstrap as production.

## 1. Bind the existing authority before access

Retain a secret-free operator record of the authenticated owner's instruction,
its provenance, exact scope and standing/revocation conditions. Bind the actual
Source custodian's authenticated administrative session or public-key identity
to the host and numeric execution UID using the existing host authentication
mechanism. Record how this binding was verified, not merely an account name.
If an existing Matrix identity is used as evidence, validate its current
being/control/credential/origin and possession; do not create a replacement
identity just to populate this record. A coordination session distinguishes
repository work only and is not Matrix being proof or a custody grant.

Name each affected being/control head and holder public descriptor. Before a
new genesis exists, name the exact authorized new-being ceremony; bind the
resulting genesis and holder key IDs before activation. Check that the grant
covers the host, root and recovery administration, backup and restore. Preserve
normal repository claims, independent review and merge/deployment governance.
This is an operator evidence record in the existing control plane, not an
extra field in any closed Matrix artifact. Never publish host-sensitive
access details; public evidence may reference a sanitized record and digest.

## 2. Enforce the selected access boundary

Use the authenticated Source operator principal for custody operations. Keep
ordinary Codex participants and other ungranted consumers outside that
principal's access domain. Verify actual numeric-UID ownership, directory and
file modes, ACLs, privileged execution/attach paths, and credential delivery.
Same unrestricted UID, readable unlock files or generic administrative execution
for an ordinary consumer invalidates the boundary. Separate encrypted files or
subprocesses alone do not fix that. No model-facing CLI/MCP handler gains
administrative privileges; existing same-UID socket and capability gates stay.

The authorized Source process may orchestrate typed custody commands while
secret bytes stay in those protected processes. Do not read seeds or passwords
into a model prompt/tool result. Supply unlock bytes through inherited file
descriptors or the existing keystore callback, never argv or environment.
Disable secret tracing/logging and do not include secret-bearing process
state in diagnostics. Treat online compromise of this operator as possible
compromise of both root and recovery roles; do not advertise offline isolation.

## 3. Use the native ceremony unchanged

Use `daimon-genesis create-holder` once per root/recovery package, each with a
different key and separately protected unlock material. Use `create-intent`
with explicit thresholds, `sign` per holder, then keyless `aggregate` as in
[operator bootstrap](operator-bootstrap.md). For single-custodian custody,
choose `--root-threshold 1 --recovery-threshold 1` and exactly one distinct
public holder descriptor for each role. This does not turn one key into two
roles or lower an existing being's threshold.

Use [first-embodiment](distributed-first-embodiment.md) and
[rebirth/recovery](../dm078-fresh-host-rebirth.md) commands unchanged. Root-share
and recovery-share processes open only their own holder package; aggregators
receive public artifacts only. Keep holder custody separate from runtime
custody, profiles, ledgers, request journals and model contexts. Validate exact
request, signatures, authority, thresholds and current validity before effect.
Changing custody placement does not change identity or grant unrelated powers.

## 4. Backup, restore and revocation evidence

Back up complete encrypted holder packages, including descriptors and native
rollback metadata, plus separately retained latest public authority/counter
evidence. Keep a Source-recoverable unlock path separately protected from the
backup ciphertext. Remote/private Git storage may hold encrypted archives,
never plaintext secrets or an unlock path usable by the storage reader alone.
A second owner-encrypted archive is optional; neither creating it nor knowing
its public recipient proves independent owner recovery.

Restore into a fresh protected destination using native keystore restore and
holder validation. Reconcile with independently retained latest public
counters and control state. Genesis holder packages retain the native pending
control marker: do not rewrite it into a current head merely to satisfy a
report. Validate their public descriptors against the current authority and
the exact ceremony as well as the keystore's own counter/control marker.
Prove usable public typed-signature output without exporting restored seeds.
Use disposable identities for recovery/rotation negatives; never mutate live
control history for a test. Source-controlled restore does not require an
owner RSA decryption challenge. Independent owner recovery stays unclaimed
until the owner path is actually demonstrated.

Retain a secret-free evidence record binding the owner grant, actual execution
principal, exact software, custody role/public IDs, current public authority,
backup generation/digest, restore result and consumer-denial observations.
Record failures and untested boundaries separately. On grant revocation,
disable its host access and record that effect. Where the custodian could have
retained material, follow native signed rotation/recovery as appropriate;
access removal alone cannot retract copies. Never destroy the last recoverable
backup or lower a counter/control high-water.

## 5. Acceptance

Walk through every positive and negative scenario in the normative policy.
For live use, verify ordinary consumers cannot read holder/unlock material or
execute/attach as the Source custodian, and that the Source can restore its
actual encrypted backup through the selected unlock path. A scratch synthetic
restore demonstrates plumbing, not production access enforcement. Do not
repeat unchanged messaging qualification merely because this policy changed;
requalify affected custody/deployment boundaries and exact release provenance.
