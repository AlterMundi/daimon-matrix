# Receiver-compatible authority updates

A locally healthy sender does not establish a working cohort. SDK validators,
verified authority histories, application authority pins, visibility acceptance,
and receiving observers must agree before a rollout is complete.

## One authorized rollout

1. Identify required receiving bodies from the installed applications and signed
   body inventory. Record unavailable bodies explicitly; labels are not identity.
2. Prepare the exact candidate SDK and public signed authority chain. Run the
   receiving validator against that chain before irreversible sender activation.
   Stage a content-addressed receiving code/SDK successor using the existing
   deployment adapter, retaining the original context and previous generations.
3. Keep new-epoch egress disabled or the selected Matrix sender quiesced through
   required receiver adoption and republication. An accepted authority commit is
   separate from enabling new-epoch egress: compatible candidate validation alone
   is not receiving readiness. Commit the exact signed authority only after the
   required preflight; once accepted, retain it and recover forward. Publish a
   credential-free update package for offline bodies, without Root custody,
   unlock files, provider logins or private routes. Ordinary code-only updates
   do not manufacture an authority transition or require unrelated interruption.
4. Under each receiver's existing runtime writer lock, use `adopt_peer_authority`
   (or `operator_messaging adopt-peer --peer-authority ... --peer-history ...`)
   for an already-known foreign being. The exact signed descendant must anchor
   the previously trusted control/history prefix. No new relationship ceremony
   is needed. It preserves local identity, custody, grants and routes, and retains
   the original remote ledger while advancing its verified copy.
5. Reload the receiver. Reissue a native visibility installation if it pins the
   changed runtime bundle. `republish --peer-being-ref ...` updates only selected
   trusted authority entries in each affected application and reissues its
   owner-local installation over the unchanged disclosure. Foreign acceptance
   bytes remain intact, require the same currently active body and credential,
   and verify in their exact historical epoch. Incarnation restart does not
   silently change the audience or replace the accepting key.
6. Verify each required receiver has selected the compatible validator, adopted
   the exact signed successor and loaded matching application/visibility state.
   Retain the adoption and authenticated observer/readiness receipts before
   enabling general new-epoch egress. Use only a scoped authorized probe for the
   receiving communication check, then retain actual intake/echo evidence before
   marking the cohort current. Neither publication, preflight nor authoring
   proves delivery. Explicit offline exclusions remain pending, never healthy.

## Restart and failure

Stages are prepared, accepted-awaiting-republication, and current. An interrupted
application/installation transition resumes through the same republication,
including an already selected application. Repeating a complete update adds no
application or remote-ledger generation. Persist the original request IDs and
never retransmit an uncertain message merely to obtain a green result.

After an accepted authority advance, recovery is forward only: preserve the
old files and proofs for investigation, but never restore obsolete active Root
heads or custody counters. Compatible previous software can be retained only
when it accepts the current signed state. Offline and failed adoption remain
explicit pending work; do not declare a whole cohort healthy from one body.

A receiving body of the *same* being uses its maintained local authority/custody
successor procedure, not foreign-peer adoption. Preserve its distinct body keys,
origin and native conversations. A body with no enrolled Matrix runtime requires
onboarding; this repair never invents membership or imports another body.

This procedure installs no model attention, autonomous peer reply, inbox reader
or scheduler. Existing human authorization covers the finite deployment; it
adds no repeated approval or new identity ceremony.

## Resume a missing observation or retained intake

`systemctl is-active` proves unit state, not socket readiness or successful native
startup. Await the selected sockets, then use the current authenticated base and
group APIs with their connected-process observer and the existing loaded verifier.
Resume a missing observation without repeating a completed lifecycle transition.
Do not reconstruct archived pair enrollment to observe a selected membership group.
A scoped maintenance driver restores every service it paused on success or failure.

When signed intake is already committed, recover the original retained operation
under exclusive native runtime ownership. `GroupMessaging.reconcile_intake` is a
finite technical operation: an expired control can retain its historical ACK and
project its verified receipt without network egress, new message IDs or models.
Native intake, retained control and signed semantic completion remain distinct.

Use the receiving deployment's actual composition. A dual base/group host loads
its closed base controller first, then its independently signed application via
`chat_host.application_view`; the group's proof key cannot authenticate the base
catalogs. The current standalone `operator_messaging reconcile-intake` command
uses one visibility factory and is not a qualified recovery command for that dual
profile. Reuse the host's supported composition under the writer lock rather than
loading a second runtime beside its daemon. Local recovery of an expired control
does not prove that the original live HTTP ACK failure has been corrected.

The receiver retains authenticated intake failures as a closed diagnostic code
and stage in its existing transport-diagnostics sidecar. Stages distinguish
admission verification, the opaque ACK transaction and the signed ACK record.
These local observations neither change the wire reply nor prove remote delivery;
unknown exception text is never retained and a diagnostic-write failure does not
replace the original intake result.

## Bounded local completion and transport retries

Ledger and its CommunicationStore views share one per-path storage gate through
transaction close and pending-sidecar cleanup. Other Ledger operations, including
read APIs that initialize retained metadata, use that same gate. Completion carries
its original monotonic deadline into local storage; this does not hold a lock over
network effects. Native immutable egress callbacks use their explicit read-only
connections outside the gate.

An automatic completion retries proved SQLite BUSY/LOCKED, including beneath the
known retained-intake verification wrapper. Unknown errors, authority failures and
other wrappers remain terminal; a transient local storage deadline is not a signed
receipt rejection. Closed diagnostics distinguish these outcomes without retaining
exception text.

The original data fanout permits at most three attempts for connection failure or
timeout, using the exact retained request bytes, identifiers, route and original
carrier/deadline. A verified retained ACK prevents another network release.
Authority and current reader readiness are checked again before every write.
Expired inspection and exact later observation never create another send. This is
finite technical transport work, not inbox attention or autonomous model activity.
