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
3. Activate the sender only when required compatibility preflight succeeds.
   Publish a credential-free update package for offline bodies. Never distribute
   Root custody, unlock files, provider logins or private routes in that package.
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
6. Verify the receiving observer and authenticated native/application readiness.
   Retain adoption receipts and actual communication/intake/echo evidence before
   marking each body current. Neither publication nor authoring proves delivery.

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
