# Membership group runtime

The group application `dm.messaging.application/v3` contains one `tribe` channel,
shared verified governance, Root inventories, owned stores, one local intake
registration and a transport roster. It contains no pair directions, peer policy,
resource or grant. Joining is a signed invitation and acceptance in the existing
Tribe, never a new founder/member Tribe or reciprocal pair enrollment.

The roster is routing, not authority. Each body registers once; all senders use
the same body registrations. The signed membership snapshot and verified Root
inventories determine every message's audience, including active offline bodies.
Unavailable registrations leave explicit pending legs; they cannot shrink the
audience. Admission and receiving deployment must distribute the updated trusted
Root inventory and group roster through the maintained cohort procedure.

`messaging.send`, `messaging.inbox`, `messaging.reply` and `messaging.delivery`
keep their existing argument shapes. The same channel ID is incoming and outgoing
for the group. Replies retain verified parent identity and the original thread.
Presentation derives sender and audience labels; message prose need not repeat
identifiers. The explicit directed applications remain separate from the group.

Before any effect, the sender retains its operator-bound request, send-time
membership, Root epochs, signed message and resolution, and exact sealed envelope.
The existing authenticated HTTP provider transports that unchanged group frame.
Every network copy is gated against the same logical carrier obligation, producing
one mandatory confirmed human echo, not one per recipient. Its native paths are
inter-daimon paths, including when a receiving body belongs to the author being.

The receiver independently reconstructs send-time membership and frozen Root
targets, checks current operational credentials before decryption, and persists
readable intake before signing its receipt. A receipt returns through the same
authenticated transport as a control frame; it neither wakes a model nor produces
another speech echo. Transport ACK alone never terminates a semantic leg. The
author signs a local retention outcome, without intaking its own message.

Exact retries and restarts preserve the logical IDs, audience and ciphertext.
An expired carrier is reported separately from the retained semantic vector and
is not retransmitted or silently replaced. V0 does not re-wrap old messages.
Historical reads verify retained records and their original authority epochs;
later membership changes do not erase readable history or reveal it to newcomers.

The delivery result retains the complete `semantic.legs` and all-body terminal
rule. Its additive `members` view reports `receiving_copy: "proved"` only when
at least one receiving body's signed intake receipt is verified. The referenced
`receiving_leg_ids` identify those proofs. `author_retained_leg_ids` separately
identify the author's local retention; it does not establish receiving uptake.
Without a receiving receipt the member remains `unknown`, even after an ACK or
carrier expiry. One proved receiving copy does not close pending sibling legs.

Transport rows separate recorded `attempt_state` from `current_route`
availability. Removing a route never erases a retained authenticated response.
An unconfirmed attempted effect stays uncertain when its route disappears.
Carrier expiry ends transmission permission; it does not prove non-delivery.
Late authenticated semantic receipts may improve retained knowledge without
reopening transmission, resolving membership again or replacing logical IDs.
This increment adds no long-offline catch-up policy, store migration or wire
format. Confirmed Telegram echo remains the selected prerequisite. Exact retry
reuses confirmed publication proof; ambiguous platform acceptance stays visible
and is not an unconditional exactly-once promise. Delivery does not imply model
reading, and none of these technical stages wakes a model.

Managed bodies select the owner-signed group application under their existing
daemon lock, receiving admission and body fence. The selection replaces default
bootstrap pair applications while retaining their configuration, proofs and
private history as archives. No global Stop, model restart, inbox poller or
autonomous answer is part of group installation.

## Recoverable technical intake

The group HTTP composition uses a staged owner-local callback. The existing
byte-only `TransportIngress.handle` contract remains available for synchronous
ordinary adapters; staged group HTTP/IPC owners use `handle_deferred` and consume
its per-request completion only after the ACK write attempt. Validation and
opening have no durable effect. One `TribeRecordStore` transaction then commits
the exact authenticated request context, the first readable inbox record and its
signed receipt obligation. Concurrent exact copies reuse those records. A failed
commit observation is resolved by retained-row lookup; known intake must never
be replaced by a sticky transport refusal.

Opaque carrier bookkeeping and its exact authenticated ACK follow that commit.
The admitted HTTP handler attempts the ACK write/flush before one finite receipt
completion attempt. A failed socket write does not prove the remote peer missed
or saw the ACK. The handler retains its existing concurrency slot and runtime
ownership until its technical attempt ends. No worker, poller or model is added.

The obligation freezes the original observation time, message/resolution and
carrier bindings, selected recipient body, return target, route/key/policy
context and one return deadline. Signing later uses the genuine current event
time and authority, while `observed_at_ms` preserves durable intake time. An
unconfirmed return uses the same receipt/carrier/request; a proved return is not
sent again. Restart never adds another sending window. An unavailable or changed
return selection stays explicitly blocked; historical proof does not grant a
new route or permission.

Control receipt frames similarly commit a signed proof and pending foreign
projection before ACK creation. Incorporating that already validated proof into
`CommunicationStore` happens after the ACK attempt and can recover independently.
Control proof does not become speech, a readable conversation item, a reciprocal
receipt or a model turn. Transport ACK and signed semantic delivery stay distinct.

`operator_messaging reconcile-intake` is a finite owner operation under the same
exclusive runtime lock as the daemon. It accepts bounded `--intake-after`,
`--intake-limit`, `--intake-max-bytes` and `--intake-max-elapsed-ms` navigation
budgets and reports pending work without exposing request contents. It cannot
load another writer beside a running owner. The elapsed budget stops starting
more items; strict in-flight network deadlines and actual socket fencing remain
#340. No timed-out writer is detached.

Recovery after a message carrier expires uses the signed admission, readable
inbox and receipt obligation; it never opens the expired frame again. It can
retain historical ACK bytes in the signed `intake-ack` record without admitting
an expired egress operation. A signed semantic proof may remain local when its
return deadline is expired. Legacy inboxes require retained receipt/native
deadline provenance; missing provenance is blocked, never reconstructed from
"now plus TTL". Completed records remain deduplication evidence. Capacity credit requires a
verified signed completion bound to the exact original admission, obligation or
control proof. Incoming evidence/projection has its own bounded count and byte
reserve, so pending message receipt returns cannot consume that reserve. The
reconciliation scan selects IDs and lengths first and checks its record-byte and
elapsed budgets before loading and decoding admissions. It enumerates staged
admissions; it does not automatically repair every legacy inbox gap.

The receiving release descriptor advertises `durable-group-intake/v1`,
`deferred-receipt-observation/v1` and the retained intake reconciliation view.
An older reader that lacks them is not a compatible selection or rollback for
that release. These source contracts require installed qualification and actual
receiver-compatible selection; they do not assert a production rollout.
