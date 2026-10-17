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

`messaging.inbox`, `messaging.reply` and `messaging.delivery` keep their existing
argument shapes. `messaging.send` adds an optional explicit `destination` for
member/body directs; omission keeps the old group request bytes. This is source
support, not proof of a selected readiness adapter or live direct. The same
channel ID is incoming and outgoing
for the group. Replies retain verified parent identity and the original thread.
Presentation derives sender and audience labels; message prose need not repeat
identifiers. A same-Tribe direct uses this same membership application and shared
registration. Deliberately selected bilateral applications remain independent.

The additive `dm.tribe.direct-conversation/v1` carrier binds its logical recipient
and frozen verified Root epoch into the signed message. Recipient bodies alone
receive wrapped keys and semantic legs; author-local ledger retention is separate.
Direct replies derive their destination from the verified parent and preserve
ID/hash-only visibility correlation without automatically copying parent plaintext.
The complete confirmed Tribu echo names the logical direct recipient; this profile
does not promise secrecy. Details retain all selected body legs and their proofs.

The owner-local direct-reader guard defaults to denying emission. A route,
prepared SDK or selected host file is insufficient; Cluster #232 must supply its
actual selected-and-loaded receiving evidence and invalidate it before incompatible
replacement/reassignment. Readiness is checked before transport preparation and
inside the bounded provider's actual write fence. Its refreshable evidence never
changes frozen frames or transport fingerprints. Unknown/offline readers remain
visible without group/pair fallback. Historical attempts and receipts survive a
later readiness loss. The ordinary compositor has not installed this controller
adapter yet; #344 remains open through receiving integration and #342 acceptance.

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
The admitted HTTP handler attempts the ACK write/flush before finite receipt
completion. A failed socket write does not prove the remote peer missed
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

Concurrent projection operations on one owned ledger serialize through SQLite
COMMIT, pending-journal cleanup and connection close. SQLite's writer lock alone
ends too early to protect that cleanup from a second initializer. This local gate
is shared by all views of that ledger; completion uses its existing explicit
deadline when waiting. Native egress's immutable request/route callbacks stay
read-only and outside the gate to preserve lock ordering and ACK progress. Full
signature, projection, pending-journal and rollback validation remains required.
Closed completion diagnostics retain safe error/errno categories, never exception
text or private paths; a missing signed receipt is never inferred from an ACK.

`operator_messaging reconcile-intake` is a finite owner operation under the same
exclusive runtime lock as the daemon. It accepts bounded `--intake-after`,
`--intake-limit`, `--intake-max-bytes` and `--intake-max-elapsed-ms` navigation
budgets and reports pending work without exposing request contents. It cannot
load another writer beside a running owner. The elapsed budget stops starting
more items and also limits each in-flight numeric HTTP attempt to its remaining
budget. No timed-out writer is detached. Local storage completion retains runtime
ownership rather than pretending that a timed-out commit stopped.

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

## Bounded transport and owned responses

The selected group compositor uses numeric IPv4/IPv6 destination endpoints and
one native-network attempt budget: at most twelve seconds, no later than the
original immutable carrier deadline. Connect/TLS and whole-request writes each
have a two-second phase cap; response reading has a ten-second phase cap. All
caps share one absolute monotonic deadline. Partial reads, interim responses,
headers, body chunks and partial writes cannot renew it. Explicit port zero is
rejected, never changed to a default port. TLS retains certificate verification.
Legacy directed hostname and outbound Unix adapters remain available, but do
not inherit this numeric HTTP guarantee. No resolver thread is abandoned.

TCP/TLS setup sends no Matrix application bytes and happens before the execution
fence. After setup, bounded release acquires the existing fence within the
remaining budget, checks exact bytes/current authority/expiry and already
discharged visibility, then consumes its permit around the actual request write.
The owner callback and wall-clock expiry are checked again at that boundary.
Response reading happens outside the fence. A partial write or lost response is
uncertain; exact retry uses the same retained identity and bytes.

Visibility preparation remains a separate prerequisite. It completes the
retained multipart echo before fanout, or stops on ambiguous publication or
backoff. Check-only permit issuance does not call Telegram or return a reusable
permit. Controller SQLite busy waits fail immediately in bounded release;
arbitrary owner callbacks, other stores, filesystem completion and the selected
visibility service retain their own qualified availability assumptions. These
transport limits are not a hard real-time promise for the entire Python process.

One runtime controller shares four speech attempts, two independent control
attempts and two sending operations. Each operation submits at most two tasks
in a rolling window, acquiring global capacity before submission. Active exact
recipient attempts coalesce. Every started writer is joined before the call
returns; no unbounded task queue or background retry service exists. Saturated
unstarted rows remain in the full frozen audience, distinct from retained
unconfirmed attempts and authenticated responses in the existing delivery view.
This qualifies the current small cohort; it does not guarantee every destination
under arbitrary load. Historical retained records are not deleted to fake capacity.

The receiving HTTP socket gets a thirty-second ownership deadline at acceptance,
before request-line/header parsing, plus a five-second per-I/O cap. At most eight
message handlers occupy the sixteen admitted connections, preserving an evidence
share under the qualified load. Unlimited pre-header flooding is outside that
assumption. Accepted ACKs and signed refusals retain their exact binding until
the HTTP/IPC writer: response headers/framing/body/flush execute inside release,
using unbuffered writes, rather than releasing a bytes-returning placeholder.
Technical completion runs in `finally`, even if authority or a failed ACK write
blocks the response. It freezes one separate budget of at most thirty seconds,
clipped to the retained receipt obligation or control request's original expiry.
Pending, in-flight and transient storage outcomes retry with bounded backoff,
using the same signed receipt and frozen transport request. Terminal outcomes,
blocked authority/selection/clock and invalid bindings stop continuation. The ACK
writer keeps its original five-second budget; technical continuation does not
renew any carrier or admission horizon. A nonblocking, closed local diagnostic
records the completion outcome. No model, poller or extra service is started.
Exhausted budgets leave recoverable intent. HTTP handlers and workers drain under runtime
ownership; a stalled local completion cannot be abandoned to claim clean shutdown.

Echo publication has a separate execution guard shared by ordinary advancement
and authorized ambiguity recovery. Short journal phases use the native storage
fence; Telegram network I/O does not hold that fence. An already suppressed or
confirmed ACK therefore does not wait for unrelated publication. Native release
still rechecks current authority, reader selection, exact bytes and expiry under
the original physical writer fence. Legacy sibling visibility exclusions remain.

The release descriptor includes `bounded-numeric-http/v1`,
`owned-transport-reply/v1` and `bounded-group-fanout/v1`. Source/installed
qualification does not establish actual receiving readiness or compatible
rollback. Those selections remain the receiver-compatible rollout's work.
