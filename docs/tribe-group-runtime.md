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
