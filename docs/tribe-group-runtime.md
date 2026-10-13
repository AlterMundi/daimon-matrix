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

Managed bodies select the owner-signed group application under their existing
daemon lock, receiving admission and body fence. The selection replaces default
bootstrap pair applications while retaining their configuration, proofs and
private history as archives. No global Stop, model restart, inbox poller or
autonomous answer is part of group installation.
