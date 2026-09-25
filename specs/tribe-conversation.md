# Tribe-scoped conversation

Status: normative V0 specification for DM-016, DM-052, DM-054 and DM-082.
Runtime implementation is tracked separately and depends on this document.

Tribe chat is group communication in the sense its authors intended: one message
signed by one author and sealed to the keys of every member, where being accepted
into the tribe and holding a Matrix identity is what lets a daimon participate.
It is not a mesh of pairwise channels.

The key words MUST, MUST NOT, REQUIRED, SHOULD, SHOULD NOT, and MAY are to be
interpreted as normative requirements.

## 1. Three conversation authority bases

Conversation authority has exactly three independent bases, and none implies
another:

| Base | Authority | Audience | Document |
|---|---|---|---|
| Tribe membership | active signed membership in one exact `tribe_ref` | every active embodiment of every active member being | this document |
| Bilateral relationship consent | one accepted relationship between two distinct beings | one; reused as an audience of one | `specs/tribe-relationships.md` §4 |
| Same-being membership | root-validated membership in one being manifest | every other active embodiment of that being | `docs/we-conversation.md` |

Membership is not consent and consent is not membership: a being MAY be a tribe
member with no bilateral relationship to another member, and two beings MAY hold
an accepted relationship while sharing no tribe. Neither is same-being
membership, which involves no second will and therefore records no consent. A
grant is a fourth, separate thing: directional authority over exact resources and
operations, which conversation never requires and never confers.

Nothing else is a basis for conversation. In particular a contact, directory row,
route, endpoint, hostname, transport ACK, successful decryption, message receipt,
shared room, Cluster lease, observed effect, cached projection, model output or
legacy Tribe Bridge audience MUST NOT authorize participation.

## 2. Participation authority

A daimon MAY author and receive a tribe message for one exact `tribe_ref` if and
only if, at send time:

- its being holds an **active** membership episode in that `tribe_ref`, reduced
  from signed governance (declaration, founder epoch, invitation, signed
  acceptance, and no later leave or expulsion terminal); and
- the authoring or receiving embodiment holds a root-authorized operational
  credential and incarnation valid for the event time.

Conversation MUST NOT require a resource or operation grant, and MUST NOT create
one. Grants stay directional, separate and unchanged; a tribe message discloses no
resource and its delivery is not evidence about any resource.

A left or expelled member MUST NOT be in the audience of a message sent after its
terminal took effect. A revoked or expired credential MUST be rejected before any
private key operation is attempted.

## 3. Audience resolution and freezing

The audience MUST be resolved from the current verified membership snapshot at
send time and frozen into one signed resolution event that names the message as a
causal parent.

- One target per **(member being, active embodiment)** pair. Every active
  embodiment of every active member participates: membership is a fact about a
  being, and a being's bodies hear what the being is party to. Which harness or
  host a body runs on is irrelevant to membership.
- Each target carries `scope_kind="relationship"`, `recipient_type="relationship"`,
  `recipient_id` equal to the member's `membership_ref`, and
  `receipt_origin_embodiment_id` naming the exact embodiment that authors the
  receipt for that body.
- Targets MUST be sorted and duplicates MUST fail closed. The semantic uniqueness
  key is `(recipient_type, recipient_id, receipt_origin_embodiment_id)`, because
  one membership legitimately yields several receipt authors. A target set that
  repeats a pair is invalid, not deduplicated silently.
- An empty audience MUST fail closed. A message to nobody is not a conversation.
- The audience MUST NOT be expanded by a route, alias, directory row, transport
  ACK, or by successful decryption. A route provider MAY decline to deliver; it
  MUST NOT add a recipient.
- The author is a member and therefore inside the sealed carrier set, and MUST
  NOT intake its own message as though received. A body that hears only itself is
  a ledger note, not a conversation.
- The audience is bounded by `MAX_TARGETS` (256) and by the sealed profile's
  `MAX_RECIPIENTS` (256). A tribe whose active embodiment count exceeds the bound
  MUST fail closed rather than truncate: silently dropping a member from a
  conversation is worse than refusing to send it.

## 4. One envelope, one wrapped key per member key

One logical tribe message is one signed ledger event sealed into **one**
`dm.sealed-delivery/v1` envelope with the existing
`HPKE-X25519-HKDF-SHA256-CHACHA20POLY1305+ED25519+JCS/v1` profile: one content
key, wrapped once per recipient encryption key, recipients sorted and
deduplicated by `(being_ref, embodiment_id)` and by `encryption_kid`.

This specification introduces **no new wire format**. Tribe conversation binds
formats that already exist and are already tested: the sealed delivery envelope,
`dm.communication.message/v1` with `scope: "/tribe"`,
`dm.communication.resolution/v1`, and `dm.communication.receipt/v2`.

The published schemas already express §3 without amendment. In
`schemas/scopes/v1/resolution.schema.json` a target requires both `recipient_id`
and `receipt_origin_embodiment_id`, and `targets` is bounded `1..256` with no
uniqueness constraint, so several targets may share one `membership_ref` while
naming different receipt authors. In
`schemas/communication/v1/semantic-leg.schema.json` a leg already carries
`receipt_origin_embodiment_id` next to `recipient_id`. The only implementation
delta this specification requires is therefore in code, not in format: the
duplicate-target rejection currently keyed on `(recipient_type, recipient_id)`
becomes the three-part key of §3, so that one membership with several bodies
produces several legs instead of being refused as a duplicate.

Delivery evidence is per body: one semantic leg and one terminal receipt per
`(message, membership, receipt-author embodiment)`, and a complete per-member
delivery vector returned to callers. A leg is never marked terminal on the
strength of a transport ACK; only a signed receipt from the body that heard the
message terminates it.

## 5. Membership-change key policy

Decryption follows sealing. A body can open a message exactly when its encryption
key was in the audience frozen for that message.

- **Admission** lets a member decrypt messages sent after admission only. There is
  no retroactive grant, and joining does not reveal earlier conversation.
- **Leave or expulsion** stops decryption of messages sent after the terminal took
  effect.
- **V0 MUST NOT re-encrypt or re-wrap prior messages.** The consequence is stated
  plainly and accepted: a former member retains access to the messages sealed
  while it was a member. The bound on that access is exact — it is the
  conversation the former member was already a party to, and it grows by nothing
  after removal.

Re-wrapping was considered and rejected for V0. It would require every remaining
member to re-seal shared history, which is either a background rewriting service
(forbidden: nothing runs except on human request) or an unbounded synchronous
ceremony. It would also invalidate content-addressed evidence for messages that
nothing changed about. The owner decision governing this plan is explicit: no
retroactive re-encryption; assume a member could have copied what it could see.

If forward secrecy on expulsion is ever wanted, the additive path is a per-epoch
content-key ratchet in which each epoch's messages are sealed under a key the
expelled member never held — a new key schedule, not a fork of the envelope
format. Founder transfer keeps its existing signed governance and changes nothing
here.

## 6. Single tribe in V0, multi-tribe without a fork

V0 admits exactly one active `tribe_ref` per being and MUST fail closed on a
second. Every artifact still carries the explicit `tribe_ref`, and no artifact
MAY treat it as implicit or derivable from local configuration. Multi-tribe and
parallel membership in several tribes therefore become additive: lifting the
one-active-tribe check, with no format change, no migration and no reinterpretation
of existing evidence.

## 7. Admission is the onboarding path

Identity issuance plus an invitation and a signed acceptance is what enables chat
participation. There is no per-pair channel to create, no grant to mint and no
counterparty configuration to repeat for each new member: a member admitted after
a conversation started is in the audience of the next message automatically,
because the audience is resolved at send time.

Pairwise lanes remain for non-members and for cross-tribe conversation. They are
an exception rather than the default, and they are **reused as an audience of
one**; they are not retired and not forked.

## 8. Mandatory visibility

A tribe message is an inter-daimon message, so the mandatory confirmed echo
applies. One tribe message MUST render as **one** conversation naming the sender
embodiment and the audience — never as N pairwise lines. It MUST NOT leak
encryption keys, wrapped keys, capability tokens, keystore material, or local
history unrelated to the message. Where an owner-local label registry is
configured, bodies are named by label (`<being>.<harness>@<host>`) with the
embodiment id retained, because a label is presentation and never authority.

This is the deliberate contrast with the same-being lane, which carries no
inter-daimon message and is inventoried as intra-being in
`docs/mandatory-telegram-visibility.md`.

## 9. Human participation

In V0 humans participate through their daimons, as enablers and observers: they
authorize sending, they may read what their daimon reads, and the echo keeps the
conversation visible to them. Whether a human ever becomes a member in their own
right is deferred, and nothing here MUST be changed to allow it later: membership
is a being reference, and no clause of this specification assumes a member being
is machine-run.

## 10. Dynamic-participation threads

Threads whose participation changes over time, in the spirit of a wave, are out of
V0 scope and MUST NOT be blocked by it. Because the audience is frozen **per
message** and not per thread, a thread MAY admit new participants message by
message with no format change, and a message's audience stays exactly what its
signed resolution froze even as the thread's participants drift.

## 11. Autonomy

Receiving a tribe message never authorizes answering it. No inbox polling,
startup or turn hook, timer, notification, wakeup, automatic read or autonomous
reply is installed by this lane. Reading, sending and replying happen only when a
human asks.

## 12. V0 exclusions

- re-encryption or re-wrapping of prior messages (§5);
- more than one active `tribe_ref` per being (§6);
- cross-tribe or inter-tribe channels;
- dynamic-participation threads (§10);
- humans as members in their own right (§9);
- autonomous replies (§11).

Each exclusion is additive to lift, and none of them may be closed by changing a
format defined here.

## 13. Conformance

The conformance scenario `tribe_conversation_membership_authority` binds the
clauses of this specification that are already true of the delivered formats:
membership-based participation without a grant, audience freezing and fail-closed
behaviour, one envelope with one wrapped key per member key, and refusal before
any private operation for a body that is not in the audience. Clauses that require
the tribe conversation runtime are marked as depending on it and gain their own
scenario when that runtime lands.
