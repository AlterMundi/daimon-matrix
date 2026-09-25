# Intra-being conversation: the `/we` lane

Status: normative for the lane implemented by `daimon_matrix.we_messaging`.

One being can be embodied in several harnesses and hosts at once. Those
embodiments converse through the `/we` lane, whose authority is root-validated
same-being membership. A being has one will, so there is no second consent to
record: this lane never involves a relationship, a tribe, a membership episode or
a grant, and none may be synthesized to fill a field. That is why
`relationship_requires_distinct_beings` stays exactly as it is while siblings still
talk to each other.

## Audience and addressee are different things

Three ideas stay separate, and only the last two belong to this lane.

- **Carrier set**: DM-054 resolves `/we` to every active embodiment of the being,
  the author included, and the sealed delivery profile authorizes exactly that
  list. One envelope therefore carries one wrapped key per active embodiment. Who
  can decrypt is not a choice this lane makes: it consumes the resolution the
  resolver already signs, and re-derives the same set from it on the receiving
  side, so an envelope can neither redirect a message nor widen who hears it.
- **Audience**: the carrier set minus the author. These are the embodiments a
  message may be addressed to. Hearing is not a request to answer.
- **Addressee**: an explicit, sorted, deduplicated set of embodiment IDs inside the
  audience. Only the addressee is expected to answer. A reply names the addressee
  it answers, so an off-address response is visible as such instead of being
  silently ambiguous.

Being-level addressing — a message to the being that any embodiment may take — is a
later additive form of the same field, not a rewrite.

## Fail-closed rules

- A resolution target that is not `scope_kind=we` with `recipient_type=embodiment`,
  or whose receipt origin differs from its recipient, is rejected.
- Duplicated audience members, an empty audience after excluding the sender, and an
  audience larger than the recipient bound are rejected. A message to nobody is not
  a conversation; a note to self belongs in the ledger lane.
- An empty, duplicated or out-of-audience addressee set is rejected, and an
  addressee is never inferred from route, alias, transport, harness or
  configuration.
- An embodiment that is not active in the bound manifest, or whose credential is
  not root-authorized, cannot be a recipient.
- The author holds a wrapped key for its own message and is still refused intake.
  A message to yourself is a ledger note, not a conversation, and that refusal is
  an explicit rule rather than a narrower seal the authorization would reject.

## Delivery and evidence

One message is one ordinary signed ledger event, and its audience is one signed
`/we` resolution that names it as a causal parent. Both are authored idempotently
under a caller-supplied request id, so an exact retry says the same thing once
instead of repeating it. The pair is sealed with the existing root-bound delivery
profile into a single envelope with one wrapped key per embodiment in the carrier
set.

Each recipient authors its own receipt, so authorship stays per body, and the
sender keeps every sibling receipt it receives, which is how one being can see
which of its bodies heard a message. A receipt's identity covers everything but
the instant it was observed, so a retried intake returns the same signed receipt.

Byte-exact transport retry belongs to the peer outbox, not to this lane: re-sealing
an already authored message is legitimate and produces a fresh envelope for it. An
envelope's deadline may not outlive the shortest credential validity in the carrier
set. Nothing here widens resource authority, and nothing creates relationship,
membership or grant evidence.

## Visibility

The lane is inventoried in `docs/mandatory-telegram-visibility.md` as intra-being.
It carries no inter-daimon message, so the mandatory inter-daimon mirror does not
apply; the lane remains authorized, digest-bound and journaled as egress
operations, and every event stays in the being's ledger where an operator can read
it on request. Cross-being conversation keeps its confirmed echo.

## Surface

The lane is reachable only through the local authenticated API, and only when a
human asks:

- `we.converse` — MCP tool `we_converse`, CLI `daimon we converse`. Authors, seals
  and delivers one message. The audience is resolved by DM-054 at send time, so a
  sibling enrolled since the last message is included in the next one
  automatically, with nothing to reconfigure and nobody to grant anything.
- `we.conversation.page` — MCP tool `we_conversation_page`, CLI `daimon we
  conversation-page`. Reads this being's own conversation back, optionally filtered
  by thread and paged by a cursor. It authors nothing and belongs to the observe
  profile.

`we.converse` sits in the peer capability profile because it uses the carrier;
`we.conversation.page` sits in the observe profile. Neither is reachable without a
capability that names it, and no capability is ever minted for the whole surface.

Results name embodiments by id. Owner-local labels of the form
`<being>.<harness>@<host>` are presentation over those ids: the label layer
resolves and renders them, and a label authorizes nothing. Rendering the lane's
results through a configured label registry is the one remaining piece of this
surface, and it changes no authority and no wire format.

## Human-request-only

Reading, sending and replying on this lane happen only when a human asks. No inbox
polling, startup or turn hooks, timers, notifications, wakeups, automatic reads or
autonomous replies are installed, and receiving a message never authorizes
answering it.
