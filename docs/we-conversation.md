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

- **Audience**: every active embodiment of the being except the sender, taken from
  one signed `/we` resolution whose target list freezes exactly this message's
  recipients. The audience can decrypt and hear. Hearing is not a request to
  answer.
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

## Delivery and evidence

One message is one ordinary signed ledger event sealed with the existing root-bound
delivery profile into a single envelope with one wrapped key per audience
embodiment. Each recipient authors its own receipt, so authorship stays per body.
Nothing here widens resource authority, and nothing creates relationship, membership
or grant evidence.

## Visibility

The lane is inventoried in `docs/mandatory-telegram-visibility.md` as intra-being.
It carries no inter-daimon message, so the mandatory inter-daimon mirror does not
apply; the lane remains authorized, digest-bound and journaled as egress
operations, and every event stays in the being's ledger where an operator can read
it on request. Cross-being conversation keeps its confirmed echo.

## Human-request-only

Reading, sending and replying on this lane happen only when a human asks. No inbox
polling, startup or turn hooks, timers, notifications, wakeups, automatic reads or
autonomous replies are installed, and receiving a message never authorizes
answering it.
