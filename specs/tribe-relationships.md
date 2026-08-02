# Founded tribes and resource relationships

Status: normative.

A tribe is an explicit collective identified by a content-derived
`tribe_ref`. It is not `/we`, a transport audience, or a list of contacts.

## Declaration and founder

The declaration names a random nonce, founder principal, creation time, and
policy reference. `tribe_ref` is the domain-separated SHA-256 of its JCS core.
The founder is the only admission and expulsion authority. Members may leave
at any time.

An invitation is signed by the current founder and contains exactly:
`tribe_ref`, `founder_epoch`, `invite_id`, `invitee_principal_id`,
`issued_at_ms`, `expires_at_ms`, and `nonce`. It is single-use and cannot be
accepted by another principal. Acceptance signs the exact invitation hash.

Expulsion and voluntary leave append membership events and never delete
history. Founder transfer requires an old-founder transfer statement and an
acceptance by the named successor, then increments `founder_epoch`. If the
founder is lost before transfer, the remaining participants create a new tribe
rather than inventing authority.

## Grants

Membership grants no resource access. Each resource has an exact controller,
descriptor, operations, validity interval, and directional grant chain. Child
grants can only attenuate. Expiry, revocation, controller change, membership
loss, or an invalid parent fails closed.

Knowledge retrieved through a grant remains attributed to its remote
controller. A local embodiment may later create a separate insight or decision
citing it.

## Transport boundary

Tribe Bridge authenticates and carries membership artifacts but does not
decide them. A signed directory entry or audience cannot create `tribe_ref`
membership. Conversely `/we` may use direct Tribe delivery without creating a
tribe.
