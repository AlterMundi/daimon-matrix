# Tribe Bridge integration

## Current decision

`nicoechaniz/tribe-bridge` remains a transitional ordinary-message component
while Matrix's native authenticated intake and semantic-receipt path is
qualified. This document makes no claim that a Tribe service is currently
deployed or reachable.

Matrix relationship, Tribe membership and directional-grant authority comes
only from verified signed Matrix history. A Tribe directory, audience,
delivery acknowledgement or Cluster lifecycle fact cannot create that
authority. Transport ACK and Matrix semantic receipt are distinct facts.

## Migration policy

- Do not restore legacy compatibility or introduce ambiguous dual-write.
- Start successor stores empty; do not copy legacy messages or writable
  databases into a new embodiment.
- Keep signing, recipient-encryption, relationship and transport credentials
  purpose-separated.
- Provision and rotate through authenticated application protocols rather than
  host account access; missing or expired authority fails closed.
- Preserve hash-pinned behavioral provenance without importing source whose
  authorization is unresolved.
- Keep gateways as optional edge adapters. They do not define identity,
  membership, memory or canonical message state.

DM-050 records the no-copy provenance boundary. DM-051 through DM-055 provide
recipient encryption, logical message state, routing, scope resolution and the
native peer carrier. DM-082 provides the relationship/grant producer consumed
by those layers. These implementations remove the need for Tribe to become a
Matrix authority, but do not by themselves authorize a cutover or retirement.

## Replacement gates

- stable logical IDs, ordered cursors and exact retry survive restart and
  bursts;
- duplicate direct/hub delivery yields one logical intake;
- authentication, authorization, expiration and revocation fail closed;
- transport acknowledgement remains separate from foreign-being signed
  semantic receipt;
- provisioning/rotation works without SSH and has tested expiration recovery;
- a consented cross-being canary demonstrates authenticated intake and the
  semantic receipt with independently held participant authority;
- migration, publication/cutover and repository retirement each receive their
  explicit human approval.

Until every gate passes, Tribe remains transitional. It must not be silently
archived, disabled, re-keyed or treated as the source of Matrix truth.
