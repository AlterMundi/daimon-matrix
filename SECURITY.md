# Security Policy

## Reporting

Do not publish vulnerabilities involving active identities, private memory,
credentials, or deployed infrastructure in a public issue. Contact the
AlterMundi maintainers privately with reproduction details and affected
versions.

## V0 boundaries

- Root `/me` keys are never committed, shared among collective members, or
  installed in ordinary bodies.
- One `/me` may have at most one active body lease; overlapping valid leases
  are split-brain evidence and are quarantined.
- Runtime keys and credentials remain outside the public repository.
- GitHub coordination uses dedicated ephemeral session keys. It must never
  reuse a Daimon root, operational, transport, SSH, signing, or encryption key;
  a coordination session is work attribution, not `/me` or presence evidence.
- Public signing keys are never treated as encryption secrets.
- Tribe and source relationships do not imply access beyond signed grants.
- Models may propose memory changes but cannot write canonical state directly.
- Legacy Tribe Bridge ciphertext must be treated as potentially
  non-confidential.
- Fixtures and CI must use synthetic identities, memories, keys, and messages.

The V0 threat model and cryptographic test vectors must be complete before any
live CompAII canary.
