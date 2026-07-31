# Security Policy

## Reporting

Do not publish vulnerabilities involving active identities, private memory,
credentials, or deployed infrastructure in a public issue. Contact the
AlterMundi maintainers privately with reproduction details and affected
versions.

## V0 boundaries

- Root `/me` keys are never committed or shared among incarnations.
- Runtime keys and credentials remain outside the public repository.
- Public signing keys are never treated as encryption secrets.
- Tribe and source relationships do not imply access beyond signed grants.
- Models may propose memory changes but cannot write canonical state directly.
- Legacy Tribe Bridge ciphertext must be treated as potentially
  non-confidential.
- Fixtures and CI must use synthetic beings, memories, keys, and messages.

The V0 threat model and cryptographic test vectors must be complete before any
live CompAII canary.

