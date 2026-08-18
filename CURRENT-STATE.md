# Current state

## Release-candidate checkpoint — 2026-08-18

The qualified Matrix V0 functional boundary is merged at commit
`09414d6edd9586f539be8272c4979d0b36c86b87`, tree
`d7146e291ae3f8313dc0b3d3c3a0b5e5f94d33ad` (PR #121). The package version is
`0.1.0rc1`. No current deployment or live-host state is asserted.

The exact boundary ran 640 tests, including 22 declared skips, with zero
failures, plus the Python 3.11–3.14 CI matrix. The closed conformance registry
contains 102 scenarios.
Two offline builds were byte-identical: wheel SHA-256
`5896ae31813b7b9e1224ada14b7f9da9745790404c5a1eee9043079572f20089`
and sdist SHA-256
`f0ba76eb6650647a8b808f8648d04ef6d35806fcafd2f271d140c4fa5f9e96a1`.
Exact evidence is recorded in
[`docs/verification/v0-rc-qualification.md`](docs/verification/v0-rc-qualification.md).

## Implemented Matrix boundary

The package provides:

- threshold-separated genesis and recovery ceremonies with per-holder signed
  shares and a keyless aggregator;
- being-root identity, plural embodiment credentials, incarnation succession,
  revocation and recovery/rebirth authorization;
- root-bound append-only ledgers, replay-safe synchronization, deterministic
  projections and rebuild;
- an authenticated owner-local daemon plus typed CLI and MCP clients;
- relationship, Tribe membership and directional-grant reduction from signed
  Matrix history;
- recipient encryption, logical message state, authenticated intake, semantic
  receipts and native peer transport;
- memory, publication, source, birth, species, Codex and Hermes contracts with
  synthetic or isolated acceptance journeys;
- ten purpose-limited operator profiles and two separate host-bound clients:
  an exact five-method status profile and an exact four-method curator profile.

Runtime mutation paths fail closed when required authority or custody is
absent. Synthetic single-store helpers remain explicitly named test fixtures;
they are not an operational custody design.

## Cross-component boundary

Matrix identity and social state remain independent from Cluster lifecycle
truth. Cluster may verify embodiment/incarnation and resource-fence evidence,
but cannot derive being roots, relationships, grants or semantic receipts.
Conversely, Matrix does not claim that a local lock provides global admission.

Tribe Bridge remains a transitional ordinary-message component. Matrix has a
native encrypted peer and semantic-receipt path, but Tribe removal still needs
explicit migration evidence and repository-owner authorization. No legacy
dual-write or ambiguous compatibility path is part of the RC plan.

Its final software successor is merged at
`294e1194db6cd60d9349a2d43938475bbd1c8c20`, tree
`bcba9989a38519df87ecbb6c87a33a2f9740b85d` (PR #65), after exact-head
independent approval and 148 tests with zero failures on Python 3.10–3.13.
This is software evidence, not evidence of live provisioning, key rotation,
service changes or cutover.

The external Matrix.org protocol is unrelated and is not a dependency.

## Evidence classification

Local and CI evidence may establish software behavior, reproducibility and
adversarial rejection. It cannot establish physical singleton guarantees,
independent real-world custody, participant consent or a current deployment.
Older reviews and runbooks are retained as historical records only; this file
supersedes their operational-state claims.

## Remaining release work

- merge the prepared Matrix documentation successor and repin Cluster to that
  exact Matrix commit;
- reconcile final Cluster/Tribe metadata without treating documentation-only
  commits as new functional authority;
- regenerate the final three-repository manifest and repeat artifact-only
  installation against the resulting exact default-branch heads;
- leave publication and every physical or participant-facing action behind its
  explicit human gate.
