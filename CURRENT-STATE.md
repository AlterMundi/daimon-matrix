# Current state

## Release-candidate checkpoint — 2026-08-16

The integrated Matrix V0 baseline is merged at commit
`75b34804f8d013d348129946c0cd541a4448e71d`, tree
`38f3edb002ac52aac2d51fbf533cb58c38b813c5`. The package is being prepared as
`0.1.0rc1`. No current deployment or live-host state is asserted.

The merged code passed 600 tests with 37 intentional skips and 1,414
parameterized subtests, plus the Python 3.11–3.14 CI matrix. The closed
conformance registry currently contains 102 scenarios. Exact evidence and the
pre-version-bump artifact hashes are recorded in
[`docs/verification/v0-rc-qualification.md`](docs/verification/v0-rc-qualification.md).
Because package metadata is part of each distribution, the RC artifacts must
be rebuilt and receive new hashes. The V7/V3-only successor has now been
qualified locally with 619 unittest cases (22 intentional skips) and two
byte-identical offline builds; exact hashes are recorded in
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

The external Matrix.org protocol is unrelated and is not a dependency.

## Evidence classification

Local and CI evidence may establish software behavior, reproducibility and
adversarial rejection. It cannot establish physical singleton guarantees,
independent real-world custody, participant consent or a current deployment.
Older reviews and runbooks are retained as historical records only; this file
supersedes their operational-state claims.

## Remaining release work

- freeze the V7-only runtime-bundle and V3-only client surface now that the
  never-deployed compatibility paths are removed;
- finish exact cross-repository pins and manifests;
- rebuild `0.1.0rc1` twice and record byte-identical artifact hashes;
- perform clean artifact installation and the complete supported-Python suite;
- pass disposable end-to-end backup/export, restore, recovery/rebirth,
  disaster rebuild, rollback and concurrent-launch tests;
- obtain independent review of each final content-addressed candidate;
- leave publication and every physical or participant-facing action behind its
  explicit human gate.
