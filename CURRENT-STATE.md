# Current state

## Deployed membership group — 2026-10-13

CompAII, Eko and Oliva now participate in one membership-based messaging group,
using SDK `cdafbc0513d43c39f03be6e8b1b0636b9e4e9422` (PR #330). Group-only
application/v3 has no pair policy, resource or grant. Audience comes from signed
membership and all active Root bodies, frozen before authoring/sealing. One native
carrier and mandatory human echo cover its copies. Transport ACK and expiry are
separate from signed per-body semantic delivery; records/receipts survive restart.

Actual three-body sends: `4e4fc6b6-4060-41c8-b87a-1a92fdca1cdb`,
`cad5e8ce-56d3-46fb-ae18-671f33714e91`, `1a565ad2-76f9-4cc9-8fde-6e34631ad0db`.
Each retained six bodies in audience and confirmed the three VPS semantic legs;
three unavailable sibling routes remain explicit. A connected group reply,
exact retry with unchanged message/audience and manual read after Matrix restart
were observed. Each speech has one confirmed Tribu publication, with no duplicate
on retry. No model reads, answers or autonomous attention are implied.

Oliva left both legacy memberships and joined the existing Source/Eko group via
normal authenticated service guards. Source's three legacy founder declarations
remain historical signed facts; V0 has no dissolution event. They are not defaults.
Existing history, custody, accounts and harness sessions remain preserved. Group
selection replaces default pair applications under the same native lock/admission;
eight obsolete default/temporary pair proxies were retired. One shared roster
registration per body replaces per-pair onboarding for the deployed group.

Cluster PR #226 is merged and the qualified maintenance generation is selected.
Its worker recognizes authenticated group selectors, uses group owner-client
channels and checks the requested being's semantic receipt; missing group
admission cannot construct pairs or count an archived pair as completed onboarding.
Host/body SDK pins and actual per-body runtime selectors are coherent. The
independent Telegram consumer, receiving context, custody and journals are retained.
A final send after maintenance (`7d0c4ffb-680c-48c8-a847-581dcb1cdc17`) again
confirmed the three VPS signed deliveries and the complete six-body audience.

Future portal admission still requires the qualified membership/Root-inventory/
shared-roster transaction. This is explicit future automation work, not permission
to reopen founder/member pair installation. Current group success does not claim
a fully automatic new-member portal flow. Historical Bridge records and earlier
onboarding runbooks are history or deliberate directed tools, never Tribe defaults.

CI on the exact SDK head is green. The installed group suite also exercises actual
catalog migration/validation and atomic carrier/visibility admission, covering the
real deployment blocker found during cutover. Reuse earlier passing directed-link
qualification. No global Stop was requested or performed; only Matrix processes
were drained, with no Codex/Telegram restart. Every future global Stop still needs
fresh explicit human consent.

## Current Bridge retirement policy

The [retirement policy](TRIBE-MIGRATION.md) incorporates the merged Bridge
#71/#72 decision and Cluster #103 dependency removal. It supersedes older
transitional-Bridge requirements, not the historical RC evidence below. The
stable successor is Matrix plus Cluster with Bridge absent, with no Bridge
state migration, compatibility, fallback or dual-run phase. This source-level
reconciliation does not claim a completed stable release or live removal.

## Historical release-candidate checkpoint — 2026-08-18

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

The merged Matrix closeout predecessor
`7266de8551ae861f3773c587bf907cfcddde6ffd`, tree
`d1ff7a6fc6b1351f67fd13171dcee51242fc9804`, also repairs the Hermes CI source
pin. During closeout qualification the former Hermes merge commit was not
advertised by that remote; public PR head
`5c8870c1625761956a56fd2b225720dbe9083e45` was selected and verified with the
identical audited tree
`ac7dec02ca029e895963402788bd1cdc3afb36f8` and identical contract bytes. Its
unprefixed git-archive SHA-256 is
`09789981423142fec1a26239d5209f96c41453078ff73e2fc4a11e1d45728660`.
Two isolated builds after this repin were byte-identical: wheel SHA-256
`11ef77b2b4c743cfa25d6652e9cad3594e41223cb73f558d5ead8f47bd43609d`
and sdist SHA-256
`b23d66004039dc9d454c1bf4382b87a381c538fe8194a3c262440425ffa6de69`.

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

Tribe Bridge is superseded. Matrix has native same-being peer transport and a
distinct encrypted logical-message/semantic-receipt path; native `/tribe` and
relationship authority remain. Live Bridge removal requires its own exact
inventory and human GO, not operational-state migration. The cross-being
participant gate remains separate; isolated implementation evidence cannot
satisfy consent or establish a live relationship.

The historical Bridge RC software boundary was merged at
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

## Qualification evidence boundary

The historical RC metadata handoff could not embed its own merge commit. Its
external integrated manifest had to bind the three exact Matrix, Cluster and
Bridge heads, source artifacts and replayed offline-install evidence. Preserve
that record; do not retroactively turn it into a two-component stable manifest.

The stable successor must separately bind and qualify Matrix plus Cluster,
demonstrate native birth/continuity with Bridge absent, and obtain its explicit
publication/cutover authorization. Existing three-component freezer tools are
historical RC tooling, not an already implemented stable contract. Follow
[TRIBE-MIGRATION.md](TRIBE-MIGRATION.md) for successor tracking and gates.

Documentation-only successors do not create new identity, custody or runtime
authority. Publication and every physical or participant-facing action remain
behind their explicit human gates regardless of software or manifest status.
