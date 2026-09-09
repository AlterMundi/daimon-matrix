# DM-132 review record

## Independent legacy status-label correction — 2026-09-09

The deployed legacy receiver has signing label `daimonmatrix` and a distinct
observer slot `runtime.capability.v1:status:clusterd`. Both the pinned native
legacy parser and actual five-method status client accept this shape. The prior
upgrade gate incorrectly required bootstrap-default matching labels, rejecting
before transaction creation. Production source was preserved and its original
services resumed; no slot or descriptor was rewritten to satisfy a fixture.

Independent read-only review **APPROVE**, limited to:

- `src/daimon_matrix/operator_runtime_upgrade.py`, SHA-256
  `3af58175dea9b02c40fb4774747061e0cc12721a90d368d8f44737f4d04c1719`.
- `tests/test_operator_runtime_upgrade.py`, SHA-256
  `12845c87e350922783d10bbdb5293c62a771045e5577d53949076fe9f6cc048d`.

The sole production hunk requires two distinct slots, the original signing-label
operator and a different independently named nonempty status slot with exactly
the canonical observer methods. Identity derivation, source/legacy pins, native
validation, live authorization, custody counters, publication and monotonic
rollback remain unchanged. The reviewer ran all 39 upgrade tests plus 35
independently recorded cases: two fresh positive journeys, the exact old failure,
and 32 adversarial refusals. Forward/reverse preserves the old slot names and
secrets at counters 2 -> 3 -> 4. Malformed API inputs can retain existing bounded
TypeError/KeyError refusal; the CLI catches them without exposing private data.

Parent reconciled both hashes and separately verified the new Cluster native V1
external-sidecar forward/reverse regression against these frozen source bytes.
That is unit integration evidence, not installed dependency provenance. Expected
DM041 generated hash drift was regenerated without changing inventories. Declared
mypy 2.3.0 passes all 58 source files; an initial attempt using Cluster's mypy
1.19.1 produced unrelated diagnostics and was not used to modify source.

Full-repository qualification, exact-commit CI, installed-pair qualification,
normal integration and the actual bilateral tool journey remain separate gates.
The bounded approval does not claim completed deployment or authorize checkpoint
rewinds after post-activation effects.

## Historical status

**INCOMPLETE — not release or deployment approval.** This record preserves bounded
review results while real receiver integration is completed. The published
checkpoint is `f2c9906880a9b985360beb5aa12e29a898c91f31`. Shared-authority and
packaging successor slices have independent bounded approvals below. Migration
review found blocking B1. Its successor correction reproduces semantic refusal
under parent verification; independent re-review and full qualification remain
pending. No release approval is implied.

## Reviewed application/MCP slice

An independent read-only reviewer examined the frozen application/operator and
explicit messaging-only MCP code carried in checkpoint
`9b2bb21448be303ca8fc5dee7ec76d534a51a16b`. The review reran actual authorization
and delivery code with isolated synthetic custody, not production keys.

- Ordinary relationship composition could acknowledge revocation while a
  separate messaging history kept authorizing traffic. Fixed at that checkpoint
  by refusing the unsafe composition, **not by solving production integration**.
- Deleting the relationship database could replay enrollment and resurrect a
  grant. Published loading now rejects missing state instead of reinitializing.
- A post-rename fsync failure could leave a loadable installation and an
  unbounded cleanup error. Publication preserves ambiguous state and provides
  exact-digest recovery, without pretending external effects can be rolled back.
- Fixed-duration local capabilities lacked renewal. Trusted predecessor-bound
  renewal preserves client identity, keys, journals and encrypted retries.
- Independent controls verified completed delivery reuse without new transport
  calls and ambiguous admitted-message replay with identical request bytes and
  one peer inbox entry.
- Narrow MCP hidden ordinary calls/resources reject. Cached plaintext is not
  disclosed after actual signed grant revocation.

No blocker was found in that reviewed narrow MCP isolation behavior. This is
not whole-repository approval or an actual installed participant journey.

## Follow-up R1: detectable store schema loss

The independent review found that an existing nonzero outbox lacking its tables
was silently reinitialized. Preparing the same send ID produced new ciphertext
and additional Ledger events. Parent independently reproduced the defect.

The correction in `messaging_config.py` validates every published store before
constructors run, using read-only catalog, version, integrity and initialization
checks. Trusted unpublished staging remains separate. Missing/incompatible
security-bearing schema and pending journal sidecars reject rather than repair.

Parent reran the original attack body: it now stops at `load_application` with
`messaging_required_store_invalid`. The integrated regression suite passes at
`f2c9906`. This is bounded refusal evidence, not independent approval of every
new schema-checking detail, arbitrary row-loss detection or malicious-owner
anti-rollback protection.

## Packaging correction

The earlier reproducible builder omitted five native messaging modules. Two
identical builds therefore still produced an unusable MCP package. Parent
verified the failure by importing directly from the wheel outside the checkout.

The builder, exact distribution inventories and source-parity checks now include
the five modules. Tests mutate actual archives, repairing incidental metadata,
and require rejection of altered source bytes. Parent verified the corrected
intermediate installation's module origins and dependency consistency. Final
qualification must compare every package source member to the exact frozen
source; older source-parity enumeration gaps must not be mistaken for exhaustive
future drift protection.

## Local verification at the published checkpoint

The parent integrated `unittest discover` run completed with **730 tests, 22
skipped, no failures**, and **14 ResourceWarning lines**. Warnings are disclosed;
this is not a warning-free run or hosted CI result. Subsequent source changes
invalidate applying that result to a newer candidate without appropriate checks.

## Successor shared-authority approval

An independent read-only reviewer approved the exact shared-history/preload
slice after 82 targeted tests and four original probes. Parent independently
verified the five source hashes and reran the 12 added tests. The ordinary and
native services use the same relationship context/store; actual signed ordinary
revocation denies new send, manual/cached read, and later transport phases.
Preparation does not insert shared bootstrap grants. Public preflight validates
signed application selection and ordinary schema before custody or constructors.

Reviewed source SHA-256:

- `runtime.py`: `ab02d0c446b114d7cdb5e5ffa2cd7ded30a067ab9bd3ac9ec6f1955538407789`
- `relationship_store.py`: `ab1d48b3b9ff3729ec52226385f2dd20288d7157ae36393a1895d38fe963aa9d`
- `messaging_config.py`: `6606a16d3f91b7268c8a810bf95127975fa79f6f85ec14382f3ecfe76f184c31`
- `test_runtime_relationship_authority.py`: `e7106a02034d51c6a6a1c1599a23af3a1674a209486ca42c88bc0ac3e0c3e054`
- `schemas/messaging/v1/application.schema.json`: `dbbf50940a96706db797834d4cb8c76bc083bb2b6601f7978802687b67fd0e5b`

This approval assumes the documented host lock and trusted owner filesystem.
It does not establish a mutable foreign-root subscription, arbitrary historical
row-loss detection, participant enrollment, or installed transport acceptance.
Cluster issue #104's successor preload wiring also received an independent
bounded approval; its final dependency pin and real installed composition remain
separate integration gates.

## Successor exhaustive package parity approval

Independent review approved the explicit upgrader addition and source-parity
checks derived from the existing closed distribution allowlists. Filesystem
scanning does not grant permission to ship files. All 58 package modules and
`py.typed` are byte-bound. The reviewer independently passed 12 package tests,
including 116 one-module byte-drift subcases with repaired wheel RECORD, and
additional omission/unknown-member probes. These are subcases, not separately
counted unittest methods. Actual wheel-backed imports were verified, not merely
checkout imports; pip-installed behavior still requires final qualification.

Reviewed source SHA-256:

- `tools/reproducible_build.py`: `7e64619a99271faaf220c42d197d002c8adeb46ec8434a8b5d041a41e6cca562`
- `tools/check_distribution.py`: `fddd4467df5c18db166c01eb178d5973a199b1f0dd8d42e0f345f6dc9dd9dc1a`
- `tests/test_package_scaffold.py`: `ecffbd9eee66840a55fdafc9f44375eb947c998957edcf18e48a552c3a9285e4`

## Migration B1 — unresolved, deployment gate

The independent migration review returned REQUEST_CHANGES on upgrader hash
`a6faf8367482e08b7c2bc81a7164e2bb1004e02e80ced30f6205e23a6904a3d2`
and test hash
`49b9240f6f01e7c04314703a3a613793047b6b0f47e7ef047a6332adaa3085b1`.
With canonical expired or revoked legacy descriptors, real forward staging and
publication produced twelve fresh active profiles. Parent reproduced both cases.
The old loader validates descriptor/key binding, not present usability; its
acceptance cannot substitute for explicit lifecycle checks during conversion.
The previous expiry regression failed on noncanonical JSON rather than expiry.

Correction must check active/current legacy descriptors at the defined staging
and fresh-publication boundaries, use canonical semantic negative tests, and
preserve exact already-committed retry behavior. No source approval is claimed
until that correction receives independent re-verification. The integrated
Matrix suite for the defective candidate was deliberately interrupted and is
not passing evidence. Monotonic pre-effect reverse conversion passed bounded
review probes, but cannot make the defective forward converter deployable.

## B1 successor — parent refusal verification, review pending

The successor frozen upgrader is
`03ba11f0de0f0661794173d85f43e1483f5a0e59ca169969a4990867867eb1b6`;
its tests are
`a3bdf760f3f4c6683b29a4cc547697b00903c38b654a0dad225ffd6b97443202`.
The parent checked both hashes and ran the successor canonical reproducer:
expired descriptors reject with `upgrade_legacy_authorization_expired`, revoked
descriptors with `upgrade_legacy_authorization_inactive`. The real pinned old
loader accepted both canonical bindings; refusal preserved the source and
created no checkpoint or publication. The author's 61 focused passing tests
remain author evidence until independent reproduction completes.

Independent re-review of staging/publication boundaries, time crossing,
committed replay and rollback is running separately. The new full integrated
suite is also pending. DM-041 provenance was regenerated only after checking
the exact expected drift; its subsequent `--check` and diff checks pass.
Parent strict mypy passes all 58 source files; Ruff passes the complete source
and changed Python tests/tools. An exploratory broader lint invocation also
reported existing diagnostics in untouched historical vector/coordination
files; those files were not silently reformatted or included in this claim.

## Remaining acceptance boundaries

- Independently approved B1 correction and final existing-runtime migration.
- Actual Cluster host lifecycle and host-client compatibility.
- Final package/CI qualification and authorized same-plan deployment/rollback.
- Real enrolled remote Codex and deployed CompAII using installed tools in both
  directions, with current clock, correlated response, restart/dedup and denial
  verification.
- Telegram is a separately authorized visibility projection. The owner permits
  it to remain explicitly pending if unavailable; that does not waive any core
  messaging criterion or establish that the mirror works.

The historical owner-authorized self-review exception belongs only to its
recorded earlier checkpoint; it is not a standing exemption from independent
migration/identity review. No review result grants authority from incoming
messages or permission to modify unrelated or Tribe services.
