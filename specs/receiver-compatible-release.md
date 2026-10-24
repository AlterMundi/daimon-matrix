# Receiver-compatible release contract

This is deployment metadata, not a Matrix identity, membership, resource grant
or new social scope. Matrix owns the receiving codec contract. Cluster #232 owns
the resumable operation, exact installation, selection CAS and observed effects.
Use the existing qualified code/SDK digests and approved provenance; do not create
a second release identity or derive approval from an integrity hash.

## Public manifest

`dm.receiving-release/v1` is a closed, canonical JSON object:

- `artifacts`: existing content digests. `matrix_sdk` is required; explicitly
  selected `receiving_code`, `worker`, `owner_client` and `telecodex` are optional.
  A missing component is outside this change, not permission to upgrade it.
- `provenance`: `matrix_revision` and `qualification_sha256`. These locate the
  selected source/qualification evidence; the controller must verify the actual
  approved evidence and artifacts. Merely writing these values proves nothing.
- `contract`: receiving `profile`, exact `interpreter` implementation/version,
  `wire_read`, `wire_write`, versioned `store_versions`, `capabilities`,
  `pending_inspection`, and `pending_transmission`.
- `authorities`: sorted, unique `current` and `candidate` public closure rows,
  each containing `being_ref`, `control_head`, and `manifest_hash`.
- `required_receivers`: sorted, unique `(being_ref, embodiment_id)` rows with
  `expected_selection_sha256`, the digest of each receiver's actual existing
  selection vector, and an optional `artifacts` map using the same existing
  non-SDK roles/digests. Failed adoption cannot remove a row or make it optional.

For the shared-SDK profile, `matrix_sdk` is exclusively global; receiver overrides
for it are refused. Effective artifacts are global defaults overlaid by the exact
receiver row. Only roles absent from BOTH maps remain unchanged. There are no null,
reset or implicit upgrade semantics. Put genuinely shared components globally and
heterogeneous receiving-code/other selections in receiver rows; one shared SDK
does not imply equal receiving code or equal independent Telegram selections.
The extended form requires `per-receiver-artifacts/v1`; older closed readers must
refuse it, never strip an override or silently use only the global map.

`selected_artifacts()` resolves this frozen public selection for one exact required
receiver. The controller still verifies each effective combination through the
maintained successor helper against its immutable original base; a selected
code generation's SDK must match the shared selected SDK. Unselected components
in a staged bundle do not become selected merely because they are present.

The owning authenticated controller pins the SHA-256 of this complete canonical
manifest in its existing approved operation before effects. That manifest digest
is distinct from the enclosing operation's digest. The manifest is external to
the artifacts it references, avoiding a circular content hash. Qualification
referenced here precedes selection; subsequent adoption/load/communication
evidence belongs to the operation record, outside this preselected manifest.
Public data has no private paths,
routes, tokens, custody, provider login, native input or copied memory.

The controller derives receivers from actual installed applications and verified
Root inventory. Manifest references alone neither verify that inventory nor
prove enrollment. It verifies every signed authority against the receiver's
existing trust prefix through the maintained known-peer successor procedure.
Unknown peers still require enrollment. Code-only updates leave the actual
authority closure, original seed/context, provider account and native sessions
unchanged; none of these is derived from a package version.

## Qualified reader description

The `daimon_matrix.release_compatibility` module prints `dm.receiving-reader/v1`
from the qualified SDK without opening runtime state, custody, inboxes, network
listeners or persistent stores. The controller MUST verify the exact SDK bytes
and executable startup/import surface before launching the probe, through the
existing installer. `-I` alone is insufficient: it still runs site startup hooks.
Use a hook-free `-I -S` process with an explicitly verified package root, or
qualify the complete installed startup/import surface. A verified closed wheel
can supply the pure-standard-library candidate probe without importing unrelated
installed packages; this observes candidate code, not the selected live process.
Cluster #232 must apply this requirement to preliminary checks too, including
`pip check`, and qualify an isolated extra-startup-hook fixture without executing
the hook. Matching required wheel members does not qualify extra executable files.
Do not trust a supplied JSON claim, an unqualified import path or a peer message
as an installed-reader observation.

The current profile is `membership-group/v1`: application V3, existing group
conversation/intake, semantic message/resolution/receipt, sealed delivery,
authenticated transport and operator-binding formats. The descriptor includes
the actual interpreter and versioned communication/visibility metadata support.
It declares only group delivery inspection; it does not claim the unfinished
authority-successor directed inspection (#326), member-directed mode (#344),
router, autonomous attention or a token/spend guarantee.

`assess_reader(release, descriptor, expected_digest=approved_digest)` checks
declared requirements against that descriptor. Required reading AND writing
formats, versioned stores, capabilities and inspection contracts must be supported.
Unknown/mismatched profiles, interpreter versions, formats or capabilities produce
`compatible: false`, never an unverified fallback. Its result always reports
`receiving_readiness: "unobserved"`. It transmits, selects and adopts nothing.

Code compatibility is necessary, not actual receiving readiness. Before activation
the controller must also qualify the candidate validator against public signed
closure and consistent store snapshots, including unversioned SQL layouts,
integrity, authenticated records and pending operations. Reuse maintained read-only
validators; do not let a probe initialize, migrate or recover a live store. A busy
or crashed store is not a valid immutable snapshot. Public manifest validation
does not replace artifact qualification, authority verification or observed load.

## Durable operation and activation

The immutable manifest and required cohort are inputs to the existing receiving
operation. Retain preparation, compatible-reader selection, staged public
authority/application/visibility, irreversible authority acceptance, actual
receiver adoption/load, and new-epoch egress enablement separately. Any stage
that needs accepted authority happens after acceptance, with affected egress
fenced until receiving readiness; preparation is not a claim of adoption.

Check each expected selection under its maintained writer lock before its first
effect. A resume checks completed effects against their retained expected outcome;
it does not reapply them or demand the pre-effect state again. A stale operation
must not overwrite a newer selection/roster. The controller retains host/helper
selection evidence as well as per-body evidence; this is CAS and forward recovery,
not a distributed atomic transaction or another identity ceremony.

Resolve artifact roles to actual selection targets before preparation. Distinct
receiver rows cannot independently change the same physical host/helper target:
contradictory intended digests are refused. Bind the complete pre/post-vector
hashes in the existing operation's immutable intent and verify the returned
retained vectors. The shared journal's separately stored precondition/transition
arguments are not automatically part of its intent hash. On resume and apply,
use retained journal vectors, never fresh caller values. Qualification evidence
must cover every distinct selected artifact combination; one loaded receiver
does not prove another receiver's readiness.

Do not enable new-epoch egress until every required receiver has the selected
compatible validator, exact adopted public authority and matching loaded
application/visibility, with actual authenticated observation. A scoped authorized
communication probe is distinct from general activation. Required offline bodies
stay pending; possessing an update kit is not readiness. An explicit human-selected
exclusion narrows the receiving guarantee without changing signed membership.

Compatible code-only updates may report offline adoption pending while preserving
old traffic. No update may report the entire frozen message audience adopted from
three working VPS bodies. Supply qualified public recovery packages for unavailable
external bodies; never custody, accounts or private routes.

## Reader eligibility and proof deadlines

A finite maintenance operation or fresh observation deadline bounds the control
transaction. It is not the lifetime of a selected receiving body's signed
credential. `credential-bound-reader-validity/v1` advertises owner-control
`dm.runtime.reader-selection/v2`, alongside supported closed V1 commands.
V2 rows use `dm.receiving.reader/v2` with the identity validity algebra: either
finite `not_before_ms`/`not_after_ms`, or explicit `until-revoked` with
`not_before_ms`. A large numeric expiry is not an indefinite credential.

A V2 select requires the exact current signed-roster digest. Under the existing
physical fence and roster transaction, each row must match the active body,
incarnation, credential and authority; its requested validity must attenuate the
actual verified signed credential. Existing loaded-code, selection, wire,
authority-epoch, revocation and process requirements remain necessary for egress.
An until-revoked row does not bypass these requirements or activate a model.

The authenticated reader journal records this as V2, preserving prior finite V1
controls and tombstones unchanged. Old V1 rows retain their original expiry;
installing new software does not reinterpret or renew them. A new explicitly
qualified selection is required to adopt credential-bound eligibility. Restart
recovery revalidates the retained exact roster, actual credential, validity and
existing loaded binding. A rollback must read the actual retained journal version;
an SDK that understands only V1 cannot recover a V2-selected reader journal.
The fresh control deadline and original operation expiry remain unchanged.

## Pending work, expiry and rollback

`pending_transmission` is `original-binding-unexpired`: a software update does not
renew deadlines, re-resolve audiences, change ciphertext, regenerate requests or
rewrite route/config fingerprints. A retained pending operation either has a
verified compatible sending context for still-permitted work, or remains
inspectable and explicitly non-sendable. Expiry ends permission to transmit;
late authenticated proof may improve knowledge without reopening transmission.
Inspection still requires current client/disclosure authorization and verified
historical provenance. #326/#338/#340/#341 own the affected detailed contracts.

Retain software as rollback only if its actual reader can accept the current
signed state, store layouts and pending records. Old files alone are not proof.
After accepted authority, recover forward: never restore obsolete authority,
decrease high-waters or erase accepted/uncertain input, budgets or pause.

The current communication service stays usable during development. Fault injection
uses isolated synthetic state. Before a real test/cutover that could interrupt
communication, prepare its exact candidate/readiness/recovery and obtain the
human's scoped authorization. Every global Stop separately requires a fresh
explicit human request. This contract activates no model, reader or scheduler.
