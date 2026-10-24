# Scoped owner capability upgrades

## Ordinary reader restart is not a capability upgrade

A serving SDK with `durable-reader-recovery/v1` records authenticated reader
controls in its existing group record store. Startup recovers the latest selected
reader vector only when the qualified code/SDK, runtime, application, stores,
visibility, controller, identity, authority and signed roster are unchanged.
It preserves the selected validity and retains fresh process provenance. Legacy
V1 reader rows keep their original finite expiry. With
`credential-bound-reader-validity/v1`, an explicitly selected V2 reader instead
uses the actual signed credential's finite or until-revoked validity; a finite
maintenance/proof deadline never grants indefinite eligibility. V2 selection
requires the current signed roster and verifies credential/incarnation authority
under the existing fence. A software installation alone does not convert V1
rows. Keep a V2-capable recovery SDK once a V2 journal has been selected. It does
not replay old requests, messages, models or completed onboarding stages.

Use authenticated `runtime.status.receiving.recovery` to distinguish selected,
recovered, disabled, invalidated, expired and unavailable states. Merely having
an active service or seeing a Telegram projection does not prove receiving
readiness. An unsupported historical SDK remains explicit; installing the
feature does not manufacture a positive selection for an old process.

Revoke and empty selections are durable tombstones. Before a supported fallback
to an SDK without this feature, durably revoke through the existing sender
barrier. Returning from unaccounted legacy execution requires fresh receiving
qualification. Never search backwards for an older positive record or overwrite
the original lifecycle evidence. An unresolved startup journal cannot serve;
the existing service manager retries without a new worker or model activation.

The offline transaction below applies only to genuinely missing capability
methods. An unchanged ordinary restart requires no repeat of that procedure.

## Missing capability methods

An older authenticated V7/V8 bundle can remain loadable while omitting methods
added later. Updating the SDK or rendering a newer client does not issue those
methods. In particular, `scope.we`, history sync and healthy `runtime.status`
do not prove `we.conversation.page` or sealed `we.converse` is available.

Use the native owner-local offline transaction below to issue explicitly
requested missing methods without changing the being, embodiment, incarnation,
operational keys or original capability expiry. The explicit optional-controller
expiry repair below is the only renewal supplied here. Both use the existing
owner transaction, separately from rebirth and the pinned legacy converter. It is not a model-facing tool or an
automatic startup migration.

## Prepare the exact request

Use the maintained installed wheel. Inspect actual descriptors, profile methods,
runtime binding, validity and daemon/socket provenance first. Missing methods
and peer transport rejection are separate observations; inspect actual receiver
evidence before attributing a transport failure to a local grant.

Stop and fence every consumer of the runtime, including service auto-restarts.
Retain owner-only copies of its startup selection, rendered client, binding
manifest and request journals. Quiescence is an explicit owner obligation:
advisory writer locks alone do not fence a host. Do not delete pending requests or
clear native catalogs. Reconcile outstanding requests through their owning
workflow before changing their profile; a changed descriptor has a new capability
ID, so an old authenticated request must not be rewritten as an exact retry.

The source and transaction must be sibling owner-only directories. Inspect the
bundle's actual counter, control head, being and full origin. Compute the exact
quiescent source inventory:

```bash
python -I -m daimon_matrix.operator_runtime_upgrade inventory \
  --source /owner/package/runtime
```

Create an owner-only JSON request with exactly these fields. Paths and values are
examples, not installation defaults:

```json
{
  "source": "/owner/package/runtime",
  "transaction": "/owner/package/conversation-upgrade",
  "expected_source_sha256": "ACTUAL_QUIESCENT_INVENTORY",
  "expected_counter": 1,
  "expected_control_head": "ACTUAL_CONTROL_HEAD",
  "expected_being_ref": "ACTUAL_BEING_REF",
  "expected_origin": {
    "body_ref": "ACTUAL_BODY_REF",
    "embodiment_id": "ACTUAL_EMBODIMENT_ID",
    "incarnation_id": "ACTUAL_INCARNATION_ID",
    "principal_id": "ACTUAL_PRINCIPAL_ID"
  },
  "add_methods": {
    "observe": ["we.conversation.page"],
    "weave": ["we.converse"]
  },
  "expires_at_ms": 0
}
```

Select only genuinely missing methods from each role's maintained profile.
Methods must be sorted and unique. The request expiry is a future bounded
authorization deadline, not a new grant lifetime. Unknown roles, cross-profile
methods, already-issued methods, mismatching inventory/identity, inactive grants
and an incorrect custody password refuse before creating a transaction.

## Stage, inspect and publish

Pin the exact request SHA256. Supply the existing custody password through an
inherited descriptor only; never through argv, environment or public evidence.

```bash
python -I -m daimon_matrix.operator_runtime_upgrade stage-capabilities \
  --request /owner/input/request.json --request-sha256 ACTUAL_REQUEST_SHA256 \
  --password-fd 3 --externally-quiesced 3</owner/input/body.password
```

Staging authenticates the existing runtime with the native loader, preserves its
complete checkpoint, adds exactly the requested methods to the selected profiles,
and signs the successor capability-set binding with the existing authenticated
embodiment key. All capability keys, validity windows, unrelated profiles and
history stay intact. The encrypted store advances its counter once without
changing its secrets. Selected client descriptors change coherently with the
bundle. Validation runs on disposable copies; the source is untouched.

Inspect the owner-local `ready.json` and candidate. Keep failed stages for
diagnosis; do not infer acceptance from their presence. Pin the exact ready-file
SHA256, then publish while consumers remain fenced:

```bash
python -I -m daimon_matrix.operator_runtime_upgrade publish-capabilities \
  --source /owner/package/runtime \
  --transaction /owner/package/conversation-upgrade \
  --ready-sha256 ACTUAL_READY_SHA256 \
  --password-fd 3 --externally-quiesced 3</owner/input/body.password
```

Publication verifies the checkpoint, original/candidate inventories, requested
differences, current authorization and native successor authentication, then
exchanges directories with one Linux `renameat2(RENAME_EXCHANGE)`. Legacy receipts
cannot authorize this operation, and capability-upgrade receipts cannot authorize
the legacy converter. An exact retry acknowledges an interrupted completed
exchange without issuing again. Unexpected bytes or later effects refuse and
remain intact. Recover forward; restoring an older counter is not supported
rollback.

## Installed operational acceptance

Deploy the exact reviewed SDK and re-render the existing owner client and neutral
binding from the maintained plan. Keep one body installation. The client must
select the issued `observe` and `weave` profiles and report their real methods.
Verify matching signed server/runtime binding and preserve harness controls.

Restart the existing daemon with its previously approved startup selection,
then check original identity, integrity and authorized scoped read. Qualify
sealed send separately using genuine receiving receipts; local `we.observe`
authorship is not delivery. Retain exact request IDs and native outcomes.
Do not turn a rejected or ambiguous older send into an unrecorded fresh attempt.

Before the conversation qualification, reconcile both bodies' signed history
prefixes through their ordinary owner clients. A valid peer envelope and sealed
message can still fail native intake with `origin_sequence_gap` when the receiver
lacks earlier events in the author's incarnation lane. Inspect actual receiver
evidence or a read-only native preview of the exact retained payload before
attributing that refusal to grants, keys or transport compatibility. Use the
supported `we.sync.peer-pull` operation with the exact peer, a retained
`sync_request_id` and a bounded page limit, continuing only if the authenticated
result reports `more`. Qualify the reverse prefix as well: accepting a returned
receipt also requires the recipient's prior signed events.

History convergence remains private and preserves existing journals. A message
copied by sync is not conversational intake or receipt authoring. After
reconciliation, qualify actual conversation delivery in both directions. Keep
older terminal or undetermined attempts and distinguish any new qualification
operation explicitly; never rewrite an older request or call it delivered merely
because its history became readable.

Closed visibility remains closed: this upgrade grants methods but changes no
visibility policy, transport targets or Telegram installation. A body that
needs an authorized sibling mirror must separately follow
[owner-sibling-conversation-mirror.md](owner-sibling-conversation-mirror.md).
Acceptance requires actual intake, appropriate required visibility and receipts
in both directions, not only green tests or healthy daemons. New onboarding uses
current issuance and this same acceptance procedure, rather than declaring
conversation ready after sync alone.


## Expired optional receiving controller

An update authorization deadline is not a grant lifetime. New receiving-controller
issuance records `receiving_controller_lifetime: owner-profile-horizon/v1` in its
private ready receipt. Its descriptor ends at the earliest existing original
operator/host grant expiry, bounded by the30-day operator policy. A short update
therefore does not accidentally disable the controller when that task ends.
Previously staged receipts without this marker retain their original contract;
a new SDK does not rewrite an older transaction or its grant lifetime.

For an already expired optional controller in a V8 runtime, reuse the same
`stage-capabilities` / `publish-capabilities` commands, exact inventory/counter/
identity pins, fenced receiving owner and password descriptor. The request uses
`add_methods: {}` and `renew_receiving_controller: true`; omit or set false
`provision_receiving_controller`. The caller must select a new, finite transaction
authorization deadline inside the remaining original-owner grant horizon.

This operation requires exactly one existing canonical receiving-controller
profile. It renews only an expired descriptor whose status remains active.
Revocation, a live/unexpired target, expired original roles, wrong custody,
invalid current Root/body authority, additional methods or changed source bytes
refuse. The expired role does not authorize its own renewal: the receiving owner
authenticates the unchanged currently valid original roles and signed custody.
V7 expiry and other expired roles are not repaired by this narrow operation.

The existing controller key, methods, identity and all unrelated profiles stay
unchanged. Its client receives the renewed signed descriptor; the encrypted store
advances its counter exactly once. Native validation runs on disposable copies,
and the original is untouched until the existing atomic publication. Ready
receipts retain the renewal selection and exact old/new inventories. A lost
publication return is reconciled by the original transaction, including after its
authorization deadline, without another grant or counter change.

Old authenticated requests remain bound to their original capability ID. Keep
request journals and expired/uncertain outcomes intact; do not re-sign an old
request and call it an exact retry. Receiving controllers must retain the old
loaded-process receipt and link the separately observed renewed load through a
new exact lifecycle operation. Compatible software rollback preserves the renewed
current authority and counter; restoring the expired bundle is not rollback.

This is an owner-local maintenance capability, not a model tool, automatic
startup mutation or general role renewal service. Runtime validation, authentic
serving-process load, selected readers and actual communication remain separate
observed outcomes under the receiving update workflow.
