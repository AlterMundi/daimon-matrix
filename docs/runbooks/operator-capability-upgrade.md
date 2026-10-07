# Scoped owner capability upgrades

An older authenticated V7/V8 bundle can remain loadable while omitting methods
added later. Updating the SDK or rendering a newer client does not issue those
methods. In particular, `scope.we`, history sync and healthy `runtime.status`
do not prove `we.conversation.page` or sealed `we.converse` is available.

Use the native owner-local offline transaction below to issue explicitly
requested missing methods without changing the being, embodiment, incarnation,
operational keys or original capability expiry. This is separate from rebirth
and from the pinned legacy converter. It is not a model-facing tool or an
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

Closed visibility remains closed: this upgrade grants methods but changes no
visibility policy, transport targets or Telegram installation. A body that
needs an authorized sibling mirror must separately follow
[owner-sibling-conversation-mirror.md](owner-sibling-conversation-mirror.md).
Acceptance requires actual intake, appropriate required visibility and receipts
in both directions, not only green tests or healthy daemons. New onboarding uses
current issuance and this same acceptance procedure, rather than declaring
conversation ready after sync alone.
