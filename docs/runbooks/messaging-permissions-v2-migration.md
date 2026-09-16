# Messaging permissions V2 migration — integration handoff

Status: library APIs implemented; **no operator apply command or live migration is
provided by this slice**. Do not edit a participant bundle by hand using this
runbook. Exact owner approval, protected publication/recovery, independent review
and installed Matrix/Cluster qualification remain mandatory.

See [the protocol](../../specs/messaging-permissions-v2.md).

## Available interfaces

* `identity.validate_validity`, `validity_contains`, `validity_attenuates`: closed
  finite/indefinite algebra. V1 inclusive credential endpoints are not reinterpreted.
* `identity.create_embodiment_credential_v2`: current root threshold and existing
  embodiment acceptance; unchanged custody supplied by a separately authorized
  ceremony. This is not an untrusted model-facing root signing API.
* `authority_epochs.create_credential_succession(previous, successor, ...,
  migration_id, issued_at_ms, root_seeds, signing_seed)` and verifier: exact
  V1-to-V2 same-incarnation transition. Retain old authority in `authority_history`.
* `operator_rebirth.authority_from_runtime_bundle`: reads V7/V8 and verifies the
  mixed authority history. Existing rebirth/enrollment workflows are not new
  indefinite-permission migration commands.
* `runtime.load_runtime`: explicit V8 startup. All finite operator profiles,
  signed binding, client bytes and secret-slot checks remain mandatory even when
  unavailable. `LocalCapability.active_at` determines availability, not readiness.
* `runtime.verify_relationship_card_authority`: current root/credential and
  routing-key check with historical card pin selection. Requires indefinite V2
  credential for a V2 card. It assumes separately authenticated card event/lane.
* `local_api.create_messaging_capability`: V2 exact-method capability; the owner
  must attach it only together with durable revocation checks.
* `RelationshipStore.authorization_view`: existing-state-only context manager,
  reverified signed events, SQLite writer exclusion, current terminal-evidence
  semantics. Keep the final local operation/read release inside the context.
  `view` remains historical and is not a fresh-authorization API.

## Parent integration obligations (not optional)

1. Reconcile #132 writes and acquire successor exact-file ownership before editing
   messaging/config/store/service/operator code or DM-041 generated inventories.
2. Add closed messaging application/binding/migration schemas and an owner-local
   capability-revocation journal outside replaceable application generations.
   Revocation must bind runtime/capability/key and monotonic predecessor/action,
   survive restart, and reject a replayed old descriptor. Never treat the
   descriptor status bit as sufficient revocation.
3. Plan against exact old/new control, manifest, policy and relationship heads,
   signed membership episodes and current revocations. Approve both parties.
   Never automatically convert a revoked, relinquished, closed or withdrawn
   predecessor. Expired unrevoked V1 grants require explicit fresh bilateral
   consent in a distinct lineage. Record exact old/new mappings rather than
   claiming that changing `schema` migrates signed history.
4. Publish successor cards and bilateral grants with exact `messaging.read` /
   `messaging.send` operations and unchanged intended resources. The old generic
   `read` operation is deliberately NOT silently given indefinite authority.
   Integrate V2 snapshot/resolution consumption in messaging's policy checks.
5. Add a signed retained-read mapping bound to predecessor/successor policy
   digests and immutable historical evidence. Keep old inbox rows, cursors,
   envelopes, RPC journals and prepared outbox bytes unchanged. The mapping must
   not authorize fresh ingress or restart an expired prepared send.
6. Use `authorization_view` with a documented lock order relative to messaging's
   capability journal and admission/RPC stores. Recheck after network I/O, before
   unwrap/admission/read release, and on cached replies. Serialize revocation
   with final local effects. Do not hold the SQLite writer lock across unbounded
   I/O or recursively call a writer. Test opposite race interleavings.
7. Add staged/fsynced owner-approved application publication with an exact
   recoverable journal and monotonic generation floor. Revalidate root and
   relationship heads at apply. Test every crash boundary and reject missing or
   corrupt established journals instead of creating empty authorization state.
8. Qualify actual authenticated send/inbox/reply/delivery and retained reads after
   large clock advances and real process restart. Preserve all TTL, nonce, HMAC,
   ciphertext/delivery-ID, origin sequence and exact-retry checks.
9. Qualify Cluster's status/fence/sidecar/client guards against V8. Expired optional
   status/scopes/sync capabilities remain unusable but must not indirectly stop
   otherwise valid messaging. Do not grant indefinite non-messaging methods to
   turn readiness green. Admission/fencing still requires independent legitimate
   authority; this slice does not implement a Cluster policy change.
10. Run exact-head independent security/persistence review, full CI, generated
    inventory checks and installed-wheel/cross-repository qualification. No partial
    closure of #136 from these library tests.

## Recovery and threats

Indefinite stolen permission no longer ages out. Keep least-privilege capability
keys owner-local, monitor unauthorized use, and publish authenticated revocation
promptly. Emergency action uses existing signed grant revoke/relinquish/close,
card withdrawal, and root credential revocation plus the integrated owner-local
capability revoke. Root recovery is separately authorized and must retain all
revocation floors. Already disclosed plaintext cannot be recalled.

Revocation reaches remote peers when verified evidence arrives; offline peers
are not magically synchronized. Record ambiguous already-sent network effects.
Before activation an unpublished generation can be discarded. After activation
repair forward; restoring old files, permission records or SQLite backups is not
rollback authorization. Whole-filesystem rollback protection needs an external
monotonic anchor. A human instruction's deadline still stops execution, without
revoking its independent standing messaging permission.

## Frozen slice validation (2026-09-16)

Author verification only; independent review is still required. Base/HEAD remains
`acb131f18c200bb028ee86fa3a8ef9a2f6c040a3`, branch
`issue-136-indefinite-messaging-permissions`; changes are deliberately uncommitted.

Final focused run: **104 tests passed**, including **19 new issue136 tests**,
using the mandated read-only test venv, `PYTHONPATH=src`, and the specified
collective-memory checkout. Modules: issue136 permissions/migration, DM-021
identity, DM-024 runtime, DM-079 authority epochs, DM-082 relationships, DM-051
sealed, runtime relationship authority and weave V1 contracts. Published V2
schemas/vectors are checked through actual signed fixtures. Ruff check/format,
mypy on all 58 source files, DM-082 vector `--check`, and `git diff --check` pass.
Changed-file secret scan and exact claim-resource audit pass; no new source module.

Exploratory full regression before the final freeze: **796 tests**, **22 skips**,
**2 failures**. One was V1 relationship scenario drift caused by adding a link to
its byte-pinned normative spec; that optional link was removed (V1 spec untouched),
and final focused/vector checks pass. The remaining failure is the expected
DM-041 generated package/provenance inventory drift. The explicit DM-041 generator
`--check` names `provenance/hermes-agent-0.19.0.json`,
`vectors/hermes/v1/valid/profile-manifest.json`,
`vectors/hermes/v1/valid/launch-receipt.json`, and
`vectors/hermes/v1/index.json`. These excluded files were NOT regenerated.
The full run also emitted temporary-directory cleanup ResourceWarnings at process
exit; the final focused run did not. The full suite is **not claimed green** and
must be rerun after parent-owned generated inventory reconciliation.

No commits, pushes, GitHub writes, participant mutation, real message exchange,
model launch or production service operation was performed. Local test fixtures
and loopback test services do not constitute deployment acceptance.
