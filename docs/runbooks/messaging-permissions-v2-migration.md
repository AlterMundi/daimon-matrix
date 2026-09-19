# Messaging permissions V2 migration — integration handoff

Status: library APIs plus the bounded F3 operator apply/resume transaction are
implemented. **No live participant migration is authorized or claimed.** Do not
edit a participant bundle by hand. Exact owner approval, independent review and
installed Matrix/Cluster qualification remain mandatory. F1/F2 production
messaging integration is still blocked on successor claim scope for #132-owned
files.

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
* `operator_rebirth.create_messaging_permissions_migration_approval`: signs one
  exact V1-to-V2 publication. It binds old/new canonical bundle hashes; control,
  manifest, policy and relationship heads; complete authority-history values and
  hashes; complete current-revocation values and hashes; capability-journal
  identity/key identity; preserved inbox/outbox/RPC file references and hashes;
  and the output generation.
* `operator_rebirth.prepare_messaging_permissions_migration` and
  `resume_messaging_permissions_migration`: establish and authenticate an
  owner-only durable journal, stage/fsync/replace the exact candidate, advance an
  authenticated monotonic generation floor, and finish an exactly retryable
  completion record. Existing or corrupt conflicting state fails closed.
* `daimon-rebirth apply-messaging-permissions-migration` and
  `resume-messaging-permissions-migration`: executable wrappers for those APIs.

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
7. The bounded F3 transaction now supplies staged/fsynced owner-approved runtime
   publication, an exact authenticated recoverable journal, and an authenticated
   monotonic generation floor. It revalidates the actual old/new runtime authority
   and the stage-appropriate supplied policy/relationship heads. Fault-injection
   tests cover every durable boundary. This does not satisfy obligations 1-6 or
   authorize mutation of their owning modules.
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

## F3 apply and recovery procedure

The owner approval and journal key are separate inputs. The journal key file MUST
be an owner-only, single-link regular file containing 32-64 bytes and MUST be the
key whose derived identity is bound by the signed approval. Runtime, candidate,
authenticated journal/floor and preserved inbox/outbox/RPC files also MUST be
owner-only single-link regular files; link count is checked both before and after
open. Candidate and approval JSON MUST be canonical owner-only regular files. The
approval is created only after the old runtime, V8 candidate, current heads, and
exact preserved state files have been frozen and reviewed.

### Required OS quiescence and privilege separation

The transaction lock serializes cooperating migration invocations; it is not a
security boundary against another process with the same UID or a privileged
writer. Before `apply` or any `resume`, stop the runtime/model and every inbox,
outbox, RPC, policy, relationship, backup, restore or administrative writer that
can reach the state root. Run migration under a dedicated operator account while
those processes cannot impersonate that account. The selected root MUST be an
owner-only directory reached through non-symlink ancestors that ordinary runtime
users cannot rename, replace or write. Keep this quiescence until the command
returns and the installed runtime, floor and completed journal have been read
back.

The implementation retains and revalidates the root directory FD and a per-runtime
`flock`, performs supported child operations relative to that FD, retains the
runtime/journal/floor/candidate and all three preserved-reference descriptors,
and rechecks pathname/inode identity, metadata and hashes at commit boundaries.
After each floor/completion staging file is fully written and file-fsynced, a final
invariant check runs while the retained root, lock, installed-runtime,
prepared-journal and preserved-store descriptors are still open, immediately before
the authoritative-name install. It verifies the installed runtime bytes before floor
or completion publication. A detected candidate, reference or root race fails
without completing; repair the exact approved filesystem state and retry. These
checks narrow accidental races but do not make hostile same-UID mutation safe
between all kernel syscalls; OS quiescence and privilege separation are therefore
mandatory, not advisory.

First execution establishes the journal and applies it:

```bash
daimon-rebirth apply-messaging-permissions-migration \
  --state-root /exact/runtime/root \
  --runtime-name runtime.json \
  --candidate /owner-only/reviewed-v8.json \
  --approval /owner-only/signed-migration-approval.json \
  --journal-key-file /owner-only/capability-journal.key \
  --current-policy-head OLD_POLICY_SHA256 \
  --current-relationship-head OLD_RELATIONSHIP_SHA256
```

After interruption, inspect which approved head set is current. If the runtime is
still the old exact hash, provide the old policy/relationship heads. If the exact
new bundle has already been published, provide the new heads:

```bash
daimon-rebirth resume-messaging-permissions-migration \
  --state-root /exact/runtime/root \
  --runtime-name runtime.json \
  --journal-key-file /owner-only/capability-journal.key \
  --current-policy-head CURRENT_APPROVED_POLICY_SHA256 \
  --current-relationship-head CURRENT_APPROVED_RELATIONSHIP_SHA256
```

The durable boundaries are: authenticated `prepared` journal, exact candidate,
published runtime output, authenticated generation floor, and authenticated
`completed` journal. Journal, candidate, floor and completion bytes are first
written to transaction-unique owner-only staging names, fully written and file-
fsynced, then atomically installed and directory-fsynced. An interrupted retry
classifies and removes only strict transaction-owned staging residue; a partial
write is never exposed under an authoritative name. Every authoritative file and
containing directory is fsynced before its durable boundary is reported.
Repeating resume after completion produces the same bytes. Unknown runtime bytes,
changed preserved references, changed heads, a corrupt or different journal, a
corrupt floor, a same-generation conflict, an unexpected hard link, or a
generation below the durable floor is rejected. Never delete authoritative
records to force a retry; repair the exact authenticated transaction forward.

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
