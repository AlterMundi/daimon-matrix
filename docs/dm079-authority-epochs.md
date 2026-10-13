# DM-079 signed authority-epoch succession

> Explicit successor: [messaging permissions V2](../specs/messaging-permissions-v2.md) adds indefinite
> messaging validity, root/body-approved credential succession and V8 startup.
> Historical V1 signed semantics below remain unchanged. This library slice
> does not establish messaging integration, migration or live acceptance.

Status: implemented V0 contract for a same-embodiment incarnation restart.

DM-021 could authorize incarnation `N+1`, but DM-022/024 originally fixed one
SQLite database to its first `manifest_hash`. A real Cluster-hosted restart
therefore failed even when both incarnations were valid. DM-079 makes that
transition explicit without treating a newer manifest as an implicit winner.

## Exact transition

`dm.we.authority-epoch/v1` binds the previous and successor manifest hashes and
revisions, the stable being and embodiment, both incarnation IDs, the exact new
incarnation-authorization artifact, and its issue time. The delegated
embodiment Ed25519 key signs the complete canonical transition.

The V0 validator permits one operation only:

- the being, control head and optional history binding are unchanged;
- the manifest revision advances by exactly one;
- the prior active row becomes byte-identical `retired` history;
- exactly one active row is appended for the same body, embodiment and
  root-issued credential;
- its embodiment-signed authorization has incarnation sequence `N+1` and a
  later start time;
- every row for every other embodiment is byte-identical; and
- the successor has at most one active incarnation for each embodiment.

Adding/removing an embodiment, changing a body or credential, advancing the
root control head, reviving a retired incarnation, skipping a sequence, or
combining competing successors requires a different future transition
contract and is rejected here. Thus the ordinary body restart does not require
root seeds online, but it also cannot mutate another embodiment's authority.

## Exact historical verification

`RootHistoryAuthority` contains an ordered chain of individually verified
`RootAuthority` values. For a stored or imported event, its signed
`manifest_hash` selects exactly one authority. Historical events are never
reinterpreted under the active manifest. New events and all live `/me`, `/we`,
transport and relationship checks use only the active authority.

Hosted successor state uses closed `dm.runtime.bundle/v7`. Its
`authority_history` contains every prior root manifest and the signed successor
leading to the next entry or the current `manifest`. Runtime bundles V1 through
V6 were never deployed and are rejected; there is no compatibility or downgrade
path.

Owner-local clients use config V3 and accept only the current expected server
and runtime identity. Both are repeated inside every authenticated response;
well-formed but substituted config identity fields therefore cannot be dead
metadata. Responses from retired incarnations fail closed; callers must retry
against the current incarnation.

Activated provisional history and root-authority history are deliberately
separate mechanisms. V7 refuses to combine them in this first profile; the
provisional binding must be completed before the first root-authority epoch
succession.

## SQLite transaction

The ledger admits a metadata change only when the being, local embodiment and
trust mode are stable; the prior accepted-hash set is a strict subset of the
new verified set; and both old and active hashes are present. Under one
`BEGIN IMMEDIATE` transaction it then:

1. parses every immutable event from its canonical stored bytes;
2. verifies it under the exact authority selected by its manifest hash;
3. compares all indexed identity, sequence, kind, subject and hash columns;
4. expands `accepted_manifest_hashes` and changes the active hash; and
5. deletes only the disposable projection cache.

Any exception rolls back the complete metadata change. The exact accepted
successor reopens idempotently. Sync cursors, RPC journals, communication state,
canonical events and effect receipts are preserved. Runtime status exposes
only the active hash, sorted accepted hashes and epoch count.

## Cluster handoff

Cluster remains responsible for quiescing the old process, registering the
fresh physical incarnation, installing the already signed V7 bundle, retaining
the same per-embodiment volume and starting the daemon through descriptor-only
custody. Matrix validates the epoch before binding its socket. Cluster registry
equality is still required, and neither manifest nor incarnation authority
substitutes for a current resource fence. Matrix also supplies the exact scope
evaluation time to Cluster's body reader, so a restarted process cannot race
an independently sampled millisecond while producing `/me`.

Schemas are `schemas/weave/v1/authority-epoch.schema.json` and
`schemas/hosted/v7/bundle.schema.json`. Core, corruption, downgrade, hosted
restart and projection evidence is in `tests/test_dm079_authority_epochs.py`;
the canonical signed positive and tampered negative fixtures are reproducibly
generated under `vectors/weave/v1/authority-epoch/`;
the installed cross-repository process/relocation proof lives in
`daimon-cluster#48`.

## Surgical embodiment retirement

`dm.we.embodiment-retirement/v1` is a separate Root-threshold successor. It
retains every manifest row, credential and incarnation authorization. Only the
selected active rows become `retired`, the revision advances once, and the
control head advances through one ordinary DM-021 revocation per selected
embodiment, in sorted order. It neither rotates Root nor performs recovery.

Each control independently meets the current Root threshold. Its cutoff equals
the highest retained incarnation sequence, preserving historical verification;
its revocation generation advances exactly once, rejecting fresh credential use.
The transition also meets Root threshold and binds the exact preceding/successor
manifest hashes, revisions, control heads, control artifact IDs and issue time.
Unselected changes, forks, skipped revisions, insufficient signatures, replay
and restoration of active authority are rejected.

The previous epoch must be retained in the full supported format: manifest,
control artifacts/head, credentials, incarnations and successor. Compact history
would inherit the new control head and misinterpret the previous manifest.
Historical event verification selects its original epoch; current scope and
transport authorization use the retired manifest. Active `/we` delivery omits
retired targets without silently changing conversation fan-out semantics.

`daimon-rebirth create-retirement-intent` prepares exact public material with a
bounded expiry. `retirement-share` opens one native encrypted holder using
`--password-fd`, reconstructs that intent and emits only public signatures.
`aggregate-retirement` verifies the controls and transition without custody.
`retire-bundle` creates a verified public candidate and removes only the retired
peer targets. It refuses retirement of that bundle's local origin. These tools
do not install a bundle, interrupt a daemon, create an embodiment or wake models.

The deployment owner quiesces the selected daemon, holds its runtime lock,
retains the original encrypted custody and journals, and advances the existing
keystore control-head metadata with its compare-and-swap counter; keys remain
unchanged. Then install the verified candidate and a compatible SDK. Preserve
the forward bundle after partial completion: once retirement is accepted, code
rollback must continue understanding the signed successor or fail closed. An
old manifest/control head is history, never an active rollback selector.

Schema and deterministic positive/negative retirement vectors accompany the
existing DM-079 evidence. Live receiver uptake remains an explicit observed
deployment result, separate from preparation or signature creation.
