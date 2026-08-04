# DM-079 signed authority-epoch succession

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

Hosted successor state uses closed `dm.runtime.bundle/v2`. Its
`authority_history` contains every prior root manifest and the signed successor
leading to the next entry or the current `manifest`. V1 remains valid for a
single unchanged epoch. Once a ledger accepts V2 history, reopening it with the
old V1 bundle is a downgrade and fails.

Activated provisional history and root-authority history are deliberately
separate mechanisms. V2 refuses to combine them in this first profile; the
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
fresh physical incarnation, installing the already signed V2 bundle, retaining
the same per-embodiment volume and starting the daemon through descriptor-only
custody. Matrix validates the epoch before binding its socket. Cluster registry
equality is still required, and neither manifest nor incarnation authority
substitutes for a current resource fence.

Schemas are `schemas/weave/v1/authority-epoch.schema.json` and
`schemas/hosted/v2/bundle.schema.json`. Core, corruption, downgrade, hosted
restart and projection evidence is in `tests/test_dm079_authority_epochs.py`;
the canonical signed positive and tampered negative fixtures are reproducibly
generated under `vectors/weave/v1/authority-epoch/`;
the installed cross-repository process/relocation proof lives in
`daimon-cluster#48`.
