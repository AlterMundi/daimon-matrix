# Daimon Cluster adapter for Matrix relationship state

Status: required adaptation contract; Matrix owns semantics, Cluster owns host
lifecycle. “Matrix” means `daimon-matrix`, not Matrix.org.

## Non-authority rule

Cluster MUST NOT infer a relationship, membership, founder, invitation, grant,
revocation or disclosure decision. A body record, running container, route,
lease, fence, snapshot, effect receipt or observed process state is never social
or resource authority. Cluster may report effect truth only for the lifecycle
operation it actually observes.

## Required Cluster adaptation

1. Pin an exact Matrix commit that supports `dm.runtime.bundle/v7` and reject a
   mismatched installed package before start.
2. Accept V7 bundles and preserve the closed `relationships` configuration
   without translating known beings into Cluster registry rows.
3. Provision the relationship database under the embodiment's owner-only
   portable state root. Never mount one writable database into two processes.
4. Start one Matrix daemon per embodiment with the existing resource-fence
   lifecycle. The fence protects the process and state resource; it grants no
   relationship permission.
5. Quiesce Matrix before snapshot. Back up ledger, relationship store, source
   store, transport state, custody descriptors and bundle as one consistent
   embodiment state set; do not copy WAL or live partial state.
6. On restore or rebirth, verify the exact snapshot receipt, advance through the
   Matrix authority-epoch protocol, retain old signed history and start with a
   new authorized incarnation. Do not rewrite card or membership history.
7. Health checks may assert process availability, owner-only files, SQLite
   integrity, bundle/package pin and Matrix status. They MUST NOT synthesize a
   successful disclosure or grant.
8. Rollback may restore a quiesced complete snapshot or revert adapter code. It
   MUST NOT delete canonical relationship events to make a stale snapshot pass.

## Interoperability gate

The Cluster repository must add an installed-process test that:

- installs the exact pinned Matrix wheel;
- loads a V7 bundle with relationship storage;
- runs the deterministic Matrix relationship journey or equivalent daemon calls;
- stops and snapshots the embodiment through real Cluster lifecycle adapters;
- restores it under a newly authorized incarnation;
- proves status/cursor continuity and revoked-grant non-resurrection; and
- proves a second writer, package-pin mismatch, symlinked state and corrupted
  snapshot fail before process start.

The test uses isolated roots and inert resources. Any real-host preflight,
deployment, participant contact or service cutover requires separate explicit
authorization.
