# Implementation workstreams

The GitHub project and repository issues are the live tracking system. This
file records stable ownership and successor workstreams; it intentionally does
not mirror transient PR or deployment status.

[TRIBE-MIGRATION.md](TRIBE-MIGRATION.md) is current retirement policy. Historical
three-repository RC evidence remains preserved, but stable qualification is
native Matrix+Cluster; Bridge is neither a stable dependency nor an authority.

## Matrix-owned

- Being-root, embodiment and incarnation authority.
- Distributed root/recovery custody contracts and signed holder artifacts.
- Canonical ledgers, sync, projections, scopes, native tribe/relationships and
  grants; native tribe governance is distinct from the retired Bridge product.
- Authenticated daemon/CLI/MCP surfaces and purpose-limited runtime clients.
- Native encrypted intake, logical delivery and semantic receipts.
- Reproducible package, 102-scenario conformance registry and RC provenance.

## Cluster-owned

- Body/incarnation lifecycle and state-volume handling.
- Shared admission/fencing across hosts or state directories.
- Root-authorized new-embodiment handoff without private-key or writable-state
  cloning.
- Backup/export, restore, disaster rebuild, rollback and crash-safe journals.
- Exact installed Matrix dependency and capability-profile adaptation.

## Retired Bridge boundary

- Bridge provisioning, rotation and retention are not active release workstreams.
- No Bridge operational-state migration, compatibility, downgrade, fallback or
  dual-run; preserve public Git provenance, not operational state.
- Bridge transport ACK never establishes Matrix intake or semantic receipt.
- Repository retirement decisions do not imply live removal or source archive.

## Stable successor preparation

- [#72](https://github.com/AlterMundi/daimon-matrix/issues/72) owns candidate
  preparation/freeze: exact Matrix+Cluster heads, tested cross-pins,
  reproducible artifacts, clean installation and native continuity evidence.
- A new external content-addressed two-component freeze must replace the
  historical three-repository RC as the stable checkpoint. This is a
  requirement, not a claim that a successor manifest/tool is implemented.

## External gates

- native continuity/cutover and independent real custody;
- purpose-built physical targets and backup target selection;
- exact authorization for a content-addressed physical plan;
- cross-being operational consent, separate protocol acceptance and participant
  custody ([#40](https://github.com/AlterMundi/daimon-matrix/issues/40));
- live Bridge removal: separately reviewed exact deletion inventory and matching GO;
- stable publication: independent exact-candidate approval and release-owner GO
  ([#44](https://github.com/AlterMundi/daimon-matrix/issues/44));
- later final Bridge source-only release/archive: separate exact preflights and
  owner GOs after native continuity and stable publication
  ([#73](https://github.com/AlterMundi/daimon-matrix/issues/73)).

No gate authorizes another, and source archival does not prove runtime deletion.

Cards or historical acceptance text that imply identity-wide singleton
exclusion, current deployment, or authority derived from transport/lifecycle
state are superseded by the current contracts.
