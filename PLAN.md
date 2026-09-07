# Daimon Matrix delivery plan

## Product boundary

The stable successor coordinates `daimon-matrix` and `daimon-cluster`.
Matrix owns identity continuity, canonical history, scopes, relationships,
grants, memory policy and communication semantics. Cluster owns bodies,
incarnations, storage, lifecycle effects and shared-resource admission/fencing.
Tribe Bridge is superseded, not a third authority or a stable dependency.
Matrix's native tribe/relationship governance remains part of the being model;
it is not the retired Bridge product. Bridge ACKs never establish Matrix intake
or semantic receipts. [TRIBE-MIGRATION.md](TRIBE-MIGRATION.md) is current policy:
no Bridge operational-state migration, compatibility, downgrade, fallback or
dual-run. This plan neither authorizes live removal nor claims it occurred.

## Delivery sequence

1. Qualify the merged native Matrix+Cluster successor and prepare `0.1.0`
   package/application metadata under [#72](https://github.com/AlterMundi/daimon-matrix/issues/72).
   The `0.1.0rc1` three-repository freeze remains historical evidence only.
2. Freeze the runtime-bundle V7 and client-config V3 surface; the never-deployed
   compatibility paths have been removed from production code.
3. Land the final Cluster admission, recovery handoff and Matrix V7 package
   adaptation; pin exact commits in both directions.
4. Qualify native authenticated intake, logical delivery, restart/retry,
   expiration/revocation and foreign-being signed semantic receipts without
   provisioning, rotating or retaining Bridge as a release requirement.
5. Build Matrix artifacts reproducibly and verify metadata, allowlists,
   signatures, hashes and clean installation.
6. Run cross-repository local/CI suites and disposable end-to-end lifecycle
   journeys without contacting existing infrastructure.
7. Prepare a new external content-addressed Matrix+Cluster stable freeze with
   exact commits, provenance, supported Python versions, commands, limitations
   and native recovery/rollback instructions, never a return to Bridge. The
   historical three-repository RC manifest/tool is not a stable input; this
   plan does not claim the successor manifest/tool is already implemented.
8. Obtain independent review for each exact final candidate and merge through
   normal repository protection.
9. Prepare native continuity, physical and cross-being canary plans. Stop at
   their scoped custody and consent gates ([#40](https://github.com/AlterMundi/daimon-matrix/issues/40)).
   Live Bridge removal requires its own reviewed exact deletion inventory and
   matching GO. Stable publication ([#44](https://github.com/AlterMundi/daimon-matrix/issues/44))
   and the later final source-only release/archive
   ([#73](https://github.com/AlterMundi/daimon-matrix/issues/73)) require separate
   exact-candidate/owner authorizations; none substitutes for another.

## Completion evidence

Automatable stable work is complete only when both Matrix and Cluster heads
and their cross-pins are exact, clean and green; artifacts reproduce; empty-environment
installation succeeds; lifecycle journeys pass without reruns masking flakes;
and documentation/tracking describe the same state.

Passing compilation or unit tests alone is insufficient. Historical
experiments and the three-repository RC remain useful historical evidence, but
are not substituted for native Matrix+Cluster stable successor
qualification and do not imply a present deployment.
