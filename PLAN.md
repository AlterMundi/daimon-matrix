# Daimon Matrix delivery plan

## Product boundary

The release candidate coordinates `daimon-matrix` and `daimon-cluster`.
Matrix owns identity continuity, canonical history, scopes, relationships,
grants, memory policy and communication semantics. Cluster owns bodies,
incarnations, storage, lifecycle effects and shared-resource admission/fencing.
Tribe Bridge is a transitional component, not a third authority.

## Delivery sequence

1. Qualify the merged Matrix baseline and set package/application metadata to
   `0.1.0rc1`.
2. Remove or explicitly fixture-isolate never-deployed runtime-bundle V1–V6
   and pre-V3 client compatibility before the package surface is frozen.
3. Land the final Cluster admission, recovery handoff and Matrix V7 package
   adaptation; pin exact commits in both directions.
4. Keep Tribe on its native transitional path while finishing zero-SSH
   provisioning/rotation preparation and expiration handling in code, tests
   and documentation.
5. Build Matrix artifacts reproducibly and verify metadata, allowlists,
   signatures, hashes and clean installation.
6. Run cross-repository local/CI suites and disposable end-to-end lifecycle
   journeys without contacting existing infrastructure.
7. Produce one content-addressed RC manifest with provenance, supported Python
   versions, commands, limitations and rollback instructions.
8. Obtain independent review for each exact final candidate and merge through
   normal repository protection.
9. Prepare the physical and cross-being canary plans. Stop at their human
   authorization gates.

## Completion evidence

Automatable work is complete only when all three repository heads and their
cross-pins are exact, clean and green; artifacts reproduce; empty-environment
installation succeeds; lifecycle journeys pass without reruns masking flakes;
and documentation/tracking describe the same state.

Passing compilation or unit tests alone is insufficient. Historical
experiments remain useful evidence, but are not substituted for the final RC
qualification and do not imply a present deployment.
