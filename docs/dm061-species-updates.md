# DM-061 species evolution and declared branching

Status: implemented as synthetic V0 release evidence. No real species,
speciation, Agent 0, live runtime cutover, or incompatible adoption is claimed.

## Outcome

DM-061 implements the frozen DM-014 species contract inside `daimon-matrix`:
content-addressed genomes and bundles, threshold-maintained genesis and release
chains, deterministic local compatibility verification, the read-only paged
`/species.incoming` projection, crash-safe compatible application, fork
quarantine and resolution, rollback, and deliberate incompatible branching to
a new species.

Here “Matrix” means the internal `daimon-matrix` component. Matrix.org is not a
dependency. Daimon Cluster may host an embodiment and its state volume, but it
does not decide species validity, compatibility, or application.

## Three independent decisions

DM-061 never collapses these decisions:

1. **Release validity** verifies canonical bytes, IDs, predecessor position,
   exact maintainer policy, threshold authorization, new-key possession,
   immutable floors, high-water and fork state.
2. **Compatibility** is recomputed locally from the accepted predecessor's
   exact requirements and CAS bytes in the pinned deterministic WASI sandbox.
3. **Application** is a subject-local opt-in effect that rechecks a frozen
   incoming snapshot, policy, capability set and registry cursor under the
   application lock.

A valid release can therefore be incompatible or locally vetoed. Import never
means adoption, and a maintainer or remote-CI assertion cannot substitute for
local verification.

## Registry and fork semantics

The registry persists canonical genesis and release artifacts, endorsement
sets, every occupied position, greatest observed position, the last
unambiguous accepted head, fork evidence, closed epochs, branch relations,
incoming page sets and application events.

- Genesis and release zero require threshold authorization plus possession by
  every initial maintainer.
- Compatible successors advance exactly one sequence and name the exact
  predecessor.
- Policy rotation is authorized by the predecessor policy; every resulting
  key proves possession and the immutable genesis floor still holds.
- Same-position siblings quarantine the epoch and descendants. Arrival order,
  label, length, timestamp and hash never choose a winner.
- Only a specialized next-epoch resolution with complete committed closure and
  fresh resulting-key possession closes a normal fork. Old-epoch evidence is
  retained and cannot reopen the epoch.
- A genesis/release-zero fork is terminal for that species identifier.

## Deterministic verifier boundary

The implementation pins `wasmtime==45.0.0`; its exact Linux wheel digest and
upstream provenance are recorded in `requirements-species.txt` and
`provenance/wasi-runner-v0.json`.

Every selected suite and invariant binds its runner, resource profile, inputs,
expected output, implementation bundle and dependency closure by content
reference. Matrix resolves those bytes from its local CAS and recomputes the
report. The runner provides:

- fixed-zero time and deterministic clock resolution;
- no network, randomness, environment, devices, threads or child processes;
- no argv and exact stdin/export selection;
- read-only normalized `/bundle` and `/deps` trees;
- fresh engine store per case; and
- per-case and aggregate fuel, wall-time, memory, output, file-count,
  filesystem-byte, dependency-depth, dependency-node and closure-byte bounds.

Mutating WASI calls, network/randomness imports, traversal, absolute paths,
aliases, cycles, over-deep dependencies, digest mismatch, missing bytes and
resource exhaustion fail closed. Bundle files are individual CAS blobs and are
never extracted as archives, so symlink, hardlink, device and archive-bomb
semantics have no representation in the executable format.

## Incoming and application

`species.incoming` returns an unsigned deterministic snapshot whose precedence
is `quarantined`, `incomplete`, `diverged`, `current`, then
`compatible-behind`. It binds subject, immutable enrollment, effective
application, accepted/greatest/closed cursor, all occupied positions, candidate,
missing/conflict references and evidence closure.

Paths longer than 64 releases are content-bound pages. Every page repeats the
same occupied-position hash and candidate; application remains ineligible until
the final null continuation and the complete page set has been stored and
reverified.

Application uses an owner-local cross-process lock and a fenced fsynced journal:

1. persist the prepared exact pointer and deterministic event identifier;
2. switch and fsync the non-serving pointer;
3. append one subject-operational `matrix/species-release-application` event;
4. record the exact event and un-fence.

Startup recovery checks the canonical ledger event. Before durable event commit
it restores the prior pointer; after durable commit it completes the exact
target. Exact retry never repeats the effect. A late release fork creates a new
`release-fork` rollback event and restores the most recent previously applied
unforked ancestor without changing `/me`, enrollment, memory or history.

## Existing beings and receiving preparation

The runtime does not require recreating a being to configure species updates.
The V7 `species` section selects a subject-local registry context; incoming and
application use the existing signed manifest's `being_ref`. Its
`enrollment_release_id` fixes the baseline of that species context. It does not
rewrite the being's birth/control genesis, credentials, embodiment or history.
An existing parent carrier still cannot adopt an incompatible child in V0.

Use the existing CAS, registry and runtime configuration route:

1. Select the attributed shared `/me` definition and real implementation,
   contracts, suites and boundary invariants. Exclude personal `/me.identity`,
   private memory, body bindings and credentials. `/we` remains the same being's
   plural embodiments, never all beings of the same species.
2. Reuse dedicated species-maintainer custody and its published threshold policy.
   Maintainer keys must be distinct from identity, recovery and operational roles.
   The deterministic keys and no-op bundles in `synthetic_species` are test
   fixtures, not a production foundation or maintainer policy.
3. Prepare the exact content closure and accepted genesis/release in the receiver's
   bounded local CAS/registry using `SpeciesCAS` and `SpeciesRegistry`. Store its
   explicit local policy with `store_local_policy`; `auto_apply: false` vetoes
   application. Resolve existing authorized custody and ingress before modifying
   a live runtime. Do not open its active writer's stores offline.
4. Through the owning compatible runtime-maintenance route, configure the existing
   `species` section with the selected species ID, fixed baseline release ID,
   policy reference and distinct owner-local CAS/registry/pointer filenames.
   Preserve all identity, custody, ledger and unrelated runtime fields. Required
   dependencies include the qualified deterministic runner; inspect the installed
   generation before rebuilding or installing anything.
5. Use authenticated `species.incoming` and follow its exact paged snapshot to
   completion, then `species.apply` with a retained operation UUID under the
   existing species operator capability. Observation grants alone do not authorize
   application. Retain the request/result and use exact retry/recovery, never a new
   operation to hide an uncertain outcome. Verify the application event's subject,
   selected release and unchanged original history/identity.

Bound prepared content to the declared closure/resource limits and the selected
host's available storage. Retain only the active selection, required rollback,
unfinished operations and necessary evidence under the owning retention policy;
do not accumulate a full runtime copy per preview or application.

The pointer is **non-serving**: a committed species application does not install
skills, change a harness prompt or prove model use. Use the existing selected
artifact installer for authorized behavioral/skill delivery and observe actual
receiving consumption separately. Source ancestry assertions, locally admitted
claims and species-release validity also remain separate; a Skills project
publication or shared species never supplies a disclosure grant.

`HostedSpeciesRuntimeTests.test_existing_being_bootstrap_and_successor_preserve_identity`
qualifies the authenticated runtime/ledger path on a synthetic existing being.
It is not a live cohort adoption receipt or a production species-authoring tool.

## Deliberate incompatible branching

A new species requires two independent authorities:

- the parent predecessor policy signs an ordinary next-position
  `branch-declaration` with unchanged parent genome, bundle and policy plus a
  complete incompatible child foundation; and
- the child's distinct initial maintainers authorize its self-certifying
  genesis and release zero and prove possession.

The foundation commits both nonces, exact child genome/bundle/policy/floor,
every breaking delta and locally recomputed predecessor-selected evidence.
Every actual difference must be declared exactly once. Protected
identity/history/memory/membership/authority changes are not branchable.

An existing parent-species carrier reports the child as `diverged` and cannot
apply it in V0. A fresh DM-013 newborn may enroll the exact accepted child
release. Missing, invalid or later-forked species context quarantines only
species provenance/application; it never invalidates the independently
self-certifying being.

## Public surfaces

Runtime bundle V7 may configure one private species CAS, registry, application
pointer, immutable enrollment release, species identifier and local policy.
The authenticated daemon, CLI and MCP expose only:

- `species.genesis.ingest`;
- `species.release.ingest`;
- `species.incoming`;
- `species.apply`; and
- `species.rollback`.

They expose no database handle, CAS path, private maintainer seed, pointer path,
runner process, mutable package manager, credential, route or raw authority
state.

## Reproducible evidence

Run the source or installed journey in an empty owner-only directory:

```bash
PYTHONPATH=src python -m daimon_matrix.synthetic_species \
  --state-root /an/empty/owner-only/root \
  --output /an/existing/parent/dm061-report.json

daimon-synthetic-species \
  --state-root /an/empty/owner-only/root \
  --output /an/existing/parent/dm061-report.json
```

The output is canonical, atomic, mode `0600`, path-free and secret-free. The
journey creates deterministic synthetic parent/child species, bootstraps and
advances one synthetic carrier, proves child enrollment versus existing-carrier
refusal, discovers a late fork and rolls the runtime back. It performs no live
host, Cluster, Tribe, gateway or provider effect.

`tools/generate_dm061_vectors.py --check` reproduces:

- `conformance/fixtures/dm061-synthetic-species.json`;
- `vectors/species/v0/synthetic-report.json` and its hash-bound index; and
- `conformance/species-section14-v0.json`, the exact 124-row executable map of
  DM-014 Section 14.

The four top-level DM-026.16 scenarios are `species_registry_state`,
`species_compatibility_sandbox`, `species_application_recovery`, and
`species_branch_birth`.

## Operational boundary

This card does not authorize installing a real candidate, cutting over a live
being, provisioning a Cluster body, creating Agent 0, or adopting an
incompatible child into an existing being. Those actions require later cards
and explicit human authorization. The Matrix↔Cluster contract continues to be:
Matrix owns signed lineage and application truth; Cluster owns concrete
process, volume and resource-fence effects and reports their observed truth.

## References

- [Species evolution contract](../specs/species-evolution.md)
- [DM-061 invariant record](verification/dm061-invariants.json)
- [DM-061 scenario registry](../conformance/species-section14-v0.json)
- [WASI runner provenance](../provenance/wasi-runner-v0.json)
