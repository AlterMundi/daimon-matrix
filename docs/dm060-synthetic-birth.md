# DM-060 synthetic birth acceptance

Status: historical pre-RC synthetic evidence. Its never-deployed V3 runtime
fixture is retained for contract tests, but it is no longer an installed command
or RC qualification journey. Production accepts V7 only.

## Outcome

DM-060 recorded an acceptance journey that creates a fresh synthetic parent,
witness, and newborn, accepts one
lineage, authorizes the newborn's first embodiment and incarnation, starts the
real Daimon Matrix daemon, and proves through CLI and MCP that the newborn has
one local embodiment and no autobiographical history.

This work uses Matrix to mean the internal `daimon-matrix` component. It does
not use Matrix.org.

## What the journey proves

The acceptance runner proves all of these claims together:

- parent, newborn, and witness have pairwise distinct self-certifying being
  roots;
- the offer contains no newborn identifier or key;
- the newborn root and recovery keys are generated independently with the
  production CSPRNG path;
- encrypted offline custody can be backed up and restored against the exact
  public counter and control head;
- the parent offer, awakening proof, newborn root threshold, first embodiment,
  sequence-zero incarnation, and witness receipt all validate under distinct
  domains and purposes;
- the one-use registry reaches `active` through durable verified transitions;
- the newborn root-bound manifest has exactly one active embodiment;
- the canonical ledger, memory lane, and projection cache all contain zero
  records at activation;
- installed CLI `runtime.status`, `/me`, `/we`, heads, and projection queries
  agree with the signed artifacts;
- installed MCP `scope_me` agrees with the CLI result; and
- the daemon produces only its expected `ready` and `stopped` diagnostics.

It does not claim that signatures prove social parentage or the truth of
species/source context. It does not grant a relationship, `/tribe` membership,
the parent's `/we` membership, a route, a Cluster resource, or an external
effect.

## Public input

The checked-in fixture is
`conformance/fixtures/dm060-synthetic-birth.json`. It is a closed
`dm.synthetic-birth-scenario/v1` document containing only:

- scenario UUID;
- species release identifier;
- attributed source references;
- inert tribal commitments; and
- synthetic body references for parent, newborn, and witness.

Fresh key, nonce, being, embodiment, incarnation, credential, and receipt IDs
are deliberately different on every run. Reproducibility is structural: the
same state transitions, counts, authority boundaries, surfaces, and closed
report shape must hold. Secret-byte equality is neither expected nor exposed.

The loader rejects symlinks, non-files, files over 128 KiB, unknown fields,
noncanonical UUIDs, unsafe body references, unsorted/duplicate references, and
noncanonical commitment structures.

## Isolation boundary

The runner accepts only an existing empty directory that is owned by the
effective user and has no group/other permission bits. When `--work-root` is
omitted, it creates and later removes one exact temporary root.

Within that root it creates independent locations for:

- newborn offline custody;
- backup and restore verification;
- birth registry;
- runtime custody;
- Matrix ledger and projection cache;
- Unix socket and MCP request directory; and
- client configuration.

The runner never discovers or reads a home profile, live runtime bundle,
Cluster service, Tribe Bridge store, HMK database, Codex/Hermes session,
provider account, ambient route, or message history. Peer transport is disabled
in the synthetic runtime bundle.

Passwords and capability secrets enter child processes through inherited file
descriptors. They do not appear in argv, environment, logs, or reports. Root
and recovery private material remains only in the encrypted custody test files
and in-process ceremony memory.

## Archived fixture boundary

The checked-in scenario, report schema and contract tests remain historical
evidence. `daimon_matrix.synthetic_birth` is clearly named fixture code and is
not imported by the production runtime; `daimon-synthetic-birth` is no longer a
console entry point. Executing its V3 runtime document now fails at the V7-only
loader before custody is opened. New release evidence must use the V7 operator
bootstrap/rebirth journeys.

## Report semantics

`dm.synthetic-birth-report/v1` is closed by
`schemas/birth/v1/synthetic.schema.json`. It publishes:

- public lineage and first-embodiment content identifiers;
- exact registry state;
- zero event/memory/projection counts and ledger-state hash;
- custody counter, control head, public key counts, and restore booleans;
- context counts and explicit inert/not-autobiography semantics;
- explicit zero inherited parent authority/state counts;
- installed daemon/CLI/MCP method names and canonical result hashes; and
- the exact synthetic disclaimer.

It excludes raw CLI/MCP bodies to keep the public evidence bounded and avoid
accidental operational metadata disclosure. Their hashes bind what the runner
actually validated in-process.

## Adversarial evidence

`tests/test_dm060_synthetic_birth.py` covers:

- closed schemas and unknown fields;
- newborn precommitment and awakening/root/recovery key aliasing;
- parent-controlled newborn root reuse;
- offer, copied context, receipt, signature, purpose, origin, and time tamper;
- nonempty canonical ledger/projection rejection;
- double acceptance retention and lineage quarantine without a winner;
- crash rollback and exact retry at acceptance and activation;
- concurrent replay producing one durable acceptance;
- owner-only regular-file and symlink enforcement;
- archived report validation; and
- fail-closed rejection of the pre-RC runtime fixture.

The three DM-060 conformance scenarios are `birth_contract_integrity`,
`birth_durable_one_use`, and `birth_installed_journey` in suite DM-026.16.

## Remaining production boundary

This acceptance does not authorize a live cutover. A real first birth would
still require a human-approved custody ceremony, concrete body provisioning,
independent witness policy, protected delivery of the one-use awakening secret,
and operational monitoring.

A future CompAII rebirth on another host is a different journey: it restores an
existing being root and authorizes an additional or relocated embodiment while
preserving origin-retaining history. That journey depends on the remaining V0
cards and Matrix↔Cluster integration evidence; it must not invoke DM-060 to
create a different being.

## References

- [Birth and first awakening V1](../specs/birth-first-awakening.md)
- [Being root and plural embodiment authorization](../specs/identity-root-v1.md)
- [Daimon Matrix ontology](../ONTOLOGY.md)
- [DM-060 invariants](verification/dm060-invariants.json)
