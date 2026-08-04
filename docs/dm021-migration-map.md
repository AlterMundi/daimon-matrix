# DM-010/DM-011 migration map after plural ontology

Status: normative retirement record for DM-021.

The original V0 vector corpus remains immutable historical evidence. It is not
the V0.1 runtime contract. The following classification prevents a useful
cryptographic primitive from accidentally reintroducing the retired
single-awake-body model.

| Old artifact or invariant | Classification | V0.1 destination |
|---|---|---|
| genesis self-certification | retained concept, replaced wire shape | `genesis` V1 |
| independent threshold root and recovery sets | retained and strengthened | `genesis`, `recovery` V1 |
| root transition with old authority and new possession | retained | `root-rotation` V1 |
| recovery-policy replacement and possession | retained | `recovery-policy` V1 |
| competing control successors | retained as fail-closed identity equivocation | `ControlChain` quarantine |
| recovery naming every known competing head | retained | `recovery` V1 |
| operational certificate | replaced | plural `embodiment-credential` |
| operational acceptance | retained in new scope | embodiment acceptance signature |
| per-event origin signature and causal validation | retained | `dm.we.v1` plus incarnation authorization |
| revocation generation and exact high-waters | retained | embodiment cutoff and control generation |
| root/operational/transport purpose separation | retained and strengthened | V1 verifier rejects public-key aliasing |
| HPKE/sealed-delivery vectors | retained KAT, replaced runtime wire | `dm.sealed-delivery/v1` in DM-051 |
| presence lease, wake receipt, witness and presence TTL | retired singleton behavior | no Matrix successor |
| “one active body per `/me`” | retired and forbidden | plurality regression gate |
| overlapping presence as split brain | retired and forbidden | only same-resource Cluster fence conflicts |
| presence ID used as deployment exclusion | moved out of identity | `resource-fence/v1` in Daimon Cluster |
| lease high-water in identity recovery | retired from identity | resource-local Cluster recovery evidence |
| one operational/session body substitution checks | narrowed | incarnation remains bound to one embodiment/body, without excluding peers |

Old `vectors/v0/` files and `tests/test_dm011_vectors.py` continue to prove the
published historical corpus regenerates and validates under its own frozen
rules. New runtime code MUST NOT import its presence-lease oracle, generator
state, fixtures or singleton acceptance predicates. The V1 executable contract
is `daimon_matrix.identity`, its schemas, and `vectors/identity/v1/`.

Cards DM-022–DM-026 consume the verified control state and credentials. DM-037
binds `body_ref` and incarnation evidence to Cluster without moving resource
authority into Matrix. DM-042 uses embodiment credentials for harness
adapters. DM-050–DM-055 bind Tribe principals and then absorb its transport.
DM-070 consumes the same public identity contract. DM-078 exercises additional
embodiment, relocation and disaster-rebirth journeys on distinct hosts.
