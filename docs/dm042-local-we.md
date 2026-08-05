# DM-042 Codex and Hermes in one local `/we`

Status: implemented synthetic integration contract.

“Matrix” in this document is the `daimon-matrix` component. Matrix.org is not
used. The test runs locally and does not claim a multihost Cluster deployment,
live model-provider access, CompAII rebirth, Tribe delivery or publication.

## Outcome

DM-042 proves that Codex and Hermes can be two simultaneously active,
replaceable embodiments of one root-authorized being without collapsing their
custody, runtime state, ledgers or adoption choices. It composes the public
DM-040 Codex adapter, DM-041 Hermes adapter, DM-021 root authority, DM-022
ledger, DM-023 sync and projection engine. It does not introduce a second
identity or synchronization protocol.

The integration starts both real adapter state machines. Child/provider and
App Server effects are synthetic and bounded: no model is called and no live
provider credential is present. Each adapter nevertheless performs its normal
profile verification, bootstrap admission, pending-before-effect transition,
ready/presence checks and active-handle receipt creation.

## Shared authority and independent custody

Both bootstraps bind the exact same:

- `dm:being:v1` root;
- root control head and canonical `being-manifest/v2` digest; and
- initial Matrix high-water.

Each body has a different body reference, embodiment, incarnation, transport
principal, embodiment credential, incarnation authorization, signing key,
encryption key, transport key set, Matrix session, capability-set hash,
profile ID/root, runtime session and SQLite file/inode. The report is refused
if any identity/custody value aliases or the writable ledgers resolve to the
same regular file.

DM-040 now accepts the identity forms defined by the root contract:
`body_ref` is bounded opaque text, while embodiment and incarnation are
canonical `embodiment:...` and `incarnation:...` identifiers. Derived
`dm:...` IDs remain required for the Matrix session and content-addressed
adapter artifacts. This corrects the isolated adapter's earlier synthetic-only
ID assumption; it does not weaken root verification.

Hermes launch evidence also has a standalone verifier. The verifier recomputes
the plan and launch IDs and checks the pinned Hermes version/commit, Python
interval, complete loaded Matrix package evidence, profile, handles, ready
receipt, session, high-water and deployment class. DM-042 additionally
re-verifies both on-disk profiles and binds each launch receipt to its exact
plan before accepting it.

## Partition, convergence and plurality

The deterministic scenario is:

1. Codex and Hermes reach `active` while both body handles remain live.
2. While partitioned, Codex authors the shared target and Hermes authors an
   independent observation. The opposite SQLite cannot read either event.
3. Two DM-023 exchanges import both signed events. Exact request, page and
   receipt replay is checked.
4. Codex locally authors `adoption.decided=adopt`; Hermes locally authors
   `adoption.decided=reject` for the same target.
5. Two further exchanges make both event sets and heads identical.
6. Both ledgers are reopened. Serving and pulling all four frozen exchanges
   returns byte-identical pages and receipts.
7. The local Codex projection remains `adopted`; the local Hermes projection
   remains `rejected`; each records the other decision as remote evidence.

This is the intended meaning of plural embodiment. Import is not adoption,
convergence is not uniform preference, and another embodiment's decision does
not acquire local projection authority.

## Validation receipt

`dm.local-we.validation/v1` is a closed, path-free, content-addressed receipt.
It contains:

- being, root control-head and manifest bindings;
- exactly ordered Codex and Hermes evidence;
- authority credential/authorization and public key identifiers;
- Matrix session/high-water, capability set, profile and launch receipt IDs;
- converged event-set and head hashes;
- each local decision/projection and its remote decision references;
- sorted bidirectional DM-023 page/receipt/count evidence; and
- explicit storage/custody isolation observations.

Before issuing it, the producer also reconstructs both projections directly
from their supplied SQLite ledgers and requires byte equality with the claimed
projections; a merely shape-valid, self-hashed projection is insufficient.

The report contains no filesystem path, profile bytes, SQLite content,
bootstrap signature, capability, provider secret, prompt, model output or
private key. `validate_local_we_report` validates it without filesystem access,
including content-derived ID, canonical form, ordering, direction coverage,
shared convergence hashes, distinct public custody evidence and crossed remote
decision references. Filesystem/profile/authority truth is checked by
`create_local_we_report` before the bounded receipt exists.

The schema is `schemas/local-we/v1/validation.schema.json`. Deterministic public
vectors and their digest index are under `vectors/local-we/v1/`. Regenerate or
check them with:

```bash
python tools/generate_dm042_vectors.py
python tools/generate_dm042_vectors.py --check
python -m unittest tests.test_dm042_local_we -v
```

## Failure matrix

| Fault | Required outcome |
|---|---|
| Different root manifest | refuse before report |
| Shared ledger path or inode | `shared_writable_ledger` |
| Body not active in root manifest | refuse authority evidence |
| Bootstrap/origin mismatch | refuse body binding |
| Swapped plan, profile or launch receipt | refuse launch evidence |
| Reused credential, key, session or capability set | refuse distinct custody |
| Missing author from either body | refuse plurality proof |
| Non-identical final event sets or heads | refuse convergence proof |
| Imported decision replaces local decision | refuse independent adoption |
| Missing reverse sync direction | refuse bidirectional proof |
| Repeated request ID | refuse sync evidence |
| Path or secret in report | impossible by closed construction; tests scan path absence |
| Report mutation with stale ID | refuse content-addressed receipt |

No failure path deletes or repairs a profile, ledger or runtime journal.

## What this does and does not unlock

DM-042 removes the single-host composition risk: the two supported runtime
types can inhabit one canonical `/we`, exchange signed history and preserve
local plurality. It is a prerequisite for a later real rebirth demonstration,
not that demonstration itself.

To rebirth CompAII on another host, the remaining roadmap must still supply
Cluster-hosted body lifecycle/presence, communications migration from Tribe,
multihost transport and sync, handoff/park fencing, installation and operations
receipts, then a live canary that restores no ambient model memory. Those
responsibilities stay with their owning cards; DM-042 deliberately cannot
simulate them into completion.

## Rollback

DM-042 adds no live state or migration. Rollback removes the code/schema/vector
release as one source change. A future live deployment must instead park bodies
and preserve Matrix ledgers, root history, high-waters and launch receipts;
deleting runtime state is never a continuity rollback.
