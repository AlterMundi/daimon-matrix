# DM-037 Cluster evidence and effect-truth boundary

Status: implemented synthetic contract. No live Cluster mutation or production
deployment is claimed.

DM-037 defines the exact point where `daimon-matrix` may consume facts owned by
Daimon Cluster. Matrix owns identity, canonical intent/decision/receipt events,
adoption, scopes and synchronized meaning. Cluster owns body lifecycle,
resource fences, external effects and current postcondition observation. An
adapter credential on either side never inherits the other side's authority.

## Body observations

`validate_body_snapshot` is the public validator for
`dm.cluster-body-snapshot/v1`. The document is closed and bounded; body,
embodiment and incarnation must equal the local root-authorized Matrix origin,
the observation cannot be in the future relative to the caller's single clock
sample, and resource rows must be unique and sorted. Snapshot reads have no
acquire, renew, release or mutation side effect. Presence, reachability and a
running container remain observations rather than fences.

## Resource-fence evidence

`dm.cluster-resource-fence-evidence/v1` freezes one Cluster claim over one
`resource_ref`. It binds body, holder embodiment, holder incarnation, monotonic
epoch, observation and expiry times, an opaque `verification_ref`, and a
domain-separated content hash. Constructing or hashing the document grants no
authority.

Before use, `verify_resource_fence_evidence` requires an injected Cluster
verifier to return a closed `dm.cluster-resource-fence-verification/v1` for the
same hash, resource, holder and epoch at or before the evaluation time. The
verifier owns signature validation, trusted high-water comparison and current
holder lookup. Expired evidence, `current=false`, substitution, malformed
verification and verifier outage fail closed. Matrix contains no Cluster key,
signer, lease table or fallback presence check.

Only the derived `dm.cluster-resource-fence-position/v1` is embedded in a
signed `projection.receipted` event. Its exact fields are resource, holder,
epoch and source evidence hash. The holder must equal the event's exact local
origin embodiment; arbitrary maps and another embodiment's fence are not
accepted. The event records what evidence justified a historical effect; it
does not assert that the fence remains current forever.

## Effect receipts and reconciliation

`dm.cluster-effect-receipt/v1` is a content-bound adapter result. It binds an
effect UUID, Matrix target and adoption decision UUIDs, adapter, preview and
intent hashes, actor and authority, optional exact fence position, timing,
result, and a bounded canonical observed postcondition. Postconditions reject
secret-bearing keys, private material, paths, sockets, URLs and endpoints.
`projection_receipt_payload` performs the exact lossless conversion of the
fields admitted by a signed Matrix `projection.receipted` event; Cluster cannot
append or sign that event.

`reconcile_effect_receipt` is pure and performs no effect. It hashes the exact
current intent bytes, requires current verification of the recorded fence when
one exists, and compares canonical observed postcondition bytes. Its result is
closed and intentionally three-valued:

- `verified`: intent, current fence and postcondition all match;
- `effect-truth-discrepancy`: an observed fact contradicts the receipt, such as
  a changed intent, stale generation, different holder or changed
  postcondition; or
- `effect-truth-unverifiable`: current truth cannot be established, such as a
  verifier outage, missing fence observation or unavailable postcondition.

Only `verified` may serve a cached success. The caller decides whether a
discrepancy or unavailable observation permits a fresh convergent execution.
DM-037 deliberately does not classify operations as convergent, authorize an
effect, expose execution through CLI/MCP, or implement DM-030 policy.

Unfenced receipts remain valid only for adapters that declare no exclusive
resource. Supplying fence evidence to reconcile such a receipt is a
discrepancy. Different resource references are independent; a newer epoch or
holder for the same resource invalidates replay of the older effect.

## Implemented daimon-cluster adaptation

The downstream implementation landed through `nicoechaniz/daimon-cluster#48`
and PR #49 at `676495e852e6772a60de8221271ee9fc976f77ce`. It pins the exact
merged Matrix package and:

1. host one owner-only Matrix state root/process per registry-bound embodiment;
2. inject side-effect-free exact body snapshots;
3. produce fence evidence only from Cluster's verified registry, current
   incarnation, signer and high-water state;
4. implement the injected verifier with current signature, expiry, holder and
   monotonic-epoch checks—never `FakeSigner`, reachability or cached response
   alone;
5. retain evidence addressed by `verification_ref` for effect reconciliation;
6. call reconciliation before any idempotent success replay and preserve
   discrepancy versus unavailable audit reasons;
7. quiesce Matrix around portable snapshots and exclude host-local sockets and
   locks; and
8. retire executable duplicate `weave/` code only after installed-runtime
   parity evidence.

The completed Cluster #48 adapter does not by itself claim hardened
inter-process fence CAS,
production supervision, real Incus relocation, a generic projection executor
or live Tribe transport. Those remain separate follow-ups and must stay visible
as unsupported rather than being inferred from this adapter boundary.

## DM-031 follow-up boundary

DM-031 consumes this contract through optional `load_runtime` injection points:
`curator_fence_verifier` and `curator_effect_observer`. Queue-item coordination
needs neither. Resource-fenced completion fails closed until a host supplies
both exact adapters; the standalone daemon command does not synthesize them
from presence, bundle fields or environment variables.

The existing Cluster #48 five-method capability and Matrix pin remain valid for
its implemented host lifecycle scope. A later Cluster adaptation must bump to
the exact reviewed DM-031 artifact before enabling curator projection effects,
wire the current registry/fence verifier and effect observer without exposing
private endpoints or credentials, and run Matrix's cached-RPC contradiction
test through the real process boundary. Until then, `resource-fence` curator
execution is unsupported rather than silently downgraded to queue-item CAS.

## Verification and rollback

Executable evidence is in `tests/test_dm037_cluster_effects.py`; public cases
and invariants are frozen in
`conformance/fixtures/dm037-cluster-effect-truth.json` and
`docs/verification/dm037-invariants.json`. Tests cover exact schema/runtime
parity, content mutation, wrong identity/resource/holder, expiry, high-water
rejection, verifier outage, intent and postcondition contradiction, independent
resources, stale same-resource epochs, disclosure rejection, and conversion to
a real signed Matrix event.

Before a consumer exists, rollback may remove the unused V1 contracts. After a
receipt exists, preserve every canonical Matrix event and Cluster evidence,
disable the adapter, and introduce a forward version. Never rewrite receipts,
lower a fence high-water, infer being identity from Cluster state, or move
private Matrix custody into Cluster.
