# Owner memory sync delivery review (#162)

Implementation reviewed: `b2491b259bfe7f6617edc6f9965d5b609009ab63`, based on
`e360a5b6f6ea6fc181c4f7b809e209606b3c6842`.

Independent reviewer: `review_162_origin_projection` (analysis-only review).
Verdict: **APPROVE**. No blocking findings or required follow-up conditions.
This approves code delivery, not live adoption or operational acceptance.

## Scope and findings

The review covered the new owner CLI, all nine operator/package modules,
runtime-authority and destination binding, official writer lock, installed native
worker, private provenance, retained namespace recovery, runbook and packaging.
Earlier independent helper approvals were reused after normalized semantic port
comparison. Typing/formatting changes preserve those fixes; extracting the common
lock context extends source-ledger preservation to failure paths and to native
and namespace operations. Initial digest/signature guards remain intact.

The reviewer confirmed that unsigned pool lineage is descriptive provenance,
not signed Matrix authorship; assertion origin remains the signed namespace.
Native writes use the pinned API, with protected projection rows and receiver
history preserved. The installed worker uses isolated Python and a stripped
environment. Failure diagnostics are withheld from the operator result.

## Independent verification

- 28 owner operator and DM-034 regressions passed with sanitized pinned contracts.
- All nine new modules in wheel
  `9711131ad92469e7a9b604006a1c5acdb7336c4744215b90c740eb90c9dd7529`
  matched the reviewed source bytes.
- Synthetic installed native CLI preparation/application refused a held runtime
  lock before effects, recovered a real first native commit after injected worker
  response failure, and repeated the retained plan without duplication. Final
  state: two chapters, one link; source/runtime ledger and baseline preserved.
- Synthetic namespace CLI recovery rejected substituted plans, excessive packet
  size, wrong namespaces and stale checkpoints; reconstructed adapters recovered
  committed-response loss from the exact saved packet. Corrections kept assertion
  origin, retractions affected only their namespace, and unrelated native rows
  and other-origin heads remained unchanged.

The reviewer used synthetic data, did not reread the owner's actual private
receiver copies, and made no repository, live runtime, provider or custody changes.

## Owner qualification and limits

42 owner/projection/runtime regressions passed. The package/Hermes suite covered
39 tests with one optional native Hermes-source discovery skip; two stale frozen
inventory/entry-point assertions were corrected and their focused reruns passed.
All 86 source modules passed strict typing, lint and formatting. Explicit frozen
inventories and generated artifacts passed. Two builds were byte-identical;
sdist SHA256 is
`0169991f037bec8cb3d62107dc700583cd028e9fb46d1d2d3007a292528e32fb`.
Checkout and both distribution secret scans passed.

The official runtime lock excludes the Matrix owner, not all HMK consumers.
Exact rollout approval, all-writer cutoff, consistent backups, source intake,
consumer bindings and deployed validation remain required. Initial projection
digests do not grant arbitrary retry authority; namespace effects are individually
transactional. Private/synthetic proofs do not prove real cross-host adoption,
consumer recall, skills activation, Cluster/lifecycle or roadmap completion.
