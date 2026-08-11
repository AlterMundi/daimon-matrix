# DM-074 plus DM-083/DM-036 integration receipt

Date: 2026-08-11. Integration candidate only; not deployed, claimed for merge,
or independently reviewed.

## Exact boundary

- Qualified merge: `d0d8fde6419dfed56a26e2585bf7a6064820fdd7`.
- DM-083 plus DM-036 candidate: `ba1a52df22d74abb70922fbeacec46ef5ea38ee4`.
- DM-074 candidate: `e0b06b9a9385fb231515841d644e8782d130c1f4`.
- DM-036 collective-memory contract:
  `3e3b39416917f8e3c2bc5ca69362b20296205938`.
- Hermes Memory Kit contract:
  `f10fd5c3089c0962920314c97e14bc024feffa7a`.
- Conformance registry: 101 required scenarios, canonical digest
  `12f01cb1704e9943b7f2069ba41fa3f7f9b153c8cf5a22f506e404ac918b963f`.

Git merged the two candidate heads without a content conflict. The integration
adds explicit Ruff, strict-mypy and deterministic-generator CI lanes for the
DM-074 profile generator and conformance corpus. It retains all DM-083 and
DM-036 runtime, authority, source, relationship, packaging and remote-dogfood
contracts. No service, host state, corpus, route or runtime installation was
changed.

## Finding repaired in the owning branch

The new DM-074 files had not been included in the static workflow lane. The
first explicit strict-mypy run found that both intentional fixture imports
needed a typed dynamic-import exemption. The repair was committed inside the
live DM-074 claim as `e0b06b9a9385fb231515841d644e8782d130c1f4` and pushed to
its existing review PR. Ruff, strict mypy, generator drift and all ten focused
DM-074 tests then passed. This integration branch carries the additional CI
lane, but does not alter or bypass the issue claim.

## Clean combined gate

```text
workflow-equivalent static gate: 18 commands passed
DM-074 focused conformance: 10 passed
complete combined Matrix suite: 576 passed, 19 skipped
DM-036/041/042/061/070/074/081/082 generators: byte-exact
compileall and git diff --check: clean
reproducible wheel: 18f6524733da7a1592f0e8a762c520ddaaee0117f571ec1af71081ede89c8e32
reproducible sdist: 58654f643fdbac1ec74d3d0c16a2bbcfb981d4eaa848c4730c62ec0f9f862111
repository and artifact secret scans: clean
installed conformance twice: release_ready=true and byte-identical
conformance transcript: 1e4db1a2609ea995f5512ab14f2206ee9ab56b835e984f909c6652d752b16e81
conformance report file: f9bb7382d98ea9a32e3fc2ab9580ef7aad1d983beda27a6374eff352ccdc8182
```

The wheel and sdist are byte-identical to the qualified DM-083/DM-036
candidate, proving the DM-074 merge changes only public harness profiles,
documentation, provenance, schemas, test fixtures and their verification
surface. The installed conformance report is nevertheless bound to the exact
combined commit above rather than inferred from the earlier candidate.

## Remaining gate

Keep this as an integration-only branch. The existing DM-074, DM-083 and
DM-036 PRs retain their separate issue/claim/review boundaries. Independent
review and their dependency order must decide the eventual merges; this
receipt proves technical convergence but grants no review, release,
deployment, consent or publication authority.
