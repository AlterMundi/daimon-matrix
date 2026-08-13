# DM-036 plus DM-083 integration receipt

Date: 2026-08-11. Candidate only; not deployed or independently reviewed.

## Exact boundary

- Qualified semantic merge: `56f79a1a9128284ef53c4289343162ba84020ad7`.
- DM-083 base: `e45ff577e0594065eb26440caa80cf5377eadb86`.
- DM-036 source branch: `2b8e956f95074c60c537148c10b5bd9533cee509`.
- Collective-memory contract: `3e3b39416917f8e3c2bc5ca69362b20296205938`.
- Hermes Memory Kit contract: `f10fd5c3089c0962920314c97e14bc024feffa7a`.
- Conformance registry: 101 required scenarios, canonical digest
  `12f01cb1704e9943b7f2069ba41fa3f7f9b153c8cf5a22f506e404ac918b963f`.

The merge retains the DM-083 authority epochs, source ancestry, relationships,
Hermes packaging and two-host dogfood contracts. It adds distinct inbound and
outbound collective-memory adapters, separate journals and credentials,
quarantine-only import, exact consent plus independent review for publication,
monotonic successors and tombstones, and crash recovery around both Matrix and
external effects. Upstream provenance was advanced from the historical DM-036
pin to the hardened public contract above. No upstream database, live corpus,
Matrix runtime or service configuration was changed.

## Clean automated gate

All checks used fresh Python 3.13 environments and the exact contract pins.

```text
DM-036 contract, crash and real-I/O gate: 23 passed
complete Matrix suite: 566 passed, 19 skipped
workflow-equivalent ruff and mypy gates: clean
all checked generators and compileall: clean
reproducible wheel: 18f6524733da7a1592f0e8a762c520ddaaee0117f571ec1af71081ede89c8e32
reproducible sdist: 58654f643fdbac1ec74d3d0c16a2bbcfb981d4eaa848c4730c62ec0f9f862111
distribution allowlist and secret scans: clean
installed DM-026 conformance, two byte-identical runs: release_ready=true
conformance transcript: 1e4db1a2609ea995f5512ab14f2206ee9ab56b835e984f909c6652d752b16e81
conformance report file: cc95be312cd8617fcba98e060c18d9fcc95b72274adf5d3c0aee2da236f53b75
```

The real-I/O scenario exports a synthetic attributed generation, lands it in
Matrix quarantine, publishes separately reviewed derived bytes, verifies FTS
and Atlas projections, then applies a reviewed tombstone. It also checks both
SQLite databases for integrity and proves unrelated corpus content remains
byte-exact. Fault scenarios cover preparation, ledger, external-effect and
acceptance boundaries, response loss, replay, pagination, offline catch-up,
forks, symlinks, drift, expired or revoked consent and self-review.

## Remote scratch confirmation

The exact candidate and collective-memory commits were cloned into one unique
temporary root on the authorized `daimonmatrix` host. Vector regeneration and
all 23 DM-036 tests passed there under Python 3.13.5. The bounded cleanup trap
removed the complete scratch root. `clusterd` remained active and
`daimon-matrixd` remained inactive before and after; no `/opt` release or live
state was replaced.

## Remaining gate

Publish this stacked candidate for CI and independent review. Do not deploy or
merge it merely from this receipt. A real publication still requires current
source intent, explicit subject consent and an independent human review over
the exact final bytes; this synthetic receipt supplies none of those
authorities.
