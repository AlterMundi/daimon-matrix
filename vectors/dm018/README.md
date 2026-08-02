# DM-018 adapter conformance vectors

`index.json` is the normative inventory. This corpus is deliberately separate
from DM-011's byte-identical generated `vectors/v0` tree. Every referenced record first passes
the closed Draft 2020-12 schema in
`schemas/adapters/v0/contracts.schema.json`; checks named in the index then
apply the cross-record monotonicity, continuity, or dual-gate rule.

Positive records are minimal structural examples, not trusted production
evidence. Placeholder digests and signatures exercise wire shape only. An
implementation must additionally retrieve referenced bytes, recompute hashes,
validate their DM-010–DM-017 contracts, and verify real signatures.

Run from the repository root:

```sh
python -m unittest tests.test_dm018_contracts -v
```
