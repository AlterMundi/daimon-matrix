# DM-021 identity V1 vectors

These are deterministic, synthetic public artifacts. They contain no private
seed, password, production identifier, or live CompAII ceremony material.

`valid/` contains one artifact for every V1 kind. `support/` contains the two
control branches required to verify fork recovery. `negative/` removes one
required authorization or possession role from an otherwise byte-valid
artifact. `index.json` is the closed inventory and binds the published Weave
manifest/head used by the history-binding vector.

Regenerate with:

```bash
PYTHONPATH=src python tools/generate_dm021_vectors.py
```

`tests/test_dm021_vectors.py` requires byte-identical regeneration, validates
every artifact against the public schema, verifies all positive signatures,
and proves every negative fixture fails its runtime verifier.
