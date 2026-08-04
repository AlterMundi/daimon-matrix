# Package scaffold and reproducible builds

DM-020 introduced an intentionally behavior-free package scaffold. DM-021 and
DM-022 add identity/custody and the independent Weave ledger while preserving
the same closed reproducible artifact boundary. The package still contains no
daemon, RPC, CLI/MCP, remote transport, adapter, deployment, provider, or live
state.

## Supported interpreter baseline

The package requires Python 3.11 or newer. Public CI directly exercises Python
3.11, 3.12, 3.13, and 3.14. A newer interpreter is not claimed tested until it
is added to that matrix; the pure-Python metadata deliberately has no upper
bound that would force an otherwise unnecessary protocol migration.

## Build

Install development inputs, then run the verifier:

```bash
python -m pip install -r requirements-dev.txt -r requirements-vectors.txt
python tools/reproducible_build.py --output dist
```

The verifier creates two distinct clean source roots. Each invokes the PEP 517
frontend, which creates its own isolated build environment using the exactly
pinned Hatchling backend. Both builds use:

- `SOURCE_DATE_EPOCH=946684800` (`2000-01-01T00:00:00Z`), safely after the ZIP
  timestamp floor;
- `PYTHONHASHSEED=0`, `TZ=UTC`, and a stable UTF-8 locale; and
- the explicit sdist and wheel file selections in `pyproject.toml`.

It requires byte-identical sdists and wheels, compares SHA-256 digests, and
runs `tools/check_distribution.py` over each result. The sdist is a source
input, not a directly installed runtime artifact; the wheel is the externally
observable install path.

## Artifact boundary

The sdist may contain only its single normalized root plus `.gitignore`,
`LICENSE`, `PKG-INFO`, `README.md`, `pyproject.toml`, the public canonical,
identity, keystore, Weave, and ledger modules, `__init__.py`, and `py.typed`.
The wheel may contain only those package modules, the typing marker, MIT
license, and required `.dist-info` metadata/record files.

The checker rejects absolute/traversing paths, links and special archive
members, generated `egg-info`, bytecode/caches, SQLite or WAL state, private
keys, credentials, messages, experimental modules, and every unexpected file.
It independently verifies wheel `RECORD` hashes/sizes, metadata name/version,
Python requirement, the exact `cryptography` runtime dependency, pure-Python
tag, source-byte identity, and fixed timestamps.

## Installed smoke test

Install only the built wheel into an empty environment:

```bash
python -m venv /tmp/daimon-matrix-wheel-smoke
/tmp/daimon-matrix-wheel-smoke/bin/python -m pip install --no-deps \
  dist/daimon_matrix-0.0.0-py3-none-any.whl
/tmp/daimon-matrix-wheel-smoke/bin/python -c \
  'import daimon_matrix; assert daimon_matrix.__version__ == "0.0.0"'
```

Use a fresh disposable path rather than an existing operator environment. No
artifact from DM-020 is published, deployed, or given a credential.

## Security and rollback

Run `python tools/scan_secrets.py . dist` before accepting artifacts. A failed
or non-reproducible build is never published. Rollback is a source revert and
removal of local generated artifacts; this scaffold has no identity, canonical
state, migration, network, or deployment effect.
