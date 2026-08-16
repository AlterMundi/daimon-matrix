# Package scaffold and reproducible builds

The `0.1.0rc1` package contains the reviewed Matrix V0 runtime: identity and
recovery custody contracts, ledgers, daemon, authenticated clients, CLI/MCP,
native peer transport and isolated acceptance entry points. Public schemas,
vectors, templates, provenance and synthetic roots remain repository evidence
rather than wheel runtime state. The distribution contains no operator
credentials, private keys, writable databases, provider profile or live state.
Matrix.org is not a dependency.

The merged pre-version-bump tree and its old artifact hashes are classified in
[`verification/v0-rc-qualification.md`](verification/v0-rc-qualification.md).
Changing package metadata changes distribution bytes, so those hashes cannot
identify `0.1.0rc1`; fresh reproducible hashes are required before freeze.

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
identity, keystore, Weave, ledger, sync, projection, daemon, client, CLI, MCP,
Codex-body, Hermes-body, local-We, source, relationship, synthetic-source,
synthetic-relationship and conformance
modules, `__init__.py`, and `py.typed`.
The wheel may contain only those package modules, the typing marker, MIT
license, and required `.dist-info` metadata/record files.

The checker rejects absolute/traversing paths, links and special archive
members, generated `egg-info`, bytecode/caches, SQLite or WAL state, private
keys, credentials, messages, experimental modules, and every unexpected file.
It independently verifies wheel `RECORD` hashes/sizes, metadata name/version,
Python requirement, exact `cryptography==50.0.0`, `mcp==2.0.0` and
`wasmtime==45.0.0` runtime dependency metadata, pure-Python tag, source-byte
identity, and fixed timestamps.

## Installed smoke test

Install only the built wheel into an empty environment:

```bash
python -m venv /tmp/daimon-matrix-wheel-smoke
/tmp/daimon-matrix-wheel-smoke/bin/python -m pip install \
  cryptography==50.0.0 mcp==2.0.0 wasmtime==45.0.0
/tmp/daimon-matrix-wheel-smoke/bin/python -m pip install --no-deps \
  dist/daimon_matrix-0.1.0rc1-py3-none-any.whl
/tmp/daimon-matrix-wheel-smoke/bin/python -c \
  'import daimon_matrix; assert daimon_matrix.__version__ == "0.1.0rc1"'
/tmp/daimon-matrix-wheel-smoke/bin/daimon-conformance --help
/tmp/daimon-matrix-wheel-smoke/bin/daimon-hermes-body --help
/tmp/daimon-matrix-wheel-smoke/bin/daimon-synthetic-sources --help
/tmp/daimon-matrix-wheel-smoke/bin/daimon-synthetic-relationships --help
```

Use a fresh disposable path rather than an existing operator environment. No
artifact is published, deployed, or given a credential by this check.

## Security and rollback

Run `python tools/scan_secrets.py . dist` before accepting artifacts. A failed
or non-reproducible build is never published. Rollback is a source revert and
removal of local generated artifacts; the check has no identity, live-state,
network-carrier or deployment effect.
