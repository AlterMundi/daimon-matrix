# daimon-matrix

`daimon-matrix` implements persistent beings that may have zero, one or many
simultaneously active embodiments.

The situated scopes are:

- `/me`: this embodiment, here and now;
- `/we`: embodiments of the same being;
- `/tribe`: principals joined through signed relationship and grant history;
- `/species` and `/source`: capability lineage and attributed ancestry.

Plurality is normal. A global admission mechanism prevents reuse of one
embodiment credential in two bodies; it must not collapse every embodiment of
the being into a singleton.

## Release-candidate status

The integrated V0 Matrix baseline is merged at commit
`75b34804f8d013d348129946c0cd541a4448e71d`, tree
`38f3edb002ac52aac2d51fbf533cb58c38b813c5`. The package is being qualified as
`0.1.0rc1`. The conformance registry contains 102 closed scenarios and public
CI covers Python 3.11 through 3.14.

This status does not claim that any host, service or production deployment is
currently running. Historical operational reports document bounded past
experiments only. Start with [RESUME.md](RESUME.md) and
[CURRENT-STATE.md](CURRENT-STATE.md) for the authoritative checkpoint.

## Component boundary

`daimon-matrix` owns being-root continuity, canonical signed state, scopes,
relationships and grants, memory policy, synchronization, and communication
semantics. `daimon-cluster` owns body/incarnation lifecycle, storage and
resource-scoped admission/fencing. Neither side may infer the other's
authority.

Tribe Bridge remains transitional. Its transport acknowledgement cannot
replace authenticated Matrix intake or a signed semantic receipt. No legacy
dual-write is part of the release-candidate design, and retirement remains an
explicit human gate. See [TRIBE-MIGRATION.md](TRIBE-MIGRATION.md).

This project is unrelated to the external Matrix.org protocol.

## Runtime and evidence

The typed Python package includes threshold-separated identity/recovery
ceremonies, plural embodiment and incarnation authorization, encrypted
custody, append-only ledgers, replay-safe sync, deterministic projections, an
authenticated owner-local daemon, CLI/MCP clients, relationships and grants,
recipient-encrypted communication, source/publication contracts, and isolated
acceptance journeys.

Synthetic fixtures are deliberately named as synthetic. They provide
repeatable software evidence, not claims of physical custody, global host
fencing, participant consent or live deployment.

## Development

Install pinned development dependencies and run the standard gates:

```bash
python -m pip install -r requirements-dev.txt -r requirements-vectors.txt
python -m pytest -q
python -m ruff check src tools tests
MYPYPATH=src python -m mypy src
python tools/reproducible_build.py --output dist
```

The reproducible build and clean-wheel workflow are documented in
[docs/packaging.md](docs/packaging.md). Delivery order is in
[PLAN.md](PLAN.md) and [ROADMAP.md](ROADMAP.md).

Official repository: `AlterMundi/daimon-matrix`. License: MIT.
