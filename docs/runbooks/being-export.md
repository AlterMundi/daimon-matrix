# Export an established being from Hermes or Codex

Use `tools/export_being.py` on the source machine. It is a standalone Python
3.11+ standard-library tool: no Matrix enrollment, account login, model call,
background service or installed Python package is needed. It preserves the
being's original contextual material in one private `.tgz` or `.zip`, verifies
it, and can restore it to a fresh staging directory.

The aim is useful continuity: identity, remembered experience, learned skills,
working tools, configuration and relational/project context. Preserve originals
completely within the selected sources. Adopt behavior that actually helps the
receiving being work, remember and relate to its human. Source-machine operating
rules and project-specific contribution procedures do not automatically become
global receiving instructions. An archive records provenance; it does not grant
authority or require a new ceremony.

Relational continuity includes the being's tribe, humans and other daimons met
through its life: shared experiences, commitments, agreements and the context
that lets a future body recognize and continue those relationships. Preserve
that history in its original memory/context sources, with provenance and scope.
Do not reduce it to the primary human pairing. Matrix references and historical
relationship records remain attributable records; this archive does not issue
credentials or create relationships it has not observed.

## First use: Oliva and Eko

Agree a brief pause of source writers with the human. Stop or pause the actual
memory/harness writers without losing their active work. The command does not
stop someone else's services or pretend to prove that they stopped. Its flag
records the operator's declaration of a common snapshot cutoff.

For Oliva, whose source is Hermes:

```bash
python3 tools/export_being.py export --being Oliva --harness hermes \
  --writers-stopped --output Oliva.tgz
```

For Eko, already using Codex with Hermes components and HMK:

```bash
python3 tools/export_being.py export --being Eko --harness mixed \
  --writers-stopped --output Eko.tgz
```

These inspect the selected owner's `.hermes` and/or `.codex` directories, plus
shared `.agents/skills` when present. Familiar relocated `agent-memory`/`skills`
roots referenced by direct harness symlinks are preserved as separate roots.
Other symlinks are reported, not followed into unrelated history.

The source agent discovers other actual roots and adds them to that command,
for example `--memory-root /owner/being-memory`, `--context-root /owner/wiki`,
`--skills-root /owner/private-skills`, `--sessions-root /owner/selected-history`
or `--project-root /owner/selected-project`. Flags can repeat. Never select the
whole computer, another being's pool or all projects without the human's scope.
If Eko has multiple owned HMK stores, supply each separately; no database overlay
or silent deduplication occurs. Different profile homes can be selected through
the discovery mode below. A missing `.hermes` in a mixed setup is an actual
selection error; choose Codex plus the specific remaining Hermes components
rather than fabricating an installation.

The command prints only counts, archive size and SHA-256. Keep that checksum
for the receiving verification. Keep the archive private; its source mapping,
memory, sessions and projects can contain personal information. Restart the
paused source writers after the agreed baseline export, or keep them paused
for an explicitly agreed final cutover. Record that decision in the handoff.

## Optional discovery and baseline comparison

For an unusual installation, the agent can first produce a private inventory:

```bash
python3 tools/export_being.py discover --being Eko \
  --codex-root /owner/current-codex --hermes-root /owner/old-hermes \
  --memory-root /owner/eko-memory --output Eko-plan.json
```

The plan inventories every regular file and omission in the selected roots.
Unknown extensions and older memory/backups are preserved, rather than filtered
into a recent summary or a small filename allowlist. The agent checks its
coverage against the actual installation and adds missing authorized roots.
Record available source versions, external references and active-work notes.
The human decides ownership, transfer scope and cutover; the agent handles paths
and inventories. The human need not fill in a technical reconstruction form.

Each source may have an optional `baseline` directory and exact `version` in
the private plan. The exporter compares against that supplied baseline and
records `added`, `modified`, `unchanged` and files absent from the source, along
with SHA-256 references. Without a supplied baseline it records `unknown`.
It never guesses a harness default from the current installation. Original
selected files remain in the archive even when they match the baseline, so a
future receiving adapter can reconstruct them without a disappearing download.
SQLite contextual deltas remain `unknown`: a matching physical main file can
have different memories in its WAL. Physical file hashes/comparison and the
verified full snapshot remain separately available; there is no false claim of
unchanged memory. Unknown SQLite extensions can prevent integrity/count checks;
the export then fails without dropping or changing source data. Validate those
databases with their supported source runtime before attempting migration.
Regenerate the plan after pausing writers, retain the selected baseline/version
information, then export:

```bash
python3 tools/export_being.py export --plan Eko-plan.json \
  --writers-stopped --output Eko.tgz
```

## Verify and stage on the receiving host

```bash
python3 tools/export_being.py verify --archive Eko.tgz --sha256 ARCHIVE_SHA256
python3 tools/export_being.py unpack --archive Eko.tgz --sha256 ARCHIVE_SHA256 \
  --destination Eko-received
```

Verification checks version, exact archive membership, paths, sizes and file
hashes. Extraction additionally checks SQLite integrity, foreign keys, schema
and table counts. It refuses an existing destination, traversal, links,
duplicates and unlisted payloads. Files remain private and inactive. No source
instructions, hooks, skills, project code or account settings are executed or
installed by extraction.

The versioned `dm.being-context-archive/v1` manifest records each source's origin,
kind, source version, reconstruction mapping, omissions, baseline comparison,
individual file hashes and SQLite evidence. Payloads live under separate
`payload/<source-id>/` directories. The archive keeps native sessions and project
files with their origin, ready for future receiving adapters. Preserving a
Hermes transcript does not yet make it natively resumable in Codex.

## Current coverage and concrete limits

| Surface | Current tool behavior | Remaining adaptation |
| --- | --- | --- |
| Identity and instructions | Preserve selected original files and history | Receiving identity reconciliation and instruction precedence |
| HMK and other SQLite | Snapshot every detected SQLite DB; preserve other selected files and backups | Supported schema upgrades and target retrieval validation |
| Skills, scripts and plugins | Preserve selected packages, local variants and history | Select compatible useful behavior; resolve dependencies and harness hooks |
| Configuration | Preserve selected nonsecret files | Rebind paths/accounts and review embedded credentials |
| Sessions | Preserve selected raw native files | Cross-harness conversion, indexing and native resume |
| Projects | Preserve selected worktree/context files | Git history import and complete project reconstruction |

Known credential/custody files and rebuildable dependencies are recorded as
omissions. Git internals are explicitly deferred to a future Git-history adapter.
SQLite WAL/SHM files are replaced by coherent backup-API snapshots of the main
database, with the omission recorded. `.env`/`.envrc` files additionally produce
an inactive `.nonsecret` copy retaining simple scalar settings such as
`HERMES_TUI=1`. Automatic separation supports `KEY=value`, optional `export`,
blank lines and comments; complex shell syntax requires a separate source-agent
adaptation. It is never guessed or executed.
Credential variable names remain visible for fresh private configuration; their
values are removed. The original stays unchanged. No environment expression is
evaluated. Detected remaining embedded credentials stop the export,
as do multiline, array or executable environment expressions.
preserving the unchanged source. Known-pattern scanning cannot guarantee that
arbitrary binary/compressed historical material contains no secret.

Coverage is honestly limited to selected roots. Unresolved links, external
references, missing baseline versions and omitted historical data remain visible
work for the source agent; successful archive verification alone does not prove
that every source of the being's identity has been discovered.

The next receiving adapter must retain this complete original archive, restore
the being's own memory, render actual receiving instructions and working skills,
test familiar retrieval and work tasks, and explain remaining losses. It must
never replace historical context with a summary, pool other beings' memory, or
claim imported native transcripts as new signed Matrix experiences.

Dedicated bot data remains necessary before new owner-facing embodiment
enrollment. Packaging, lineage review, enrollment, SSH/Telegram setup and real
receiving acceptance stay distinct observed steps. See the
[cohort procedure](hermes-to-codex-cohort.md) and implementation issue
[#260](https://github.com/AlterMundi/daimon-matrix/issues/260).
