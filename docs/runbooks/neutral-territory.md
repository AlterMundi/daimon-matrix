# Runbook: harness-neutral territory (`~/.agents/`)

Status: implemented for CompAII on Legion (2026-09-27). Renderer:
`daimon_matrix.neutral_binding` (`dm.neutral-binding/v1`). Tracker:
AlterMundi/daimon-matrix#161.

The neutral territory is host-common ground owned by no harness. It exists so
one being can be embodied in several harnesses on the same host (and several
beings can share a host) without any harness owning the others' memory or
skills, and so the whole arrangement is re-executable on any host by any
human+daimon pair.

## Invariant layout

```text
<home>/.agents/
  skills/                        shared skill surface (single source of truth)
  memory/<being>/agent-memory/   being-level memory pool (hmk library)
```

- Memory is pooled at being level. Per-embodiment authorship is not an hmk
  concept: it comes from the signed event origin and the Matrix projection
  `source_instance` (`matrix:embodiment:<uuid>`, see `docs/dm034-memory-projection.md`).
- Skills on the neutral surface are harness-neutral content. Harness
  integration mechanisms stay harness-local and are preserved as explicit
  differences (comparison data, not defects): Hermes may auto-prefetch memory
  via the `hmk-memory` plugin; other harnesses are human-request-only and must
  not auto-load memory or poll inboxes (autonomy gate #148).
- Per-body runtime bindings (e.g. `daimon-chat` `connection.json`) are NOT
  neutral content. They live in each body's state
  (`~/.local/state/daimon-matrix/<body>/agent-attachment/`) and are emitted by
  the body renderers (DM-040/DM-041), never placed on the shared surface.

## Render the binding

Write a plan JSON (closed field set; everything else is derived):

```json
{
  "schema": "dm.neutral-binding/v1",
  "being_name": "compaii",
  "host_word": "legion",
  "home": "/home/nicolas",
  "platform": "linux-systemd",
  "harnesses": ["hermes", "codex"],
  "env_file": "/home/nicolas/.hermes/.env",
  "wrapper_path": "/home/nicolas/.local/bin/hmk",
  "service_unit": "hermes-gateway.service"
}
```

`platform` is `linux-systemd` (adds the required `service_unit` field),
`macos-launchagent`, or `env-file` (fallback: the env file is the mechanism).
`env_file` and `wrapper_path` must be absolute paths under `home`.

```bash
PYTHONPATH=src python -m daimon_matrix.neutral_binding \
  --plan binding-plan.json --out /tmp/neutral-binding
```

Outputs (owner-only 0600): `env_fragment.env`, `service_env.txt`,
`hermes_skills_fragment.yaml` (only when `hermes` is bound),
`surface_check.py`, `binding-manifest.json` (content-addressed: sha256 of
every artifact plus every derived path). stdout prints the manifest digest;
record it in the issue/deployment notes.

## Apply (Linux + Hermes + Codex)

1. Create the territory: `mkdir -p <home>/.agents/skills
   <home>/.agents/memory/<being>/agent-memory`.
2. Memory base: for a NEW being, run `hmk memoryctl.py init` against the
   neutral base (via the wrapper env below). To MIGRATE an existing Hermes
   base, follow "Migration" underneath.
3. Env: install `env_fragment.env` lines into `env_file` (replace any previous
   `HMK_AGENT_MEMORY_BASE` / `HERMES_AGENT_MEMORY_BASE` lines). Hermes loads
   this file at gateway start (`hermes_cli.env_loader`, override=True) and the
   `hmk` wrapper loads it per invocation, so one flip covers both harnesses.
4. Service env: on `linux-systemd`, also install `service_env.txt` as
   `~/.config/systemd/user/<service_unit>.d/neutral-binding.conf` and
   `systemctl --user daemon-reload` (belt-and-braces: the env file already
   covers the gateway; the drop-in covers units that do not read it).
   On macOS, merge the `EnvironmentVariables` dict into the LaunchAgent plist.
5. Hermes skills root: merge `hermes_skills_fragment.yaml` into
   `<home>/.hermes/config.yaml` under `skills.external_dirs` (upstream
   mechanism; local skills win name collisions, so do not keep a stale local
   copy of a promoted skill). Restart the gateway.
6. Codex skills root: native — Codex scans `<home>/.agents/skills`. For
   selected packages with auxiliary skill documents, prepare the discovery
   controls described below.
7. Run `python3 surface_check.py`; it must print `surface-check: ok`.

## Migration of an existing memory base

Only with the human owner present or explicitly authorized.

1. Stop the harness service (`systemctl --user stop <service_unit>`).
2. Verify + record: `sqlite3 "file:<src>/library.db?mode=ro" "PRAGMA
   integrity_check;"` (and `sessions.db`), plus per-table row counts.
3. `rsync -a <src>/ <dst>/` — WAL/SHM included; with the service stopped the
   copy is consistent.
4. Re-verify integrity and row counts on `<dst>`; they must match exactly.
5. Flip the env (step 3 above), restart the service, confirm `active` and no
   new errors in the journal.
6. Functionally verify: `hmk memoryctl.py stats` and a `hybrid-pack` query
   resolve `<dst>/library.db`; a test write lands in `<dst>` and NOT in
   `<src>`; delete the test entry afterwards.
7. Keep `<src>` untouched as rollback until the full verification passes;
   only then remove it, and say so in the tracker.

Rollback: restore the previous env lines (keep a backup of the env file
before flipping; it may contain secrets — backup stays local, 0600, never in
git), restart the service.

## Skill lifecycle on the neutral surface

- Default: harness-local skills stay where they are. No mass migration.
  Promotion candidates are classified jointly by the human and the daimon;
  the decision is recorded when a skill actually moves.
- Creating a skill: evaluate whether it is harness-neutral and worth
  promoting; harness-specific skills stay in that harness.
- Updating a neutral skill: preserve neutrality (label harness-specific
  sections, never delete the difference), then run `surface_check.py` (and
  the repo test suite when the skill ships with repo tooling) so other
  embodiments do not break.
- Promoting = move (single source of truth), not copy; remove the local
  original so the collision rule cannot shadow the promoted version.
- Never promote deprecated tooling (e.g. Tribe Bridge skills) or per-body
  bindings/credentials; the surface check fails on malformed frontmatter and
  the manifest pins what was rendered.

## Harness extension contract

A new harness joins the territory by supplying four things; the surface
itself never changes per harness:

1. a skills-root mechanism (Hermes: `skills.external_dirs`; Codex: native
   `~/.agents/skills`; others: their equivalent scan root);
2. a memory-base env mechanism (any way to publish
   `HMK_AGENT_MEMORY_BASE` to the harness process);
3. an identity declaration (its AGENTS.md/SOUL equivalent naming
   `<being>.<harness>@<host>`);
4. a rendered owner-local client / MCP surface from its body adapter.

Harness adoption evidence states are governed by DM-074
(`docs/harness-adoption-v0.md`): a new harness enters as
`documented-candidate` and earns its own evidence; nothing is inherited.
Claude Code, goose, Open Code, Pi etc. are future DM-04x adapters over this
same contract.

## Legion execution record (2026-09-27)

- Migrated `~/.hermes/agent-memory` → `~/.agents/memory/compaii/agent-memory`
  (89 MB; integrity ok both ends; row counts identical; env flipped at
  `.env` lines 413/417; gateway restarted clean).
- No systemd drop-in was needed: `env_loader` + wrapper cover gateway and CLI
  (kept as documented mechanism, not required on this host).
- Skills moved: `mariano-memory-kit` (+`librarian`),
  `daimon-matrix-contributions`; created `collective-memory-access`;
  `daimon-chat` neutralized (instructions single-source, per-body binding
  documented and left to the renderers). Legacy `tribe-*` skills intentionally
  NOT promoted (deprecated system). Hermes sees 16 neutral skills via
  `external_dirs`.
- Owner-local client retired as a hand-rolled script: the body venv now runs
  the pinned wheel built from the exact head (editable install removed;
  `daimon_matrix` resolves to site-packages), and the client is the rendered
  `dm.owner-client/v1` artifact — byte-identical to the retired script —
  installed at
  `~/.local/state/daimon-matrix/compaii-codex-legion/owner-client/`
  (0700, plan beside it, digest pinned in the binding manifest). After the
  PR merges, re-pin the body venv to the merged commit.
- Evidence: issue #161 comments; local pre/post row counts and env backup in
  `/tmp/nt-evidence/` on Legion.


## Selected skill packages and native discovery

The installed wheel ships `neutral_skill_assets/daimon-chat/`. Render with
`--chat-skill` to emit an installable neutral package at
`<out>/skills/daimon-chat/`; copy that directory to
`<home>/.agents/skills/daimon-chat` only during an approved adoption.
It contains one shared body and interface/policy-only `agents/openai.yaml` and
`agents/hermes.yaml` adapters. Both declare `allow_implicit_invocation: false`.
A harness must support the adapter policy to enforce it natively; Hermes's
existing tool/request gate remains the operational boundary when it does not
consume that file. Installing a package creates no hooks, timers or listeners.
No ECC source is vendored. Resolve each body's existing rendered connection
outside the package; never copy `connection.json`, credentials or custody with it.

Codex recursively discovers auxiliary `SKILL.md` documents that Hermes excludes
from discovery beneath a package's support directories. Preserve their bytes,
but prepare a closed owner-selected discovery plan to disable those auxiliary
paths in Codex. For example:

```json
{
  "schema": "dm.skill-discovery/v1",
  "packages": [
    {
      "path": "mariano-memory-kit",
      "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "auxiliary_skills": ["references/example/SKILL.md", "librarian/SKILL.md"]
    },
    {
      "path": "mariano-memory-kit/librarian",
      "sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "auxiliary_skills": []
    }
  ]
}
```

Paths are package locators under the derived neutral root, never identity.
Replace example digests with the exact captured package-manifest digests and
retain that source inventory as evidence. The renderer binds this declaration,
but does not inspect source bytes or certify provenance, fitness or adoption.
The owner selects packages and classifies auxiliary documents from an inventory;
rendering does not authorize mass promotion or query any runtime.

Render with `python -m daimon_matrix.neutral_binding --plan binding.json
--skill-plan selected-skills.json --out prepared-binding`. This additionally emits
`codex_skills_fragment.toml`, with sorted unique exact-path `skills.config` entries,
and records the normalized package declaration and fragment digest in the binding
manifest. A declared nested package root remains enabled even if its parent lists
that document as auxiliary. With no skill plan, existing binding bytes stay the
same. This is a discovery policy, not permission to invoke tools or load memory.

Pass `--codex-config <prepared-rendered-baseline.toml>` with `--skill-plan` to
emit the final `codex_config.toml`. The renderer preserves the baseline bytes,
refuses an existing `skills.config` policy rather than overriding it, and binds
both the baseline digest and composed output to the manifest. Neither input nor
active profile is changed. Check the prepared final config with the pinned native
strict-config loader before approval. Reconcile a conflicting baseline explicitly;
do not repeatedly append fragments to a live file. Verify the enabled roots
against the declared inventory using `skills/list`; auxiliary parser diagnostics
must be distinguished from missing enabled roots. Record the exact final config,
package inventories and rollback in the deployment packet. Native discovery alone
does not prove body admission, invocation fitness or operational adoption.
