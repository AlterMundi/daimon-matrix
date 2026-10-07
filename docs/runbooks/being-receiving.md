# Prepare a preserved being for ordinary Codex

This is the first reusable receiving step for #263, delivered by #269.
`tools/receive_being.py` uses the maintained archive verifier and existing Codex
identity installer. It preserves originals, prepares separate writable memory
copies and selected skills, and renders full receiving context. It does not
activate Codex, issue Matrix identity, import sessions, install dependencies or
call a memory provider. Real Oliva/Eko acceptance remains separate evidence.

Use the actual receiving user's ordinary environment. The source agent handles
archive member discovery and technical selection; the human chooses identity,
portable scope and account policy. Preserve the existing account, authentication,
native history and any signed being root. An export label is context, not Matrix
authority or a database ownership filter.

## Discover the preserved context

Use the verified checksum supplied with the private archive:

```bash
python3 tools/receive_being.py discover \
  --archive /owner/handoff/being.tgz --sha256 <verified-sha256> \
  --output /owner/handoff/receiving-selection.json
```

The private draft lists `SOUL.md` candidates, SQLite-backed `library.db` stores
and historical `SKILL.md` packages. A single SOUL becomes a candidate selection;
several SOULs require an explicit choice. Discovery never proves completeness,
compatibility, signed membership or consent. The source SOUL and all alternative
versions remain preserved regardless of the receiving choice.

An agent reconciles the draft with the actual archive and the pair's decisions:

```json
{
  "schema": "dm.being-receiving-selection/v1",
  "being_label": "Oliva",
  "memory_coverage": "complete-authorized",
  "soul": "payload/hermes-001/SOUL.md",
  "memory": [
    {
      "name": "live",
      "path": "payload/hermes-001/agent-memory",
      "database": "library.db"
    }
  ],
  "skills": [
    {
      "name": "listening",
      "path": "payload/hermes-001/skills/listening"
    }
  ]
}
```

Keep `owner-selected` when the authorized portable selection is partial, as Sai
currently chose for Eko's hosted continuity. `complete-authorized` is an owner
declaration, not a conclusion drawn from file or chapter counts. Preserve full
source stores and their origins independently of portable coverage. The draft's
optional `discovery` evidence may be retained; unknown top-level selection fields
are refused. Package names are local safe names, not new identity or species.

Memory selections copy the entire selected directory, including its auxiliary
files and provenance. Distinct stores stay separate. The selected database must
have verified SQLite evidence in the archive. There is no row filtering or
implicit pool merge. Ordinary Codex/session SQLite files are not automatically
treated as HMK. An agent can name another database explicitly when the actual
supported native HMK distribution uses it.

## Prepare originals, working copies and context

```bash
python3 tools/receive_being.py prepare \
  --archive /owner/handoff/being.tgz --sha256 <verified-sha256> \
  --selection /owner/handoff/receiving-selection.json \
  --output /owner/state/being-receiving \
  --hmk-python /owner/installed-hmk-venv/bin/python \
  --hmk-scripts /owner/installed-hmk/scripts \
  --receiving-soul /owner/selected/reconciled-SOUL.md \
  --foundation /owner/selected/FOUNDATION.md
```

The output must not exist. The two HMK arguments are optional together; they
select an already installed, owner-approved receiving interpreter/distribution.
The command does not download, execute or verify compatibility of that
distribution. Its credentials/provider configuration must be receiving-local.
Omitting them prepares the memory but reports the native binding as pending.
`--receiving-soul` selects a locally reconciled SOUL while retaining the original;
without it, the selected preserved SOUL is used byte-for-byte. Foundation is an
explicit choice, not inherited CompAII autobiography or private memory.

The private output contains:

- `source.archive` and `originals/`: checksum-verified original archive and its
  complete payload, source instructions, histories and provenance.
- `memory/<name>/`: separate writable copies with matching SQLite integrity,
  table/count evidence and initial content hashes.
- `skills/<name>/`: selected historical packages with their executable bits,
  preserved without execution, shared promotion or automatic global activation.
- `commands/hmk-<name>.py`: manual native wrappers when HMK was selected. They
  override database/base selection to the corresponding working copy, preserve
  literal arguments and refuse script-path traversal. They never source the
  exported dotenv or run during preparation.
- `context/`: full receiving SOUL, identity description, optional foundation,
  manual memory instructions and `AGENTS.preview.md`. The preview passes the
  existing installer's actual UTF-8/NUL/instruction-size rules; oversize context
  is refused rather than silently truncated.
- `continuity-index.json`: private file/source provenance and external references
  for retained history and projects. This index does not convert a Hermes
  transcript into a native Codex thread or import Git history.
- `preparation.json`: completion evidence and explicit remaining limitations.

Known credential files/patterns are refused before working context preparation.
Safe exporter-derived dotenv stays preserved evidence and is never installed as
active configuration. Pattern scanning cannot establish that opaque content is
credential-free; source review still applies.

If preparation fails, preserve its private partial output and original handoff
for diagnosis. There is no completion marker and no active harness change. A
rerun cannot overwrite it or later receiving work; correct the problem and
select a distinct new output. Do not delete source memory, custody or journals.

## Install and test the actual receiving interface

Use the existing [ordinary Codex identity installer](native-harness-onboarding.md)
with `context/IDENTITY.md`, `SOUL.md`, `MEMORY-ACCESS.md` and the selected foundation.
Inspect its prepared result, then apply under the existing adoption authorization
with the actual model/reasoning/policy and effective `--codex-home`/`CODEX_HOME`.
The receiver itself writes no active Codex settings. A conflicting global
`AGENTS.override.md` still needs the existing owner-selected resolution.

The context description explicitly marks signed enrollment as pending. If a
valid signed body already exists, select its current authenticated binding in
the owner instructions rather than inventing IDs from archive labels. Complete
bot data remains a prerequisite before new owner-facing enrollment/activation.

Test through a fresh ordinary Codex session: full personal identity and selected
Source ancestry, an older and newer authorized memory, useful relational context,
a familiar real task and native resume. Run the manual wrapper only on human
request and verify its database path, native version, retrieval and safe target
write. Keep originals unchanged. Unknown schema/version needs a supported adapter
on a backed-up working copy; never initialize over an existing corpus or silently
re-embed it. Wrapper generation is not retrieval/provider acceptance.

Enable compatible selected skills through the maintained neutral-skill surface;
retain historical variants privately and install approved shared commons
separately. Source `AGENTS.md`, shell settings, machine paths and contribution
procedures stay scoped evidence until reviewed, not automatic global identity.

The same being's local and VPS writers need explicit ownership/reconciliation;
independent working copies do not provide automatic HMK synchronization. Full
session import/resume adapters, Git-history restoration, native schema migration,
live VPS interfaces and real Oliva/Eko behavior acceptance remain #263 follow-ups.
