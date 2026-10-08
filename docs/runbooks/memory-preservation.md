# Preserve memory history and required content in archive v1

`tools/preserve_memory.py` produces an inert
`dm.being-memory-preservation/v1` sidecar and selected Git bundles. Include that
output directory as an ordinary contextual source in the existing
`dm.being-context-archive/v1` exporter. The base manifest and its authority
meaning remain unchanged. This is source-history preservation, not event
admission, identity issuance, enrollment or activation.

First discover the human-authorized same-being roots using the existing
[export procedure](being-export.md). Quiesce their actual writers and regenerate
the plan. A label does not establish ownership. Keep private inputs/output private;
use the existing recipient-protected transport when selected material requires it.
Do not put real packets, source paths or credentials into public evidence.

Prepare a selection naming the source IDs from that plan. For example:

```json
{
  "schema": "dm.being-memory-preservation.selection/v1",
  "hmk": [{"source_id": "memory-001", "path": "library.db"}],
  "matrix": [{"source_id": "context-002", "path": "ledger.sqlite"}],
  "content": {
    "<statement-sha256>": {"source_id": "context-002", "path": "content/statement.txt"}
  },
  "artifacts": [{"source_id": "codex-003", "path": "memories/lesson.md", "role": "native-learned-artifact"}],
  "git_sources": ["codex-003"],
  "world_references": ["https://example.invalid/project/issues/47"]
}
```

Select only an actual owned repository root for `git_sources`. Bundles retain all
its available refs/commits, including HEAD; selected worktree files retain local
changes separately. Local configuration, hooks and connection state are excluded
from bundles. Indirect Git directories and shallow history require a separate
explicit adaptation; the tool neither fetches missing history nor runs hooks.

```bash
python3 tools/preserve_memory.py build --plan plan.json \
  --selection preservation-selection.json --output memory-profile --writers-stopped
```

Append `memory-profile` as the last contextual root when regenerating the export
plan; keep the original source order/IDs. Export with the existing tool. Preserve
and independently supply the archive checksum, then use its `verify`/`unpack`
commands to obtain a fresh private staging directory. Finally:

```bash
python3 tools/preserve_memory.py verify --stage received \
  --profile-member payload/context-004/memory-preservation.json
```

The last source's ordinal determines the profile member prefix. Sidecar checking
assumes the base archive has already been verified with the expected transport
checksum; a sidecar is not an authentication mechanism. It binds all checked
members to that staged manifest and detects subsequent payload/profile drift.

Full SQLite snapshots retain all tables/columns, native originals, revisions,
links, metadata and capture history. Logical schema/table fingerprints are
compared after transport: backup snapshots can have different physical bytes.
For selected Matrix ledgers every `memory.recorded` statement content reference,
including superseded assertions/corrections before a retraction, must resolve to
selected exact bytes. The complete ledger also retains evidence identifiers and
signatures. A source's `known`/`incomplete` status remains attributed source data;
this tool does not validate or accept it into a receiving body's authority.
Additional byte dependencies can be listed in `required_content` using content
references. URLs and history identifiers are not automatically fetched.

Unresolved required content stops building. A source agent may explicitly record
an already-unavailable reference in `unavailable`, keyed by SHA-256, with
`status: "unavailable_before_export"` and a reason. This is an attributed operator
declaration, not proof of when loss occurred. Verification reports incomplete
content separately. Loss introduced after building remains a failure and cannot
be reclassified by modifying the preserved declaration. Unknown selection fields
are retained as original JSON; verification claims behavior only for known fields.

This procedure does not test receiving conversational continuity or supported
DM-034 target releases. Those qualifications remain distinct. Keep original
archives and already-valid capture/consolidation evidence available.

## Current HMK implementation qualification

DM-034's unchanged v1 profile declares its frozen wire-contract reference
`f10fd5c3089c0962920314c97e14bc024feffa7a`. A separately configured
`CurrentHMKCompatibilityTests` executes the real CLI at
`0f9a3b22c7a765514d36c9aa64d4649d7318a863`; its exact HEAD and unchanged scripts
are checked before running the same behavioral contract tests. Record both
identifiers, not a substituted profile pin. This is compatibility evidence for
that implementation, not a new v1 release registration or a live target change.

```bash
HMK_CURRENT_ROOT=/path/to/exact-current-hmk \
  PYTHONPATH=src python -W error::ResourceWarning -m unittest \
  tests.test_dm034_memory_projection.CurrentHMKCompatibilityTests -v
```

The transport test withdraws selected sources before restoring the packet,
validates preserved event signatures with only archived public fixture authority,
restores an earlier Git revision, detects missing/altered content and repairs it,
then rebuilds current Matrix heads into a separate HMK copy. Historical assertions
are retained but cannot be re-applied over a later correction or retraction.
Native records and revisions survive the rebuild. Synthetic authority is an
isolated test fixture, never enrollment of a real receiving embodiment.

Set `HMK_PRESERVATION_CORPUS` to an already-qualified **fictitious** SQLite corpus
for the larger local qualification; `HMK_PRESERVATION_REPORT` and
`HMK_PRESERVATION_EVIDENCE` retain its report and packet privately. Without that
selection CI uses its own small fictional native record. The larger run checks
four bounded native lookups; it does not repeat natural-narration acceptance.
