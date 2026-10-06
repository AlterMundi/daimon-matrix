# Native interactive daimon onboarding

For all current daimon incarnations, the everyday interface is the harness's
ordinary interactive command. On a Codex host, typing `codex` with no arguments
must open a native conversation as the selected daimon, just as on the owner's
existing machine. Native slash commands, goals where supported, shell tools,
conversation history and `codex resume` remain available. A custom command
accepting one task, or a successful bounded App Server test, does not satisfy
this operational requirement. Do not replace the vendor CLI or create another
daily installation, workspace, being or embodiment to meet it.

## Adopt the existing body into the ordinary harness

1. Identify the existing signed runtime, rendered owner client, current
   incarnation and owner-selected SOUL/foundation. Instructions describe that
   existing body; they do not issue identity, capabilities or custody. Preserve
   the original source SOUL and its history. Label source-harness differences.
2. Use the actual login user's ordinary Codex home (`~/.codex` unless that user
   explicitly selected another home). Inspect its global instructions and
   effective configuration. Preserve authentication and conversations; do not
   inspect or import unrelated personal conversations. Archive stale
   instructions before replacing their unsupported claims.
   A nonempty global `AGENTS.override.md` takes precedence over `AGENTS.md`.
   The installer refuses that conflict and unsafe override files before editing
   either target. Explicitly select and archive a conflicting override under
   the owner's authorized identity migration, then repeat installation.
3. Write an owner-selected identity instruction file naming the existing body,
   runtime, authenticated rendered owner client and its actual capabilities.
   Include the manual shared-memory entry point and neutral skill directory.
   Render the owner client from the approved release and the existing body plan.
   Validate its actual issued profiles with `methods`; test `say` using native
   recipient receipts and retain its request UUID for exact recovery. See
   [owner conversations](neutral-territory.md#owner-conversations-and-installed-operation-profiles).
   Keep memory and Matrix human-request-only, with no hooks, prefetch, timers or
   autonomous replies. Source instructions cannot override signed authority.
4. Install the selected instructions and ordinary configuration with the
   reusable installer below. It prepares by default and applies only with
   `--apply`. Policy is explicitly selected by the owner, not hardcoded to
   full access. The installer preserves unrelated configuration values and
   backs up the two affected files; it never reads authentication, imports
   conversations, changes a signed runtime or launches a model/Matrix call.
5. Codex natively scans the owner's neutral `~/.agents/skills` surface. Reuse
   the approved common skills and memory binding rather than duplicating them
   into another profile. Verify the installed binding's surface check.

```bash
python3 tools/install_codex_identity.py \
  --identity-file /owner/selected-current-body.md \
  --soul /owner/selected/SOUL.md \
  --foundation /owner/selected/FOUNDATION.md \
  --memory-access /owner/selected/MEMORY-ACCESS.md \
  --model <owner-selected-model> --reasoning medium \
  --approval <owner-selected-approval> --sandbox <owner-selected-sandbox>
# Inspect the prepared selection, then repeat with --apply when authorized.
```

The selected full context must fit the native global instruction bound. The
installer refuses oversize context rather than silently truncating the SOUL.
Existing configuration comments are preserved in the byte-exact backup;
effective unrelated TOML settings survive installation. Restore the two files
from the reported private backup to roll back (consult its manifest for a file
that originally did not exist). Authentication, conversation data, Matrix
history and custody remain untouched throughout.

## Acceptance uses the interface the human will use

Open a real terminal under the target login and run exactly `codex`. Verify the
effective model/reasoning/permissions and that the daimon recognizes its current
body, selected SOUL, memory entry point and skills. Test an ordinary development
operation and, on an explicit human request, its authenticated owner client and
memory retrieval. Exit and use native `codex resume` to verify continuation.
Record actual observations, not only model self-descriptions. A different
authentication account must be owner-authorized; never clone a rotating refresh
grant into a competing store. Credential renewal and failed-resume recovery
must use the chosen provider's real supported path.

An ordinary interactive adoption with an authenticated owner client is distinct
from the separately pinned App Server/MCP lifecycle profile. It does not inherit
that profile's launch receipts, Cluster presence, bounded-turn proofs or support
classification. Neither native transcripts nor global instructions become
canonical Matrix memory or authority. Reuse existing valid body, memory and
delivery evidence without relabeling it as proof of the interactive interface.

Apply this procedure to every daimon adopted into a native harness. Other
harnesses use their ordinary interactive entry point and supported global
instruction/configuration surface; each needs its own actual acceptance proof.
