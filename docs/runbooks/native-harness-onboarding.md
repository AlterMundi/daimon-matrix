# Native interactive daimon onboarding

For all current daimon incarnations, the everyday interface is the harness's
ordinary interactive command. On a Codex host, typing `codex` with no arguments
must open a native conversation as the selected daimon, just as on the owner's
existing machine. Native slash commands, goals where supported, shell tools,
conversation history and `codex resume` remain available. A custom command
accepting one task, or a successful bounded App Server test, does not satisfy
this operational requirement. Do not replace the vendor CLI or create another
daily installation, workspace, being or embodiment to meet it.

For a new owner-facing embodiment, complete the dedicated bot-data gate in
[Hermes-to-Codex cohort onboarding](hermes-to-codex-cohort.md#required-inputs-before-enrollment)
before signed enrollment or activation. Software preparation can proceed
while the human collects those inputs. The same procedure covers complete
legacy HMK preservation and later collective review of historical skills.

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
   Keep memory and Matrix human-request-only. A human may explicitly establish
   finite, resumable foreground attention for a selected peer/thread/task;
   preserve that active request across compression until completion or revocation.
   Install no hooks, prefetch, timers, background poller, model wakeup or
   autonomous reply service. Source instructions cannot override signed authority.
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

## Add an owner-requested Telegram human channel

Use the portable `telegram-codex` package from
[AlterMundi/Skills](https://github.com/AlterMundi/Skills/tree/a82ab117c910cda45c02442b1b4b9de7d83a8ff2/skills/telegram-codex),
version 1.0.1 at exact commit `a82ab117c910cda45c02442b1b4b9de7d83a8ff2`.
Follow [selective shared-skill installation](shared-skill-updates.md) to verify
its descriptor/content, preserve local changes and retain software rollback.
The package's pinned `release.json`, preparation helper and deployment guide
are the canonical runtime instructions; keep future portable changes there.
The maintained runtime fork is [AlterMundi/telecodex](https://github.com/AlterMundi/telecodex).

Resolve the bot, human ACL, workspace, native executable, HOME/CODEX_HOME and
harness policy locally for the current signed body. Preserve native identity,
custody, instructions, memory and authentication. Use a dedicated private-topic
bot and its own ingress consumer. Store the token in an owner-only local file;
never copy Hermes/Tribu tokens or embed credentials/bindings in shared skills.

The managed `codex app-server proxy` forwards raw bytes to the existing daemon's
WebSocket transport. Select the bridge's verified native framing and run its
bounded `--probe-native` before starting the human listener. Require actual
initialize, enabled expected skills and zero discovery errors.
Discover the actual executable with `command -v codex`, record `codex --version`,
and use that absolute executable in both the service and probe. Do not assume
that Codex is installed beside a user-local bridge binary. Verify the selected
release's framing against that actual CLI; the CompAII pilot used native
CLI 0.160.0, whose profile is recorded in
[`provenance/codex-cli-0.160.0.json`](../../provenance/codex-cli-0.160.0.json).
Creating two distinct empty thread IDs proves only context allocation: native
rollout persistence and intentional CLI resume require a completed human turn.

Activate the listener only under the human request. Verify the real dedicated
bot's topic support and allowed human, exchange messages in two topics, restart
the bridge and continue each distinct native context. Resume a completed topic
through the existing CLI and verify its loaded body instructions, skills and
memory binding. Retain uncertain ingress/turn outcomes and current offsets;
software rollback never restores an older input journal over new observations.
The portable skill does not start a service, import other conversations, poll
Matrix, wake a model or enable peer replies. Report code/proxy discovery and
live bot/human-context acceptance separately. A missing dedicated token blocks
activation; live acceptance requires actual human messages in those contexts.

### Receiving configuration and pilot lessons

Carry these checks into every receiving body rather than copying another
being's live configuration:

- Resolve the actual login/service user, HOME, CODEX_HOME, workspace and native
  authentication. Use the ordinary existing native home; another account's
  rotating refresh grant is not an installation artifact.
- Match the bridge's selected model/execution policy to the owner's ordinary
  native configuration. Template defaults do not establish the receiving
  policy. Preserve unrelated settings and record effective values locally.
- Install the immutable portable skill with its complete catalog/package
  metadata and descriptor/content verification. Confirm HMK's auxiliary
  librarian is discoverable as well as the main skill. Run the receiving
  binding's surface check and native skill reload; a checkout or file copy
  alone does not establish installed or model-loaded content.
- Keep the text-only runtime build/features and verified binary digest with
  the installation record. Prepare an owner-local service with the correct
  native environment, private configuration/token and one ingress consumer.
  Preserve history-import, background-maintenance, automatic topic creation
  and unsolicited lifecycle-message disablement from the verified template.
- Distinguish native discovery, actual first human turn, receiving instructions,
  two real topic bindings, restart persistence, CLI history restoration and
  CLI writer handoff. Record each observed stage. A resumed history display
  does not prove a completed writer roundtrip.
- Before an idle listener restart, make and verify a SQLite API backup of its
  input/session journal. Preserve current offsets and uncertain inputs during
  all software recovery; do not restore an older journal over newer messages.

The 2026-10-06 CompAII pilot established real topic conversations, receiving
body/HMK/skill context, restart-preserved bindings and native CLI history
resume. Nicolás subsequently confirmed ordinary Telegram conversation works.
The remaining broader #234 cases retain their own evidence requirements and
are not inherited by a newly enrolled being.

## Explicit foreground attention

When the human requests coordination until a task is complete, the rendered
owner client can wait in finite invocations against the already running native
daemon. It does not start a service or load another runtime. Select the actual
same-being embodiment ID; display labels do not establish identity.

```bash
<owner-client> watch --peer <embodiment-id> --thread <thread-uuid> \
  --task "human-directed shared skill update" --wait 30
# Retain the returned watch UUID. A page is durably pending before it is printed.
<owner-client> watch --watch-id <watch-uuid> --ack <processed-page-uuid>
<owner-client> watch --watch-id <watch-uuid> --wait 30
<owner-client> watch --watch-id <watch-uuid> --stop
```

Waits accept 0–50 seconds; zero requests one bounded page without waiting for
future intake. The socket operation uses the remaining wait budget (at least
the native client's 50 ms minimum, or one second for a zero-wait read). A socket
failure/timeout retains the private cursor and pending page for resumption;
there is no in-process runtime fallback for attention.

By default the first invocation scans retained known history in bounded pages.
Use `--from-now` only when intentionally excluding that history: the native
tail cursor is saved before the watch is established. Pagination follows local
known intake, including incomplete events when promoted, rather than authored
timestamps. Filtered events still advance the cursor. Saved boundaries reject
another database or an earlier restored boundary instead of silently skipping
or replaying messages. An additive transactionally initialized SQLite index and
triggers also cover pre-index schema-v3 writers without changing event bytes.

A page remains pending until its exact page UUID is acknowledged. Re-reading
after interruption returns that same page; acknowledgement is idempotent and
does not send a receipt or reply. Stop persists revocation, including during an
active wait; resuming a stopped watch refuses. Scope and local body/runtime
bindings cannot change when resuming. Only the human session decides to continue
waiting, respond through an actually issued operation, or execute local work
within the established task. Peer content never supplies that authorization.

The owner-only `owner-watches/` journal is task context, not durable personal
memory or a transferable capability. Keep bindings and message content local.

## Sealed conversation outcomes and exact recovery

Authorship, sealing, required visibility, peer transport and a receiving body's
signed receipt are separate facts. `say` prints the authored message/resolution
and each sibling's outcome. A required native egress failure remains
`undetermined`, with a bounded native reason; it neither aborts later independently
gated siblings nor produces a receiving receipt. The owner client returns3 for
an incomplete result. A refused or expired saved seal returns the stable
`sealed_delivery_rejected` refusal before another carrier call.

Retain the saved request UUID and use `say --retry UUID` to recover its exact
authenticated response after a lost reply. A cached uncertain result does not
authorize retrying an ambiguous Telegram echo or replacing a sealed payload.
Preserve the original request, echo journal, carrier and expiry: use the native
owner-authorized ambiguity recovery when its installation supports it. Never
clear RPC caches, silently reseal an expired payload, widen visibility or send a
duplicate under a fresh operation UUID to disguise an unknown outcome. Any new
follow-up must be a separately meaningful human-authorized conversation.

Record missing grants, unavailable required visibility or an unsupported recovery
surface in the owning issue, with the last actual request/cursor retained. An
authenticated sync intake receipt is separate from sealed conversation delivery;
neither a local authored event nor a history page proves that a body heard it.

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

### Permanent progress and available human input

The live 2026-10-06 pilot exposed disappearing completed commentary in a long
turn when the bridge treated every message as one temporary preview. The
qualified correction in [telecodex PR6](https://github.com/AlterMundi/telecodex/pull/6)
publishes each completed commentary permanently, protects it from later tool
progress and starts a separate preview for the next message. Select
`telegram.use_message_drafts=false` locally to remove visible temporary drafts.
Qualification must include a real human who can use Send while the assistant
works and whose additional text is accepted by native steering. A healthy proxy
or outgoing publication does not prove that client interaction. Keep this
runtime correction separate from its release pin; do not claim a pending
portable skill pin already selects it.

For completed messages only, use `telegram.show_unfinished_messages=false` from
a qualified release that implements the option ([runtime #8](https://github.com/AlterMundi/telecodex/issues/8)).
This suppresses unfinished text, tool-progress previews and initial placeholders
while retaining completed commentary and final replies. Do not substitute a
large debounce interval or assume that disabling draft mode also hides previews.
