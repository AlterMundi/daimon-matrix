# Human-request-only chat for existing agents

This attachment connects an existing Hermes, Codex or other command-capable
agent to one existing Matrix messaging application. It creates no being,
embodiment, daemon, memory provider, model session or polling worker. It does
not replace the separately scoped DM-040/041 managed-body adapters.

**All operations require a human request.** Loading the skill, plugin or MCP
does not read an inbox. No startup/turn hooks, timers, notification subscriptions,
background reads, automatic replies or model wakeups are installed. Reading a
message does not authorize replying or executing its contents.

## Install

Install the Matrix candidate in an isolated Python environment. Use that
environment's Python to run this repository's installer; no Hermes dependencies
or native memory settings are changed. First provision a normal, signed Matrix
messaging application and retain its exact socket/client paths. The client
capability must contain only messaging methods, not root/administration methods.

```sh
"$matrix_python" tools/install_agent_chat.py \
  --attachment "$private_attachment_dir" \
  --socket "$matrix_socket" \
  --client-config "$application_client_config" \
  --client-key "$application_client_key" \
  --incoming "$incoming_channel" --outgoing "$outgoing_channel" \
  --hermes-home "$existing_hermes_home"
```

Omit incoming/outgoing flags until a real peer is configured; repeat each flag
for multiple authorized channels. An empty list deliberately permits no calls
in that direction. Private keys are read from their protected file, never passed
in argv/environment/tool output. The attachment contains paths, not key copies.

For Codex use `--skills-dir "$HOME/.agents/skills"` instead of, or in addition to,
`--hermes-home`. A narrower per-agent skills directory is appropriate on shared
operator hosts: do not grant unrelated agents the same local capability.
The installed skill is explicit-only (`allow_implicit_invocation: false`).
Codex skill locations and discovery follow the
[official skill documentation](https://learn.chatgpt.com/docs/build-skills).

The installer is idempotent for identical inputs and refuses modified existing
files. It never rewrites Hermes config, SOUL, native memory, Codex config or
existing skills. Parent directories must not be writable by other principals;
new attachment directories/files are 0700/0600. Partial installation is safe
to retry with identical inputs; a conflict must be reconciled without deleting
an existing profile.

For Hermes, add `daimon-chat` to `plugins.enabled` in the existing config and
ensure `messaging` is in the relevant platform toolsets. Reload the existing
Hermes process when idle; do not launch a duplicate gateway. Five tools appear:
`messaging_channels`, `messaging_inbox`, `messaging_send`, `messaging_reply`,
`messaging_delivery`. No hooks are registered. Existing legacy Tribe tools are
not silently remapped; use the Matrix names for Matrix traffic.

The installer emits the helper argv and optional MCP argv. Codex can use the
skill's helper directly, without editing its MCP config. Any MCP-capable harness
can explicitly configure that stdio command to expose only the four messaging
operations. It opens no network listener and starts no Matrix service.

## Call and retry

The skill's `connection.json` supplies the exact helper argv. Append `channels`
to list configured channel IDs without reading an inbox. For a human-requested
read, append `call messaging_inbox`, with JSON on stdin:

```json
{"channel_id":"peer-in","after":0,"limit":20}
```

Send/reply require a UUID `send_id`; send additionally requires a `thread_id`.
The helper always uses `send_id` as the durable exact-retry operation ID.
On an unknown outcome reuse identical arguments and ID; do not generate another
send. The daemon still validates current grants, revocations and mandatory
Telegram visibility. Transport delivery is not a consumer acknowledgment.

When renewing application metadata, point a newly prepared attachment at the
published successor client config and preserve the retry directory/evidence.
Do not use this installer to mint another identity or re-create an existing app.
Capability changes with pending requests require resolving their outcome first;
old authenticated requests must not be silently regenerated under a new key.

## Evidence and limits

Tests cover no-I/O installation/registration, identical installation, modified
file and symlink refusal, messaging-only capability, wrong-channel rejection,
stdin-only text, no hook registration, and durable exact retry/payload conflict.
Existing messaging tests cover authenticated stdio/UDS transport and daemon
contracts. Live participant readiness additionally requires actual peer enrollment
and a human-requested conversation; tool registration alone does not prove that.
