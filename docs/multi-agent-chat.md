# Multiple agents, one Matrix host

`python -m daimon_matrix.chat_host --config /absolute/owner-only/host.json`
hosts explicit local identities and their signed chat applications in one
process. It is transport infrastructure, not another agent or a model runner.
Reads, sends and replies remain human-request-only in every harness.

The owner-only configuration has schema `dm.chat-host/v1` and a `runtimes` list.
Each runtime specifies its absolute `state_root`, protected `password_file`,
and `applications`. Each application specifies its absolute `directory` and
`visibility` installation paths, plus a short `socket` basename, e.g.
`matrix.sock`. The first application's visibility controller also governs the
runtime's existing native transport; subsequent applications have independent
controllers and transport journals. Preserve that ordering when adding a link.

Every runtime is locked and unlocked once. Each application keeps its signed
authority, messaging-only client capability, Unix socket, HTTP listener,
Telegram policy and durable retry stores. Listeners must use distinct addresses
and ports. A failure stops all hosted views rather than silently dropping an
identity. No automatic inbox reader or reply loop is installed.

For an existing identity, `chat_link.py finish --additional-link` initializes
only the new application's visibility catalogs; it does not replace the proof
key of the existing native transport. Enrollment reuses the current valid
relationship card and its chat resource so existing accepted relationships are
not invalidated. The file-enrollment responder must still be a freshly prepared
identity. An incompatible existing card is rejected, not silently rotated.

## Harness attachment

An existing v1 agent binding remains supported. To give the **same identity**
several links, point the helper at an owner-only v2 binding:

```json
{
  "schema": "dm.agent-chat.binding/v2",
  "links": {
    "oliva": "/absolute/path/oliva-binding.json",
    "codex": "/absolute/path/codex-binding.json"
  }
}
```

Each child is an ordinary v1 binding. `channels` lists aliases such as
`oliva/peer-in` and `codex/peer-out`. Replies must use incoming and outgoing
channels from the same link. Nested collections and mixed runtime identities
are rejected. No credential is implicitly borrowed from another identity.

For a distinct Codex identity, generate and enroll its own identity, use its own
client capability and retry directory, and install the existing `daimon-chat`
skill using `tools/install_agent_chat.py --skills-dir`. Keep explicit-only skill
invocation and no inbox hooks. The same helper also serves Hermes and MCP.

## Qualification and rollback

Run `--check` with the host stopped to verify all signed applications and
visibility registries under runtime locks without starting listeners or workers.
The disposable three-identity test exercises real HTTP/Unix sockets, capability
separation, preserved old-peer delivery, new-peer delivery and complete shutdown;
only Telegram is replaced with an explicit test double.

Before activation, retain the previous unit, package and attachment binding.
Adding a link must not delete an existing application, replace identity custody,
or reset a ledger. To roll back a host deployment, stop the host and restore the
previous unit/package/binding. Keep newly enrolled signed history and new-link
files; rolling software back is not permission to roll back cryptographic state.
