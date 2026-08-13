# DM-074 harness adoption V0

Status: offline guide, profiles, fixture, checker and deterministic reports are
implemented. No vendor account, credential, model, remote service, personal
profile or live human is used. Nothing in this card is a production-support
announcement.

“Matrix” means `daimon-matrix`; Matrix.org is unrelated. A harness is a
replaceable body runtime. Its account, model, session, prompt, instructions,
tool approvals, transcript and native memory never establish `/me`, presence,
relationship, grant, canonical memory or effect authority.

## Evidence states

These are the only V0 states:

1. `documented-candidate`: pinned extension points are mapped; mandatory unknown
   or failed controls refuse the body canary.
2. `synthetic-conformant`: an exact artifact/profile passes the offline fake
   Matrix corpus in a disposable root.
3. `private-smoke`: the same exact profile additionally passed a consented,
   reversible private canary with redacted evidence.
4. `live-supported`: all earlier evidence exists and an explicit maintained
   version/support policy has been accepted.

No state is inherited from another harness or model. This card records no
`private-smoke` or `live-supported` profile. Codex 0.146.0 and the
vendor-neutral fixture are `synthetic-conformant`; every additional vendor is a
`documented-candidate` and is refused. Hermes remains governed by its exact
DM-041/DM-042 evidence and is not silently reclassified by this guide.

The following summary uses `P` (pass), `F` (fail), and `?` (unknown). Every cell
has a source reference and note in `profiles/harness/v0/*.json`.

| Harness | Evidence | Iso | Life | Instr | Matrix | Tools | Ask | Net | Mem | Hist | Secrets | Retry | Proposal | Authority | Receipts | Pin | Upgrade |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Codex CLI 0.146.0 | synthetic-conformant | P | P | P | P | P | P | P | P | P | P | P | P | P | P | P | P |
| Generic MCP/CLI V0 | synthetic-conformant | P | P | P | P | P | P | P | P | P | P | P | P | P | P | P | P |
| Claude Code | documented-candidate | ? | ? | P | ? | P | P | P | P | ? | ? | ? | ? | ? | ? | ? | ? |
| Grok Build | documented-candidate | P | ? | P | ? | P | P | P | P | F | ? | ? | ? | ? | ? | ? | ? |
| Kimi Code | documented-candidate | P | ? | ? | ? | P | P | ? | ? | F | ? | ? | ? | ? | ? | ? | F |
| Google Antigravity | documented-candidate | ? | ? | ? | ? | P | P | P | ? | ? | ? | ? | ? | ? | ? | ? | ? |

`Matrix` in the table means an authenticated, startup-required local call
boundary with stable request/receipt IDs. `Authority` covers explicit refusal
of identity, ledger, root-signing, key rotation, membership/grant, memory,
source, species, audience, presence/fence and deployment effects. Missing
isolation, lifecycle, instructions, native-state subordination, receipts or
authority refusal means unsupported for a Matrix body canary even when MCP or
tool calling exists.

## Common narrow waist

An admitted harness receives one required local server named `matrix` through
an inherited descriptor. It exposes exactly:

- reads: `daimon_status`, `scope_me`, `scope_we`, `we_heads`, and
  `we_projection_get`; and
- one gated write: `we_observe`.

The capability is never copied to profile JSON, environment values, argv,
instructions, logs or reports. The harness asks for work and displays results;
Matrix authenticates, authorizes, idempotently journals and receipts every
canonical effect again. `we_observe` only proposes a non-adopting observation.
A UI approval, hook or model statement is evidence, never a Matrix decision.

Every reference overlay records launch argv, non-secret environment bindings,
effective configuration expectations, state roots, config precedence,
auto-update and migration policy, artifact/install provenance and limitations.
`reference-only` launch data must not be executed until an exact artifact is
pinned and all mandatory controls pass.

## Pinned evidence

`provenance/harnesses-v0.json` is the source inventory. Each mutable official
page has its retrieval date and SHA-256 of the fetched bytes. Each repository
document uses an exact commit URL and Git blob ID. These pins preserve the
audit input; they do not turn vendor documentation into conformance evidence.
The generated profile and fixture SHA-256 values in each frozen report bind the
Matrix-produced result separately.

### Codex reference profile

DM-040 remains the exact AI-harness reference: `codex-cli 0.146.0`, native
binary SHA-256
`2e863156ed35ecc5253b1e2f907a9143077b9f7cb51942070c61996471ff6e04`,
generated App Server contracts and a fresh owner-only `CODEX_HOME`. Its overlay
sets history persistence to none, disables web/network and native memory,
requires the Matrix server, freezes the six-tool inventory and binds lifecycle
receipts. OpenAI documents the relevant
[configuration](https://learn.chatgpt.com/docs/config-file/config-reference),
[MCP required/tool filters](https://learn.chatgpt.com/docs/extend/mcp?surface=cli),
and [AGENTS.md precedence](https://learn.chatgpt.com/docs/agent-configuration/agents-md).
Mutable documentation explains controls; DM-040's exact artifact and generated
contract hashes are the compatibility authority.

DM-074 reruns its overlay through the vendor-neutral synthetic corpus but makes
no model call and does not promote Codex to private or live support.

### Claude Code candidate

Claude Code documents local stdio MCP, workspace trust, named MCP permissions,
sandbox network restrictions and disabling auto memory. `CLAUDE.md` supplies
context and precedence, not enforcement. See Anthropic's official
[MCP](https://code.claude.com/docs/en/mcp),
[permissions](https://code.claude.com/docs/en/permissions), and
[memory/instructions](https://code.claude.com/docs/en/memory) references.

The profile is refused because no exact executable/digest, complete transcript
disablement, startup-fatal required-Matrix proof, stable crash/resume receipt
adapter or closed update/migration evidence is bound. A future profile must use
a fresh configuration root, must not use permission bypass, and must complete a
no-model startup smoke before any provider credential is present.

### Grok Build candidate

The source audit pins official xAI commit
`b13fa526f5112c0b20dad5f1f2300d3d3b127895` and exact blobs for configuration,
MCP, memory and sandbox behavior. The sources describe relocatable `GROK_HOME`,
headless tool filters, approval rules, a highest-precedence no-memory switch and
custom Linux sandboxing.

The profile is refused. Headless sessions persist in SQLite; required Matrix
startup, lifecycle receipts, artifact digest and closed update/migration are not
proven. Built-in sandbox profiles may warn or continue on unsupported systems.
A successor must use an exact custom fail-closed Linux sandbox, disable built-in
web tools and all imports, and pin the built executable. Official source:
[Grok Build audited tree](https://github.com/xai-org/grok-build/tree/b13fa526f5112c0b20dad5f1f2300d3d3b127895).

### Kimi Code candidate

The current candidate is the official `MoonshotAI/kimi-code` tree at commit
`0401ec4286f37929d1d298527c05f5351850bf8a`. It is distinct from the older
`MoonshotAI/kimi-cli` repository; their commits and contracts are never mixed.
The current docs show `KIMI_CODE_HOME` isolation, global tool allow/deny lists,
ordered permission rules, MCP, hooks, migration, persistent sessions and a TUI
auto-install default. Pinned sources include
[configuration](https://github.com/MoonshotAI/kimi-code/blob/0401ec4286f37929d1d298527c05f5351850bf8a/docs/en/configuration/config-files.md),
[MCP](https://github.com/MoonshotAI/kimi-code/blob/0401ec4286f37929d1d298527c05f5351850bf8a/docs/en/customization/mcp.md),
[sessions](https://github.com/MoonshotAI/kimi-code/blob/0401ec4286f37929d1d298527c05f5351850bf8a/docs/en/guides/sessions.md),
and [migration](https://github.com/MoonshotAI/kimi-code/blob/0401ec4286f37929d1d298527c05f5351850bf8a/docs/en/guides/migration.md).

The profile is refused because session history cannot yet be disabled, the
complete built-in service/subagent/network surface is not closed, automatic
update/migration is not yet proven off, and Matrix lifecycle/authority controls
have not run against an exact executable. A future smoke must disable telemetry
and auto-install and must never import Kimi CLI, Claude, Codex or personal
sessions.

### Google Antigravity candidate

Antigravity documents MCP allow/ask/deny resources with deny precedence and
plugins that bundle MCP servers, rules, skills and hooks. Those facilities are
not an embodiment adapter. The audited public material does not bind an
executable/version, fresh product state root, native memory/history disablement,
complete instruction/lifecycle semantics or Matrix receipts. The candidate is
therefore refused. Official references:
[permissions](https://www.antigravity.google/docs/cli-permissions),
[MCP](https://www.antigravity.google/docs/mcp), and
[plugins](https://www.antigravity.google/docs/plugins).

### Generic MCP/CLI reference

This is a Matrix-owned protocol fixture, not a claim that an unknown agent is
supported. A supervisor may use DM-025 only when it owns a fresh process root,
passes the descriptor locally, exposes no other tool/network/history/memory,
uses stable lifecycle and request IDs, and preserves Matrix receipts. Any
host-specific state or behavior moves the host back to `documented-candidate`
until independently pinned and tested.

## Offline fixture and checker

`tests/fixtures/harness/v0/manifest.json` is the closed
`dm.harness-adoption-fixture/v0` manifest. Admitted profiles use a real AF_UNIX
socket, a disposable owner-only harness home and a deterministic fake Matrix
process with a persisted Matrix-owned journal. The corpus proves:

- exact protocol/tool negotiation and unknown/downgrade refusal;
- isolated-profile preflight, ambient-profile trap exclusion, effective-config
  digest and owner-only modes;
- stable process/session/turn/tool/receipt/park/wake/crash/resume IDs, unknown
  lifecycle refusal and stale-resume refusal;
- a committed observation whose response is deliberately lost, daemon crash,
  restart and byte-identical terminal retry;
- same ID and bytes returning one effect/result, while changed bytes conflict;
- all identity/key/ledger/grant/memory/source/species/audience/presence/fence and
  deployment methods refusing;
- native state disabled, malformed and oversized request/response refusal,
  missing-receipt refusal, and transcript/export/tool-log quarantine;
- adapter disablement and replacement while the canonical event digest and
  rebuild result remain identical; and
- deletion of only the validated disposable profile after the run.

Refused candidates never start the fake session. Their blocking controls and
source pins are frozen in deterministic reports. The fixture uses no DNS,
network, vendor executable, model, credential, private key or personal state.

Regenerate and verify with:

```bash
PYTHONPATH=src python tools/generate_dm074_profiles.py
PYTHONPATH=src python tools/generate_dm074_profiles.py --check
PYTHONPATH=src python tests/fixtures/harness/v0/checker.py \
  --fixture tests/fixtures/harness/v0/manifest.json \
  profiles/harness/v0/*.json
PYTHONPATH=src python -m unittest tests.test_dm074_harness_conformance -v
```

The repository's existing `unittest discover` CI gate also runs a DM-074 smoke
test. The checker is fixture code rather than a packaged runtime module so it
does not alter the frozen DM-041 Matrix-package attestation.

## Upgrade and compatibility policy

No version range is supported in V0. Every admitted profile is an exact tuple of
artifact digest, source/doc pins, configuration precedence, state-root policy,
launch overlay, Matrix protocol and fixture digest.

Any vendor version, documentation/source pin, executable digest, release
channel, auto-update/migration behavior, configuration precedence, default
feature, tool inventory, transport, memory/history behavior, sandbox, approval
mode, hook schema or profile storage change invalidates the evidence. Re-audit
official source, create a successor profile, regenerate reports, run a clean
no-model startup smoke and obtain the review required for any identity, secret
or persistent-state boundary. Never widen an old profile to make a new version
pass. Unknown behavior fails closed.

Only `live-supported` may appear in an operator support statement. A
`synthetic-conformant` profile is useful for development but is not a promise of
provider availability, model behavior, operational reliability or live support.

## Troubleshooting

| Symptom | Required response |
|---|---|
| Profile/report drift | Stop; rerun the generator from the exact source head and review the diff. |
| Missing/extra/renamed tool | Refuse startup; never dynamically widen the allowlist. |
| Config root non-empty, symlinked or inherited | Refuse and create a newly validated disposable root. |
| Effective config differs from overlay | Refuse; identify the winning precedence layer before retrying. |
| Unknown version, hook or lifecycle event | Refuse and create a successor profile after re-audit. |
| Timeout or lost response | Retry only the same request ID with byte-identical canonical bytes. |
| Same request ID with changed bytes | Treat as conflict; do not guess or overwrite the journal. |
| Missing/invalid receipt | Treat the operation as unresolved and reconcile with Matrix. |
| Native transcript/memory appears | Quarantine and purge only the disposable root; never import it into `/me`. |
| Adapter disable/replace changes Matrix digest | Fail rollback and restore/reconcile Matrix-owned state before proceeding. |
| Secret or private path in public evidence | Quarantine the artifact, revoke the narrow capability if exposed, and regenerate redacted evidence. |

## Security and cleanup checklist

Before any future real harness smoke:

1. verify exact executable/source, digest, owner/mode, non-symlink ancestors and
   a fresh empty harness home;
2. disable auto-update, migration/import, native memory, transcript/history
   reuse, telemetry, web/network, plugins/apps/subagents and every non-Matrix
   tool before credentials exist;
3. verify effective config and instructions after managed, user, project,
   environment and CLI precedence layers apply;
4. pass the capability only by inherited descriptor and scan argv, environment,
   logs, transcripts, exports, reports and profile files for secrets/private
   state;
5. require exact Matrix startup and tool inventory; reject missing, extra,
   renamed, dynamically added or stale tools;
6. prove reads, separately approved write, exact retry, response loss, crash,
   resume, park, disable and replacement with Matrix receipts while native state
   remains noncanonical;
7. explicitly refuse identity, append/sign/key, membership/grant, memory/source/
   species, audience, presence/fence and deployment methods; and
8. park/retire the test profile forward, revoke its narrow capability and delete
   only the validated disposable root. Retain only approved redacted evidence.

Never expose a local Matrix endpoint through a public tunnel, copy Matrix root
keys or Cluster control credentials into a harness, restore authority from a
vendor session, or interpret native memory/history as canonical autobiography.
