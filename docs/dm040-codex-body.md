# DM-040 Codex body adapter

Status: implemented V0 contract for synthetic isolated profiles.

“Matrix” means the `daimon-matrix` component. Matrix.org is unrelated and is
not a dependency.

## Outcome and authority

DM-040 makes Codex one body/incarnation surface of an existing `/me`. Codex,
the ChatGPT/provider account, model, prompt, workspace, thread store, MCP
connection and local files are not the being and are not personal-memory,
presence, policy or authorization authority.

The authority split is explicit:

- Matrix certifies being, embodiment and incarnation, owns the ledger, `/me`
  and `/we` projections, semantic policy, capabilities and effect receipts;
- Daimon Cluster owns process placement, lifecycle and resource fences and
  reports current body/incarnation observations to Matrix;
- Codex executes turns inside the admitted body and calls only the required
  owner-local Matrix MCP surface;
- Codex approval and hooks are UI/guardrail evidence. Matrix authenticates and
  authorizes every canonical effect again.

DM-040 does not create a live CompAII profile, copy authentication, deploy to a
host or enable a body. Those operations remain later canary work.

## Audited Codex boundary

The exact supported payload is `codex-cli 0.146.0`, native executable SHA-256
`2e863156ed35ecc5253b1e2f907a9143077b9f7cb51942070c61996471ff6e04`.
The npm JavaScript launcher hash is recorded separately and is not sufficient:
it selects another executable. The locally observed npm installation was also
group-writable, so it is audit evidence, not an admissible production
installation. An operator must supply the pinned native payload from a
root/owner-controlled, non-symlinked and non-group-writable installation.
The adapter never downloads, copies, updates or repairs Codex.

The 0.146.0 App Server generator produced 275 JSON schema files and 622
TypeScript files. The TypeScript output was byte-identical across two runs. One
aggregate JSON schema changed only definition-key order. DM-040 therefore
hashes every relative path plus canonical JSON, yielding:

- normalized JSON bundle: `146a56d701ccd97a76ad1a461d51fc454f32df6c5b4d338ea65968331ccc8b7a`;
- TypeScript bundle: `b60eaad826761bac1ebb33a933e0a0ad389a343f983b288107484e2e2b9c93e2`.

The exact feature snapshot and official source inventory are in
`provenance/codex-cli-0.146.0.json`. The relevant documented surfaces are:

- [`CODEX_HOME` and configuration](https://learn.chatgpt.com/docs/config-file/config-reference);
- [lifecycle hooks](https://learn.chatgpt.com/docs/hooks);
- [local Memories](https://learn.chatgpt.com/docs/customization/memories);
- [`codex exec --ephemeral`](https://learn.chatgpt.com/docs/non-interactive-mode);
- [App Server JSON-RPC](https://learn.chatgpt.com/docs/app-server).

App Server remains labelled experimental in this release. It is isolated
behind an exact version, executable, generated-schema and notification
boundary. The Matrix adapter, profile plan and runtime-handle contract do not
depend on rollout/SQLite internals. A Codex change needs a new provenance
record, vectors, review and DM-018 migration receipt.

## Closed profile plan

`dm.codex-body.plan/v1` contains public logical IDs and policy, never host
paths or credentials. Trusted local paths are supplied separately to
`CodexBodyPlan`; no path can enter a protocol receipt.

The plan fixes:

- an Ed25519-signed `dm.codex-body.bootstrap/v1` certified by Matrix;
- exact being/body/embodiment/incarnation/Matrix-session IDs and high-water;
- body-certificate and capability-set hashes plus validity interval;
- logical workspace reference, explicit model/provider declaration;
- Codex binary and App Server contract digests;
- `workspace-write`, `on-request`, disabled network and no history;
- the exact six Matrix MCP tools and one safe descriptor-name environment
  variable.

The bootstrap uses the root identity vocabulary rather than inventing an
adapter namespace: `body_ref` is bounded opaque text (normally `cluster:...`),
`embodiment_id` matches `embodiment:...`, and `incarnation_id` matches
`incarnation:...`. Matrix session, workspace and content-addressed artifact IDs
remain derived `dm:...` values. The initial DM-040 synthetic vectors used
derived IDs for all four fields; DM-042 corrected that overly narrow adapter
assumption so an admitted Codex body can match `being-manifest/v2` exactly.

Creation requires a fresh nonexistent `CODEX_HOME`, an owner-only parent and
synthetic workspace, a current injected Matrix bootstrap verifier and trusted
executables. It rejects symlinks, hard links, unsafe modes/owners, path swaps,
unexpected existing state and drift without deleting anything. A crash during
creation leaves a partial profile that is deliberately refused for inspection;
there is no cleanup routine that could erase a human profile.
The profile identity also binds the observed Matrix MCP launcher and hook
Python executable hashes and rechecks them before every launch; trusting a path
name alone is insufficient.

The deterministic profile contains only:

```text
AGENTS.md
bootstrap.json
config.toml
hooks/lifecycle.py
profile-manifest.json
```

Codex may later create opaque runtime state. DM-040 never reads it for
identity, memory or continuity. Any `memories`, Chronicle or imported/external
memory artifact quarantines the profile.

## Effective Codex policy

The renderer emits strict TOML and launches App Server with
`--strict-config`. It explicitly sets:

- `features.memories = false`;
- `memories.use_memories = false`;
- `memories.generate_memories = false`;
- `history.persistence = "none"`;
- hooks on, analytics and OpenTelemetry exporters off;
- apps, plugins, browser/computer use, Chronicle and external-memory import
  off;
- multi-agent tools off and the workspace explicitly marked `untrusted`, so
  project-local `.codex` config, hooks and rules are not loaded;
- web search off, no login shell and a closed shell environment;
- one enabled and required `matrix` MCP stdio server;
- bounded MCP startup/tool timeouts and an exact tool allowlist;
- automatic approval only for five reads and prompt approval for
  `we_observe`.

The six tools are `daimon_status`, `scope_me`, `scope_we`, `we_heads`,
`we_projection_get` and `we_observe`. A generic path, SQL, prompt, model or
command tool is not admitted. Before launch the adapter also probes effective
feature state and rejects a managed/host override. Child processes run with
`umask 077`. After thread start/resume the adapter reads the App Server MCP
inventory and requires exactly one `matrix` server. When App Server reports
server metadata and tool inventory they must match `daimon-matrix` `0.0.0` and
the exact six tools; its legacy `2025-06-18` status response currently leaves
those two optional fields empty, so the reviewed profile/launcher hashes and
successful required-MCP handshake remain the admission evidence. Required-MCP
startup failure blocks the Codex thread before a runtime handle is accepted.

The MCP capability remains in the Matrix/DM-024 trust boundary. Its inherited
descriptor number is public configuration; the 32-byte capability is passed
only through that open descriptor, never TOML, argv content, environment
value, logs or receipts.

## Instructions and hooks

The reviewed global `AGENTS.md` states the body role, Matrix authority,
untrusted-content rule, classification/secret discipline, receipt requirement
and park behavior. It contains no biography, NOW projection or generated
memory. App Server must report this exact global source. Additional sources may
only be `AGENTS.md` beneath the admitted workspace; any other source,
duplicate, missing global source or external path fails closed. Project prose
cannot override Matrix admission or sandbox minima.

The generated lifecycle hook accepts closed release-specific JSON for
`SessionStart`, `UserPromptSubmit`, `Stop` and `SessionEnd`, under strict byte
and timeout limits. It never logs prompt, assistant content, transcript path,
cwd, MCP payload or exception representation. `SessionStart` returns only the
bounded signed bootstrap descriptor. Lifecycle observations contain public
IDs, model, timestamp and outcome class.

Hooks do not authorize effects. Hosted/specialized tools can bypass local tool
hooks and `SessionEnd` is advisory. Matrix request/receipt state and the
runtime-handle journal recover missing observations.

## App Server and recovery state machine

V0 uses only a child process over stdio JSONL. No TCP, wildcard listener,
WebSocket, remote control or bearer endpoint is configured. Initialization
requires the exact four-field response and matching isolated `codexHome` and
version. Responses are bounded, correlated and unique. Unknown notifications,
methods, fields, duplicate IDs, reordered responses, invalid framing and
schema drift fail closed.

Runtime handles distinguish Codex thread, session tree and turn from Matrix
body, incarnation and session. They form an append-only content-addressed
chain:

```text
starting -> active -> resuming -> active -> parked
```

`starting` is written and fsynced before `thread/start`; `resuming` precedes
`thread/resume`. If Codex commits and its response is lost, the pending state
survives and blocks a blind retry. The adapter never creates a second thread
to make the test green and never treats a rollout as proof. Explicit future
reconciliation must establish the exact returned thread/session handles or
retire the profile forward.

Every resume revalidates current Matrix body, embodiment, incarnation,
session, expiry and high-water. The adapter supplies its last accepted
high-water as a minimum; the trusted Matrix verifier must prove the current
value descends from it before returning the advanced value. Expired/parked
evidence, a substituted body or a non-descendant/rolled-back high-water cannot
revive a thread. Park records the terminal local state; Cluster/Matrix then
perform the authoritative body handoff and fence release.

`dm.codex-body.launch-receipt/v1` is path-free and content-addressed. It binds
the profile/plan, exact compatibility, reviewed file hashes, model/provider,
logical workspace, sandbox/approval/network policy, distinct runtime handles
and current Matrix binding. It contains no prompt, model output, memory,
credential or private host path.

## Verification and real smoke

Closed contracts are in `schemas/codex/v1/contracts.schema.json`; reviewed
templates are in `templates/codex/v1/`; deterministic vectors are in
`vectors/codex/v1/`. Regenerate and check them with:

```bash
python tools/generate_dm040_vectors.py
python tools/generate_dm040_vectors.py --check
```

The public tests use fresh temporary roots and fake subprocesses. They cover
determinism, closed schemas, unsafe owner/mode/type/symlink/hard-link/path
replacement, existing-state preservation, memory negatives, two isolated
beings, hooks, journal corruption/crash windows, response loss, expired
presence, high-water rollback, MCP timeout/version/tool drift, instruction
sources, root-manifest identity formats, fragmented/coalesced JSONL, unknown
notifications and secret/path-free receipts.

The private real-Codex smoke is opt-in because it needs the 311 MB pinned
native Codex payload. It does not need provider authentication or invoke a
model. It creates a new owner-only `CODEX_HOME`, reviewed synthetic workspace,
real synthetic Matrix daemon and required local MCP with an inherited
capability FD. It starts one thread, reads the synthetic projection, commits
exactly one idempotent `we_observe`, persists only supported thread metadata,
restarts App Server, resumes the same thread after a monotonic Matrix
high-water advance, checks no native-memory/auth artifact and then parks. CI
skips this lane with an explicit reason and never archives stdout, auth,
prompts or model content.

## Rollback

Before any admitted thread, rollback may remove only the known unused
synthetic profile after an operator resolves its exact path. After a thread or
pending `starting/resuming` record exists, disable admission and park/retire
the body through forward Matrix/Cluster evidence. Preserve handle, Matrix
ledger and receipt high-waters. Never delete/import Codex memory, restore a
rollout as continuity, rewrite a pending outcome or re-enable expired body
evidence.
