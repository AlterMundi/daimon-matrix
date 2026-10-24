# Human-requested complete same-being delta

Matrix#376 owns the unfinished integrated workflow. Its unit is all customization
relative to each versioned harness baseline, plus memory and selected skills.
The merged inventory supplies read-only discovery/comparison; DMK PR32 supplies
native exchange, and Cluster PR295 supplies selected behavioral materialization.
Cluster#296 composes these with the existing selective Skills installer. The full
end-to-end increment and actual two-body use remain unfinished.

Use the owning ordinary checkout and receiving-private operation directory. Reuse
`tools.export_being` for file inventory, source selection and credential checks;
no onboarding archive, whole-home export, database copy, peer activation or model
turn is needed for recurring behavioral discovery.

## Receiving discovery

`python -m tools.behavior_inventory` records configuration leaves, literal path
references, global instruction precedence, project instruction/config candidates,
selected skill metadata and explicitly supplied launch/context sources. New
configuration keys are included without extending a filename/key allowlist.
Aliases, missing references, unreadable files and unknown defaults stay explicit.
No credential value is included. Reports still contain private local paths and
must remain owner-private; do not publish them as portable content or authority.

Required inputs are `--home`, `--codex-home`, `--cwd`, `--version`, an exact
`--source-revision`, `--source-evidence`, and a fresh `--output` path. Source
evidence is the receiving version's maintained loader/default contract, not a
later checkout's moving HEAD. An upstream tag alone does not prove reproducible
identity between a packaged binary and that source. `--origin` can bind an existing
owner-client status observation with being/local-origin IDs; it remains an
unsigned observation, never a fabricated historical native event.

Use `--additional` for the receiving profile's actual wrappers, service fragments
and context sources. Literal absolute/home paths in configuration are inspected
without evaluating shell, environment or remote content. Relative/indirect
references, managed policy, hooks, plugins and launch overrides still need their
receiving adapters/content closure; the report lists these gaps instead of
claiming complete consumption. A candidate file is not proof the harness loaded it.

## Exact native configuration and baseline

Retain the supported native `config/read` response with `includeLayers=true`
and the selected cwd, initialization/version evidence and exact executable hash.
Read the existing daemon; do not restart it or create a thread to inspect config.
Transport depends on the installed version: qualified0.163.0 control is WebSocket
over its owner-local Unix socket, while a standalone app-server can speak NDJSON
on stdio. Sending NDJSON directly to that WebSocket is a verifier error, not proof
of a broken native session. Reuse the installed compatible client.

For a default reference, read the same exact binary through a finite isolated
empty home/cwd, without authentication, threads, models or inherited personal
configuration. Retain its system/packaged layers: an empty user home alone is not
proof of a factory-only baseline. Close only that disposable process afterward.
Never upgrade an older receiver to manufacture a matching default reference.

Pass the retained packets as `--native-config` and `--native-baseline`. Each has
`binary_sha256` and the native `result`; mismatched binary baselines are refused.
Comparison retains every key, with sensitive credential bindings omitted. An
explicit native null is `baseline_unspecified`, not a claimed effective factory
value. A known matching value is inherited; a known difference is modified;
unknown keys/defaults remain unknown. Running-turn consumption remains unverified.

Each non-secret setting also records `input_sources`, referencing the ordered
`layers` metadata by `layer_index`. An `exact` declaration names the leaf; an
`ancestor` names a scalar/null input above an expanded effective object. The
comparison flag describes equality only, never which input won or a model read.
Input values and their digests are not copied into this report. Disabled layers
remain visible without becoming active declarations. Missing layer configuration
is unavailable evidence, not proof that a setting has no input.

`declaration_state` distinguishes `active-exact`, `active-ancestor`,
`disabled-only`, `no-active-declaration` and `unavailable`. An expanded setting
without an active declared leaf must not silently become a CompAII customization
to install elsewhere. Existing unknown/unspecified baseline classes remain
unchanged even when an active layer declares the setting. Receiving-local intent
and adaptation still decide adoption; neither declaration nor equality grants it.

## Exact receiving comparison

Add `--compare-with` for a selected attributed inventory of another body of the
same being, and optionally `--common` for retained common inventory history.
The tool compares exact native-setting, global-instruction and skill-document
hashes, retaining both inventory references and original unknowns. Without common
history it does not manufacture an incoming winner. Divergent edits on both
sides are explicit conflicts; a local unchanged preimage identifies only a
candidate incoming change. Local path/config adaptations still require a local
intent decision. These unsigned observations never grant execution authority or
author a Weave adoption. The resulting comparison is a preview with no effects.

## Integration frontier

Use DMK `scripts/same_being_sync.py` for the current unsigned native delta
([DMK PR32](https://github.com/AlterMundi/daimon-memory-kit/pull/32)): finite
read-only pages, retained-content closure, native transactional application,
original/receiving history and legacy sidecar provenance. Its commands are
`export`, `inventory`, `apply`, `status`; the parent joins one existing
`backupctl` operation across all pages. Source publication is not receiving
installation/adoption. Preserve the old `owner-memory-sync` qualification for
its signed projection scope; do not downgrade a current DMK distribution to
force an unsigned recurring delta through its old checkout/writer cutoff. Reuse
Skills `describe/prepare/apply/status/recover/rollback` for selected immutable
packages, and Weave `configuration.proposed`, `adoption.decided` and
`projection.receipted` for existing native semantics. Discovery itself neither
authors these events nor changes identity, permissions, account, custody or history.

The owner-local `we.propose` RPC accepts the same closed fields as `we.observe`
(`subject`, `payload`, `sensitivity`, `causal_parents`, `occurred_at_ms`, `event_id`)
plus a `kind` equal to `configuration.proposed` or `skill.proposed`. It uses the
existing weave mutation capability; the default observe capability cannot
propose. The existing `we.observe` contract is unchanged. Use the maintained
client's `we_propose`/`we_event_get` methods (or `invoke`), stable operation
request IDs and exact content
references. Native unsigned records and manual edits remain attributed migration
input, never historical signed `memory.recorded` events.

`we.event.get` with `{ "event_id": "<canonical UUID>" }` returns
`dm.we.event-result/v1` and the complete original signed event, or `event: null`
when that event is not known/complete. It is an authenticated observe read, not a
peer-chosen file resolver. An RPC request ID retains its original read snapshot;
a later observation uses a new read ID, never a new mutation ID to hide uncertainty.
CLI equivalents are `we propose --kind ... --subject ... --payload ...` and
`we event-get --event-id ...`; MCP exposes `we_propose` and `we_event_get` with
the same closed fields. Use the existing persisted request file or MCP operation
ID for an exact mutation retry. Normal native sync carries the proposal unchanged. Receiving it does not adopt
it: use the existing local `we.decide` chain. Neither proposal, event retrieval
nor adoption proves or executes the external effect. The effect adapter must
supply actual postcondition evidence through the established projection boundary.

The remaining operator must connect exact references/preview, explicit retained
local decisions and missing behavior-materialization adapters under one resumable
operation. Preserve body-local bindings and deliberate differences; concurrent
edits are conflicts, never timestamp winners. Saving files does not rewrite an
existing model's context. Demonstrate actual receiving use separately from receipt
and installation, while reusing valid earlier memory/skill/recovery evidence.
An offline receiver remains pending without blocking independent implementation.

No recurring timer, hook, attention loop, automatic adoption or global Stop is
implied. Each global Stop requires fresh explicit human consent. Rollback preserves
current accepted authority, conversation/incident data and uncertain effects.

## Observed foreground projection receipts

`we.projection.receipt` takes exactly `{ "receipt": <dm.cluster-effect-receipt/v1> }`.
CLI: `we projection-receipt --receipt <file>`. MCP: `we_projection_receipt`.
It belongs to the existing weave mutation capability, not observe. It never
executes the external effect or installs its observer from RPC/peer data.

The receiving host injects `projection_observer` and, for a fenced effect, the
existing Cluster `projection_fence_verifier` through `load_runtime`. The observer
returns exactly `intent`, `observed_postcondition`, `current_fence_evidence` from
its actual retained owning operation. The same-being Cluster integration observer
resolves the opaque effect UUID in OperationJournal and rechecks actual DMK,
selective skill and behavioral state. A claimed success from the caller alone
cannot cross this boundary. Other native memory projections keep their dedicated
qualified adapter; this foreground method accepts configuration/skill proposals.

Matrix requires a known complete proposal, its current linear adoption by this
exact local origin, the local daimon actor and valid local timing. It uses the
existing canonical Cluster reconciliation and ledger state CAS before authoring
`projection.receipted`. Sensitivity is never lowered: equal target/decision
sensitivity is preserved; differing sensitivities produce a private receipt.
The canonical event ID derives from the effect UUID; recording it from another
request cannot duplicate the event or silently replace changed evidence.

Persist the complete signed mutation request before sending, including its
original nonce/authentication, not merely its UUID. Reuse the existing CLI
request file or MCP operation ID; the integration parent retains those exact
documents. The receiving client capability must support the method and a fresh
`runtime.status.projection_receipts.observer_available` must be true before any
child effect starts. This uses the existing receiving status read; no separate
manual preflight or approval is needed. Preserve the original client profile for unresolved
requests across a qualified receiver update; never re-sign an uncertain request
with a fresh nonce to conceal an authorization mismatch.

Every exact retry independently reconciles the current effect and adoption,
including a cached RPC success or previously unavailable observer. The original
RPC/event remains historical evidence; a later refusal never deletes it. This
observation concerns materialized state, not a model's consumed context.
The actual receiving harness-use checks remain separate unfinished work in376.
