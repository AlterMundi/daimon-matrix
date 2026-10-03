# Issue 205 independent security and persistence review

Independent reviewer: Codex task `review_codex_0155`.
First reviewed head: `5a23c4ea8f0ce206070857e7d99d2c38330c8be4`.
First verdict: **REQUEST_CHANGES**. Historical findings are recorded below;
subsequent correction approvals are recorded in the later sections.

Three demonstrated implementation blockers were corrected:

- B1: First start could append active after admission expired during native RPC.
  The successor now verifies fresh admission after native result and MCP checks,
  anchored to the previous high-water mark. The regression advances the clock
  during the RPC, proves refusal, preserves starting history and refuses blind
  retry. Historical admission behavior remains separately pinned.
- B2: Effective configuration admitted automatic `notify` and alternate
  `model_instructions_file` / `experimental_compact_prompt_file` values.
  All three mechanisms now require absence, alongside the existing instruction
  and hook exclusions. Each populated control has a refusal regression.
- B3: Session-proof load blocked opening a FIFO before its file-type refusal.
  Opens are nonblocking and validate the descriptor before locking. The related
  runtime-handle read also opens without waiting for FIFO peers. Real FIFO
  regressions bound load/append to two seconds and preserve the artifact.

Focused source regressions pass:79 tests,3 historical optional skips. The rebuilt
installed wheel passes52 successor tests with no skips, and its four affected
actual-native controls/lifecycle/refusal probes pass. Reproducible build and
unchanged fresh production dependencies are reused; no live state or inference
was accessed. Baseline broad evidence remains1407 source tests/57skips and572
installed package-job tests/6skips at the first reviewed head. Current-head CI
and limited independent correction verification remain required.

The reviewer also observed integer zero accepted as false in sandbox metadata.
No enabled network or wider writable roots were admitted in that probe. This
wire-type observation is nonblocking and is not an adoption or release gate.
Other instruction-display flags have no demonstrated separate failure.

The successor remains a documented candidate with refused adoption. Trusted
project precedence, approved neutral memory binding, deployed/physical lifecycle,
participant exchange and provider acceptance remain pending. No review or
fixture result authorizes a live rollout.

## Correction verification retained

Independent task `review_codex_0155` approved the B1/B2/B3 correction at
`199b062`; later owner reopening correction B4 was independently approved at
`9ea5662430676caccf83202eef21a6c2f3ee60da`. B4 verification repeated the original
signed advanced-tip scenario with installed modules and real private socket,
proof/handle journals and causal witnesses. Active, resuming and parking saved
handles reopened while missing/empty/torn/substituted proofs refused before
spawn and preserved journals. The reviewer independently passed52 installed
regressions. These approvals retain their original scope; they do not supply
live consent or attest later CI by themselves.

## Selected neutral skills: APPROVE

Independent reviewer: Codex task `review_162_origin_projection`.
Exact implementation head: `8f540d12930910dbed3e5636d13d7b496b0327a7`.
Delta parent: `de436a2606f0665c2501f527f8a192ea7a023b2d`.
Verdict: **APPROVE**, no blocking findings.

The reviewer checked the closed optional inventory, path/digest/overlap rules,
safe source intake, profile materialization and manifest binding, projected
file closure, shared neutral discovery renderer, effective native controls,
CLI and v2 schema/generator. Historical/no-option semantics and existing
bootstrap/capability/admission gates were preserved.

Independently verified wheel SHA-256
`08666d9e4c767ee8ea913992a68f0bbca032e73d46808fb7d58fb0d2b5142fea`
and installed changed-module/source parity. Installed56 focused tests passed
without skips. Additional source symlink/hardlink/group-write/executable drift
probes refused before profile creation; projected hardlink/mode drift and
file-directory collisions refused. An extra linked directory was rejected by
the existing whole-profile generated-state scan.

Actual installed supported profile and pinned0.155.1 in private user/network
namespaces loaded two synthetic nested roots, disabled one valid auxiliary
SKILL.md, passed effective configuration and post-native profile verification,
with0errors/exit0. No threads, model, tool or Matrix calls. A malformed auxiliary
fixture produced its expected parser diagnostic while declared roots remained
available; the valid auxiliary fixture passed without errors.

Approval covers this implementation delta, not live adoption, invocation fitness,
implicit-invocation enforcement, memory adoption, operational cross-host sync,
physical Cluster lifecycle or overall acceptance. Synthetic bootstrap verification
and an inert descriptor are not Matrix authority evidence. No live state changed.
