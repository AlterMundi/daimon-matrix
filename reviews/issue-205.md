# Issue 205 independent security and persistence review

Independent reviewer: Codex task `review_codex_0155`.
First reviewed head: `5a23c4ea8f0ce206070857e7d99d2c38330c8be4`.
First verdict: **REQUEST_CHANGES**. Correction verification is pending.

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
