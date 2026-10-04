# Issue 205 — explicit native turn and retained-history recovery

Independent reviewer: separate Codex review task.
Initial candidate: `d96315a181f2984d1be82730ca7b50d33eb1b0ac`.
Correction reviewed: `ffdfb76640c9c6988235f39c922507099b3ca459`.
Verdict: **APPROVE** corrected runtime; initial R1 **FIXED**.

## Outcome and scope

One explicitly selected text input now reserves a private digest-only intent and
pending handle before native dispatch, retains a correlated terminal result before
restoring active, and refuses blind retries after uncertainty. Explicit recovery
reads the saved native thread/latest turn and checks acknowledgement or baseline
adjacency plus the original input hash; it submits no replacement input. Native
history/private results supply recovery data, never Matrix authority or canonical
memory. Historical profiles and strict Matrix signing codecs remain unchanged.

The independent review inspected production transport, descriptor validation,
intent/handle/result persistence, vendor JSON, notification correlation, bounded
history recovery and the CLI. It used actual controller functions, real subprocess
pipes and private synthetic profiles. It did not access live bodies, credentials,
inboxes or external providers.

## Finding and resolution

R1: current presence could cease to be valid during intent/journal or result fsync.
The initial controller nevertheless dispatched input or returned active using the
pre-write proof. Both transitions were reproduced independently.

The correction refreshes current presence after pending persistence immediately
before dispatch and after terminal-result persistence before active. Rechecking
the original probes showed refusal before any input in the first case and one
accepted input with the committed result/turning handle preserved in the second.
Errors suppress automatic retry, and restored presence does not enable ordinary
resume or duplicate submission. Two regressions cover the real write boundaries.
The limited correction review passed five affected success/recovery/refusal tests;
it reused unaffected initial evidence rather than repeating the unrelated stack.

## Validation and limits

- 126 selected source and 126 installed-wheel tests pass, with four explicit
  optional contract skips in each environment. ResourceWarning is an error.
- Exact pinned Codex 0.155.1, private signed Matrix fixture and the corrected
  installed adapter: interrupted input survives process reopening and explicit
  retained-history recovery, reporting zero submitted recovery inputs and native
  exit zero. The fixture daemon terminates. No actual provider credential or
  successful external model inference was used or qualified.
- Reproducible wheel/sdist builds pass; all 87 packaged Python modules match the
  source bytes. Installed dependencies pass pip check. Changed-file ruff/mypy,
  frozen inventories/generated artifacts and source/package secret scans pass.
- The broad source runner began before the narrow R1 correction; its results are
  separate regression evidence, not exact final-head proof. Current-head CI remains
  a delivery gate.

Provider authentication/completed inference, deployed target cold resume,
operational native retention, memory adoption and participation acceptance remain
separate requirements. This review authorizes no live action and does not close
operational acceptance or the overall CompAII goal.
