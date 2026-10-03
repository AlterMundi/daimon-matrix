# Issue 162: origin-preserving cross-host projection increment

Independent reviewer: Codex analysis-only peer review, synthetic fixtures only.
Implementation reviewed: `98929ca9e403849f87c7c9fad152977d40f878c6`.
Corrected implementation: `ae8dc7c2ad1d27bf4e949b0cacfcdb2e31b49d2b`.
Final verdict: **APPROVE** for this implementation increment.

The original review verified origin selection, sibling corrections/retractions,
namespace substitution, stale complete-checkpoint refusal and retry/recovery.
It requested one correction, R1: HMK active-only rebuild deletes inactive rows,
but Matrix required those rows after commit and refused the valid rebuilt view.
The same assertion→retraction→rebuild failed against unmodified main; this was an
inherited operational gap exposed by the cross-host later-head path.

R1 is FIXED. Active heads remain required; absent retracted derived rows are
valid after rebuild. Any inactive row still present must match its current
signed head, statement, category, author and namespace. Exact checkpoint and
active-manifest binding remain mandatory. Independent probes against real HMK
responses reject missing active, duplicate, reordered, extra, resurrected and
substituted inactive-head rows. The original retraction/rebuild and pending /
completed retry scenarios pass on the corrected implementation.

Validation: 35 DM-034/DM-023 source tests and 35 installed-wheel tests pass,
without skips. Independent review separately reran those 35 tests and the
probes above. Hermes coupling: 26 pass, one optional native-binary test skipped.
Ruff, mypy, generated/frozen inventories, secret scan and two reproducible builds
pass. The installed projector's digest equals source. Existing qualified test
dependencies were reused; no fresh dependency installation is claimed.

Live cross-host peer exchange, content transfer/adoption, reconciliation of
unsigned legacy memories and skills, deployment approval and operational
acceptance remain pending. This review does not close those requirements or
approve a live action. No identity, custody, capability or existing pool changed.
