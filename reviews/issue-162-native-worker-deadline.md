# Full-pool native worker deadline

Independent review: **APPROVE** `a02fb998c691b9465b935b154477759060547ba9`.
Reviewer: independent Codex review session `review_162_origin_projection`.

The actual dual-host return exceeded the 300-second worker deadline after 212 of
230 durable receipts. Both pools were recovered and original services restored;
accepted Matrix history was preserved. The product change increases only the
bounded native worker deadline to 900 seconds. Authority validation, official
runtime lock, isolated installed interpreter, stripped environment, exact plans,
checkpoint semantics and retained-plan recovery remain unchanged.

The official Hermes generator check passed independently. Relevant qualification
passed 35 tests with one optional native-Hermes-source skip; Ruff, format, frozen
87-module/generated invariants, mypy and changed-file secret scans passed.

Deployment must also let the outer operator/SSH deadline exceed the worker plus
cleanup. This review does not establish successful live reconciliation or native
body acceptance.
