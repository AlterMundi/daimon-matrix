# Issue 204: historical communication migration review

This change addresses immutable-history corruption in the previous legs migration.
Storage schema 4 keeps canonical per-body rows and validates historical locator
aliases, preserving signed receipt documents, attempt hashes, authenticated egress
requests, cached responses and conflict evidence. Existing healthy schema 3 remains
readable without implicit conversion. Repair of already damaged schema 3 is outside
this transition.

## Independent analysis

The independent native reviewer `review_legacy_leg_migration` reviewed the design,
implementation and corrections using real library functions and disposable signed
SQLite state. The initial IA Bridge attempt failed with a provider subscription
HTTP 403 and supplied no review; it is not counted as approval.

Two mandatory findings were corrected:

- Conflict evidence needed canonical-byte/hash validation and exact semantic
  association checks before migration and on read paths. Corrupt associations and
  evidence now refuse without changing the database or anchor.
- Every existing and presented target referenced by a delivery conflict, and every
  signed target of a terminal conflict, must remain quarantined. Historical lookup,
  fresh attempts and conflict reads refuse attempts to restore eligibility by
  changing only a referenced target's state.

The correction re-review identified communication source SHA-256
`d669d1523746183eac54d6ecc07409ded4d5f0352288fcd99e32dc51903cb51b`.
The reviewer independently passed 25 history/selector tests and verified positive
two-target conflict migration plus corruption refusals before and after migration.
Both mandatory findings were marked FIXED. This analysis is not final approval of
a qualified committed head or permission to alter a live runtime.

The review also confirmed exact cached cursor chains, accepted snapshots after
delivery and compaction, terminal pages and failed-attempt retries. Additional
committed regressions exercise cursor cutoff preservation, compaction, signed
foreign receipts and a real lost-response gated-route retry with unchanged native,
projection and Echo bindings and exactly one receiver intake.

## Qualification and limits

The finished source passes the relevant typed checks, Ruff and frozen inventories
and generated artifacts. Twenty history tests pass. The wheel and source archive
build reproducibly and the changed source, tests, documentation and distributions
pass the secret scanner. Full isolated unit qualification and installed-wheel
regressions are tracked separately until their terminal results are available;
current-head independent approval and successful CI are required before merge.

Alias validation establishes signed-target consistency and coverage of the current
stored cutoff. It does not provide independently immutable migration provenance
against coordinated owner-local rewrites of both cutoff metadata and alias rows.
The existing external anchor binds the generation and counter, not that cutoff.
No additional custody ceremony or unsupported cryptographic guarantee is claimed.

Issue 202 must adapt its separate operator rehearsal, backup and bounded recovery
to storage schema 4 and preserve the foreign-authority resolver. This library work
does not authorize deployment, memory migration or lifecycle changes.
