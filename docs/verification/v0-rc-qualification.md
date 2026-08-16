# V0 release-candidate qualification receipt

Status: accepted baseline evidence plus local V7/V3-only candidate
qualification. Publication and cross-repository qualification remain separate.

## Subject

- Repository: `AlterMundi/daimon-matrix`
- Commit: `75b34804f8d013d348129946c0cd541a4448e71d`
- Tree: `38f3edb002ac52aac2d51fbf533cb58c38b813c5`
- Integrated merge: PR #119

## Recorded qualification

- Test result: 600 passed, 37 skipped.
- Parameterized evidence: 1,414 subtests.
- Supported CI interpreters: Python 3.11, 3.12, 3.13 and 3.14.
- Pre-version-bump wheel SHA-256:
  `df96015fe2bea750c97dc994cdfaccb96ef1d775cd4de315454b6edf540d1548`.
- Pre-version-bump sdist SHA-256:
  `ba89a1d77ac8f664fdac3be177d7778d004fb0045d65a44b62289176f4b9c879`.

Those two digests identify the historical pre-version-bump distributions and
must not be published as RC artifacts.

## V7/V3-only candidate qualification

- Version: `0.1.0rc1`.
- Operational runtime bundle: V7 only; V1 through V6 reject before authority
  or custody opens.
- Operational client config: V3 only; V1/V2 and retired-server response
  fallback reject closed.
- Source-isolated unittest result: 619 tests run, 22 intentionally skipped and
  zero test failures. Python 3.13 still emitted known temporary-directory
  cleanup diagnostics at interpreter shutdown; they did not alter the result
  and are not represented here as warning-free evidence.
- Ruff formatting/lint and strict mypy: pass for the release workflow surface.
- Current vector generators, offline lock validation and byte comparison: pass.
- Wheel SHA-256: `5ed4b034c0f5d7e74f2755562d5fa9d13776d5b4b9a44de2ac3f1ce05511f7ad`.
- Sdist SHA-256: `5e232f47d4477afb2018d97395fc1a9a8b01442f6fcb4441a7b0129dfa7a821b`.

The two artifacts were built twice offline with `SOURCE_DATE_EPOCH=946684800`;
each pair was byte-identical, passed the closed distribution allowlist and
passed the packaged-secret scan. Their exact source commit/tree is recorded in
the candidate handoff rather than embedded here, avoiding a self-referential
commit identifier.

## Scope

This receipt establishes local/CI software qualification for the exact Matrix
subject. It does not establish a current deployment, physical global fencing,
real independent holder custody, cross-being consent, publication or cutover.

Historical reviews and receipts remain unchanged and retain their original
subjects. `RESUME.md` and `CURRENT-STATE.md` classify their operational claims
as history rather than current state.
