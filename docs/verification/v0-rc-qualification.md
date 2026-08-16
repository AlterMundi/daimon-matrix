# V0 release-candidate qualification receipt

Status: accepted qualification evidence for the merged Matrix code baseline;
artifact regeneration required after the release metadata change.

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

The test and review result applies to the merged code tree. The two artifact
digests identify distributions built before the package version was changed
from `0.0.0` to `0.1.0rc1`; they must not be published or cited as the hashes
of the RC metadata successor. Reproducible RC artifacts require two fresh
builds, byte comparison, distribution inspection, clean installation and new
recorded hashes after the planned removal or fixture-isolation of never-deployed
runtime-bundle V1–V6 and pre-V3 client compatibility.

## Scope

This receipt establishes local/CI software qualification for the exact Matrix
subject. It does not establish a current deployment, physical global fencing,
real independent holder custody, cross-being consent, publication or cutover.

Historical reviews and receipts remain unchanged and retain their original
subjects. `RESUME.md` and `CURRENT-STATE.md` classify their operational claims
as history rather than current state.
