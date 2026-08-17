# V0 release-candidate qualification receipt

Status: accepted V7/V3-only functional qualification. The final integrated
manifest remains pending the protected Tribe merge and exact-head repins.

## Subject

- Repository: `AlterMundi/daimon-matrix`
- Commit: `09414d6edd9586f539be8272c4979d0b36c86b87`
- Tree: `d7146e291ae3f8313dc0b3d3c3a0b5e5f94d33ad`
- Integrated merge: PR #121

## Recorded qualification

- Test result: 640 passed, 22 declared skips.
- Supported CI interpreters: Python 3.11, 3.12, 3.13 and 3.14.
- Wheel SHA-256:
  `5896ae31813b7b9e1224ada14b7f9da9745790404c5a1eee9043079572f20089`.
- Sdist SHA-256:
  `f0ba76eb6650647a8b808f8648d04ef6d35806fcafd2f271d140c4fa5f9e96a1`.

## V7/V3-only candidate qualification

- Version: `0.1.0rc1`.
- Operational runtime bundle: V7 only; V1 through V6 reject before authority
  or custody opens.
- Operational client config: V3 only; V1/V2 and retired-server response
  fallback reject closed.
- Source-isolated unittest result: 640 tests run, 22 declared skips and zero
  failures.
- Ruff formatting/lint and strict mypy: pass for the release workflow surface.
- Current vector generators, offline lock validation and byte comparison: pass.
- Wheel SHA-256: `5896ae31813b7b9e1224ada14b7f9da9745790404c5a1eee9043079572f20089`.
- Sdist SHA-256: `f0ba76eb6650647a8b808f8648d04ef6d35806fcafd2f271d140c4fa5f9e96a1`.

The artifacts were built twice offline with `SOURCE_DATE_EPOCH=946684800`;
each pair was byte-identical, passed the closed distribution allowlist and
passed the packaged-secret scan. Any later documentation/pin successor changes
the repository source archive and must produce a new integrated manifest.

## Cross-repository checkpoint

- Cluster merge: `820e3792a227b1848681a3421b113e8822c8d08a`, tree
  `4f62eb4f6eff1dfafbd477339a86fa7d5e70a5d8`.
- Tribe reviewed candidate: `42d637245864fcd431198a570d19d7a6dd042924`,
  tree `5145f6446f3ec3013347509477a262f98825ebfa`; normal protected merge
  still requires one fresh independent GitHub approval.
- Provisional three-repository freezer proof: SHA-256
  `d3ac479d4ff581e0f1dfb82a1a41f15d25ad3e45eb03723065e865d037cc8fd5`.
  It is deliberately not the final manifest because Tribe is not yet merged.

## Scope

This receipt establishes local/CI software qualification for the exact Matrix
subject. It does not establish a current deployment, physical global fencing,
real independent holder custody, cross-being consent, publication or cutover.

Historical reviews and receipts remain unchanged and retain their original
subjects. `RESUME.md` and `CURRENT-STATE.md` classify their operational claims
as history rather than current state.
