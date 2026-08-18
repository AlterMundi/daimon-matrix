# V0 release-candidate qualification receipt

Status: accepted historical V7/V3-only Matrix qualification. Matrix, Cluster
and Tribe functional successors are merged. This Matrix-local receipt does not
assert whether a later external integrated manifest has completed its
exact-head and artifact requalification.

## Subject

- Repository: `AlterMundi/daimon-matrix`
- Commit: `09414d6edd9586f539be8272c4979d0b36c86b87`
- Tree: `d7146e291ae3f8313dc0b3d3c3a0b5e5f94d33ad`
- Integrated merge: PR #121

## Recorded qualification

- Test result: 640 tests run, including 22 declared skips, zero failures.
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
- Recorded vector generators, offline lock validation and byte comparison: pass.
- Wheel SHA-256: `5896ae31813b7b9e1224ada14b7f9da9745790404c5a1eee9043079572f20089`.
- Sdist SHA-256: `f0ba76eb6650647a8b808f8648d04ef6d35806fcafd2f271d140c4fa5f9e96a1`.

The artifacts were built twice offline with `SOURCE_DATE_EPOCH=946684800`;
each pair was byte-identical, passed the closed distribution allowlist and
passed the packaged-secret scan. Any later documentation/pin successor changes
the repository source archive and must produce a new integrated manifest.

## Merged Hermes reachability closeout

The merged Matrix closeout predecessor
`7266de8551ae861f3773c587bf907cfcddde6ffd`, tree
`d1ff7a6fc6b1351f67fd13171dcee51242fc9804`, carries the Hermes reachability
repair. The Hermes 0.19.0 compatibility bytes remain tree
`ac7dec02ca029e895963402788bd1cdc3afb36f8`. During closeout qualification the
former merge commit was not advertised by the source remote. The merged
closeout therefore pins public PR head
`5c8870c1625761956a56fd2b225720dbe9083e45`, selected and verified during that
qualification; its tree and every audited contract digest are identical. The
replacement unprefixed git archive is SHA-256
`09789981423142fec1a26239d5209f96c41453078ff73e2fc4a11e1d45728660`.

The repinned source produced two byte-identical isolated builds with
`SOURCE_DATE_EPOCH=946684800`:

- Wheel SHA-256: `11ef77b2b4c743cfa25d6652e9cad3594e41223cb73f558d5ead8f47bd43609d`.
- Sdist SHA-256: `b23d66004039dc9d454c1bf4382b87a381c538fe8194a3c262440425ffa6de69`.

These hashes supersede the functional-merge package hashes for that merged
Matrix closeout. Any integrated manifest must bind the actual selected
default-branch commit and exact copied artifacts rather than infer them from
this historical receipt.

## Cross-repository checkpoint

- Cluster merge: `820e3792a227b1848681a3421b113e8822c8d08a`, tree
  `4f62eb4f6eff1dfafbd477339a86fa7d5e70a5d8`.
- Tribe protected merge: `294e1194db6cd60d9349a2d43938475bbd1c8c20`,
  tree `bcba9989a38519df87ecbb6c87a33a2f9740b85d`; exact reviewed head
  `e81c5da0b96d0ac29f7a3bdeacb1f0e7c860ec3c` has the same tree and ran
  148 tests with zero failures on Python 3.10 through 3.13.
- Provisional three-repository freezer proof: SHA-256
  `d3ac479d4ff581e0f1dfb82a1a41f15d25ad3e45eb03723065e865d037cc8fd5`.
  Its exact subject was Matrix `09414d6`, Cluster `820e379` and Tribe
  `42d637245864fcd431198a570d19d7a6dd042924` (tree `5145f6446f3ec3013347509477a262f98825ebfa`).
  It is superseded historical method evidence because it does not bind the
  Tribe merge or any later documentation/pin successors.

## Scope

This receipt establishes local/CI software qualification for the exact Matrix
subject. It does not establish a current deployment, physical global fencing,
real independent holder custody, cross-being consent, publication or cutover.

Historical reviews and receipts remain unchanged and retain their original
subjects. `RESUME.md` and `CURRENT-STATE.md` classify their operational claims
as history rather than current state.
