# Project resume checkpoint

Status: the integrated V0 Matrix baseline is merged and release-candidate
qualification is active. No current deployment, host state, service state or
operator access is assumed by this checkpoint.

Last reconciled: 2026-08-18.

## Exact qualified boundaries

- Matrix functional merge: `09414d6edd9586f539be8272c4979d0b36c86b87`,
  tree `d7146e291ae3f8313dc0b3d3c3a0b5e5f94d33ad`, PR #121.
- Cluster functional merge: `820e3792a227b1848681a3421b113e8822c8d08a`,
  tree `4f62eb4f6eff1dfafbd477339a86fa7d5e70a5d8`, PR #93. It pins the
  exact Matrix functional merge.
- Tribe protected merge: `294e1194db6cd60d9349a2d43938475bbd1c8c20`,
  tree `bcba9989a38519df87ecbb6c87a33a2f9740b85d`, PR #65. Its reviewed
  head ran 148 tests with zero failures on Python 3.10 through 3.13; its
  post-merge `main` workflow is green.
- Matrix qualification: 640 tests run, including 22 declared skips, with zero
  failures; CI is green on Python 3.11 through 3.14. See
  [`docs/verification/v0-rc-qualification.md`](docs/verification/v0-rc-qualification.md).

The package version is `0.1.0rc1`. Two clean offline builds of the exact Matrix
functional merge were byte-identical: wheel SHA-256
`5896ae31813b7b9e1224ada14b7f9da9745790404c5a1eee9043079572f20089`
and sdist SHA-256
`f0ba76eb6650647a8b808f8648d04ef6d35806fcafd2f271d140c4fa5f9e96a1`.
The final integrated manifest must be regenerated after every documentation or
pin successor because the repository heads and source archives change.

## Current architecture

- `daimon-matrix` owns being-root continuity, canonical signed history,
  scopes, relationship/grant authority, communication semantics and the
  owner-local runtime.
- `daimon-cluster` owns body/incarnation lifecycle, storage and shared-resource
  admission/fencing. Lifecycle evidence cannot create Matrix social authority.
- `tribe-bridge` is transitional. Its transport acknowledgement is never a
  substitute for Matrix-authenticated intake or a semantic receipt.
- Multiple embodiments of one being are legitimate. Admission excludes two
  bodies using the same embodiment credential; it is not a being-wide
  singleton.

## Resume order

1. Merge this Matrix documentation successor and repin Cluster's exact Matrix
   dependency to the resulting commit without changing the reviewed functional
   boundary.
2. Reconcile Cluster and Tribe metadata to those protected merges, keeping
   executable dependency pins distinct from documentation-only repository heads.
3. Regenerate the content-addressed integrated manifest and repeat clean
   artifact installation from those exact heads. The latest pre-merge freezer
   proof is superseded and remains historical evidence only.
4. Close automated tracking only after the three default branches and final
   manifest agree. Keep the physical preflight prepared but unexecuted.

## Human and external gates

The remaining non-automatable gates are real distributed custody, selection of
non-production physical targets and an exact execution authorization,
cross-being participant consent and independent custody, publication/cutover,
and eventual Tribe retirement. A general project authorization does not imply
any of those decisions.

Historical operational reports and reviews remain evidence of the experiments
they describe. They are not a statement that the named infrastructure still
exists, is reachable or is running this software.
