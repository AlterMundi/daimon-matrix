# Project resume checkpoint

Status: the integrated V0 Matrix baseline is merged and release-candidate
qualification is active. No current deployment, host state, service state or
operator access is assumed by this checkpoint.

Last reconciled: 2026-08-16.

## Exact Matrix baseline

- Commit: `75b34804f8d013d348129946c0cd541a4448e71d`
- Tree: `38f3edb002ac52aac2d51fbf533cb58c38b813c5`
- Merge: PR #119, which includes the distributed-custody and least-authority
  host-capability work through `c773029`.
- Qualification: 600 passed, 37 skipped, 1,414 parameterized subtests; CI was
  green on Python 3.11 through 3.14. See
  [`docs/verification/v0-rc-qualification.md`](docs/verification/v0-rc-qualification.md).

The package version is now `0.1.0rc1`. Artifact hashes recorded for the merged
pre-version-bump tree are historical qualification evidence, not hashes for
this RC metadata successor. Rebuild and record the final hashes before freezing
or publishing the candidate.

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

1. Regenerate and independently qualify reproducible `0.1.0rc1` artifacts; the
   operational surface is now runtime-bundle V7 and client-config V3 only.
2. Pin the exact Matrix, Cluster and Tribe candidate commits and dependency
   hashes in their release manifests.
3. Run clean-install and disposable end-to-end backup, restore,
   recovery/rebirth, rollback and double-launch rejection suites.
4. Reconcile cross-repository documentation and tracking to those exact heads.
5. Prepare a content-addressed physical preflight, but do not execute it.

## Human and external gates

The remaining non-automatable gates are real distributed custody, selection of
non-production physical targets and an exact execution authorization,
cross-being participant consent and independent custody, publication/cutover,
and eventual Tribe retirement. A general project authorization does not imply
any of those decisions.

Historical operational reports and reviews remain evidence of the experiments
they describe. They are not a statement that the named infrastructure still
exists, is reachable or is running this software.
