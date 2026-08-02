# Dependency policy

The DM-020 package scaffold has **no runtime dependencies**. The empty
`project.dependencies` array in `pyproject.toml` is a tested release invariant.

Build and development tools are kept separate from runtime metadata:

- `requirements-build.txt` pins the PEP 517 frontend used by local and CI
  reproducibility checks. The build backend is pinned exactly in
  `build-system.requires` so both isolated builds resolve the same backend.
- `requirements-dev.txt` pins formatting, lint, and static-type tools and
  includes the build frontend.
- `requirements-vectors.txt` remains the bounded, offline verification input
  for the frozen DM-011 and DM-018 conformance corpora. It is not package
  runtime metadata.

Top-level build and development tools are exact pins. Their transitive
dependencies are isolated build inputs, never imported by `daimon_matrix`, and
must be refreshed through a reviewed dependency-only change with the complete
build, artifact inspection, wheel-install, and contract suites. Production
dependencies may be introduced only by the focused implementation card that
needs them, with a documented trust boundary and version policy.

CI uses no publication credential and grants read-only repository permission.
An untrusted pull request can build only synthetic/public content and cannot
publish artifacts as a release.
