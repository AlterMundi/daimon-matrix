# Dependency policy

The runtime dependency boundary is explicit and tested in distribution
metadata:

- `cryptography>=46.0.7,<47` supplies Ed25519/X25519 and encrypted custody
  primitives (Apache-2.0 OR BSD-3-Clause).
- Official `mcp==2.0.0` supplies final MCP `2026-07-28` models, stdio and server
  dispatch (MIT). It pins `mcp-types==2.0.0`; the adapter exposes none of the
  SDK's HTTP, OAuth, application, prompt, sampling, elicitation or subscription
  surfaces.

The MCP version is an exact reviewed production pin. An upgrade requires a
focused protocol/dependency review, modern positive and legacy negative
fixtures, the installed-process suite and reproducible artifact verification.

Build and development tools are kept separate from runtime metadata:

- `requirements-build.txt` pins the PEP 517 frontend used by local and CI
  reproducibility checks. The build backend is pinned exactly in
  `build-system.requires` so both isolated builds resolve the same backend.
- `requirements-dev.txt` pins formatting, lint, static-type tools and the exact
  MCP test/runtime version, and includes the build frontend.
- `requirements-vectors.txt` remains the bounded, offline verification input
  for the frozen DM-011 and DM-018 conformance corpora. It is not package
  runtime metadata.

Top-level build and development tools are exact pins. They must be refreshed
through a focused dependency change with the complete build, artifact
inspection, wheel-install, and contract suites. Production dependencies may be
introduced only by the implementation card that needs them, with a documented
trust boundary and version policy.

CI uses no publication credential and grants read-only repository permission.
An untrusted pull request can build only synthetic/public content and cannot
publish artifacts as a release.
