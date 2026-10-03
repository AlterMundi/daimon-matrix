# Independent review: explicit Cluster owner-reader transport

Reviewed implementation: `fc8ab5c4f869fa97e5f6e48d2b64ead823862a47` against
`74f9c0507ad6107e7c9a931e276394d13d8e7d55`. Reviewer:
`/root/review_162_origin_projection`, analysis-only independent security review.
Verdict: **APPROVE**; no substantive blocker in the bounded change.

The reviewer independently ran the eight native unittest methods with strict
ResourceWarning handling and additional real-socket probes. A socket inode
replacement after connection refused before any request byte was sent; writable
and alias ancestors refused; delayed header/payload input expired at0.201seconds
against one0.2second budget. Historical pinned-reader behavior and current signed
Matrix authority, origin, running-state, freshness and lifecycle-before-spawn
checks remain intact. Mixed/incomplete selectors and socket failures never fall
back to filesystem access or a daemon-health observation. The official Hermes
vector check passed. No live state, custody, inbox, peer or model was accessed.

Owner qualification:130 related source tests and130 installed-wheel tests passed
(four explicit opt-in/contract skips in each); official global static gates,
frozen87-module inventory, reproducible two-build packaging and secret scan
passed. Installed wheel SHA-256:
`9e37b49fd4ff768f512b29b4a974ca5e7f55bc313bb715d90970bf878b5e11ec`.
A separate-process qualification used this actual installed client and the
Cluster server with genuine non-editable Matrix95216a dependency: native snapshot,
wrong-origin/stopped-registration refusal, unchanged registry/fence rows and clean
SIGTERM/socket removal passed. The reviewer inspected that owner evidence without
claiming to have independently established a deployed result.

Both fixture processes use the current UID. Actual cross-UID deployment,
truthful physical registration/lifecycle, runtime adoption and the parent issue's
operational acceptance remain pending. This review authorizes code delivery only;
it grants no live installation, launch, memory adoption or capability change.
