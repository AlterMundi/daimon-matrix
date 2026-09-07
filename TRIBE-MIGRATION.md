# Tribe Bridge retirement and native communication

## Current decision

Tribe Bridge is a superseded experimental transport, not a stable Matrix
runtime or release dependency. This policy reconciles the owner decision in
[Bridge #71](https://github.com/nicoechaniz/tribe-bridge/issues/71), incorporated
by [Bridge #72](https://github.com/nicoechaniz/tribe-bridge/pull/72), and the
active dependency removal in
[Cluster #103](https://github.com/nicoechaniz/daimon-cluster/pull/103).
The [Cluster retirement boundary](https://github.com/nicoechaniz/daimon-cluster/blob/main/docs/tribe-bridge-retirement.md)
defines its corresponding source-level changes.

These merged source changes do not establish live service removal, a current
deployment, completed native cutover or stable publication. Historical RC
records remain evidence of their exact original subjects, not current
operational instructions. This successor policy supersedes older requirements
to preserve, provision or rotate Bridge for a stable Matrix release.

## No operational migration

All Bridge operational state is disposable: messages, queues, directories,
identities, keys, databases, profiles, routes, timers and configuration.
Nothing is migrated to Matrix. There is no compatibility, downgrade, fallback
or dual-run phase. Do not onboard new participants to Bridge to prepare native
Matrix communication, or renew Bridge custody merely to satisfy an old RC gate.

Disposable does not mean deletion is already authorized. Live removal requires
its own reviewed exact inventory and human GO. Public Git provenance remains
preserved without history rewrite, including the DM-050 hash-pinned behavioral
inventory. Keep Matrix signing, recipient-encryption, relationship and
transport credentials purpose-separated; do not copy Bridge credentials or
writable stores into successor embodiments.

## Native Matrix communication survives

Native Matrix `/tribe`, bilateral relationships and directional grants are not
the retired Bridge product. Their authority comes only from verified signed
Matrix history. A Bridge directory, transport ACK, GitHub account or Cluster
lifecycle fact cannot create that authority.

The native paths have distinct purposes:

- DM-055 carries same-being scope/sync documents in `dm.peer-envelope/v1`.
- DM-051/052/053 provide sealed logical messages, per-recipient semantic legs,
  routing, authenticated intake and independently signed semantic receipts.
- DM-082 produces the relationship/grant history consumed by DM-054 scope
  resolution and the logical-message path.

Stable logical IDs, ordered cursors, exact retry, direct/hub deduplication and
fail-closed authentication, expiration and revocation remain native acceptance
requirements. A transport ACK is not a signed semantic delivery receipt;
receipt of a message is not permission to execute its requested action.

Local and isolated implementation evidence is not an operational relationship
with an external participant. [DM-071 (#40)](https://github.com/AlterMundi/daimon-matrix/issues/40)
retains separate participant consent, independent custody and bounded real
cross-being delivery/source-exchange requirements. Neither a general
collaboration invitation nor this policy completes that gate.

## Human-facing edges and issue/PR notifications

[DM-053](docs/dm053-route-providers.md) defines a disabled generic gateway edge.
Telegram and Buzz are possible future implementations, not shipped native
notification connectors. External gateway input is `external-source-only`;
it cannot manufacture a Daimon origin, relationship, semantic receipt or
execution authorization.

An issue/PR notification is a concrete integration use case, not a claim of
existing end-to-end automation. GitHub remains the canonical work record;
agent-directed notification requires an explicitly configured, authorized
recipient route and tested intake. Any human-facing mirror is optional and
separately authorized; it must not expose private content or become the
identity/membership authority.

## Historical RC evidence and stable successor

The historical `0.1.0rc1` manifests, qualification records and freezer tools
bind Matrix, Cluster and Bridge. Retain their exact hashes, artifacts and
observations; do not relabel them as two-component stable evidence.

The stable successor is Matrix plus Cluster and must demonstrate native birth
and continuity with Bridge absent. It needs its own exact artifact manifest
and replayed qualification. Existing three-component freezer contracts,
including the [cross-being preflight](docs/runbooks/cross-being-canary-preflight.md),
are historical RC tooling. This documentation does not change their schemas
or implement two-component acceptance. Route any necessary freezer/schema and
qualification changes through the release work tracked by
[DM-076 (#72)](https://github.com/AlterMundi/daimon-matrix/issues/72) and
[DM-075 (#44)](https://github.com/AlterMundi/daimon-matrix/issues/44), with normal
implementation review and tests before using them for stable publication.

## Independent remaining authorizations

Native software evidence does not substitute for any of these decisions:

- exact operational execution plans, independent real custody and participant
  consent, including the separate DM-071 cross-being gate;
- stable publication/cutover after native continuity with Bridge absent;
- stopping/disabling Bridge and deleting its exact disposable operational
  state under a reviewed removal inventory and matching human GO;
- a final source-only Bridge release and public repository archival, each
  under its own owner-approved plan, tracked by
  [DM-077 (#73)](https://github.com/AlterMundi/daimon-matrix/issues/73).

Final removal, source-only release and archive follow demonstrated native
continuity and stable V0.1.0. Do not silently disable, re-key, delete or archive
Bridge. No Matrix ledger, custody, message receipt or sync high-water is
rewritten as a retirement or rollback shortcut.
