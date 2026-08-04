# DM-024 hosted Matrix runtime

Status: implemented contract for the Matrix-owned local service. “Matrix” in
this document means `daimon-matrix`, never Matrix.org.

`daimon-matrixd` hosts one concrete embodiment and one independent Weave ledger.
It is the application boundary consumed by the future absorbed Tribe adapter,
CLI and MCP surfaces. Cluster owns process placement and lifecycle only; it does
not interpret events, sync cursors, decisions or projections.

## Startup and custody

The daemon receives an explicit owner-only state root, public canonical
`dm.runtime.bundle/v1`, and an unlock password through an inherited descriptor.
The bundle binds the verified control chain, exact V2 manifest, credentials,
incarnations, optional activated provisional history, local origin, relative
ledger/socket filenames and capability descriptors. Unknown fields, forks,
unsafe paths, stale/revoked local authority and mismatched signer material fail
before the socket exists.

The encrypted DM-021 keystore must contain exactly one named
`runtime.signing.v1:*` slot and the declared `runtime.capability.v1:*` slots.
The signing seed must match the local credential. Root/recovery or undeclared
slots are rejected. Passwords and private bytes never enter argv, environment,
the bundle, logs, API documents or responses.

Startup order is: validate root, take `.daimon-matrixd.lock`, verify public
authority, unlock custody, migrate and integrity-check the ledger, remove only a
safe owner socket left behind under the held lock, bind `0600`, then emit the
canonical redacted `ready` diagnostic. A second writer fails immediately.

DM-079 adds `dm.runtime.bundle/v2` for an exact signed authority-epoch chain.
V2 preserves prior manifests so existing events remain verified under the
manifest hash they signed, while the fresh incarnation becomes the only active
local origin. The SQLite metadata advances only after every stored event
verifies and the complete update commits atomically. An accepted ledger cannot
be reopened with its prior V1 bundle. See `docs/dm079-authority-epochs.md`.

## Local protocol

The only release listener is an owner-local AF_UNIX stream socket. Linux peer
credentials must name the daemon UID. Each connection carries exactly one
`uint32_be length || canonical JSON` request and one response; the maximum
document is 2 MiB and the read/write deadline is five seconds.

Requests and responses are HMAC-SHA-256 authenticated with distinct domain
separators. Capabilities bind a client, exact method set and validity interval.
Authentication, expiry, peer UID and method scope are checked before params or
runtime membership are disclosed. Unauthenticated framing/auth failures close
without a response. Authenticated failures use stable bounded codes.

The original closed registry is `runtime.status`; `we.heads`, `we.preview`, `we.diff`;
`we.observe`, `we.decide`; `we.projection.get`, `we.projection.rebuild`; and the
four DM-023 sync operations. There is no generic signing, secret retrieval,
identity selection, TCP/HTTP, external effect, Tribe routing or live `/we`
fan-out method.

DM-052 extends the daemon registry with closed `communication.*` operations for
message/leg projection, attempts, delivery replay, route ACKs, terminal
receipts, pages, claims, cursor advancement, compaction and canonical rebuild
plans. These methods require an explicitly scoped adapter capability and remain
absent from the general CLI/MCP surface. They do not enable a carrier, generic
routing or live fan-out.

DM-053 adds the equally purpose-limited `route.inspect` and `route.submit`
methods. An absent route profile returns `route_profile_absent`; there is no
host-wide default. An enabled profile is public authority-free configuration
inside the runtime bundle, while provider endpoints live in a separate
owner-only custody document and HMAC route credentials live only in declared
`runtime.route.v1:*` keystore slots. The loader requires exact
profile/origin/provider/secret bindings before constructing a provider.
Neither method is added to the human CLI or MCP surface.

DM-054 adds safe `scope.me`, `scope.we`, `scope.we.diff`,
`scope.we.sync-plan`, `scope.resolve` and `scope.tribe` methods. Their authority
is the exact root manifest or an externally verified tribe snapshot; route
availability cannot alter membership. The runtime bundle has an explicit
nullable `scopes` section for sorted body capabilities and an owner-only tribe
snapshot file. A Cluster reader is injected and must return an exactly bound
`dm.cluster-body-snapshot/v1`; a relationship file is unusable without an
injected history verifier. Live fan-out and carrier dispatch remain outside the
general daemon surface.

## Replay and crash semantics

Ledger schema V3 journals `(client_id, request_id, request_hash, method)` and the
first exact authenticated response. An exact completed retry returns identical
bytes. Reuse with different authenticated bytes records durable equivocation.
An exact request already present in that journal may be retried after the
ordinary freshness window while its capability remains active; an old request
without the exact journal row is rejected before dispatch. This permits a
durable CLI/MCP retry token without making stale requests generally valid.
Observe/decide also atomically bind the request to the authored event, so a
crash after semantic commit cannot author twice. DM-023 sync journals retain
their own IDs, pages and receipts; transport IDs never substitute for them.

The daemon uses fixed worker and backlog bounds. SIGTERM/SIGINT stop accepting,
drain bounded work and unlink only the socket inode created by that process.
DM-026 extends the deterministic kill/restart and saturation matrix; it does not
change this protocol.

## Transport boundary

DM-053 providers authenticate exact `dm.transport-request/v1` bytes over local
Unix or direct/hub HTTP round trips. The sender body, transport principal,
opaque route reference, request lifetime and sealed-delivery digest are bound
by a purpose-specific route credential. Recipient intake reopens the DM-051
authority/cryptography gate before durable acceptance; hub acceptance does
not. Telegram, Buzz or another human gateway may be added later only behind
the disabled generic edge. No carrier becomes event, scope, adoption, receipt
or Weave-cursor authority.

Schemas are in `schemas/hosted/v1/` and `schemas/hosted/v2/`; runnable verification is in
`tests/test_dm024_service.py` and `tests/test_dm024_runtime.py`.
