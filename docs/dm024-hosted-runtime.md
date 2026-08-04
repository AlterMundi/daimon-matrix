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

The closed registry is `runtime.status`; `we.heads`, `we.preview`, `we.diff`;
`we.observe`, `we.decide`; `we.projection.get`, `we.projection.rebuild`; and the
four DM-023 sync operations. There is no generic signing, secret retrieval,
identity selection, TCP/HTTP, external effect, Tribe routing or live `/we`
fan-out method.

## Replay and crash semantics

Ledger schema V3 journals `(client_id, request_id, request_hash, method)` and the
first exact authenticated response. An exact completed retry returns identical
bytes. Reuse with different authenticated bytes records durable equivocation.
Observe/decide also atomically bind the request to the authored event, so a
crash after semantic commit cannot author twice. DM-023 sync journals retain
their own IDs, pages and receipts; transport IDs never substitute for them.

The daemon uses fixed worker and backlog bounds. SIGTERM/SIGINT stop accepting,
drain bounded work and unlink only the socket inode created by that process.
DM-026 extends the deterministic kill/restart and saturation matrix; it does not
change this protocol.

## Transport boundary

The absorbed Tribe runtime will authenticate a remote route and call the sync
methods with exact `(scheme, principal_id)` evidence. Matrix rechecks that
principal against DM-021 credentials. Telegram, Buzz or another carrier may be
added later as a versioned adapter if it can supply the same authenticated
transport evidence and preserve canonical payload bytes. No carrier becomes
event authority, adoption authority or the source of Weave cursors.

Schemas are in `schemas/hosted/v1/`; runnable verification is in
`tests/test_dm024_service.py` and `tests/test_dm024_runtime.py`.
