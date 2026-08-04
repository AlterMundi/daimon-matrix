# DM-025 owner clients: CLI and MCP

Status: implemented against the DM-024 owner-local runtime. “Matrix” here means
`daimon-matrix`, never Matrix.org. Buzz, Telegram and Tribe are carrier or
adapter concerns and are not contacted by either client.

## One authority boundary

`daimon`, `daimon-mcp` and the reusable `LocalClient` are clients of
`daimon-matrixd`. They never open the ledger or keystore and cannot select an
embodiment, widen a capability, sign arbitrary material, invoke Cluster, or
route a Tribe message. Configuration names an exact owner-only Unix socket, an
owner-only public capability descriptor and the expected server origin. The
32-byte capability key is read once from an inherited descriptor and wiped
from the mutable input buffer.

Each call sends one bounded canonical DM-024 frame and verifies the response
HMAC, request ID/hash and server origin. For a durable retry, `daimon
--request-file PATH` creates a `0600` request token without replacement and
reuses its exact authenticated bytes. MCP write/sync tools accept an optional
`operation_id`; supplying the same UUID reuses the same owner-only token under
`--request-dir`. Omitting it creates a fresh operation. A token can be replayed
after the ordinary 30-second freshness window only if the daemon already has
its exact journal row and the capability remains active. A never-seen stale
request is rejected.

## CLI

The installed `daimon` families are exactly `daemon status`; `we heads`,
`diff`, `preview`, `observe`, `decide`, `projection-get` and
`projection-rebuild`; and `sync request`, `serve`, `pull` and
`validate-receipt`. Structured documents come from an explicit file or `-`
stdin. There is no inline generic RPC option.

DM-054 adds `scope me`, `we`, `diff`, `sync-plan`, `resolve` and `tribe`.
These read or freeze an exact plan; they cannot run peer fan-out, seal,
dispatch, adopt, mutate Cluster, or select an arbitrary method.

`--json` emits one canonical `dm.cli.result/v1` line. The response authentication
tag is verified internally and omitted from presentation. Human output carries
the method, outcome and RPC request ID. Exit 0 is success, 2 is local
usage/input rejection, 3 is local auth/config rejection, 4 is daemon transport
failure, 5 is an authenticated daemon refusal, and 6 is a response protocol
mismatch.

## MCP

`daimon-mcp` serves only final MCP `2026-07-28` newline-delimited JSON-RPC on
stdio. It uses official Python SDK `mcp==2.0.0`; the reviewed release/tag object
is `6f69a3758ebf2ee55ce050f58b470ce11af71133`. The spec tag object is
`5f5440bb26a62e2cf3440b92da5a667efa03b267`. The adapter invokes the SDK's
modern runner directly, so legacy `initialize` and missing/wrong modern
envelopes fail before daemon dispatch. Input is strict UTF-8 with duplicate-key
and 2 MiB line rejection. Stdout is reserved for MCP frames.

The twenty-four advertised tools map one-to-one to twelve DM-024 methods, six
DM-054 scope methods, two DM-030 memory methods, and four DM-031 curator
methods. Every
input schema is closed; no method name, path, SQL, shell command, URI fetch,
identity selector, capability or key is model-controlled. The eight fixed
`daimon:` resources expose public contract descriptors or capability-authorized
redacted status, scope, heads and projection results. Resource envelopes bind media
type, SHA-256, expected-origin provenance and canonical content; no `file:` URI
or local path is returned. Prompts, sampling, roots, elicitation,
subscriptions, templates and server-initiated requests are absent.

Schemas are in `schemas/clients/v1/`. Executable evidence is in
`tests/test_dm025_client.py` and `tests/test_dm025_cli_mcp.py`.
