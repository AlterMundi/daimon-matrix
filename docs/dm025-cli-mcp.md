# DM-025 owner clients: CLI and MCP

Status: implemented against the DM-024 owner-local runtime. “Matrix” here means
`daimon-matrix`, never Matrix.org. Buzz, Telegram and Tribe are carrier or
adapter concerns and are not contacted by either client.

## One authority boundary

`daimon`, `daimon-mcp` and the reusable `LocalClient` are clients of
`daimon-matrixd`. They never open the ledger or keystore and cannot select an
embodiment, widen a capability, sign arbitrary material, invoke Cluster, or
route a Tribe message. Configuration is closed `dm.local.client-config/v3` and
names an exact owner-only Unix socket, an owner-only public capability
descriptor, the expected server origin, runtime ID and runtime label. V1 and
V2 configs were never deployed and are rejected before capability material is
read. The
32-byte capability key is read once from an inherited descriptor and wiped
from the mutable input buffer.

Each call sends one bounded canonical DM-024 frame and verifies the response
HMAC, request ID/hash, server origin and exact V3 runtime ID/label. Config fields
that are merely well formed but do not match the serving runtime therefore fail
closed on the authenticated response. For a durable retry, `daimon
--request-file PATH` creates a `0600` request token without replacement and
reuses its exact authenticated bytes. MCP write/sync tools accept an optional
`operation_id`; supplying the same UUID reuses the same owner-only token under
`--request-dir`. Omitting it creates a fresh operation. A token can be replayed
after the ordinary 30-second freshness window only if the daemon already has
its exact journal row and the capability remains active. A never-seen stale
request is rejected.

After an incarnation succession, clients accept only the exact current server
origin bound in V3. The never-deployed historical-origin response fallback was
removed; an old daemon response fails closed and the caller must issue a fresh
request to the current incarnation.

The capability method allowlist is bounded at 128 entries. The current fixed
service surface has 84 methods after DM-082, so one least-privilege operator
capability may name the complete surface without truncation; exact-bound and
plus-one tests keep the widened bound finite.

## CLI

The installed `daimon` families are exactly `daemon status`; `we heads`,
`diff`, `preview`, `observe`, `decide`, `projection-get` and
`projection-rebuild`; and `sync request`, `serve`, `pull` and
`validate-receipt`. Structured documents come from an explicit file or `-`
stdin. There is no inline generic RPC option.

DM-054 adds `scope me`, `we`, `diff`, `sync-plan`, `resolve` and `tribe`.
These read or freeze an exact plan; they cannot run peer fan-out, seal,
dispatch, adopt, mutate Cluster, or select an arbitrary method.

DM-081 adds `source content-put`, `claim`, `assess`, `publication-append`,
`import-decide`, `status`, `cursor-create`, `diff`, `incoming`, `pull`,
`promote` and `projection`. These are fixed typed calls to the owner daemon;
none accepts an arbitrary method, locator, shell command, identity override or
database path. `pull` requires an operation UUID and never promotes.

DM-082 adds fixed `relationship` and `tribe` families for signed card,
handshake, membership, founder, grant, cursor, status, snapshot, ingest and
disclosure operations. They cannot fabricate a foreign signature, select a
database, turn membership into a grant or reveal an unauthorized denial reason.

`--json` emits one canonical `dm.cli.result/v1` line. The response authentication
tag is verified internally and omitted from presentation. Human output carries
the method, outcome and RPC request ID. Exit 0 is success, 2 is local
usage/input rejection, 3 is local auth/config rejection, 4 is daemon transport
failure, 5 is an authenticated daemon refusal, and 6 is a response protocol
mismatch.

## MCP

`daimon-mcp` serves final MCP `2026-07-28` per-request envelopes and the exact
Codex-compatible `2025-06-18` initialize-handshake protocol over
newline-delimited JSON-RPC on stdio. Other legacy handshake versions are
rejected before daemon dispatch. It uses official Python SDK `mcp==2.0.0`; the reviewed release/tag object
is `6f69a3758ebf2ee55ce050f58b470ce11af71133`. The spec tag object is
`5f5440bb26a62e2cf3440b92da5a667efa03b267`. The adapter invokes the SDK's
dual-era runner behind an exact opening-frame gate, so a connection cannot
switch eras and missing/wrong modern envelopes fail before daemon dispatch.
Input is strict UTF-8 with duplicate-key and 2 MiB line rejection. Stdout is
reserved for MCP frames.

The 67 advertised tools are frozen by `TOOL_CONTRACTS` and their schema/vector
tests. Every
input schema is closed; no method name, path, SQL, shell command, URI fetch,
identity selector, capability or key is model-controlled. The eight fixed
`daimon:` resources expose public contract descriptors or capability-authorized
redacted status, scope, heads and projection results. Resource envelopes bind media
type, SHA-256, expected-origin provenance and canonical content; no `file:` URI
or local path is returned. Prompts, sampling, roots, elicitation,
subscriptions, templates and server-initiated requests are absent.

The client protocol family remains in `schemas/clients/v1/`, while
`client.schema.json` accepts only config V3. Executable evidence is in
`tests/test_dm025_client.py` and `tests/test_dm025_cli_mcp.py`.
