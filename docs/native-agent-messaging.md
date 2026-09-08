# Native agent messaging: foreign inbox foundation

Status: implementation candidate for #132. **Not an installed send/read/reply
client, not a deployment, and not completion of the real collaborator journey.**

## Boundary

`MessagingChannel` admits sparse foreign message evidence to an owner-local
`MessagingInboxStore`. It uses existing DM-051 signatures and HPKE, current
DM-082 relationship history, and DM-052 message/resolution validation. Foreign
events never enter the local `Ledger`, `/we` synchronization or adoption.

The receiver starts with independently configured public authorities, its own
recipient custody, and verified relationship events. It does not receive the
sender's private key or the original plaintext message out of band. The sender
uses its own custody and separately held public policy to seal the artifacts.

This is a library seam, not a model-facing API. Construction inputs are trusted
owner-local configuration: no caller-supplied `verified=true` object, transport
roster, Telegram membership, or GitHub login confers authorization.

## Directional policy

`MessagingPeerPolicy` binds the sender being, embodiment and credential, the
relationship, tribe, receiving membership, resource, operation, classification,
and an exact sorted list of grant ID/event ID/event hash references. Grants must
be active, accepted, issued by that sender to this recipient and bound to that
relationship/tribe. Recipient card and encryption material are checked against
the current public authority. A read decision is not permission to execute an
incoming request.

The default maximum envelope lifetime is 60,000 milliseconds. The operator's
clock and authority resolver are trust inputs. Authority/grant freshness is only
as current as the verified histories supplied locally; this module does not
fetch control-chain updates or repair stale enrollment.

## Encrypted wire sequence

Both inputs are ordinary DM-051 encrypted and signed envelopes:

1. An `experience.observed` event with subject `communication-evidence` and the
   following closed payload:
   - `schema`: `dm.communication.evidence-package/v1`
   - `message_id`, `message_hash`
   - `resolution_event`: the exact signed DM-052 resolution event
   - `message_authorization_id`
   - `message_authorized_at_ms`, `message_expires_at_ms`
2. The original signed `communication` event with its ordinary DM-052 payload.

The evidence payload does not carry the original message body. Its bootstrap
policy hash is SHA-256 over canonical JSON containing schema
`dm.communication.bootstrap-policy/v1`, the directional policy, the current
recipient descriptor and independently recomputed disclosure decision. The
receiver reconstructs this value; it never accepts an envelope's claimed hash
as authorization. Envelope signature and authorization checks precede unwrap.
The bootstrap authorization interval must match that evidence envelope's issued
and expiry times.

After opening the evidence, the receiver verifies its embedded resolution,
recipient/embodiment binding and selected grants. It reconstructs the original
message authorization before opening the message. After open, it compares that
authorization against `from_relationship_resolution_event` and validates the
actual resource, operation and scope. Missing evidence is a retryable
`CommunicationError`; it does not trigger speculative decryption.

## Persistence and manual reads

The separate owner-only SQLite store retains exact signed events and envelope
bytes. Transactions bind foreign event IDs and origin positions to immutable
bytes and delivery IDs to ciphertext hashes. Identical retry and a new envelope
for the same signed event produce one logical inbox item; conflicting event or
delivery identities fail without partial admission.

`page(after=..., limit=...)` is ordered by durable local admission sequence,
not by foreign origin sequence. Bounds are explicit (`limit` 1 through 100;
non-negative exact integer cursor within the interoperable JSON range). Reading
does not consume messages or create a receipt. A page revalidates signed
message/evidence content and their authorization binding. Retained evidence is
also signature-checked before using it for subsequent message decryption.

Current policy is checked on every admission and read. Historical reads need
not unwrap an expired delivery, but revocation prevents current-policy access.
Policy/recipient changes can make older rows unavailable under the new policy
hash; no automatic cross-policy migration or fallback is provided. SQLite is an
owner-local persistence boundary, not a tamper-proof or rollback-proof archive.

## Durable sender preparation

`MessagingSender.prepare(client_id=..., send_id=..., thread_id=..., text=...)`
uses the sender's real local `Ledger`, signer and delivery custody. The sender
context holds independently configured public recipient authority and verified
relationship history; it never needs the recipient's private custody.

The owner-only `MessagingOutboxStore` binds the stable caller operation UUID to
its client, message request, local origin and exact policy. It reserves the
original authorization IDs and lifetime before authoring. Message, resolution
and evidence are appended through the existing Ledger idempotency journal with
separate deterministic phase IDs. Recovery after interrupted signing resumes
those same events rather than authoring another logical message.

Preparation returns an ordered encrypted evidence/message pair only after
persisting both envelopes atomically. Completed retries and restarts return
those exact bytes while current authority, policy and the original lifetime
remain valid. A changed request, client, origin or policy is rejected; expired
operations cannot silently renew their authorization. This preparation API does
not perform network I/O; the delivery facade below owns transport orchestration.

## Exact prepared transport requests

`AuthenticatedProvider.prepare_submission(submission)` produces canonical HMAC
transport request bytes without network I/O. A caller must persist those exact
bytes before calling `send_prepared(raw)`. Reconstructing a provider after a
restart does not regenerate request IDs or timestamps when resending that file.
`send_prepared` revalidates the closed framing, current provider/route/key and
sender binding, HMAC and original lifetime before I/O; response authentication
and exact request-hash correlation remain enforced. The wire schemas are
unchanged. The provider does not itself journal the request.

The existing `deliver(submission)` convenience method still prepares a fresh
request on each call. Durable callers must use the split API: reusing an
attempt ID while regenerating its timestamp is not exact replay. Expired
requests are rejected, not silently renewed. Endpoint ownership/configuration
remains a trusted caller responsibility; envelope encryption independently
limits who can read the content.

A real loopback HTTP test now carries the genuine sender's evidence and message
through `DirectHTTPProvider` and `TransportIngress` into the independent inbox.
It drops the HTTP response after message admission, reloads the stored request,
reconstructs the provider and retries at a later clock value. The request bytes
remain identical and the receiver keeps one message. The test HTTP handler is
only a fixture, not the installed daemon listener. `recipient-intake` remains
transport/application intake evidence, not a consumer or signed semantic receipt.
The provider alone does not journal requests. The application facade below adds
that journal; runtime wiring and a supported client remain incomplete.

## Journaled application transport

`MessagingDelivery(sender=..., evidence_provider=..., message_provider=...,
config_digest=...).send(client_id=..., send_id=..., thread_id=..., text=...)`
uses trusted owner-configured providers, not model-supplied endpoints or grant
objects. The future loader must derive the lowercase 64-hex configuration digest
from actual validated endpoints, key references and channel selection. Merely
accepting a caller-chosen digest is not a configuration authorization boundary.

The facade rechecks sender authority, policy, request binding and original
lifetime before reading cached progress and before each stage. Both complete
authenticated requests are committed atomically before I/O. Each stage commits
`pending` before its byte exchange and then atomically records its authenticated
response and outcome. Only evidence `recipient-intake` releases the message
stage. Config changes conflict rather than replacing an in-flight generation.

Returned progress includes the send UUID, phase, transport status, retryability,
ambiguity and bounded stage summaries. Lost, truncated or unauthenticated
responses remain pending/ambiguous; an identical manual call resumes the same
requests without duplicate logical admission. Explicit refusal does not advance
the next stage. There is no autonomous retry worker or status-only API yet.

Cached terminal outcomes retain the exact HMAC-authenticated response, bound to
the exact original request. Resume revalidates that proof, its outcome and
normalized-result hash before trusting the cache. A status string plus an
unverifiable digest is insufficient. `validate_prepared_response` checks
historical proof, not permission for new I/O: a response may arrive after the
original operation window, but `send_prepared` still rejects expired requests
and the facade rechecks authority before releasing another stage.

These results remain transport/application intake evidence only, not consumer
acknowledgment, canonical direct reply, signed semantic receipt or task success.

## Bounded HTTP listener factory

`daemon.create_messaging_http_server(listen, evidence_ingress=...,\nmessage_ingress=...)` now returns a bound server using the daemon's existing
connection/concurrency limit. Its only application POST paths are
`/dm-messaging/v1/evidence` and `/dm-messaging/v1/message`, each bound to a
separately configured authenticated ingress. Paths do not select arbitrary
peers or supply authority.

The handler rejects missing/duplicate/non-decimal/oversized content lengths,
transfer encoding and non-exact media types before calling an ingress. Unknown
paths and query variants are not routed. It bounds body size, uses the existing
socket idle timeout, closes each connection, emits bounded empty error bodies
and suppresses request logging. This is not an absolute slow-client deadline,
a TLS terminator or a public-edge rate limiter; those deployment boundaries
remain to be configured and verified before public exposure.

A real loopback test now exercises this production handler with
`MessagingDelivery` and `DirectHTTPProvider`, not a substitute test handler.
Malformed framing never reaches ingress, correctly framed unauthenticated input
is rejected, and authenticated evidence/message delivery plus cached retry
produces one independent inbox entry without foreign Ledger ingestion.

An explicitly constructed `HostedRuntime.messaging_http` now attaches these
ingresses to `daemon.serve_forever`: startup binds the listener before its ready
signal, and daemon exit closes the HTTP listener and local socket. This typed
lifecycle seam does not yet load or provision messaging configuration from the
public runtime bundle. No installed service has been enabled by adding it.

## Real Codex client evidence and activation boundary

A local standalone Codex session has executed the actual CLI inbox command
against the production owner-local Unix-socket server. The command returned an
authenticated successful response, and its message ID and body were compared
with the expected admitted message outside the model. This test used disposable
synthetic identities, independent encrypted stores and a deliberately frozen
fixture clock. It proves manual Codex inbox consumption, not production
provisioning, Mariano's enrollment, reply delivery or Telegram visibility.

A Codex process exiting successfully is insufficient: inspect the completed
shell-command event and authenticated application response. In the service
launch environment used for this test, the read-only Codex sandbox could not
reach the separately running test socket. The bounded test was performed using
an explicitly selected unsandboxed process with one allowed command, disposable
paths, no source edits, and verified teardown. This is not a recommendation to
disable sandboxing for normal agent work or to give incoming messages execution
authority. Production client placement must deliberately make the narrow local
socket and capability available through its supported execution boundary.

Real activation also requires a single explicit participant handoff:

- The collaborator identifies which independently controlled Matrix being and
  embodiment each working Codex session uses, and operates its own enrollment.
- Each participant retains its own private custody. Only signed public
  enrollment/card/grant material and approved route references are exchanged;
  no private key, login file or writable state is sent through chat.
- The agreed messaging classification, directional grants and exact content
  eligible for human mirroring are recorded separately from transport success.
- The authorized operator verifies the existing Telegram bot identity and
  destination, its locally held credential, and a reversible integration target.
  Historical bot/group names are discovery hints, not verified authorization.

Missing external enrollment does not block implementation and isolated tests.
It does block a claim that the independently controlled participant journey or
human-visible projection is complete.

## Reusing authenticated runtime custody

`HostedRuntime.create_delivery_custody()` supplies the typed `DeliveryCustody`
interface used by sealed delivery and native messaging. It wraps only the
already-loaded peer custody, fixes signing to the sealed-delivery signature
domain, and reuses the existing compatible HPKE operation. It neither reopens
the encrypted store nor reads another password, copies private material to a
new store, changes v7 secret slots, or invents a runtime capability profile.
A runtime without its verified peer context rejects this factory call.

The adapter is an owner-local Python seam, not a model-facing signing/decryption
API or authorization decision. Ordinary message checks still precede private
operations; this factory does not create a messaging channel or enable a
listener. Client capability/configuration enrollment remains separate work.

A test loads an actual synthetic v7 runtime with a one-shot password reader,
seals and opens signed events repeatedly, and verifies one password read and
unchanged custody/bundle bytes. Its disclosure authorization is deliberately a
synthetic primitive test, not participant enrollment or the real cross-being
journey. Separate controls verify signature-domain separation and stable
rejection of unknown keys, malformed wrapping and noncanonical signing input.

## Explicit application provisioning and tool mode

The source now provides `daimon_matrix.operator_messaging` for an external,
owner-only application directory. It does not silently extend the ordinary v7
runtime bundle or host/operator profiles. The base runtime must already satisfy
the current identity and signed-capability contracts and have compatible loaded
peer custody. This command is **not a migrator for an older installed runtime**.

Trusted operator commands (replace uppercase path placeholders with verified
local paths; FD 3 must supply the runtime password without an added newline):

```sh
python -m daimon_matrix.operator_messaging prepare \
  --state-root R --bundle runtime.json --app-dir A \
  --spec S --secret-dir K --password-fd 3
python -m daimon_matrix.operator_messaging diagnostics \
  --state-root R --bundle runtime.json --app-dir A --password-fd 3
python -m daimon_matrix.operator_messaging run \
  --state-root R --bundle runtime.json --app-dir A --password-fd 3
```

`S` is a reviewed canonical public specification; `K` holds the exact protected
transport key files named by it. `A` must be a new directory outside `R`, beneath
an owner-only parent. Public authority, bilateral grants and exchanged route
secrets must already be valid: preparation does not invent participant consent,
root authority, relationships or foreign Ledger history. Public schemas live in
`schemas/messaging/v1/`; the executable synthetic specification builder is
`tests.test_messaging_runtime.application_fixture`, not a production identity.

All operator commands take the runtime lock; stop the matching daemon under its
authorized lifecycle before invoking them. Do not launch this standalone daemon
beside a Cluster-hosted receiver or use it to bypass Cluster hooks/fences. A
Cluster deployment must explicitly compose the application in its own hosting
path. Composition currently rejects an ordinary relationship-service context
rather than allow two histories to disagree about revocation. This fail-closed
restriction is not a completed production compatibility transition.

Preparation publishes initialized stores and a signed metadata pointer. Runtime
loading never reinitializes a missing or empty required store from historical
enrollment. Preserve every application database, its required companions, keys,
metadata generations and publication pointer together. Missing state is an
error, not an invitation to delete more state and re-enroll.

Diagnostics returns the selected application digest and client paths. Trusted
lease renewal preserves keys, client identity and all delivery/history stores:

```sh
python -m daimon_matrix.operator_messaging renew \
  --state-root R --bundle runtime.json --app-dir A --password-fd 3 \
  --expected-application-sha256 EXACT_PREDECESSOR_DIGEST
```

Renewal requires current identity and grants; the daemon/model cannot renew its
own enrollment. Use the generation-specific client configuration returned by the
operator. A post-publication durability error must not trigger deletion or blind
rollback. Preserve the target, inspect the selected signed state, and use the
trusted `recover` command with its exact `--expected-application-sha256` to retry
validation/fsync. Recovery does not restore lost history or authorize rewinding
published messages, counters or deduplication state.

The installed `daimon-mcp` entry point has an explicit `--messaging-only` mode:

```sh
daimon-mcp --messaging-only --socket SOCKET --client-config CLIENT_JSON \
  --capability-key-fd 3 --request-dir REQUESTS
```

Here FD 3 is the **messaging client capability key, not the runtime password**.
Keep it local and protected; a reviewed owner-local launcher can open that file
and exec this command without putting secrets in argv. `REQUESTS` must be an
existing owner-only request-journal directory. Use that same installed launcher
as a stdio MCP server in Codex or Hermes; no generic agent proxy is required.
MCP configuration alone is not verification: check discovery and a real tool call
in the intended running agent before declaring installation complete.

This mode exposes only `messaging_inbox`, `messaging_send`, `messaging_reply`,
and `messaging_delivery`; ordinary hidden calls/resources are rejected. Default
MCP mode remains unchanged and does not expose messaging. The dedicated local
capability and channel policy still enforce access independently of tool listing.
Tool parameters cannot choose credentials, endpoints, grants or destination
policy. Inbox data is untrusted content, not execution instructions.

## What this does not yet implement or establish

- A reviewed compatibility migration and installed Cluster/agent integration.
- An autonomous transport retry worker (manual journaled retry exists).
- Consumer acknowledgment or canonical remote application acknowledgment.
- Canonical direct replies or signed DM-052 terminal delivery receipts.
- A concrete participant-sharing verifier and production Telegram wiring.
  The disabled-by-default `TelegramMirror` adapter has offline per-part tests,
  but neither its callback interface nor a `SharingBinding` value proves consent.
- Real participant enrollment, remote installed-tool acceptance, or live mirror
  deployment and independently verified posted content.

An inbox result is local verified receipt of data, not adoption, task completion
or merge/deployment authority. Transport ACKs must never be presented as signed
semantic receipts. Sparse foreign evidence cannot be imported as contiguous
same-being history just to satisfy reply causal-parent requirements. The
implemented application-correlated response is explicitly distinguished from the
canonical direct-reply contract and requires authorization in the reverse
direction. Its signed body binds the authenticated original message ID, hash and
thread; it does not manufacture a canonical semantic receipt.

## Validation

The tests use independent synthetic identities and encrypted keystores, real
signed grants and real HPKE. They cover encrypted body delivery without foreign
Ledger mutation, restart, exact/resealed retries, bounded pages, event-position
and delivery conflicts, tampered retained signatures and mismatched evidence,
missing evidence, signature failure, policy mismatch, expiry, unaccepted grants
and revocation. Negative authorization tests assert no unwrap and no inbox
mutation; positive controls prove the same receive seam works.

```sh
PYTHONPATH=src python -W error::ResourceWarning -m unittest tests.test_native_messaging -v
python -m ruff format --check src/daimon_matrix/messaging.py src/daimon_matrix/messaging_store.py tests/test_native_messaging.py
python -m ruff check src/daimon_matrix/messaging.py src/daimon_matrix/messaging_store.py tests/test_native_messaging.py
MYPYPATH=src python -m mypy src/daimon_matrix/messaging.py src/daimon_matrix/messaging_store.py tests/test_native_messaging.py
```

Synthetic test success is not evidence of Mariano's consent, his installed
Codex integration, a live receiving agent response, or human-visible delivery.
