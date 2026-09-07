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
operations cannot silently renew their authorization. This is preparation only:
there is no network worker, persistent transport-request replay or delivery
inspection in this slice.

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
The application still needs journaled network-stage orchestration and runtime
wiring; the preparation outbox alone does not provide them.

## What this does not yet implement

- Supported daemon provisioning, transport listener integration or client
  capability enrollment for this application.
- Ordinary Codex CLI/MCP send, manual inbox read or response commands.
- A transport retry worker (the durable encrypted preparation outbox exists).
- Consumer acknowledgment or remote application acknowledgment.
- Canonical direct replies or signed DM-052 terminal delivery receipts.
- Telegram projection, participant visibility consent, bot credential custody,
  or a live mirror deployment.

An inbox result is local verified receipt of data, not adoption, task completion
or merge/deployment authority. Transport ACKs must never be presented as signed
semantic receipts. Sparse foreign evidence cannot be imported as contiguous
same-being history just to satisfy reply causal-parent requirements. A future
application-correlated response must be explicitly distinguished from the
canonical direct-reply contract and authorized in the reverse direction.

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
