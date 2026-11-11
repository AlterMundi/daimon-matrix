# Portable human visibility — implementation under #496

The four children are signed members with full portable Conversation publication
and selected native group readers. All seven readers were authenticated after
publication. A real ordinary request to each child produced an automatic native
execution and a signed reply received on ITACA, preserving original parents and
threads. The first technical probe and its initial refusal/deferral remain
historical evidence; they are not the current service state. No Telegram account
or Tribu viewing was required.

The actual App composition includes current image819/HUD820 plus the heartbeat
recovery correction, and the complete compatible Codex0.167 package. Configuration
is not selection: loaded executable paths and digests were verified after
resolving higher-priority unit overrides. Global/lane pause controls remain;
children select Messaging only. The seven-body chat skill and current child
context now distinguish ordinary peer conversation from private child records
or instructions to change services.

Native technical-cache retirement is implemented and selected on all four
children, as described below. This receiving journey does not claim complete
foundation or indefinite service acceptance. The single current coverage map is the existing #437 checkpoint.

## Implemented journal primitive

`mandatory_echo` accepts an additional `daimon-visibility-policy/v3` for the
existing bounded obligation journal. Its common owner fields remain generation,
origin, acceptance digest and proof-key identity. Its publication descriptor is:

- `kind`: `conversation-journal/v1`;
- `surface_ref`: the owner-selected conversation resource;
- `audience`: the sorted, unique, nonempty authorized human/resource audience,
  at most 256 entries and 32 KiB of serialized UTF-8 JSON;
- `receipt_key`: the existing backend's Ed25519 public verification key, in
  unpadded canonical base64url form.

This audience identifies who can inspect the publication. It is independent of
the signed native message's recipients. The first portable representation is
`plain-json/v2`, retaining the complete authenticated projection in bounded
parts. The existing record, part, attempt, byte and exact-retry limits apply.
No additional queue or scheduler is introduced.

Each `dm.visibility.publication/v1` request binds the exact native obligation
digest, selected surface/audience, part index/count and complete part text.
Its stable publication UUID derives from that obligation digest, original native
deadline and part index. The native `publication_not_after_ms` is immutable in
the obligation binding and appears as `not_after_ms` in the request. Expired
fresh requests refuse. Changing the deadline changes identity; it cannot make a
retired original into a valid exact retry.
The backend must atomically retain that exact immutable request in the existing
audience-protected conversation journal before signing a receipt. A conflicting
request for the same publication UUID must fail. A closed browser does not affect
this backend operation.

The signed `dm.visibility.publication-receipt/v1` binds request digest,
publication UUID, surface, audience, exact text digest, committed timestamp,
positive journal sequence and `durable=true`. Ed25519 signs the canonical JSON
body without `signature`; the signature is canonical unpadded base64url. The
native journal verifies the selected backend key and every binding before
accepting a part as confirmed. All parts must be confirmed before release.
Unsigned App results, socket acceptance and Telegram-shaped responses are not
portable publication proofs. A missing acknowledgment never causes another
publication attempt. The portable worker may recover by inspecting that exact
retained publication, verifying the same signed bindings before using the proof.

The SQLite fixture proves commit-before-attestation, multipart completeness,
retained proof verification after reopen, audience/surface/content/key rejection
and lost-ack handling. It is not evidence of live App publication or delivery.

## Current receiving integration

The App writer now retains the exact publication before signing and
exposes it through the existing authenticated Conversation feed/part reader.
Its real owner-socket/SQLite/HTTP/restart fixture passed without Telegram or
inference. App PR814 is selected on all four children, preserving their actual
voice/workshop configuration and native Matrix/Codex processes. Own authorized
descriptors, HTTPS assets and private-API denial passed; authenticated paired-human
reading of a real native publication remains unobserved. Its 4096-part / 64-MiB
cap includes bounded retirement: technical copies become eligible 24 hours
after both native expiry and the host acknowledgment of committed native
confirmation. Pending/ambiguous copies stay pinned. Each commit or owner
retirement handles at most 64 eligible rows, transactionally advancing one
per-conversation deadline fence before deletion. Retired exact requests cannot
republish even after clock regression; there is no unbounded tombstone archive.
Native histories and ordinary inbox/response records remain separate.

The native worker's `confirm_publications` transport callback runs only from an
authenticated confirmed journal record, after the response commit. It passes
exact publication IDs and request hashes; repetition never republishes. The
native installer/transport connects this acknowledgment and the original deadline
to the App route; it is selected on all four children.

## Readable publication and expired-before-attempt recovery

The existing `compact-text/v1` presentation is also accepted by V3 policies.
It publishes attributed ordinary speech and useful delivery status as text;
authorization-control records render zero human-facing parts. Their exact native
projection and signed authorization remain retained in the existing journals.
A suppressed technical record is not a signed human-publication receipt.

Multipart V3 publication uses the same signed Conversation receipts for every
part. It never derives a Telegram reply message ID from an earlier part. A
verified first receipt must remain commit-able while later parts are queued;
each part keeps its deterministic publication identity and one normal attempt.
If a previous result was lost, inspect that exact App publication before any
recovery. A committed first part does not prove later publication or delivery.

Use the existing accepted presentation/visibility successor writer after all
required readers support that exact profile. The publication descriptor, audience,
proof key, native identity and original message bindings remain unchanged.
Legacy plain-JSON records retain their original rendering and proofs. The existing
explicit recovery request can then carry an expired, proven-unattempted original
without a second speech publication, using its one retained recovery ID. It does
not renew uncertain carriers, resource accounts or an expired recovery authorization.
No alternate transport, retry scheduler or new publication format is introduced.

## Changing an existing publication destination

The existing trusted `publish_group_visibility` writer accepts an explicit
`replacement_configuration` containing only `destination` and
`publication_backend`. This selects a portable Conversation destination for an
existing installation, without reenrollment or a membership expansion. Use the
current installation digest as the predecessor and the ordinary complete signed
disclosure/bindings for the new destination. No additional human approval or
separate installation is required for an already authorized change.

The writer retains the original proof key, increments the generation and saves
the authenticated predecessor under its existing bounded operation/recovery
route. The exact replacement backend is part of operation identity; a changed
backend cannot reuse a lost acknowledgment. Ordinary membership expansion keeps
its existing destination-preserving behavior. Selection affects future messages:
it does not retry old obligations or settle earlier ambiguous Telegram effects.

The existing App/Gateway conversation writer and actor/resource grant supply
this typed publication and retained-receipt operation. Reuse its canonical
output journal and bounded storage; do not fabricate a human utterance or create
another reasoning session. Keep the signing key in the backend's existing
custody, separate from the Matrix caller. A generic model-callable publication
signer is not the receiving adapter.

## Prepared native installation and App connection

The existing `group_visibility_disclosure`, `accept_group_visibility` and
`publish_group_visibility` APIs now also accept an approved destination with
exact fields `publication` (the App's public descriptor) and
`representation: plain-json/v2`. The same current native membership/authorities
and participant-binding writers apply. This is the recorded human's authorized
installation, not a new approval round or a peer-selected destination.

The initial configuration keeps `destination`, `secrets: {proof_key_file}` and
`publication_backend: {kind: owner-unix/v1, socket_path: ...}`. It writes a
`dm.messaging.visibility-installation/v2` envelope with a V2 disclosure and V3
policy. No Telegram token, bot identity or Telegram qualification is required.
The backend's signing key stays in App custody; Matrix holds its verification
key and its own existing journal HMAC key. Private local socket/secret references
belong in the protected installation, not shared records.

`load_owner_visibility` verifies the same owner/participant bindings and exact
application digest, destination, backend and proof-key reference. Its new branch
constructs `ConversationJournalTransport` offline. Unknown fields, relative
sockets, extra Telegram secrets and changed audience/policy refuse. The existing
owner reissue operation preserves foreign signatures and the selected backend
byte-for-byte. Telegram installations keep their existing format and behavior.

The transport connects only to the existing owner-only App Unix socket. It
checks socket ownership/mode and Linux peer credentials, uses fixed typed
publication/confirmation commands, and bounds request/response bytes and each
exchange by the earlier native deadline or five seconds. The complete metadata
acknowledgment batch shares five seconds. It starts no server, executable, model
or alternate router. After a lost result, it reserves at most one exact retained
proof inspection durably before reading. That read can also resume after native
restart; an already consumed inspection budget is not reset. An expired original
starts no inspection. A valid proof records `response_source: retained-publication`
and its inspection time in the authenticated journal, without another publication
call. Failed/invalid reads keep uncertainty. Confirmation acknowledges only an
already committed native proof and can safely repeat that exact metadata
acknowledgment. No native SQLite transaction is held during publication,
inspection or confirmation, including already-confirmed warm operations.

The real App socket fixture now drives the actual native journal and transport:
native intent, App commit and signed receipt, native response commit, then App
acknowledgment. It also checks authenticated presentation, restart recovery,
lost-result read recovery, failed-read uncertainty and absence of Telegram/native
inference. This uses synthetic identities and a
native harness fixture; it does not establish live group delivery or model use.

## Native technical-cache retirement

Visibility catalog schema 2 adds a nullable authenticated retirement witness to
its existing native operation row and a partial pending index. The explicit
`migrate-visibility --visibility-schema-version 2` owner operation accepts the
exact schema-1 predecessor, preserves its originals and obligations, and upgrades
it transactionally. Ordinary loading performs no migration. Qualify every
required reader before selecting this schema; schema-1 binaries cannot load it
and are not a compatible rollback after migration. This changes no identity,
publication policy, enrollment or participant signatures.

For V3 portable publications only, fully confirmed technical echo records become
eligible 24 hours after both the original native deadline and the last committed
publication confirmation. When new admission reaches the existing 4096-record/64-MiB
cap, the native writer retires at most 64 eligible records in the same transaction.
The ordinary path reuses the existing capacity check and only retries the
local, uncommitted admission after space is freed. The controller also exposes
bounded owner-local
`retire_confirmed_publications(limit=64)` maintenance. Neither path contacts a
transport, calls a model or creates a scheduler. Pending/ambiguous publication
records and historical Telegram policies remain pinned.

Retirement retains the exact binding, confirmed part counts, proof digest and
timestamps under the existing journal HMAC key in the original native operation.
It deletes only the redundant technical echo record. Native messages, release
counts and uncertain carrier outcomes are untouched: publication confirmation is
not proof of native delivery. The retained witness permits historical inspection
and permanently refuses release, including after clock regression. No independent
unbounded tombstone archive is introduced; original history retains its own
owning retention policy. Normal pending queries exclude retired records.

The source fixture verifies capacity recovery, original preservation, rollback,
tamper rejection, old-schema migration, pending/ambiguous retention and regressed
clock refusal. The compatible Matrix511/schema-2 successor is selected on all four children;
all seven current readers were qualified afterward. No eligible live row existed
at the receiving inspection, so actual production deletion is not claimed.
Historical original-three Telegram records remain pinned under their original
policies; their current installations now select portable Conversation publication.
App retirement alone does not
establish complete production composition bounds.

The compatible SDK/imports, four exact Conversation disclosures and all28
genuine owner acceptances are retained. All four installations and their full
native entrypoints are selected. Seven current reader selections and four real
request/action/reply journeys replace the former preparation-only observation.
Routine software iteration must use the maintained incremental successor path;
these completed enrollment/publication operations are not a new ceremony to
repeat after every update.
