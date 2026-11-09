# Portable human visibility — implementation under #496

The four children have signed membership and selected native readers. Their
receive-only application keeps outbound visibility closed. The first directed
Pixin attempt retained `route_echo_unconfirmed` and `completion_blocked` in the
receiver's diagnostic sidecars while the sender retained an unconfirmed HTTP
outcome. Reader qualification alone cannot complete that communication. Preserve
the original carrier and its uncertainty; configuration changes do not authorize
replaying it or rebinding its historical publication obligation.

Nicolas has authorized the required implementation. Telegram accounts or viewing
Tribu are not admission prerequisites. The existing Telegram V2 policies and
pending proofs retain their original meaning. The remaining implementation must
publish through the general conversation's durable backend, with Telegram as an
optional client of that backend.

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

## Remaining receiving integration

The App writer candidate now retains the exact publication before signing and
exposes it through the existing authenticated Conversation feed/part reader.
Its real owner-socket/SQLite/HTTP/restart fixture passed without Telegram or
inference. This candidate is not selected on a living body. Its 4096-part / 64-MiB
cap now has staged bounded retirement: technical copies become eligible 24 hours
after both native expiry and the host acknowledgment of committed native
confirmation. Pending/ambiguous copies stay pinned. Each commit or owner
retirement handles at most 64 eligible rows, transactionally advancing one
per-conversation deadline fence before deletion. Retired exact requests cannot
republish even after clock regression; there is no unbounded tombstone archive.
Native histories and ordinary inbox/response records remain separate.

The native worker's `confirm_publications` transport callback runs only from an
authenticated confirmed journal record, after the response commit. It passes
exact publication IDs and request hashes; repetition never republishes. The live
native installer/transport must connect this acknowledgment and the original
deadline to the App route before production selection.

Extend the existing App/Gateway conversation writer and its actor/resource grant
with this typed publication and retained-receipt operation. Reuse its canonical
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

The native journal's own steady-state retirement still needs the composing
parent's authoritative completion state, preserving unknown effects and old
policies. App retirement alone does not make the complete production composition
bounded. Neither prepared installation nor this fixture reopens a living child.

Qualify the compatible successor on all seven current receivers before selection.
Then observe an actual committed App publication with Telegram absent, technical
completion, signed receiving-copy evidence and a useful authored response through
the existing messaging heartbeat. Retain global/lane pause, resource/accounting,
source attribution and old uncertain messages. Neither fixture success nor a new
installation retroactively completes the original Pixin attempt.
