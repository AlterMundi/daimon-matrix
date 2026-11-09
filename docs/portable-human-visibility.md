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
portable publication proofs. A missing acknowledgment stays ambiguous and does
not cause another publication attempt.

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

The native owner installer must bind the selected backend, public key,
surface/audience and participant disclosure through the existing signed
installation route. Its loader, registry authentication and authority/revocation
checks must accept that exact portable installation. The current native loader
still selects Telegram V2 installations; the new journal primitive alone does
not make a portable installation selectable or reopen any child egress.

Qualify the compatible successor on all seven current receivers before selection.
Then observe an actual committed App publication with Telegram absent, technical
completion, signed receiving-copy evidence and a useful authored response through
the existing messaging heartbeat. Retain global/lane pause, resource/accounting,
source attribution and old uncertain messages. Neither fixture success nor a new
installation retroactively completes the original Pixin attempt.
