# Tribe Bridge Integration

## Decision

The Tribe Bridge implementation will be absorbed into `daimon-matrix` as the
first communications transport. `/tribe` remains a semantic relationship and
audience scope above that transport.

Maintaining two independent projects would create duplicate identity,
encryption, cursor, receipt, routing, and storage models that would then need
an adapter despite being controlled by the same project.

## Reusable work

The current project provides useful starting points:

- SSH-signed envelopes;
- direct delivery with hub fallback;
- offline inboxes;
- stable logical message IDs;
- local/hub deduplication;
- optional human-facing gateway mirroring.

These behaviors will be imported behind a transport interface so they can be
replaced or supplemented without changing namespace semantics.

## Security replacement

The current AES key is deterministically derived from the public
`allowed_signers` roster and a fixed public string. Anyone with the public
roster can derive that key, so the existing mechanism does not provide
confidentiality.

V0 must separate:

- identity signing keys;
- relationship and authorization grants;
- transport authentication;
- recipient encryption keys.

Each semantic message uses a fresh content key. The content key is wrapped for
each intended recipient using that recipient's encryption key. A hub stores
opaque ciphertext and cannot expand its readership.

The SSH signing roster may be accepted during migration for authentication,
but it must never be used as encryption key material.

## Repository and history

- Import Git history when it is straightforward and preserves authorship.
- If history import would materially delay the planning or implementation,
  import the code with explicit commit and repository provenance.
- Preserve current messages as read-only legacy records only when migration is
  straightforward.
- Never promote legacy conversation records into personal memory
  automatically.
- Treat legacy ciphertext as potentially non-confidential.
- Archive the old repository after the replacement transport passes its
  migration and compatibility gates.
- Add an archive notice pointing to `AlterMundi/daimon-matrix`.

## Target layers

1. Namespace and operation resolver.
2. Audience membership and capability grants.
3. Logical messages, threads, fan-out, and per-recipient receipts.
4. Signed and recipient-encrypted envelopes.
5. Route providers: local, direct, hub/store-and-forward.
6. Inbox cursor and idempotent ingestion.
7. Optional gateways such as Telegram.

Gateways are edge adapters. They do not define identity, tribe membership,
memory, or canonical message state.

## Compatibility gates

- Existing text clients can send and receive during a documented transition.
- Typed payloads carry protocol version, logical ID, thread ID, scope,
  operation, and recipient information.
- Stable ascending cursors cannot lose bursts exceeding 100 messages or
  multiple messages within one second.
- Duplicate direct and hub deliveries produce one logical ingestion.
- Transport acknowledgement and semantic recipient receipt remain distinct.
- Old and new signature verification have negative tampering tests.
- No confidential V0 payload uses the legacy group-key mechanism.

