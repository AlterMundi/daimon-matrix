# Tribe Bridge Integration

## Pause checkpoint and repository name

At the 2026-08-06 pause, the only identified chat-facing Tribe repository is
`nicoechaniz/tribe-bridge`: documentation-only handoff/baseline wording PRs
#51/#54 may advance repository `main`, while deployed/runtime code remains the
`b81a683` baseline. Inspect Git for the documentation head. No separate
`tribe-chat` repository was found locally or under the recorded GitHub owners.
Treat “tribe-chat” as an informal reference to the current Tribe Bridge
experience unless an exact repository and authority boundary are recorded
later.

DM-082 has completed the local relationship, grant, encrypted delivery,
authenticated intake and semantic-receipt slice inside `daimon-matrix`.
Tribe Bridge v1 nevertheless remains deployed as the transitional ordinary
human-message lane for the future authorized DM-083 dogfood. It must not be
archived, dual-written or silently replaced during the pause. The exact resume
and retirement order is in [`RESUME.md`](RESUME.md).

## Decision

The Tribe Bridge implementation will be absorbed into `daimon-matrix` as the
first communications transport. `/tribe` remains a semantic relationship and
audience scope above that transport.

This absorption is part of the V0.1 MVP. It does not introduce or depend on
the external Matrix.org protocol; “Matrix” below means `daimon-matrix` only.

The normative V0 relationship, handshake, grant, descendant-delegation,
revocation, birth-limit, and remote-knowledge contract is
[`specs/tribe-relationships.md`](specs/tribe-relationships.md). This document
owns transport migration only and cannot widen that authority model.

Maintaining two independent projects would create duplicate identity,
encryption, cursor, receipt, routing, and storage models that would then need
an adapter despite being controlled by the same project.

## Reusable work

The current project provides useful starting points from the retired v0
implementation and the deployed v1 runtime:

- canonical signed JSON and negative parsing vectors;
- Ed25519 signing and X25519/HPKE recipient wrapping;
- governance-signed directories with rollback protection;
- direct delivery with hub fallback;
- offline inboxes;
- stable logical message IDs;
- local/hub deduplication;
- durable outboxes, delivery leases, acknowledgements, and backups;
- optional human-facing gateway mirroring.

These behaviors will be independently reimplemented behind Daimon interfaces
so they can be replaced or supplemented without changing namespace semantics.
DM-050 found no detected upstream license at the pinned public head, so no
Tribe source, schema, fixture or prose is currently copied. The exact no-copy
provenance boundary is in `provenance/tribe-bridge-v1.json`.

## Completed v0 retirement

V0 derived an AES key from public roster material and therefore did not provide
confidentiality. It is no longer running on Legion or the hub. V0 services,
parsers, commands, ports, downgrade paths, and message-history migration have
been retired. Rollback means repairing v1 with a successor state; it never
means reinstalling v0.

The active transitional runtime is Tribe Bridge v1 directory epoch 3. It uses
signed directory chaining, recipient encryption, authenticated envelopes,
stable IDs, leases, and direct/hub routing. This is useful transport evidence,
but its directory still must not become Daimon `/me` authority.

The v1 cutover established these separations, which the Daimon import must
preserve:

- identity signing keys;
- relationship and authorization grants;
- transport authentication;
- recipient encryption keys.

Each semantic message uses a fresh content key. The content key is wrapped for
each intended recipient using that recipient's encryption key. A hub stores
opaque ciphertext and cannot expand its readership.

The SSH signing roster may be accepted during migration for authentication,
but it must never be used as encryption key material.

## Repository and legacy history

- Do not import Git history or source while the upstream license/authorization
  state remains unresolved.
- If compatible authorization is later recorded, use a successor provenance
  manifest and retain exact file-level authorship, license and commit evidence.
- Do not migrate, import, dual-write, back up, or preserve v0 messages for the
  Daimon transport. New stores start empty.
- Treat legacy ciphertext as potentially non-confidential.
- Archive the old repository after the replacement transport passes its
  replacement and provenance gates.
- Add an archive notice pointing to `AlterMundi/daimon-matrix`.

Repository provenance and behavioral evidence are retained; source bytes, wire
compatibility and conversation history are not.

## Transitional v1 operating policy

- Prefer anyVPN endpoints, then configured fallbacks.
- Require an explicit per-agent client environment; an absent host default
  fails closed instead of impersonating a convenient harness.
- Principals ending in `@localhost` may address only audiences wholly local to
  the same body. Their content keys are not wrapped for remote members.
- Directory epochs advance through the governance-signed hash chain. Clients
  and brokers never downgrade an anti-rollback state.
- A new host seeded directly at an epoch greater than one needs the matching
  trusted roots and seeded directory-state receipt.
- Governance-root custody, recovery, and loss are transitional operational
  risks and direct evidence for DM-010.

## Target layers

1. Namespace and operation resolver.
2. Audience membership and capability grants.
3. Logical messages, threads, fan-out, and per-recipient receipts.
4. Signed and recipient-encrypted envelopes.
5. Route providers: local, direct, hub/store-and-forward.
6. Inbox cursor and idempotent ingestion.
7. Optional gateways such as Telegram or Buzz (both deferred and unselected).

Gateways are edge adapters. They do not define identity, tribe membership,
memory, or canonical message state.

DM-052 completes layer 3 and the transport-neutral queue/cursor portion of
layer 6. It reimplements stable semantic keys, one row per recipient, exact
replay, bounded claims and restart recovery inside the DM-023 ledger boundary.
DM-053 completes layer 5 and the carrier-owned portion of layer 6 with
explicit profiles, deterministic local/direct/hub selection, authenticated
Unix/HTTP exchange and opaque provider inboxes. Its providers ship disabled
and are exercised only against synthetic loopback endpoints. DM-054 completes
native namespace/scope integration. DM-055 independently implements the final
root-bound HPKE/Ed25519 peer carrier for Matrix scope and sync documents; it
does not tunnel those documents through Tribe audiences. The standalone Tribe
runtime now remains only for ordinary human-message regression during the
authorized canary, after which DM-077 may retire it under the repository
owner's explicit approval.

DM-082 completes the missing producer for layer 2. It creates bilateral
relationships, founded-Tribe membership and directional grants only from
verified signed Matrix history, then supplies DM-054 with the closed snapshot.
No Tribe directory, audience, delivery receipt or Cluster lifecycle fact is
accepted as a shortcut into that authority model.

## Replacement gates

- V1/DM stores start empty and reject v0 envelopes or downgrade negotiation.
- Typed payloads carry protocol version, logical ID, thread ID, scope,
  operation, and recipient information.
- Stable ascending cursors cannot lose bursts exceeding 100 messages or
  multiple messages within one second.
- Duplicate direct and hub deliveries produce one logical ingestion.
- Transport acknowledgement and semantic recipient receipt remain distinct.
- Imported signing and recipient-encryption behavior has negative tampering
  tests against the Daimon contracts.
- No confidential V0 payload uses the legacy group-key mechanism.
