# DM-055 native peer transport and cutover

Status: implementation complete in runtime bundle V7; synthetic and real
loopback HTTP evidence pass. No live endpoint, host, Tribe service or repository
state has been changed.

## What changed

The final Weave carrier is native to `daimon-matrix`. Scope and sync protocol
documents travel inside `dm.peer-envelope/v1`; logical messages retain the
separate DM-051 `dm.sealed-delivery/v1` plus DM-053 route path. The implementation
does not import or accept `tribe-weave/v1`, a Tribe directory, audience, key,
database, cursor or ACK.

This corrects the old shorthand “through Tribe direct audiences.” Retaining
that wire would leave a permanent runtime dependency after DM-050–054 already
replaced its semantics. Ordinary human Tribe messages are a different product
surface and remain unchanged during the canary.

## Implemented runtime

`peer_transport.py` supplies:

- root/current-manifest-bound direct encryption and signature verification;
- exact active embodiment/incarnation/principal and recipient-key checks;
- a durable randomized-ciphertext outbox keyed per recipient envelope whose
  semantic V2 call plan reuses the first bounded expiry across later retries;
- a durable inbound processing lease and byte-exact committed response replay;
- client correlation/reply checks and a bounded HTTP(S) round trip;
- dispatch only to the existing DM-054 scope and DM-023 sync handlers; and
- one client context that resolves targets only from the current being manifest.

Runtime bundle V7 has an optional `peer_transport` object. It names an
owner-only exchange DB, outbox DB, purpose-specific X25519 slot and explicit
listen address. The encrypted keystore is opened once with the one-shot runtime
password descriptor; only the exact validated signing and encryption seeds are
retained by the purpose-bound custody object. When absent, no peer listener or
client context exists. Never-deployed bundles V1 through V6 are rejected rather
than retained as compatibility profiles.

DM-083 closes the remaining operator seam with bundle V7. It adds a sorted,
complete target map for every active remote embodiment and the authenticated
`we.sync.peer-pull` composition. Callers provide only the target embodiment and
the frozen DM-023 request ID; they cannot substitute an endpoint at runtime.
Configured peers are visible as available in `/we`, while manifest membership
continues to come only from root authority.

The same `daimon-matrixd` process starts `POST /dm-peer/v1` only after the full
bundle, root authority, current origin, encrypted custody and stores validate.
The endpoint accepts one bounded canonical ciphertext and emits one bounded
canonical ciphertext. Connections are bounded before handler threads are
allocated, every accepted socket has a read timeout, and error responses carry
no server banner or plaintext diagnostic. There is no discovery/default
identity.

## Evidence already exercised

The DM-055 tests use two different embodiment keys, encrypted keystores and
SQLite ledgers. They prove:

- encrypted `/me` request/response with actual DM-054 signatures and origin;
- encrypted sync request/delta with actual DM-023 pull, retaining the remote
  origin and importing as known rather than adopted;
- real HTTP I/O whose carrier-visible request contains neither the schema nor
  `/me` plaintext;
- V7 load, exact key-slot binding and in-process daemon HTTP handler;
- response loss after remote completion followed by byte-identical request and
  response replay with one handler effect, including a clock advance, process
  reconstruction, legacy V1 outbox-plan recovery and fail-closed expiry;
- concurrent duplicate serialization, expired-lease takeover, stale claimant
  rejection and corrupted exchange/outbox digest rejection;
- one-shot password custody, absent/malformed/colliding/wrong-key V3 profiles,
  pre-handler connection bounds and banner-free non-peer HTTP rejection;
- handler failure before response commit followed by safe retry; and
- manifest mismatch, revocation, tamper, wrong recipient/type and expiry
  rejection.

These are release-blocking scenarios in conformance suite DM-026.14. They are
production-shaped local evidence, not a claim that a remote host was contacted.

## Live canary procedure

The operator must first authorize the exact two hosts and maintenance window.
For each embodiment, record only public evidence: Matrix build, bundle digest,
being/control/manifest hashes, embodiment/incarnation/credential IDs and
AnyVPN endpoint. Never copy or print keystore values.

1. Back up and integrity-check each owner-local Matrix state root.
2. Install the exact reviewed wheel and a V7 bundle with a distinct peer
   encryption slot, exchange DB, outbox DB, explicit AnyVPN listen address and
   exact remote target.
3. Start both `daimon-matrixd` processes and verify local `/me` before network
   traffic.
4. From A, send one encrypted `/me` request to B and validate B's exact origin.
5. Append synthetic non-private events independently; request bounded pages in
   both directions until `more` is false; prove heads converge and neither side
   auto-adopts.
6. Drop one response after B commits it, retry, and prove identical request,
   identical response and one handler effect.
7. Present a mismatched manifest and then perform the separately authorized
   revocation drill; both must produce zero accepted peer effect.
8. Send one ordinary Tribe human message through the existing Tribe command;
   verify it is unchanged and no Matrix peer envelope entered Tribe storage.
9. Review the redacted receipts and obtain the explicit human cutover decision.

## Rollback

Stop the peer listener or restore the previous bundle with `peer_transport`
absent. Preserve the exchange/outbox databases for diagnosis. Restart and
verify local Matrix integrity plus the prior communication configuration.
Rollback never edits ledger events, semantic receipts, sync cursors, projection
high-waters, root/control state or Tribe history. It never re-enables Tribe v0.

DM-077 may publish the final notice and archive the Tribe repository only after
V0.1.0 is released, the native cutover remains healthy and the repository owner
explicitly approves the irreversible GitHub archive action.
