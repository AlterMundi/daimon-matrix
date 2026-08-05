# Native Matrix peer transport V1

Status: normative DM-055 successor contract. “Matrix” means `daimon-matrix`;
Matrix.org and `tribe-weave/v1` are not part of this wire.

## Decision

DM-050 through DM-054 already replaced Tribe's identity, recipient encryption,
logical communication, route, cursor and scope responsibilities with native
Matrix contracts. DM-055 therefore does not put those contracts back inside a
Tribe audience. It activates an independently implemented direct carrier whose
only authority inputs are the current root-bound being manifest, embodiment
credential, incarnation authorization and transport principal binding.

The transitional Tribe Bridge may continue carrying ordinary human messages
during a bounded canary. It carries no new Matrix peer traffic after cutover.
Its database, directory, keys, audiences and history are neither imported nor
rewritten. Repository archival remains the later DM-077 owner-approved action.

## Encrypted narrow waist

`dm.peer-envelope/v1` encrypts one canonical typed document to one exact active
embodiment. The fixed profile uses a fresh 32-byte CEK and 12-byte nonce,
ChaCha20-Poly1305 payload encryption, RFC 9180 HPKE Base mode with X25519,
HKDF-SHA256 and ChaCha20-Poly1305 for the CEK, and an Ed25519 signature over the
complete envelope. The signature, payload AAD and HPKE `info` have distinct V1
domains.

The closed content types are scope request/response and sync request/delta.
Logical messages continue to use `dm.sealed-delivery/v1` through DM-053 routes;
the peer envelope does not create another message ID, receipt, adoption rule or
ledger. A future content type requires a successor schema and review.

Every envelope binds:

- exact being and manifest hash;
- sender body, embodiment, incarnation, current credential, Matrix transport
  principal and signing key;
- recipient embodiment, current credential and encryption key;
- envelope and correlation UUIDs plus an optional exact reply parent;
- content type, issue time and an expiry no more than 60 seconds later; and
- ciphertext, wrapped CEK and the complete signature.

The receiver validates current root/control state, manifest equality, active
origin and credential, principal binding, signature, exact local recipient,
expiry and canonical form before opening the private key. Revocation or
manifest succession makes stale traffic unusable; reachability, DNS, an
AnyVPN address, a process name or a prior Tribe directory entry grants nothing.

## Calls, replay and authority

The transport layer may deliver bytes and correlate a response. It cannot
interpret `/me`, select `/we`, serve a sync delta, pull/adopt events, append a
ledger, mint a receipt, issue presence, acquire a resource fence or decide a
relationship. Dispatch hands decrypted typed documents to the existing
DM-054/DM-023 handlers, which repeat their own validation.

The inbound dispatcher must durably bind the request envelope ID to the exact
ciphertext hash before invoking a handler. Exact replay returns the previously
committed response bytes. Changed bytes conflict. A crash before handler
commit is retryable; a crash after an irreversible handler effect requires the
handler's existing idempotency record before the transport response is frozen.
Scope serving and sync delta production already freeze their exact results.

## Deployment and rollback

Configuration is per embodiment and disabled when absent. The public profile
contains only target embodiment and opaque route references. Endpoints and
purpose-specific private slots remain in owner-only custody. The preferred
network path is direct AnyVPN; public direct endpoints are an explicit fallback.
The runtime password descriptor is consumed exactly once while loading the
authenticated keystore. Only the exact purpose-bound seeds survive in process
memory. A wrong public/private key binding refuses startup.

The HTTP carrier bounds accepted connections before allocating handler threads,
sets a finite read timeout, requires one exact content length and media type,
and emits no server banner or diagnostic body. Durable store corruption is a
stable fail-closed protocol rejection, never a fresh handler execution.

Cutover proceeds with synthetic loopback, two installed processes, a bounded
two-host canary, restart/response-loss recovery, manifest mismatch and
revocation drills, and an ordinary Tribe-message regression check. Rollback
disables the Matrix peer profile and returns to the prior transport
configuration. It never rewrites Matrix ledgers, lowers high-waters, translates
envelopes, imports Tribe rows or revives Tribe v0.
