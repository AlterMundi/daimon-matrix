# DM-051 root-bound recipient encryption

Status: implemented but disabled for live routes.

## Ontology correction

The frozen DM-011 `daimon-sealed-event/v0` corpus remains historical
interoperability evidence. Its `me_id`, `operational_id` and V0 certificate
authority are not the V0.1 runtime model. Installing that wire would restore a
retired singleton vocabulary after DM-021.

The runtime successor is `dm.sealed-delivery/v1`. It binds the sender to
`being_ref`, `embodiment_id`, `incarnation_id`, the exact root-authorized
embodiment credential and Ed25519 key. Each recipient binds `being_ref`,
`embodiment_id`, exact credential and X25519 key. Multiple simultaneous
embodiments of one being remain normal.

## Construction

The fixed profile is
`HPKE-X25519-HKDF-SHA256-CHACHA20POLY1305+ED25519+JCS/v1`:

1. verify the canonical `dm.we.v1` event, current sender authority, every
   recipient credential and the exact disclosure authorization input;
2. generate a fresh 32-byte CEK and 12-byte nonce through the OS CSPRNG;
3. encrypt the canonical event once with ChaCha20Poly1305 and protected
   metadata as domain-separated AAD;
4. use RFC 9180 Base mode to wrap the CEK independently to each recipient,
   binding the complete protected metadata and exact recipient in HPKE `info`;
5. sign the complete unsigned envelope with the sender embodiment key; and
6. self-parse and verify the canonical immutable bytes before returning them.

PyCA `cryptography==50.0.0` supplies the official single-shot HPKE API. Its
`Suite.encrypt` returns `enc || ciphertext`; X25519 `enc` is 32 bytes and the
wrapped 32-byte CEK plus ChaCha20Poly1305 tag is 48 bytes. There is no suite
negotiation, fallback, deterministic production randomness, shared roster key,
or Tribe wire alias.

## Authorization and receive order

DM-051's closed `dm.disclosure-authorization-input/v1` is a narrow-waist result,
not a new relationship authority. It carries the exact event ID/hash,
sensitivity, sender, sorted recipients, evidence hash and validity interval.
Tests construct it synthetically. DM-054 must later construct the same value
only after verifying the signed scope/relationship/grant evidence.

Receive performs bounded canonical parsing, current sender credential and
incarnation checks, signature verification, authorization equality and current
validation of the complete recipient credential set before any private-key
operation. It then selects exactly one local credential/key, unwraps the CEK,
authenticates the payload, verifies the inner `dm.we.v1` event through its root
authority and checks the outer/inner sender and event binding. Every external
failure is `sealed_delivery_rejected`; the carrier cannot use errors as a
recipient or key oracle.

## Custody and retry

`KeystoreDeliveryCustody` exposes only typed delivery-sign and CEK-unwrap
operations. It opens exact `sealed.signing.v1:*` and
`sealed.encryption.v1:*` slots from the owner-only, encrypted, control-head and
counter-bound DM-021 keystore. Raw private material never enters an envelope,
route, SQLite row, log, argument or environment.

`EnvelopeStore` uses SQLite `journal_mode=DELETE` and `synchronous=FULL` to bind
one request UUID to one plan hash and immutable envelope. Exact retry retrieves
the same bytes. Changed input conflicts. Failure before commit leaves no row;
response loss after commit retrieves the committed ciphertext instead of
generating a second delivery under one request.

Resealing or changing recipients intentionally creates a new delivery UUID,
CEK, nonce, HPKE encapsulations, ciphertext and signature while retaining the
logical event ID. Removing a recipient prevents future wrapping but cannot
erase plaintext or keys already obtained. The profile does not claim metadata
privacy, forward secrecy after endpoint capture, MLS group state or
post-compromise recovery.

## Carrier boundary

The output is carrier-neutral immutable bytes. DM-052 now adds typed message
storage and DM-053 adds disabled local/direct/hub providers. Telegram and Buzz
are possible future human-facing carrier/gateway adapters; neither is selected,
imported or trusted by this card, and neither may define identity, scope or
message state.

## Evidence

- `src/daimon_matrix/sealed.py`
- `schemas/communication/v1/`
- `provenance/cryptography-hpke-v1.json`
- `tests/test_dm051_sealed.py`
- immutable `vectors/v0/` HPKE CEK-wrap KAT

No live message, route, transport account, key or deployment is changed.
