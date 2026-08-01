# DM-011 conformance vectors (v0)

Normative synthetic conformance vectors for `specs/canonical-artifacts.md`
Section 9.  All key material is synthetic and deterministically derived;
nothing here is a real identity, real memory, a credential, or live
ciphertext.

## Layout

- `index.json` — machine-readable inventory mapping the Section 9
  positive/negative inventory (and the DM-010 Section 13 scenarios) to
  vector files, execution mode, and expected outcome.  Entries with
  `execution: "documented"` are state-machine/time-oracle conformance
  expectations that byte vectors cannot execute offline; they carry a
  normative `rationale`.
- `keys.json` — all synthetic test keys, including private material so
  implementations can exercise decryption.  Not secrets.
- `fixtures/` — x/test placeholder body/capability bodies (DM-018
  freezes the normative bodies; their hashes follow the current formulas).
- `me1/`, `me2/` — identity-control chains, certificates, acceptances,
  lease, events, checkpoint, sealed deliveries.
- `threshold/` — mergeable threshold-endorsement variants of the me1
  genesis wrapper.
- `fork/` — a real signed competing control branch, its branch-anchored
  certificate/acceptance, and a quorum-signed fork-resolving recovery.
- `boundary/` — real signed protocol wrappers at exact resource limits and
  one over; the index explains why 128 authorized signatures is unreachable.
- `negative/` — signed semantic negatives and tamper descriptors.
- `raw/*.wire` — exact parser/JCS byte vectors (consume the bytes verbatim).

## Rules for consumers

- Consume the checked-in bytes; do not regenerate random fields and
  compare whole files (regeneration via
  `tools/generate_dm011_vectors.py --out <dir>` is byte-identical and is
  exercised by the test suite as a determinism check).
- The disclosure authorization is a clearly labeled
  `x/test-disclosure-authorization` event fixture binding the exact event,
  sender certificate/key, and concrete recipient certificate/key set.  It
  is not a DM-012 normative schema.
- HPKE in production is randomized; these vectors pin fixed ephemeral keys
  so fixtures are reproducible.  Decryption of the checked-in sealed
  vectors is normative.
- RFC 9180 helper provenance is pinned to upstream commit
  `b1f7cb0cdeab6906c61b3d6574e8bdfdbe1cd3fb`.
