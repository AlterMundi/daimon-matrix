# Operational stack contract: daimon-matrix, Cluster, Weave, and Tribe

Status: normative for the V0.1 MVP and its provisional migration stage.

This contract assigns authority while the provisional Cluster/Tribe canary is
migrated into the required `daimon-matrix` runtime. It is intentionally strict
about the difference between operational trust and cryptographic identity.
The external Matrix.org protocol is not part of this stack.

## Authority map

| Component | Owns | Does not own |
|---|---|---|
| `daimon-matrix` | ontology, being-root continuity, canonical schemas/state, Weave ledger/sync, scopes, memory policy, communications | host resources and container lifecycle |
| Cluster | bodies, embodiments, incarnations, Matrix process/state-volume hosting, resource fences, lifecycle evidence | being identity, event meaning, memory meaning, Tribe governance |
| Weave subsystem | independent per-embodiment ledger and reusable `/we.sync` evidence inside `daimon-matrix` | transport directory, resource fencing, root identity |
| Tribe Bridge | transitional authenticated principals, encrypted delivery, audiences, ACKs | same-being membership, memory adoption, resource effects |

## Provisional same-being manifest

Before a Matrix root exists, an administrator installs the same canonical
`being-manifest/v1` document on every participating host. Its required fields
are `schema`, `being_ref`, `revision`, and `embodiments`. Each embodiment entry
has exactly `embodiment_id`, `principal_id`, `body_ref`, and `status`.

The document is an operational configuration statement, not identity proof.
Peers MUST compare the SHA-256 of its JCS encoding before exchanging `/we`
traffic. A mismatch fails closed and reports both hashes. Incarnations are not
manifest members: Cluster creates a fresh `incarnation_id` whenever the same
body runtime starts.

A Matrix root binds the provisional history only through an explicit
root-authorized binding artifact naming the exact `being_ref`, manifest hash,
and accepted event heads. Similar names, keys, memories, or routes never imply
that binding. Tribe keys MUST NOT become Matrix root keys.

After binding, Matrix credential verification replaces the administrator
manifest as same-being authority. The exact bound provisional manifest and
event closure remain readable historical authorities but cannot authorize new
events. DM-050 through DM-055 replace the standalone Tribe Bridge runtime while
preserving its recipient-encrypted delivery evidence. Neither migration changes
Cluster's resource authority.

## End-to-end flow

1. Cluster resolves the local body, embodiment, and current incarnation.
2. `daimon-matrix` verifies the being root, embodiment credential, incarnation
   authorization, and any provisional-history binding.
3. The Matrix communications layer authenticates and encrypts direct messages;
   during migration, Tribe Bridge supplies that transport.
4. Matrix verifies the sender, credential/revocation state, event signature,
   origin chain, bounds, and `being_ref` before adding data to `known` state.
5. Imported data is not effective until a local decision accepts it.
6. An adapter previews a requested projection. High-impact effects require a
   human confirmation before application.
7. The adapter records an immutable result receipt. Cluster supplies a
   resource-fence token whenever the effect writes a shared resource.

No component may collapse these steps into transport-implies-membership,
receive-implies-adopt, or identity-implies-resource-lock.

## Failure boundaries

- Experience branches and different local decisions are valid plurality.
- A different event at one origin sequence is equivocation and fails closed.
- A missing sequence is a gap; a later page cannot conceal it.
- Conflicting writes against the same concrete resource use Cluster CAS and
  fencing, independent of `being_ref`.
- A cached effect result is reusable only if intent bytes, current fence, and
  observed postcondition still match.
- No private key, password, bearer token, or secret value enters Weave.
