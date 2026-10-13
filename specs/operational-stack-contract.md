# Operational stack contract: daimon-matrix, Cluster, Weave, and Tribe

Status: authority boundaries for the V0.1 MVP; the provisional Bridge
migration stage described below is historical.

> Retirement successor: [TRIBE-MIGRATION.md](../TRIBE-MIGRATION.md) supersedes
> the transitional Bridge carrier/retained-delivery provisions below. They do
> not require migrating Bridge messages, keys, queues or other operational
> state, and do not require compatibility, fallback or dual-run for stable.
> Native Matrix communication replaces that carrier; native `/tribe` remains.
> The authority separation and non-adoption/resource-fence invariants below
> remain in force. No schema, runtime, live removal or archive is changed by
> this documentation reconciliation.

This contract assigns current component authority. Start operational work from
[current architecture and profiles](../docs/current-architecture.md). The
provisional canary section retains signed-binding history, not a current
installation flow. The external Matrix.org protocol is not part of this stack.

## Authority map

| Component | Owns | Does not own |
|---|---|---|
| `daimon-matrix` | ontology, being-root continuity, canonical schemas/state, Weave ledger/sync, scopes, memory policy, communications | host resources and container lifecycle |
| Cluster | bodies, embodiments, incarnations, Matrix process/state-volume hosting, resource fences, lifecycle evidence | being identity, event meaning, memory meaning, Tribe governance |
| Weave subsystem | independent per-embodiment ledger and reusable `/we.sync` evidence inside `daimon-matrix` | transport directory, resource fencing, root identity |
| Native Matrix messaging and authenticated carriers | membership-based group/directed semantics and separate transport observations | resource permission, memory adoption, model activation |

Codex and Hermes are replaceable body runtimes above this authority map. They
may consume Matrix scopes and submit authorized requests, but neither owns
`/me`, canonical memory, presence, resource fences or transport membership.
Cluster supervises their processes and volumes; Matrix admits their exact body
binding and receipts. Their local threads/sessions remain body state across
park/rebirth and never become a continuity root.

DM-042 is the single-host composition gate for those two runtimes. It requires
two independently writable ledgers and custody sets under one root manifest,
bidirectional DM-023 synchronization, converged signed history and independent
local adoption. Its validation receipt is integration evidence, not presence,
a Cluster lifecycle receipt, a multihost transport ACK or a rebirth claim.

DM-070 is the installed multihost convergence gate. It runs two isolated
Matrix daemon processes with disjoint custody and state, partitions and resumes
the native encrypted peer carrier, converges immutable per-origin chains,
retains observer-local decisions, advances one signed incarnation epoch and
injects current Cluster fence truth. Ordinary partition healing is additive
set union of verified per-origin history. It never rewrites branches into a
single global chain, elects an embodiment winner, treats process presence as
membership, or lets a Cluster receipt authorize Matrix meaning. The full
contract and the later Cluster pin-bump checklist are in
`docs/dm070-multihost-convergence.md`.

## Historical provisional same-being manifest

This section describes canary-to-Root binding only. New receiving bodies use
signed identity/enrollment, never administrator-only identity or Bridge setup.

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
events. Native Matrix communication supersedes Bridge; its operational state is
not a required migration input. Original provisional evidence remains preserved
through explicit binding. Neither history mechanism changes Cluster authority.

## End-to-end flow

1. Cluster resolves the local body, embodiment, and current incarnation.
2. `daimon-matrix` verifies the being root, embodiment credential, incarnation
   authorization, and any provisional-history binding.
3. Matrix resolves signed group membership or deliberate directed authority,
   freezes the audience and encrypts the native message. Authenticated carrier
   adapters move unchanged bytes without adding recipients. No Bridge fallback
   participates.
4. Matrix verifies the sender, credential/revocation state, event signature,
   origin chain, bounds, and `being_ref` before adding data to `known` state.
5. Imported data is not effective until a local decision accepts it.
   Different embodiments may retain different decisions after their signed
   event histories converge.
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
