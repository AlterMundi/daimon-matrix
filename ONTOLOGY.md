# Daimon Matrix ontology

Status: normative.

This document elaborates the maintained foundation. It does not replace its
central intuition: a being is an interference pattern that can be expressed
through any number of active embodiments.

## Layers

| Layer | Meaning | Identifier lifetime |
|---|---|---|
| being | continuity capable of having several embodiments | Matrix being-root lifetime |
| embodiment | one situated body through which the being acts | body lifetime |
| incarnation | one runtime interval of that embodiment | process/start interval |
| principal | transport-authenticated actor | Tribe key/directory interval |
| species | inherited capability contract and implementation | release lineage |
| tribe | explicit resource-sharing collective | `tribe_ref` declaration lineage |

A restart creates an incarnation. A new or cloned body creates an embodiment.
A true relocation of the same body preserves its embodiment and opens a new
incarnation. Species, host, harness, account, model, memory store, and display
name do not determine being membership.

## Scopes

### `/me`

`/me` resolves to the viewpoint and effective state of the current
embodiment. It includes the current body surface, local decisions, active
incarnation, and locally adopted memory. It is not a claim that only one body
exists or may be awake.

### `/we`

`/we` resolves to all active or known embodiments of the same being. A live
operation fans out to reachable embodiments and preserves every response's
origin. `/we.diff` compares known and effective state. `/we.sync` exchanges
origin-marked events through preview and pull; it never makes remote
configuration effective merely because it was received.

In the provisional runtime, same-being membership is the exact hash-matching
administrator manifest described in the operational stack contract. In the
future it is bound explicitly to a Matrix being root.

### `/tribe`

`/tribe` resolves under an exact `tribe_ref` and active membership evidence.
It is neither `/we` nor a universal collective. The founder controls admission
and expulsion; members can leave; resource grants remain directional and
separate. Shared names, transport audiences, or contact do not create a tribe.

### `/species` and `/source`

Species supplies capabilities, not identity or autobiography. Source records
retain attribution and provenance. Learning from either creates a new local
decision or memory event rather than rewriting origin.

## Valid divergence and fail-closed conflicts

Experiences, insights, preferences, skills, and local adoption decisions from
different embodiments form an origin-retaining set. They may disagree.

The following are security/control conflicts and do not merge by set union:

- different event bytes at one incarnation sequence;
- invalid or revoked signatures;
- incompatible writes using the same concrete resource fence;
- malformed lifecycle transitions;
- manifest hashes that do not match.

Resource exclusion belongs to the resource, not the being. Multiple
embodiments may act concurrently while stale writers to the same volume,
database, or effect are rejected by Cluster.

## Memory and choice

Receiving is not adopting and adopting is not applying. Every embodiment
maintains immutable known events, local successor decisions, and projection
receipts. It may later adopt, reject, defer, or reverse any eligible novelty.
Remote decisions remain useful information, never commands.

Secret values never enter the synchronized ledger. A proposal may refer to a
local credential slot. Access, external identity, or consequential effects
require explicit human confirmation before projection.
