# Being, embodiment, and incarnation continuity

Status: normative.

## Operational identifiers

The first release uses an administrator-created `being_ref` and a canonical
being manifest. It is an explicit trust configuration, not cryptographic
proof. Cluster assigns an `embodiment_id` when a body is created and an
`incarnation_id` whenever that body runtime starts.

Multiple active embodiments with one `being_ref` are valid. Presence evidence
is per incarnation and exists for observability and routing only. It MUST NOT
act as a fence against another embodiment.

Each embodiment maps to exactly one active Tribe principal in a manifest
revision. A principal authenticates messages and event signatures but does not
prove the being by itself. Manifest changes are installed explicitly and
audited on every host; peers with different hashes do not synchronize.

## Matrix identity in the V0.1 MVP

The Matrix identity has an offline root and recovery policy. The root
authorizes a distinct credential for every embodiment. Incarnations use
short-lived subordinate keys or sessions without changing the embodiment.
Root material is never installed in ordinary bodies and is never replaced by
Tribe transport keys.

DM-021 implements an explicit binding artifact naming the provisional
`being_ref`, manifest hash, accepted event heads, new Matrix identifier, and
complete authorization evidence. Pre-binding events retain their original
signatures and identifiers; the binding adds continuity rather than rewriting
history.

Identity-control equivocation and compromised credentials fail closed.
Different experience or preference branches do not.
