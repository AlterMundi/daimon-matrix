# Being, embodiment, and incarnation continuity

Status: normative identity separation, with historical provisional binding
explicitly separated below. Current execution uses verified Root identity.

## Operational identifiers

Current being identity comes from verified Root-authorized signed history.
Administrator labels or a manually copied manifest cannot establish it. Cluster
observes the enrolled embodiment and actual physical incarnation; these must
match Matrix signed authority. Process creation alone does not issue credentials
or incarnation authorization.

Multiple active embodiments with one `being_ref` are valid. Presence evidence
is per incarnation and exists for observability and routing only. It MUST NOT
act as a fence against another embodiment.

Transport principals are bound to embodiment credentials, not being names or
Tribe membership. Verify and adopt authority successors through the
[receiver-compatible rollout](../docs/runbooks/receiver-compatible-authority-updates.md).
Historical epochs remain available for original-event verification; a newer
unverified manifest is never an automatic winner.

## Matrix identity in the V0.1 MVP

The Matrix identity has a root and recovery custody policy. Offline custody
outside ordinary bodies is the default. An explicitly owner-authorized Source
custodian MAY instead use the online custody policy in
[identity-root-v1.md](identity-root-v1.md#owner-authorized-source-custody).
The root authorizes a distinct credential for every embodiment. Incarnations
use short-lived subordinate keys or sessions without changing the embodiment.
Root material is never installed in ordinary runtime custody and is never
replaced by Tribe transport keys. Source access is an explicit operator grant,
not authority inherited by other embodiments, models, species or descendants.

## Historical provisional binding

The original canary used administrator-created `being_ref` and
`being-manifest/v1` as trust configuration, not cryptographic identity. This is
retained migration evidence, never current onboarding authority.
DM-021 implements an explicit binding artifact naming that provisional
`being_ref`, manifest hash, accepted event heads, new Matrix identifier, and
complete authorization evidence. Pre-binding events retain their original
signatures and identifiers; the binding adds continuity rather than rewriting
history.

The executable artifact, control-chain, credential, binding, and custody
contract is [`identity-root-v1.md`](identity-root-v1.md). Transport principals,
including Tribe keys, are explicitly bound to one embodiment credential and
remain separate from being/root authority.

Identity-control equivocation and compromised credentials fail closed.
Different experience or preference branches do not.
