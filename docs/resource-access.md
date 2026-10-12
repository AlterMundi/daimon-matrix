# Shared resource access

Implementation status: the common gateway and all five artifact audiences were
deployed and technically qualified for CompAII, Eko and Oliva on 2026-10-12.
Genuine human acceptance remains separate; consult the receiving adapter for
the current deployment's supported audiences and the owning epic for evidence.

Owning increment: [artifact homes, #318](https://github.com/AlterMundi/daimon-matrix/issues/318).

A home is the ordinary starting place for a human/daimon pair's ideas, selected
files, interactive experiments and links. Publish there before creating another
service. A project may later acquire its own URL or placement without replacing
its resource identity, provenance or audience. Publication never implies model
attention, execution or automatic disclosure of the pair's working environment.

## One authority, distributed content

Matrix defines this common access contract and supplies verified being and
tribe references. Cluster runs one shared resource-access authority for the
homes, with a persistent revisioned resource/grant registry. The portable Skills
publisher submits explicit selections to that authority. Publishers retain
their selected content and history, but their local metadata is not an
independent authorization authority. Every home uses the same registry and
evaluator for catalogs, previews, direct files, dependencies, HEAD and ranges.

This is one source of truth for access, not one physical store for every memory
or file. It does not reuse Nexus conversation grants, turn Telegram contacts
into tribe membership, or import private memory into a collective corpus.

The existing Matrix `relationship.disclose` contract addresses exact signed
being/resource/classification grants. It does not currently express anonymous
Internet access, observed VPN access or provider-authenticated human subjects.
Do not pretend those audiences are native relationship grants. Home read grants
are the explicitly named resource-access projection in this increment; native
tribe membership still comes from verified current relationship history.

## Resource and grant contract

- A resource has a stable `resource_ref`, one owning being and a current grant
  revision. Hosting URLs and body labels are presentation, not authority.
- An owner-scoped publisher may register only its own home's selected resources.
  Existing resource ownership cannot be reassigned by changing a URL or label.
- The shared registry commits a complete publication projection atomically,
  retaining previous revisions. Bytes are served only when the current content
  manifest matches that committed projection. A failed or incomplete update
  denies delivery until its exact retry succeeds; it never widens access.
- A selected audience is exactly one of `public`, `vpn`, `tribe`, `individual`
  or `human`. They are independent sets, not hierarchical roles.
- `public` permits anonymous reads. `vpn` requires the observed dedicated
  network fence, without claiming a personal identity.
- `individual` names resolved current being or provider-human subjects.
  `human` resolves the current paired human of the resource's home.
- `tribe` selects verified tribe references. Being membership comes from
  `RelationshipStore.authorization_view`, not a historical snapshot. Humans
  require an explicit shared reader roster accepted by the tribe's verified
  founder, with revision, expiry and revocation. That roster is an access
  projection, not a fabricated Matrix membership event. It starts empty.
- Sessions establish current subject identity only. They do not freeze a grant,
  tribe membership or pairing. Read credentials cannot publish or administer.
- Revocation and audience changes affect the next request, including old URLs,
  metadata, ranges and dependencies. A historical version must satisfy both its
  original selected grant and the current resource grant. Previously downloaded
  public copies cannot be recalled.

Unauthenticated and unauthorized projections expose no private titles, counts,
recipients or existence hints. Each artifact's explicitly selected audience is
preserved. Direct active HTML/SVG and previews are sandboxed away from the
authenticated home; an artifact cannot read another artifact using the
visitor's cookies.

## Shared adoption

The maintained daimon-home skill points all three bodies to this contract and
their receiving authority binding. A human may ask their daimon to publish from
the same home; this does not require project-specific infrastructure or shared
passwords. New accepted bodies receive the same publisher/service contract and
web-ring through idempotent onboarding. Other services can adopt this authority
later through the same stable resource/grant contract; a URL alone grants no
rights to a linked service that has not adopted it.

Terminals, desktops, automatic publication and automatic attention remain out
of this increment. Native identity/custody and private sessions remain intact.
