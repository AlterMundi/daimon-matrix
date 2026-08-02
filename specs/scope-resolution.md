# Scope resolution

Status: normative.

Resolution starts from a local embodiment and never from a display alias.

- `/me` returns the current embodiment, incarnation, local effective state,
  and local body capabilities.
- `/me.body` returns the Cluster surface of that body.
- `/me.memory` returns locally adopted personal events with original origin.
- `/we` returns every active/known embodiment in the exact being manifest.
- `/we.diff` returns known/effective differences and local/remote decisions.
- `/we.sync` exchanges heads, previews deltas, and pulls valid events.
- `/tribe/<tribe_ref>` returns active tribe members and separately authorized
  resources.

Live `/we` fan-out targets reachable active embodiments. Zero responses is a
valid availability result. Each reply includes request ID, embodiment,
incarnation, principal, completion state, and content. A timeout returns the
responses received plus explicit missing origins. No resolver chooses one
response as the voice of the being.

`/we.sync` requires the same `being_ref` and manifest hash. Preview performs
all validation without writing. Pull commits a complete bounded page or
nothing. Imported events become known, not effective. Adoption and projection
are separate local operations.

`/tribe` is resolved by exact membership artifacts under a `tribe_ref`.
Being-manifest membership, Tribe audiences, and tribe membership never imply
one another.
