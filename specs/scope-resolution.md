# Scope resolution

Status: normative; implemented by DM-054.

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

Membership is resolved before availability. Only active incarnations already
present in the exact root-bound manifest are fan-out targets. Route evidence
may select a carrier for those targets and cannot widen or shrink the roster.
Two active incarnations for one embodiment are ambiguous and fail closed.

Fan-out request and response bytes use purpose-separated Ed25519 signatures
bound to exact Matrix origins, being root, manifest hash, request ID and
deadline. Requests are bounded to 60 seconds and responses to 1 MiB. Exact
duplicates replay durably; changed bytes under one request/origin key conflict.
A frozen response may replay after deadline, but no new late computation is
performed. Missing, refused and unavailable are distinct from responded.

`/we.sync` requires the same `being_ref` and manifest hash. Preview performs
all validation without writing. Pull commits a complete bounded page or
nothing. Imported events become known, not effective. Adoption and projection
are separate local operations.

`/tribe` is resolved by exact membership artifacts under a `tribe_ref`.
Being-manifest membership, Tribe audiences, and tribe membership never imply
one another.

DM-052 target rows preserve the ontology: same-being targets use
`recipient_type=embodiment`; tribe targets use
`recipient_type=relationship` and the exact membership artifact as
`recipient_id`. `receipt_origin_embodiment_id` separately names the expected
receipt author. DM-053 route selection occurs after this target set is frozen.
