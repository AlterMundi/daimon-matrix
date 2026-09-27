# Embodiment labels

Status: normative for presentation and routing. Labels are never identity or
authority.

A daimon is embodied in as many harnesses and hosts as exist. One label names one
body:

```text
<being>.<harness>@<host>
```

`compaii.hermes@legion`, `compaii.codex@legion` and `compaii.cluster@daimonmatrix`
are three embodiments of one being. Identity remains `being_ref` plus
`embodiment_id`, and host, harness, model, account or display name never determine
being membership.

## Derivation

Labels are derived, not free text:

1. `being` comes from an owner-local registry mapping `being_ref` to one human
   name (`^[a-z0-9][a-z0-9-]{0,30}$`). A being without a registry name fails
   closed with `labels_being_name_missing`; a name is never invented from an
   opaque reference, and two beings never share one name.
2. `harness` and `host` come from the signed `body_ref` of the embodiment's
   origin, which is `<kind>:<host>:<name>`. The registry may override either
   component for one embodiment, because a body reference records the body kind
   and not always the harness wording (`cli:legion:compaii-chat` is a Hermes
   body).
3. A collision gets a deterministic discriminator: the first six hex characters
   of SHA-256 of the `embodiment_id`, appended as `-<discriminator>`. An explicit
   registry discriminator wins. An unresolved collision fails closed with
   `label_collision_unresolved`.
4. A label is at most 128 bytes and contains no whitespace, so it is also a valid
   `principal_id` (`^\S{1,128}$`). New embodiments are enrolled with their label
   as `principal_id`, which makes the signed transport principal readable.

## Registry

One owner-local closed document, `dm.labels.registry/v1`, kept outside every
repository with owner-only permissions, for example
`~/.local/state/daimon-matrix/labels/registry.json`:

```json
{
  "schema": "dm.labels.registry/v1",
  "beings": {"dm:being:v1:...": "compaii"},
  "overrides": {"embodiment:...": {"harness": "hermes"}}
}
```

`beings` and `overrides` are the only sections; an override carries only
`harness`, `host` or `discriminator`. Anything else is rejected as
`labels_registry_invalid`.

## Resolution

`daimon_matrix.labels.LabelIndex` is read-only and authorizes nothing:

- `compaii.codex@legion` resolves to exactly one embodiment.
- `compaii` is a being-level selector and resolves to every labelled embodiment
  of that being, sorted. This is what makes "talk to CompAII" independent of
  harness and host: the audience is the being's embodiments and any of them may
  answer, with authorship naming the embodiment that did.
- Unknown, ambiguous, malformed, oversized or whitespace-bearing input fails
  closed with `label_unknown`, `label_ambiguous` or `label_invalid`. Resolution
  never guesses and never falls back to a substring match.

Every caller still verifies signatures, credentials and authority by reference.
A label that resolves is a routing convenience, not a permission: relabeling a
body changes no reference and grants nothing.

## Adding a harness

A new harness (Claude Code, Open Code, goose, Pi or another) needs a harness
profile, a body adapter and, when its `body_ref` kind does not read as the
harness name, one registry override. It needs no new identity semantics, no new
scope and no change to being membership.
