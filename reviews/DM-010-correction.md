# DM-010 identity-boundary correction reviews

> Historical review only. The hierarchy below was superseded by the
> 2026-08-04 ontology rectification: one being may authorize plural concurrent
> embodiments, `/me` is situated, `/we` navigates embodiments of that same
> being, and distinct beings use explicit relationships/Tribes. See
> [`../RESUME.md`](../RESUME.md), [`../ONTOLOGY.md`](../ONTOLOGY.md), and
> [`DM-010.md`](DM-010.md). Do not reapply the singleton-body conclusion.

Date: 2026-08-01

Scope: the correction from the superseded one-`/me`/many-simultaneous-
incarnations model to the three-level hierarchy:

1. `/we`: an emergent collective of distinct identities;
2. `/me`: one root-bearing cryptographic and experiential identity;
3. body: the one machine/container in which that identity is awake now.

## CompAII design confirmation

CompAII supplied the hierarchy after the `daimon-cluster` review and confirmed
that multiple `/we` identities may be awake simultaneously while one identity
may move bodies only sequentially through park/wake. Same-identity concurrent
bodies are split-brain.

After the no-root membership ceremony was formalized, CompAII returned
`NO OBJECTION` in Tribe message
`019fbc29-948e-7b87-9f31-8faafcb6e2af`. The confirmed ceremony uses a
content-bound `we_id`, founding `me_id` values, ordered membership transitions,
member-root threshold authorization, separate admitted-identity acceptance,
durable anti-replay high-water, and routing through membership intersected with
DM-010 active presence.

## Independent Kimi reviews

All reviews were analysis-only Kimi Code CLI `/build` runs. They did not edit
the worktree or publish state.

The first pass returned **NOT READY** and identified three blockers:

- `/we` membership had no identifier, admission/removal authority, or replay
  protection;
- two superseded foundation sentences were still inherited into the species
  genome without an explicit carve-out;
- the identity-wide lease head lacked external durability and crash-wake
  semantics.

It also found that a superseded credential retained event authority and that
the plan overstated physical prevention across partitions. All findings were
integrated.

The second pass returned **READY WITH NOTES** and verified that all blockers
were closed. Its remaining tightening notes were also integrated:

- reserve separate membership genesis, transition, and acceptance domains;
- require admitted identities to accept with their `/me` roots even when they
  are not governance signers;
- require possession proofs from a replacement governance signer set;
- define an accepted park/wake event cutoff as externally checkpointed or
  receipt-bearing, never a purely local head;
- correct residual terminology and grammar.

The third pass returned **READY WITH NOTES**, with no blockers. It verified all
prior findings as integrated and found only two cosmetic terminology nits:
align `sleeping` with the normative `parked` state and replace one residual
`embodiment` reference with `body`. Both are integrated in this branch.

Local review artifacts:

- `~/.bridge-ai/builds/20260801-035143-daimon-matrix-dm010-correction-kimi-build.md`
- `~/.bridge-ai/builds/20260801-040610-daimon-matrix-dm010-correction-kimi-build.md`
- `~/.bridge-ai/builds/20260801-043621-daimon-matrix-dm010-correction-kimi-build.md`

## Disposition

The corrected DM-010 boundary passed independent verification and is ready for
PR.
DM-011 and DM-012 remain reusable after adaptation and MUST NOT merge their
superseded incarnation semantics. DM-012 PR #53 must resolve `/we` as the
accepted `we_id` membership set intersected with active DM-010 identity/body
evidence.
