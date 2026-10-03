# Issue 161 host-specific neutral binding review

Candidate `fc068650f59344b1550d2abf061547fb5657ea22`, based on main
`8ae14b27b9967c19308b744e1f4756d405e99d17`.
Independent reviewer: Codex agent `review_162_origin_projection`, read-only review
and isolated native probes. Verdict: **APPROVE** for this implementation increment.

The optional Hermes HOME locates the actual harness configuration without moving
shared roots. The explicit native HMK command plan binds its interpreter, scripts,
workspace and shared database; generated wrapper bytes are manifest-bound. Closed
fields, literal arguments, traversal/direct-symlink refusal and owner-only output
preserve the existing binding boundaries. Plans without the new options retain
the previous artifact and manifest bytes.

The initial review found a blocking database-selection bug: native embedding
commands could ignore the canonical shared-base variable and use an unrelated
inherited database. The correction explicitly binds absolute HMK_DB_PATH to the
selected pool/library.db. Independent actual pinned read-only embed_verify probes
with paired synthetic databases now select the intended pool under both previous
failure cases and combined wrong inherited aliases. The unrelated database stays
byte-identical. Independent isolated binding suite: 30 tests passed, no skips.
No provider/model, real memory, credential or live runtime access occurred.

This review reuses prior neutral-binding/Codex/memory reviews and covers only the
new host-specific increment and its corrected database destination. It does not
prove live installation, consumer rebinding, cross-host sync or operational
acceptance. Actual distribution/interpreter pinning and the owner's pending live
approvals remain separate; rendering supplies no runtime identity or authority.
