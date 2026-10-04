# Owner-selected Codex execution — issue205

Implementation reviewed: `93c9460bd0c77a8201c6a591794e5c1efbc02b48`.
Baseline: `b247b58cfea8a1bbe270f13d07e2d3c249cc783a`.
Independent reviewer: Codex `/root/review_162_origin_projection`, analysis only.
Verdict: **APPROVE**. No blocking findings.

The review inspected the exact implementation, closed plan/schema policy
combinations, config/start/resume/result/receipt propagation and CLI/vector/CI
changes. Seven independent strict-warning tests passed. Additional probes
verified baseline byte parity for unselected successor, selected-skills and
historical profiles; exhaustive eight-combination policy checks admitted only
the two intended tuples. Fresh-controller cold resume refused substituted
reasoning after one request and retained uncertain resuming evidence.
Official successor/Hermes generator checks passed.

Author qualification:152 related tests passed (four explicit optional skips),
125 built-wheel tests passed (one explicit optional skip), official static job,
frozen87 inventories, source secret scan and two byte-identical builds passed.
Genuine pinned native0.155.1 selected model/medium/full policy initialization
and six common skills loaded without errors. Signed synthetic Matrix/Cluster
native start/park passed with zero model inputs and clean termination. The
independent reviewer inspected those metadata reports without credentials or
provider calls.

This review covers source/profile behavior. Actual provider authentication,
completed inference, deployed cold recovery and operational acceptance remain
separate checks. Full local access reflects explicit owner selection and adds
no Matrix/custody authority, hooks, automatic replies, timers or memory prefetch.
No live rollout, provider message, Root signing or custody change is approved
by this source record.

## External Hermes OAuth

Additional implementation: `4227ade0f79915e3fe0248d7a044823982bf0037`.
Independent verdict: REQUEST_CHANGES, one blocking transport finding. A valid
notification drip could renew the legacy inactivity wait indefinitely; an
admitted token could block a pipe write before any timeout.

Correction reviewed: `40c92b13d1f3f9ae3530e107817a60fe1d0e4936`.
Independent verdict: **APPROVE**, R1 FIXED. Authentication now uses one shared
monotonic deadline across nonblocking login/read writes and responses. Actual
pipe probes replayed the drip, constrained-pipe stall and combined delayed
replies; each refused at the total deadline, cleared auth context and preserved
the profile. Nine affected strict-warning tests passed, including the actual
socket/signed-journal bridge with only its native process seam replaced.

The explicit successor/OpenAI auth selection enables native external ChatGPT
token login; credentials enter through a private FD and ephemeral RPC, with no
auth.json, token environment, refresh-token import or automatic login retry.
Unselected and historical profiles retain their original behavior. Recognition
of a ChatGPT account does not prove model entitlement or completed inference.

Final author qualification:187 related source tests passed (five explicit
optional skips),133 extracted-wheel tests passed (one explicit optional skip),
static/type checks, frozen87 inventory/generators and reproducible builds passed.
The actual pinned-native no-model profile/lifecycle evidence and original
private OAuth account-recognition preflight remain separate from live rollout
or inference. No fabricated signatures or changed Matrix authority are involved.
