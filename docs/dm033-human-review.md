# DM-033 purpose-limited human review

DM-033 is the narrow authorization boundary between a deterministic DM-030
`review-required` plan and any resulting personal-memory event. A reviewer may
authorize one exact plan, request a reviewed successor, reject it, or defer it.
The reviewer never authors `memory.recorded`; after a threshold is reached the
subject runtime independently revalidates the complete request and authors the
effect with its operational credential.

All V1 deployment evidence is synthetic. No live personal memory, reviewer
secret, provider response or external publication is included.

## Authority model

Three signatures have different meanings and are never interchangeable:

1. The subject ledger signature registers an authorization, request, decision
   or receipt as canonical history for that being.
2. A fresh purpose-separated reviewer Ed25519 key accepts its exact delegation
   and signs disclosure proofs and decisions.
3. The subject operational signer revalidates and authors a resulting
   `memory.recorded` event. A human decision is necessary authorization, not
   `/me` authorship and not a truth assertion.

The hosted runtime has no reviewer private key. `daimon-reviewer` holds exactly
one encrypted `reviewer-signing` slot and exposes no generic signing operation.
The custody password is read from a non-standard file descriptor; it is never
accepted through argv, environment variables or stdin.

A reviewer delegation is content-addressed and closed. It binds:

- exact subject, memory policy ID and canonical policy hash;
- reviewer public key and a content-addressed threshold group;
- allowed categories, classifications and decision actions;
- issue, activation and expiry times plus a maximum count of unresolved
  requests on which this reviewer has a decision head;
- exact subject manifest, embodiment and incarnation control position; and
- the reviewer's Ed25519 acceptance over the derived authorization ID.

Registration verifies both the human acceptance and current subject control
position. Revocation is an immutable successor ledger event. Historical
decisions remain attributable but cannot execute at or after the revocation
cutoff. Unique reviewer key IDs, rather than names, sessions, accounts or hosts,
are counted toward a threshold.

## Immutable artifacts

The closed public schemas live in `schemas/review/v1/`:

- `authorization.schema.json` — exact delegation and reviewer acceptance;
- `revocation.schema.json` — subject-authored revocation successor;
- `request.schema.json` — complete review input and projected effect binding;
- `decision.schema.json` — human-held signed decision;
- `access-proof.schema.json` — short-lived disclosure possession proof;
- `execution-receipt.schema.json` — terminal effect or no-op receipt; and
- `queue.schema.json` — rebuildable, authorization-scoped projection.

Every identifier is derived from a distinct domain and canonical JSON body.
Unknown fields, duplicate set members, non-canonical identifiers, altered
hashes and cross-domain substitutions fail closed.

A review request embeds the exact DM-030 policy, candidate and transition plan,
and optionally the exact DM-032 evidence-only worker proposal. It repeats and
checks their canonical hashes, subject, classification, consent, stable reason
codes, threshold group, fixed `memory-transition` requested action, explicit
predecessor request, expiry and projected event-preview hash. It accepts only
a `review-required` plan. A proposal content reference must agree with the
candidate content reference; a proposal remains evidence and never authority.

A human decision binds the complete request hash, one authorization and
reviewer key, action-compatible closed reason code, bounded note reference,
canonical UUID nonce, time, content-derived ID, predecessor decision and
optional exact edit replacement.
It cannot carry a personal-memory signature or authority override.

An execution receipt binds the request event, exact sorted threshold decision
IDs, action, time and exactly one result shape:

- `accept` — `applied` and one `memory_event_id`;
- `edit` — `successor-requested` and one new review request ID; or
- `reject` — `no-op` and no memory or successor.

`defer` is deliberately nonterminal and therefore has no execution receipt.

## Queue and disclosure

There is no authoritative queue database. The coordinator derives queue rows
only from complete canonical `review.requested`, `review.decided` and
`review.executed` events at the current cutoff. Rows are ordered by content-
addressed request ID, pagination is deterministic, replay collapses to one
semantic artifact, and display never claims or locks work.

Queue and inspection first resolve a known authorization, reject revocation,
and verify an Ed25519 access proof bound to the exact authenticated RPC request
ID. Only then may they disclose membership or request bytes. A proof is valid
for at most 60 seconds and cannot be replayed under another RPC ID.

Queue rows are payload-minimized. Exact inspection returns the immutable
request, its canonical event and deterministic decision state. Invalid imported
human signatures are retained as quarantined evidence and force conflict;
operational event signing never upgrades them into valid human decisions.

## Terminal safety

Normal `daimon review ...` output never renders untrusted response strings. It
prints the response as complete canonical UTF-8 JSON bytes encoded in hex, with
byte count, SHA-256 and offsets. Consequently terminal escapes, OSC hyperlinks,
URLs, Markdown/HTML, shell substitutions and prompt-like text remain inert, and
no byte is hidden or truncated.

`--json` preserves exact machine-readable bytes but is refused when stdout is a
terminal, before an RPC is sent. Redirect sensitive output only into a protected
destination, for example after `umask 077`. A human signing ceremony consumes
owner-only, canonical, non-symlink files. For `edit`, its preview contains the
before/after canonical hashes and one exact linear-time byte replacement hunk
whose removed and inserted bytes are hex encoded.

The signing prompt is always `SIGN <12-character artifact suffix>` on a real
TTY. There is no `--yes`, stdin signing, environment identity, daemon connection
or generic signer. An interrupted, mistyped or non-TTY ceremony creates no
decision file.

## Decision state machine

`accept` authorizes only the unchanged exact plan. Execution regenerates the
DM-030 decision from the embedded policy, candidate and checkpoint, verifies
the present memory lane/evidence state, and commits through the separate
`MemoryPolicyExecutor.execute_reviewed` path.

`edit` never mutates original bytes. Its replacement contains a complete new
policy, candidate, plan and optional proposal. Deterministic policy is rerun;
successful execution of the edit creates a content-addressed successor review
request. The successor starts pending and requires a fresh threshold over its
new request hash before any memory effect.

`reject` is terminal for that exact request and creates only a no-op receipt.
Materially changed evidence requires a new request. `defer` records a signed
nonterminal head; a successor decision must name it as predecessor. Expiry can
block further action but never turns defer into acceptance.

Each reviewer has one explicit predecessor chain per request. A terminal head
cannot be replaced. Distinct terminal votes are retained; conflicting or
invalid heads make the request non-executable. A threshold winner requires
matching action and, for edit, matching canonical replacement hash from distinct
authorized keys. Arrival order is not authority.

`max_outstanding_decisions` counts unresolved request heads, not immutable
history. A replacement after `defer` does not consume another slot. Execution,
supersession or expiry releases the slot while retaining every signed decision.

## Durable execution and retry

Authorization, revocation, request, decision and receipt events use semantic
content IDs in addition to authenticated RPC idempotency. Repeating identical
artifact bytes under another RPC request returns the existing canonical event;
the same identity with different bytes is equivocation.

Immediately before execution the coordinator verifies current authorization
windows/revocation/group/scope, the exact request and decision signatures,
deterministic DM-030 regeneration, and the current memory checkpoint. Review
administrative events may advance the general ledger while the underlying
evidence, lane, policy, projection and proposed event remain unchanged.
Unrelated semantic drift refuses the effect, marks the old request superseded
and creates exactly one predecessor-bound pending successor at the new
checkpoint when deterministic reevaluation remains reviewable.

The memory event is committed before `review.executed`, with deterministic IDs
and durable local-operation journaling. A lost response or daemon restart is
retried with the same prepared authenticated request. Tests kill and reload the
installed daemon twice and observe exactly one decision event, one memory event
and one execution receipt.

## Local and model-facing surfaces

The authenticated local methods are:

```text
review.authorize
review.revoke
review.request
review.queue
review.inspect
review.decision.draft
review.decision.submit
review.execute
```

The `daimon` CLI maps one-to-one onto all eight. MCP exposes only request,
queue, inspect, unsigned draft and submit-shaped compatibility. Every MCP
decision submission refuses locally with a typed human-boundary error before
daemon dispatch. MCP has no authorize, revoke, execute or signing method.

The dedicated human commands are:

```text
daimon-reviewer ... key-create
daimon-reviewer ... authorization-accept --core ... --out ...
daimon-reviewer ... access-proof --authorization ... --rpc-request-id ... --out ...
daimon-reviewer ... decision-sign --authorization ... --request ... --draft ... --out ...
```

## Matrix, Cluster and Tribe boundary

`daimon-matrix` owns reviewer delegation, human decisions, deterministic policy,
canonical memory and receipts. `daimon-cluster` may host the encrypted state,
restart or relocate the runtime, and supply separately verified resource/body
evidence. Cluster fences cannot become review authority. Tribe transports exact
signed artifacts; delivery, provider identity and message receipt cannot count
as a human decision. Matrix.org is unrelated and remains outside the MVP.

## Verification

```text
PYTHONPATH=src python -W error::ResourceWarning \
  -m unittest tests.test_dm033_human_review -v
python tools/generate_dm033_vectors.py --out /tmp/dm033-vectors
diff -ru vectors/review/v1 /tmp/dm033-vectors
```

The release gate also checks closed JSON Schemas, negative vectors, independent
environment reproduction, real PTY custody ceremonies, authenticated daemon and
MCP boundaries, conformance scenarios, strict types/lint, all earlier tests,
reproducible archives, installed-wheel execution, license inventory and secret
scans.
