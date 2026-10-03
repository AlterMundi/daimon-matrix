# Attributed memory: lighting up the DM-034 projection

Status: operational runbook. Normative contract stays in
[`docs/dm034-memory-projection.md`](../dm034-memory-projection.md) and in the HMK
side's `docs/daimon-projection.md`.

This is the procedure that turns the projection layer from built-and-empty into
live, attributed, and verifiable. It was executed end to end on 2026-09-28 for two
embodiments of one being on one host; the identifiers below are placeholders.

## Authority boundary

Matrix is authoritative for the memory: identity, event order, category,
corrections, retractions, classification and policy. HMK holds a **disposable
retrieval view** plus local receipts. A projected chapter is never HMK-native
authority and cannot become collective memory by implication. Nothing in this
runbook widens what anyone may do.

Attribution is structural, never textual: which body lived which memory is a JOIN
over `daimon_projection_namespaces` keyed by `source_instance`, which is exactly
`matrix:embodiment:<embodiment-uuid>`.

## Prerequisites

- HMK at the commit DM-034 pins, with `scripts/daimon_projection.py` present. A
  different commit, API version, schema version or projector is unsupported rather
  than compatible by guess.
- The neutral pool's environment, so the adapter resolves the same `library.db` the
  being's bodies share (`HMK_AGENT_MEMORY_BASE=<pool-path>`).
- Two distinct local clients per body, because the authority is split:
  - the runtime/observe client, whose capability carries `memory.evaluate`;
  - the memory operator client at `runtime/operator-clients/memory/`, whose
    capability carries exactly `memory.execute` and nothing else.

  Using the observe client for `execute` fails with `authentication_failed`. That
  refusal is the design working, not a misconfiguration.
- The body password, passed through an inherited descriptor. Never through argv or
  environment.

## Procedure

### 1. Build the policy and the candidate with the constructors

Do not hand-compute identifiers. `create_memory_policy`, `create_content_ref` and
`create_memory_candidate` derive `policy_id`, `content_id` and `candidate_id`
themselves by domain-separated SHA-256 over canonical bytes. Canonical examples live
in `vectors/memory/v1/`.

For an owner-local body use a category that does not require body evidence:

- `personal-insight` or `personal-skill` with `derivation="local-synthesis"`, and
  `body_evidence=None`.

`personal-experience` with `derivation="body-occurrence"` requires
`body_evidence_state == "verified"`, which in turn requires the cutoff event's
payload to carry `session_ref` and `lease_ref`. See *Known limits* below.

`subject_me_id` and `author_me_id` must both equal the being ref, or a personal
category is rejected as `false-personal-author`. Keep `effect="local-only"`,
`consent="granted"`, `safety="clear"`, `contradiction="none"`, and make sure the
category is in the policy's `automatic_categories` and the classification is not in
its `review_classifications`, or the plan comes back `review-required` instead of
`eligible`.

### 2. Evaluate, then execute inside the plan TTL

```bash
daimon --socket <runtime>/matrix.sock --client-config <runtime>/client.json \
  --capability-key-fd 3 --json memory evaluate \
  --policy policy.json --candidate candidate.json 3<<runtime>/client.key
```

Expect `outcome: eligible` with a `plan_id`, a `decision_id` and an
`expires_at_ms`. The plan TTL is five minutes by default: evaluate and execute in
the same pass, or re-evaluate.

```bash
daimon --socket <runtime>/matrix.sock \
  --client-config <runtime>/operator-clients/memory/client.json \
  --capability-key-fd 3 --json memory execute \
  --policy policy.json --candidate candidate.json --plan plan.json \
  3<<runtime>/operator-clients/memory/capability.key
```

The result carries the committed `memory.recorded` event. Record its `event_id` and
`content_hash`: they are what the projection must later match.

For a body with no daemon, load the runtime in process instead and call
`service.handle()` with requests built by `local_api.create_request` and checked
with `verify_response`, using the matching capability for each of the two methods.

### 3. Compute the checkpoint and the current projection

`projection_checkpoint(ledger)` gives the `sequence` and `hash` the adapter requires
as `source_checkpoint`; `current_memory_projection(ledger, limit=...)` gives the
entries. Both need the ledger, so if a daemon holds the state-root lock, stop it,
compute, and start it again.

### 4. Apply through the adapter

The boundary accepts only canonical compact UTF-8 JSON on stdin: sorted keys,
`,`/`:` separators, NFC, at most one trailing newline. Unknown fields, duplicate
keys, floats or oversized documents fail before a transaction begins, and
diagnostics carry only a stable code.

```bash
HMK_AGENT_MEMORY_BASE=<pool-path> python3 scripts/daimon_projection.py \
  --instance-id <hmk-instance-id> apply < apply.json
```

Required request fields: `schema` (`hmk.daimon-projection.request/v1`), `adapter`,
`request_id`, `idempotency_key`, `operation` (`project` for a first view, `advance`
for the next contiguous sequence, `retract` to remove from retrieval while keeping
provenance), `target` (`instance_id`, `api_version`, `schema_version`),
`source_instance`, `subject_me_id`, `author_me_id`, `memory_id`, `category`, `head`
(`event_id`, `event_hash`, `sequence`, predecessors), `statement` (`sha256`,
`byte_length`, `media_type`, `classification`, `text`), `projector`, and
`source_checkpoint`.

`statement.sha256` and `byte_length` must equal the candidate's `content_ref`, and
the adapter instance id must match `--instance-id` or it fails closed.

Expect `outcome: applied` with a `namespace_id`, a `projection_id` and a
`receipt_id`.

### 5. Verify — by hash, not by inspection

Three checks, all of them comparisons rather than readings:

1. **Attribution.** JOIN `daimon_projections` to `daimon_projection_namespaces` and
   confirm one row per embodiment namespace, each with its own `source_instance`.
2. **Provenance.** For each projected row, open that body's own ledger read-only and
   confirm the projection's `head_event_hash` equals the `content_hash` of the event
   named by `head_event_id`, with `kind = memory.recorded` and a committed status.
3. **Isolation from unsigned writes.** Capture each namespace's `logical_hash` via
   the adapter's `verify`, perform a direct unsigned write
   (`memoryctl.py add-text`), then re-run the attributed query and `verify`. The
   attributed row count must be unchanged, no attributed row may lack a
   `memory_id`, and every `logical_hash` must be byte-identical.

## Known limits

- **`personal-experience` is unreachable for an owner-local body.**
  `memory_checkpoint` only reports `body_evidence_state = verified` when the cutoff
  event's payload carries `session_ref` and `lease_ref` equal to the declared ones.
  Owner-local lanes do not produce those fields — `lease_ref` belongs to
  Cluster-hosted bodies — so the evaluation returns `rejected` with the single
  opaque reason `body-evidence-mismatch`. Either owner-local bodies get a
  body-evidence shape that does not depend on a Cluster lease, or the category is
  documented as Cluster-only. Until then, use `local-synthesis` categories.
- **Plan TTL.** Five minutes by default; an expired plan cannot be executed.
- **Split authority.** `evaluate` and `execute` are different capabilities by
  design. Do not widen one client to cover both.
- **The cross-host projection boundary is tested; live adoption is a separate
  operator action.** The procedure below does not establish a working peer route,
  authorize a service restart or grant a capability the installed body lacks.

## Manual cross-host adoption

Continue the existing same-being DM-023 peer exchange; do not transport or merge
whole `library.db` files between hosts. The host-local pool remains shared by the
being's bodies on that host. Perform each invocation only for a human request.

1. Verify the actual installed protocol, signed being/origin authority, peer route
   and purpose-limited owner clients on both hosts. A reachable listener, matching
   label or successful SSH copy is not same-being authority.
2. Exchange signed event pages through the supported sync operation. Preserve the
   request/page/receipt identities and origin signatures. An intake receipt is
   not an adoption receipt. Do not read conversational inboxes as a shortcut.
3. Supply the selected accepted memory's content separately through an explicit,
   private artifact transfer. Resolve by the signed content reference, not title,
   local chapter ID, destination path or semantic similarity. The existing
   adapter validates NFC UTF-8, media type, length and SHA-256 before any effect.
   The event exchange does not itself transfer these bytes.
4. Create the projection profile with `source_instance="matrix:" +
   assertion_event["origin"]["embodiment_id"]` and the actual target HMK instance.
   Use one local projection journal per namespace. Do not replace the source with
   the receiver. On a mixed-origin ledger, only that assertion-origin namespace
   is selected, including during rebuild and verified recall.
5. Project the current head with the supported adapter and verify its receipt and
   current HMK effect. If the first received head is already a later correction,
   use `rebuild-plan` then `rebuild-apply` for the exact origin namespace rather
   than fabricating prior apply receipts. Keep the signed lane available for
   verification. Correction authors remain distinguishable in that lane.
6. Compare source and receiver memory ID, event head/hash, statement hash and
   assertion-origin namespace. Local chapter IDs, receipt IDs, file hashes and
   database layout need not equal between hosts. Replaying an identical event
   page or applying the same verified intent must not duplicate memory.

Unsigned HMK-native legacy memories remain a distinct artifact class. Preserve
both source inventories and divergent variants. They cannot be signed now as if
an embodiment had historically authored them; a later import witness must state
its actual current provenance and retain their HMK-native authority. This
procedure does not silently move that legacy content, private traces, skills,
authentication material, custody or capabilities. Skill package reconciliation
and binding are separately reviewable changes, preserving harness differences.

The deterministic regression uses two independently signed ledgers, DM-023
exchange/replay and the real pinned HMK CLI/SQLite effects. It checks separate
origin namespaces, rebuild isolation, sibling corrections and rejection of
missing/substituted content. It proves this boundary, not a live two-host
operational acceptance or a completed reconciliation of legacy pools.

## Repair

`retract` removes a row from retrieval while retaining provenance, last statement
reference and audit history. `rebuild-plan` and `rebuild-apply` are deliberately
two-phase and operate on one exact namespace and checkpoint. Source checkpoints
cannot regress; an equal checkpoint sequence with a different hash is a fork, and a
repeated idempotency key with different request bytes is a conflict.
