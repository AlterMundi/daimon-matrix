# DM-138 — bounded execution core implementation review record

Status: **implementer self-review and test evidence; independent review pending**.
This record does not close #138 or certify installed Codex/Hermes integration.

## Scope and provenance

- Worktree: `/home/debian/dm-milestone2-issue138`.
- Base: `acb131f18c200bb028ee86fa3a8ef9a2f6c040a3`.
- Supplied accepted claim: `2835e208-9e56-4fd9-9cfe-4eec996615ba`.
- Shared core, execution schema, focused tests and documentation only; plus the
  parent's explicitly requested existing Codex schema-parser correction inside
  `codex_body.py` / `test_dm040_codex_body.py`.
- No generated inventories, profile policies, schema pins, messaging stores,
  services, dependency installations, real model runs, real credentials,
  GitHub writes, commits or pushes. Existing regression tests ran isolated
  synthetic subprocesses/temporary runtime fixtures, not installed services.

## Implemented and checked

| Boundary | Evidence |
|---|---|
| Human authority, not an origin/boolean | Ed25519 complete-payload verification; wrong key, purpose, tampered payload, replay and `human=true` negatives |
| Finite, closed instruction | Runtime validation and public JSON Schema; explicit window, revision/predecessor, exact scope, provider/model/task digest and budgets |
| Passive proposals / absent permission | Empty/pending journal produces zero fake inference/native calls |
| Immutable cancellation/renewal | Signed cancellation tombstones; fresh predecessor-bound signed renewal; old revisions and stale predecessor rejected |
| Durable concurrency | Real SQLite reopen, two OS processes racing for a slot, common manual/periodic session fence |
| Crash uncertainty | Child process exits during dispatch after durable intent; reopened store retains unresolved operation and refuses later slots |
| Dispatch cancellation ordering | Real SQLite transaction lock against concurrent signed cancellation; post-cancel guard denied |
| Deadlines | Absolute end, queue delay crossing end, monotonic deadline and rollback; wall-clock rollback latched across reopen |
| Scope / grant mediation | Exact scope rejection, separately revoked communication authorization, native budget exhaustion, host token forgery rejection |
| Cancellation under clock fault | Signed cancellation remains durable and returns its cancellation receipt without requiring a valid clock |
| External Codex schemas | Genuine 275-file generated bundle matches unchanged pinned digest after parser repair; finite float/Unicode fixture, duplicates/nonfinite/invalid JSON negatives |
| Matrix artifact separation | Existing signed-artifact JSON loader still rejects `0.0`; external parser is not reused by signed-artifact code |

Initial missing-capability tests and the genuine Codex parser regression were
run RED before implementation and GREEN afterward. Additional regression tests
exercise existing implemented invariants. The supplied environment has no
pytest; tests use the repository's unittest style without installing anything.

## Verification commands and outcomes

With `/home/debian/dm-milestone2-test-venv/bin/python`:

```sh
CODEX_GENERATED_SCHEMA_ROOT=/home/debian/dm-milestone2-codex-probe/schema \
PYTHONPATH=src python -m unittest tests.test_execution_instruction \
  tests.test_execution_store tests.test_passive_messaging_execution \
  tests.test_dm040_codex_body -v
```

Outcome: **48 tests run, 2 existing private/live smoke tests skipped**, all other
tests successful. The genuine generated-schema test was enabled and passed.
The skips were the private installed-binary smoke and the opt-in real Codex
Matrix body smoke; neither was bypassed or relabeled as passing.

```sh
PYTHONPATH=src python -m unittest tests.test_native_messaging -q
```

Outcome: **48 existing native-messaging regression tests passed**. This is a
regression check, not new invocation-counter evidence for real harnesses.

Focused Ruff checks passed for all changed Python files; strict mypy passed for
the four new core modules and modified Codex module (five source files).
`git diff --check` and the operator module's real `--help` invocation passed.
Full-suite clean-wheel qualification and DM-041 generated inventory updates
remain with the parent integrator and are not asserted here.

## Security/integration limitations retained explicitly

1. **No human frontend deployed.** The configured public keys must belong to an
   isolated independently authenticating frontend. The CLI consumes proofs; it
   does not authenticate a human by UID, chosen key file or an approval flag.
2. **No real runner implemented.** The bounded fake runner proves the common
   gate only. Existing Codex policy remains six-tool/proposal-only and cannot
   be relabeled a restricted native-messaging execution profile.
3. **Adapter enforcement remains required.** Token budgets, provider/model
   selection, hard timeouts, exact native payload destination, communication
   policy, and exclusive credential/tool routes must be enforced by trusted
   adapters. The controller is not a sandbox or background watchdog. Authorized
   callbacks must be bounded and non-reentrant into the journal.
4. **Intent is uncertain, not retryable.** `intent`/`ambiguous` sessions remain
   single-flight blocked even across renewal. `finish` is an isolated trusted
   adapter API requiring evidence of exact-turn/effect settlement, not a model
   completion flag. No recovery API for lost capabilities or clock faults was
   invented; those cases remain blocked pending reviewed reconciliation.
5. **One inference per cycle.** No arbitrary model loop or additional provider
   request is silently included. The allowed native operations consume the
   approved per-cycle submission budget. Multi-inference support requires an
   explicit contract successor.
6. **Cancellation order is transaction order.** Already admitted bounded
   submissions may finish before the cancellation transaction acquires the
   lock. Already transmitted remote effects cannot be recalled. Technical
   receipts, model review and semantic completion remain distinct.
7. **Persistence assumes owner isolation.** Signature revalidation detects
   request mutation, but SQLite is not tamper-proof against its owner and an
   old whole-store snapshot is not trusted recovery. Never expose the journal,
   trust keys or arbitrary Python/native-client credentials to the model.

## Codex parser repair, separately bounded

The parent supplied a credential-free public schema bundle generated from its
exact npm 0.146.0 probe. The old loader passed vendor JSON Schema through Matrix
canonicalization and failed on finite float schema constraints. The new
`_normalized_external_schema` parser rejects duplicate keys, invalid Unicode,
invalid/nonfinite JSON and oversized documents, while sorting JSON keys with
UTF-8/`ensure_ascii=False` and compact separators. Path/NUL framing and the
existing schema count/hash checks remain unchanged.

The full genuine bundle now returns the unchanged tuple:

```text
275
146a56d701ccd97a76ad1a461d51fc454f32df6c5b4d338ea65968331ccc8b7a
```

No compatibility successor or new pin is needed **for this parser defect**.
A review-runner/profile successor remains separate work. Exact follow-up
repository and public generated-schema paths are listed in
`docs/bounded-human-execution.md`.
