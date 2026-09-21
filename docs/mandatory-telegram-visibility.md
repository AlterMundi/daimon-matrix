# Mandatory Telegram visibility — independent V2 primitive

## 1. Status and scope

This is an **unactivated library slice of issue #137**, not completion of that
issue, an installed application policy, participant consent, or evidence of live
Telegram/native delivery. The owner-selected rule is:

> Durably queue new logical communications. No corresponding native delivery
> before complete confirmed Telegram echo. Unavailable or ambiguous outcomes
> never unlock delivery. Passive storage remains available without a model.

`mandatory_echo.py` supplies a native-transaction-compatible journal, bounded
one-part worker, and exact-binding confirmation check. `telegram_mirror.py`
adds independent V2 plaintext rendering, response validation and HTTPS transport.
Existing `MirrorMessage`, `SharingBinding`, `render_parts`, and `TelegramMirror`
V1 behavior remain unchanged. **V1 integer progress is not V2 proof.** No code in
this slice wires an existing native egress path to the new barrier.

RFC 2119/8174 MUST/SHOULD requirements below are integration requirements unless
explicitly identified as implemented. Schemas are
`schemas/messaging/v2/visibility-policy.schema.json` and
`schemas/messaging/v2/echo-proof.schema.json`; they do not modify historical V1
application contracts or #132-owned schemas.

## 2. Exact projection and closed communication registry

The trusted native producer supplies this exact object (no extra keys):

- `event_id`, `event_digest`: immutable native logical event ID and lowercase
  64-hex digest, authenticated by the runtime resolver. The primitive does not
  invent native event hashing or verify native signatures itself.
- `sender`: exact origin/being/embodiment identity descriptor, not a display name.
- `recipients`: exactly one exact identity descriptor. Fanout/group is rejected
  in this version, not silently exempted.
- `thread_id`: exact application correlation.
- `reply_to`: `null` for `message`; otherwise exact `{event_id, event_digest}`.
- `kind` and its closed `content`:

| Kind | Exact content | Meaning / downstream duty |
|---|---|---|
| `message` | `{text: string}` | Complete human-authored/free-form communication. |
| `reply` | `{text: string}` | Complete reply, with mandatory referenced event. |
| `semantic-receipt` | `{outcome: received\|accepted\|rejected}` | Recipient-authored semantic statement; parent must map the final #132 carrier without conflating transport intake and understanding. Unsupported #132 outcomes must be rejected or obtain a reviewed successor registry, never lossy-mapped. |
| `transport-result` | `{stage: evidence\|message, outcome: accepted\|refused}` | Safe result projection correlated to the logical event; no envelope, MAC, capability or raw protocol response. |
| `authorization-control` | `{stage: evidence-before-message}` | Safe declaration of the correlated authorization/evidence stage. Fresh native carrier must later validate against this exact semantic projection. |

Opaque identity/event/thread strings are nonempty, at most 256 Unicode scalar
characters. The parent MUST resolve the actual native descriptor format and
include every authority-bearing identity component; aliases/labels do not
satisfy that contract. Text is nonempty and at most 65,536 UTF-8 bytes. Lone
surrogates, unsupported kinds, unknown fields, attachments, raw secret/control
payloads and arbitrary metadata are rejected. There is no prose secret detector:
free-form text is externally visible by contract and may not contain secrets.

The representation is `plain-json/v2`: Python JSON serialization with
`ensure_ascii=False`, `sort_keys=True`, `indent=2`, no normalization/truncation.
It displays the **entire projection**, including content, identity and digest
correlations. JSON escaping is reversible and is not a content summary. The
resulting document must fit 98,304 UTF-8 bytes and 32 parts. Each chunk has at
most 3,000 UTF-16 units and a deterministic header:

`Daimon Matrix visibility v2 · part i/n` followed by newline and chunk.

Concatenating chunks without the first header line and decoding JSON reproduces
the exact projection. Astral characters are never split. Telegram `parse_mode`
and caller-supplied entities are absent; link previews are explicitly disabled.
Returned text must equal the complete expected part. Only bounded automatic
plain-text entities (`mention`, `hashtag`, `cashtag`, `bot_command`, `url`,
`email`, `phone_number`) are accepted; hidden links/custom formatting are not.
If Telegram normalizes an unsupported input, it fails closed as ambiguous.

Transport bookkeeping, the local echo journal/state and Telegram's HTTP/TLS
framing are **not newly authored inter-daimon logical messages**. There is no
`control=true` bypass: `echo-status`, Telegram-origin kinds and unknown kinds
are rejected. The parent resolver MUST exclude reflected observation-edge events.
No Telegram ingress, polling, commands, webhook or model wakeup exists here.

## 3. Fixed policy, trust and retained evidence

`daimon-visibility-policy/v2` is an exact object containing `generation`,
`origin`, numeric `bot_id`, nonzero numeric `chat_id`, explicit `topic_id`
(integer or `null`), `representation: plain-json/v2`, `acceptance_digest` and
`proof_key_id`. Generation/bot/chat magnitudes are below 2^52; topics are positive
and below 2^31. Origin and proof-key identifiers are at most 128 characters.
The schema field is required. There are no token, destination override, per-send
visibility switch or private-key fields. The parent MUST authenticate this policy
through its signed successor application, participant disclosure/enrollment and
current manual revocation checks. A digest alone is not consent. No fabricated
far-future expiry is used; transport freshness remains a separate contract.

The journal receives a **runtime-only 32-byte purpose-specific authentication
key**, loaded by an independently reviewed parent custody adapter. The key is
not read, generated, persisted, exported, or exposed through any model API here.
`proof_key_id` MUST select that exact runtime key in the signed application;
passing arbitrary caller-selected keys is forbidden. There is no public signing
method, raw signer tool or model-facing journal/transport constructor.

Canonical journal encoding is UTF-8 JSON with sorted keys, `ensure_ascii=False`,
compact separators, and `allow_nan=False`. Duplicate keys/noncanonical persisted
encoding fail closed. `binding_digest` is SHA-256 over that encoding of
`{operation_id, policy, projection}`. The entire record except `authentication`
is HMAC-SHA256 authenticated under `b"daimon-echo-proof/v2\0"`. It includes:

- schema, catalog identity and revision;
- complete policy, projection, operation identity and binding digest;
- the complete **ordered** array of exact part strings; array order and length
  bind part index/count (not independently editable hash/count columns);
- each persisted UUIDv4 attempt ID, exact request digest, intent/response times,
  retained UTF-8 Bot API response (positive acceptance or explicit rejection),
  or `null` for unresolved intent, and any verified owner retry decision/evidence.

Request digests use the same canonical encoding over the complete `sendMessage`
JSON object. Revalidation recomputes the projection/parts and request digests,
checks the closed shape, unique attempt IDs, contiguous completed prefix and
revision, and revalidates every retained response. Schema compliance and
`validate_proof_shape()` are **not authentication or release authority**.
`require_confirmed()` checks the private runtime MAC, independently supplied
expected binding, complete transcript and current authorization.

Responses require exact bot identity with `is_bot: true`, exact numeric chat,
positive numeric Message ID below 2^52, complete expected text and exact topic
semantics. Explicit no-topic rejects any returned `message_thread_id` or true
`is_topic_message`; explicit topic requires its ID and `is_topic_message: true`.
Booleans cannot alias integer identities. JSON duplicate keys, NaN, malformed,
oversized, truncated or inconsistent responses do not confirm anything. Extra
Telegram Message metadata is retained inside the bounded private raw response,
not interpreted as authority or included in the public projection.

`PlainTelegramTransport(token=..., bot_id=..., chat_id=..., topic_id=...)` uses
TLS-validating urllib to the fixed `https://api.telegram.org/.../sendMessage`
origin, no redirects or ambient proxies, and a **10-second monotonic total HTTP
budget**, in addition to the 10-second socket inactivity timeout. A private,
stdlib-only subprocess performs DNS, connection/TLS, request, headers/framing and
body reading. The parent includes startup and IPC in the total budget and kills
and reaps the executor before returning on timeout or interruption. This is not
an abandoned-thread/future timeout. OS process creation/reaping and scheduling
can add latency; if quiescence stalls, the execution guard stays held rather than
silently releasing it. Linux `PR_SET_PDEATHSIG(SIGKILL)` plus a post-install
parent-PID check prevents a hard-crash orphan from continuing HTTP. The Darwin
candidate instead gives the fresh executor a private controlling terminal:
the parent exclusively owns its master, so parent exit hangs up the executor's
foreground session. The executor restores and unblocks SIGHUP and verifies its
parent after attachment, before HTTP. This is fresh exec, not `pty.fork()` or
Python `preexec_fn`. The terminal never carries request bytes. Unsupported
platforms or unavailable death coupling fail closed before network. Forced
process/host loss still requires the parent's runtime recovery/quiescence policy,
not treating lock availability as remote cancellation.

The decoded response limit is 65,536 bytes; cumulative consumed plaintext HTTP
bytes, including headers, chunk extensions and trailers, are capped at 262,144.
The child receives only the bounded request and URL through a private pipe, not
argv/environment or a job file. It inherits no journal/guard descriptors or
ambient environment and emits no exception diagnostics. The composing installation
must provide a trusted executable `sys.executable`, immutable real-file module
path and qualified platform lifetime support. On Darwin the host must not
duplicate the terminal master or retain it in a raw-fork child: CLOEXEC and
explicit descriptor passing prevent inheritance across ordinary exec, not an
arbitrary embedding process's raw fork. The Matrix host does not raw-fork.
Zipped/frozen distributions and other platforms are not qualified by this slice.
The dedicated portability workflow tests real local HTTP, deadlines, process
interruption and hard parent death on Linux and macOS ARM64. Its exact-head
result is required before claiming Darwin qualification; Linux PTY success alone
does not establish it. This does not qualify Intel dependency installation,
Hermes attachment, participant onboarding or a live Telegram conversation.
The legacy V1 selective adapter remains Linux-only (`/proc/self/fd` SQLite
opening); it is not used by V2 mandatory echo and is tested only on Linux.
No new public configuration,
model capability or transport destination selector is introduced.

Explicit negative HTTP/Bot API responses are returned only after their exact
rejection shape and matching HTTP status are validated. Construction does no
network; fixed `getMe`/access verification belongs to authorized parent setup.
Request/response exceptions are sanitized. It returns only a locally validated
raw response, not a signed Telegram receipt. Neither local executor termination
nor a timeout proves the remote operation stopped. Timeout leaves durable
ambiguity and never grants an automatic retry.

A retained authenticated result proves what the trusted runtime observed over
its trusted transport. It establishes **platform acceptance**, not human reading,
Telegram-signed portable proof, native adoption, or exactly-once delivery.
Runtime/owner/root and the installed callbacks remain trusted. Authentication
detects row edits and swaps without the key, but does not prevent whole-store
rollback, deletion followed by unauthorized fresh admission, or compromised
runtime/key forgery. Independent monotonic witnesses are not implemented.

## 4. Integration API and exact transaction order

The primitive never opens a SQLite path, creates a polling database, enumerates
an inbox, opens native custody, dispatches native I/O, or starts a service.

### Initialization and reopen

1. The parent MUST use its existing native outbox connection, owner-only protected
   path/ancestors and companions, descriptor-safe open/reopen, bounded SQLite busy
   timeout and full global schema validation. `isolation_level=None`, explicit
   transactions, `journal_mode=DELETE`, `synchronous=FULL` are the tested contract.
   A connection must not be concurrently shared between threads. SQLite 3.11+
   Python support alone does not certify the filesystem or SQLite build.
2. Under its existing runtime/migration lock and `BEGIN IMMEDIATE`, an **explicit
   signed successor migration** calls
   `EchoJournal.initialize(db, catalog_id=..., authentication_key=...)` once.
   This adds exactly the two tables in exported `TABLE_SQL`, plus their SQLite
   automatic primary-key indexes. Initialization never commits. The parent MUST
   roll back the whole migration if initialization or its own catalog update
   fails, then fsync/commit the validated whole generation through its normal
   durable publication protocol. Never catch initialization failure and commit
   partially created tables.
3. Reopen with `EchoJournal(db, catalog_id=..., authentication_key=...)`. This
   does no DDL. Missing/changed catalog, wrong key/catalog identity, unsupported
   SQLite durability mode, additional owned tables/indexes/triggers, or absent
   required tables fail closed. It does not initialize an empty replacement.
   A static catalog MAC uses `b"daimon-echo-catalog/v2\0"` and binds catalog ID
   and exact `TABLE_SQL`; it is not an anti-rollback counter.

### Atomic logical admission

Within the parent's **same native `BEGIN IMMEDIATE` transaction**:

1. Check current client/channel/native/visibility authority and representability.
2. Reserve the stable native operation ID, complete immutable request/payload and
   deterministic Ledger operation IDs. Do not create a short-lived native
   transport wrapper at this stage.
3. Call `binding_digest = journal.admit(operation_id, projection, policy)` and
   persist that digest with the native operation. It does not commit. An exact
   existing obligation is idempotent; conflicting binding or corrupt evidence
   fails closed. Capacity failure must roll back native admission too.
4. Commit the linked native admission/obligation. Reconcile idempotent Ledger
   append through the native reservation protocol if its separate DB commits
   later; the resolver must refuse an unlinked or unauthenticated logical event.

The parent MUST enforce its `(origin, client, send-id)` uniqueness and operation
catalog: an already-admitted native operation missing its echo row is damaged
state, not permission to call `admit` afresh. Startup MUST reconcile all expected
native operations against obligations; this library does not know the parent's
native table name and cannot discover deleted rows on its own. Backup/restore
must preserve native catalog, immutable Ledger links, echo data and key selection.

### Worker, inspection and native release

Construct runtime-local:

```python
worker = MandatoryEcho(
    journal,
    transport=transport_or_none,
    resolve=authenticate_retained_native_projection,
    authorize=check_current_exact_binding_authority,
)
```

`resolve(operation_id)` returns the independently authenticated exact retained
projection. `authorize(binding)` must return the actual Boolean `True` only
after checking current body/fence, origin, client/channel, exact recipient,
policy generation/audience, key selection and participant acceptance. It receives
a detached complete binding copy. These are trusted non-model callbacks, not
caller configuration or Boolean confirmation supplied by a sender.

- `advance(operation_id, expected_binding_digest)` performs **at most one part**.
  Use no active parent SQL transaction. A short `BEGIN IMMEDIATE` loads and
  authenticates history, checks current authority, and commits exact intent
  before HTTP. It rechecks authority after intent commit, then calls transport
  outside the SQL transaction. Competing connections observe unresolved intent
  and cannot issue another send. The verified response is stored in a second
  short transaction only if the complete authenticated prior record still
  matches. Confirmation is derived **after** that commit, never from a status
  flag or unverifiable response hash.
- `inspect(operation_id, expected_binding_digest)` performs no I/O effects,
  authenticates retained evidence and checks current authority. It returns only
  `{state, confirmed_parts, part_count, binding_digest}`. The states are `queued`,
  `ambiguous`, `confirmed`. Invalid storage/authentication or blocked current
  authorization raises a stable `EchoError`; it is not confirmation.
- `require_confirmed(operation_id, expected_binding_digest)` repeats the evidence
  and current-authority checks and returns the retained authenticated record only
  when every part has validated response evidence. It raises otherwise. Returned
  records contain disclosed content/private operational evidence and MUST NOT be
  dumped into logs/model RPC results. The result is **not a reusable bearer grant**.

The parent MUST load expected operation/binding from its authenticated native
catalog, never take a caller's digest as sufficient authority. Immediately before
**each** native phase/provider/fallback or result release, it must call the gate
under its current runtime fence and bind the actual outgoing operation to the
returned full binding. A stale `inspect.state`, copied proof dict or Boolean
callback is never an egress capability. Current-authority checks are separate
from historical response validity; revocation does not erase retained evidence.

### State and crash behavior

| Boundary | Implemented result |
|---|---|
| No transport configured before attempt | Remains queued; no HTTP and no native release. |
| Partial complete prefix, next part never attempted | Queued; next call sends only the next part. |
| Intent persisted, process dies before HTTP | Ambiguous conservatively; never blind replay. |
| Remote success, lost response / invalid response / process death before response commit | Ambiguous; exact attempt/prefix retained; no native release. |
| Validated response committed, lost local return | Reopen revalidates evidence and confirms without reposting completed parts. |
| Current authorization revoked between parts or before native release | Stable blocked error; retain exact evidence, no new I/O. |
| Pending status changed to success, hashes recomputed, proof/part swapped | Authentication/exact binding/transcript reject. |
| Missing table/catalog/operation/proof, wrong key, unexpected schema, disk full | Fail closed; no silent initialization, eviction or success. |
| Concurrent worker / caller retry | Durable intent plus short transactions and exact-record comparison; no second HTTP claim. |

### Verified rejection and owner-approved ambiguous recovery

`classify_plain_response` distinguishes exact positive platform acceptance from
explicit Bot API rejection. Only strict `ok:false` responses with error codes
400/401/403/404/409/429, bounded description and optional exact
`parameters.retry_after` are demonstrably rejected admission. The real HTTP
transport additionally checks that the HTTP status equals the error code. The
full bounded raw response is retained and runtime-authenticated. A 5xx, unknown
shape, redirect, timeout, malformed/truncated result or changed-destination hint
is **ambiguous**, never assumed rejected. No token or raw failure body appears
in returned errors. `transport=None` means known pre-I/O unavailability and
creates no attempt.

A rejected attempt leaves the obligation queued, with no native release. A
subsequent `advance` retries the exact part only after the retained rejection's
backoff: default 30 seconds, or validated integer `retry_after` from 1 through
86,400 seconds. Each attempt records `at_ms` and `response_at_ms`; the injected
runtime `clock` must be trustworthy and returns nonnegative milliseconds below
2^52. Backwards time fails closed. Every old rejection/attempt is retained.
Successful parts are never resent. There are at most **four attempts per part**;
exhaustion raises `echo_attempt_limit` and requires an explicit reviewed capacity
recovery/migration, never deleting prior evidence or pretending confirmation.

For genuinely ambiguous attempts the core exposes
`retry_ambiguous(operation_id, expected_binding_digest, authorization_bytes)`.
This is **owner/runtime-only**, not a model-facing retry flag. Construction must
supply BOTH:

- `verify_retry(raw_bytes, exact_binding, prior_attempt_id) -> RetryDecision | None`:
  a trusted verifier of a purpose-specific independently authenticated owner
  command. The raw command is bounded to 8,192 bytes. A Boolean, unverified
  dictionary or exception does not authorize retry. The returned frozen
  `RetryDecision` has exact fields `authorization_id` (UUIDv4), `actor`,
  `operation_id`, `binding_digest`, `attempt_id` (the exact unresolved prior
  attempt), `approved_at_ms`, `expires_at_ms`, and
  `risk: duplicate-platform-post-accepted`. The approval must be current at
  intent creation, with a positive interval of at most 60 seconds. This deadline
  is anti-replay for the owner command, not expiry of messaging permissions.
- `execution_guard() -> context manager`: the parent's shared, owner-local
  **cross-process runtime execution/quiescence lock**. The same non-expiring
  lock must cover ALL workers and manual retry instances for this native store.
  `advance` and `retry_ambiguous` both hold it across intent, HTTP and response
  commit. It is not a SQLite transaction and must not block passive intake. A
  socket timeout does not cancel remote work; the guard only fences local
  executors. The owner's decision explicitly acknowledges residual duplicate
  platform-post risk. Supplying different/no-op guards in production is invalid
  composition. Without both capabilities, recovery is unavailable. Standalone
  worker tests without recovery can rely on durable single-flight intent alone.

The core revalidates exact content/audience/current authority, verifies the owner
command while fenced, then samples trusted time again after verification. Expired
(including boundary equality) or backwards-time decisions fail without a new
attempt or HTTP. The fresh sample is the admitted attempt timestamp. Every
candidate transcript is structurally validated before persistence; reuse of an
already-retained decision ID cannot poison the journal or reach HTTP. Exact
admitted-command replay remains a no-I/O historical return.

The core records the full decision plus base64-encoded command
in `retry_authorization` on the new attempt **before HTTP**. Old ambiguous and
completed attempts stay intact. The entire trail is runtime-authenticated. The
core does not expose a raw signer or decide owner authority from the command
body; the installed verifier must pin the actual owner authority and purpose,
check the signature and command/actor bindings, and reject cross-purpose replay.

Replaying the identical admitted command after a crash/lost return returns the
existing state; it never starts another HTTP attempt, even if the command later
expires. An unresolved new attempt requires a NEW current decision naming that
new attempt. Historical approval is revalidated structurally under its original
attempt time and journal MAC, not treated as permission for fresh I/O. There is
no `mark_confirmed` or reconciliation shortcut that bypasses a newly validated
Telegram response. Success after retry may have duplicated a remote post and
never claims exactly-once delivery.

Fixed limits: 4,096 retained operations; 4 MiB encoded record; 64 MiB total encoded
records; 32 parts; four attempts per part; 65,536 response bytes per attempt;
8,192 bytes per owner authorization. Limits never evict history. Filesystem
and native outbox quotas/reserved control capacity belong to the parent. A
capacity/commit failure after remote acceptance may leave an ambiguous intent;
it cannot be silently upgraded to success. No fictitious Bot API `getMessage`
is used.

## 5. Concrete parent obligations before activation / issue closure

All of the following remain **unimplemented by this slice**:

1. Reconcile final #132 semantic carrier/outcome contracts and obtain accepted
   successor scope for overlapping messaging/store/config/service/routes/daemon
   files and exact generated inventory paths. No V1 historical evidence may be
   relabeled echo-before-delivery.
2. Split native logical admission from fresh transport authorization/evidence
   generations. Queue longer than the current 60-second wrapper lifetime without
   changing signed logical bytes or reusing expired wrappers. Preserve exact
   native duplicate history across generations and ambiguous native intake.
3. Add these two tables to the signed native store migration/catalog and atomically
   link every admission/control obligation. Protect paths/companions, expected
   operation inventory, rollback/recovery, quota reservation and policy/key binding.
4. Wire a bounded non-model worker into the existing daemon, with fairness,
   pre-I/O availability checks, queued retry scheduling, shutdown/quiescence and
   no receiver locks held during HTTP. Integrate the core recovery seam through
   a reviewed owner-only command verifier/operator interface and ONE shared
   cross-process execution guard. Show exact duplicate-risk disclosure and
   preserve decision evidence; never expose this seam as a model retry flag.
5. Gate **all** native egress: send/reply, semantic receipts, evidence and message
   phases, generated transport results/ACKs, cached responses, fresh generations,
   direct/hub/local/fallback providers and runtime resume. Disable/reject generic
   `route.submit`, direct `send_prepared`, peer/sync/source or future unclassified
   surfaces until they have exact-operation gates. One supported path bypassing
   the barrier means #137 is not complete.
6. For inbound transport results: commit passive intake and a bounded recoverable
   result/echo obligation without holding the receiver transaction or occupying
   unbounded HTTP workers. Withhold semantic native result release until its echo.
   Design historical-result/fresh-wrapper convergence across expiry without
   creating a new logical event. A generic infrastructure error must not leak an
   unconfirmed daimon outcome.
7. Authenticate exact participant all-communication disclosure, fixed bot/chat/topic
   access (`getMe` included), signed application and purpose-specific runtime key
   custody. This constructor does not perform those ceremonies. No production
   key/token or service change is authorized by these source tests.
8. Freeze source, reconcile DM-041 module/package hashes and exact expected module
   counts under accepted successor scope. The full-suite run identified additional
   **literal paths that must be claimed**, not just generated vector files:
   `tools/reproducible_build.py` (`BUILD_INPUTS`),
   `tools/check_distribution.py` (`SDIST_FILES` / `WHEEL_FILES`),
   `tests/test_package_scaffold.py`, and `tests/test_dm041_hermes_body.py`.
   The isolated slice has 59 modules against the baseline's asserted 58; derive
   the final integrated count and explicitly assert all new modules rather than
   weakening closed inventories. Merely tracking/committing the new file does
   not fix the build-input omission: the builder copies its explicit list.
   Regenerate only authorized inventories, run full supported-Python and actual
   installed-wheel gates, and obtain independent security/persistence review.
   Source self-tests are not independent approval.
9. Qualify the exact Matrix+Cluster installed pair and run separately authorized
   actual-destination acceptance (expected text and bot/chat/topic/message IDs),
   native-before/after ordering, outage longer than transport TTL, passive receive,
   both directions, duplicate ingress, restored state, revoked authority and
   zero model/harness calls. This implementation did no real Telegram calls.

## 6. Acceptance evidence supplied by this slice

The two focused test modules exercise real SQLite files/connections; a local
HTTP server through the actual urllib transport (test-only URL interception,
no credentials); strict plaintext and topic/bot/content evidence; raw HTTP
truncation; atomic admission rollback; process death after received/validated
response but before persistence; committed-proof lost return; completed prefixes;
competing connections; verified HTTP rejection/backoff/recovery; owner-authenticated
ambiguous retry and command idempotence after lost return;
status/hash/identity/destination/proof tampering; missing
catalog/state; quotas and sanitized failures; current authority; closed control
kinds; V1 compatibility; and public schema validation.

The primitive tests do not call native provider/service functions. Whole-runtime
egress completeness, installed provenance, live visibility, human consent,
independent review and deployment therefore remain parent acceptance gates.

### Historical initial slice author-run validation (before independent review)

Worktree: `/home/debian/dm-milestone2-issue137`; branch
`issue-137-mandatory-telegram-echo`; unchanged HEAD
`acb131f18c200bb028ee86fa3a8ef9a2f6c040a3`. No commits or staged changes.
The shared `/home/debian/dm-milestone2-test-venv/bin/python` was used read-only
with `PYTHONPATH=src`. The full suite used
`COLLECTIVE_MEMORY_CONTRACT_ROOT=/home/debian/dm-milestone2-collective-contract`.

- Focused `unittest tests.test_mandatory_echo tests.test_telegram_mirror -q`:
  **36 tests passed**, including `-W error::ResourceWarning`.
- Scoped Ruff check/format and `git diff --check`: passed.
- `MYPYPATH=src python -m mypy src`: passed across 59 source files.
- AST comparison against HEAD: all eight existing V1 module declarations and
  the original `MirrorTests` class unchanged.
- `tools/generate_dm041_vectors.py --check`: expected drift in
  `provenance/hermes-agent-0.19.0.json`,
  `vectors/hermes/v1/valid/profile-manifest.json`,
  `vectors/hermes/v1/valid/launch-receipt.json`, and
  `vectors/hermes/v1/index.json`; all left untouched.
- Full discovery: **805 tests run, four failures, 22 skips**, 835.636 seconds.
  Failures were the DM-041 module-count and provenance checks plus the package
  closed-inventory count and actual-wheel import checks. The latter proves the
  new module is absent from the explicit build lists. These are real unresolved
  parent packaging/inventory gates, not a passing full suite. The process also
  emitted temporary-directory cleanup `ResourceWarning`s at shutdown.
- Broad `ruff check src tools tests`: 153 inherited findings in seven files;
  every affected file was byte-compared with HEAD and was unchanged. No scoped
  file had a lint finding. Unrelated legacy lint was not repaired here.

The full-suite process was `proc_623a4a1a611c` (exited 1). Its build fixture used
an isolated temporary build environment; no shared parent-venv packages were
changed. This is author verification, not independent review or installation
qualification. Source and schema writers are frozen for parent handoff.

### Corrective freeze after independent findings R1–R3

This is **author fix verification**, not independent approval. Uncommitted delta
on unchanged HEAD `6b34a9121a7b0c90af6e259665a72b9711189336` in the same issue-137
worktree. Parent-supplied accepted claim
`13fe3ecd-4a25-4b35-bc41-75c8bfde933b` covers the exact seven primitive paths;
this correction changes only this document, both primitive modules and their
two test files. Neither schema changed. No credentials/session key, GitHub,
services, shared inventories, native integration, commits or pushes were used.
The shared test interpreter was used read-only.

Independent source evidence (left unchanged):
`/home/debian/dm132-live-exchange/ISSUE137-CORE-INDEPENDENT-REVIEW.md` and
`/home/debian/dm132-live-exchange/review137_independent_probes.py`.
The original probes were executed before edits: **8 tests, 3 failures, exit 1**,
15.961 seconds. Observations: stale approval caused a second POST and stored
1000 ms while current time was 3000; reused authorization ID caused three POSTs
and three retained attempts; slow body confirmed after 12.031886 seconds.

Corrections and regressions:

- **R1:** fresh trusted time after verification while inside the execution guard;
  expired equality, expiry during verification, backwards time, actual threaded
  guard contention and last-valid-millisecond acceptance are covered. Rejected
  commands leave byte-identical state and no transport calls.
- **R2:** every `_write` validates the complete candidate transcript before any
  SQL mutation. Duplicate decision IDs are rejected before HTTP, with unchanged
  valid state; exact admitted evidence replay after expiry and a new-ID recovery
  still work. Complete authenticated response/history validation remains intact.
- **R3:** isolated kill-and-reap HTTP executor, total monotonic deadline, bounded
  raw framing as well as body, and Linux parent-death coupling. Tests use real
  loopback HTTP for slow headers, body and chunk-extension framing, excessive
  chunk trailers, content-length and chunked success, truncation and rejection.
  A deliberately stalled resolver in the real child proves pre-open coverage.
  Thread contention verifies the child has exited before guard release and a
  different operation progresses afterward. Interrupt and actual parent SIGKILL
  probes check local executor cleanup; the parent-death probe was first observed
  failing before adding death coupling. No timeout grants retry authority.

Frozen verification:

- `PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src` with the shared interpreter,
  `-W error -m unittest tests.test_mandatory_echo tests.test_telegram_mirror -q`:
  **43 tests passed**, 10.304 seconds, exit 0, no warnings.
- Scoped Ruff check and format check: passed; `git diff --check`: passed.
- `MYPYPATH=src python -m mypy src`: passed across 59 source files.
- Original eight independent assertions, replayed with only their loopback URL
  interception moved to the subprocess boundary: **8 passed**, 15.938 seconds,
  exit 0. Stale command: one POST/one retained attempt. Duplicate ID: two POSTs,
  two attempts, unchanged valid record. Default-budget drip: **10.018438 seconds,
  ambiguous**, one POST. The original server logs an expected `BrokenPipeError`
  because its drip handler does not catch client disconnect; this was not hidden
  or counted as pristine output. The maintained regressions catch that expected
  server-side disconnect. V1 AST equality and authenticated recovery, tamper,
  revocation, reopen and cross-process guard controls also passed.

The original probes' assertions and server were not edited. Reproduction adapter
(run from this worktree using the same interpreter and environment):

```python
import runpy
import unittest
from unittest.mock import patch
from daimon_matrix import telegram_mirror as t

m = runpy.run_path(
    "/home/debian/dm132-live-exchange/review137_independent_probes.py"
)
C = m["Probe"]
setup, exchange = C.setUp, t._plain_http_exchange

def wrapped(self):
    setup(self)
    self.intercept.stop()
    def local(url, payload):
        self.assertEqual(url,
            "https://api.telegram.org/bot123:SYNTHETIC_ONLY/sendMessage")
        return exchange(
            f"http://127.0.0.1:{self.server.server_port}/sendMessage", payload)
    p = patch.object(t, "_plain_http_exchange", local)
    p.start()
    self.addCleanup(p.stop)

C.setUp = wrapped
r = unittest.TextTestRunner(verbosity=2).run(
    unittest.defaultTestLoader.loadTestsFromTestCase(C))
raise SystemExit(not r.wasSuccessful())
```

Frozen source/test SHA-256 (this document is deliberately not self-hashed):

| Path | SHA-256 |
|---|---|
| `src/daimon_matrix/mandatory_echo.py` | `6c48fbbb672228744ae487335ce415204ae7967611a345800ff8adebc61da189` |
| `src/daimon_matrix/telegram_mirror.py` | `035fefa0608ece7e0f907680b4a5b488aa957ac2165d57421bc3cfcf36a6d88f` |
| `tests/test_mandatory_echo.py` | `f31896738c21860dc1027ce230df0b44a85d98b7c0521a88783ed9274d12ea8f` |
| `tests/test_telegram_mirror.py` | `4b39b354409d7dab93c13341a518a5ac2f09c480df5d0af887817337691cb915` |

**Integration caveats remain blocking:** verified durable queue, no native egress
until full echo confirmation; complete authenticated proof and retained history;
owner/runtime-only ambiguous recovery; no native integration is supplied here.
The shared paths listed in section 5 lack this claim's coverage and were not
edited. Full suite, packaging/inventory generation, installed wheel/pair and live
Telegram were not rerun in this corrective slice; the historical full-suite
failures remain unresolved, not waived. Qualify isolated-child execution, Linux
death coupling, immutable module/interpreter provenance and supervisor hard-kill
quiescence in the actual installed runtime. Total deadlines stop local work, not
already accepted remote work. Independent re-review of this exact delta is still
required before treating any finding as independently closed.
