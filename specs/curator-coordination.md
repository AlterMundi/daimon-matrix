# Resource-scoped curator coordination

Status: normative for `dm.curator.* /v1` and DM-031.

This contract describes the Daimon Matrix component. It does not use the
Matrix.org protocol. It replaces the obsolete idea of one exclusive Librarian
lease for an entire being with coordination over one concrete queue item or
one concrete Cluster resource.

## 1. Authority boundary

The coordinator may order work, reject stale workers, and retain who produced
a result. It cannot:

- create, rotate, borrow, or collapse `/me` identity;
- prevent other embodiments of the same being from being awake or curating a
  different resource;
- turn presence, reachability, a queue row, a process lock, or a curator claim
  into a Cluster resource fence;
- approve a human-review-required memory transition;
- make model output, a proposal, an adapter ACK, or an external row canonical
  memory; or
- replay an external success whose current intent, fence, or postcondition is
  contradictory or unavailable.

Matrix owns item meaning, local queue CAS, actor attribution and result
history. Cluster alone owns current resource-fence truth. DM-030 owns memory
policy and canonical memory execution. DM-033 owns purpose-limited human
review. Later projection/publisher adapters own their bounded effects.

## 2. Immutable item

`dm.curator.item/v1` is closed and content-addressed as
`dm:curator-item:v1:*`. It binds:

- the subject being;
- one exact `resource_ref`;
- work kind `memory-evaluation|memory-proposal|memory-projection|publication`;
- immutable input reference and SHA-256;
- coordination mode `queue-item|resource-fence`;
- required authority `daimon|human`;
- an external effect-intent hash only for `resource-fence`; and
- enqueue time.

The item carries references and hashes, not private content bytes, paths,
endpoints, credentials, prompts, or model transcripts. A changed input,
resource, mode, authority, or intent is a different item. A queue row is an
operational projection of these bytes and grants no authority.

## 3. Coordination modes

### 3.1 `queue-item`

This mode coordinates one logical task in one embodiment's owner-local Matrix
ledger. It uses SQLite `BEGIN IMMEDIATE` and a generation compare-and-swap. It
must not contain fence evidence or an effect receipt. Its completion records an
immutable output reference; it does not claim a shared external effect.

### 3.2 `resource-fence`

This mode coordinates a mutation of one concrete external/shared resource. An
item must bind the exact effect-intent hash. Claiming it requires
`dm.cluster-resource-fence-evidence/v1` for the same resource, body,
embodiment, and incarnation, accepted by an injected current Cluster verifier.
The lease cannot outlive the evidence.

The stored claim embeds only the derived closed fence position. That position
is historical evidence, not a renewable or transferable lease. Presence,
Matrix membership, matching names, old signatures, or a cached verification
cannot substitute for a current verifier result.

Independent Matrix ledgers do not pretend to provide distributed exclusion.
Cross-host mutation safety is the Cluster resource fence. Queue-item CAS is
local work coordination; it is not advertised as global consensus.

## 4. Claims and generations

`dm.curator.claim/v1` binds a canonical UUID, item/resource, strictly positive
generation, exact actor origin (`body_ref`, `embodiment_id`, `incarnation_id`,
`principal_id`), half-open issue/expiry interval, optional exact fence
position, and a content hash.

New items begin at generation zero. A successful claim increments the exact
current generation. Only the current claim/generation may complete. An expired
claim may be replaced through a new CAS, which increments generation again;
the old worker then fails even if its process, session, or embodiment remains
valid. Claims last at most 24 hours and never grant identity or human authority.

Different `resource_ref` values have independent rows and can progress
concurrently. Only an active item with the same exact resource blocks another
item locally. The terminal history remains inspectable while a later distinct
item may reuse that resource.

## 5. Results and human review

`dm.curator.result/v1` is content-addressed and binds the exact item, claim,
generation, actor origin, outcome, sorted output references, explicit human
review requirement, optional effect receipt, and completion time.

Outcomes are:

- `completed`: bounded automatic work/effect completed;
- `proposed`: immutable output exists but human authority is still required;
- `deferred`: prerequisites are incomplete or temporarily unavailable; and
- `failed`: this attempt ended without the requested result.

Only `completed` may carry an effect receipt. `proposed`, `deferred`, and
`failed` prove that no external effect is being claimed by that result.

An item with `required_authority=human` can never record `completed` through
DM-031. It may record only `proposed`, `deferred`, or `failed`; its queue state
remains visibly `review-required` after a proposal. DM-033 must later validate
and sign a separate content-bound human decision. The curator principal,
worker, model, MCP caller, OS account, GitHub identity, or queue claimant cannot
stand in for that decision.

Actor attribution is never reduced to a display name. Every claim and result
retains all four origin coordinates. A later publisher must carry those
coordinates into its decision and publication evidence.

## 6. Effect receipt binding

A successful `resource-fence` completion requires an exact
`dm.cluster-effect-receipt/v1`. Before storing it, Matrix requires:

- receipt intent hash equals the item's effect-intent hash;
- receipt actor equals the claim origin's transport principal;
- receipt fence position equals the claim's verified position;
- the injected observer returns the exact current intent and postcondition;
- the injected Cluster verifier accepts current evidence for the same holder,
  resource and epoch; and
- DM-037 reconciliation returns `verified`.

Missing observer/verifier/evidence is `effect-truth-unverifiable`, not success.
Changed intent, holder, epoch, evidence, actor, or postcondition is
`effect-truth-discrepancy` or a binding rejection. Neither state may serve a
cached success.

## 7. Durable retry and effect truth

Every mutating operation is journaled by authenticated client/request ID and
canonical request hash in the same transaction as its queue mutation. Exact
bytes return the exact stored artifact after restart. Different bytes under the
same operation identity return `curator_request_conflict`.

A second request ID cannot duplicate a terminal item. If its proposed result
is byte-equivalent apart from the original completion coordinate, it receives
the stored result and that second operation identity is durably journaled;
competing result bytes fail `curator_item_terminal`.

External-effect replay has an additional rule: the stored receipt is reconciled
against current observed truth before it is returned, including when the outer
authenticated RPC journal already contains a successful response. A later
contradiction produces a fresh typed error rather than replaying the cached
success. The immutable old receipt is retained; it is not rewritten as failure.

## 8. Crash and concurrency semantics

Queue mutation, generation advance, claim/result storage and the inner
operation journal share one SQLite transaction under `BEGIN IMMEDIATE` with the
ledger's `DELETE` journal and `synchronous=FULL` policy.

- crash before commit leaves no claim/result;
- crash after commit and before response is discovered by exact retry;
- concurrent generation-zero claimants produce one generation-one winner;
- expiry/reclaim produces a new generation and rejects the old worker;
- restart rebuilds inspection from durable item/claim/result rows; and
- no queue mutation appends or edits a canonical Weave event by itself.

The outer DM-024 RPC journal and inner coordinator journal deliberately overlap
at the response-loss boundary: an interrupted outer pending row re-dispatches,
while the coordinator returns the already committed semantic result.

## 9. Hosted interfaces

The authenticated owner-local runtime exposes four explicit methods:

- `curator.enqueue {item}`;
- `curator.claim {item_id, claim_id, expected_generation, lease_until_ms,
  fence_evidence}`;
- `curator.complete {claim_id, expected_generation, outcome, output_refs,
  effect_receipt}`; and
- `curator.inspect {item_id}`.

The typed client, `daimon curator ...` CLI, and MCP tools mirror these shapes.
Only inspect is read-only. MCP does not gain a generic method escape hatch or
human-decision capability. Runtime capabilities must explicitly list curator
methods; existing Cluster's exact five-method host capability is not expanded
implicitly.

## 10. Privacy, limits, and rollback

Artifacts are canonical JSON with closed fields, bounded strings, safe
integers, at most 256 output references, and no embedded private content. The
public vectors use synthetic IDs and postconditions. Logs, errors, receipts,
reports, wheel/sdist and conformance artifacts are secret-scanned.

Before use, unused tables/interfaces may be reverted. After items, claims, or
results exist, rollback preserves their bytes and generations. Do not delete a
terminal result to rerun an effect, lower a generation, revive an expired
claim, recast a proposal as human approval, or copy one writable coordinator
database between embodiments. Recovery restores the exact ledger and queue
state or rebuilds later canonical projections; it never fabricates effect
truth.

## 11. Normative scenarios

The release registry requires:

| Scenario | Required proof |
| --- | --- |
| `curator_resource_cas` | plural different-resource progress; one same-resource CAS winner; expiry/reclaim rejects stale generation |
| `curator_review_actor` | automatic human completion refuses; proposal remains explicit and retains exact actor origin |
| `curator_effect_truth` | exact fence/intent/actor/postcondition at commit and every replay; no blind cached success |
| `curator_installed_retry` | real daemon/CLI response loss, restart and exactly-one durable result |

Public deterministic artifacts live in `vectors/curator/v1/`; closed schemas
live in `schemas/curator/v1/`.

## 12. Downstream contract

DM-032 may claim `memory-evaluation|memory-proposal` items and return inert
proposal references only. DM-033 consumes human-required proposals without
granting the worker review authority. DM-034 through DM-036 may use
`resource-fence` items for projection/publication only with their exact adapter
intent and effect-truth observers. No downstream component may reintroduce an
exclusive being-wide Librarian lease.
