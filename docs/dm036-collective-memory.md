# DM-036 collective-memory exchange

Status: normative for `dm.collective-* /v1`.

“Matrix” means the `daimon-matrix` component. Matrix.org is not used. The
collective-memory dependency is the exchange boundary at commit
`3e3b39416917f8e3c2bc5ca69362b20296205938`, whose closed schema SHA-256 is
`2aad43d1b309ee95108c855fc8dc682a854e5fdf3a1e799ecfca96d3ebf7c5d9`.
Any other commit, schema, producer, release, policy, scope or target fails
closed.

## Two directions, no shared authority

DM-036 is two adapters, not one bidirectional credential:

| Boundary | Adapter | Owns | Cannot do |
| --- | --- | --- | --- |
| inbound | `dm:adapter:v0:Sh-2fDC4rpFOZz_ddjWqLptoX2SgUUzJPKhe6XQOtj8` | read-only transport identity, immutable source log, quarantine receipts | publish, review, consent, promote, write `/me` |
| outbound | `dm:adapter:v0:Jsug9D2N641xJwE5Q_oLaHDy0wxT5knRJfxzV2ZEOXc` | reviewed request queue, exact provider receipts, effect reconciliation | read exports, trust sources, write `/me`, mint identity |

Their credentials, transports, capabilities, SQLite files, lock files,
idempotency keys, events and receipts are distinct. Construction rejects the
same path or inode for both stores. Neither receives a host path, URL, command,
SQL statement, database handle, prompt, key or credential through its public
contract. Both DM-018 manifests deny Matrix, identity, presence, membership and
`/me` signing authority.

Matrix remains authoritative for ledger history, `/me`, classification,
consent, human review and accepted adapter receipts. collective-memory remains
authoritative for its corpus, export generations, publication transaction,
index and Atlas. Each side retains a content-bound receipt for the other; a
receipt never transfers authority.

## Inbound immutable source intake

The injected source transport implements only `manifest`, `page` and `object`.
Credentials and endpoints stay inside that transport. Matrix validates before
any local effect:

1. the exact producer instance/release, policy and public scope;
2. closed canonical manifest identity and state digest;
3. sorted unique artifact/logical IDs, authors and source references;
4. license, explicit scope, classification, media type, predecessors and
   tombstones;
5. bounded page/cursor sequence and byte/count totals; and
6. every inert UTF-8 object's declared SHA-256 and length.

Preview performs remote reads and validation but writes no file, cursor,
receipt, error, ledger event or projection. Apply re-fetches the exact immutable
generation. It prepares all descriptors and content in an owner-only inbound
source-log transaction while the prior generation remains active. A
deterministic `source.imported` event then records one receiver-authored
`quarantined:initial-pull` decision and explicitly commits to
`personal_memory_assertions = 0`. Only after that event exists does the source
log advance its active generation.

Per-artifact provenance and bytes remain in the append-only source log; the
small canonical ledger event binds its source-log hash, generation, manifest,
counts and decision. This keeps a 4096-artifact import below the Weave event
bound without treating a remote database or index row as canonical evidence.
Tombstones advance only the imported logical head. Historical manifests,
objects, events and decisions remain available.

### Offline catch-up

The pinned upstream adds `ExportBoundary.manifest(generation_id)`. Matrix reads
the current manifest, follows `predecessor_generation` backwards to its locally
accepted high-water, rejects cycles/gaps/forks, validates the entire chain and
applies it oldest-first. It never skips an unobserved predecessor or guesses a
winner. A normal single-generation preview still rejects a gap.

### Inbound recovery

| Crash/failure | Observable result |
| --- | --- |
| fetch, timeout, invalid page/object or policy mismatch | prior generation remains active; apply records a redacted stable error code |
| before source-log prepare commits | no new source state or ledger event |
| after prepare, before ledger event | recovery authors the deterministic event once |
| after ledger event, before active switch | recovery finds the same event and activates once |
| invalid successor, implicit removal or fork | generation remains inactive and records a closed error |
| receipt/event/source-log drift | effect-truth discrepancy; no cached success |

`rebuild()` performs no remote read. It validates every stored manifest,
descriptor, inert content byte, predecessor and chained source-log hash, then
uses the authoritative Matrix `source.imported` event prefix to reconstruct
only the derived active/superseded markers and missing crash-window receipt
bindings. A fork, disconnected generation, accepted-after-missing event,
content mismatch or contradictory non-null receipt fails closed.

## Outbound reviewed publication

Outbound accepts only a caller-rendered derived Markdown title/body plus exact
current Matrix source event IDs. `collective_checkpoint` binds those IDs and
hashes and the exact being/manifest. Matrix recomputes it before preview,
submit and execute; superseded or missing source events make the request stale.

Matrix locally reproduces the upstream final Markdown bytes, including closed
frontmatter, and scans title, metadata and body for private-key, bearer,
provider-token, credential-assignment and credential-URL patterns before any
provider plan. The upstream preview must return byte-identical canonical bytes,
hash and length.

Consent and review are separate Ed25519 evidence envelopes over the exact
preview hash, final content hash, subject, requester, action, logical target,
classification, policy and source checkpoint. Consent must be signed by the
subject. Review must use a current, non-revoked `human:*` principal distinct
from the subject and requester. Inbound trust, a model, Librarian or publisher
receipt cannot satisfy either role.

The outbound journal stores the full bounded request privately. The canonical
`collective.publication.requested` event stores a content-bound summary rather
than raw body bytes and depends on all Matrix source events and the exact prior
acceptance. Under its own process lock, the adapter asks upstream for a
deterministic plan, applies the supported transaction and validates the complete
content-addressed receipt. It then requires fresh upstream
`reconcile(effect=verified)` before authoring
`collective.publication.receipted`.

Initial publish, successor and reviewed tombstone are monotonic. A successor
names the current upstream receipt and supersedes the corresponding Matrix
acceptance. Identical retries require fresh effect truth and return the same
event/receipt. Changed bytes under an idempotency key, untracked targets, stale
predecessors and concurrent target writers fail closed.

### Outbound recovery

| Failure window | Required retry result |
| --- | --- |
| before request journal prepare | no queue event or external effect |
| after prepare, before request event | recovery authors the deterministic request event |
| provider rejects plan/final bytes | closed rejection; no Matrix acceptance |
| response lost after provider commit | exact apply replay returns the one receipt |
| after provider receipt, before Matrix acceptance | fresh reconcile then one acceptance event |
| after acceptance, before journal completion | journal binds the existing event exactly once |
| target/index/Atlas drift on replay | effect-truth discrepancy; cached success refused |

## Contracts, vectors and real-I/O gate

Matrix contracts are in
`schemas/collective-memory/v1/contracts.schema.json`; upstream is pinned by
commit and schema hash rather than copied as executable source. Deterministic
vectors are in `vectors/collective-memory/v1/` and regenerate with:

```bash
python tools/generate_dm036_vectors.py
python tools/generate_dm036_vectors.py --check
```

`tests/test_dm036_collective_memory.py` uses the real pinned upstream
`ExportBoundary` and `PublicationBoundary` in isolated roots. It covers initial
import/retry, 257-item pagination, multi-generation offline catch-up,
successor/tombstone, corrupt/mixed/unavailable refresh, both inbound crash
windows, source-log rebuild, exact review, consent/review revocation and expiry,
secrets, response loss, source/target drift, concurrency and both outbound
acceptance windows. Its real projection lane performs:

```text
export → Matrix quarantine → reviewed publish → real FTS index + Atlas
       → reviewed tombstone → real reindex
```

That lane checks both SQLite databases with `PRAGMA integrity_check`, verifies
the published and unrelated documents in index/Atlas, preserves unrelated
corpus content, and proves there is no shared DB, WAL or SHM file.

## Operation and rollback

DM-036 has no live deployment authorization. Configure only temporary isolated
roots until a later consented canary card permits a corpus. Source and publisher
database parents must be separate owner-only directories. Start by calling
inbound `recover()` and outbound `recover()`, then reconcile every cached active
receipt before serving it.

Before the first accepted effect, rollback may disable the adapters and remove
unused local stores. After an import or publication exists, disable the relevant
capability independently and preserve its ledger/source log, high-water and
receipts. Withdraw an outbound artifact only with a reviewed tombstone. Never
delete external data by inference, copy SQLite/WAL files, lower a high-water,
turn collective text into autobiographical memory or use inbound revocation to
activate outbound authority.
