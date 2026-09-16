# Messaging permission validity V2 — issue #136 library slice

Status: implementation contract for identity/relationships/hosted startup. This is
NOT an authorization to migrate custody, a deployment claim, independent review,
or completion of #136. Messaging application publication, durable local capability
revocation, retained-policy read mappings and effect-boundary integration remain
separately owned integration work.

## 1. Explicit validity and least privilege

The RFC 2119 keywords apply. V1 signed documents retain their original finite
meaning. No V1 deadline is extended, ignored, or replaced with a sentinel.

V2 uses a closed tagged union:

* `{"mode":"until-revoked","not_before_ms":T}`;
* `{"mode":"finite","not_before_ms":T,"not_after_ms":U}`.

Instants MUST be integers (not booleans), from zero through the JCS safe-integer
maximum. Finite intervals are half-open and MUST have U > T. Unknown modes,
extra fields and null deadlines fail closed. A child MUST begin no earlier than
its parent; an indefinite child MUST NOT descend from finite authority. Finite
V2 proposed/actual grants retain the V1 maximum duration. Actual finite grants
MUST be issued before their end.

Indefinite relationship permissions are restricted to the exact operations
`messaging.read` and `messaging.send`. Other operations, including legacy `read`,
remain finite. An application adapter MUST explicitly adopt the new operation
and exact resource; it MUST NOT interpret an indefinite messaging grant as
ordinary memory, source, compute, publication or administrative permission.

## 2. Signed relationship history

Existing authenticated event kinds dispatch on exact payload schema. Card,
offer, acceptance, close, grant, grant-acceptance and grant-revocation have V2
payload schemas. Unchanged resources, membership and founder governance retain
V1 schemas. Stable card-series, relationship, resource and grant identifiers keep
their V1 derivations: their derivation inputs did not change. Event content hashes
and signatures bind the entire versioned payload. Reusing a grant ID for altered
bytes is a fork, not a migration.

V2 cards replace expiry with indefinite validity and explicit `status` (`active`
or `withdrawn`). Validity starts exactly at `issued_at_ms`. Withdrawal is an
ordinary signed successor card in the existing predecessor-linked card lane,
not an expired-card trick or an unsigned status edit. A V2 withdrawal is terminal
for that series. Current authorization MUST NOT fall back to an older card.
Forks/gaps remain fail-closed. Cards alone never grant messaging.

V2 offers retain finite `expires_at_ms` as an **acceptance deadline only**.
Their proposed grants use V2 validity. Proper bilateral acceptance survives the
offer deadline. V2 relationships may retain their original card evidence through
ordered same-being card succession; resource/operation grants do not widen when
a newer card appears. V1 relationships keep exact-current-card semantics.

V2 grants preserve subject acceptance, exact resource and operation, classification,
delegation depth, parent cascade, and signed revoke/relinquish/close governance.
Membership remains governed by signed acceptance/leave/expulsion. A V2 grant tied
to a tribe cannot survive membership reentry: the current membership episode's
signed event must precede grant issuance. A regrant requires distinct consent.

Mixed snapshots use `dm.tribe-snapshot/v2` and resolutions use
`dm.tribe-resolution/v2`; every projected grant then has explicit validity,
including genuinely finite V1 grants. No numeric infinity is projected.

## 3. Dependency credentials and signed succession

`create_embodiment_credential_v2` emits `dm.identity.artifact/v2`, kind
`embodiment-credential`, with `dm:identity:v2:` IDs. Its signing/hash domain is
`dm.identity.embodiment-credential/v2`; acceptance uses that domain plus
`/acceptance\0` and the raw body digest. The V2 body replaces the two V1 time
fields with `validity`. Root threshold, purpose separation, embodiment acceptance,
explicit root carry-forward and revocation generation remain enforced.

An indefinite dependency credential MUST include the `messages` purpose.
An indefinite shared-purpose dependency credential extends temporal validity for
its **unchanged** purposes, not only messages. Owners MUST approve that exact
tradeoff. Finite administrative capabilities still gate administrative methods.
This does not silently convert other independently scoped permissions.

`create_credential_succession` / `verify_credential_succession` bind a narrow
`dm.we.credential-succession/v2` transition under current root threshold AND exact
existing embodiment acceptance. The hash domain is
`daimon/weave-credential-succession/v2\0`; root signatures cover domain + raw hash;
embodiment acceptance covers that preimage + `/acceptance`.

The transition MUST preserve control state (including revocations), being, body,
embodiment, signing/encryption/transport keys, principals, purposes and revocation
generation. It increments manifest revision once, replaces only the selected
credential/authorization references, and retains all previous credential and
incarnation artifacts unchanged. Current root control head is mandatory in the
new credential. Root rotation/recovery is not part of this transition.

The existing incarnation ID, sequence and original start are unchanged; its key
explicitly reauthorizes the new credential ID. The V2 validity lower bound is the
original V1 lower bound, so verification of the original incarnation start stays
truthful. The old credential is verified at that authenticated historical start
with **current revocations enforced**; this is not fresh use at a frozen clock.
An expired but unrevoked predecessor can receive explicit new root/body consent.
A revoked predecessor cannot. The transition itself records the actual issuance
instant. Historical events still select their exact original manifest.

`RootHistoryAuthority` verifies the mixed successor chain. This library transition
does not publish files, fence a body, alter secret slots, or make another embodiment.
Cluster MUST qualify the same-incarnation reauthorization before activation.

## 4. Runtime V8 and local capability

V8 retains V7 bundle fields and profile/custody/signature checks. A valid expired
or revoked finite operator/host capability is unavailable to requests, but is not
a host startup deadline. V7 retains its active-capability startup requirement.
V8 does not mint indefinite status, scopes, sync or administrator authority.
`LocalCapability.active_at(at_ms)` is the explicit availability predicate;
readiness MUST NOT be inferred from the fact that a descriptor was loaded.

`create_messaging_capability` creates a closed `dm.local.capability/v2` descriptor
with indefinite validity and only `messaging.send`, `messaging.inbox`,
`messaging.reply`, `messaging.delivery` (or a nonempty subset). Capability ID/hash
uses `daimon/local-api/capability/v2\0`. Local request/response HMAC domains and
request freshness are unchanged. A descriptor's `status` is NOT a durable
revocation journal: replay-resistant owner-local revocation is an integration
obligation, and the descriptor alone MUST NOT be deployed as sufficient authority.
The V2 messaging capability is attached by the messaging application, not inserted
into V8's closed finite operator/host role inventory.

`verify_relationship_card_authority(card, authority, at_ms=...)` checks historical
manifest pins separately from the current same-body routing key and root revocation.
V2 cards require a current indefinite V2 dependency credential. Finite peer
credentials cannot silently become indefinite enrollment dependencies.

## 5. Current authorization versus history

`RelationshipStore.view` is a historical proof API. It MUST NOT authorize a fresh
V2 effect after clock rollback. `authorization_view` requires an existing store,
revalidates all retained event signatures and holds a SQLite `BEGIN IMMEDIATE`
transaction against every history writer until context exit. It reduces all
observed evidence, so known terminal actions cannot disappear with clock rollback.
Positive validity still uses the caller's actual clock. The caller MUST hold the
context through final local commit/read release and MUST NOT perform nested store
writes or unbounded network I/O inside it. Recheck between network stages.

This provides a local serialization primitive, not distributed instant revocation.
Remote effects already transmitted can be ambiguous. Entire-filesystem rollback
requires an external monotonic anchor; SQLite alone does not supply one. Historical
reads require original proof plus current standing authority, not renewed envelopes.

## 6. Acceptance and downstream contracts

| Scenario | Library evidence / required integration |
|---|---|
| Large clock advance | Real V2 signed relationship history, V2 credentials, fresh finite encrypted envelope and V8 reconstruction tests |
| Mixed V1/V2 | V1 child under V2 parent remains finite; V1 expiry regressions retained |
| Revocation | Signed parent cascade, withdrawal, membership reentry, reopened-store clock rollback tests |
| Migration tampering | Exact manifest/credential/authorization IDs and dual signatures; unchanged custody on V8 restart |
| Malformed input | Null/nested/wrong operations, finite duration and issue-time negatives; authenticated malformed grants do not mutate store |
| Freshness | Local stale requests and expired sealed deliveries still reject |
| Missing integration | Cached RPC checks, capability journal, application migration/read bridge, multi-stage races, actual messaging send/read/reply/status via UDS |

Parent #136 integration MUST implement the remaining row before claiming issue
completion. #132 owns receipt semantics; #137 owns mandatory visibility; #138 owns
finite human scheduling. Downstream Cluster must qualify status/fence/sidecar
checks against V8 without treating obsolete finite role expiry as messaging expiry.
