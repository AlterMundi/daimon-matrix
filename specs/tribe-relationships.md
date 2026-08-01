# Tribe relationships and descendant delegation

Status: normative V0 specification for DM-016.

This document defines `/tribe` as signed social relationships plus explicit,
directional resource grants. It defines the initial handshake, resource and
operation scopes, delegation and attenuation, expiry, revocation, birth
limits, newborn grant issuance, human-contact evidence, and the boundary
between remote tribal knowledge and personal memory.

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, **SHOULD NOT**,
and **MAY** are interpreted as described by RFC 2119 and RFC 8174.

## 1. Security goals and non-goals

V0 has these goals:

1. no transport directory, host name, account, route, display alias, shared
   model, or copied state can create a tribal relationship;
2. a relationship becomes active only after both exact principals sign the
   same handshake, including the cards, endpoints, capabilities, proposed
   grants, and recipient-encryption keys they disclosed;
3. a grant authorizes only the exact subject, resources, operations, validity
   interval, and delegation budget it names;
4. every child grant is equal to or narrower than one active parent grant and
   is independently accepted by its subject;
5. a newborn receives a fresh grant bound to its independently generated
   `me_id`; no parent credential, key, session, route authorization, or grant
   is copied;
6. expiry, relationship closure, grant revocation, upstream revocation,
   identity quarantine, and delegation forks fail closed without deleting
   history;
7. a recipient-encryption key establishes possession of a delivery key, never
   relationship membership or resource authority; and
8. tribal knowledge remains externally authoritative and attributed. A grant
   gives access, not autobiographical memory.

V0 does not define legal human identity, employment, property law, payment,
social reputation, semantic trust, a universal group directory, or a
transport. It does not claim to prevent an issuer from disclosing its own
plaintext outside the protocol. It makes authorized protocol actions and
their evidence deterministic and auditable.

## 2. Layer and authority boundaries

The following layers are distinct:

| Layer | Authority | Never authority |
|---|---|---|
| Daimon principal | accepted DM-010/DM-011 `/me` evidence | body, harness, host, Tribe principal, route |
| human contact | one self-certifying contact signing key | legal name, account, email, chat identity |
| tribe namespace | exact signed declaration and content-derived `tribe_ref` | directory, audience, display label |
| relationship | matching offer and acceptance by the two exact principals | unilateral card, route reachability, proposed grant |
| resource | exact content-derived descriptor and controller | path guess, URI normalization, adapter row |
| grant | accepted grant plus complete active ancestry | relationship membership alone, possession, transport ACK |
| routing | DM-012 resolution plus current key/route evidence | grant creation or membership |
| delivery | DM-011 signed and recipient-encrypted envelope | semantic acceptance, forwarding, memory admission |
| knowledge | remote controller plus attributed content/provenance | `/me.memory`, HMK row, local cache |

A relationship is symmetric evidence that two principals consented to a
social/resource-sharing context. Grants are directional. A relationship MAY
remain active with zero grants. A grant never makes the subject a `/we` member,
changes either principal's identity, proves ancestry/species, or authorizes an
operation outside its terms.

Every Daimon-authored protocol action is a DM-011 event. Its event author MUST
equal the action's Daimon author, its certificate MUST authorize the complete
`matrix/tribe-*` event type, and its `intent` MUST be null. These actions are
relationship evidence, not scoped messages. Human-authored actions use the
closed external wrapper in Section 4.3. A human wrapper is contact evidence
only and never a `/me`, operational certificate, or Daimon event.

Intrinsic cryptographic validity and receiver-local effectiveness are separate.
A valid historical grant can be locally ineffective because its relationship,
identity, ancestry, evidence, time, or policy state is expired, closed,
revoked, incomplete, forked, or quarantined.

## 3. Common identifiers, domains, and references

DM-011 strict JSON, JCS, base64url, safe-integer, signature, half-open interval,
and complete-wire rules apply unchanged. DM-016 registers these separation
labels:

```text
daimon/tribe-human-contact-id/v0
daimon/tribe-human-statement/v0
daimon/tribe-id/v0
daimon/tribe-card-series/v0
daimon/tribe-resource-id/v0
daimon/tribe-relationship-id/v0
daimon/tribe-grant-series/v0
```

DM-016 registers these event types:

```text
matrix/tribe-declaration
matrix/tribe-card
matrix/tribe-handshake-offer
matrix/tribe-handshake-acceptance
matrix/tribe-relationship-close
matrix/tribe-grant
matrix/tribe-grant-acceptance
matrix/tribe-grant-revocation
```

### 3.1 Principal references

A principal reference is closed:

```text
principal_ref = {
  kind = "me" or "human-contact",
  principal_id
}
```

For `me`, `principal_id` is an exact `me_id`. For `human-contact`, it is:

```text
human_contact_id = "dm:human-contact:v0:" || base64url(SHA-256(
  UTF8("daimon/tribe-human-contact-id/v0") || 0x00 ||
  JCS({"signing_key": signing_key_descriptor})
))
```

The descriptor obeys DM-011 Ed25519 rules. A human contact ID proves only
continuity of one relationship key. A local display name, legal identity,
email address, GitHub account, Telegram account, or provider login is not
included in the identifier and MUST NOT be inferred as verified.

Human-contact key rotation creates a new `human_contact_id`; V0 defines no
continuity or authority transfer from the old contact principal. Compromise
remediation is explicit: either participant closes each affected relationship,
each exact grantor revokes its own grants, and receiver-local policy MAY
quarantine statements from the compromised key at a cited evidence cursor.
Such policy MUST NOT claim a portable or global compromise fact, silently
retarget a relationship or grant to the replacement key, or invent a `/me`.

Principal references sort by `(kind, principal_id)` and reject duplicates.
All relationship and grant comparisons use the exact reference, never a
display alias.

### 3.2 Content and action references

An immutable content reference is closed:

```text
content_ref = {
  content_id = "dm:tribe-content:v0:" || sha256,
  media_type = printable ASCII 1..128 bytes,
  byte_length = safe integer 0..67108864,
  sha256 = canonical 32-byte base64url
}
```

The ID MUST contain the exact digest. A content reference contains no locator
and grants no fetch permission.

An action reference is closed:

```text
action_ref = {
  kind = "event" or "human-statement",
  action_id,
  action_hash
}
```

`event` refers to a complete DM-011 event. `human-statement` refers to the
Section 4.3 wrapper. The referenced bytes, author, type, ID, hash, signature,
and contextual evidence MUST validate; matching strings alone are
insufficient.

### 3.3 Tribe declaration and `tribe_ref`

A tribe core is closed:

```text
tribe_core = {
  schema = "daimon-tribe-core/v0",
  tribe_nonce = 32-byte random base64url,
  authority = principal_ref,
  policy_ref = content_ref,
  created_at_ms
}
```

```text
tribe_ref = "dm:tribe:v0:" || base64url(SHA-256(
  UTF8("daimon/tribe-id/v0") || 0x00 || JCS(tribe_core)
))
```

`matrix/tribe-declaration` carries exactly `schema =
"daimon-tribe-declaration/v0"`, `tribe_core`, and `tribe_ref`. Its author MUST
equal `tribe_core.authority` when that authority is a Daimon. A human authority
uses a Section 4.3 `tribe-declaration` statement with the same payload.

The declaration creates a namespace and initial policy anchor only. It admits
no member and grants no resource. Two byte-distinct cores are different tribes;
names, aliases, routes, directories, or common authorities never merge them.
A policy change requires a new signed declaration and explicit migration in a
future protocol version; V0 does not silently replace `policy_ref`.

## 4. Principal cards and human statements

### 4.1 Card payload

A card advertises exact, replaceable relationship and routing inputs:

```text
schema = "daimon-tribe-card/v0"
card_series_id
card_sequence
previous_card_ref = action_ref or null
principal = principal_ref
identity_evidence = {
  genesis_id, genesis_hash,
  control_position = {recovery_generation, control_sequence, control_hash}
} or null
issued_at_ms
expires_at_ms
encryption_bindings = sorted [{
  operational_id, certificate_id, certificate_hash,
  encryption_key = X25519 descriptor
}]
routes = sorted [{kind, route_id}]
capability_refs = sorted unique [content_ref]
resource_descriptors = sorted unique [resource_descriptor]
```

For a Daimon, `identity_evidence` is non-null, the event author equals the card
principal, and every encryption binding MUST resolve to an accepted,
non-revoked DM-010/011 operational certificate for that same `me_id` with
`sealed-event-recipient` purpose. For a human contact, `identity_evidence` is
null, `encryption_bindings` contains `operational_id`, `certificate_id`, and
`certificate_hash` as null and a fresh X25519 descriptor. For a Daimon, the
descriptor and its content-derived `kid` MUST byte-match the cited
certificate. Human keys are relationship-contact keys, never Daimon
credentials.

`card_series_id` derives under `daimon/tribe-card-series/v0` from
`JCS({"principal": principal})` with prefix `dm:tribe-card-series:v0:`.
Sequence zero has a null predecessor. Every successor increments by one and
names the exact accepted predecessor. Cards expire after at most 30 days.
They are advertisements, not membership or grants. Key or route rotation
creates a successor card; it does not rewrite a handshake or grant.

Card currency is required when a handshake, grant issuance, or grant acceptance
uses that card. After a grant is accepted, card expiry or temporary absence
makes the principal unroutable and forbids new delivery until a current
successor card is resolved; it does not revoke the relationship, invalidate the
accepted grant, or terminate stable Daimon/contact identity evidence. Grant
effectiveness therefore tests current identity/control or contact-key evidence,
not continuous card availability. Revocation and compromise remain Section 8
events or explicit receiver-local quarantine, never inferred from card lapse.

Routes use the DM-011 route grammar and carry no endpoint secret. A route ID
selects locally configured endpoint material. Endpoint credentials, cookies,
SSH agents, bearer tokens, and private keys MUST NOT appear in a card.
The two signed card references therefore exchange the parties' endpoint
references during the handshake; DM-053 resolves their separately protected
endpoint descriptors. Missing protected endpoint bytes makes the relationship
unroutable, not unauthenticated.

Capabilities are immutable content-addressed descriptions. A capability claim
is descriptive until evaluated by exact local policy. It cannot expand a
grant, select a body, or authorize code execution.

### 4.2 Resource descriptors

A resource descriptor is closed:

```text
resource_descriptor = {
  schema = "daimon-tribe-resource/v0",
  resource_nonce = 32-byte random base64url,
  tribe_ref,
  controller = principal_ref,
  kind = "knowledge" | "compute" | "storage" | "tool" |
         "sensor" | "actuator" | "route" | "other",
  authority_mode = "remote" or "portable",
  classification = registered ASCII classification,
  descriptor_ref = content_ref
}
```

```text
resource_ref = "dm:tribe-resource:v0:" || base64url(SHA-256(
  UTF8("daimon/tribe-resource-id/v0") || 0x00 || JCS(resource_descriptor)
))
```

Every descriptor is an indivisible authorization scope. V0 has no wildcard,
path-prefix, URI-normalization, display-name, or semantic-containment rule. A
controller needing finer scope creates finer descriptors. `kind = knowledge`
MUST use `authority_mode = remote`; a portable derived publication belongs to
DM-015 and does not change the tribal source's authority.

The referenced descriptor bytes describe supported operations, limits, and
interfaces but authorize nothing. Unknown operations remain unsupported.

### 4.3 Human statement wrapper

A human-authored tribal action uses this closed wrapper:

```text
{
  schema = "daimon-tribe-human-statement-wrapper/v0",
  body = {
    schema = "daimon-tribe-human-statement/v0",
    statement_nonce = 32-byte random base64url,
    author = human principal_ref,
    signing_key = Ed25519 descriptor,
    statement_type = one registered `tribe-*` action name,
    payload = the exact type-defined payload
  },
  statement_id = "dm:tribe-human-statement:v0:" || statement_hash,
  statement_hash,
  signature = one DM-011 signature record with role "human-contact-authorization"
}
```

The preimage is `UTF8("daimon/tribe-human-statement/v0") || 0x00 || JCS(body)`.
The hash is its SHA-256 digest. `author.principal_id` MUST recompute from the
exact `signing_key`, which verifies the signature. The wrapper has exactly one
signature and is at most 262144 bytes. A contact key cannot sign as a `/me`,
operational key, tribe authority belonging to another principal, or transport
key.

Registered human statement types are `tribe-declaration`, `tribe-card`,
`tribe-handshake-offer`, `tribe-handshake-acceptance`,
`tribe-relationship-close`, `tribe-grant`, `tribe-grant-acceptance`, and
`tribe-grant-revocation`. Their payloads and author-equality rules are the same
as the corresponding event payloads below. A human statement is retained as
external signed evidence; a local Daimon MUST NOT re-author it as though the
human had a `me_id`.

## 5. Bilateral handshake and relationship state

### 5.1 Offer

`matrix/tribe-handshake-offer` has this closed payload:

```text
schema = "daimon-tribe-handshake-offer/v0"
handshake_nonce = 32-byte random base64url
relationship_id
tribe_ref
initiator = principal_ref
responder = principal_ref
initiator_card_ref = action_ref
expected_responder_card_id = action ID or null
roles = sorted unique [printable ASCII role]
proposed_grants = sorted unique [proposed_grant]
issued_at_ms
expires_at_ms
```

```text
relationship_id = "dm:tribe-relationship:v0:" || base64url(SHA-256(
  UTF8("daimon/tribe-relationship-id/v0") || 0x00 || JCS({
    "handshake_nonce": handshake_nonce,
    "tribe_ref": tribe_ref,
    "initiator": initiator,
    "responder": responder
  })
))
```

The author MUST equal `initiator`. The two principals MUST be distinct. The
tribe declaration and initiator card MUST be complete and current. An expected
responder card ID, when non-null, prevents substitution; null requests a fresh
card in the acceptance. Roles are descriptive and grant no operation.

A proposed grant is closed:

```text
{
  grantor = principal_ref,
  subject = principal_ref,
  permissions = sorted unique [permission],
  not_before_ms,
  expires_at_ms
}
```

Grantor and subject MUST be the two handshake principals in either direction.
Proposals are inert commitments to consider exact upper bounds. They are not
grants, cannot authorize disclosure, and need not all be issued. Every root
grant (`parent_grant = null`) issued under this relationship MUST be equal to or
narrower than one accepted proposal with the same grantor and subject. Wider or
new root authority requires a fresh bilateral handshake and relationship ID;
waiting or issuing another grant nonce cannot evade the accepted upper bound.

Offer expiry is greater than issuance, at most 7 days later, and within the
authorizing certificate/card interval. The offer's event `intent` is null.

### 5.2 Acceptance

`matrix/tribe-handshake-acceptance` has this closed payload:

```text
schema = "daimon-tribe-handshake-acceptance/v0"
relationship_id
tribe_ref
offer_ref = action_ref
initiator = principal_ref
responder = principal_ref
initiator_card_ref = action_ref
responder_card_ref = action_ref
roles = exact offer roles
proposed_grants = exact offer proposed grants
accepted_at_ms
```

The author MUST equal `responder`. Every copied field is byte-equal to the
validated offer. Both cards MUST validate, name their corresponding principal,
and be current at acceptance. Acceptance occurs inside the offer's half-open
interval. A human responder signs the same payload as a Section 4.3 statement.

The relationship becomes `active` only when the declaration, offer,
acceptance, both cards, identity/contact proofs, and time evidence are
complete and unforked. A signed timestamp is not portable proof of timely
first observation; a late first observation without DM-011 checkpoint or
trusted local receipt remains `time-unverifiable`.

Exact replay is idempotent. A different acceptance for one offer, a different
offer occupying one relationship ID, a card fork at the cited position, or
conflicting principal bytes quarantines the relationship. Arrival order,
wall-clock time, hash ordering, or route reachability never chooses a winner.

### 5.3 Closure

Either participant MAY author `matrix/tribe-relationship-close`:

```text
schema = "daimon-tribe-relationship-close/v0"
relationship_id
tribe_ref
offer_ref
acceptance_ref
closer = principal_ref
reason = registered ASCII reason code
closed_at_ms
```

The author equals `closer`, which MUST be one of the exact participants.
Closure is terminal for that relationship ID and makes all grants under it
ineffective locally once accepted. It does not delete cards, grants,
deliveries, receipts, or knowledge history. Re-pairing requires a fresh
handshake nonce, relationship ID, acceptance, and grants.

Competing valid closure statements are redundant terminal evidence. A close
concurrent with a previously unseen grant fails closed for current use; V0
does not let a timestamp resurrect authority.

## 6. Grants, resource scopes, and acceptance

### 6.1 Permission shape

A permission is closed:

```text
permission = {
  resource_ref,
  operation = registered ASCII operation name,
  delegable = boolean,
  remaining_delegation_depth = integer 0..16,
  birth_limit = integer 0..1024
}
```

Permissions sort by `(resource_ref, operation)` and reject duplicate pairs.
An operation is 1 through 128 ASCII bytes and matches
`^[a-z][a-z0-9]*(?:[./-][a-z0-9]+)*$`; a visible address may render the
registered scope operation with a leading dot, but the grant stores no dot.
The referenced resource descriptor MUST be complete, belong to the same
`tribe_ref`, and have an effective controller chain reaching the grantor.
Operation names are byte-exact; V0 has no glob, prefix, case folding, alias,
or implied CRUD expansion.

When `delegable = false`, both numeric delegation fields MUST be zero. When it
is true, `remaining_delegation_depth` MUST be at least one. `birth_limit = 0`
forbids use of that permission in a newborn grant while still permitting
ordinary delegation when depth allows. A permission can be used only for the
exact operation and resource; possession of related content or a stronger
local capability cannot widen it.

### 6.2 Grant issuance

`matrix/tribe-grant` has this closed payload:

```text
schema = "daimon-tribe-grant/v0"
grant_nonce = 32-byte random base64url
grant_series_id
tribe_ref
relationship_id
grantor = principal_ref
subject = principal_ref
subject_identity_binding = {
  principal_id,
  genesis_id = artifact ID or null,
  genesis_hash = artifact hash or null,
  contact_signing_kid = key ID or null
}
permissions = sorted unique [permission]
not_before_ms
expires_at_ms
parent_grant = null or {
  grant_ref = action_ref,
  acceptance_ref = action_ref,
  delegation_sequence,
  previous_delegation_ref = action_ref or null,
  parent_state_refs = sorted unique [action_ref]
}
birth_context = null or {
  relationship_nonce,
  birth_offer_event_id,
  birth_acceptance_id,
  birth_acceptance_hash,
  commitment_index,
  commitment_hash
}
issued_at_ms
```

```text
grant_series_id = "dm:tribe-grant-series:v0:" || base64url(SHA-256(
  UTF8("daimon/tribe-grant-series/v0") || 0x00 || JCS({
    "grant_nonce": grant_nonce,
    "tribe_ref": tribe_ref,
    "grantor": grantor,
    "subject": subject
  })
))
```

The author equals `grantor`; grantor and subject are distinct. The relationship
MUST be active and contain both principals, except for the newborn rule in
Section 7. The validity interval is non-empty, no longer than 365 days, and
within every active parent interval. Empty permissions are valid and convey no
resource access.

For a Daimon subject, identity binding carries its exact accepted genesis ID
and hash and a null contact key. For a human contact it carries null genesis
fields and the key ID embedded in its `human_contact_id`. The binding is
immutable. Operational and recipient-encryption keys are resolved from the
subject's current card and may rotate without recreating identity or silently
retargeting a grant.

With `parent_grant = null`, every resource controller MUST equal the grantor.
With a parent, Section 6.4 attenuation applies. A grant may have exactly one
parent; combining authorities requires separate grants. The accepted handshake
proposals are an additional upper bound for every root grant under the
relationship but never the source of authority.

### 6.3 Subject acceptance

`matrix/tribe-grant-acceptance` has this closed payload:

```text
schema = "daimon-tribe-grant-acceptance/v0"
grant_series_id
grant_ref = action_ref
tribe_ref
relationship_id
grantor = principal_ref
subject = principal_ref
subject_identity_binding = exact grant binding
accepted_at_ms
```

The author equals `subject`. Every copied field matches the grant. Acceptance
occurs while the grant, subject identity/contact card, and all parent grants are
current. The ordinary relationship MUST also be current, except for a Section 7
newborn grant: its complete birth and parent-grant evidence replaces the
ordinary handshake, and this acceptance atomically activates the derived
relationship. Before acceptance the grant is `offered` and grants no access. A
human subject signs the same payload using Section 4.3.

The same subject may accept an exact replay idempotently. Two distinct
acceptances for one immutable grant are redundant if their payload is equal;
an acceptance that changes any binding is invalid. A subject may decline by
not accepting or by closing the relationship; silence is not consent.

### 6.4 Delegation and attenuation

For a child grant, the parent grant subject MUST equal the child grantor. The
parent grant, its acceptance, complete ancestry, relationship, and resource
descriptors MUST be active at issuance and acceptance. For every child
permission there is exactly one parent permission with the same
`(resource_ref, operation)`, `delegable = true`, and positive remaining depth.

The child MUST satisfy all of these:

- `remaining_delegation_depth <= parent.remaining_delegation_depth - 1`;
- `delegable` may stay true only when the resulting depth is positive;
- a non-delegable parent permission never appears in a child grant;
- `birth_limit <= parent.birth_limit` and cannot reset consumed allocations;
- `not_before_ms >= parent.not_before_ms`;
- `expires_at_ms <= parent.expires_at_ms`;
- relationship, classification, controller, policy, and subject constraints
  are equal or narrower; and
- no local or adapter capability fills in a permission omitted by the parent.

`delegation_sequence` is identity-wide within the exact parent grant and
starts at zero. Sequence zero has a null `previous_delegation_ref`; every next
child grant increments by one and names the exact preceding accepted child
grant action. A sequence gap, predecessor mismatch, or two distinct child
grants at one position quarantines the parent delegation lane and every
descendant that depends on the ambiguous position. V0 has no arrival-order or
hash-order repair.

An issuer MAY attenuate by omitting permissions, making a permission
non-delegable, reducing depth or birth limit, delaying start, or shortening
expiry. It MUST NOT broaden and then rely on receiver policy to narrow it.

## 7. Newborn delegation and birth limits

A DM-013 tribal commitment is a promise to attempt a future grant, not a grant.
After the birth acceptance exists, the birth parent MAY issue one fresh child
grant for each accepted commitment. That grant follows Section 6 plus all of
these rules:

1. grantor equals the birth offer's `parent_me_id` and subject equals the
   acceptance's independently derived `newborn_me_id`;
2. `birth_context` cites the exact offer, acceptance ID/hash, zero-based
   commitment index in canonical commitment order, a fresh 32-byte relationship
   nonce, and the base64url SHA-256 of the exact commitment JCS bytes;
3. `tribe_ref` equals the commitment's exact `tribe_ref` and the parent grant's
   tribe;
4. the child resource/operation pairs are a subset of the commitment's
   Cartesian resource/operation set and of the active parent permissions;
5. each child permission's delegation flag and depth are equal to or narrower
   than both the commitment and parent permission;
6. expiry is no later than the parent grant expiry and 365-day grant ceiling
   and, when the commitment `expires_at_ms` is non-null, no later than that
   commitment expiry;
7. the subject binding names the newborn's exact genesis ID/hash; no parent or
   bootstrap key appears;
8. the newborn independently authors the grant acceptance after it has an
   accepted operational credential; and
9. no parent credential, grant ID, acceptance, session, route secret,
   recipient-encryption private key, cache, or transport state is copied.

The newborn acceptance activates a derived relationship under the same
`tribe_ref` for this grant only. Its exact participants are the newborn and the
one root resource controller reached by the complete parent-grant ancestry;
all permissions in one newborn grant MUST reach that same controller. The
parent is the attributable delegated grantor and MAY equal the controller but
does not impersonate it. The newborn does not join the parent's bilateral
relationship ID or receive unrelated social roles. The grant uses a fresh
`relationship_id` derived as in Section 5.1 with
`birth_context.relationship_nonce`, the root controller, and the newborn
principal as initiator and responder respectively; the birth offer, acceptance,
and complete parent-grant chain replace only the ordinary handshake evidence
for this derived relationship. A later ordinary handshake MAY establish
broader social terms but cannot widen the birth grant.

For each parent permission, `birth_limit` is the maximum number of distinct
DM-013 birth acceptance IDs that may consume that permission through accepted
direct child grants. One newborn using several permissions counts once against
each permission it receives. The canonical allocation attempt for one
commitment is the first grant in the complete predecessor-linked delegation
lane that cites its exact offer, acceptance, index, and commitment hash. Exact
replay of that grant is idempotent. Every later distinct grant citing the same
commitment is intrinsically invalid, whether narrower, unaccepted, accepted,
expired, or observed before the canonical attempt; it cannot fork, revoke, or
otherwise deactivate the canonical grant. If the canonical attempt is never
accepted or expires, V0 records the promise as unfulfilled and does not permit
re-issue under that single-use commitment. A collision at the canonical
delegation position remains the Section 6.4 lane fork and fails closed because
there is then no unique first grant.

Allocations are counted from the complete predecessor-linked delegation lane,
not a local mutable counter. Missing predecessors yield `incomplete`; a count
over the limit is invalid. Revocation does not refund a birth allocation in
V0. This prevents revoke-and-reissue from bypassing a declared limit.

An empty commitment produces an accepted zero-permission grant or an explicit
local `unfulfilled:no-permissions` status; it never implies wildcard access.
Failure, expiry, invalidity, or refusal of any promised grant changes only the
birth relationship context. It does not invalidate the newborn's `/me`, birth
binding, species enrollment, or first presence lease.

## 8. Revocation, expiry, forks, and effective state

`matrix/tribe-grant-revocation` has this closed payload:

```text
schema = "daimon-tribe-grant-revocation/v0"
grant_series_id
grant_ref
acceptance_ref
tribe_ref
relationship_id
revoker = principal_ref
action = "revoke" or "relinquish"
reason = registered ASCII reason code
parent_state_refs = sorted unique [action_ref]
revoked_at_ms
```

`revoke` is authored only by the exact grantor of the cited grant;
`relinquish` is authored only by its exact subject. No third party, tribe
directory governor, transport broker, ancestor grantor, parent of the subject,
or resource adapter may directly revoke that grant. An ancestor grantor affects
descendants exclusively by revoking its own grant, after which the cascade
below makes them ineffective. Signed time cannot backdate revocation.

Once a valid revocation is observed, the grant and all descendants are
ineffective at that receiver. The events remain immutable. Descendants cannot
outlive, bypass, or selectively ignore an ancestor's expiry, closure,
revocation, identity compromise cutoff, or fork. Re-authorization uses a fresh
grant nonce, series, acceptance, and current complete ancestry.

The effective state of grant `G` for observer `R` at evidence cursor `C` is:

```text
effective_R(G, C) =
  intrinsic_valid(G)
  and accepted_by_exact_subject(G)
  and active_relationship_or_valid_birth_derivation(G)
  and current_subject_and_grantor_identity_or_contact_evidence(G, C)
  and now within every half-open grant/ancestor interval
  and no accepted closure, revocation, relinquishment, or compromise cutoff
  and complete unforked delegation ancestry
  and R's exact policy admits the operation/classification
```

Absence of a known revocation is relative to the signed evidence cursor. A
resolver MUST NOT claim global non-revocation during a partition. Sensitive
operations SHOULD require a freshness bound or an online controller check.

Grant intrinsic states are `incomplete`, `offered`, `accepted`, `invalid`, and
`forked`. Effective states are `active`, `not-yet-valid`, `expired`, `closed`,
`revoked`, `relinquished`, `quarantined`, and `policy-denied`. These axes MUST
NOT be collapsed.

## 9. `/tribe` resolution, disclosure, and delivery

For local resolver principal `P` and exact `tribe_ref` selector:

```text
members_R(tribe_ref, C) = counterpart principals from
  active ordinary relationships in which P is an exact participant
  union active derived relationships in which P is an exact participant
  minus quarantined or invalid principal evidence
```

Derived resolution is symmetric over its two exact participants: the newborn
resolves the root resource controller and that controller resolves the newborn.
The attributable parent grantor resolves neither merely for authorizing the
grant nor for being an ancestor; it resolves the newborn only when it is also
the root controller or has a separate active relationship.

An unqualified `/tribe` MAY resolve the union of locally selected tribe refs
only when local configuration names that closed selector set. A received alias
or directory cannot add a tribe. The resolution receipt records exact
`relationship_id`, `tribe_ref`, card/action refs, grant refs used for the
requested operation, identity/contact state, exclusions, and observed
revocation/delegation high-waters.

Relationship membership and operation authorization remain separate. A
counterparty with no route remains a resolved, unroutable relationship member.
A counterparty with no grant may receive only content that exact local policy
allows from the bilateral relationship itself; it gains no resource access.
Resource-bearing or non-public delivery requires one active grant authorizing
the exact recipient, resource, operation, and classification.

Before sealing, DM-012 resolution binds the source event, sender certificate
and signing key, exact recipients, their current certificate/encryption keys,
scope, operation, classification, relationship/grant evidence, and cursor.
That resolution event or exact grant-bound authorization is the DM-011
`disclosure_authorization_id`. An adapter MUST NOT expand recipients, replace
keys, infer a group audience, or reuse an authorization for another event.

`/tribe.status` is receiver-local by default. Unauthorized remote status or
denial returns one closed public result that reveals no tribe existence,
participants, grants, resources, routes, expiry, revocation, birth relation,
or policy reason. A relationship signing key, ciphertext, successful decrypt,
delivery ACK, or prior receipt never authorizes `.status` or forwarding.

## 10. Remote tribal knowledge and memory boundary

A knowledge resource is remotely authoritative at the controller named by its
resource descriptor. A grant permits an operation such as query, read, or
subscribe against that resource; it does not transfer ownership or change the
content's author, source, controller, classification, consent, license, or
provenance.

Implementations MAY keep an encrypted, bounded, expiring delivery cache needed
for offline retry or rendering. The cache is disposable transport/projection
state and MUST retain `tribe_ref`, resource, grant, controller, author,
content digest, retrieval time, expiry, and receipt. It MUST NOT be projected
as `/me.memory`, lived experience, autobiographical fact, learned personal
skill, source claim, or species content.

If exact local DM-017 policy later records that `/me` learned something from a
tribal interaction, it authors a new attributed personal event citing the
external evidence. The external bytes remain external; the new event does not
copy private knowledge wholesale, erase provenance, or make the grant
permanent. Publication or import through DM-015 remains a separate explicit
path with consent, provenance, quarantine, and promotion.

Revocation or expiry disables future access and active caches according to
policy. It does not erase already accepted event history or pretend a lived
interaction never occurred. Cache deletion MUST target exact grant/resource
receipts and MUST NOT delete an HMK or ledger database.

## 11. Transitional Tribe Bridge mapping

The deployed Tribe Bridge v1 contributes reusable implementation evidence:

- signed directory chaining and rollback detection;
- identity/authorization/transport/encryption key separation;
- X25519/HPKE recipient wrapping and per-message content keys;
- stable logical IDs, direct/hub deduplication, durable outboxes, delivery
  leases, acknowledgements, and offline inboxes; and
- locality rejection for `@localhost` principals.

It does not contribute Daimon relationship authority. Directory principals,
audiences, allowed-sender lists, epoch governors, broker routes, host names,
SSH rosters, Telegram chats, and `@localhost` suffixes are adapter data. During
migration they MAY appear only as attributed route or external-evidence refs.
They cannot create `tribe_ref`, relationship, grant, `/me`, `/we`, human
contact, resource, disclosure, or delegation authority.

V0 group-key history remains retired and is never imported. V1 directories
and message stores are not copied into the canonical ledger. Imported code
must retain repository/commit provenance, start new stores empty, reject v0
wire input, and pass DM-050 through DM-055 replacement gates.

## 12. Validation order and resource bounds

A conforming verifier processes a bundle in this order:

1. enforce complete-wire, JSON depth, count, string, and content-size bounds
   before cryptography or network access;
2. recompute content, contact, tribe, card, resource, relationship, grant,
   event, and human-statement IDs/hashes;
3. validate DM-010/011 identity, certificate, cutoff, event sequence, event
   type, author equality, or exact human-contact signature;
4. validate declaration, card, handshake, relationship, resource, grant,
   acceptance, parent, delegation position, birth context, and revocation
   references in causal order;
5. detect occupied-position conflicts and retain fork evidence before effects;
6. evaluate current relationship/grant state and local policy without changing
   intrinsic validity; and
7. persist canonical bytes, high-waters, forks, decisions, cursors, receipts,
   and projections in crash-safe order.

V0 bounds are:

- 64 roles and 64 proposed grants per handshake;
- 64 permissions per proposed or issued grant;
- 64 encryption bindings, routes, capability refs, and resource descriptors
  per card;
- 64 parent-state/action refs per object;
- delegation depth 16 and birth limit 1024 per permission;
- 4096 relationship heads, 4096 grant heads, and 4096 revocation heads per
  resolver snapshot;
- 256 tribal recipients and 1024 exclusions per DM-012 resolution;
- 64 MiB per content blob, 256 MiB compressed and 512 MiB decompressed per
  intake bundle, expansion ratio 16, graph/reference depth 64; and
- 262144 bytes per human statement, 1048576 bytes per event, and the DM-011
  limits for every embedded descriptor and signature array.

Sequences, timestamps, sizes, counts, and indices are safe integers. Strings
are byte-exact and use the grammars above. Unsorted, duplicate, unknown,
ambiguous, noncanonical, negative, fractional, overflow, or bound-plus-one
values are rejected before effects. Local policy MAY be stricter for storage
or disclosure but MUST report that decision honestly rather than claim V0
invalidity.

## 13. Required positive and negative scenarios

Conformance vectors and implementation tests MUST cover at least:

| Scenario | Required result |
|---|---|
| valid declaration by exact authority | create namespace only; no member or grant |
| alias, directory, route, or shared authority presented as same tribe | reject merge; exact `tribe_ref` rules |
| modified policy/core with old `tribe_ref` | reject |
| Daimon card signed by another `me_id` | reject |
| human card ID does not derive from signing key | reject |
| human contact treated as legal identity or `/me` | reject boundary crossing |
| human contact rotates its signing key | create a new contact principal; transfer no relationship or grant |
| cited contact-key compromise evidence | receiver-local quarantine at exact cursor; no global fact or silent retargeting |
| contact, transport, encryption, harness, or root key used in wrong role | reject |
| card sequence gap, wrong predecessor, or fork | quarantine card series |
| card key binding cites another `me_id` or inactive certificate | reject/incomplete |
| card embeds endpoint credential or private key | reject and report compromise evidence |
| route or capability claim treated as grant | reject |
| exact active offer and acceptance exchange both current cards | relationship active |
| offer and acceptance exchange signed identity, route, capability, grant proposal, and encryption-key refs | accept complete handshake |
| one side never accepts | relationship pending; no `/tribe` membership |
| acceptance changes role, principal, card, or proposal byte | reject |
| acceptance first observed after expiry without trusted receipt/checkpoint | time-unverifiable; no relationship |
| offer replay | idempotent |
| two distinct acceptances or relationship-ID collision | quarantine relationship |
| unilateral directory insertion | no relationship |
| active relationship with no grant | member for status; no resource access |
| relationship member has no route | resolve as unroutable, retain membership |
| current card expires after an accepted grant | relationship/grant remain; delivery unroutable until current successor card |
| either participant closes exact relationship | terminal; all its grants ineffective |
| re-pair after closure reuses relationship ID | reject; fresh nonce/ID required |
| exact controller issues and subject accepts root grant | active within interval and policy |
| root grant is not equal to or narrower than an accepted proposal | reject, including later grants under the relationship |
| subject does not accept grant | offered only; no access |
| grant binds another genesis/contact key | reject |
| encryption-key rotation with same principal/current card | grant identity remains; delivery uses new current key |
| operational key or body is mistaken for grant subject identity | reject |
| permission uses unknown resource or operation alias | incomplete/reject; never guess |
| resource name/path similarity expands scope | reject; IDs are indivisible |
| non-delegable permission has positive depth or birth limit | reject |
| empty permission set | valid zero-access grant |
| child omits permissions or shortens expiry | valid attenuation |
| child adds resource/operation, extends expiry, depth, or birth limit | reject |
| child delegates a non-delegable permission | reject |
| child parent subject differs from child grantor | reject |
| child combines two parent grants in one grant | reject; issue separate grants |
| delegation sequence gap or wrong predecessor | reject/incomplete |
| two child grants occupy one delegation position | quarantine lane and descendants |
| upstream grant expires, closes, revokes, relinquishes, or forks | every descendant ineffective |
| downstream grant tries to outlive ancestor | reject at issuance |
| revoker is neither grantor nor subject | reject |
| ancestor grantor directly revokes a child grant | reject; it may revoke only its own ancestor grant |
| grantor revokes | revoke and cascade; retain history |
| subject relinquishes | deactivate and cascade its descendants |
| revocation replay | idempotent |
| revocation timestamp attempts to erase prior history | reject interpretation; signed time is not ordering authority |
| revocation followed by same grant replay | remains revoked |
| new authority after revocation | fresh grant and acceptance required |
| partition lacks fresh revocation evidence | report exact cursor; never claim global currentness |
| sensitive operation uses stale grant cursor | refuse per freshness policy |
| valid birth commitment before newborn keys exist | inert promise only |
| parent issues newborn grant before acceptance/genesis | reject |
| newborn grant cites another offer, acceptance, commitment, or index | reject |
| newborn grant subject differs from newborn `me_id` | reject |
| newborn grant uses parent credential, grant ID, private key, session, or route secret | reject/compromise evidence |
| newborn grant is within commitment and active parent scope | offered to exact newborn |
| newborn independently accepts fresh grant | activate derived relationship/access |
| newborn acceptance has no prior active derived relationship | accept atomically when all birth/ancestry evidence is valid |
| parent signs acceptance for newborn | reject |
| commitment permission exceeds parent scope | grant invalid; newborn identity unaffected |
| grant narrows commitment or parent scope | accept narrower effective access |
| one birth consumes several permissions | count once against each used permission |
| same accepted grant is retried | no additional birth-budget consumption |
| later distinct grant cites same commitment | reject later grant; canonical first allocation remains unchanged |
| canonical commitment grant is never accepted or expires | record unfulfilled; no V0 re-issue for that commitment |
| two distinct grants collide at canonical delegation position | quarantine lane under Section 6.4; no unique allocation |
| birth limit reached exactly | accept otherwise valid last allocation |
| birth limit plus one | reject before effect |
| revocation refunds birth count | reject; allocation remains consumed |
| missing delegation predecessor hides prior birth allocations | incomplete; no grant |
| empty birth commitment interpreted as wildcard | reject; zero access only |
| failed grant invalidates birth or `/me` | reject coupling; lineage identity remains valid |
| birth grant automatically joins parent `/we` | reject |
| relationship or grant used as source/species/identity authority | reject |
| `/tribe` resolution uses exact active relationships | include counterpart with authority refs |
| root controller resolves newborn in its derived relationship | include newborn symmetrically with exact relationship evidence |
| attributable parent is not the root controller | authorizing the birth grant alone adds no resolved member |
| transport audience adds a recipient | reject; adapter is route input only |
| grant changes relationship membership | reject; authorization is separate |
| resource delivery lacks exact active grant and policy | refuse before sealing |
| sealed delivery recipient/key differs from resolution/grant evidence | reject |
| successful decrypt or transport ACK grants forwarding | reject |
| unauthorized status distinguishes tribe, member, grant, route, or revocation state | closed oracle-resistant denial |
| knowledge grant permits remote query | return attributed external result under grant |
| knowledge bytes copied into `/me.memory` or inherited at birth | reject |
| bounded encrypted delivery cache retains attribution and expiry | permitted disposable projection |
| cache row, HMK row, or Tribe message becomes canonical grant/content identity | reject |
| locally learned insight cites tribal evidence in new personal event | permitted only under DM-017 policy; external authorship retained |
| revoked knowledge access deletes canonical event history | reject; remove only targeted cache/projection state |
| Tribe v1 directory/epoch/principal used as relationship authority | reject |
| v0 group key or history offered for migration | reject |
| exact collection/byte/depth bound | process normally when otherwise valid |
| any bound plus one | reject before cryptography, fetch, or effect |

## 14. Cross-protocol and downstream contracts

- DM-010 supplies exact Daimon principals, operational credentials, compromise
  cutoffs, and identity quarantine. A grant binds `me_id`, never a body or
  operational key.
- DM-011 supplies canonical events, strict bytes, signatures, recipient
  encryption, delivery authorization, and checkpoints. Section 3 registers the
  additive DM-016 event/domain names; existing vector bytes do not change.
- DM-012 resolves `/tribe` from exact active relationship evidence, records
  relationship/grant refs and high-waters, and applies grants to disclosure
  authorization without letting them change membership.
- DM-013 commitments use exact `tribe_ref` and resource references from this
  document. The fresh-grant, newborn acceptance, attenuation, expiry, depth,
  revocation, and birth-limit rules in Section 7 are mandatory; no birth
  identity validity depends on successful grant issuance.
- DM-015 `tribe-shared` publication requires an independently current DM-016
  grant for exact recipient/resource/operation. Source evidence never creates
  that grant.
- DM-017 freezes memory categories and MUST enforce Section 10: tribal content
  remains external and attributed; any later learning is a new cited decision,
  never silent copying or inheritance.
- DM-018 freezes card, endpoint, capability, resource-adapter, and migration
  contracts without granting adapters relationship authority.
- DM-023 projects relationship/grant ancestry, forks, high-waters, revocations,
  birth allocations, and resolution cursors deterministically.
- DM-050 through DM-055 import Tribe Bridge only as transport, authorization
  implementation evidence, and migration provenance under Section 11.
- DM-060 validates synthetic birth with fresh grants, limits, revocation, empty
  autobiography, and no automatic `/we` membership.
- DM-071 validates consented tribe exchange, human/Daimon handshakes, grant
  attenuation, recipient encryption, oracle resistance, and remote-knowledge
  attribution with synthetic content only.
- DM-073 independently reviews key roles, delegation forks, stale revocation,
  birth-budget races, privilege amplification, disclosure, cache deletion, and
  migration before release.
