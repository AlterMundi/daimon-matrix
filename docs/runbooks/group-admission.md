# Owner-local shared group admission

Cluster [#227](https://github.com/nicoechaniz/daimon-cluster/issues/227) owns the
portal transaction; Matrix [#358](https://github.com/AlterMundi/daimon-matrix/issues/358)
owns its SDK publication and disclosure support. These additions do not select a
production release or complete an admission by themselves.

## Public authority history

`operator_messaging.public_authority_history(document, history)` verifies at most
256 signed predecessor epochs ending at the exact current authority in
`document`. It accepts the existing full public snapshots and compact native
restart entries. It returns `RootHistoryAuthority`, suitable for the existing
`load_runtime(relationship_authorities=...)` argument.

The caller must first authenticate the intended current authority and history
closure through the owning signed selector and its exact application digest.
Self-consistency is not peer approval. Preserve already accepted runtime chains;
the loader rejects replacement of a known authority with a different supplied
one. Historical signatures select their original epoch, never the current key
by approximation. An empty history supplies no historical proof epochs.

The reader opens no foreign ledger, custody or conversation store. Existing
`known_peer_successor` reuses this validation and retains its additional anchored
prefix checks; `adopt_peer_authority` still cannot enroll an unknown peer.

## Additive application publication

`operator_messaging.admit_group_application` accepts an exact predecessor digest,
the reviewed successor application, the explicit added being references and only
their new per-body transport key sources. Existing clients, intake, routes,
stores, channel policy and authority snapshots stay unchanged. Governance and
body registrations append to the original application. Every new registration
must belong to an approved active Root body; the resulting roster must cover the
actual complete signed membership.

Call it under the existing runtime writer after Cluster has fenced the old
senders. Load a fresh offline base runtime with the approved public authority
closure and a closed controller in catalog migration mode. Do not reuse a
controller already composed for the predecessor application. Ingest the actual
verified membership acceptance before publication; this operation cannot author
or substitute it. An own/known Root update is a separate existing successor
operation, not an unrelated delta to hide in an admission.

The operation retains one deterministic existing-format generation, signed
predecessor and successor bytes, and uses exclusive durable file publication.
Retry verifies existing bytes and resumes missing writes, including torn staging
files or a lost reply after pointer publication. It never remints a client or
replaces stores. A `current` or `group-application-published` result proves only
the application selection, not visibility acceptance or completed admission.

## Exact group visibility acceptance

`group_visibility_disclosure` derives participants, the actual Tribe and local
membership/channel from the current signed application and verified relationship
store. Supply the receiving owner's approved destination and one retained issue
time. Do not derive either the destination or approval from a peer's text.

`accept_group_visibility` verifies that exact disclosure before signing only the
receiving being's binding. Different bodies never sign for a different being.
Existing members and a genuine prepared newcomer use the same native binding
format. A peer may propose another member's local group channel, but it cannot
omit members, substitute a membership/Tribe or select a destination. A stale
application inventory cannot authorize the signature.

`publish_group_visibility` requires every participant's verified binding. For an
existing application, pin the original installation document digest; only the
participant expansion and its corresponding group disclosure may change. The
destination, presentation, risk, keys, qualification and existing history remain
intact. A first group installation instead takes the owner's explicitly approved
destination, private file references and retained Telegram qualification. Choose
a new group installation path: do not overwrite the native baseline installation.

The complete candidate is checked by the native visibility loader before the
selection changes. Retained preimages and exact candidate bytes make a lost
selection reply resumable without another generation or new consent signature.
Only the original or exact intended installation is accepted: a later signed
selection conflicts, rather than being replaced by a stale retry. Temporary
documents stay in an operation-private directory; secrets stay at their existing
owner paths. No network probe, speech, model, membership or positive egress gate
is started by these SDK functions.

The qualified Cluster owner routes, public-history selector and before/after
receiving transaction remain unfinished. Do not substitute `republish`, the
same-audience `visibility_presentation`, or an archived pair installation for the
new operations. Keep the prepared VPS software update independent of this work.
