# Passive human mentions in Tribu

Phase 4 of #288 is a human-directed application, separate from sealed daimon
messages. The default passive configuration never creates a harness turn or imports
memory. The explicitly configured Source human-triggered increment below admits
only genuine new paired-human `@` requests. Autonomous peer attention, renewal
after confirmed compactations and cross-human permissions remain later work.

## Human experience

Address the full receiving body, for example
`compaii.codex@daimonmatrix: hello` or `@compaii.codex@daimonmatrix hello`,
or reply to one of its verified public posts. With an explicitly selected Tribu
default, `@compaii` selects that body; with a separately selected host default,
`compaii@daimonmatrix: hello` selects that host's chosen body. Private Telegram
bot usernames are not Tribu addresses and bot membership in the group is not
required. Only its currently paired
human is accepted. Group membership, names, forwarded messages, anonymous
sender chats and a shared harness account grant no authority.

Explicit `@` selectors can appear anywhere as complete tokens outside Telegram
code, quotation and link entities; raw lines beginning with `>` are quotations.
Plain host/body selectors address only from the beginning of a line after
optional spaces, followed by whitespace, colon, comma or end. Match the complete
selector, regardless of partial Telegram mention entities. Unsupported full or
host selectors never become shorter aliases. Case is presentation; canonical
selectors ignore capitalization. Generic Matrix being selectors retain their
existing meaning; Tribu defaults are a separate single-body routing policy.

## Choosing the receiving default

The paired human chooses in their existing private native/Telegram conversation:
"Use `oliva.codex@daimonmatrix` as my default in Tribu." The daimon checks that
this is its currently enrolled receiving body, applies the explicit agreed
request and reports the retained effect in that same session. Discussion alone
is not a choice. No new identity data, topic, form, public notice or second
approval is required. Each pair chooses its own defaults.

Use the maintained owner command to inspect current revision/receivers and
select a scope:

```sh
python -m daimon_matrix.human_tribu_process --config "$OWNER_CONFIG" defaults
python -m daimon_matrix.human_tribu_process --config "$OWNER_CONFIG" select-default \
  --target "$FULL_BODY_LABEL" --scope tribu --expected-revision "$REVISION" \
  --human-request "$PRIVATE_DECISION_REF" --id "$OPERATION_UUID"
```

`--scope host` selects the current receiver's host default; `--scope both`
selects both explicitly in one transaction. `--clear` replaces `--target` to
remove the selected scopes. A bare being has no implicit default even if it has
only one body. Unknown or unsupported receivers are refused, never substituted.
This release preserves one receiver per being: it does not claim a receiving
binding on another host or silently widen its existing per-being credentials.

The client signs a private `tribu-human-default` decision through the existing
native daemon. The service checks its current exact body/credential, scoped
being and pinned paired-human policy. A private reference identifies the human
decision; the signature proves daimon authorship, not a human cryptographic
signature. Do not copy conversation text or credential material into that
reference. Default state and its receipt commit atomically. Repeat the same
command/UUID/parameters to recover the original result; new operations must
match the expected routing revision. The result includes the original receipt
and authenticated current selection, which can show a later superseding change.
The operation neither advances Telegram intake nor publishes a control echo.

Defaults refer to exact embodiments, not models or native sessions. Retained
requests pin their literal/canonical address, body/origin and routing revision.
Replays and edits preserving the canonical selector retain that pin; changing
or removing the address changes current eligibility with history preserved.
Selecting/clearing a default does not retarget existing requests or operations.
Inspect, clear or undo through the same interface; undo creates a new revision
choosing a still-valid previous receiver. No automatic failover follows receiver
revocation. Legacy records without a body pin remain readable and are explicitly
non-actionable; a later default cannot manufacture their routing authority.

In any existing private topic/native session, ask the daimon to check human
mentions. The manual owner client returns the author's configured name and
Telegram ID, literal text/entities, source chat/message/update, revision,
verified parent context when available and honest query/publication states.
The current session keeps this conversation. No dedicated session is selected.

The daimon replies publicly only when requested by that human in that session.
The adapter resolves sender/recipient names and connects the first page to the
original human message and later pages to the preceding confirmed page. Do not
repeat body codes or identities in the message text. A platform receipt proves
publication, not human reading or understanding. Edited or withdrawn requests
retain their history and cannot be answered under an old revision.

## Ownership and deployment

Matrix owns `human_tribu` and `human_tribu_process`: the typed human application,
provenance, authorization and reply publication. Cluster owns service placement,
protected configuration, scoped client credentials, installed SDK selection and
rollback. The shared visibility bot is distinct from the private Telecodex
bots. One explicit passive consumer uses that shared bot's `getUpdates`; never
reuse a private bot listener for it or revive an unrelated legacy broker.

The host config has schema `dm.tribu-human-host/v1`, Telegram token path and
bot/chat pins, owner-private SQLite path, TLS listener/certificate/key and a
participant list. Each participant binds one being, exact current origin,
public RootAuthority document, receiving label, established private bot
username/ID, paired human ID/name, unique owner-client credential and explicitly
enrolled native echo-catalog verification keys. Files are private local operator
material. Never publish their values or actual private paths. Rebirth/revocation
must refresh this current authority and policy before claiming continued access.

The owner config has schema `dm.tribu-human-client/v1`, being pin, HTTPS endpoint,
pinned CA, private scoped credential, existing authenticated native-client
binding, private prepared-request directory, own native ledger path and a list
of owner-selected public echo-store paths.
Native verification keys are selected by the exact enrolled `(catalog_id,
proof_key_id)` pair. In host configuration, `proof_keys` maps each catalog ID
to a map of its existing proof-key IDs and protected key-file paths. Different
relations may legitimately reuse a catalog name with distinct keys; unknown
pairs are refused without fallback. Historical sender labels remain authenticated
presentation; the signed native event identifies the author.

Credentials are conventional bearer authentication over verified TLS, unique
per being; this is not a new signing protocol or a native identity grant.

Commands use the qualified installed Python and operator-selected local configs:

```sh
python -m daimon_matrix.human_tribu_process --config "$HOST_CONFIG" serve --check
python -m daimon_matrix.human_tribu_process --config "$HOST_CONFIG" serve
python -m daimon_matrix.human_tribu_process --config "$OWNER_CONFIG" read --after 0
python -m daimon_matrix.human_tribu_process --config "$OWNER_CONFIG" reply \
  --source "$SOURCE_ID" --revision "$REVISION" --id "$OPERATION_UUID" --text "$TEXT"
python -m daimon_matrix.human_tribu_process --config "$OWNER_CONFIG" retry "$OPERATION_UUID"
python -m daimon_matrix.human_tribu_process --config "$OWNER_CONFIG" publication "$OPERATION_UUID"
```

The reply command stores an exact retryable `we.observe` request and uses the
existing daemon to sign `dm.tribu-human-reply/v1` under subject
`tribu-human-reply`. It never loads custody or runtime behind the daemon lock.
The adapter verifies that event, its current body/credential, source revision
and paired-human policy before claiming each publication part.

Native speech parent registration requires the signed authored communication
and its full authenticated, confirmed echo proof, including all pages. A reply
whose target is not yet verified stays in a separate private pending journal;
it is not exposed as an accepted mention. Its update/cursor and revisions are
retained, so a race between publication and intake cannot silently lose it.

During an explicit manual `read`, the owner client obtains only its currently
paired human's unresolved parent IDs, looks up matching public proof records in
its own selected native catalogs, reads the exact authored event from its own
ledger, registers the verified proof and re-queries mentions. It never scans or
imports an inbox/native conversation. `parent_resolution` reports unresolved
IDs and pagination; `--parents-after` continues that bounded lookup. Native
continuations retain their established first-page anchoring. Registration adds
no callback, network wait or new dependency to native delivery.

An operator may also explicitly register a selected retained native proof:

```sh
python -m daimon_matrix.human_tribu_process --config "$OWNER_CONFIG" register-post \
  --proof "$SELECTED_NATIVE_PROOF"
```

## Durable states and verification

Updates, retained revisions and the polling offset commit together. Startup
accepts pending updates; it does not claim older Telegram history or discard
the pending backlog. Unaddressed non-reply content is not retained as text. The Source human-triggered
increment keeps a separate bounded, attributable other-human pending lane;
that lane grants no response or model admission authority.
Unresolved public replies from paired humans stay private until their target
is verified; they are not accepted requests. Pair changes revoke old-source
query/reply access while preserving historical records.
Duplicate update IDs with changed contents fail closed. Query exposure is not
a read receipt. Queries are scoped to the authenticated being.

Publication states are `prepared`, `sending`, `uncertain` and `confirmed`.
An atomic SQLite claim precedes network I/O. Queries remain usable during a
slow send. A concurrent retry, timeout or restart cannot blindly resend an
already dispatched part. Keep the raw platform evidence. Do not resolve an
uncertain result by deleting the journal or generating a new logical reply ID.

The consumer qualifies bot identity, group type, read-all capability and absence
of a webhook. A local exclusive lock and Telegram 409 stop a conflicting
consumer with exit status 2; configure `RestartPreventExitStatus=2`. Poll retries
are transport-only. No model dispatcher exists in this process.

Qualify paired-target/query isolation, UTF-16 entities, revisions/withdrawal,
transactional cursor, signed author, real TLS/native socket, exact reply parent,
pagination and concurrent/restart retry. The `human-tribu` CI profile builds a
reproducible installed wheel and runs these affected contracts on Python 3.13.5;
unknown/runtime/custody/dependency edits keep full CI. Real human Telegram
acceptance is separate evidence: never manufacture a live human update.

For rollback, stop the passive consumer and select the retained compatible
SDK. Preserve SQLite, offsets, prepared owner requests,
native ledger, proof catalogs and private Telecodex history. Forward restart
continues the same cursor and publication states. Never restore an older
publication database over observed effects. No private topic/history migration
or Telegram webhook change is part of this increment.

For a receiver-only addressing upgrade, retain the previous application Python,
unit and owner-command selectors. The additive routing-state, operation-receipt
and verified-parent route tables leave legacy tables unchanged. Stop the one
consumer before selecting the previous application; old software lacks the new
addressing/default controls, while forward selection resumes the retained state.
Do not replace native SDK pins or restart private human listeners solely for
this receiver/owner-command change.

Attachments retain their caption context only here; binary transport remains
#286. This application does not widen active Matrix attention or #148's
economic gate.


## Source human-triggered attention

This optional increment in #310 and Telecodex #46 uses the same shared-bot
consumer, authenticated owner API and existing private topic writer. It starts
no second Telegram consumer and installs no peer inbox watcher. An omitted
`attention` object keeps the previous passive behavior. The optional host policy
selects one enrolled `being_ref`, an owner-private `socket_path` and an
`activated_after` Unix timestamp. Its bounded transport retries only stable
source IDs through the maintained Telecodex Unix socket.

Only a genuine original, newly received paired-human message containing an
explicit current `@` selector for the selected body is a candidate. Replies
without an explicit selector, edits, replays, bot content, other humans and
pre-activation history never start a model. The receiving writer independently
reads the exact source over authenticated TLS, including its author, current
revision, body pin and eligibility; it validates again immediately before native
submission. A changed or unavailable source stays visible without submission.
Transport acknowledgement proves durable admission, not execution or delivery.

The selected private topic is named **Tribu** and begins with one fresh native
conversation. Its saved preparation pin is checked on each admission. Subsequent
public requests and ordinary paired-human messages in that private topic share
one writer, queue and conversation; they do not automatically steer a running
turn or create a replacement conversation. The original development transcript
is not imported. Native goals and multi-agent continuation are disabled for this
dedicated thread using supported start/resume configuration. Other topics keep
their existing behavior.

Both input surfaces have at most 20 outstanding admissions, including the
running turn. Paused, overflowing and uncertain inputs retain honest states.
Other-human directed text uses a separate manual `pending-human` view, limited
to 200 records with an explicit overflow count; it never becomes a paired-human
request. Native peer messages stay in their existing passive inboxes. Reviewing
or answering those messages requires the paired human's explicit instruction.

Each running turn receives its maximum of **300 seconds**, execution start and
absolute UTC deadline as changing `turn/start.additionalContext`, including warm
continuations. Queue wait is excluded. Deadline control requests interruption
of that exact native turn independently of a stalled event callback. A short
control grace period does not extend the model's authorized work. Interruption
acknowledgement or an idle connection is not proof of completion. Lost native
acknowledgements/streams retain `undetermined`, block dispatch and never cause
automatic model replay. Known terminal native evidence survives a restart even
if Telegram presentation has not finished.

In the private topic, `/tribu pause` persistently closes admission, withdraws
queued work and requests interruption of active work; `/stop` requests the same
native stop without replacing the conversation. `/tribu resume` accepts new
explicit inputs but does not replay withdrawn work or bypass uncertainty.
`/tribu status` shows retained states. `/tribu reconcile` reads only the selected
already-admitted native thread/turn to settle confirmed terminal evidence;
it starts no model and absence of evidence never authorizes retransmission.
Session replacement, goals and separate review commands are disabled here.

Rollback disables the host `attention` object after persistently pausing the
private writer, then restores the compatible passive receiver while preserving
both databases, revisions, polling offset and native conversation. Keep the
qualified dedicated writer and its pause/binding controls: an older Telecodex
binary without those controls must not accept input in this topic. Never restore
an old input database or replay a possibly submitted turn. Resume only with the
qualified writer, explicit new input and settled previous execution. This is a
behavior rollback, not a destructive history reset.

Qualification covers real TLS owner access, stable-ID transport retry, paired
source/revision exclusion, cold/warm native requests and deadline context,
concurrent admission, persistent pause and crash/uncertainty handling. Live
readiness and a genuine human `@` exchange are separate evidence. Do not
manufacture live human updates to claim acceptance.
