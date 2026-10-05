# Distributed first embodiment and plural continuity

After activating the body, complete [native interactive harness
onboarding](native-harness-onboarding.md). The current everyday interface for
every daimon is its ordinary interactive harness command; a task executor or
daemon-only qualification is not operational onboarding acceptance.

This is the operational path from a threshold-separated genesis to the first
runnable embodiment, then to additional embodiments. No holder invocation opens
more than one root holder package, and no target runtime custody receives a
root seed. Offline holder hosts are the default. An explicitly authorized
Source operator may keep separate online holder custody on an authorized host,
including a Source embodiment host, under [the online custody runbook](source-online-custody.md).

The holder labels describe separate encrypted packages and process invocations,
not necessarily different people. Thresholds are explicit generic M-of-N
policies; distinct 1-of-1 root and recovery policies are supported. One operator
may execute all holder steps, but centralized control does not establish an
independent quorum. The abbreviated example uses two root shares; collect the
actual declared threshold, without changing the keyless aggregation contract.
The `/offline/` paths illustrate the default mode, not CLI-enforced isolation.

## First embodiment

Create the target profile as canonical JSON using schema
`dm.operator.rebirth-target-profile/v1`. For the first embodiment its `targets`
array is empty. The advertised endpoint must end in `/dm-peer/v1`.

```bash
daimon-first-embodiment prepare \
  --genesis /public/genesis.json \
  --profile /public/first-profile.json \
  --password-fd 3 \
  --output /target/first-preparation 3</target/first.password

daimon-first-embodiment root-share \
  --genesis /public/genesis.json \
  --request /target/first-preparation/request.json \
  --holder /offline/root-a \
  --password-fd 3 \
  --output /public/first-root-a.share.json 3</offline/root-a.password

daimon-first-embodiment root-share \
  --genesis /public/genesis.json \
  --request /target/first-preparation/request.json \
  --holder /offline/root-b \
  --password-fd 3 \
  --output /public/first-root-b.share.json 3</offline/root-b.password

daimon-first-embodiment aggregate \
  --genesis /public/genesis.json \
  --request /target/first-preparation/request.json \
  --share /public/first-root-a.share.json \
  --share /public/first-root-b.share.json \
  --output /public/first-activation.json

daimon-first-embodiment activate \
  --genesis /public/genesis.json \
  --preparation-dir /target/first-preparation \
  --request /target/first-preparation/request.json \
  --activation /public/first-activation.json \
  --password-fd 3 \
  --output /target/first-package 3</target/first.password
```

The output contains a V7 runtime with manifest revision 1 and one active
embodiment. The target custody contains fresh embodiment, transport and
least-authority capability keys only. The root-share outputs and activation are
public canonical artifacts. The aggregator is keyless.

## Additional embodiment

Export the current public authority document from the running release. The new
target profile lists every current active embodiment and its configured
endpoint. Prepare the target, freeze the exact successor, collect one paired
share from each required root holder, then aggregate without keys:

```bash
daimon-rebirth prepare \
  --authority /public/current-authority.json \
  --profile /public/new-target-profile.json \
  --output /target/new-preparation \
  --password-fd 3 3</target/new.password

daimon-rebirth create-enrollment-intent \
  --authority /public/current-authority.json \
  --request /target/new-preparation/request.json \
  --output /public/new-enrollment-intent.json

daimon-rebirth enrollment-share \
  --authority /public/current-authority.json \
  --request /target/new-preparation/request.json \
  --intent /public/new-enrollment-intent.json \
  --holder /offline/root-a \
  --password-fd 3 \
  --output /public/new-root-a.share.json 3</offline/root-a.password

daimon-rebirth enrollment-share \
  --authority /public/current-authority.json \
  --request /target/new-preparation/request.json \
  --intent /public/new-enrollment-intent.json \
  --holder /offline/root-b \
  --password-fd 3 \
  --output /public/new-root-b.share.json 3</offline/root-b.password

daimon-rebirth aggregate-enrollment \
  --authority /public/current-authority.json \
  --request /target/new-preparation/request.json \
  --intent /public/new-enrollment-intent.json \
  --share /public/new-root-a.share.json \
  --share /public/new-root-b.share.json \
  --output /public/new-activation.json

daimon-rebirth activate \
  --base-runtime /public/current-runtime.json \
  --preparation-dir /target/new-preparation \
  --request /target/new-preparation/request.json \
  --activation /public/new-activation.json \
  --output /target/new-package \
  --password-fd 3 3</target/new.password
```

Generate a forward-only candidate for each existing peer before an atomic,
quiesced deployment of that public file:

```bash
daimon-rebirth advance-bundle \
  --authority /public/current-authority.json \
  --base-runtime /existing/runtime.json \
  --request /target/new-preparation/request.json \
  --activation /public/new-activation.json \
  --target-endpoint https://new-target.example/dm-peer/v1 \
  --output /existing/runtime.next.json
```

`advance-bundle` does not modify the running runtime or its writable stores. It
verifies the request and activation, appends the signed authority epoch and
writes a new candidate only. Host orchestration must stop or quiesce the daemon,
atomically install the candidate and restart it; Cluster owns that transaction.

Historical events keep their original manifest hashes. The successor bundle
contains the prior manifest and signed transition in `authority_history`, so a
new empty embodiment can authenticate and ingest events created before it
existed. Peer pull is encrypted, replay-safe and additive; it never copies
another embodiment's private custody or adopts its local decisions.

## Host a body that has no messaging application

A package produced by `activate` cannot be served by `daimon-matrixd
--closed-visibility` until its own egress catalogs carry the echo subset. A body with
peer transport registers two catalogs — one over its peer outbox and one over its peer
exchange store — and the registry check demands the visibility tables in each. Every
other caller of the installer needs something this body does not have: a messaging
application, a link ceremony, or an owner visibility installation.

Provision it once, before the first start, with the daemon's own verb:

```bash
python -I -m daimon_matrix.daemon \
  --state-root /target/package/runtime \
  --closed-visibility \
  --provision-visibility \
  --password-fd 3 3</target/body.password
```

It takes the state-root writer lock, installs the echo subset into the catalogs this
body registered, validates them, logs `visibility_provisioned` and exits without binding
a listener. It is idempotent, it never registers an egress transport, and it leaves the
body receive-only. A catalog that is genuinely invalid still fails closed rather than
being repaired. The verb is closed-visibility only: a body with an owner installation
already has `operator_messaging migrate-visibility`, and that verb validates the
installation as it goes.

Then host it normally, and expect `{"code":"ready"}`:

```bash
python -I -m daimon_matrix.daemon \
  --state-root /target/package/runtime \
  --closed-visibility \
  --password-fd 3 3</target/body.password
```

If a start is refused, the diagnostic names the cause —
`{"code":"startup_refused","detail":"<ErrorType>:<stable_code>"}`. The detail is
included only when it is a bare lowercase code, so a stdlib error carrying a path, a
URL or key material is reported by its type name alone and nothing leaves the process.

## Re-publish messaging applications after the advance

An enrollment advances the being manifest, and two kinds of document respond
differently to that. Append-only records — relationship cards and the capability
journal — verify against the epoch they name, through the history the successor
bundle carries. Current-state documents do not: an application publication and its
visibility installation pin the epoch they were issued under, by design, and the
daemon compares that pin to its present authority exactly. So a body that carries a
messaging application will refuse to start once its bundle is advanced, reporting
`messaging_visibility_installation_rejected`.

Advance such a body only with the repair step ready, in this order:

```bash
python -I -m daimon_matrix.operator_messaging republish \
  --state-root /existing/runtime \
  --app-dir /existing/messaging-application \
  --visibility-installation /existing/visibility/installation.json \
  --password-fd 3 3</existing/body.password
```

Run it with the daemon stopped: it takes the same runtime writer lock. It derives
one successor from the application that is already published, changing exactly one
field — this being's entry in `authorities`, replaced by the present epoch's public
authority document. Routes, stores, `relationship_mode`, the client descriptor and
every secret reference are carried over untouched, and no capability is re-minted
and no key is rotated, so existing messaging clients keep working unchanged. It is
idempotent: against an application that already pins the present epoch it reports
the current digest and appends no generation.

The predecessor is proved authentic before it is used, by verifying its binding
against the epoch it names rather than against the present one, so an unverified
file on disk is not a predecessor and a tampered one is refused without any change
to the published pointer.

The visibility installation is re-signed for the same reason and with the same
limit. Two owner-side pins move: the installation's `application_sha256`, and the
owner's own entry in `acceptance_set.bindings`, which is a binding over the
disclosure and so carries the epoch's manifest digest. The installation generation
advances, which fail-closes any echo retry command issued against the previous
installation instead of letting it resolve against a policy that is no longer
current.

What does not move is the part that carries consent. `disclosure` is reproduced
byte-identically, so `acceptance_set.disclosure_sha256` is unchanged, and every
participant binding whose actor is not this being still verifies against exactly
the bytes it was issued over. No foreign acceptance is re-requested, widened, or
silently reused for a different disclosure; a re-publication re-attests owner-local
authority over a disclosure nobody re-opened. The replaced installation is kept
beside the new one, so the repair is reversible together with the bundle it was
issued under.

A body with no messaging application needs none of this. Neither does a body whose
bundle was not advanced.
