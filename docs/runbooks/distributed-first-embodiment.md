# Distributed first embodiment and plural continuity

This is the operational path from a threshold-separated genesis to the first
runnable embodiment, then to additional embodiments. No process opens more than
one root holder package, and no target host receives a root seed.

The holder labels describe independent encrypted packages and process
invocations. They do not require different people. One operator may execute all
steps while preserving the cryptographic 2-of-3 separation, provided each
password and package remains separately controlled.

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
