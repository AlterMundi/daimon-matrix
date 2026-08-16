# Distributed genesis and synthetic bootstrap fixture

`daimon-genesis` is the production-shaped first stage for a new being. Each
root and recovery holder runs `create-holder` separately, retains one encrypted
seed in one owner-only package, and publishes only `descriptor.json`. An
operator freezes those public descriptors with `create-intent`; each holder
then runs `sign`, and the keyless `aggregate` step emits the genesis artifact.
Threshold shortfall, duplicate shares, role substitution and key substitution
fail closed.

`daimon-synthetic-bootstrap` is retained only as a local deterministic fixture.
It centralizes every root and recovery seed in one process and one store and is
not an operational custody procedure.

The ceremony is one shot: the output path must not exist, all files are created
owner-only, and publication is an fsynced atomic directory rename. Passwords
enter only through inherited file descriptors. Private keys, passwords and
capability keys never enter argv, environment, stdout, the public runtime bundle
or the public receipt.

## Profile

The profile is public canonical JSON. Rows must be sorted by `label`; identifiers
and advertised endpoints must be unique. `listen_host` is the local bind address,
while `advertised_endpoint` is the exact HTTP(S) AnyVPN address the other
embodiments use.

```json
{
  "schema": "dm.operator.bootstrap-profile/v1",
  "embodiments": [
    {
      "advertised_endpoint": "http://198.51.100.10:8686/dm-peer/v1",
      "body_ref": "cluster:host-a:compaii",
      "label": "host-a",
      "listen_host": "198.51.100.10",
      "listen_port": 8686,
      "principal_id": "compaii@host-a"
    },
    {
      "advertised_endpoint": "http://198.51.100.20:8686/dm-peer/v1",
      "body_ref": "cluster:host-b:compaii",
      "label": "host-b",
      "listen_host": "198.51.100.20",
      "listen_port": 8686,
      "principal_id": "compaii@host-b"
    }
  ]
}
```

The sample addresses are documentation-only. Do not publish a real private
endpoint in repository evidence.

## Distributed genesis ceremony

Run each `create-holder` and `sign` invocation in its holder's independent
process and custody boundary. The following abbreviated example shows the file
flow; passwords enter through inherited descriptors and every output path must
be new:

```bash
daimon-genesis create-holder --role root --password-fd 3 --output root-a 3<root-a.password
daimon-genesis create-holder --role recovery --password-fd 3 --output recovery-a 3<recovery-a.password
daimon-genesis create-intent --descriptor root-a/descriptor.json --descriptor root-b/descriptor.json --descriptor recovery-a/descriptor.json --descriptor recovery-b/descriptor.json --root-threshold 2 --recovery-threshold 2 --output genesis-intent.json
daimon-genesis sign --intent genesis-intent.json --holder root-a --password-fd 3 --output root-a.share.json 3<root-a.password
daimon-genesis sign --intent genesis-intent.json --holder recovery-a --password-fd 3 --output recovery-a.share.json 3<recovery-a.password
daimon-genesis aggregate --intent genesis-intent.json --share root-a.share.json --share root-b.share.json --share recovery-a.share.json --share recovery-b.share.json --output genesis.json
```

The holder package and its descriptor are committed by one fsynced directory
rename. A crash before that rename leaves no target package and retry is safe.
The aggregator opens no holder package and receives no password or private key.

## Synthetic fixture

Open each password as an inherited descriptor and invoke the installed command:

```bash
daimon-synthetic-bootstrap \
  --output /secure/staging/compaii-bootstrap \
  --profile /secure/input/profile.json \
  --root-password-fd 3 \
  --runtime-password-fd host-a=4 \
  --runtime-password-fd host-b=5 \
  3</secure/input/root.password \
  4</secure/input/host-a.password \
  5</secure/input/host-b.password
```

This fixture handles every fresh key in memory and therefore does not establish
separated custody. Never use its evidence to claim a production quorum.
After encrypted runtime directories are transferred through an authenticated
channel and verified on their destination hosts, remove the transferred copy
from staging. At rest, each host retains only its own encrypted runtime and
transport custody; the root/recovery custody remains offline and separate.

The output contains:

- `authority.json` and `receipt.json`: secret-free root/manifest evidence;
- `offline/root-custody.json`: encrypted root and recovery seeds;
- `runtimes/<label>/runtime.json`: closed V7 bundle with exact peer targets;
- `runtimes/<label>/custody.json`: runtime signing, peer encryption and local
  capability secrets;
- `runtimes/<label>/transport-custody.json`: the separately generated transport
  principal key retained for future adapters; and
- `runtimes/<label>/client.json` plus `client.key`: host-local CLI material.
- `host-clients/<label>/client.json` plus `capability.key`: a distinct
  least-authority status observer with exactly `runtime.status`, `scope.me`,
  `scope.we`, `scope.we.diff`, and `scope.we.sync-plan`. Install this directory
  into the host controller's owner-only, non-portable client root; never give
  the controller the operator client key.

Before service start, validate the V7 schema, open each custody with its own
password, compare the common being/control/manifest hashes and prove every
embodiment, incarnation, credential, root, ledger and socket is distinct.
The status-observer key must differ from the operator key and remain outside
portable snapshots. A relocated or restored runtime receives a freshly
provisioned host-local copy only after the expected server origin matches the
current root-authorized embodiment/incarnation.

## Configured peer pull

V7 moves remote peer endpoints into the closed runtime bundle. An authenticated
client no longer supplies a URL per call:

```bash
daimon --socket "$state_root/matrix.sock" \
  --client-config "$state_root/client.json" \
  --capability-key-fd 3 \
  sync peer-pull \
  --sync-request-id "$target_request_id" \
  --target-embodiment-id "$remote_embodiment_id" \
  --limit 100 \
  3<"$state_root/client.key"
```

Use the target request ID and limit returned by `scope sync-plan`. Matrix
resolves the endpoint only from the verified bundle, sends an encrypted native
peer request, validates the exact response and atomically imports the page. A
successful pull is additive; it never adopts the remote event locally.

## Rollback and backups

Before the first effect, preserve the prior complete service release and a
verified Cluster backup. Once running, quiesce Matrix and create portable
snapshots; never copy a live SQLite root. Rollback disables the listener first,
restores the matching executable and public/host-local material, and preserves
canonical ledgers plus peer outbox/exchange evidence. Never restore one host's
private custody into another or lower a keystore/ledger high-water.
