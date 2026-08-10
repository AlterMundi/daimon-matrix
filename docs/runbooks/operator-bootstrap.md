# Root-bound plural-being bootstrap

`daimon-bootstrap` is the Matrix-owned operator ceremony used when no current
root-bound being exists to migrate. It creates one fresh self-certifying root,
an encrypted offline root/recovery custody and two or more active embodiment
runtimes. Cluster installs the resulting runtime directories but never creates
or interprets their identity.

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

## Ceremony

Open each password as an inherited descriptor and invoke the installed command:

```bash
daimon-bootstrap \
  --output /secure/staging/compaii-bootstrap \
  --profile /secure/input/profile.json \
  --root-password-fd 3 \
  --runtime-password-fd host-a=4 \
  --runtime-password-fd host-b=5 \
  3</secure/input/root.password \
  4</secure/input/host-a.password \
  5</secure/input/host-b.password
```

The process coordinating this initial ceremony necessarily handles every fresh
key in memory. It must therefore run on the designated trusted bootstrap host.
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

Before service start, validate the V7 schema, open each custody with its own
password, compare the common being/control/manifest hashes and prove every
embodiment, incarnation, credential, root, ledger and socket is distinct.

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
