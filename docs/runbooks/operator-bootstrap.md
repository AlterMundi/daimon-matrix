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

Ceremony outputs are published with fsynced atomic renames and all private files
are owner-only. The exact exception to the new-output rule is `create-holder`:
retrying after the final directory rename opens the existing package with the
supplied password and returns its descriptor only when the directory has the
complete expected file set, requested holder role, pending control head, single
expected secret slot, and matching derived public key. A wrong password, role,
file set, slot or key is a conflict and fails closed; it never overwrites or
regenerates the holder. Passwords enter only through inherited file descriptors.
Private keys, passwords and capability keys never enter argv, environment,
stdout, the public runtime bundle or the public receipt.

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
flow; passwords enter through inherited descriptors. Outputs must be new except
for the exact validated `create-holder` post-rename retry described above:

```bash
daimon-genesis create-holder --role root --password-fd 3 --output root-a 3<root-a.password
daimon-genesis create-holder --role recovery --password-fd 3 --output recovery-a 3<recovery-a.password
daimon-genesis create-intent --descriptor root-a/descriptor.json --descriptor root-b/descriptor.json --descriptor recovery-a/descriptor.json --descriptor recovery-b/descriptor.json --root-threshold 2 --recovery-threshold 2 --output genesis-intent.json
daimon-genesis sign --intent genesis-intent.json --holder root-a --password-fd 3 --output root-a.share.json 3<root-a.password
daimon-genesis sign --intent genesis-intent.json --holder recovery-a --password-fd 3 --output recovery-a.share.json 3<recovery-a.password
daimon-genesis aggregate --intent genesis-intent.json --share root-a.share.json --share root-b.share.json --share recovery-a.share.json --share recovery-b.share.json --output genesis.json
```

The holder package and its descriptor are committed by one fsynced directory
rename. A crash before that rename leaves no target package and retry is safe; a
crash immediately after it is recovered by the exact idempotent validation path.
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
- `runtimes/<label>/client.json` plus `client.key`: the safe default `observe`
  client. It cannot invoke any mutation;
- `runtimes/<label>/operator-clients/<role>/client.json` plus `capability.key`: one
  owner-only client directory for each mutating role (`weave`, `communication`,
  `curator`, `memory`, `relationships`, `review`, `routes`, `sources`, and
  `species`). Every role has a distinct random key and encrypted-custody slot.
- `runtimes/<label>/host-clients/status/` and `host-clients/curator/`: two
  additional owner-only host-bound clients. Status contains exactly
  `runtime.status`, `scope.me`, `scope.we`, `scope.we.diff` and
  `scope.we.sync-plan`; curator contains exactly the four `curator.*` methods.
  Neither is the broader operator `observe` profile, and their keys and slots
  are distinct from all ten operator roles.

The bundle's `runtime_id` is derived from its label, being root, root-authorized
origin and operational signing key. Exactly twelve capability rows are required:
ten operator roles plus the two host-bound roles. The root-authorized embodiment signing key signs a domain-separated
hash of that exact capability row set together with the runtime ID, label, being,
origin and signing-key ID. Startup verifies the signature against the active
credential. Each row and each `dm.local.client-config/v3` document also repeats
the ID and label. Consequently, copying and publicly relabelling a descriptor,
slot, key or client config from another runtime cannot produce the required
binding signature and fails closed.

Before service start, validate the V7 schema, open each custody with its own
password, compare the common being/control/manifest hashes and prove every
embodiment, incarnation, credential, root, ledger and socket is distinct.
The ten operator profiles are disjoint and together cover the service surface; no
capability is an all-method signer oracle. A caller must select the narrow role
for the operation it is about to perform. A relocated or restored runtime is
reprovisioned as a fresh embodiment and never inherits these client keys from
another embodiment.

## Expiry and reprovisioning

Every generated role capability expires 30 days after preparation. The public
receipt records both `reprovision_at_ms` (seven days before expiry) and
`expires_at_ms`. Schedule a fresh `daimon-rebirth prepare`/`authorize`/`activate`
ceremony no later than `reprovision_at_ms`, validate and start that new
root-authorized embodiment, then park or revoke the predecessor through the
normal signed authority transition. This creates new keys and role descriptors;
there is deliberately no multi-file in-place key rotation. At hard expiry, or
if any descriptor is marked revoked, runtime loading and request authentication
fail closed. Rerunning `daimon-synthetic-bootstrap` is only a disposable-fixture
rebuild and is not an operational rotation procedure.

## Configured peer pull

V7 moves remote peer endpoints into the closed runtime bundle. An authenticated
client no longer supplies a URL per call:

```bash
daimon --socket "$state_root/matrix.sock" \
  --client-config "$operator_clients/weave/client.json" \
  --capability-key-fd 3 \
  sync peer-pull \
  --sync-request-id "$target_request_id" \
  --target-embodiment-id "$remote_embodiment_id" \
  --limit 100 \
  3<"$operator_clients/weave/capability.key"
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
