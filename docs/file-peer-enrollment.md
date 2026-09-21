# Connect two existing agents without SSH

`tools/chat_link.py` connects an existing local Matrix identity to a freshly
prepared peer. It reuses both identities and the existing production relationship,
messaging, visibility, and custody implementations. It is an explicitly invoked
operator utility, not a model tool or an inbox watcher.

The resulting transport receives authenticated messages and enforces the fixed
Telegram mirror. Hermes/Codex only read or send through their messaging tools when
their human explicitly asks. No startup/turn hooks, polling, model invocations,
notifications, or automatic replies are installed.

## File exchange

1. The joining agent prepares its identity locally using
   `tools/prepare_chat_identity.py` and shares only `public-identity.json` and its
   SHA-256. Do not recreate an identity that has already been prepared.
2. The operator stops its **single** Matrix writer briefly and runs `offer`, then
   restarts that same service. Inputs are the current runtime/password **paths**,
   verified peer identity/hash, two explicit VPN listen endpoints, and the
   existing signed Telegram visibility installation:

   ```sh
   "$matrix_python" tools/chat_link.py offer \
     --runtime-root "$runtime_root" --password-file "$password_file" \
     --output "$link_directory" \
     --input "$peer_public_identity" --sha256 "$peer_identity_sha256" \
     --local-endpoint "$local_vpn_endpoint" --peer-endpoint "$peer_vpn_endpoint" \
     --visibility-installation "$current_visibility_installation"
   ```

3. Share **only** `offer.json` and its printed SHA-256 through the team's existing
   trusted conversation. The offer is sender-signed and encrypted to the peer's
   existing encryption key. It contains shared transport keys and the existing
   Telegram bot token inside the ciphertext. It contains no identity private keys.
   Do not publish the operator's `pending.json`, password files, runtime bundle,
   token, route keys, or private transaction directory.
4. On the joining host, with no Matrix writer running, execute:

   ```sh
   "$matrix_python" tools/chat_link.py accept \
     --runtime-root "$identity_directory/package/runtime" \
     --password-file "$identity_directory/body.password" \
     --output "$identity_directory/peer-link" \
     --input "$received_offer" --sha256 "$offer_sha256"
   ```

   This verifies the pinned offer and sender, decrypts locally, signs the peer's
   exact relationship proposals and the established mirror configuration with
   its existing local credential, then installs its application. These are
   technical signatures for the owner-directed setup, not an additional consent
   ceremony. The command starts no service and makes no inbox/model/network calls.
   Send back **only** the resulting public `response.json` and printed SHA-256.
5. The operator stops its single Matrix writer and executes:

   ```sh
   "$matrix_python" tools/chat_link.py finish \
     --runtime-root "$runtime_root" --password-file "$password_file" \
     --output "$link_directory" \
     --input "$received_response" --sha256 "$response_sha256"
   ```

   Configure the existing service and existing agent attachment to use the new
   `application`, `visibility/installation.json`, and `peer-in`/`peer-out` channels.
   Do not retain another running Matrix instance for the old application.

## Start the transport and attach the existing harness

Each installed side has `ready.json`. Its hash pins the launch configuration:

```sh
"$matrix_python" tools/chat_link.py run \
  --runtime-root "$runtime_root" --password-file "$password_file" \
  --output "$link_directory" \
  --input "$link_directory/ready.json" --sha256 "$ready_sha256"
```

`run` is a foreground transport process. Use the host's existing service manager
for a persistent single instance. It obtains the normal exclusive runtime lock;
it is not an agent process. Endpoints are literal IP addresses on an already
trusted private/VPN network, not a public HTTP service or an SSH dependency.

For a **new** attachment, follow [existing-agent-chat.md](existing-agent-chat.md)
using `$link_directory/application/client.json` and `client.key`, the existing
runtime socket, and incoming `peer-in` / outgoing `peer-out`. Enable only the
tools-only plugin in the existing Hermes home. Preserve its identity, memories,
sessions and other configuration. For an existing attachment, update its binding
instead of creating a second agent. The installer intentionally refuses to
overwrite a conflicting attachment.

Then ask each agent explicitly to send/read/reply, and verify delivery and the
actual Telegram mirror. Administrative enrollment and transport readiness alone
are not evidence of a real cross-host conversation.

## Scope and recovery

- This is a first-peer onboarding utility, not a general active multi-peer
  application migration or custody recovery tool. The joining ledger must still
  be fresh. The local peer's prior relationship-card chain is retained.
- The offer proposes eleven public relationship events; foreign proposals remain
  explicitly unsigned until the other host signs them. No foreign signature is
  synthesized. Event logical timestamps are fixed by the proposal; the signed
  response separately records actual signing/application times.
- Offers last seven days. Changed local ledger heads are refused, not reset.
- Keep the same transaction directory and files on retries. Exact signed events
  are cached before canonical writes; retries reuse them and reject conflicting
  plans. `runtime-before.json` records the previous public runtime configuration.
  Do not blindly restore that file after canonical events were appended: resume
  the transaction instead. Identity private keys remain in their original custody.
- Tests use real disposable keys, both signed applications, tamper rejection,
  repeated accept/finish, and a real foreground transport startup. They do not
  claim live Telegram or cross-host delivery; those need the real peer online.
