# First native chat: existing Hermes, owner-local preparation

This is the next step after an isolated package installation. It preserves the
existing Hermes conversation/profile and does not import Tribe keys, start a
daemon, bind a listener, or connect to another participant. It is not completed
messaging enrollment: routes and the signed mandatory Telegram installation come
after the two public identities are exchanged.

The team owner has established mandatory plaintext mirroring to the fixed Tribu
Telegram destination. Do not add another participant-acceptance ceremony. The
installed applications still require genuine local signatures and exact policy
bindings; never fabricate another participant's signature.

## Mac already prepared by Oliva

Use the existing isolated CPython 3.11 environment. Its compiled cryptography
50.0.0 dependency is usable on Intel: do not rebuild it, downgrade it, modify
Homebrew, or alter the global Rust/shell configuration. Update **only** the Matrix
package with `--no-deps`. The original environment directory name retains its
historical install pin; retain the verified checkout commit and pip installation
record instead of claiming the directory name identifies the new installed code.

The operator supplies an exact verified `CANDIDATE` commit. Do not substitute a
moving branch or `main`.

```bash
set -eu
CANDIDATE=<exact-commit-from-operator>
PYTHON=<absolute-path-to-existing-isolated-venv>/bin/python
setup_dir=$(mktemp -d)
git -C "$setup_dir" init
git -C "$setup_dir" remote add origin https://github.com/AlterMundi/daimon-matrix.git
git -C "$setup_dir" fetch --depth=1 origin "$CANDIDATE"
git -C "$setup_dir" checkout --detach FETCH_HEAD
test "$(git -C "$setup_dir" rev-parse HEAD)" = "$CANDIDATE" || exit 1
"$PYTHON" -m ensurepip --upgrade
"$PYTHON" -m pip install --no-deps --force-reinstall "$setup_dir"
"$PYTHON" -m pip show daimon-matrix
umask 077
mkdir -p "$HOME/.local/state/daimon-matrix"
"$PYTHON" "$setup_dir/tools/prepare_chat_identity.py" \
  --output "$HOME/.local/state/daimon-matrix/oliva" \
  --label oliva-hermes --body-ref hermes:mac:oliva --principal-id oliva@mac
```

Installing from the verified checkout records a local source path in
`direct_url.json`, not its Git commit. Retain that checkout and the verified
`git rev-parse HEAD` alongside the installation report; together they identify
the installed candidate. If pip is already present, `ensurepip` is unnecessary.

The helper refuses an existing output directory rather than overwriting an
identity. If it reports an error after preparation began, preserve the directory
and report the error; do not delete custody or rerun under another name blindly.

This creates distinct root and recovery keys with **single-owner 1-of-1 custody**.
Encrypted key stores and local unlock files remain owner-only on this Mac. This
is not distributed custody and not an off-device backup. Do not send a directory
archive or a password to the coordinator.

Send **only** the resulting `public-identity.json` and its printed SHA-256 to the
operator through the established team channel. That document contains public
authority, credential history and a genuine local signature, not private keys.
No further software access to Ani's machine is implied.

Also report the Mac's mesh/VPN address and whether it can reach Legion's existing
Matrix TCP listener at the endpoint supplied privately by the operator (connect
and close without sending a request; no SSH login is needed). This
determines direct routing versus the already authorized infrastructure route;
loopback pilot endpoints are not usable from another machine.

## Remaining acceptance

The operator prepares matching relationship permissions and routes from the real
public identities. Each host signs its own application and fixed Telegram policy,
then starts the verified daemon. Verify actual send, inbox read, correlated reply,
Telegram receipts, restart and bounded retry. Keep Hermes passive: arriving
messages must not automatically wake or invoke a model.

An owner-operated disposable peer proves transport, not Oliva's enrollment or an
autonomous Hermes conversation. Record those limits explicitly.
