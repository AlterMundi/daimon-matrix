# DaimonCards pilot

DaimonCards is the shared project-card writer proposed in
[Matrix #497](https://github.com/AlterMundi/daimon-matrix/issues/497). The Rust
crate accepts typed actions from a trusted host. The same writer handles
tool actions and actions translated from a human's A2UI surface.

A card belongs to a stable project UUID. Its immutable event records the
typed command, stable operation UUID, resulting revision, authenticated
actor and commit timestamp. SQLite atomically appends an event. Current
state is the latest event for that card. Reopen the same database to read
it, or export its events in revision order. Assignment compares the
expected revision. Exact retries of an accepted operation return the original
event under current write access. Use the project and card cursors to page
the current board and individual histories.

Git remains independent. A card links a repository UUID and full Git commit
ID. It can link several repositories, and the current view retains the latest
link per repository. The event history keeps earlier links. The host must use
its authorized project catalog to resolve a repository and verify the Git
object before claiming that the link is readable. A link alone grants no
repository access and makes no Git write.

The hosting adapter supplies `BoardAccess` from current authentication and
the project's sharing policy. It must resolve the actor and project on every
operation, including retries. Use a private owner-controlled directory and the
existing service backup path for SQLite. The browser and tool action envelopes
cannot choose their acting identity or project permission. The library adds
no new login, listener, model turn, background job or deployment.

The owner-side binary is a process adapter for an existing Node or Python
host. Launch `daimon-cards STORE` with one JSON request on standard input.
The authenticated host supplies `project`, `actor`, `can_write` and a typed
`input`. It never forwards a browser's or model's choice of identity or
permission. `apply` accepts a tool command. `apply_surface` resolves a
normalized A2UI event against the host's mounted card and passes the same
typed command to the writer. The response carries the canonical revision
or the conflict. The owner retains the same operation ID when the outcome
is unconfirmed. Close standard input to finish each request.

The event model uses
[Lattice v2's event-system design](https://github.com/Stage-11-Agentics/lattice/blob/8736575d11853b1b90c4e49685747a53f13a9e6c/docs/architecture/event-system.md)
as a reference for attributed events and derived state. This cut uses SQLite
transactions directly. It does not include Lattice's Python task store or hooks.

## Verification

From the repository root:

```sh
cargo test --locked --manifest-path components/daimon-cards/Cargo.toml
DAIMON_CARDS_PROYECCION=/path/to/proyeccion \
  cargo test --locked --manifest-path components/daimon-cards/Cargo.toml --test shared_project
```

The test uses a local bare Git remote and two independent checkouts. It exercises
create and edit, concurrent claims from A2UI and a typed daimon command, linking
a real Git commit, status synchronization, reopen, exact retry and permission
boundaries. The optional Chromium check uses Proyección's existing
[A2UI 1.0 spatial catalog](https://github.com/AlterMundi/proyeccion/blob/ad1c9d3e92b4f50104d7e75c91c986209a2e5b9c/docs/holodeck-hud.md).
It obtains the human command from a rendered button, preserving the mounted
card and the observed revision through the writer. Refresh changes only the
shared data model. View selection and drafts stay with the host.

This fixture uses synthetic actor identities and a disposable story draft.
Live acceptance requires a real project with a reachable Git remote, the
existing signed host identity and grants, and the human and daimon views
attached to this same writer. Holodeck is the planned receiving projection
for a game or place under the project contract.
