# Human-requested shared-skill updates

`AlterMundi/Skills` owns the portable packages and selective installer. Matrix
owns the authenticated same-being exchange. This runbook connects them without
making transport delivery a claim of installation. It is the bounded increment
tracked by #228; the broader roles/curator design in #170 remains separate.

## Source preparation

1. Publish and review portable content in the owning Skills repository. Keep
   personal preferences, provider configuration and body bindings local. Register
   its version/catalog and validate the actual candidate.
2. After integration, use the exact commit to prepare a descriptor with
   `scripts/skills_update.py describe` from that repository. The descriptor binds
   repository, commit, selected packages/version and actual file digests.
3. Under the human's task, send the exact reference and change summary through
   the body's rendered authenticated owner client. Include the descriptor hash
   or attach its exact private transfer artifact. Use configured same-being
   targets; do not widen clients or load a second runtime alongside its daemon.
4. Observe the actual delivery receipt. Authorship, delivery and receiver-side
   application are different facts. No polling or automatic reply is introduced.

## Receiver application

Use the receiver's existing GitHub access to fetch the exact commit. Follow
[`AlterMundi/Skills/docs/skill-updates.md`](https://github.com/AlterMundi/Skills/blob/main/docs/skill-updates.md)
for the concrete `describe`, `prepare`, `apply`, `status`, `recover` and `rollback`
commands. Use the actual neutral binding; the body does not gain authority from
its filesystem location or the message. The human's request must include the
application; receiving update data alone does not authorize it.

First adoption of an unmanaged package snapshots the inspected baseline through
`prepare --adopt-existing`. Existing managed local edits are surfaced as
conflicts. Install only the selected immutable version, preserving unrelated
skills, original context and harness differences. A checkout update does not
change installed package bytes. Retain private before/after history and records.

Then:

- run `status` and the existing neutral binding's `surface_check.py`;
- reload/rediscover with the real supported harness interface;
- verify the receiving harness sees both HMK and its auxiliary librarian skill
  and reads the durable-memory/project-state distinction;
- record hashes, version and observed results in the issue/project context;
- return the actual result through `/we` only when the human's request includes
  that reply. Do not claim a model has loaded new text from a filesystem check.

## Scope and recovery

The pilot updates skills, not memory data, permissions, identity, Root custody,
provider setup or the installed Matrix release. Native conversation history
remains harness history. Keep actual credentials, private paths, memory content
and endpoints out of repository evidence.

Use the owning installer's recovery/rollback after failure. Never restore a
being's ledger or identity as part of a skill rollback. A recovery conflict
preserves files and requires inspection; it does not permit overwriting local
work. Do not add a new service, timer, inbox reader or model invocation outside
the current human-directed task.
