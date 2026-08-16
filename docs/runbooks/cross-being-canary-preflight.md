# Cross-being canary preflight

Status: preparation only. This runbook does not authorize contact or execution.

This gate freezes the exact inputs for a future canary between two different
beings. It is deliberately offline: it cannot resolve an endpoint, open a
transport, contact a participant, inspect custody, or execute a step. The
result is evidence that a proposed plan was closed and content-addressed, not
evidence that its human or operational requirements have been satisfied.

## Closed plan

The input is owner-only canonical JSON using
`daimon-cross-being-canary-preflight/v1`. Its fixed shape requires:

- distinct `being_ref`, participant, endpoint, custodian, and custody-store
  references for side A and side B;
- an exact commit, tree, and non-empty artifact inventory with SHA-256 and size
  for Daimon Matrix, Daimon Cluster, and Tribe Bridge;
- separate consent gates for both participants, explicitly required,
  unrecorded, and not inferred;
- independent custody as a requirement for each side, with verification and
  evidence explicitly still absent;
- opaque endpoint, transport, procedure, effect, and observation references;
- declarative steps with expected effects and observations plus a declarative
  rollback for every step;
- Matrix authenticated intake and semantic receipt as required evidence; and
- Tribe acknowledgements marked non-semantic and unable to substitute for
  either Matrix requirement.

Unknown fields fail validation. Raw hostnames, addresses, URLs, ports, shell
commands, and argument vectors have no place in the schema. An opaque reference
is only an identifier for a later, independently reviewed plan; this tool never
dereferences it.

## Freezing and interpretation

`tools/build_cross_being_canary_preflight.py` accepts an input path and a new
output path. The input must be canonical JSON, ending in one LF, in an
owner-only regular file with no additional hard links.
The output path must not exist and its real parent directory must be owned by
the caller with mode `0700`. A successful freeze creates an owner-only
canonical receipt containing the exact plan, the SHA-256 of those exact input
bytes, and the corresponding
`GO <sha256>` text.

The emitted GO text is an identifier, not an authorization. The receipt always
states all of the following:

- `go_is_authorization` is false;
- `external_contact_approved` is false; and
- `execution_authorized` is false.

Changing any plan byte requires a new freeze and a new hash. Re-running against
an existing output fails closed and does not overwrite it. The freezer keeps
the created descriptor open through file and directory synchronization and
revalidates both the parent-path binding and the final name-to-inode binding; a
concurrent replacement is reported as failure and is never mistaken for the
frozen receipt.

## Human gates that remain

Before any real canary, a separate operational process must obtain and verify
both participants' scoped consent, independently verify each side's custody,
approve any external contact, select purpose-built non-production endpoints,
review the concrete transport and procedures behind every opaque reference,
and issue an execution authorization for that exact reviewed plan. None of
those facts can be inferred from this receipt or from a general permission.

The future canary must record Matrix intake and a Matrix semantic receipt. A
Tribe acknowledgement may be observed for transition diagnostics, but it never
proves Matrix intake or semantic acceptance.

## Failure and rollback evidence

Each planned action includes expected effect and observation references and a
rollback with its own effect and observation references. Missing rollback data,
duplicate action identities, open consent, claimed custody verification, open
network/contact/execution flags, or semantic substitution causes the freezer to
reject the plan. Because the freezer performs no action, its own rollback is
simply to discard the newly created receipt; source plans and existing receipts
are never modified.
