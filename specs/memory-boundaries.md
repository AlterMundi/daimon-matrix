# Origin-retaining memory and local adoption

Status: normative.

## States

Every embodiment stores immutable origin events and derives local views:

- `known`: valid event present in the ledger;
- `effective`: current local decision is adoption;
- `projected`: adapter receipt confirms the intended effect;
- `pending`, `deferred`, `rejected`, `reverted`, `inapplicable`, or `failed`.

Receive, adopt, and project are three distinct transitions. No database copy,
transport ACK, similarity score, or remote decision skips one.

## Synchronized categories

Experiences, insights, skills, preferences, and configuration proposals may be
synchronized. Every item preserves origin embodiment and incarnation.
Experiences from another embodiment of the same being are same-being
experience but do not falsely claim that the receiving body lived them.

Configuration carries semantic proposals and references, never private keys,
passwords, bearer tokens, or secret values. A local projection adapter shows a
diff and records its result. Identity/access/external effects require human
confirmation.

## Decisions

An embodiment may adopt, reject, defer, or reverse an item. Every change is a
new successor event naming the previous decision. Other embodiments can
inspect this trajectory without inheriting it. A difference query must explain
the incoming item, provenance, local effective value, remote choices, and the
effect of each available action.

HMK and other memory stores are disposable projections. They never become the
canonical ledger and must support idempotent projection by event ID. A crash
between effect and receipt is reconciled by observing the postcondition before
retrying.
