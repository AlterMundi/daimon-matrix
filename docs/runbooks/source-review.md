# Bounded review of selected shared learning

`tools/source_review.py` composes existing authenticated `source.status` and
`source.projection` reads. It answers which selected publications are offered,
already applied, known but not applied, conflicted, ahead, or unavailable across
the receiving bodies. With one local reader, it also reports retained foreign
publications available for that body’s review; it explicitly does not establish
that publisher’s current remote head. It does not read chat, create native sessions, invoke a
model, transfer content, mint Source cursors, decide trust, or apply a skill.
An exact later selection still uses the existing signed-cursor diff, incoming,
quarantine, assessment, promotion and selective installer.

This is a learning review workflow, not another update catalog. The Sources
stores remain authoritative. In particular, a shared **project** Source is not
the foundation's shared ancestry `/source.pull` or `/species.pull.name`.
Those selections must retain their actual lineage meaning.

## Receiving binding

The operator creates one owner-only configuration outside the repository, using
the current capability map and receiving bindings. The closed fields are:

- `schema`: `dm.source-review-config/v1`;
- `human_task`: retained human task correlation, never execution authority;
- `expires_at_ms`, `max_runs` (1–128), `interval_seconds` (60–86,400);
- `selectors`: 1–8 exact existing Source selectors;
- `targets`: 1–8 objects containing `id`, `being_ref`, exact four-field `server`
  identity, and `command` as an argv array.

Each command must launch this same public tool with `--probe-runtime` using the
receiver's qualified installed SDK, own runtime and existing observer capability.
Use its supported placement transport; no shell interpolation or credential
values in arguments. Do not copy another being's credentials or access map.
Public probe bytes can be installed independently of the immutable serving SDK.
Verify their exact hash and consuming-owner access before selection.

The driver passes only `{"selectors": [...]}` over stdin. The probe accepts no
generic method or executable input. Native client authentication validates its
server; the driver additionally requires the selected server and observer being.
Results contain metadata and active-projection hashes, not publication content
or private autobiography. Keep the report private. Technical reachability is not
content-disclosure authority: an offered item still needs its actual read grant
before diff/content transfer, and its receiver's assessment before promotion.

## Run, pause and stop

```text
python3 OPERATOR_CODE/source_review.py --config PRIVATE/config.json --state PRIVATE/state.json --report PRIVATE/report.json
python3 OPERATOR_CODE/source_review.py --config PRIVATE/config.json --state PRIVATE/state.json --report PRIVATE/report.json --control pause
python3 OPERATOR_CODE/source_review.py --config PRIVATE/config.json --state PRIVATE/state.json --report PRIVATE/report.json --control resume
python3 OPERATOR_CODE/source_review.py --config PRIVATE/config.json --state PRIVATE/state.json --report PRIVATE/report.json --control stop
```

Pause/resume performs no probe and never replenishes attempts. Stop is terminal.
The state binds the full configuration digest: editing limits or commands cannot
silently reset it. A new contract is an explicit operator selection, not crash
recovery. Unavailable targets remain unavailable; no provider fallback or model
activation is attempted.

For explicitly requested periodic review, use the existing service manager with
one existing `daimon-source-review.service`/`.timer` per selected operator host,
selecting `--scheduled`. A receiver-local contract runs as its existing owner.
A human-selected cohort contract may instead use the maintained host-operator
placement routes (for example Incus for an existing KVM and pinned SSH for a
native receiver). Run each probe as that receiver’s actual owner with its own
observer capability; do not copy credentials or widen native grants. When those
routes require the existing host operator, the driver runs under that operator
with a protected fixed configuration. This does not grant generic peer execution
or model attention. Keep the existing process-group and service bounds; size the
whole-run deadline for the finite target count. No scheduler is installed by the
tool or a goal edit. The selected human contract
must specify the interval, expiry, run count and participants. The scheduled
mode prints only a small summary. `calendar_slots` generates a finite list of
absolute UTC `OnCalendar` dates, each before expiry and at most `max_runs`. Use
those dates with `Persistent=false` and `RemainAfterElapse=false`; never convert
them to an unbounded recurring expression. The state independently refuses
reads after expiry, stop or attempt exhaustion. A stopped job may still have
its finite remaining timer dates; those execute no probes. The existing host
operator can stop/disable only this task’s timer immediately. The ordinary private report remains inspectable by the
existing Interaction integrator during its authorized work. It does not enqueue
a new model turn, automatically publish a reply or import that integrator's
private history into Matrix.

## Enforced resource bounds and recovery

- At most 32 native read calls per target/probe, including projection lookups;
  no model calls. Failed probes may have spent reads: their reserved attempt
  remains consumed and their exact read count is unconfirmed, not reported zero.
- Each owned probe process group has a 40-second driver deadline and a 256 KiB
  output limit. The probe itself binds its native client to 30 seconds. The
  driver kills/reaps its group, including a descendant holding stdout after its
  leader exits. A selected systemd unit also needs a finite runtime, memory/CPU
  limits and `KillMode=control-group` for the complete run.
- Reserve a run and its next allowed time before I/O. A crash cannot create
  another immediate attempt; restart preserves count, pause and stop. A
  backward clock delays review instead of granting another run.
- Keep one bounded state and one latest report, at most 256 KiB each; 256 offer
  comparisons maximum. The cursor hashes observed publication states, local candidates and
  unavailable targets. It is a review checkpoint, not a fabricated signed
  Sources cursor. Changes prompt review; an unchanged result creates no notice.
- Atomic replacement reclaims only this operation's unfinished staging file.
  There is no per-run snapshot, media generation or history archive. Native
  Sources journals keep their own existing capacity/retention contract.

Installed configuration, first live result, actual service/timer state and
remaining device/model acceptance belong in the existing project checkpoint.
A successful exact-identity publisher-local probe establishes only that selected
publisher’s metadata at the report time. A transport failure stays unavailable,
and local retained foreign evidence never substitutes for that publisher read.
Timer selection alone establishes neither an actual remote observation,
publisher convergence nor independent Eko/Oliva model learning. A successful empty or partial local review
is not full foundation coverage; supported remote discovery and selected uptake
remain separate work.

## Replacing a selected finite contract

Do not edit a live configuration behind its bound state digest. For an explicitly
selected successor, stop the existing task timer, use the driver’s terminal
`--control stop` on the predecessor, and retain its consumed count. Prepare a
new protected configuration/state location with at most the remaining attempts
and the original expiry. Account for any task-owned foreground comparison being
carried into this contract; it does not replenish the budget. Reuse the same
service/timer and original finite absolute calendar rather than installing a
parallel monitor or extending the schedule. A lower count or shorter expiry is
valid. Preserve other receivers’ separately selected contracts.

Inspect the current unit before changing its selected configuration, owner,
writable directory or whole-run deadline. Preserve memory/CPU limits, process
cleanup, read-only protection and actual native/bot/web/Matrix services. Start the
selected existing review unit once and inspect its retained report and actual
limits; service success alone is not exact-identity cohort acceptance. Pause,
resume and terminal stop use the new selected configuration/state. An expired
or exhausted successor remains terminal even if a finite timer date fires.

Retain one predecessor contract/control receipt and the successor’s bounded state
and latest report; do not create per-run archives. This operator transition
changes metadata observation only. Content transfer still needs the existing
resource disclosure grant, exact receiving assessment/promotion and selective
application; the review never supplies them implicitly.
