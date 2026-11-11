# Foreground native /near discovery

The initial operator workflow is `tools/scope_discovery.py`. It composes the
existing authenticated native `/all` inventory with fixed `scope.me(surface)`
reads through owner-selected routes. No serving SDK, identity, grant, daemon,
peer model, inbox attention or messaging target is created. The literal native
`scope.resolve` API still does not accept `/near`; do not claim that its core
protocol was extended by installing this operator.

## Explicit operational distance

The supported domain is `authenticated-control-route-ms`. A distance is locally
measured monotonic elapsed milliseconds for one authenticated body/surface read
through the configured owner route. It includes transport, process startup,
server scheduling and native/parent observation work. Concurrent probes can
influence timings. It is directional operational proximity, not geography,
pure network RTT, physical colocation or a universal metric. Always supply the
domain and threshold explicitly; never substitute `/all` or `/here` for `/near`.

```text
SDK_PYTHON OPERATOR/scope_discovery.py --config PRIVATE/config.json \
  --domain authenticated-control-route-ms --within-ms 750 \
  --report PRIVATE/latest.json
```

The caller chooses the threshold for that task;750ms above is an example, not a
Tribe policy. Results state their domain, units and measurement evidence.
Qualifying/excluded observations are distinct from unavailable measurements.
A failure is unknown, never zero distance. This is a native process read, not
an answer from a model or permission to send, disclose content or actuate devices.

## Existing receiving authority and configuration

Keep one owner-only `dm.scope-probe-config/v1` configuration with:
`schema`, `observer_id`, `expires_at_ms` and `targets`, plus optional `resources`
for the explicit selected-device workflow below. At most8targets reuse the
actual receiving capability-map placements, original identities and existing
observer clients. Each target has exactly `id`, `being_ref`, the four-field
`server` identity and a fixed argv-array `command`. Do not copy credentials,
create another participant catalog or derive authority from labels. The
observer must be one of those targets. Expired configuration refuses all probes.

The command launches this public operator with `--probe-runtime ACTUAL_RUNTIME`
as the receiver's actual owner using its selected installed SDK. Install the
operator and its unchanged `source_review.py` helper together in the selected
operator-code directory. Keep only the current code and necessary predecessor;
no per-query installation/version directory. Match exact code hashes and check
consumer traversal before selection. The helper opens only the owner's existing
client config/key and daemon socket; it never opens the live ledger/custody.

Stdin accepts only a view (`inventory` or `body`) and a UUID. The fixed inventory
read is `scope.resolve(view=discovery, scope=/all)`; the body read is
`scope.me(view=surface)`. Both require the receiver's actual existing grants. Use the already selected
qualified SDK Python for the driver and probe; its existing surface validator
checks the exact body observation, including isolated `-I` launches.
No generic method, socket, file, executable, provider or model input is accepted.

The observer's authenticated current admission inventory selects exact being,
body, embodiment and incarnation before peer probes. A configured nonmember is
excluded without probing it only for a complete inventory; omission from a
partial/truncated inventory remains unknown without probing. Authority-issued
lease lifetimes are computed against the authority snapshot clock and spent
using conservative local monotonic elapsed time, never cross-host wall-clock
comparison. Admitted bodies lacking configured routes remain
explicitly unconfigured/partial. Wrong source/observer/server or missing inventory
prevents peer probing; it never falls back to all configured targets. Reported
native parent admissions are cooperative evidence, not physical attestation.
Changing an incarnation requires the supported receiving binding update, not an
automatic alias or another identity.

## Bounds and observed use

There is no scheduler or recurring job. Each foreground run has at most9native
reads (one observer inventory plus at most8body reads),40seconds and256KiB per
owned probe process group, at most8concurrent body probes, and a90second whole-run
budget also narrowed by configuration expiry. The native probe has its own30s
absolute deadline. Failed probes retain unconfirmed counts; reported successful
reads are distinct from zero-call failures. Reuse the host's existing managed
foreground unit when aggregate memory/CPU enforcement is required.

Keep one protected latest report at most256KiB, replaced atomically through the
existing operator writer. No per-run snapshots, logs, media or result archives.
The command exits after that report; stop its task-owned unit/process group to
cancel. Configuration expiry is the stop path for later invocations. Do not
install a timer, hook, inbox/model listener or change other work's state.

Tests cover identity/admission/threshold/failure behavior and real owned-process
I/O/atomic latest-report replacement. Real cohort output, exact installed code,
actual resource limits and remaining native/core/model/device gaps belong in
#437's single receiving checkpoint. Synthetic tests or a successful empty result
are not full foundation completion.

## Partial `/everyone` through existing authorized routes

The same operator also accepts `--scope /everyone --config PRIVATE/config.json
--report PRIVATE/latest.json`. It reuses the exact protected target configuration
and fixed authenticated body probe. Supply neither a distance domain nor a
threshold. The default `/near` command and its admission semantics are unchanged.

Unlike `/all` and admission-selected `/near`, this foreground search probes each
configured route under that target's existing read authority, including a body
outside the observer's Cluster. It does not consult Cluster or Tribe membership
to decide who is reachable. A successful current native surface read establishes
only that this exact being/body/incarnation answered the authenticated native
read. No inbox, model, message target, grant or device is activated.

The default native-only report remains `dm.scope.everyone/v1`. Add
`--include-humans` explicitly for `dm.scope.everyone/v2`: each fixed probe first
reads its authenticated native surface, then invokes its existing installed
`daimon-home human` client as that same actual owner. It uses the current shared
resource-access pairing/registered applications, not another contact registry,
new login or a Matrix human identity. The home response's owning being must match
the authenticated native body. Deploy this compatible probe successor on all
selected routes before selecting the opt-in; older probes refuse that view.

Native `members` and `human_contacts` remain separate. Contacts preserve their
provider-human kind, source and association through the exact being/body; two
beings sharing a human retain both associations/routes. Registered applications
are `configured-route-not-probed`, not evidence of presence or message delivery.
An empty application set stays `route-unconfigured`. A missing/refused home read
or wrong owner/schema/unsafe URL never erases an independently observed native
body; it yields `human_unavailable`. Invalid native binding prevents contact
discovery. Native and home read counts are distinct; unknown outcomes are retained.

The report always remains partial: unconfigured routes cannot be enumerated and
human reachability/delivery are not established by registry lookup. Do not present
the Cluster inventory as `/everyone`, invent humans from provider IDs, claim
global discovery or create native membership from an access projection. A native
read proves neither an available model nor message/device authority. Human
communication and first-class native scope completion remain separate work.

Bounds and retention are the same as above, narrowed to at most8native body
reads, no inventory read and no model call. The opt-in permits at most8additional
owner-home reads, each with at most15seconds within its probe's shared30second
absolute deadline; the existing40second process and90second aggregate limits
still apply. Keep one protected atomic256KiB latest report. Configuration expiry
and task-owned process cancellation remain stop controls; no recurring job or
extra participant catalog is installed. Returned application URLs are never
fetched, and no message, publication, grant or model turn is requested.


## Selected device resources through the existing owner route

The same foreground operator accepts `/integrators`, `/perceptors` and
`/actuators` with one explicit `--resource EXISTING_RESOURCE_ID`. It first reads
its configured observer's authenticated native body, then queries the selected
resource's existing Integrators projection once. This associates the actual
current being/body with the resource it can inspect; it does not enroll the
resource as a being, infer realm membership, or issue a control grant.

```text
SDK_PYTHON OPERATOR/scope_discovery.py --config PRIVATE/config.json \
  --scope /integrators --resource host-cuevanico --report PRIVATE/latest.json
```

The optional `resources` list contains at most8 entries, each with exactly
`resource_ref` (the existing Shared Resources ID) and `command` (a fixed argv
array for its installed read-only `device_discovery.py --resource ID`, through
its existing authorized owner route). This is a private operation selection,
not another resource catalog. Select the route from that resource's maintained
record and actual access binding; do not copy credentials or infer permission
from a host label. Missing selection refuses before any I/O. Body admission
failure prevents the device read. Existing `/near` and `/everyone` queries do
not consume these optional routes.

The device response must match `dm.integrator-discovery/v1` and the selected
resource, with zero models, capture and control effects. The operator validates
and filters its public observation fields; process names, paths, arbitrary extra
fields and other native history are never forwarded. The existing Integrators
helper determines device freshness/coverage. The coordinator additionally
requires a response evaluation within10seconds of receipt (at most1second future
clock tolerance), and refuses inconsistent fresh/negative observations. An
unsynchronized or stale route is unavailable/partial, never a healthy negative.
Requested and observed panel state stay separate. A stale integrator cannot
establish complete resource coverage.

`dm.scope.resources/v1` reports this operator-selected association and its
limits. `/integrators` returns the filtered hub/device projection; `/perceptors`
and `/actuators` return the corresponding selected facets. Listed panel commands
are descriptions, never executed output. They retain
`existing-owner-control-required`: a successful status read is not a native
Matrix grant, proof of ownership, permission to acquire media or an instruction
to actuate. Use the existing resource owner control adapter for an independently
authorized action and retain its actual effect/uncertainty; this discovery adds
no command executor or new controls.

One run performs at most1 native read and1 resource read, at most30seconds per
process and60seconds overall, narrowed by the existing configuration expiry.
It uses the existing256KiB atomic latest report and foreground cancellation path;
no cache history, recurring producer, media, model or service is started. Current
receiving selection and useful work routing/physical-human acceptance remain
separate evidence in the single Matrix437 map.


## Own foreground realm work controls

The same installed `scope_discovery.py` supplies the initial `/realm.controls`
operator workflow. It authenticates the actual current native body through its
existing `scope.me` surface read, matches that opaque OS surface to the local
kernel, then uses the caller's existing systemd **user** manager. No root fallback,
new daemon, job scheduler, credential, grant store or command launcher is added.
A body observation does not grant control; the operation requires the human's
selected own task and existing OS-user authority. A foreign OS or unavailable
user manager refuses. This is a foreground operator, not a new native daemon RPC.

Use the [existing own-work launch route](../dm054-scope-resolution.md#foreground-native-os-work-controls)
with a fresh, never-reused name `matrix-work-UUIDHEX` (`UUIDHEX` is32lowercase hex
characters). It must be a transient active service with no automatic restart,
NoNewPrivileges, control-group cleanup, a finite lifetime of at most10minutes,
at most1GiB memory/128tasks and an enforced CPU quota of at most one CPU. These
are maximum supported operator bounds, not a grant to allocate them. Use the
actual task's smaller approved bounds. Permanent native/Conversation/goal units
are not accepted targets. Do not reuse a unit name after completion or while a
control acknowledgment is uncertain.

```text
SDK_PYTHON OPERATOR/scope_discovery.py --scope /realm.controls \
  --runtime OWN_RUNTIME --unit matrix-work-UUIDHEX.service \
  --action inspect --report PRIVATE/work-latest.json
```

The response contains the actual body, exact systemd invocation, selected unit,
manager properties, kernel `cpu.max`/`memory.max`/`pids.max` and supported actions.
It contains no command arguments, logs, media or model activity claim. Effective
kernel limits must agree with the selected manager's memory/process bounds.

For a human-authorized quota change, reuse that exact invocation:

```text
SDK_PYTHON OPERATOR/scope_discovery.py --scope /realm.controls \
  --runtime OWN_RUNTIME --unit matrix-work-UUIDHEX.service \
  --action cpu --cpu-percent 50 --invocation EXACT_INVOCATION \
  --report PRIVATE/work-cpu-effect.json
```

The `stop` action takes the same exact selection and a separate effect-receipt
path; it stops only that job and verifies removal of its original cgroup. A quota
change verifies the resulting kernel quota. Neither action changes native goals,
heartbeat controls, accounts, providers or any other service. Each mutation
reserves its exclusive private receipt before manager submission. A lost reply
retains `mutation_intent` or `inspect_retained_outcome_no_replay`; inspect the
same task without another mutation. Never overwrite an effect receipt with an
inspection or treat a changed invocation as permission to repeat the effect.

Each call performs one authenticated native read and at most three8second
manager calls, with a30second native deadline; no loop or recurring activation.
Keep one replaceable inspection plus the selected task's quota/stop receipts
(maximum256KiB each) in the existing bounded task record. Retire disposable task
outputs after their owning completion/retention rule; never delete uncertain
originals to free space. This initial route does not grant filesystem/network or
provider spending authority, implement physical actuators, or prove another
body's receiving availability. Native `scope.me(view="realm")` remains a status
RPC; it does not infer these controls from available OS memory.
