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
python3 OPERATOR/scope_discovery.py --config PRIVATE/config.json \
  --domain authenticated-control-route-ms --within-ms 750 \
  --report PRIVATE/latest.json
```

The caller chooses the threshold for that task;750ms above is an example, not a
Tribe policy. Results state their domain, units and measurement evidence.
Qualifying/excluded observations are distinct from unavailable measurements.
A failure is unknown, never zero distance. This is a native process read, not
an answer from a model or permission to send, disclose content or actuate devices.

## Existing receiving authority and configuration

Keep one owner-only `dm.scope-probe-config/v1` configuration with exactly:
`schema`, `observer_id`, `expires_at_ms` and `targets`. At most8targets reuse the
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
`scope.me(view=surface)`. Both require the receiver's actual existing grants.
No generic method, socket, file, executable, provider or model input is accepted.

The observer's authenticated current admission inventory selects exact being,
body, embodiment and incarnation before peer probes. A configured nonmember is
excluded without probing it. Admitted bodies lacking configured routes remain
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
