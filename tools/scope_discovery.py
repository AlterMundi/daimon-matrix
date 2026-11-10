"""Bounded foreground body, contact and selected device-resource discovery."""

from __future__ import annotations

import argparse
import importlib.util
import json
import math
import os
import re
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import urlsplit

from daimon_matrix.cluster import validate_surface_snapshot

# Operators can run with isolated Python: load only the adjacent selected helper.
_spec = importlib.util.spec_from_file_location(
    "scope_operator_limits", Path(__file__).with_name("source_review.py")
)
assert _spec is not None and _spec.loader is not None
_limits = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_limits)
MAX_BYTES = _limits.MAX_BYTES
bounded_call, encode = _limits.bounded_call, _limits.encode
private_read, write = _limits.private_read, _limits.write

DOMAIN = "authenticated-control-route-ms"
SERVER = {"body_ref", "embodiment_id", "incarnation_id", "principal_id"}
ORIGIN = {"body_ref", "embodiment_id", "incarnation_id"}


def text(value, maximum=1024):
    return (
        isinstance(value, str)
        and 0 < len(value.encode()) <= maximum
        and "\0" not in value
    )


def configuration(value):
    if (
        not isinstance(value, dict)
        or set(value)
        not in (
            {"schema", "observer_id", "expires_at_ms", "targets"},
            {"schema", "observer_id", "expires_at_ms", "targets", "resources"},
        )
        or value["schema"] != "dm.scope-probe-config/v1"
    ):
        raise ValueError("invalid_scope_probe_config")
    if (
        type(value["expires_at_ms"]) is not int
        or not 0 < value["expires_at_ms"] < 2**53
    ):
        raise ValueError("invalid_scope_probe_expiry")
    if not isinstance(value["targets"], list) or not 1 <= len(value["targets"]) <= 8:
        raise ValueError("invalid_scope_probe_targets")
    identifiers, bodies = [], []
    for target in value["targets"]:
        if not isinstance(target, dict) or set(target) != {
            "id",
            "being_ref",
            "server",
            "command",
        }:
            raise ValueError("invalid_scope_probe_target")
        server, command = target["server"], target["command"]
        if (
            not text(target["id"], 64)
            or not text(target["being_ref"])
            or not isinstance(server, dict)
            or set(server) != SERVER
            or not all(text(v) for v in server.values())
            or not isinstance(command, list)
            or not 1 <= len(command) <= 64
            or not all(text(v, 16384) for v in command)
        ):
            raise ValueError("invalid_scope_probe_target")
        identifiers.append(target["id"])
        bodies.append(key(target["being_ref"], server))
    if (
        len(set(identifiers)) != len(identifiers)
        or len(set(bodies)) != len(bodies)
        or value["observer_id"] not in identifiers
    ):
        raise ValueError("ambiguous_scope_probe_target")
    resources = value.get("resources", [])
    if not isinstance(resources, list) or len(resources) > 8:
        raise ValueError("invalid_scope_probe_resources")
    seen = set()
    for row in resources:
        if (
            not isinstance(row, dict)
            or set(row) != {"resource_ref", "command"}
            or not isinstance(row["resource_ref"], str)
            or re.fullmatch(r"[a-z][a-z0-9-]{0,95}", row["resource_ref"]) is None
            or row["resource_ref"] in seen
            or not isinstance(row["command"], list)
            or not 1 <= len(row["command"]) <= 64
            or not all(text(part, 16384) for part in row["command"])
        ):
            raise ValueError("invalid_scope_probe_resources")
        seen.add(row["resource_ref"])
    return value


def key(being, origin):
    return (being, *(origin.get(field) for field in sorted(ORIGIN)))


def binding(value, target):
    if (
        not isinstance(value, dict)
        or len(encode(value)) > MAX_BYTES
        or set(value) != {"schema", "server", "native_calls", "value"}
        or value["schema"] != "dm.scope-probe/v1"
        or value["server"] != target["server"]
        or type(value["native_calls"]) is not int
        or value["native_calls"] != 1
    ):
        raise ValueError("scope_probe_binding_rejected")
    result = value["value"]
    if (
        not isinstance(result, dict)
        or result.get("being_ref") != target["being_ref"]
        or result.get("origin") != target["server"]
    ):
        raise ValueError("scope_probe_origin_rejected")
    return result


def discover(
    settings, *, domain, within_ms, call=None, now_ms=None, clock=time.monotonic_ns
):
    """Read admitted bodies in the selected operational distance domain."""
    settings = configuration(settings)
    if domain != DOMAIN or type(within_ms) is not int or not 0 <= within_ms <= 40000:
        raise ValueError("unsupported_near_domain_or_threshold")
    now = time.time_ns() // 1_000_000 if now_ms is None else now_ms
    if settings["expires_at_ms"] <= now:
        raise ValueError("scope_probe_expired")
    started = clock()
    deadline = started + min(90_000, settings["expires_at_ms"] - now) * 1_000_000
    if call is None:

        def call(command, request):
            remaining = (deadline - clock()) / 1_000_000_000
            if remaining <= 0:
                raise TimeoutError("scope_probe_deadline")
            return bounded_call(command, request, timeout=min(40, remaining))

    request_id = str(uuid.uuid4())
    observer = next(
        t for t in settings["targets"] if t["id"] == settings["observer_id"]
    )
    report = {
        "schema": "dm.scope.near/v1",
        "scope": "/near",
        "request_id": request_id,
        "domain": domain,
        "unit": "milliseconds",
        "within_ms": within_ms,
        "observed_at_ms": now,
        "observer": observer["server"],
        "members": [],
        "excluded": [],
        "unavailable": [],
        "unconfigured": [],
        "partial": False,
        "confirmed_native_calls": 0,
        "native_call_ceiling": 1 + len(settings["targets"]),
        "unconfirmed_probes": 0,
        "model_calls": 0,
        "process_response": "not-observed",
        "authority": "native-cluster-admission",
        "distance_evidence": "locally-measured-configured-route-elapsed",
    }
    try:
        inventory = binding(
            call(observer["command"], {"view": "inventory", "request_id": request_id}),
            observer,
        )
        if (
            inventory.get("schema") != "dm.scope.discovery/v1"
            or inventory.get("scope") != "/all"
            or inventory.get("request_id") != request_id
            or type(inventory.get("partial")) is not bool
            or not isinstance(inventory.get("members"), list)
            or len(inventory["members"]) > 256
            or type(inventory.get("authority_observed_at_ms")) is not int
            or inventory["authority_observed_at_ms"] < 0
        ):
            raise ValueError("scope_inventory_rejected")
        admitted = {}
        for row in inventory["members"]:
            if (
                not isinstance(row, dict)
                or not all(text(row.get(field)) for field in ORIGIN | {"being_ref"})
                or type(row.get("lease_expires_at_ms")) is not int
                or row["lease_expires_at_ms"] <= inventory["authority_observed_at_ms"]
            ):
                raise ValueError("scope_inventory_rejected")
            marker = key(row["being_ref"], row)
            if marker in admitted:
                raise ValueError("scope_inventory_rejected")
            admitted[marker] = row
        if key(observer["being_ref"], observer["server"]) not in admitted:
            raise ValueError("scope_inventory_rejected")
        report["confirmed_native_calls"] = 1
        report["partial"] = inventory["partial"]
        report["authority_observed_at_ms"] = inventory["authority_observed_at_ms"]
    except (OSError, RuntimeError, ValueError, TimeoutError):
        report["partial"] = True
        report["unconfirmed_probes"] = 1
        report["unavailable"] = [
            {"id": observer["id"], "reason": "inventory-unavailable-or-rejected"}
        ]
        return report
    selected = []
    configured = {key(t["being_ref"], t["server"]) for t in settings["targets"]}
    for marker, row in admitted.items():
        if marker not in configured:
            report["unconfigured"].append(
                {field: row[field] for field in sorted(ORIGIN | {"being_ref"})}
            )
    for target in settings["targets"]:
        marker = key(target["being_ref"], target["server"])
        if marker not in admitted:
            if inventory["partial"]:
                report["unavailable"].append(
                    {
                        "id": target["id"],
                        "reason": "membership-unknown-partial-inventory",
                    }
                )
            else:
                report["excluded"].append(
                    {"id": target["id"], "reason": "not-in-current-admission"}
                )
        else:
            selected.append(target)

    def measured(target):
        start = clock()
        try:
            result = binding(
                call(target["command"], {"view": "body", "request_id": request_id}),
                target,
            )
            validate_surface_snapshot(
                result.get("surface"),
                body_ref=target["server"]["body_ref"],
                embodiment_id=target["server"]["embodiment_id"],
                incarnation_id=target["server"]["incarnation_id"],
                evaluated_at_ms=result.get("evaluated_at_ms"),
            )
            elapsed = clock() - start
            expires = admitted[key(target["being_ref"], target["server"])][
                "lease_expires_at_ms"
            ]
            # Lease timestamps belong to the authority's clock. Subtract that
            # snapshot time, then conservatively spend our monotonic elapsed.
            lifetime_ms = expires - inventory["authority_observed_at_ms"]
            if math.ceil((clock() - started) / 1_000_000) >= lifetime_ms:
                raise ValueError("scope_admission_expired_during_probe")
            if (
                result.get("schema") != "dm.scope.me-surface/v1"
                or elapsed < 0
                or clock() > deadline
            ):
                raise ValueError("scope_body_rejected")
            return {
                "id": target["id"],
                "being_ref": target["being_ref"],
                "server": target["server"],
                "elapsed_ms": math.ceil(elapsed / 1_000_000),
                "process_response": "not-observed",
            }
        except (OSError, RuntimeError, ValueError, TimeoutError):
            return {"id": target["id"], "reason": "body-probe-unavailable-or-rejected"}

    with ThreadPoolExecutor(max_workers=len(selected)) as pool:
        for result in pool.map(measured, selected):
            if "reason" in result:
                report["unavailable"].append(result)
                report["unconfirmed_probes"] += 1
            else:
                report["confirmed_native_calls"] += 1
                if result["elapsed_ms"] <= within_ms:
                    report["members"].append(result)
                else:
                    report["excluded"].append({**result, "reason": "outside-threshold"})
    report["partial"] |= bool(report["unavailable"] or report["unconfigured"])
    if len(encode(report)) > MAX_BYTES:
        raise ValueError("scope_report_capacity")
    return report


def human_endpoint(value, being_ref):
    """Validate access-projection data without turning it into Matrix identity."""
    fields = {
        "schema",
        "scope",
        "source",
        "home_ref",
        "owner_being_ref",
        "human",
        "applications",
        "route_state",
        "human_presence",
        "delivery",
        "native_membership",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("human_endpoint_rejected")
    human = value["human"]
    if (
        value["schema"] != "dm.human-endpoint/v1"
        or value["scope"] != "/human"
        or value["source"] != "shared-resource-access-pairing"
        or value["owner_being_ref"] != being_ref
        or not text(value["home_ref"], 256)
        or value["human_presence"] != "not-observed"
        or value["delivery"] != "not-requested"
        or value["native_membership"] != "not-implied"
        or not isinstance(human, dict)
        or set(human) != {"ref", "kind", "name", "revision"}
        or human["kind"] != "human"
        or not all(text(human[k], 1024) for k in ("ref", "name", "revision"))
        or not isinstance(value["applications"], list)
        or len(value["applications"]) > 32
    ):
        raise ValueError("human_endpoint_rejected")
    capabilities, origins = [], set()
    for row in value["applications"]:
        if not isinstance(row, dict) or set(row) != {"capability", "url", "state"}:
            raise ValueError("human_endpoint_rejected")
        if (
            not text(row["capability"], 64)
            or re.fullmatch(r"[a-z][a-z0-9-]{0,63}", row["capability"]) is None
            or not text(row["url"], 2048)
            or row["state"] != "configured"
            or any(ord(c) < 33 or c == "\\" for c in row["url"])
        ):
            raise ValueError("human_endpoint_rejected")
        url = urlsplit(row["url"])
        _ = url.port  # Reject malformed ports without fetching a returned URL.
        if (
            url.scheme != "https"
            or not url.hostname
            or url.username
            or url.password
            or url.query
            or url.fragment
            or re.fullmatch(r"/[A-Za-z0-9_-]+/", url.path) is None
        ):
            raise ValueError("human_endpoint_rejected")
        capabilities.append(row["capability"])
        origins.add(url.netloc.lower())
    if (
        len(set(capabilities)) != len(capabilities)
        or len(origins) > 1
        or value["route_state"] != ("configured" if capabilities else "unconfigured")
    ):
        raise ValueError("human_endpoint_rejected")
    return value


def everyone(
    settings, *, include_humans=False, call=None, now_ms=None, clock=time.monotonic_ns
):
    """Observe configured reachable bodies, without requiring Cluster membership.

    This is a partial foundation projection: configured owner routes bound the
    search, and human contact discovery is not supplied by the native body API.
    Neither route possession nor a successful read grants messaging/actuation.
    """
    settings = configuration(settings)
    if type(include_humans) is not bool:
        raise ValueError("explicit_human_selection_required")
    now = time.time_ns() // 1_000_000 if now_ms is None else now_ms
    if settings["expires_at_ms"] <= now:
        raise ValueError("scope_probe_expired")
    deadline = clock() + min(90_000, settings["expires_at_ms"] - now) * 1_000_000
    if call is None:

        def call(command, request):
            remaining = (deadline - clock()) / 1_000_000_000
            if remaining <= 0:
                raise TimeoutError("scope_probe_deadline")
            return bounded_call(command, request, timeout=min(40, remaining))

    request_id = str(uuid.uuid4())
    observer = next(
        t for t in settings["targets"] if t["id"] == settings["observer_id"]
    )
    report = {
        "schema": "dm.scope.everyone/v1",
        "scope": "/everyone",
        "request_id": request_id,
        "observed_at_ms": now,
        "observer": observer["server"],
        "members": [],
        "unavailable": [],
        "partial": True,
        "coverage": {
            "daimons": "configured-authorized-native-routes-only",
            "humans": "not-configured",
            "unconfigured_routes": "not-enumerated",
        },
        "authority": "per-target-authenticated-native-read",
        "membership": "not-inferred",
        "confirmed_native_calls": 0,
        "native_call_ceiling": len(settings["targets"]),
        "unconfirmed_probes": 0,
        "model_calls": 0,
        "process_response": "not-observed",
    }
    if include_humans:
        report.update(
            schema="dm.scope.everyone/v2",
            human_contacts=[],
            human_unavailable=[],
            confirmed_home_reads=0,
            unconfirmed_home_reads=0,
            home_read_ceiling=len(settings["targets"]),
            human_authority="per-target-current-resource-access-pairing",
        )
        report["coverage"]["humans"] = "paired-owner-access-projections-only"

    def reachable(target):
        try:
            if clock() >= deadline:
                raise TimeoutError("scope_probe_deadline")
            wrapped = call(
                target["command"],
                {
                    "view": "contacts" if include_humans else "body",
                    "request_id": request_id,
                },
            )
            if include_humans:
                if (
                    not isinstance(wrapped, dict)
                    or set(wrapped)
                    != {
                        "schema",
                        "server",
                        "native_calls",
                        "value",
                        "human_endpoint",
                        "home_read_attempted",
                    }
                    or wrapped["schema"] != "dm.scope-contact-probe/v1"
                    or type(wrapped["home_read_attempted"]) is not bool
                ):
                    raise ValueError("scope_contact_binding_rejected")
                native = {k: wrapped[k] for k in ("server", "native_calls", "value")}
                result = binding({"schema": "dm.scope-probe/v1", **native}, target)
            else:
                result = binding(wrapped, target)
            validate_surface_snapshot(
                result.get("surface"),
                body_ref=target["server"]["body_ref"],
                embodiment_id=target["server"]["embodiment_id"],
                incarnation_id=target["server"]["incarnation_id"],
                evaluated_at_ms=result.get("evaluated_at_ms"),
            )
            if result.get("schema") != "dm.scope.me-surface/v1" or clock() >= deadline:
                raise ValueError("scope_body_rejected")
            row = {
                "kind": "daimon",
                "id": target["id"],
                "being_ref": target["being_ref"],
                "server": target["server"],
                "reachability": "authenticated-native-read-observed",
                "process_response": "not-observed",
            }
            if include_humans:
                row["_home_attempted"] = wrapped["home_read_attempted"]
                try:
                    if not wrapped["home_read_attempted"]:
                        raise ValueError("home_read_not_attempted")
                    row["_human"] = human_endpoint(
                        wrapped["human_endpoint"], target["being_ref"]
                    )
                except ValueError:
                    row["_human"] = None
            return row
        except (OSError, RuntimeError, ValueError, TimeoutError):
            return {"id": target["id"], "reason": "body-probe-unavailable-or-rejected"}

    with ThreadPoolExecutor(max_workers=len(settings["targets"])) as pool:
        for row in pool.map(reachable, settings["targets"]):
            if "reason" in row:
                report["unavailable"].append(row)
                report["unconfirmed_probes"] += 1
                if include_humans:
                    report["human_unavailable"].append(
                        {"id": row["id"], "reason": "native-binding-unavailable"}
                    )
            else:
                if include_humans:
                    contact, attempted = row.pop("_human"), row.pop("_home_attempted")
                    if contact is None:
                        report["unconfirmed_home_reads"] += int(attempted)
                        report["human_unavailable"].append(
                            {
                                "id": row["id"],
                                "reason": "home-read-unavailable-or-rejected",
                            }
                        )
                    else:
                        report["confirmed_home_reads"] += 1
                        report["human_contacts"].append(
                            {
                                "kind": "human",
                                "via_being_ref": row["being_ref"],
                                "via_server": row["server"],
                                "endpoint": contact,
                                "reachability": "configured-route-not-probed"
                                if contact["route_state"] == "configured"
                                else "route-unconfigured",
                            }
                        )
                report["members"].append(row)
                report["confirmed_native_calls"] += 1
    if len(encode(report)) > MAX_BYTES:
        raise ValueError("scope_report_capacity")
    return report


DEVICE_SCOPES = {"/integrators", "/perceptors", "/actuators"}


def device_projection(value, resource_ref, now_ms):
    """Read the existing Integrators contract; never forward private extras."""
    if (
        not isinstance(value, dict)
        or len(encode(value)) > 65536
        or value.get("schema") != "dm.integrator-discovery/v1"
        or value.get("resource_ref") != resource_ref
        or type(value.get("evaluated_at")) is not int
        or not -1000 <= now_ms - value["evaluated_at"] * 1000 <= 10000
    ):
        raise ValueError("resource_projection_rejected")
    limits = value.get("limits", {})
    if (
        not isinstance(limits, dict)
        or type(limits.get("model_calls")) is not int
        or limits.get("model_calls") != 0
        or limits.get("device_capture_started") is not False
        or limits.get("controls_executed") is not False
        or "control" in value
    ):
        raise ValueError("resource_projection_not_read_only")
    integrator = value.get("integrator", {})
    if (
        not isinstance(integrator, dict)
        or not isinstance(integrator.get("state"), str)
        or integrator.get("state") not in {"observed", "stale"}
        or type(integrator.get("observed_at")) is not int
        or integrator["observed_at"] < 0
        or (
            integrator["state"] == "observed"
            and not -1 <= value["evaluated_at"] - integrator["observed_at"] <= 4
        )
    ):
        raise ValueError("resource_projection_rejected")
    sensors, controls = value.get("perceptors"), value.get("actuators")
    if (
        not isinstance(sensors, list)
        or len(sensors) > 32
        or not isinstance(controls, list)
        or len(controls) > 32
    ):
        raise ValueError("resource_projection_rejected")
    selected_sensors = []
    for row in sensors:
        if (
            not isinstance(row, dict)
            or not text(row.get("id"), 64)
            or row.get("resource_ref") != resource_ref
            or not isinstance(row.get("state"), str)
            or row.get("state")
            not in {"unknown", "in-use", "absent", "no-use-detected"}
            or type(row.get("observed_at")) is not int
            or type(row.get("fresh")) is not bool
            or type(row.get("coverage_complete")) is not bool
            or row.get("media_read") is not False
        ):
            raise ValueError("resource_projection_rejected")
        if (
            row["observed_at"] < 0
            or (
                row["fresh"]
                and not -1 <= value["evaluated_at"] - row["observed_at"] <= 4
            )
            or (row["fresh"] and integrator["state"] != "observed")
            or (row["state"] != "unknown" and not row["fresh"])
            or (
                row["state"] in {"absent", "no-use-detected"}
                and not row["coverage_complete"]
            )
        ):
            raise ValueError("resource_projection_rejected")
        selected_sensors.append(
            {
                k: row[k]
                for k in (
                    "id",
                    "resource_ref",
                    "state",
                    "observed_at",
                    "fresh",
                    "coverage_complete",
                    "media_read",
                )
            }
        )
    selected_controls = []
    for row in controls:
        if (
            not isinstance(row, dict)
            or row.get("id") != "panel-view"
            or row.get("commands") != [["view", "compact"], ["view", "expanded"]]
            or row.get("permission") != "existing-owner-control-required"
            or row.get("executed") is not False
            or any(
                row.get(k) is not None and type(row[k]) is not bool
                for k in ("requested_compact", "observed_compact")
            )
        ):
            raise ValueError("resource_projection_rejected")
        selected_controls.append(
            {
                k: row.get(k)
                for k in (
                    "id",
                    "commands",
                    "permission",
                    "executed",
                    "requested_compact",
                    "observed_compact",
                )
            }
        )
    return {
        "resource_ref": resource_ref,
        "evaluated_at": value["evaluated_at"],
        "integrator": {k: integrator[k] for k in ("state", "observed_at")},
        "perceptors": selected_sensors,
        "actuators": selected_controls,
    }


def resource_discovery(
    settings, *, scope, resource_ref, call=None, now_ms=None, clock=time.monotonic_ns
):
    """Associate one selected resource read with the current authenticated body."""
    settings = configuration(settings)
    if scope not in DEVICE_SCOPES:
        raise ValueError("unsupported_resource_scope")
    selected = [
        row
        for row in settings.get("resources", [])
        if row["resource_ref"] == resource_ref
    ]
    if len(selected) != 1:
        raise ValueError("resource_route_not_selected")
    now = time.time_ns() // 1_000_000 if now_ms is None else now_ms
    if settings["expires_at_ms"] <= now:
        raise ValueError("scope_probe_expired")
    deadline = clock() + min(60_000, settings["expires_at_ms"] - now) * 1_000_000
    if call is None:

        def call(command, request):
            remaining = (deadline - clock()) / 1_000_000_000
            if remaining <= 0:
                raise TimeoutError("scope_probe_deadline")
            return bounded_call(command, request, timeout=min(30, remaining))

    observer = next(
        row for row in settings["targets"] if row["id"] == settings["observer_id"]
    )
    request_id = str(uuid.uuid4())
    report = dict(
        schema="dm.scope.resources/v1",
        scope=scope,
        request_id=request_id,
        resource_ref=resource_ref,
        observed_at_ms=now,
        members=[],
        unavailable=[],
        partial=True,
        confirmed_native_calls=0,
        confirmed_resource_reads=0,
        native_call_ceiling=1,
        resource_call_ceiling=1,
        model_calls=0,
        device_capture_started=False,
        controls_executed=False,
        media_read=False,
        association="operator-selected-existing-resource-route",
        control_authority="existing-owner-control-required-not-a-discovery-grant",
        resource_ownership="not-established-by-discovery",
    )
    try:
        body = binding(
            call(observer["command"], {"view": "body", "request_id": request_id}),
            observer,
        )
        if body.get("schema") != "dm.scope.me-surface/v1":
            raise ValueError("scope_native_body_rejected")
        validate_surface_snapshot(
            body.get("surface"),
            body_ref=observer["server"]["body_ref"],
            embodiment_id=observer["server"]["embodiment_id"],
            incarnation_id=observer["server"]["incarnation_id"],
            evaluated_at_ms=body.get("evaluated_at_ms"),
        )
        report.update(
            observer=observer["server"],
            being_ref=observer["being_ref"],
            confirmed_native_calls=1,
        )
    except (OSError, RuntimeError, ValueError, TimeoutError):
        report["unavailable"] = [{"reason": "native-body-unavailable-or-rejected"}]
        return report
    try:
        observed = call(selected[0]["command"], {})
        received_at = time.time_ns() // 1_000_000 if now_ms is None else now_ms
        device = device_projection(observed, resource_ref, received_at)
        if scope == "/integrators":
            report["members"] = [device]
        else:
            report["members"] = device[scope[1:]]
        report.update(
            confirmed_resource_reads=1,
            partial=device["integrator"]["state"] != "observed",
            resource_state=device["integrator"]["state"],
        )
    except (OSError, RuntimeError, ValueError, TimeoutError):
        report["unavailable"] = [
            {"reason": "resource-projection-unavailable-or-rejected"}
        ]
    if len(encode(report)) > MAX_BYTES:
        raise ValueError("scope_report_capacity")
    return report


def probe(root, request):
    """Use existing owner client; never open the active runtime/ledger offline."""
    from daimon_matrix.client import ClientConfig, LocalClient, read_capability_key

    if (
        not isinstance(request, dict)
        or set(request) != {"view", "request_id"}
        or request["view"] not in {"body", "inventory", "contacts"}
    ):
        raise ValueError("invalid_scope_probe")
    uuid.UUID(request["request_id"])
    runtime = private_read(root / "runtime.json")
    endpoint = Path(runtime["socket"])
    if not endpoint.is_absolute():
        endpoint = root / endpoint
    key_data = read_capability_key(
        os.open(root / "client.key", os.O_RDONLY | os.O_NOFOLLOW)
    )
    deadline = time.monotonic_ns() + 30_000_000_000
    client = LocalClient(
        endpoint,
        ClientConfig.load(root / "client.json", key_data),
        8,
        deadline_ns=deadline,
    )
    method, params = (
        ("scope.me", {"view": "surface"})
        if request["view"] in {"body", "contacts"}
        else (
            "scope.resolve",
            {
                "view": "discovery",
                "scope": "/all",
                "tribe_ref": None,
                "request_id": request["request_id"],
            },
        )
    )
    response = client.invoke(method, params)[1]
    if not response["ok"]:
        raise ValueError("scope_native_read_refused")
    result = {
        "schema": "dm.scope-probe/v1",
        "server": response["server"],
        "native_calls": 1,
        "value": response["result"],
    }
    if request["view"] == "contacts":
        value = response["result"]
        if (
            value.get("schema") != "dm.scope.me-surface/v1"
            or value.get("origin") != response["server"]
            or not text(value.get("being_ref"))
        ):
            raise ValueError("scope_native_body_rejected")
        validate_surface_snapshot(
            value.get("surface"),
            body_ref=response["server"]["body_ref"],
            embodiment_id=response["server"]["embodiment_id"],
            incarnation_id=response["server"]["incarnation_id"],
            evaluated_at_ms=value.get("evaluated_at_ms"),
        )
        result.update(
            schema="dm.scope-contact-probe/v1",
            human_endpoint=None,
            home_read_attempted=False,
        )
        script = Path.home() / ".agents/skills/daimon-home/scripts/home.py"
        remaining = (deadline - time.monotonic_ns()) / 1_000_000_000
        if script.is_file() and remaining > 0:
            result["home_read_attempted"] = True
            try:
                value = bounded_call(
                    [sys.executable, "-B", str(script), "human"],
                    {},
                    timeout=min(15, remaining),
                )
                result["human_endpoint"] = human_endpoint(
                    value, response["result"]["being_ref"]
                )
            except (OSError, RuntimeError, ValueError, TimeoutError):
                # Preserve the independent body observation, never invent a contact.
                pass
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe-runtime", type=Path)
    parser.add_argument("--config", type=Path)
    parser.add_argument(
        "--scope",
        choices=("/near", "/everyone", "/integrators", "/perceptors", "/actuators"),
        default="/near",
    )
    parser.add_argument("--include-humans", action="store_true")
    parser.add_argument("--resource")
    parser.add_argument("--domain")
    parser.add_argument("--within-ms", type=int)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    if args.include_humans and (args.probe_runtime or args.scope != "/everyone"):
        parser.error("include-humans requires the /everyone coordinator")
    if args.resource is not None and (
        args.probe_runtime or args.scope not in DEVICE_SCOPES
    ):
        parser.error("resource requires a device scope coordinator")
    if args.probe_runtime:
        raw = sys.stdin.buffer.read(4097)
        if len(raw) > 4096:
            raise ValueError("scope_probe_input_capacity")
        print(json.dumps(probe(args.probe_runtime, json.loads(raw))))
    else:
        if not args.config or not args.report:
            parser.error("config and report are required")
        if args.scope in DEVICE_SCOPES:
            if (
                not args.resource
                or args.domain is not None
                or args.within_ms is not None
            ):
                parser.error("device scopes require resource and no distance domain")
            report = resource_discovery(
                private_read(args.config), scope=args.scope, resource_ref=args.resource
            )
        elif args.scope == "/everyone":
            if args.domain is not None or args.within_ms is not None:
                parser.error("/everyone does not take a distance domain or threshold")
            report = everyone(
                private_read(args.config), include_humans=args.include_humans
            )
        else:
            if not args.domain or args.within_ms is None:
                parser.error("/near requires explicit domain and within-ms")
            report = discover(
                private_read(args.config), domain=args.domain, within_ms=args.within_ms
            )
        write(args.report, report)
        print(
            json.dumps(
                {
                    "scope": args.scope,
                    **({"domain": args.domain} if args.scope == "/near" else {}),
                    "members": len(report["members"]),
                    "partial": report["partial"],
                    "confirmed_native_calls": report["confirmed_native_calls"],
                    **(
                        {
                            "human_contacts": len(report["human_contacts"]),
                            "confirmed_home_reads": report["confirmed_home_reads"],
                        }
                        if args.include_humans
                        else {}
                    ),
                    **(
                        {
                            "resource_ref": report["resource_ref"],
                            "confirmed_resource_reads": report[
                                "confirmed_resource_reads"
                            ],
                        }
                        if args.scope in DEVICE_SCOPES
                        else {}
                    ),
                    "model_calls": 0,
                }
            )
        )


if __name__ == "__main__":
    main()
