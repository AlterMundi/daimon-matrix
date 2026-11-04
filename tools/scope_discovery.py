"""Bounded foreground /near in an explicit authenticated control-route domain."""

from __future__ import annotations

import argparse
import json
import math
import os
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from daimon_matrix.cluster import validate_surface_snapshot

if __package__:
    from .source_review import MAX_BYTES, bounded_call, encode, private_read, write
else:
    from source_review import MAX_BYTES, bounded_call, encode, private_read, write

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
        or set(value) != {"schema", "observer_id", "expires_at_ms", "targets"}
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
        ):
            raise ValueError("scope_inventory_rejected")
        admitted = {}
        for row in inventory["members"]:
            if (
                not isinstance(row, dict)
                or not all(text(row.get(field)) for field in ORIGIN | {"being_ref"})
                or type(row.get("lease_expires_at_ms")) is not int
                or row["lease_expires_at_ms"] <= now
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
            if now + math.ceil((clock() - started) / 1_000_000) >= expires:
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


def probe(root, request):
    """Use existing owner client; never open the active runtime/ledger offline."""
    from daimon_matrix.client import ClientConfig, LocalClient, read_capability_key

    if (
        not isinstance(request, dict)
        or set(request) != {"view", "request_id"}
        or request["view"] not in {"body", "inventory"}
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
    client = LocalClient(
        endpoint,
        ClientConfig.load(root / "client.json", key_data),
        8,
        deadline_ns=time.monotonic_ns() + 30_000_000_000,
    )
    method, params = (
        ("scope.me", {"view": "surface"})
        if request["view"] == "body"
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
    return {
        "schema": "dm.scope-probe/v1",
        "server": response["server"],
        "native_calls": 1,
        "value": response["result"],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe-runtime", type=Path)
    parser.add_argument("--config", type=Path)
    parser.add_argument("--domain")
    parser.add_argument("--within-ms", type=int)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    if args.probe_runtime:
        raw = sys.stdin.buffer.read(4097)
        if len(raw) > 4096:
            raise ValueError("scope_probe_input_capacity")
        print(json.dumps(probe(args.probe_runtime, json.loads(raw))))
    else:
        if not all((args.config, args.domain, args.report)) or args.within_ms is None:
            parser.error("config, explicit domain, within-ms and report are required")
        report = discover(
            private_read(args.config), domain=args.domain, within_ms=args.within_ms
        )
        write(args.report, report)
        print(
            json.dumps(
                {
                    "scope": "/near",
                    "domain": args.domain,
                    "members": len(report["members"]),
                    "partial": report["partial"],
                    "confirmed_native_calls": report["confirmed_native_calls"],
                    "model_calls": 0,
                }
            )
        )


if __name__ == "__main__":
    main()
