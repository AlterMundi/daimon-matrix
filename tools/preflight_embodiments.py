#!/usr/bin/env python3
"""Read-only embodiment preflight for one being.

Answers two questions before an enrollment ceremony is attempted, because the
ceremony requires the target profile to list exactly the active embodiment set with
distinct endpoints, and one active embodiment that nobody can serve blocks every
future enrollment for the whole being:

  * which active embodiments are servable from the runtimes supplied, and
  * which configured peer endpoints actually serve the peer route.

Nothing here opens custody, reads a password, writes a file or mutates state. Public
runtime bundles and their ``local_origin`` are sufficient, so the structural audit
works offline. Probing is opt-in.

An endpoint is judged by POSTing an intentionally invalid envelope. A 404 on the peer
path is this project's own answer for a route it does not serve; any other status
means something is there. A connection failure or timeout is reported as
``inconclusive`` and never as ``absent``, because mesh paths flap and a single
failure proves nothing.

    preflight_embodiments.py --host legion --runtime <state-root> [...]
    preflight_embodiments.py --host legion --runtime <root> --probe
"""

from __future__ import annotations

import argparse
import http.client
import json
import stat
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

REPORT_SCHEMA = "dm-embodiment-preflight-report/v0"
PEER_PATH = "/dm-peer/v1"
PROBE_CONTENT_TYPE = "application/vnd.daimon.peer+jcs"
PROBE_BODY = b"{}"
MAX_PROBE_SECONDS = 10.0

SERVES = "serves"
ABSENT = "absent"
INCONCLUSIVE = "inconclusive"
NOT_PROBED = "not-probed"


def _read_bundle(path: Path) -> dict[str, Any]:
    """Load one public runtime bundle. Refuses anything that is not a plain file."""
    info = path.lstat()

    if not stat.S_ISREG(info.st_mode):
        raise SystemExit(f"preflight_bundle_unreadable: {path}")
    try:
        value = json.loads(path.read_bytes())
    except (OSError, ValueError) as exception:
        raise SystemExit(f"preflight_bundle_unreadable: {path}") from exception
    if not isinstance(value, dict) or not isinstance(value.get("manifest"), dict):
        raise SystemExit(f"preflight_bundle_invalid: {path}")
    return value


def _host_of(body_ref: Any) -> str | None:
    """Middle segment of a signed ``<kind>:<host>:<name>`` body reference."""
    if not isinstance(body_ref, str):
        return None
    parts = body_ref.split(":")
    return parts[1] if len(parts) == 3 and parts[1] else None


def _origin(bundle: dict[str, Any]) -> tuple[str, str] | None:
    origin = bundle.get("local_origin")
    if not isinstance(origin, dict):
        return None
    embodiment = origin.get("embodiment_id")
    incarnation = origin.get("incarnation_id")
    if not isinstance(embodiment, str) or not isinstance(incarnation, str):
        return None
    return embodiment, incarnation


def _targets(bundle: dict[str, Any]) -> list[dict[str, str]]:
    transport = bundle.get("peer_transport")
    if not isinstance(transport, dict):
        return []
    rows = transport.get("targets")
    if not isinstance(rows, list):
        return []
    out: list[dict[str, str]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        embodiment = row.get("embodiment_id")
        endpoint = row.get("endpoint")
        if isinstance(embodiment, str) and isinstance(endpoint, str):
            out.append({"embodiment_id": embodiment, "endpoint": endpoint})
    return out


def probe(endpoint: str, timeout_seconds: float) -> str:
    """Classify one endpoint. Never raises: an unreachable peer is inconclusive."""
    try:
        parsed = urlsplit(endpoint)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return INCONCLUSIVE
        if parsed.path != PEER_PATH:
            return INCONCLUSIVE
        klass = (
            http.client.HTTPSConnection
            if parsed.scheme == "https"
            else http.client.HTTPConnection
        )
        connection = klass(parsed.hostname, parsed.port, timeout=timeout_seconds)
        try:
            connection.request(
                "POST",
                PEER_PATH,
                body=PROBE_BODY,
                headers={"Content-Type": PROBE_CONTENT_TYPE},
            )
            response = connection.getresponse()
            response.read()
            status = response.status
        finally:
            connection.close()
    except Exception:
        # Timeouts, refusals, DNS and mesh flaps all land here. None of them proves
        # the route is absent, so none of them may be reported as absent.
        return INCONCLUSIVE
    return ABSENT if status == 404 else SERVES


def audit(
    runtimes: list[Path],
    *,
    host: str,
    do_probe: bool,
    timeout_seconds: float,
) -> dict[str, Any]:
    bundles = [(path, _read_bundle(path / "runtime.json")) for path in runtimes]
    manifests = [bundle["manifest"] for _path, bundle in bundles]
    being_refs = {str(m.get("being_ref")) for m in manifests}
    if len(being_refs) != 1:
        raise SystemExit("preflight_manifests_disagree: more than one being supplied")
    revisions = {m.get("revision") for m in manifests}
    manifest = manifests[0]
    rows = manifest.get("embodiments")
    if not isinstance(rows, list):
        raise SystemExit("preflight_bundle_invalid: no embodiment rows")

    served = {}
    for path, bundle in bundles:
        found = _origin(bundle)
        if found is not None:
            served[found] = str(path)

    active: list[dict[str, Any]] = []
    retired: list[dict[str, Any]] = []
    unservable: list[str] = []
    reasons: list[str] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        embodiment = str(row.get("embodiment_id"))
        incarnation = str(row.get("incarnation_id"))
        body_ref = str(row.get("body_ref"))
        entry = {
            "embodiment_id": embodiment,
            "incarnation_id": incarnation,
            "body_ref": body_ref,
            "host": _host_of(body_ref),
            "status": str(row.get("status")),
        }
        if row.get("status") != "active":
            retired.append(entry)
            continue
        local = served.get((embodiment, incarnation))
        if local is not None:
            entry["servable"] = "here"
            entry["runtime"] = local
        elif entry["host"] is not None and entry["host"] != host:
            # Lives elsewhere. Not judged: this preflight only sees this host.
            entry["servable"] = "remote"
            entry["runtime"] = None
        else:
            entry["servable"] = "none"
            entry["runtime"] = None
            unservable.append(embodiment)
            reasons.append(
                f"active embodiment {embodiment} ({body_ref}) has no runtime on host "
                f"{host}: it cannot sign, and enrollment requires an endpoint for it"
            )
        active.append(entry)

    pairs: set[tuple[str, str]] = set()
    for _path, bundle in bundles:
        for target in _targets(bundle):
            pairs.add((target["embodiment_id"], target["endpoint"]))
    endpoints: dict[str, set[str]] = {}
    for embodiment, endpoint in pairs:
        endpoints.setdefault(embodiment, set()).add(endpoint)
    endpoint_rows: list[dict[str, str]] = []
    # One endpoint shared by two different embodiments is what breaks the ceremony.
    # The same pair reported by several bundles is agreement, not a collision.
    seen: dict[str, set[str]] = {}
    for embodiment in sorted(endpoints):
        for endpoint in sorted(endpoints[embodiment]):
            seen.setdefault(endpoint, set()).add(embodiment)
            endpoint_rows.append(
                {
                    "embodiment_id": embodiment,
                    "endpoint": endpoint,
                    "probe": (
                        probe(endpoint, timeout_seconds) if do_probe else NOT_PROBED
                    ),
                }
            )
    duplicates = {
        endpoint: sorted(ids) for endpoint, ids in seen.items() if len(ids) > 1
    }
    for endpoint, ids in sorted(duplicates.items()):
        reasons.append(
            f"endpoint {endpoint} is claimed by more than one embodiment "
            f"({', '.join(ids)}); the ceremony requires distinct endpoints"
        )

    enrollable = not unservable and not duplicates
    return {
        "schema": REPORT_SCHEMA,
        "being_ref": sorted(being_refs)[0],
        "manifest_revision": manifest.get("revision"),
        "manifest_revisions_seen": sorted(str(r) for r in revisions),
        "host": host,
        "active": active,
        "retired": retired,
        "endpoints": endpoint_rows,
        "duplicate_endpoints": duplicates,
        "unservable": sorted(unservable),
        "enrollable": enrollable,
        "reasons": reasons,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--host",
        required=True,
        help="this host's label, as it appears in the middle of a body_ref",
    )
    parser.add_argument(
        "--runtime",
        type=Path,
        action="append",
        required=True,
        help="a state root containing runtime.json; repeat for every local body",
    )
    parser.add_argument(
        "--probe",
        action="store_true",
        help="also classify each configured peer endpoint over the network",
    )
    parser.add_argument("--timeout-seconds", type=float, default=5.0)
    args = parser.parse_args(argv)
    if not 0.05 <= args.timeout_seconds <= MAX_PROBE_SECONDS:
        parser.error("--timeout-seconds must be between 0.05 and 10")
    report = audit(
        list(args.runtime),
        host=args.host,
        do_probe=args.probe,
        timeout_seconds=args.timeout_seconds,
    )
    sys.stdout.write(json.dumps(report, indent=1, sort_keys=True) + "\n")
    return 0 if report["enrollable"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
