#!/usr/bin/env python3
"""Finite operator review of selected Sources offers, never chat or inference.

The driver uses protected receiving-local argv bindings. The probe runs with the
receiver's existing SDK and observer capability; it only reads native Sources.
Neither mode imports foreign memory, creates cursors, or adopts publications.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import selectors
import signal
import stat
import subprocess
import sys
import time
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path

MAX_BYTES = 262144
MAX_ROWS = 64


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def private_read(path, owner_uid=None):
    owner_uid = os.geteuid() if owner_uid is None else owner_uid
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != owner_uid
            or info.st_mode & 0o077
            or info.st_nlink != 1
        ):
            raise ValueError("private_owner_file_required")
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("review_capacity")
    return json.loads(raw)


def write(path, value, owner_uid=None):
    owner_uid = os.geteuid() if owner_uid is None else owner_uid
    if type(owner_uid) is not int or not 0 <= owner_uid < 2**31:
        raise ValueError("invalid_report_reader")
    if owner_uid != os.geteuid() and os.geteuid() != 0:
        raise ValueError("report_reader_requires_owner_operator")
    raw = encode(value)
    if len(raw) > MAX_BYTES:
        raise ValueError("review_capacity")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.is_symlink():
        raise ValueError("private_owner_file_required")
    if path.exists():
        private_read(path, owner_uid)
    tmp = path.with_name("." + path.name + ".new")
    if tmp.exists():
        info = tmp.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid not in {os.geteuid(), owner_uid}
            or info.st_mode & 0o077
            or info.st_nlink != 1
        ):
            raise ValueError("private_owner_file_required")
        tmp.unlink()  # Only this locked operation's incomplete staging file.
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            if owner_uid != os.geteuid():
                os.fchown(stream.fileno(), owner_uid, -1)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
        directory = os.open(path.parent, os.O_DIRECTORY | os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        tmp.unlink(missing_ok=True)


def export_report(source, destination, reader_uid=None):
    """Project retained metadata only, without a review/probe or state mutation."""
    reader_uid = os.geteuid() if reader_uid is None else reader_uid
    if type(reader_uid) is not int or not 0 <= reader_uid < 2**31:
        raise ValueError("invalid_report_reader")
    if reader_uid != os.geteuid():
        if os.geteuid() != 0:
            raise ValueError("report_reader_requires_owner_operator")
        parent = destination.parent.stat()
        if (
            not stat.S_ISDIR(parent.st_mode)
            or parent.st_uid != reader_uid
            or stat.S_IMODE(parent.st_mode) != 0o700
        ):
            raise ValueError("private_reader_directory_required")
    if source.resolve() == destination.resolve():
        raise ValueError("distinct_report_projection_required")
    report = private_read(source)
    if (
        report.get("schema") not in {"dm.source-review/v1", "dm.source-review/v2"}
        or not isinstance(report.get("cursor"), str)
        or report.get("model_calls") != 0
        or report.get("automatic_adoption") is not False
    ):
        raise ValueError("source_review_report_required")
    metadata = {
        key: report[key]
        for key in ("offers", "local_candidates", "unavailable", "ancestry", "scope")
        if key in report
    }
    projection = {
        "schema": "dm.source-review-projection/v1",
        "source_schema": report["schema"],
        "source_cursor": report["cursor"],
        "observed_at_ms": report.get("observed_at_ms"),
        "metadata": metadata,
        "model_calls": 0,
        "automatic_adoption": False,
    }
    # The existing writer has one deterministic staging file. Serialize this
    # export separately from the producer; never rerun a probe to repair export.
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    lock = destination.with_name(destination.name + ".lock")
    fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_mode & 0o077
            or info.st_nlink != 1
        ):
            raise ValueError("private_owner_file_required")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        write(destination, projection, reader_uid)
    finally:
        os.close(fd)
    return {
        "state": "exported",
        "source_cursor": report["cursor"],
        "metadata_sha256": hashlib.sha256(encode(metadata)).hexdigest(),
        "model_calls": 0,
        "native_calls": 0,
        "source_mutated": False,
    }


def source_selector(value):
    if (
        not isinstance(value, dict)
        or set(value) != {"source_core_hash", "source_id"}
        or not isinstance(value["source_core_hash"], str)
        or value["source_id"] != "dm:source:v0:" + value["source_core_hash"]
        or len(value["source_core_hash"]) != 43
    ):
        raise ValueError("invalid_source_selector")
    return value


def config(value):
    ancestry = value.get("schema") == "dm.source-review-config/v2"
    if set(value) != {
        "schema",
        "human_task",
        "expires_at_ms",
        "max_runs",
        "interval_seconds",
        "selectors",
        "targets",
        *({"ancestry"} if ancestry else set()),
    }:
        raise ValueError("invalid_review_config")
    if (
        value["schema"]
        not in {"dm.source-review-config/v1", "dm.source-review-config/v2"}
        or not value["human_task"]
    ):
        raise ValueError("invalid_review_config")
    for key, low, high in [
        ("max_runs", 1, 128),
        ("interval_seconds", 60, 86400),
        ("expires_at_ms", 1, 2**53 - 1),
    ]:
        if type(value[key]) is not int or not low <= value[key] <= high:
            raise ValueError("invalid_review_limit")
    if not 1 <= len(value["selectors"]) <= 8 or not 1 <= len(value["targets"]) <= 8:
        raise ValueError("invalid_review_limit")
    for selected in value["selectors"]:
        source_selector(selected)
    labels = []
    for target in value["targets"]:
        if set(target) != {"id", "being_ref", "server", "command"}:
            raise ValueError("invalid_review_target")
        labels.append(target["id"])
        if (
            not isinstance(target["id"], str)
            or not 1 <= len(target["id"]) <= 64
            or not isinstance(target["being_ref"], str)
            or set(target["server"])
            != {"body_ref", "embodiment_id", "incarnation_id", "principal_id"}
            or not isinstance(target["command"], list)
            or not 1 <= len(target["command"]) <= 64
            or not all(
                isinstance(x, str) and 0 < len(x) <= 16384 and "\0" not in x
                for x in target["command"]
            )
        ):
            raise ValueError("invalid_review_target")
    if len(labels) != len(set(labels)):
        raise ValueError("duplicate_review_target")
    if ancestry:
        selected = value["ancestry"]
        if (
            not isinstance(selected, dict)
            or set(selected) != {"observer_id", "selector"}
            or selected["observer_id"] not in labels
        ):
            raise ValueError("invalid_review_ancestry")
        source_selector(selected["selector"])
        if (
            selected["selector"] not in value["selectors"]
            and len(value["selectors"]) == 8
        ):
            raise ValueError("invalid_review_limit")
    return value


def bounded_call(command, request, *, timeout=40):
    """Bound output during production, and kill/reap this owned process group."""
    start = time.monotonic()
    with subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    ) as child:
        try:
            child.stdin.write(encode(request))
            child.stdin.close()
            raw = bytearray()
            with selectors.DefaultSelector() as ready:
                ready.register(child.stdout, selectors.EVENT_READ)
                while True:
                    remaining = timeout - (time.monotonic() - start)
                    if remaining <= 0:
                        raise TimeoutError("review_probe_deadline")
                    if not ready.select(remaining):
                        raise TimeoutError("review_probe_deadline")
                    chunk = os.read(child.stdout.fileno(), 65536)
                    if not chunk:
                        break
                    raw.extend(chunk)
                    if len(raw) > MAX_BYTES:
                        raise ValueError("review_probe_capacity")
            exited = None
            while time.monotonic() - start < timeout:
                exited = os.waitid(
                    os.P_PID, child.pid, os.WEXITED | os.WNOWAIT | os.WNOHANG
                )
                if exited is not None:
                    break
                time.sleep(0.01)
            if exited is None:
                raise TimeoutError("review_probe_deadline")
            if exited.si_status:
                raise ValueError("review_probe_refused")
            return json.loads(raw)
        finally:
            # Keep the unreaped leader's ID reserved until its entire owned
            # process group is stopped, even if a descendant holds stdout.
            with suppress(ProcessLookupError):
                os.killpg(child.pid, signal.SIGKILL)
            child.wait()


def probe(root, request):
    """Only native status/projection; no ledger opening or generic RPC input."""
    from daimon_matrix.client import ClientConfig, LocalClient, read_capability_key
    from daimon_matrix.sources import validate_source_selector

    if set(request) != {"selectors"} or not 1 <= len(request["selectors"]) <= 8:
        raise ValueError("invalid_probe")
    runtime = private_read(root / "runtime.json")
    endpoint = Path(runtime["socket"])
    if not endpoint.is_absolute():
        endpoint = root / endpoint
    key = read_capability_key(os.open(root / "client.key", os.O_RDONLY | os.O_NOFOLLOW))
    client = LocalClient(
        endpoint,
        ClientConfig.load(root / "client.json", key),
        8,
        deadline_ns=time.monotonic_ns() + 30_000_000_000,
    )
    out = []
    remaining = 32
    for selector in request["selectors"]:
        if remaining <= 0:
            raise ValueError("review_call_limit")
        selector = validate_source_selector(selector)
        response = client.invoke("source.status", {"selector": selector})[1]
        remaining -= 1
        if not response["ok"]:
            raise ValueError("source_status_unavailable")
        value = response["result"]
        if len(value["publications"]) > MAX_ROWS or len(value["claims"]) > MAX_ROWS:
            raise ValueError("review_capacity")
        projections = {}
        for row in value["publications"]:
            if row["publisher_me_id"] == value["observer_me_id"]:
                continue  # Offering one's work does not require adopting it.
            if remaining <= 0:
                raise ValueError("review_call_limit")
            result = client.invoke(
                "source.projection", {"publication_id": row["publication_id"]}
            )[1]
            remaining -= 1
            projections[row["publication_id"]] = projection_flags(result)
        out.append({"status": value, "projections": projections})
    return {
        "server": response["server"],
        "sources": out,
        "native_calls": 32 - remaining,
    }


def projection_flags(response):
    if not response["ok"]:
        if response.get("error", {}).get("code") == "source_projection_not_promoted":
            return {"active": False, "publication_event_hash": None}
        raise ValueError("source_projection_unavailable")
    projection = response["result"]
    return {
        "active": projection.get("active", False),
        "publication_event_hash": projection.get("publication_event_hash"),
    }


def compare(observations):
    """A publisher's own offers, compared with each receiver's exact uptake."""
    offers = []
    for publisher, observed in observations.items():
        if "sources" not in observed:
            continue
        for source in observed["sources"]:
            status = source["status"]
            for pub in status["publications"]:
                if pub["publisher_me_id"] != status["observer_me_id"]:
                    continue
                for receiver, other in observations.items():
                    if receiver == publisher:
                        continue
                    state = "unavailable"
                    if "sources" in other:
                        matches = [
                            x
                            for x in other["sources"]
                            if x["status"]["selector"] == status["selector"]
                        ]
                        if len(matches) != 1:
                            raise ValueError("review_selector_mismatch")
                        received = matches[0]
                        known = next(
                            (
                                x
                                for x in received["status"]["publications"]
                                if x["publication_id"] == pub["publication_id"]
                            ),
                            None,
                        )
                        if pub["state"] != "published":
                            state = "publisher-" + pub["state"]
                        elif known is None or known["sequence"] < pub["sequence"]:
                            state = "offered"
                        elif known["sequence"] > pub["sequence"]:
                            state = "receiver-ahead"
                        elif (
                            known["event_hash"] != pub["event_hash"]
                            or known["state"] != "published"
                        ):
                            state = "conflicted"
                        else:
                            applied = received["projections"].get(
                                pub["publication_id"], {}
                            )
                            state = (
                                "already-applied"
                                if applied.get("active") is True
                                and applied.get("publication_event_hash")
                                == pub["event_hash"]
                                else "known-not-applied"
                            )
                    offers.append(
                        {
                            "publisher": publisher,
                            "receiver": receiver,
                            "source_id": status["selector"]["source_id"],
                            "publication_id": pub["publication_id"],
                            "event_hash": pub["event_hash"],
                            "state": state,
                        }
                    )
                    if len(offers) > 256:
                        raise ValueError("review_capacity")
    return sorted(
        offers, key=lambda x: (x["source_id"], x["publication_id"], x["receiver"])
    )


def local_candidates(observations):
    """Retained foreign publications are not fresh publisher observations."""
    result = []
    for receiver, observed in observations.items():
        for source in observed.get("sources", []):
            for pub in source["status"]["publications"]:
                if pub["publisher_me_id"] == source["status"]["observer_me_id"]:
                    continue
                projection = source["projections"].get(pub["publication_id"], {})
                state = (
                    "already-applied"
                    if projection.get("active") is True
                    and projection.get("publication_event_hash") == pub["event_hash"]
                    else "known-not-applied"
                )
                if pub["state"] != "published":
                    state = "known-publisher-" + pub["state"]
                result.append(
                    {
                        "receiver": receiver,
                        "publisher": pub["publisher_me_id"],
                        "source_id": source["status"]["selector"]["source_id"],
                        "publication_id": pub["publication_id"],
                        "event_hash": pub["event_hash"],
                        "state": state,
                        "publisher_freshness": "not-established-by-local-index",
                    }
                )
                if len(result) > 256:
                    raise ValueError("review_capacity")
    return sorted(
        result, key=lambda x: (x["source_id"], x["publication_id"], x["receiver"])
    )


def read_target(target, selected, call):
    result = call(target["command"], {"selectors": selected})
    if (
        set(result) != {"server", "sources", "native_calls"}
        or result["server"] != target["server"]
        or len(result["sources"]) != len(selected)
        or type(result["native_calls"]) is not int
        or not 1 <= result["native_calls"] <= 32
        or any(
            x["status"]["observer_me_id"] != target["being_ref"]
            for x in result["sources"]
        )
        or sorted(encode(x["status"]["selector"]) for x in result["sources"])
        != sorted(encode(x) for x in selected)
    ):
        raise ValueError("review_binding_changed")
    return result


def ancestry_selection(settings, result):
    """Select configured routes from one observer's admitted ancestry claims."""
    anchor = settings["ancestry"]
    sources = [
        x["status"]
        for x in result["sources"]
        if x["status"]["selector"] == anchor["selector"]
    ]
    if len(sources) != 1 or sources[0].get("schema") != "dm.source-status/v0":
        raise ValueError("review_ancestry_unavailable")
    status = sources[0]
    rows, claims = status["eligible_claimants"], status["claims"]
    if (
        not isinstance(rows, list)
        or not isinstance(claims, list)
        or max(len(rows), len(claims)) > MAX_ROWS
    ):
        raise ValueError("review_capacity")
    by_event = {x["claim_event_id"]: x for x in claims}
    if len(by_event) != len(claims):
        raise ValueError("review_ancestry_evidence_mismatch")
    members = []
    for row in rows:
        claim = by_event.get(row["claim_event_id"])
        if (
            claim is None
            or claim["intrinsic_state"] != "valid-asserted"
            or claim["disposition"] != "admitted"
            or any(claim[key] != row[key] for key in ("claimant_me_id", "relations"))
        ):
            raise ValueError("review_ancestry_evidence_mismatch")
        if "descended-from" in row["relations"]:
            members.append(
                {
                    "being_ref": row["claimant_me_id"],
                    "claim_event_id": row["claim_event_id"],
                }
            )
    members.sort(key=lambda x: (x["being_ref"], x["claim_event_id"]))
    configured = {x["being_ref"] for x in settings["targets"]}
    eligible = {x["being_ref"] for x in members}
    return {
        "state": "available",
        "observer_id": anchor["observer_id"],
        "selector": anchor["selector"],
        "members": members,
        "unconfigured_claimants": [
            x for x in members if x["being_ref"] not in configured
        ],
        "excluded_targets": [
            {"target": x["id"], "reason": "not-locally-admitted-descendant"}
            for x in settings["targets"]
            if x["id"] != anchor["observer_id"] and x["being_ref"] not in eligible
        ],
    }


def calendar_slots(settings, now_ms):
    """Finite absolute dates, no recurring timer or permission to install one."""
    settings = config(settings)
    step = settings["interval_seconds"] * 1000
    return [
        datetime.fromtimestamp((stamp + 999) // 1000, UTC).strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        )
        for stamp in (now_ms + step * (n + 1) for n in range(settings["max_runs"]))
        if ((stamp + 999) // 1000) * 1000 < settings["expires_at_ms"]
    ]


def review(
    settings, state_path, report_path, *, call=bounded_call, now_ms=None, control=None
):
    settings = config(settings)
    reserved_paths = {state_path.resolve(), state_path.with_suffix(".lock").resolve()}
    if report_path.resolve() in reserved_paths:
        raise ValueError("distinct_review_paths_required")
    now = int(time.time() * 1000) if now_ms is None else now_ms
    fingerprint = hashlib.sha256(encode(settings)).hexdigest()
    state_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(
        state_path.with_suffix(".lock"), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600
    )
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_mode & 0o077
            or info.st_nlink != 1
        ):
            raise ValueError("private_owner_file_required")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        state = (
            private_read(state_path)
            if state_path.exists()
            else {
                "schema": "dm.source-review-state/v1",
                "config_sha256": fingerprint,
                "runs": 0,
                "next_at_ms": 0,
                "paused": False,
                "stopped": False,
                "cursor": None,
            }
        )
        if state["config_sha256"] != fingerprint:
            raise ValueError("review_config_changed")
        if control is not None:
            if control not in {"pause", "resume", "stop"}:
                raise ValueError("invalid_review_control")
            if control == "stop":
                state["stopped"] = True
            else:
                state["paused"] = control == "pause"
            write(state_path, state)
            return {
                "state": "finished"
                if state["stopped"]
                else "paused"
                if state["paused"]
                else "resumed",
                "runs": state["runs"],
                "native_calls": 0,
            }
        terminal = (
            state["stopped"]
            or now >= settings["expires_at_ms"]
            or state["runs"] >= settings["max_runs"]
        )
        if terminal or state["paused"] or now < state["next_at_ms"]:
            return {
                "state": "finished"
                if terminal
                else "paused"
                if state["paused"]
                else "not-due",
                "runs": state["runs"],
                "native_calls": 0,
            }
        # Reserve before I/O. A crash consumes this attempt; no provider/input replay.
        state.update(
            runs=state["runs"] + 1, next_at_ms=now + settings["interval_seconds"] * 1000
        )
        write(state_path, state)
        observed = {}
        ancestry = None
        targets = settings["targets"]
        if "ancestry" in settings:
            anchor = settings["ancestry"]
            observer = next(x for x in targets if x["id"] == anchor["observer_id"])
            selected = list(settings["selectors"])
            if anchor["selector"] not in selected:
                selected.append(anchor["selector"])
            result = None
            try:
                result = read_target(observer, selected, call)
                ancestry = ancestry_selection(settings, result)
                observed[observer["id"]] = {
                    **result,
                    "sources": [
                        x
                        for x in result["sources"]
                        if x["status"]["selector"] in settings["selectors"]
                    ],
                }
                excluded = {x["target"] for x in ancestry["excluded_targets"]}
                targets = [
                    x for x in targets if x != observer and x["id"] not in excluded
                ]
            except Exception as error:
                observed[observer["id"]] = {
                    "state": "unavailable",
                    "error_class": type(error).__name__,
                    "native_calls": 0 if result is None else result["native_calls"],
                }
                ancestry = {
                    "state": "unavailable",
                    "observer_id": observer["id"],
                    "selector": anchor["selector"],
                    "members": [],
                    "unconfigured_claimants": [],
                    "excluded_targets": [
                        {"target": x["id"], "reason": "ancestry-unavailable"}
                        for x in targets
                        if x != observer
                    ],
                }
                targets = []
        for target in targets:
            try:
                observed[target["id"]] = read_target(
                    target, settings["selectors"], call
                )
            except Exception as error:
                observed[target["id"]] = {
                    "state": "unavailable",
                    "error_class": type(error).__name__,
                }
        offers = compare(observed)
        candidates = local_candidates(observed)
        unavailable = sorted(k for k, x in observed.items() if "sources" not in x)
        cursor_core = {
            "offers": offers,
            "local_candidates": candidates,
            "unavailable": unavailable,
        }
        if ancestry is not None:
            cursor_core["ancestry"] = ancestry
        cursor = hashlib.sha256(encode(cursor_core)).hexdigest()
        report = {
            "schema": "dm.source-review/v1",
            "observed_at_ms": now,
            "human_task": settings["human_task"],
            "run": state["runs"],
            "changed": cursor != state["cursor"],
            "cursor": cursor,
            "offers": offers,
            "local_candidates": candidates,
            "unavailable": unavailable,
            "native_calls": sum(x.get("native_calls", 0) for x in observed.values()),
            "native_call_ceiling": 32 * len(settings["targets"]),
            "unconfirmed_targets": unavailable,
            "model_calls": 0,
            "automatic_adoption": False,
            "finished": state["runs"] >= settings["max_runs"],
            "scope": (
                "Selected Sources only; project participation is not shared ancestry."
            ),
        }
        if ancestry is not None:
            report.update(
                schema="dm.source-review/v2",
                ancestry=ancestry,
                scope=(
                    "Locally admitted descendant claims select configured routes; "
                    "the observer is reviewed locally. Ancestry claims grant no "
                    "content access or automatic adoption."
                ),
            )
        write(report_path, report)
        state["cursor"] = cursor
        write(state_path, state)
        return report
    finally:
        os.close(fd)


def main():
    def interrupted(*_):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupted)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe-runtime", type=Path)
    parser.add_argument("--config", type=Path)
    parser.add_argument("--state", type=Path)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--control", choices=["pause", "resume", "stop"])
    parser.add_argument("--scheduled", action="store_true")
    parser.add_argument("--export-current", type=Path)
    parser.add_argument("--reader-uid", type=int)
    args = parser.parse_args()
    try:
        if args.export_current:
            if not args.report or any(
                (
                    args.probe_runtime,
                    args.config,
                    args.state,
                    args.control,
                    args.scheduled,
                )
            ):
                raise ValueError("invalid_report_export")
            print(
                json.dumps(
                    export_report(args.report, args.export_current, args.reader_uid)
                )
            )
            return 0
        if args.reader_uid is not None:
            raise ValueError("report_export_required")
        if args.probe_runtime:
            raw = sys.stdin.buffer.read(16385)
            if len(raw) > 16384 or any(
                (args.config, args.state, args.report, args.control, args.scheduled)
            ):
                raise ValueError("invalid_probe")
            value = probe(args.probe_runtime, json.loads(raw))
        else:
            if not all((args.config, args.state, args.report)):
                raise ValueError("review_binding_required")
            value = review(
                private_read(args.config), args.state, args.report, control=args.control
            )
        if args.scheduled:
            summary = {
                key: value[key]
                for key in (
                    "state",
                    "run",
                    "runs",
                    "changed",
                    "native_calls",
                    "native_call_ceiling",
                    "finished",
                )
                if key in value
            }
            print(json.dumps(summary))
        else:
            print(json.dumps(value))
        return 0
    except Exception as error:
        failure = {"state": "refused", "error_class": type(error).__name__}
        print(json.dumps(failure))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
