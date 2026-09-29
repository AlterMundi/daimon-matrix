#!/usr/bin/env python3
"""Read-only verification that attributed memory really is attributed.

The host-shared memory pool carries a projection layer beside the ordinary chapters:
one namespace per ``source_instance``, and one projection row per memory naming its
head event, that event's hash, and the statement's hash, length, media type and
classification. The point of the layer is that "which portions were lived by which
embodiment" is a JOIN over namespaces rather than a guess from text, and that every
row is tied to a signed event somebody can re-verify.

This tool checks that claim instead of assuming it. For each projection it opens the
signed event in the ledger of the embodiment the namespace names, and verifies the
head hash against the event's own content hash, the statement hash and length and
media type and classification against the event's content reference, the category and
author against the event payload, and the event's origin embodiment against the
namespace. That last comparison is the substitution check: a pool row claiming one
embodiment while the event was signed by another is the failure the whole design
exists to prevent, and it is reported rather than tolerated.

It also reports what is *not* attributed, because a pool where every chapter is
attributed and a pool where attributed rows are a small honest minority look the same
from inside the projection tables and completely different from the chapters table.
Direct unsigned writes are a supported part of the design; they must simply never
surface in an attributed query.

Nothing here opens custody, reads a password, writes a file or mutates state. Every
database is opened read-only. A namespace whose embodiment has no runtime supplied is
reported as unverifiable from here rather than as a failure: a pool legitimately holds
projections synced from embodiments living on other hosts, and one host cannot judge
another's ledger.

    verify_memory_attribution.py --pool <library.db> --runtime <state-root> [...]
"""

from __future__ import annotations

import argparse
import json
import re
import sqlite3
import sys
from pathlib import Path
from typing import Any

REPORT_SCHEMA = "dm-memory-attribution-report/v0"
SOURCE_INSTANCE = re.compile(r"^matrix:embodiment:[0-9a-f-]{36}$")
LEDGER_NAME = "ledger.sqlite"
RUNTIME_NAME = "runtime.json"


def _read_only(path: Path) -> sqlite3.Connection:
    """Open one database so that no write is possible even by accident."""

    connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    return connection


def _rows(connection: sqlite3.Connection, sql: str) -> list[dict[str, Any]]:
    try:
        return [dict(row) for row in connection.execute(sql)]
    except sqlite3.Error:
        return []


def local_origins(runtimes: list[Path]) -> dict[str, dict[str, Any]]:
    """Map each supplied runtime by the embodiment it is, from its public bundle."""

    result: dict[str, dict[str, Any]] = {}
    for root in runtimes:
        bundle_path = root / RUNTIME_NAME
        if not bundle_path.is_file():
            continue
        try:
            bundle = json.loads(bundle_path.read_bytes())
            origin = bundle["local_origin"]
            embodiment_id = str(origin["embodiment_id"])
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
            continue
        result[f"matrix:{embodiment_id}"] = {
            "body_ref": origin.get("body_ref"),
            "principal_id": origin.get("principal_id"),
            "ledger": root / LEDGER_NAME,
            "runtime": str(root),
        }
    return result


def _signed_event(ledger: Path, event_id: str) -> dict[str, Any] | None:
    """One event from one ledger, unwrapped, or None when it is not there."""

    if not ledger.is_file():
        return None
    try:
        connection = _read_only(ledger)
    except sqlite3.Error:
        return None
    try:
        found = connection.execute(
            "SELECT event_json, content_hash FROM events WHERE event_id = ?",
            (event_id,),
        ).fetchone()
    except sqlite3.Error:
        return None
    finally:
        connection.close()
    if found is None:
        return None
    try:
        wrapper = json.loads(found["event_json"])
    except (TypeError, ValueError, json.JSONDecodeError):
        return None
    event = wrapper.get("event", wrapper) if isinstance(wrapper, dict) else None
    if not isinstance(event, dict):
        return None
    return {"event": event, "content_hash": found["content_hash"]}


def _check(
    name: str, ok: bool, checks: dict[str, bool], reasons: list[str], detail: str
) -> None:
    checks[name] = bool(ok)
    if not ok:
        reasons.append(f"{name}: {detail}")


def verify(pool: Path, runtimes: list[Path]) -> dict[str, Any]:
    """Verify every attributable projection in one pool. Read-only throughout."""

    reasons: list[str] = []
    if not pool.is_file():
        return {
            "schema": REPORT_SCHEMA,
            "pool": str(pool),
            "verified": False,
            "reasons": ["pool_missing"],
            "namespaces": [],
            "projections": [],
            "chapters_total": 0,
            "chapters_attributed": 0,
            "chapters_unattributed": 0,
        }
    origins = local_origins(runtimes)
    connection = _read_only(pool)
    try:
        namespaces = {
            str(row["namespace_id"]): row
            for row in _rows(
                connection,
                "SELECT * FROM daimon_projection_namespaces",
            )
        }
        projections = _rows(
            connection,
            "SELECT * FROM daimon_projections ORDER BY projection_id",
        )
        counted = _rows(connection, "SELECT count(*) AS n FROM chapters")
        chapters_total = int(counted[0]["n"]) if counted else 0
    finally:
        connection.close()

    # One namespace per source instance is the whole attribution claim, so a
    # duplicate is a defect in the pool and not something to average over.
    seen: dict[str, str] = {}
    for namespace_id, row in sorted(namespaces.items()):
        instance = str(row.get("source_instance") or "")
        if instance in seen:
            reasons.append(
                f"duplicate_namespace_for_source_instance: {instance} "
                f"({seen[instance]} and {namespace_id})"
            )
        seen[instance] = namespace_id
        if SOURCE_INSTANCE.fullmatch(instance) is None:
            reasons.append(f"namespace_source_instance_not_an_embodiment: {instance}")

    verified_projections: list[dict[str, Any]] = []
    attributed_chapters: set[Any] = set()
    for row in projections:
        namespace_id = str(row.get("namespace_id") or "")
        namespace = namespaces.get(namespace_id)
        checks: dict[str, bool] = {}
        local_reasons: list[str] = []
        entry: dict[str, Any] = {
            "projection_id": row.get("projection_id"),
            "memory_id": row.get("memory_id"),
            "chapter_id": row.get("chapter_id"),
            "active": row.get("active"),
            "category": row.get("category"),
            "namespace_id": namespace_id,
            "source_instance": None
            if namespace is None
            else namespace.get("source_instance"),
            "subject_me_id": None
            if namespace is None
            else namespace.get("subject_me_id"),
        }
        if namespace is None:
            entry["state"] = "orphaned"
            entry["checks"] = checks
            entry["reasons"] = ["projection_namespace_missing"]
            verified_projections.append(entry)
            reasons.append(
                f"projection_namespace_missing: {row.get('projection_id')} "
                f"names {namespace_id}"
            )
            continue
        instance = str(namespace.get("source_instance") or "")
        entry["state"] = "verified"
        if row.get("active") in (1, "1", True):
            attributed_chapters.add(row.get("chapter_id"))
        known = origins.get(instance)
        if known is None:
            # A pool legitimately holds projections synced from embodiments that live
            # on another host. One host cannot verify another's ledger, and saying so
            # is the honest answer; calling it a failure would train the operator to
            # ignore this report.
            entry["state"] = "remote"
            entry["checks"] = checks
            entry["reasons"] = []
            verified_projections.append(entry)
            continue

        found = _signed_event(
            Path(known["ledger"]), str(row.get("head_event_id") or "")
        )
        if found is None:
            entry["state"] = "unverified"
            entry["checks"] = checks
            entry["reasons"] = [
                "head_event_absent_from_the_naming_embodiment_ledger: "
                f"{row.get('head_event_id')}"
            ]
            verified_projections.append(entry)
            reasons.append(
                f"head_event_absent: {row.get('projection_id')} names "
                f"{row.get('head_event_id')} which is not in {instance}'s ledger"
            )
            continue
        event = found["event"]
        payload = event.get("payload")
        payload = payload if isinstance(payload, dict) else {}
        content_ref = payload.get("content_ref")
        content_ref = content_ref if isinstance(content_ref, dict) else {}
        origin = event.get("origin")
        origin = origin if isinstance(origin, dict) else {}

        _check(
            "head_event_hash",
            found["content_hash"] == row.get("head_event_hash"),
            checks,
            local_reasons,
            f"pool {row.get('head_event_hash')} != ledger {found['content_hash']}",
        )
        # The substitution check: the row's claimed author must be the body that
        # actually signed the event it points at.
        _check(
            "origin_embodiment_matches_namespace",
            f"matrix:{origin.get('embodiment_id')}" == instance,
            checks,
            local_reasons,
            f"event origin {origin.get('embodiment_id')} != namespace {instance}",
        )
        for name, reference_field, pool_field in (
            ("statement_hash", "sha256", "statement_hash"),
            ("statement_length", "byte_length", "statement_length"),
            ("statement_media_type", "media_type", "statement_media_type"),
            ("classification", "classification", "classification"),
        ):
            expected = content_ref.get(reference_field)
            actual = row.get(pool_field)
            _check(
                name,
                expected == actual,
                checks,
                local_reasons,
                f"content_ref {reference_field} {expected!r} "
                f"!= pool {pool_field} {actual!r}",
            )
        _check(
            "category",
            payload.get("category") == row.get("category"),
            checks,
            local_reasons,
            f"event {payload.get('category')} != pool {row.get('category')}",
        )
        _check(
            "memory_id",
            payload.get("memory_id") == row.get("memory_id"),
            checks,
            local_reasons,
            f"event {payload.get('memory_id')} != pool {row.get('memory_id')}",
        )
        # Attribution is per embodiment and the pool is per being: the author named by
        # the event, the author named by the row and the namespace's subject must agree.
        _check(
            "author_is_the_namespace_subject",
            payload.get("author_me_id")
            == row.get("author_me_id")
            == namespace.get("subject_me_id"),
            checks,
            local_reasons,
            f"event {payload.get('author_me_id')} / pool {row.get('author_me_id')} / "
            f"namespace {namespace.get('subject_me_id')}",
        )
        if local_reasons:
            entry["state"] = "unverified"
            reasons.extend(
                f"{row.get('projection_id')}: {reason}" for reason in local_reasons
            )
        entry["checks"] = checks
        entry["reasons"] = local_reasons
        verified_projections.append(entry)

    attributed = len(attributed_chapters)
    return {
        "schema": REPORT_SCHEMA,
        "pool": str(pool),
        "verified": not reasons,
        "namespaces": [
            {
                "namespace_id": namespace_id,
                "source_instance": row.get("source_instance"),
                "subject_me_id": row.get("subject_me_id"),
                "projector_id": row.get("projector_id"),
                "projector_version": row.get("projector_version"),
                "generation": row.get("generation"),
                "accepted_checkpoint_sequence": row.get("accepted_checkpoint_sequence"),
                "verifiable_from_here": row.get("source_instance") in origins,
            }
            for namespace_id, row in sorted(namespaces.items())
        ],
        "projections": verified_projections,
        "chapters_total": chapters_total,
        "chapters_attributed": attributed,
        "chapters_unattributed": chapters_total - attributed,
        "reasons": reasons,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--pool", type=Path, required=True, help="the shared library.db"
    )
    parser.add_argument(
        "--runtime",
        type=Path,
        action="append",
        default=[],
        help="a state root with runtime.json and its ledger; repeat per local body",
    )
    arguments = parser.parse_args(argv)
    report = verify(arguments.pool, list(arguments.runtime))
    sys.stdout.write(json.dumps(report, indent=1, sort_keys=True) + "\n")
    return 0 if report["verified"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
