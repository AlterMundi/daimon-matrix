#!/usr/bin/env python3
"""Build/verify an inert full-history sidecar for the existing being archive.

No enrollment, event admission, source execution, network or live installation.
Selected roots and all Git refs must already be within the human's transfer scope.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import tempfile
from contextlib import closing
from pathlib import Path
from typing import Any

try:
    from tools import export_being as archive
except ModuleNotFoundError:
    import export_being as archive

SCHEMA = "dm.being-memory-preservation/v1"
SELECTION = "dm.being-memory-preservation.selection/v1"
PROFILE = "memory-preservation.json"


def git_command(root: Path, *args: str) -> str:
    environment = {
        **os.environ,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_NO_LAZY_FETCH": "1",
    }
    result = subprocess.run(
        [
            "git",
            "-c",
            "core.hooksPath=" + os.devnull,
            "-c",
            "core.fsmonitor=false",
            "-c",
            "pack.packObjectsHook=",
            "-C",
            str(root),
            *args,
        ],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
        env=environment,
    )
    if result.returncode:
        raise PreservationError("selected_git_history_unavailable")
    return result.stdout.strip()


class PreservationError(ValueError):
    """Stable diagnostics exclude source contents and private paths."""


def encoded(value: Any) -> Any:
    if isinstance(value, bytes):
        return {"sqlite_blob_base64": base64.b64encode(value).decode()}
    return value


def database_state(path: Path) -> dict[str, Any]:
    """Logical snapshot identity, including unknown columns and native history."""
    evidence = archive.sqlite_details(path)
    tables = {}
    with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as db:
        for (name,) in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        ).fetchall():
            quoted = '"' + name.replace('"', '""') + '"'
            cursor = db.execute("SELECT * FROM " + quoted)
            rows = sorted(
                archive.json_bytes([encoded(v) for v in row]) for row in cursor
            )
            tables[name] = {
                "columns": [d[0] for d in cursor.description],
                "rows": len(rows),
                "sha256": hashlib.sha256(b"".join(rows)).hexdigest(),
            }
    return json.loads(archive.json_bytes({"sqlite": evidence, "tables": tables}))


def located(locator: dict, sources: dict) -> tuple[Path, str]:
    source = sources.get(locator.get("source_id"))
    if source is None:
        raise PreservationError("unknown_selected_source")
    relative = archive.safe_name(locator["path"])
    if relative not in {f["path"] for f in source["files"]}:
        raise PreservationError("dependency_outside_selected_files")
    path = archive.safe_path(Path(source["root"]) / relative)
    return path, f"payload/{source['id']}/{relative}"


def memory_references(path: Path) -> list[dict]:
    with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as db:
        rows = db.execute(
            "SELECT event_id,status,event_json FROM events "
            "WHERE kind='memory.recorded' ORDER BY inserted_order"
        ).fetchall()
    found = []
    for event_id, status, raw in rows:
        event = json.loads(raw)
        # evidence_refs are history identifiers, not content-reference objects.
        # Their exact bytes remain in the complete ledger snapshot.
        refs = [event["payload"].get("content_ref")]
        for ref in refs:
            if ref is not None:
                found.append(
                    {"event_id": event_id, "source_status": status, "reference": ref}
                )
    return found


def build(plan: dict, selection: dict, output: Path, *, writers_stopped: bool) -> dict:
    if plan.get("schema") != archive.PLAN_SCHEMA or not writers_stopped:
        raise PreservationError("supported_plan_and_writer_cutoff_required")
    if selection.get("schema") != SELECTION:
        raise PreservationError("unsupported_preservation_selection")
    output = archive.safe_path(output)
    if output.exists():
        raise PreservationError("existing_profile_directory_refused")
    sources = {s["id"]: s for s in plan["sources"]}
    if len(sources) != len(plan["sources"]):
        raise PreservationError("duplicate_source_identity")
    for s in sources.values():
        root = archive.safe_path(Path(s["root"]))
        if root == output or root in output.parents:
            raise PreservationError("profile_must_be_outside_sources")
        if archive.inventory(root, s["kind"], s.get("selection")) != (
            s["files"],
            s["omissions"],
        ):
            raise PreservationError("source_drift_regenerate_plan")
    profile_source = f"context-{len(sources) + 1:03d}"
    with tempfile.TemporaryDirectory(
        prefix=".memory-profile-", dir=output.parent
    ) as td:
        stage = Path(td)
        profile = {
            "schema": SCHEMA,
            "meaning": "preservation only; no admission or authority",
            "selection": selection,
            "databases": [],
            "dependencies": [],
            "artifacts": [],
            "git_history": [],
            "unavailable": [],
        }
        references = []
        for kind in ("hmk", "matrix"):
            for locator in selection.get(kind, []):
                path, member = located(locator, sources)
                snapshot = stage / "snapshot.sqlite"
                archive.copy_source(path, snapshot)
                profile["databases"].append(
                    {"kind": kind, "member": member, "state": database_state(snapshot)}
                )
                if kind == "matrix":
                    references.extend(memory_references(snapshot))
                snapshot.unlink()
        references.extend(
            {"event_id": None, "source_status": "owner-selected", "reference": ref}
            for ref in selection.get("required_content", [])
        )
        content = selection.get("content", {})
        unavailable = selection.get("unavailable", {})
        for item in references:
            ref = item["reference"]
            sha = ref["sha256"]
            locator = content.get(sha)
            if locator is None:
                declaration = unavailable.get(sha)
                if (
                    not isinstance(declaration, dict)
                    or declaration.get("status") != "unavailable_before_export"
                    or not declaration.get("reason")
                ):
                    raise PreservationError("required_content_unresolved")
                profile["unavailable"].append({**item, "declaration": declaration})
                continue
            path, member = located(locator, sources)
            if path.stat().st_size != ref["byte_length"] or archive.digest(path) != sha:
                raise PreservationError("referenced_content_mismatch")
            profile["dependencies"].append({**item, "member": member})
        for locator in selection.get("artifacts", []):
            path, member = located(locator, sources)
            profile["artifacts"].append(
                {
                    "member": member,
                    "sha256": archive.digest(path),
                    "bytes": path.stat().st_size,
                    "role": locator["role"],
                }
            )
        for source_id in selection.get("git_sources", []):
            source = sources.get(source_id)
            if source is None or source["kind"] not in (
                "project",
                "context",
                "skills",
                "codex",
                "hermes",
            ):
                raise PreservationError("unknown_selected_git_source")
            root = archive.safe_path(Path(source["root"]))

            if not archive.safe_path(root / ".git").is_dir():
                raise PreservationError("git_indirection_requires_explicit_adaptation")
            if git_command(root, "rev-parse", "--show-toplevel") != str(root):
                raise PreservationError("git_source_must_be_repository_root")
            if git_command(root, "rev-parse", "--is-shallow-repository") != "false":
                raise PreservationError("shallow_history_requires_explicit_adaptation")
            refs = git_command(root, "show-ref", "--head")
            bundle = stage / (source_id + ".bundle")
            git_command(root, "bundle", "create", str(bundle), "--all")
            git_command(root, "bundle", "verify", str(bundle))
            if git_command(root, "show-ref", "--head") != refs:
                raise PreservationError("git_history_changed_during_bundle")
            profile["git_history"].append(
                {
                    "source_id": source_id,
                    "bundle": f"payload/{profile_source}/{bundle.name}",
                    "sha256": archive.digest(bundle),
                    "bytes": bundle.stat().st_size,
                    "refs": refs.splitlines(),
                    "head": git_command(root, "rev-parse", "HEAD"),
                    "scope": "selected refs; configuration is excluded",
                }
            )
        archive.new_file(stage / PROFILE, archive.json_bytes(profile))
        # Scan generated plaintext before exposing it as a contextual source.
        for p in stage.iterdir():
            archive.scan_credentials(p)
        output.mkdir(mode=0o700)
        shutil.copytree(stage, output, dirs_exist_ok=True)
        for p in output.iterdir():
            p.chmod(0o600)
    return profile


def verify(stage: Path, profile_member: str) -> dict:
    stage = archive.safe_path(stage)
    path = archive.safe_path(stage / archive.safe_name(profile_member))
    profile = json.loads(path.read_bytes())
    if profile.get("schema") != SCHEMA:
        raise PreservationError("unsupported_preservation_profile")
    manifest = json.loads((stage / "manifest.json").read_bytes())
    entries = {f["path"]: f for f in manifest["files"]}
    if (
        profile_member not in entries
        or archive.digest(path) != entries[profile_member]["sha256"]
    ):
        raise PreservationError("profile_not_bound_to_archive")

    def member(name: str) -> Path:
        archive.safe_name(name)
        if name not in entries:
            raise PreservationError("required_member_missing")
        p = archive.safe_path(stage / name)
        if not p.is_file() or archive.digest(p) != entries[name]["sha256"]:
            raise PreservationError("preserved_member_mismatch")
        return p

    checked = []
    refs = []
    for item in profile["databases"]:
        db = member(item["member"])
        if database_state(db) != item["state"]:
            raise PreservationError("preserved_database_history_mismatch")
        if item["kind"] == "matrix":
            refs.extend(memory_references(db))
        checked.append(item["member"])
    required = profile["selection"].get("required_content", [])
    refs.extend(
        {"event_id": None, "source_status": "owner-selected", "reference": r}
        for r in required
    )
    accounted = [
        {k: i[k] for k in ("event_id", "source_status", "reference")}
        for i in profile["dependencies"] + profile["unavailable"]
    ]
    if sorted(map(archive.json_bytes, refs)) != sorted(
        map(archive.json_bytes, accounted)
    ):
        raise PreservationError("content_reference_inventory_mismatch")
    for item in profile["dependencies"]:
        p = member(item["member"])
        ref = item["reference"]
        if p.stat().st_size != ref["byte_length"] or archive.digest(p) != ref["sha256"]:
            raise PreservationError("referenced_content_mismatch")
        checked.append(item["member"])
    for item in profile["unavailable"]:
        d = item["declaration"]
        if d.get("status") != "unavailable_before_export" or not d.get("reason"):
            raise PreservationError("invalid_prior_unavailability")
    for item in profile["artifacts"]:
        p = member(item["member"])
        if p.stat().st_size != item["bytes"] or archive.digest(p) != item["sha256"]:
            raise PreservationError("learned_artifact_mismatch")
        checked.append(item["member"])
    for item in profile["git_history"]:
        p = member(item["bundle"])
        if p.stat().st_size != item["bytes"] or archive.digest(p) != item["sha256"]:
            raise PreservationError("git_history_bundle_mismatch")
        r = subprocess.run(
            ["git", "bundle", "list-heads", str(p)],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        if r.returncode or sorted(r.stdout.strip().splitlines()) != sorted(
            item["refs"]
        ):
            raise PreservationError("git_history_refs_mismatch")
        checked.append(item["bundle"])
    return {
        "schema": SCHEMA,
        "preservation_verified": True,
        "complete_available_content": not profile["unavailable"],
        "unavailable_before_export": len(profile["unavailable"]),
        "verified_members": len(set(checked)),
        "authority_or_admission": "not_performed",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="operation", required=True)
    b = sub.add_parser("build")
    b.add_argument("--plan", type=Path, required=True)
    b.add_argument("--selection", type=Path, required=True)
    b.add_argument("--output", type=Path, required=True)
    b.add_argument("--writers-stopped", action="store_true")
    v = sub.add_parser("verify")
    v.add_argument("--stage", type=Path, required=True)
    v.add_argument("--profile-member", required=True)
    args = parser.parse_args()
    try:
        if args.operation == "build":
            result = build(
                json.loads(args.plan.read_bytes()),
                json.loads(args.selection.read_bytes()),
                args.output,
                writers_stopped=args.writers_stopped,
            )
            result = {"schema": result["schema"], "profile_created": True}
        else:
            result = verify(args.stage, args.profile_member)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (
        PreservationError,
        archive.ExportError,
        OSError,
        sqlite3.Error,
        KeyError,
        ValueError,
    ) as error:
        print(
            json.dumps(
                {
                    "error": type(error).__name__,
                    "code": str(error)
                    if isinstance(error, (PreservationError, archive.ExportError))
                    else "preservation_input_or_io_failure",
                }
            )
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
