#!/usr/bin/env python3
"""Discover, export, verify and stage private Hermes/Codex contextual continuity.

Python 3.11+ stdlib only. No harness execution, account access or live import.
Selected source homes must belong to the same being. Review the private plan.
The being label does not filter profiles or database rows. Multi-profile homes
require --selection with explicit owned context and approved omissions.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import shutil
import sqlite3
import stat
import sys
import tarfile
import tempfile
import zipfile
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

PLAN_SCHEMA = "dm.being-export-plan/v1"
ARCHIVE_SCHEMA = "dm.being-context-archive/v1"
SELECTION_SCHEMA = "dm.being-source-selection/v1"
KINDS = ("hermes", "codex", "memory", "skills", "context", "sessions", "project")
SECRET_NAMES = {
    ".env",
    ".envrc",
    "auth.json",
    "auth.lock",
    "credentials.json",
    "credentials",
    "id_rsa",
    "id_ed25519",
    ".netrc",
    ".npmrc",
    ".pypirc",
    "custody.json",
    "capability.json",
    "capabilities.json",
}
SECRET_DIRS = {".ssh", "custody", "keyring"}
EPHEMERAL = {"__pycache__", ".venv", "node_modules", ".pytest_cache", ".ruff_cache"}
TOKEN = re.compile(
    rb"\b(?:github[_]pat[_][A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|"
    rb"sk-[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{20,}|"
    rb"[0-9]{6,15}:[A-Za-z0-9_-]{30,})\b"
)
PRIVATE_KEY = re.compile(rb"-----BEGIN (?:[A-Z0-9 ]*PRIVATE KEY|PGP PRIVATE KEY)")
ASSIGNMENT = re.compile(
    rb"(?im)\b(?:api[_-]?key|access[_-]?token|client[_-]?secret|"
    rb"password|bot[_-]?token)\b\s*[:=]\s*[\"']?"
    rb"([A-Za-z0-9_./+=:@-]{20,})"
)
ENV_SECRET = re.compile(
    r"(?:^|_)(?:API_KEY|ACCESS_KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIALS?|AUTH|PRIVATE_KEY)(?:_|$)",
    re.IGNORECASE,
)
MAX_BYTES = 5 * 1024**3
MAX_MEMBERS = 100_000


class ExportError(ValueError):
    """Diagnostics contain codes, never source contents or matched credentials."""


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def safe_name(name: str) -> str:
    pure = PurePosixPath(name)
    if (
        not name
        or pure.is_absolute()
        or "\\" in name
        or "\x00" in name
        or any(part in ("", ".", "..") for part in name.split("/"))
        or pure.as_posix() != name
        or ":" in name
    ):
        raise ExportError("unsafe_relative_path")
    return name


def safe_path(path: Path) -> Path:
    path = path.expanduser().absolute()
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ExportError("symlink_path_requires_explicit_regular_source")
    return path


def new_file(path: Path, data: bytes) -> None:
    path = safe_path(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    ).encode()


def excluded(relative: str, kind: str) -> str | None:
    parts = PurePosixPath(relative).parts
    if (
        any(p.lower() in SECRET_DIRS for p in parts)
        or parts[-1].lower() in SECRET_NAMES
        or parts[-1].lower().startswith(".env.")
        or parts[-1].lower().endswith((".pem", ".key", ".p12", ".pfx"))
    ):
        return "credential_or_custody_separate_handoff"
    if ".git" in parts:
        return "repository_history_requires_future_git_adapter"
    if kind in ("hermes", "codex", "project") and any(p in EPHEMERAL for p in parts):
        return "rebuildable_runtime_dependency"
    if parts[-1].endswith(
        (
            ".db-wal",
            ".db-shm",
            ".sqlite-wal",
            ".sqlite-shm",
            ".sqlite3-wal",
            ".sqlite3-shm",
        )
    ):
        return "sqlite_sidecar_requires_verified_database_snapshot"
    return None


def validate_selection(selection: Any) -> dict[str, Any]:
    if not isinstance(selection, dict) or set(selection) != {
        "include",
        "omit",
        "ownership",
        "sqlite_ownership",
    }:
        raise ExportError("explicit_source_selection_fields_required")
    if selection["ownership"] not in ("same-being", "shared-commons"):
        raise ExportError("explicit_context_ownership_required")
    if selection["sqlite_ownership"] not in ("same-being", "unknown", "mixed"):
        raise ExportError("invalid_sqlite_ownership_declaration")
    included, omitted = selection["include"], selection["omit"]
    if not isinstance(included, list) or not included:
        raise ExportError("nonempty_context_selection_required")
    if not isinstance(omitted, list):
        raise ExportError("explicit_omissions_required")
    for path in included:
        if not isinstance(path, str):
            raise ExportError("invalid_selection_path")
        if path != ".":
            safe_name(path)
    for entry in omitted:
        if (
            not isinstance(entry, dict)
            or set(entry) != {"path", "reason"}
            or not isinstance(entry["path"], str)
            or not isinstance(entry["reason"], str)
            or not entry["reason"].strip()
        ):
            raise ExportError("omission_path_and_reason_required")
        safe_name(entry["path"])
    if len(set(included)) != len(included) or len(
        {entry["path"] for entry in omitted}
    ) != len(omitted):
        raise ExportError("duplicate_selection_path")
    if any(
        anchor == entry["path"] or anchor.startswith(entry["path"] + "/")
        for anchor in included
        for entry in omitted
    ):
        raise ExportError("selected_anchor_conflicts_with_omission")
    return selection


def selection_reason(
    relative: str, selection: dict[str, Any] | None, *, directory: bool
) -> str | None:
    if selection is None:
        return None
    for omission in selection["omit"]:
        path = omission["path"]
        if relative == path or relative.startswith(path + "/"):
            return "owner_selected_omission: " + omission["reason"]
    for path in selection["include"]:
        if path == "." or relative == path or relative.startswith(path + "/"):
            return None
        if directory and path.startswith(relative + "/"):
            return None
    return "outside_explicit_context_selection"


def check_profile_scope(
    root: Path, relative: str, selection: dict[str, Any] | None
) -> None:
    # Enumerate only the boundary, never a foreign profile's contents.
    if selection is None:
        raise ExportError("profiles_require_explicit_source_selection")
    for child in (root / relative).iterdir():
        path = child.relative_to(root).as_posix()
        if selection_reason(path, selection, directory=child.is_dir()) is not None:
            continue
        if not any(
            anchor == path or anchor.startswith(path + "/")
            for anchor in selection["include"]
        ):
            raise ExportError("each_selected_profile_requires_explicit_anchor")


def inventory(
    root: Path, kind: str, selection: dict[str, Any] | None = None
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    root = safe_path(root)
    if not root.is_dir():
        raise ExportError("source_root_must_be_directory")
    if selection is not None:
        validate_selection(selection)
    files, omissions = [], []
    sqlite_dependencies: set[str] = set()
    for directory, dirs, names in os.walk(root, followlinks=False):
        for name in list(dirs):
            item = Path(directory) / name
            relative = item.relative_to(root).as_posix()
            reason = selection_reason(relative, selection, directory=True) or excluded(
                relative, kind
            )
            if item.is_symlink() or reason:
                omissions.append(
                    {"path": relative, "reason": reason or "unresolved_symlink"}
                )
                dirs.remove(name)
            elif name == "profiles" and kind in ("hermes", "codex"):
                check_profile_scope(root, relative, selection)
        for name in sorted(names):
            item = Path(directory) / name
            relative = safe_name(item.relative_to(root).as_posix())
            scope_reason = selection_reason(relative, selection, directory=False)
            reason = scope_reason or excluded(relative, kind)
            info = item.lstat()
            if relative in sqlite_dependencies:
                if (scope_reason or "").startswith("owner_selected_omission:"):
                    raise ExportError("sqlite_sidecar_conflicts_with_context_selection")
                if not stat.S_ISREG(info.st_mode):
                    raise ExportError("sqlite_sidecar_dependency_must_be_regular")
                reason = "sqlite_sidecar_requires_verified_database_snapshot"
            if reason or not stat.S_ISREG(info.st_mode):
                omissions.append(
                    {
                        "path": relative,
                        "reason": reason
                        or (
                            "unresolved_symlink"
                            if stat.S_ISLNK(info.st_mode)
                            else "unresolved_special_file"
                        ),
                    }
                )
                if (
                    stat.S_ISREG(info.st_mode)
                    and not relative.endswith("-shm")
                    and not (reason or "").startswith(
                        (
                            "owner_selected_omission:",
                            "outside_explicit_context_selection",
                        )
                    )
                ):
                    omissions[-1].update(
                        {
                            "bytes": info.st_size,
                            "mtime_ns": info.st_mtime_ns,
                            "inode": info.st_ino,
                        }
                    )
            else:
                if selection is not None:
                    with item.open("rb") as stream:
                        is_sqlite = stream.read(16) == b"SQLite format 3\x00"
                    if is_sqlite and selection["sqlite_ownership"] != "same-being":
                        raise ExportError(
                            "mixed_or_unknown_sqlite_requires_ownership_adapter"
                        )
                    if is_sqlite:
                        sqlite_dependencies.update(
                            (relative + "-wal", relative + "-shm")
                        )
                files.append(
                    {
                        "path": relative,
                        "bytes": info.st_size,
                        "mtime_ns": info.st_mtime_ns,
                        "inode": info.st_ino,
                        "mode": stat.S_IMODE(info.st_mode) & 0o111,
                    }
                )
    return sorted(files, key=lambda f: f["path"]), sorted(
        omissions, key=lambda f: f["path"]
    )


def discover(
    being: str,
    roots: list[tuple[str, Path]],
    baselines: dict[str, Path] | None = None,
    versions: dict[str, str] | None = None,
    selections: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    if not being.strip() or not roots:
        raise ExportError("being_and_sources_required")
    sources = []
    for index, (kind, root) in enumerate(roots):
        if kind not in KINDS:
            raise ExportError("unknown_source_kind")
        source_id = f"{kind}-{index + 1:03d}"
        selection = (selections or {}).get(source_id)
        if selection is not None:
            validate_selection(selection)
            for anchor in selection["include"]:
                selected = safe_path(root / anchor)
                if not selected.exists():
                    raise ExportError("selected_context_path_missing")
        files, omissions = inventory(root, kind, selection)
        sources.append(
            {
                "id": source_id,
                "kind": kind,
                "root": str(safe_path(root)),
                "version": (versions or {}).get(source_id, "unknown"),
                "baseline": str(safe_path(baselines[source_id]))
                if source_id in (baselines or {})
                else None,
                "files": files,
                "omissions": omissions,
                **({"selection": selection} if selection is not None else {}),
            }
        )
    return {
        "schema": PLAN_SCHEMA,
        "being_label": being,
        "sources": sources,
        "created_at": datetime.now(UTC).isoformat(),
        "scope": "owner-selected same-being contextual sources; no signed authority",
        "review_required": [
            "Confirm all roots belong to this being",
            "Add external memory, skills, context, sessions and projects as roots",
            "Review omissions; discovered roots do not prove complete continuity",
            "Record versions; optionally attach immutable baseline directories",
            "Quiesce all relevant writers; regenerate the plan before export",
        ],
        "external_references": [],
        "continuity_notes": "",
    }


def discover_selection(document: Any) -> dict[str, Any]:
    if (
        not isinstance(document, dict)
        or set(document) != {"schema", "being_label", "sources"}
        or document.get("schema") != SELECTION_SCHEMA
        or not isinstance(document["being_label"], str)
        or not document["being_label"].strip()
        or not isinstance(document["sources"], list)
        or not document["sources"]
    ):
        raise ExportError("supported_source_selection_required")
    roots, selections = [], {}
    for index, source in enumerate(document["sources"]):
        if (
            not isinstance(source, dict)
            or set(source) != {"kind", "root", "selection"}
            or not isinstance(source["root"], str)
        ):
            raise ExportError("source_kind_root_and_selection_required")
        kind = source["kind"]
        if kind not in KINDS:
            raise ExportError("unknown_source_kind")
        roots.append((kind, Path(source["root"])))
        selections[f"{kind}-{index + 1:03d}"] = validate_selection(source["selection"])
    return discover(document["being_label"], roots, selections=selections)


def scan_credentials(path: Path) -> None:
    overlap = b""
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            data = overlap + chunk
            if PRIVATE_KEY.search(data) or TOKEN.search(data):
                raise ExportError("embedded_credential_requires_separate_handoff")
            for match in ASSIGNMENT.finditer(data):
                if not any(
                    p in match[1].lower()
                    for p in (b"placeholder", b"example", b"redacted")
                ):
                    raise ExportError("embedded_credential_requires_separate_handoff")
            overlap = data[-4096:]


def sqlite_details(path: Path) -> dict[str, Any]:
    with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as connection:
        if connection.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
            raise ExportError("sqlite_integrity_failed_preserve_original")
        if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise ExportError("sqlite_foreign_keys_failed_preserve_original")
        schema = connection.execute(
            "SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY name"
        ).fetchall()
        counts = {}
        for kind, name, _, _ in schema:
            if kind == "table":
                quoted = name.replace('"', '""')
                counts[name] = connection.execute(
                    f'SELECT count(*) FROM "{quoted}"'
                ).fetchone()[0]
        return {
            "integrity_check": "ok",
            "foreign_key_check": "ok",
            "schema": schema,
            "table_counts": counts,
            "user_version": connection.execute("PRAGMA user_version").fetchone()[0],
        }


def copy_source(source: Path, target: Path) -> dict[str, Any] | None:
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with source.open("rb") as stream:
        is_sqlite = stream.read(16) == b"SQLite format 3\x00"
    if is_sqlite:
        incoming = sqlite3.connect(source.as_uri() + "?mode=ro", uri=True)
        outgoing = sqlite3.connect(target)
        try:
            incoming.backup(outgoing, pages=256, sleep=0.01)
        finally:
            incoming.close()
            outgoing.close()
        target.chmod(0o600)
        return sqlite_details(target)
    shutil.copyfile(source, target, follow_symlinks=False)
    target.chmod(0o600)
    return None


def nonsecret_environment(source: Path) -> tuple[bytes, list[str]]:
    """Keep useful dotenv settings and required secret names, never evaluate values."""
    settings, private_names = [], []
    for line in source.read_text().splitlines():
        match = re.match(r"\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=", line)
        if not match and line.strip() and not line.lstrip().startswith("#"):
            raise ExportError(
                "unsupported_environment_syntax_requires_separate_handoff"
            )
        if match:
            value = line[match.end() :]
            try:
                values = shlex.split(value, comments=True)
            except ValueError as error:
                raise ExportError(
                    "multiline_environment_requires_separate_handoff"
                ) from error
            if (
                len(values) > 1
                or value.lstrip().startswith("(")
                or "$(" in value
                or "<<" in value
                or "`" in value
            ):
                raise ExportError("environment_expression_requires_separate_handoff")
        if match and ENV_SECRET.search(match[1]):
            private_names.append(match[1])
            settings.append(f"# {match[1]} requires owner-private configuration")
        else:
            settings.append(line)
    return ("\n".join(settings) + "\n").encode(), private_names


def export(
    plan: dict[str, Any], output: Path, *, writers_stopped: bool
) -> dict[str, Any]:
    if plan.get("schema") != PLAN_SCHEMA or not writers_stopped:
        raise ExportError("supported_plan_and_writer_quiescence_required")
    output = safe_path(output)
    if output.exists():
        raise ExportError("existing_output_refused")
    if not (output.name.endswith((".tgz", ".tar.gz", ".zip"))):
        raise ExportError("use_tgz_or_zip")
    sources = plan["sources"]
    ids = [s["id"] for s in sources]
    if not sources or len(ids) != len(set(ids)):
        raise ExportError("unique_nonempty_sources_required")
    for source in sources:
        safe_name(source["id"])
        if "/" in source["id"] or source["kind"] not in KINDS:
            raise ExportError("invalid_source")
        root = safe_path(Path(source["root"]))
        if output == root or root in output.parents:
            raise ExportError("output_must_be_outside_sources")
        if inventory(root, source["kind"], source.get("selection")) != (
            source["files"],
            source["omissions"],
        ):
            raise ExportError("source_drift_regenerate_plan")
    with tempfile.TemporaryDirectory(
        prefix="dm-being-export-", dir=output.parent
    ) as temporary:
        stage = Path(temporary)
        entries, provenance = [], []
        for source in sources:
            root = Path(source["root"])
            baseline = (
                safe_path(Path(source["baseline"])) if source.get("baseline") else None
            )
            baseline_files, baseline_omissions = (
                inventory(baseline, source["kind"], source.get("selection"))
                if baseline
                else ([], [])
            )
            baseline_names = {f["path"] for f in baseline_files}
            actual_names = {f["path"] for f in source["files"]}
            for item in source["files"]:
                relative = safe_name(item["path"])
                original = safe_path(root / relative)
                source_hash = digest(original)
                reference = baseline / relative if baseline else None
                baseline_hash = (
                    digest(safe_path(reference))
                    if reference and relative in baseline_names
                    else None
                )
                delta = (
                    "unknown"
                    if not baseline
                    else "added"
                    if baseline_hash is None
                    else "unchanged"
                    if source_hash == baseline_hash
                    else "modified"
                )
                archive_name = f"payload/{source['id']}/{relative}"
                target = stage / archive_name
                database = copy_source(original, target)
                scan_credentials(target)
                if digest(original) != source_hash:
                    raise ExportError("source_changed_during_export")
                entries.append(
                    {
                        "path": archive_name,
                        "source_id": source["id"],
                        "relative_path": relative,
                        "kind": source["kind"],
                        "bytes": target.stat().st_size,
                        "sha256": digest(target),
                        "source_sha256": source_hash,
                        "baseline_sha256": baseline_hash,
                        "delta": "unknown" if database else delta,
                        "physical_file_delta": delta,
                        "executable": bool(item["mode"]),
                        "sqlite": database,
                    }
                )
            if inventory(root, source["kind"], source.get("selection")) != (
                source["files"],
                source["omissions"],
            ):
                raise ExportError("source_changed_during_export")
            provenance.append(
                {k: source[k] for k in ("id", "kind", "root", "version", "omissions")}
            )
            provenance[-1]["baseline_root"] = str(baseline) if baseline else None
            if source.get("selection") is not None:
                provenance[-1]["selection"] = source["selection"]
                provenance[-1]["ownership_evidence"] = (
                    "owner declaration; not inferred from labels"
                )
            provenance[-1]["baseline_omissions"] = baseline_omissions
            provenance[-1]["absent_from_source"] = sorted(baseline_names - actual_names)
            # Preserve useful behavior stored in dotenv without copying auth values.
            for omission in source["omissions"]:
                if omission[
                    "reason"
                ] != "credential_or_custody_separate_handoff" or PurePosixPath(
                    omission["path"]
                ).name not in (".env", ".envrc"):
                    continue
                environment = safe_path(root / omission["path"])
                if not environment.is_file():
                    continue
                source_hash = digest(environment)
                raw, private_names = nonsecret_environment(environment)
                relative = safe_name(omission["path"] + ".nonsecret")
                name = f"payload/{source['id']}/{relative}"
                target = stage / name
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                new_file(target, raw)
                scan_credentials(target)
                if digest(environment) != source_hash:
                    raise ExportError("source_changed_during_export")
                entries.append(
                    {
                        "path": name,
                        "source_id": source["id"],
                        "relative_path": relative,
                        "kind": source["kind"],
                        "bytes": len(raw),
                        "sha256": digest(target),
                        "source_sha256": source_hash,
                        "baseline_sha256": None,
                        "delta": "unknown",
                        "physical_file_delta": "unknown",
                        "executable": False,
                        "sqlite": None,
                        "derivation": "nonsecret_dotenv; original remains at source",
                        "private_variable_names": private_names,
                    }
                )
        for source in sources:
            if inventory(
                Path(source["root"]), source["kind"], source.get("selection")
            ) != (
                source["files"],
                source["omissions"],
            ):
                raise ExportError("source_changed_during_export")
        manifest = {
            "schema": ARCHIVE_SCHEMA,
            "being_label": plan["being_label"],
            "created_at": datetime.now(UTC).isoformat(),
            "sources": provenance,
            "files": entries,
            "writers_stopped_declared": True,
            "source_roots_unchanged": True,
            "external_references": plan.get("external_references", []),
            "continuity_notes": plan.get("continuity_notes", ""),
            "native_session_resume": "not_performed",
            "target_adoption": "not_performed",
            "secret_scan": "known patterns only; opaque content needs owner review",
            "completeness": "selected roots preserved; reconcile omitted context",
        }
        (stage / "manifest.json").write_bytes(json_bytes(manifest))
        scan_credentials(stage / "manifest.json")
        names = ["manifest.json", *[f["path"] for f in entries]]
        candidate = stage / "candidate.archive"
        if output.suffix == ".zip":
            with zipfile.ZipFile(
                candidate, "w", compression=zipfile.ZIP_DEFLATED
            ) as archive:
                for name in names:
                    archive.write(stage / name, name)
        else:
            with tarfile.open(candidate, "w:gz") as archive:
                for name in names:
                    archive.add(stage / name, name, recursive=False)
        verify(candidate)
        candidate.chmod(0o600)
        with candidate.open("rb") as incoming:
            os.fsync(incoming.fileno())
        # Atomic publication from same-filesystem staging, without replacement.
        os.link(candidate, output)
        return {
            "schema": ARCHIVE_SCHEMA,
            "files": len(entries),
            "bytes": output.stat().st_size,
            "sha256": digest(output),
            "verified": True,
            "target_adoption": "not_performed",
        }


def verify(
    archive_path: Path,
    *,
    destination: Path | None = None,
    expected_sha256: str | None = None,
    max_bytes: int = MAX_BYTES,
    max_members: int = MAX_MEMBERS,
) -> dict[str, Any]:
    archive_path = safe_path(archive_path)
    if expected_sha256 and digest(archive_path) != expected_sha256:
        raise ExportError("archive_sha256_mismatch")
    members: dict[str, Any] = {}
    is_zip = zipfile.is_zipfile(archive_path)
    opener = zipfile.ZipFile if is_zip else tarfile.open
    with opener(archive_path, "r") as archive:
        infos = archive.infolist() if is_zip else iter(archive)
        total = 0
        for info in infos:
            name = safe_name(info.filename if is_zip else info.name)
            size = info.file_size if is_zip else info.size
            regular = (
                (
                    not info.is_dir()
                    and stat.S_IFMT(info.external_attr >> 16) in (0, stat.S_IFREG)
                )
                if is_zip
                else info.isfile()
            )
            if not regular or name in members:
                raise ExportError("archive_link_special_or_duplicate_refused")
            total += size
            if len(members) >= max_members or size < 0 or total > max_bytes:
                raise ExportError("archive_resource_limit")
            members[name] = info
        if "manifest.json" not in members:
            raise ExportError("manifest_missing")

        def open_member(name: str) -> Any:
            stream = (
                archive.open(members[name])
                if is_zip
                else archive.extractfile(members[name])
            )
            if stream is None:
                raise ExportError("unreadable_member")
            return stream

        if (
            members["manifest.json"].file_size
            if is_zip
            else members["manifest.json"].size
        ) > 64 * 1024**2:
            raise ExportError("manifest_resource_limit")
        with open_member("manifest.json") as stream:
            manifest = json.load(stream)
        if manifest.get("schema") != ARCHIVE_SCHEMA:
            raise ExportError("unsupported_archive_schema")
        entries = manifest.get("files")
        if not isinstance(entries, list):
            raise ExportError("invalid_manifest_files")
        expected = {"manifest.json"}
        for entry in entries:
            name = safe_name(entry["path"])
            source_id = safe_name(entry["source_id"])
            relative = safe_name(entry["relative_path"])
            if (
                "/" in source_id
                or name != f"payload/{source_id}/{relative}"
                or name in expected
                or entry["kind"] not in KINDS
                or not isinstance(entry["bytes"], int)
                or entry["bytes"] < 0
                or not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"])
            ):
                raise ExportError("invalid_manifest_entry")
            expected.add(name)
        if expected != set(members):
            raise ExportError("archive_membership_mismatch")
        for entry in entries:
            hashed, size = hashlib.sha256(), 0
            with open_member(entry["path"]) as stream:
                while chunk := stream.read(1024 * 1024):
                    hashed.update(chunk)
                    size += len(chunk)
                    if size > entry["bytes"] or size > max_bytes:
                        raise ExportError("member_size_mismatch")
            if hashed.hexdigest() != entry["sha256"] or size != entry["bytes"]:
                raise ExportError("member_hash_or_size_mismatch")
        if destination is not None:
            destination = safe_path(destination)
            destination.mkdir(mode=0o700, parents=False, exist_ok=False)
            try:
                # Fresh staging only. Never extractall or install live configuration.
                for name in sorted(members):
                    target = destination / name
                    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                    fd = os.open(
                        target,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                        0o600,
                    )
                    with os.fdopen(fd, "wb") as outgoing, open_member(name) as incoming:
                        shutil.copyfileobj(incoming, outgoing)
                for entry in entries:
                    target = destination / entry["path"]
                    if digest(target) != entry["sha256"]:
                        raise ExportError("staged_file_hash_mismatch")
                    if entry.get("sqlite") and json_bytes(sqlite_details(target)) != (
                        json_bytes(entry["sqlite"])
                    ):
                        raise ExportError("staged_sqlite_evidence_mismatch")
                (destination / "manifest.json").chmod(0o600)
            except BaseException:
                shutil.rmtree(destination)
                raise
        return {
            "schema": ARCHIVE_SCHEMA,
            "verified": True,
            "files": len(entries),
            "sha256": digest(archive_path),
            "target_adoption": "not_performed",
        }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    discovery = commands.add_parser(
        "discover", help="Create a private source review plan"
    )
    discovery.add_argument("--being")
    discovery.add_argument(
        "--selection", type=Path, help="Reviewed source-selection JSON"
    )
    discovery.add_argument("--output", type=Path, required=True)
    for kind in KINDS:
        discovery.add_argument(f"--{kind}-root", action="append", type=Path, default=[])
    packing = commands.add_parser("export", help="Preserve reviewed same-being sources")
    packing.add_argument("--plan", type=Path)
    packing.add_argument(
        "--selection", type=Path, help="Reviewed source-selection JSON"
    )
    packing.add_argument("--being")
    packing.add_argument("--harness", choices=("hermes", "codex", "mixed"))
    packing.add_argument(
        "--source-home",
        type=Path,
        default=Path.home(),
        help="Single-being home only; multi-profile homes require --selection",
    )
    for kind in ("memory", "skills", "context", "sessions", "project"):
        packing.add_argument(f"--{kind}-root", action="append", type=Path, default=[])
    packing.add_argument("--output", type=Path, required=True)
    packing.add_argument("--writers-stopped", action="store_true")
    for command in ("verify", "unpack"):
        check = commands.add_parser(
            command, help="Verify or stage; never adopt live context"
        )
        check.add_argument("--archive", type=Path, required=True)
        check.add_argument("--sha256")
        if command == "unpack":
            check.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "discover":
            roots = [
                (kind, root) for kind in KINDS for root in getattr(args, f"{kind}_root")
            ]
            if args.selection:
                if roots or args.being:
                    raise ExportError("choose_selection_or_source_roots")
                plan = discover_selection(
                    json.loads(safe_path(args.selection).read_bytes())
                )
            else:
                if not args.being:
                    raise ExportError("being_and_sources_required")
                plan = discover(args.being, roots)
            new_file(args.output, json_bytes(plan))
            report = {
                "schema": PLAN_SCHEMA,
                "sources": len(plan["sources"]),
                "review_required": True,
            }
        elif args.command == "export":
            extra_roots = any(
                getattr(args, f"{kind}_root")
                for kind in ("memory", "skills", "context", "sessions", "project")
            )
            if args.plan:
                if args.being or args.harness or args.selection or extra_roots:
                    raise ExportError("choose_plan_or_automatic_discovery")
                plan = json.loads(safe_path(args.plan).read_bytes())
            elif args.selection:
                if args.being or args.harness or extra_roots:
                    raise ExportError("choose_selection_or_automatic_discovery")
                plan = discover_selection(
                    json.loads(safe_path(args.selection).read_bytes())
                )
            else:
                if not args.being or not args.harness:
                    raise ExportError("being_and_harness_required")
                roots = []
                for kind in ("hermes", "codex"):
                    if args.harness in (kind, "mixed"):
                        root = args.source_home / f".{kind}"
                        roots.append((kind, root))
                        # Preserve familiar relocated roots separately.
                        for leaf, category in (
                            ("agent-memory", "memory"),
                            ("skills", "skills"),
                        ):
                            linked = root / leaf
                            if linked.is_symlink():
                                roots.append((category, linked.resolve(strict=True)))
                shared = args.source_home / ".agents" / "skills"
                if shared.is_dir():
                    roots.append(("skills", shared.resolve(strict=True)))
                roots.extend(
                    (kind, root)
                    for kind in ("memory", "skills", "context", "sessions", "project")
                    for root in getattr(args, f"{kind}_root")
                )
                plan = discover(args.being, roots)
            report = export(plan, args.output, writers_stopped=args.writers_stopped)
        else:
            report = verify(
                args.archive,
                destination=getattr(args, "destination", None),
                expected_sha256=args.sha256,
            )
        print(json.dumps(report, sort_keys=True))
        return 0
    except ExportError as error:
        print(json.dumps({"ok": False, "error": str(error)}), file=sys.stderr)
        return 1
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        sqlite3.Error,
        tarfile.TarError,
        zipfile.BadZipFile,
    ):
        print(
            json.dumps(
                {
                    "ok": False,
                    "error": "export_failed; check selection, quiescence, integrity",
                }
            ),
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
