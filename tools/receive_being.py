#!/usr/bin/env python3
"""Prepare preserved being context and writable memory; never activate a body.

Run from the maintained checkout with Python 3.11+. Source instructions,
sessions and configuration stay evidence. Only explicitly selected context is
prepared for the ordinary Codex installer. Native HMK runs only when requested.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import shutil
import stat
import tarfile
import zipfile
from pathlib import Path
from typing import Any

try:
    from tools import export_being as archive_tool
    from tools.install_codex_identity import fsync_directory, read_owned, render
except ModuleNotFoundError:  # Direct invocation: Python puts tools/ on sys.path.
    import export_being as archive_tool
    from install_codex_identity import fsync_directory, read_owned, render

SELECTION_SCHEMA = "dm.being-receiving-selection/v1"
PREPARATION_SCHEMA = "dm.being-receiving-preparation/v1"
NAME = re.compile(r"[a-z][a-z0-9-]{0,62}\Z")
LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._-]{0,79}\Z")


class ReceivingError(ValueError):
    """Refusals carry codes, not private contents or credentials."""


def archive_path(path: Path) -> Path:
    path = archive_tool.safe_path(path)
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > archive_tool.MAX_BYTES:
        raise ReceivingError("archive_requires_bounded_regular_file")
    return path


def manifest_from_archive(path: Path) -> dict[str, Any]:
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as incoming:
            return json.loads(incoming.read("manifest.json"))
    with tarfile.open(path, "r") as incoming:
        stream = incoming.extractfile("manifest.json")
        if stream is None:
            raise ReceivingError("manifest_missing")
        with stream:
            return json.load(stream)


def validate_manifest(manifest: dict[str, Any]) -> None:
    if not isinstance(manifest.get("being_label"), str) or not LABEL.fullmatch(
        manifest["being_label"]
    ):
        raise ReceivingError("invalid_receiving_label")
    if not isinstance(manifest.get("sources"), list):
        raise ReceivingError("source_provenance_required")


def discover(archive: Path, expected_sha256: str) -> dict[str, Any]:
    archive = archive_path(archive)
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
        raise ReceivingError("expected_archive_sha256_required")
    result = archive_tool.verify(archive, expected_sha256=expected_sha256)
    manifest = manifest_from_archive(archive)
    if archive_tool.digest(archive) != result["sha256"]:
        raise ReceivingError("archive_changed_during_discovery")
    validate_manifest(manifest)
    souls, memories, skills = [], [], []
    for entry in manifest["files"]:
        path = Path(entry["path"])
        if path.name.lower() == "soul.md":
            souls.append(entry["path"])
        if path.name == "library.db" and entry.get("sqlite"):
            memories.append(
                {
                    "name": f"store-{len(memories) + 1:03d}",
                    "path": path.parent.as_posix(),
                    "database": path.name,
                }
            )
        if path.name == "SKILL.md":
            skills.append(
                {
                    "name": f"skill-{len(skills) + 1:03d}",
                    "path": path.parent.as_posix(),
                }
            )
    return {
        "schema": SELECTION_SCHEMA,
        "being_label": manifest["being_label"],
        "memory_coverage": "owner-selected",
        "soul": souls[0] if len(souls) == 1 else None,
        "memory": memories,
        "skills": skills,
        "discovery": {
            "soul_candidates": souls,
            "archive_sha256": result["sha256"],
            "coverage_evidence": "owner declaration required; not inferred from counts",
        },
    }


def selected_entries(path: str, entries: dict[str, dict[str, Any]]) -> list[str]:
    archive_tool.safe_name(path)
    parts = path.split("/")
    if len(parts) < 2 or parts[0] != "payload":
        raise ReceivingError("selection_must_name_preserved_payload")
    selected = sorted(name for name in entries if name.startswith(path + "/"))
    if not selected:
        raise ReceivingError("selected_directory_not_in_archive")
    return selected


def validate_selection(
    selection: Any, manifest: dict[str, Any]
) -> dict[str, dict[str, Any]]:
    required = {"schema", "being_label", "memory_coverage", "soul", "memory", "skills"}
    if (
        not isinstance(selection, dict)
        or not required <= set(selection)
        or set(selection) - required - {"discovery"}
        or selection["schema"] != SELECTION_SCHEMA
    ):
        raise ReceivingError("invalid_receiving_selection")
    if selection["being_label"] != manifest["being_label"]:
        raise ReceivingError("archive_and_receiving_label_differ")
    if selection["memory_coverage"] not in ("owner-selected", "complete-authorized"):
        raise ReceivingError("explicit_memory_coverage_required")
    entries = {entry["path"]: entry for entry in manifest["files"]}
    soul = selection["soul"]
    if not isinstance(soul, str) or soul not in entries:
        raise ReceivingError("select_one_preserved_soul")
    for kind, fields in (
        ("memory", {"name", "path", "database"}),
        ("skills", {"name", "path"}),
    ):
        rows = selection[kind]
        if not isinstance(rows, list):
            raise ReceivingError("invalid_receiving_selection")
        names: set[str] = set()
        for row in rows:
            if (
                not isinstance(row, dict)
                or set(row) != fields
                or not isinstance(row["name"], str)
                or not NAME.fullmatch(row["name"])
                or row["name"] in names
                or not isinstance(row["path"], str)
            ):
                raise ReceivingError("invalid_or_duplicate_selected_package")
            names.add(row["name"])
            selected_entries(row["path"], entries)
            if kind == "memory":
                database = row["database"]
                if not isinstance(database, str) or "/" in database:
                    raise ReceivingError("invalid_memory_database_name")
                archive_tool.safe_name(database)
                entry = entries.get(f"{row['path']}/{database}")
                if not entry or not entry.get("sqlite"):
                    raise ReceivingError("memory_requires_verified_sqlite")
            elif f"{row['path']}/SKILL.md" not in entries:
                raise ReceivingError("selected_skill_requires_skill_document")
    return entries


def copy_selected(
    originals: Path, destination: Path, prefix: str, entries: dict[str, dict[str, Any]]
) -> None:
    destination.mkdir(mode=0o700)
    for name in selected_entries(prefix, entries):
        target = destination / name[len(prefix) + 1 :]
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with (originals / name).open("rb") as incoming:
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as outgoing:
                shutil.copyfileobj(incoming, outgoing)
                outgoing.flush()
                os.fsync(outgoing.fileno())
        if archive_tool.digest(target) != entries[name]["sha256"]:
            raise ReceivingError("working_copy_hash_mismatch")
        if entries[name].get("executable"):
            target.chmod(0o700)


def wrapper_bytes(python: Path, scripts: Path, memory: Path, database: str) -> bytes:
    # No shell evaluation, source dotenv, credential copying or provider call.
    return f'''"""Human-requested native HMK, bound to one working memory copy."""
import os
import sys
from pathlib import Path

if (len(sys.argv) < 2 or Path(sys.argv[1]).name != sys.argv[1]
        or not sys.argv[1].endswith(".py")):
    raise SystemExit("native_script_basename_required")
memory = {str(memory)!r}
os.environ["HMK_AGENT_MEMORY_BASE"] = memory
os.environ["HERMES_AGENT_MEMORY_BASE"] = memory
os.environ["HMK_DB_PATH"] = str(Path(memory) / {database!r})
python = {str(python)!r}
os.execv(python, [python, str(Path({str(scripts)!r}) / sys.argv[1]), *sys.argv[2:]])
'''.encode()


def prepare(
    archive: Path,
    expected_sha256: str,
    selection: dict[str, Any],
    output: Path,
    *,
    hmk_python: Path | None = None,
    hmk_scripts: Path | None = None,
    receiving_soul: Path | None = None,
    foundation: Path | None = None,
) -> dict[str, Any]:
    output = archive_tool.safe_path(output)
    archive = archive_path(archive)
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
        raise ReceivingError("expected_archive_sha256_required")
    if (hmk_python is None) != (hmk_scripts is None):
        raise ReceivingError("native_hmk_interpreter_and_scripts_required_together")
    if hmk_python is not None:
        hmk_python = hmk_python.expanduser().absolute()
        hmk_scripts = archive_tool.safe_path(hmk_scripts)
        if not hmk_python.is_file() or not (hmk_scripts / "memoryctl.py").is_file():
            raise ReceivingError("selected_native_hmk_not_installed")
    # Preserve incomplete private preparations on error; never reinitialize them.
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    preserved_archive = output / "source.archive"
    with archive.open("rb") as incoming, preserved_archive.open("xb") as outgoing:
        preserved_archive.chmod(0o600)
        shutil.copyfileobj(incoming, outgoing)
        outgoing.flush()
        os.fsync(outgoing.fileno())
    originals = output / "originals"
    archive_tool.verify(
        preserved_archive, expected_sha256=expected_sha256, destination=originals
    )
    manifest = json.loads((originals / "manifest.json").read_bytes())
    validate_manifest(manifest)
    entries = validate_selection(selection, manifest)
    for entry in manifest["files"]:
        if archive_tool.excluded(entry["relative_path"], entry["kind"]) == (
            "credential_or_custody_separate_handoff"
        ) and not (
            Path(entry["relative_path"]).name == ".env.nonsecret"
            and entry.get("derivation")
            == "nonsecret_dotenv; original remains at source"
        ):
            raise ReceivingError("credential_member_requires_separate_handoff")
        archive_tool.scan_credentials(originals / entry["path"])
    archive_tool.scan_credentials(originals / "manifest.json")
    context = output / "context"
    context.mkdir(mode=0o700)
    soul = (
        read_owned(receiving_soul)
        if receiving_soul is not None
        else (originals / selection["soul"]).read_bytes()
    )
    soul.decode("utf-8")
    archive_tool.new_file(context / "SOUL.md", soul)
    archive_tool.scan_credentials(context / "SOUL.md")
    if foundation is not None:
        archive_tool.new_file(context / "FOUNDATION.md", read_owned(foundation))
        archive_tool.scan_credentials(context / "FOUNDATION.md")
    label = selection["being_label"]
    archive_tool.new_file(
        context / "IDENTITY.md",
        (
            f"You are {label}, continuing the owner-selected identity and history.\n"
            "This preparation supplies context, not signed Matrix authority.\n"
            "Use an existing valid body binding when selected by the owner; otherwise "
            "Matrix enrollment remains pending. Never invent runtime identifiers.\n"
            "The full selected SOUL follows in the installed context. Historical "
            "AGENTS/configuration remain scoped source evidence, available in the "
            "private continuity index, not automatically installed global rules.\n"
        ).encode(),
    )
    memory_root, skill_root, commands = (
        output / "memory",
        output / "skills",
        output / "commands",
    )
    for directory in (memory_root, skill_root, commands):
        directory.mkdir(mode=0o700)
    restored, manual = [], []
    for row in selection["memory"]:
        target = memory_root / row["name"]
        copy_selected(originals, target, row["path"], entries)
        database = target / row["database"]
        evidence = archive_tool.sqlite_details(database)
        expected = entries[f"{row['path']}/{row['database']}"]["sqlite"]
        if archive_tool.json_bytes(evidence) != archive_tool.json_bytes(expected):
            raise ReceivingError("restored_memory_evidence_mismatch")
        restored.append({**row, "sqlite": evidence, "working_copy": str(target)})
        if hmk_python is not None:
            command = commands / f"hmk-{row['name']}.py"
            archive_tool.new_file(
                command, wrapper_bytes(hmk_python, hmk_scripts, target, row["database"])
            )
            manual.append(
                f"Store {row['name']}, human-requested native HMK command:\n"
                + shlex.join(
                    [
                        str(hmk_python),
                        str(command),
                        "memoryctl.py",
                        "hybrid-pack",
                        "--query",
                        "<human-requested query>",
                        "--budget",
                        "1500",
                        "--limit",
                        "5",
                    ]
                )
                + "\n"
            )
    for row in selection["skills"]:
        copy_selected(originals, skill_root / row["name"], row["path"], entries)
    index = {
        "schema": "dm.being-continuity-index/v1",
        "being_label": label,
        "archive_sha256": expected_sha256,
        "files": manifest["files"],
        "sources": manifest["sources"],
        "external_references": manifest.get("external_references", []),
        "continuity_notes": manifest.get("continuity_notes", ""),
        "originals_root": "originals",
        "native_resume": "not_imported; retain source harness origin",
        "git_history": "not_imported; originals/references retained",
    }
    archive_tool.new_file(
        output / "continuity-index.json", archive_tool.json_bytes(index)
    )
    access = (
        "Access memory only on human request. Do not prefetch on startup/turn "
        "boundaries or add timers, hooks or autonomous peer attention.\n"
        f"Portable memory coverage: {selection['memory_coverage']} "
        "(owner declaration).\n"
        "Originals and provenance remain in the private continuity-index.json.\n"
        "Working memory stores are separate writable copies; do not merge them "
        "implicitly or confuse cross-host writes with SQLite mirroring.\n"
        + "\n".join(manual)
        + ("\nNative HMK binding is not configured yet.\n" if not manual else "")
        + f"\nSelected skills are preserved under {skill_root}; enable compatible "
        "packages through the existing neutral-skill surface after review. "
        "No source scripts were executed or promoted to shared commons.\n"
    )
    archive_tool.new_file(context / "MEMORY-ACCESS.md", access.encode())
    for file in context.iterdir():
        archive_tool.scan_credentials(file)
    # Qualify the full context against the existing installer's real UTF-8,
    # NUL and instruction-size rules without reading any active Codex home.
    candidate = render(
        argparse.Namespace(
            identity_file=context / "IDENTITY.md",
            soul=context / "SOUL.md",
            foundation=context / "FOUNDATION.md" if foundation is not None else None,
            memory_access=context / "MEMORY-ACCESS.md",
            model="preparation-only",
            reasoning="medium",
            approval="on-request",
            sandbox="workspace-write",
        ),
        b"",
    )
    archive_tool.new_file(context / "AGENTS.preview.md", candidate["AGENTS.md"])
    report = {
        "schema": PREPARATION_SCHEMA,
        "archive_sha256": expected_sha256,
        "being_label": label,
        "memory_coverage": selection["memory_coverage"],
        "selection": selection,
        "memory": restored,
        "context": {
            file.name: archive_tool.digest(file) for file in sorted(context.iterdir())
        },
        "native_hmk_bound": hmk_python is not None and bool(restored),
        "memory_runtime_acceptance": "not_performed",
        "source_agency_rules": "preserved; not globally installed",
        "native_sessions": "indexed; not imported or converted",
        "git_history": "future adapter; retain source references",
        "codex_installed": False,
        "matrix_enrolled": False,
        "providers_called": False,
        "ready_for_context_install": True,
    }
    # Recursive mkdir's mode does not apply to intermediate directories.
    # Complete the private tree and durable directory entries before readiness.
    for directory in sorted(
        (path for path in output.rglob("*") if path.is_dir()), reverse=True
    ):
        directory.chmod(0o700)
        fsync_directory(directory)
    fsync_directory(output)
    archive_tool.new_file(output / "preparation.json", archive_tool.json_bytes(report))
    fsync_directory(output)
    return {
        "schema": PREPARATION_SCHEMA,
        "archive_sha256": expected_sha256,
        "prepared": True,
        "memory_stores": len(restored),
        "skills": len(selection["skills"]),
        "native_hmk_bound": report["native_hmk_bound"],
        "codex_installed": False,
        "matrix_enrolled": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("discover", "prepare"):
        sub = subparsers.add_parser(command)
        sub.add_argument("--archive", type=Path, required=True)
        sub.add_argument("--sha256", required=True)
        sub.add_argument("--output", type=Path, required=True)
        if command == "prepare":
            sub.add_argument("--selection", type=Path, required=True)
            sub.add_argument("--hmk-python", type=Path)
            sub.add_argument("--hmk-scripts", type=Path)
            sub.add_argument("--receiving-soul", type=Path)
            sub.add_argument("--foundation", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "discover":
            selection = discover(args.archive, args.sha256)
            archive_tool.new_file(args.output, archive_tool.json_bytes(selection))
            result = {"schema": SELECTION_SCHEMA, "discovered": True}
        else:
            result = prepare(
                args.archive,
                args.sha256,
                json.loads(read_owned(args.selection)),
                args.output,
                hmk_python=args.hmk_python,
                hmk_scripts=args.hmk_scripts,
                receiving_soul=args.receiving_soul,
                foundation=args.foundation,
            )
        print(json.dumps(result))
        return 0
    except (
        ValueError,
        OSError,
        KeyError,
        TypeError,
        tarfile.TarError,
        zipfile.BadZipFile,
    ):
        # Private state remains inspectable; neither source content nor paths leak.
        print(json.dumps({"prepared": False, "error": "receiving_preparation_refused"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
