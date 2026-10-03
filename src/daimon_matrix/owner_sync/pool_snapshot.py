"""Owner-private pool images. No provider, semantic transcript read or live overwrite.

Only declared memory trees and root SQLite files are copied. Historical backup
folders and transient SQLite sidecars remain at the unchanged original pool.
Caller must quiesce writers for a cross-file operational cutoff.
"""

import hashlib
import json
import os
import shutil
import sqlite3
import stat
from pathlib import Path
from typing import Any

TREES = ("state", "index", "episodes", "plans")
DATABASES = ("library.db", "sessions.db")


def digest(path: Path | str) -> str:
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def safe_ancestors(path: Path | str) -> None:
    path = Path(path)
    if not path.is_absolute():
        raise ValueError("absolute_path_required")
    for ancestor in (path, *path.parents):
        if ancestor.is_symlink():
            raise ValueError("path_symlink_refused")


def inventory(root: Path | str) -> list[Path]:
    root = Path(root)
    safe_ancestors(root)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("unsafe_pool_root")
    files = []
    for name in DATABASES:
        path = root / name
        if path.is_symlink():
            raise ValueError("pool_symlink_refused")
        if path.exists():
            files.append(path)
    for name in TREES:
        path = root / name
        if path.is_symlink():
            raise ValueError("pool_symlink_refused")
        if path.exists():
            if not path.is_dir():
                raise ValueError("pool_tree_not_directory")
            for item in path.rglob("*"):
                if item.is_symlink():
                    raise ValueError("pool_symlink_refused")
                if item.is_file():
                    files.append(item)
                elif not item.is_dir():
                    raise ValueError("pool_special_file_refused")
    if root / "library.db" not in files:
        raise ValueError("native_library_missing")
    for path in files:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("pool_special_file_refused")
    return sorted(files)


def new_directory(path: Path | str) -> Path:
    path = Path(path)
    ancestor = path.parent
    while ancestor != ancestor.parent:
        if ancestor.is_symlink():
            raise ValueError("destination_ancestor_symlink")
        ancestor = ancestor.parent
    path.mkdir(mode=0o700, parents=False, exist_ok=False)
    return path


def copy_opaque(source: Path | str, destination: Path | str) -> None:
    descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError("pool_special_file_refused")
        with (
            os.fdopen(descriptor, "rb", closefd=False) as incoming,
            Path(destination).open("xb") as outgoing,
        ):
            shutil.copyfileobj(incoming, outgoing, 1024 * 1024)
    finally:
        os.close(descriptor)
    Path(destination).chmod(0o600)


def copy_sqlite(source: Path | str, destination: Path | str) -> None:
    incoming = sqlite3.connect(Path(source).as_uri() + "?mode=ro", uri=True)
    outgoing = sqlite3.connect(destination)
    try:
        incoming.backup(outgoing)
        if outgoing.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise ValueError("snapshot_sqlite_integrity_failed")
        if outgoing.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise ValueError("snapshot_sqlite_foreign_keys_failed")
    finally:
        incoming.close()
        outgoing.close()
    Path(destination).chmod(0o600)


def snapshot_pool(source: Path | str, output: Path | str) -> str:
    source = Path(source)
    files = inventory(source)
    output = new_directory(output)
    pool = new_directory(output / "agent-memory")
    entries = []
    for original in files:
        relative = original.relative_to(source)
        target = pool / relative
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        before = original.stat()
        if str(relative) in DATABASES:
            copy_sqlite(original, target)
            kind = "consistent-sqlite"
        else:
            copy_opaque(original, target)
            after = original.stat()
            if (before.st_ino, before.st_size, before.st_mtime_ns) != (
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
            ):
                raise ValueError("pool_file_changed_during_snapshot")
            kind = "opaque-file"
        entries.append(
            {
                "path": relative.as_posix(),
                "kind": kind,
                "bytes": target.stat().st_size,
                "sha256": digest(target),
            }
        )
    manifest = {
        "schema": "compaii.private-pool-snapshot/v1",
        "files": entries,
        "source_roots_unchanged": True,
        "semantic_dialogue_read": False,
        "cross_file_cutoff_requires_writer_quiescence": True,
        "retained_at_original": "All historical backups, transient lock files and "
        "SQLite sidecars; no source moved or deleted",
    }
    raw = (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode()
    (output / "manifest.json").write_bytes(raw)
    (output / "manifest.json").chmod(0o600)
    return hashlib.sha256(raw).hexdigest()


def restore_to_new_directory(
    snapshot: Path | str, expected_manifest_sha256: str, destination: Path | str
) -> dict[str, Any]:
    snapshot = Path(snapshot)
    safe_ancestors(snapshot)
    manifest = snapshot / "manifest.json"
    if manifest.is_symlink() or digest(manifest) != expected_manifest_sha256:
        raise ValueError("snapshot_manifest_integrity_failed")
    document = json.loads(manifest.read_bytes())
    if document["schema"] != "compaii.private-pool-snapshot/v1":
        raise ValueError("unsupported_snapshot")
    names = set()
    for entry in document["files"]:
        relative = Path(entry["path"])
        if not relative.parts or relative.as_posix() != entry["path"]:
            raise ValueError("unsafe_snapshot_path")
        if not (
            relative.as_posix() in DATABASES
            or (len(relative.parts) > 1 and relative.parts[0] in TREES)
        ):
            raise ValueError("undeclared_snapshot_path")
        if (
            relative.is_absolute()
            or any(part in (".", "..") for part in relative.parts)
            or relative.as_posix() in names
        ):
            raise ValueError("unsafe_snapshot_path")
        names.add(relative.as_posix())
        source = snapshot / "agent-memory" / relative
        safe_ancestors(source)
        if (
            source.is_symlink()
            or not source.is_file()
            or digest(source) != entry["sha256"]
            or source.stat().st_size != entry["bytes"]
        ):
            raise ValueError("snapshot_artifact_integrity_failed")
    restored = new_directory(destination)
    for entry in document["files"]:
        relative = Path(entry["path"])
        target = restored / relative
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        copy_opaque(snapshot / "agent-memory" / relative, target)
        if digest(target) != entry["sha256"]:
            raise ValueError("restored_artifact_integrity_failed")
    return {
        "files": len(names),
        "restored_image_verified": True,
        "existing_destination_overwritten": False,
    }
