#!/usr/bin/env python3
"""Reject private keys, credentials, databases, and unsafe packaged paths."""

from __future__ import annotations

import argparse
import json
import stat
import sys
import tarfile
import zipfile
from collections.abc import Iterable
from pathlib import Path
from typing import Final

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.check_distribution import (
    FORBIDDEN_SUFFIXES,
    validate_member,
)

SKIP_DIRECTORIES: Final = frozenset(
    {
        ".git",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".venv",
        "__pycache__",
    }
)
SKIP_ROOT_DIRECTORIES: Final = frozenset({"build", "dist"})
MAX_FILE_SIZE: Final = 10 * 1024 * 1024


class SecretScanError(ValueError):
    """Raised when source or artifact material crosses the public boundary."""


def _scan_bytes(name: str, data: bytes) -> None:
    try:
        validate_member(name, data)
    except ValueError as error:
        raise SecretScanError(str(error)) from error


def scan_archive(path: Path) -> int:
    """Inspect every regular archive member without extracting it."""

    count = 0
    if path.name.endswith(".tar.gz"):
        with tarfile.open(path, mode="r:gz") as archive:
            for member in archive.getmembers():
                _scan_bytes(member.name, b"")
                if member.isdir():
                    continue
                if not member.isfile() or member.issym() or member.islnk():
                    raise SecretScanError(f"special/link archive member: {member.name}")
                if member.size > MAX_FILE_SIZE:
                    raise SecretScanError(f"oversized archive member: {member.name}")
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise SecretScanError(f"unreadable archive member: {member.name}")
                _scan_bytes(member.name, extracted.read(MAX_FILE_SIZE + 1))
                count += 1
    elif path.suffix == ".whl" or zipfile.is_zipfile(path):
        with zipfile.ZipFile(path, mode="r") as archive:
            for info in archive.infolist():
                _scan_bytes(info.filename, b"")
                if info.is_dir():
                    continue
                mode = (info.external_attr >> 16) & 0o177777
                file_type = stat.S_IFMT(mode)
                if file_type not in {0, stat.S_IFREG}:
                    raise SecretScanError(
                        f"special/link archive member: {info.filename}"
                    )
                if info.file_size > MAX_FILE_SIZE:
                    raise SecretScanError(f"oversized archive member: {info.filename}")
                _scan_bytes(info.filename, archive.read(info))
                count += 1
    else:
        raise SecretScanError(f"unsupported archive: {path}")
    return count


def _source_files(root: Path) -> Iterable[Path]:
    for path in sorted(root.rglob("*")):
        parts = path.relative_to(root).parts
        if any(part in SKIP_DIRECTORIES for part in parts) or (
            parts and parts[0] in SKIP_ROOT_DIRECTORIES
        ):
            continue
        if path.is_symlink():
            raise SecretScanError(f"source symlink forbidden: {path}")
        if path.is_file():
            yield path


def scan_path(path: Path) -> int:
    """Scan one source tree, regular file, or package archive."""

    path = path.resolve()
    if path.is_dir():
        count = 0
        for member in _source_files(path):
            relative = member.relative_to(path).as_posix()
            if member.stat().st_size > MAX_FILE_SIZE:
                raise SecretScanError(f"oversized source file: {relative}")
            _scan_bytes(relative, member.read_bytes())
            count += 1
        return count
    if not path.is_file() or path.is_symlink():
        raise SecretScanError(f"invalid scan target: {path}")
    if path.name.endswith(".tar.gz") or path.suffix == ".whl":
        return scan_archive(path)
    if path.name.lower().endswith(FORBIDDEN_SUFFIXES):
        raise SecretScanError(f"forbidden source suffix: {path.name}")
    if path.stat().st_size > MAX_FILE_SIZE:
        raise SecretScanError(f"oversized source file: {path.name}")
    _scan_bytes(path.name, path.read_bytes())
    return 1


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="+", type=Path)
    return parser


def main() -> int:
    args = _parser().parse_args()
    report = {str(path): scan_path(path) for path in args.paths}
    print(
        json.dumps(
            {"schema": "dm-020-secret-scan-report/v0", "files": report},
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
