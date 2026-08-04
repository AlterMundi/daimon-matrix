#!/usr/bin/env python3
"""Strict DM-020 sdist/wheel allowlist and metadata verifier."""

from __future__ import annotations

import argparse
import base64
import csv
import gzip
import hashlib
import io
import json
import stat
import tarfile
import zipfile
from datetime import UTC, datetime
from email import policy
from email.parser import BytesParser
from pathlib import Path, PurePosixPath
from typing import Final

NAME: Final = "daimon-matrix"
NORMALIZED: Final = "daimon_matrix"
VERSION: Final = "0.0.0"
SOURCE_DATE_EPOCH: Final = 946_684_800
SDIST_NAME: Final = f"{NORMALIZED}-{VERSION}.tar.gz"
WHEEL_NAME: Final = f"{NORMALIZED}-{VERSION}-py3-none-any.whl"
SDIST_ROOT: Final = f"{NORMALIZED}-{VERSION}"
DIST_INFO: Final = f"{NORMALIZED}-{VERSION}.dist-info"

SDIST_FILES: Final = frozenset(
    {
        ".gitignore",
        "LICENSE",
        "PKG-INFO",
        "README.md",
        "pyproject.toml",
        "src/daimon_matrix/__init__.py",
        "src/daimon_matrix/canonical.py",
        "src/daimon_matrix/identity.py",
        "src/daimon_matrix/keystore.py",
        "src/daimon_matrix/py.typed",
    }
)
WHEEL_FILES: Final = frozenset(
    {
        "daimon_matrix/__init__.py",
        "daimon_matrix/canonical.py",
        "daimon_matrix/identity.py",
        "daimon_matrix/keystore.py",
        "daimon_matrix/py.typed",
        f"{DIST_INFO}/METADATA",
        f"{DIST_INFO}/RECORD",
        f"{DIST_INFO}/WHEEL",
        f"{DIST_INFO}/licenses/LICENSE",
    }
)
FORBIDDEN_PARTS: Final = frozenset(
    {
        ".git",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "__pycache__",
        "build",
        "dist",
        "experimental_we",
        "messages",
        "runtime",
        "secrets",
        "state",
    }
)
FORBIDDEN_NAMES: Final = frozenset({".env", "credentials.json"})
FORBIDDEN_SUFFIXES: Final = (
    ".db",
    ".key",
    ".pem",
    ".pyc",
    ".pyo",
    ".sqlite",
    ".sqlite3",
    ".wal",
)
SECRET_MARKERS: Final = (
    b"-----BEGIN " + b"PRIVATE KEY-----",
    b"-----BEGIN RSA " + b"PRIVATE KEY-----",
    b"-----BEGIN EC " + b"PRIVATE KEY-----",
    b"-----BEGIN OPENSSH " + b"PRIVATE KEY-----",
    b"OPENAI_API_KEY=" + b"sk-",
    b"ANTHROPIC_API_KEY=" + b"sk-ant-",
    b"XAI_API_KEY=" + b"xai-",
    b"github_" + b"pat_",
    b"SQLite format " + b"3\x00",
)


class PackageCheckError(ValueError):
    """Raised when a distribution violates the frozen scaffold boundary."""


def sha256_bytes(data: bytes) -> str:
    """Return a lowercase SHA-256 digest."""

    return hashlib.sha256(data).hexdigest()


def _record_digest(data: bytes) -> str:
    digest = hashlib.sha256(data).digest()
    return "sha256=" + base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def validate_member(name: str, data: bytes = b"") -> PurePosixPath:
    """Reject unsafe names, private/runtime material, and secret signatures."""

    if not name or "\x00" in name or "\\" in name:
        raise PackageCheckError(f"invalid archive member name: {name!r}")
    path = PurePosixPath(name.rstrip("/"))
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise PackageCheckError(f"unsafe archive member path: {name!r}")
    if any(
        part in FORBIDDEN_PARTS
        or part.endswith(".egg-info")
        or part.startswith("experimental_")
        for part in path.parts
    ):
        raise PackageCheckError(f"forbidden archive member: {name}")
    if path.name.lower() in FORBIDDEN_NAMES:
        raise PackageCheckError(f"forbidden archive filename: {name}")
    if path.name.lower().endswith(FORBIDDEN_SUFFIXES):
        raise PackageCheckError(f"forbidden archive suffix: {name}")
    for marker in SECRET_MARKERS:
        if marker in data:
            raise PackageCheckError(f"private/runtime marker in {name}: {marker!r}")
    return path


def _assert_exact(actual: set[str], expected: frozenset[str], kind: str) -> None:
    missing = sorted(expected - actual)
    unexpected = sorted(actual - expected)
    if missing or unexpected:
        raise PackageCheckError(
            f"{kind} allowlist mismatch; missing={missing}, unexpected={unexpected}"
        )


def _check_metadata(data: bytes, source: str) -> None:
    message = BytesParser(policy=policy.default).parsebytes(data)
    if message["Name"] != NAME:
        raise PackageCheckError(f"{source}: wrong Name: {message['Name']!r}")
    if message["Version"] != VERSION:
        raise PackageCheckError(f"{source}: wrong Version: {message['Version']!r}")
    if message["Requires-Python"] != ">=3.11":
        raise PackageCheckError(
            f"{source}: wrong Requires-Python: {message['Requires-Python']!r}"
        )
    if message.get_all("Requires-Dist") != ["cryptography<47,>=46.0.7"]:
        raise PackageCheckError(f"{source}: runtime dependency contract mismatch")
    if message["License-Expression"] != "MIT":
        raise PackageCheckError(
            f"{source}: wrong License-Expression: {message['License-Expression']!r}"
        )


def inspect_sdist(path: Path, source_root: Path) -> dict[str, object]:
    """Inspect an sdist without extracting it."""

    if path.name != SDIST_NAME:
        raise PackageCheckError(f"unexpected sdist filename: {path.name}")
    raw = path.read_bytes()
    if int.from_bytes(raw[4:8], "little") != SOURCE_DATE_EPOCH:
        raise PackageCheckError("sdist gzip header does not use SOURCE_DATE_EPOCH")

    files: dict[str, bytes] = {}
    with (
        gzip.GzipFile(fileobj=io.BytesIO(raw), mode="rb") as compressed,
        tarfile.open(fileobj=compressed, mode="r:") as archive,
    ):
        for member in archive.getmembers():
            validate_member(member.name)
            if member.mtime != SOURCE_DATE_EPOCH:
                raise PackageCheckError(
                    f"sdist timestamp mismatch for {member.name}: {member.mtime}"
                )
            if member.isdir():
                continue
            if not member.isfile() or member.issym() or member.islnk():
                raise PackageCheckError(
                    f"sdist special/link member forbidden: {member.name}"
                )
            if member.mode & 0o022:
                raise PackageCheckError(f"sdist writable member: {member.name}")
            extracted = archive.extractfile(member)
            if extracted is None:
                raise PackageCheckError(f"sdist unreadable member: {member.name}")
            data = extracted.read()
            validate_member(member.name, data)
            prefix = f"{SDIST_ROOT}/"
            if not member.name.startswith(prefix):
                raise PackageCheckError(
                    f"sdist member outside single root: {member.name}"
                )
            files[member.name.removeprefix(prefix)] = data

    _assert_exact(set(files), SDIST_FILES, "sdist")
    _check_metadata(files["PKG-INFO"], "sdist PKG-INFO")
    for relative in (
        "src/daimon_matrix/__init__.py",
        "src/daimon_matrix/canonical.py",
        "src/daimon_matrix/identity.py",
        "src/daimon_matrix/keystore.py",
        "src/daimon_matrix/py.typed",
    ):
        if files[relative] != (source_root / relative).read_bytes():
            raise PackageCheckError(f"sdist source drift: {relative}")
    return {
        "filename": path.name,
        "sha256": sha256_bytes(raw),
        "size": len(raw),
        "files": sorted(files),
    }


def _zip_mode(info: zipfile.ZipInfo) -> int:
    return (info.external_attr >> 16) & 0o177777


def inspect_wheel(path: Path, source_root: Path) -> dict[str, object]:
    """Inspect a pure-Python wheel, metadata, and RECORD without extraction."""

    if path.name != WHEEL_NAME:
        raise PackageCheckError(f"unexpected wheel filename: {path.name}")
    raw = path.read_bytes()
    files: dict[str, bytes] = {}
    expected_time = datetime.fromtimestamp(SOURCE_DATE_EPOCH, UTC).timetuple()[:6]
    with zipfile.ZipFile(io.BytesIO(raw), mode="r") as archive:
        for info in archive.infolist():
            validate_member(info.filename)
            if info.flag_bits & 0x1:
                raise PackageCheckError(f"encrypted wheel member: {info.filename}")
            if info.is_dir():
                continue
            mode = _zip_mode(info)
            file_type = stat.S_IFMT(mode)
            if file_type not in {0, stat.S_IFREG}:
                raise PackageCheckError(f"wheel special/link member: {info.filename}")
            if mode & 0o022:
                raise PackageCheckError(f"wheel writable member: {info.filename}")
            if info.date_time != expected_time:
                raise PackageCheckError(
                    f"wheel timestamp mismatch for {info.filename}: {info.date_time}"
                )
            data = archive.read(info)
            validate_member(info.filename, data)
            files[info.filename] = data

    _assert_exact(set(files), WHEEL_FILES, "wheel")
    _check_metadata(files[f"{DIST_INFO}/METADATA"], "wheel METADATA")
    wheel_text = files[f"{DIST_INFO}/WHEEL"].decode("utf-8")
    if "Root-Is-Purelib: true\n" not in wheel_text:
        raise PackageCheckError("wheel is not marked purelib")
    if "Tag: py3-none-any\n" not in wheel_text:
        raise PackageCheckError("wheel does not use py3-none-any tag")

    record_name = f"{DIST_INFO}/RECORD"
    rows = list(csv.reader(io.StringIO(files[record_name].decode("utf-8"))))
    if len(rows) != len(files):
        raise PackageCheckError("wheel RECORD row count mismatch")
    seen: set[str] = set()
    for row in rows:
        if len(row) != 3 or row[0] not in files or row[0] in seen:
            raise PackageCheckError(f"invalid wheel RECORD row: {row!r}")
        seen.add(row[0])
        if row[0] == record_name:
            if row[1:] != ["", ""]:
                raise PackageCheckError("wheel RECORD self-row must omit hash and size")
        elif row[1] != _record_digest(files[row[0]]) or row[2] != str(
            len(files[row[0]])
        ):
            raise PackageCheckError(f"wheel RECORD mismatch: {row[0]}")
    if seen != set(files):
        raise PackageCheckError("wheel RECORD member set mismatch")

    source_map = {
        "daimon_matrix/__init__.py": "src/daimon_matrix/__init__.py",
        "daimon_matrix/canonical.py": "src/daimon_matrix/canonical.py",
        "daimon_matrix/identity.py": "src/daimon_matrix/identity.py",
        "daimon_matrix/keystore.py": "src/daimon_matrix/keystore.py",
        "daimon_matrix/py.typed": "src/daimon_matrix/py.typed",
    }
    for member, relative in source_map.items():
        if files[member] != (source_root / relative).read_bytes():
            raise PackageCheckError(f"wheel source drift: {member}")
    return {
        "filename": path.name,
        "sha256": sha256_bytes(raw),
        "size": len(raw),
        "files": sorted(files),
    }


def inspect_artifacts(sdist: Path, wheel: Path, source_root: Path) -> dict[str, object]:
    """Return the complete deterministic inspection report."""

    return {
        "schema": "dm-020-distribution-report/v0",
        "source_date_epoch": SOURCE_DATE_EPOCH,
        "sdist": inspect_sdist(sdist.resolve(), source_root.resolve()),
        "wheel": inspect_wheel(wheel.resolve(), source_root.resolve()),
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sdist", type=Path, required=True)
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, default=Path.cwd())
    return parser


def main() -> int:
    args = _parser().parse_args()
    report = inspect_artifacts(args.sdist, args.wheel, args.source_root)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
