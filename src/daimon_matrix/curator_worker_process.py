"""Owner-only one-shot process boundary for the evidence-only curator worker."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
import time
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from .canonical import CanonicalError, canonical_bytes
from .curator_worker import (
    MAX_CONTENT_BYTES,
    CuratorWorker,
    CuratorWorkerError,
    DeepSeekHTTPS,
    DeepSeekProvider,
    validate_worker_profile,
    validate_worker_registration,
    validate_worker_task,
)
from .daemon import _password_reader, _state_root, acquire_lock
from .runtime import RuntimeError as MatrixRuntimeError
from .runtime import load_runtime

MAX_CONFIG_BYTES: Final = 512 * 1024
_FILENAME: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class CuratorProcessError(RuntimeError):
    """Stable process-boundary refusal with no path or secret disclosure."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise CuratorProcessError("curator_process_duplicate_field")
        value[key] = item
    return value


def _owner_file(root: Path, filename: str, *, maximum: int) -> bytes:
    if _FILENAME.fullmatch(filename) is None:
        raise CuratorProcessError("curator_process_filename_refused")
    root_descriptor: int | None = None
    descriptor: int | None = None
    try:
        root_descriptor = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        descriptor = os.open(
            filename,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=root_descriptor,
        )
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & 0o077
            or not 1 <= info.st_size <= maximum
        ):
            raise CuratorProcessError("curator_process_file_refused")
        chunks: list[bytes] = []
        remaining = info.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                raise CuratorProcessError("curator_process_file_truncated")
            chunks.append(chunk)
            remaining -= len(chunk)
        current = os.fstat(descriptor)
        if (current.st_dev, current.st_ino, current.st_size) != (
            info.st_dev,
            info.st_ino,
            info.st_size,
        ):
            raise CuratorProcessError("curator_process_file_replaced")
        return b"".join(chunks)
    except CuratorProcessError:
        raise
    except OSError as exception:
        raise CuratorProcessError("curator_process_file_unavailable") from exception
    finally:
        if descriptor is not None:
            with suppress(OSError):
                os.close(descriptor)
        if root_descriptor is not None:
            with suppress(OSError):
                os.close(root_descriptor)


def _document(root: Path, filename: str) -> Mapping[str, Any]:
    raw = _owner_file(root, filename, maximum=MAX_CONFIG_BYTES)
    wire = raw[:-1] if raw.endswith(b"\n") else raw
    try:
        value = json.loads(wire, object_pairs_hook=_unique_object)
        if not isinstance(value, Mapping) or canonical_bytes(value) != wire:
            raise CuratorProcessError("curator_process_document_not_canonical")
    except (CanonicalError, UnicodeDecodeError, json.JSONDecodeError) as exception:
        raise CuratorProcessError("curator_process_document_invalid") from exception
    return value


@dataclass
class _SecretReader:
    descriptor: int
    expected_handle: str
    used: bool = False
    closed: bool = False

    def __call__(self, handle: str) -> bytearray:
        if self.used or handle != self.expected_handle:
            raise CuratorWorkerError("provider_secret_unavailable", retryable=True)
        self.used = True
        try:
            value = os.read(self.descriptor, 4097)
        finally:
            os.close(self.descriptor)
            self.closed = True
        if not value or len(value) > 4096:
            secret = bytearray(value)
            for index in range(len(secret)):
                secret[index] = 0
            raise CuratorWorkerError("provider_secret_unavailable", retryable=True)
        return bytearray(value)

    def close(self) -> None:
        if not self.closed:
            with suppress(OSError):
                os.close(self.descriptor)
            self.closed = True


def _secret_reader(descriptor: int, expected_handle: str) -> _SecretReader:
    return _SecretReader(descriptor, expected_handle)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--state-root", type=Path, required=True)
    result.add_argument("--bundle", default="runtime.json")
    result.add_argument("--password-fd", type=int, required=True)
    result.add_argument("--provider-secret-fd", type=int, required=True)
    result.add_argument("--profile", default="curator-profile.json")
    result.add_argument("--registration", default="curator-registration.json")
    result.add_argument("--task", default="curator-task.json")
    result.add_argument("--content", default="curator-content.bin")
    result.add_argument("--completion-request-id", required=True)
    return result


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    lock_descriptor: int | None = None
    provider_reader: _SecretReader | None = None
    try:
        root = _state_root(args.state_root)
        lock_descriptor = acquire_lock(root)
        runtime = load_runtime(
            root,
            args.bundle,
            _password_reader(args.password_fd),
            clock=lambda: time.time_ns() // 1_000_000,
        )
        profile = validate_worker_profile(_document(root, args.profile))
        registration = validate_worker_registration(
            _document(root, args.registration), profile=profile
        )
        task = validate_worker_task(_document(root, args.task), profile=profile)
        content = _owner_file(root, args.content, maximum=MAX_CONTENT_BYTES)
        coordinator = runtime.service.curator
        if coordinator is None:
            raise CuratorProcessError("curator_process_coordinator_unavailable")
        provider_reader = _secret_reader(
            args.provider_secret_fd, registration["secret_handle"]
        )

        def resolve_content(reference: Mapping[str, Any]) -> bytes:
            if reference != task["candidate"]["content_ref"]:
                raise CuratorWorkerError("curator_worker_content_mismatch")
            return content

        worker = CuratorWorker(
            coordinator=coordinator,
            provider=DeepSeekProvider(profile, registration, DeepSeekHTTPS()),
            content_resolver=resolve_content,
            secret_resolver=provider_reader,
            clock=lambda: time.time_ns() // 1_000_000,
            sleeper=lambda milliseconds: time.sleep(milliseconds / 1000),
        )
        proposal = worker.run(task, completion_request_id=args.completion_request_id)
        sys.stdout.buffer.write(canonical_bytes(proposal) + b"\n")
        return 0
    except (CuratorProcessError, CuratorWorkerError, MatrixRuntimeError) as exception:
        code = (
            exception.code
            if isinstance(exception, CuratorWorkerError)
            else str(exception)
        )
        sys.stderr.buffer.write(
            canonical_bytes({"schema": "dm.curator-worker.diagnostic/v1", "code": code})
            + b"\n"
        )
        return 1
    except Exception:
        sys.stderr.buffer.write(
            canonical_bytes(
                {
                    "schema": "dm.curator-worker.diagnostic/v1",
                    "code": "curator_process_refused",
                }
            )
            + b"\n"
        )
        return 1
    finally:
        if provider_reader is None:
            with suppress(OSError):
                os.close(args.provider_secret_fd)
        else:
            provider_reader.close()
        if lock_descriptor is not None:
            os.close(lock_descriptor)


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["CuratorProcessError", "main", "parser"]
