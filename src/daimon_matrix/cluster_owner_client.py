"""Explicit, authenticated local transport for Cluster-owned body observations.

No registry, custody, daemon, session or inbox is opened by this client.
"""

from __future__ import annotations

import json
import os
import socket
import stat
import struct
import time
from pathlib import Path
from typing import Any

from .cluster import validate_body_snapshot
from .codex_body import CodexBodyError
from .scopes import BodyReader

MAX_BYTES = 65536
TIMEOUT_SECONDS = 5


def _refuse() -> CodexBodyError:
    return CodexBodyError("owner_cluster_socket_rejected", retryable=True)


def _socket_identity(path: Path, owner_uid: int) -> tuple[int, int]:
    if not path.is_absolute() or any(p in {".", ".."} for p in str(path).split("/")):
        raise _refuse()
    for parent in path.parents:
        info = parent.lstat()
        sticky_root = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid not in {0, owner_uid, os.geteuid()}
            or (info.st_mode & 0o022 and not sticky_root)
        ):
            raise _refuse()
    info = path.lstat()
    if (
        not stat.S_ISSOCK(info.st_mode)
        or info.st_uid != owner_uid
        or stat.S_IMODE(info.st_mode) not in {0o600, 0o666}
        or path.parent.lstat().st_mode & 0o022
    ):
        raise _refuse()
    return info.st_dev, info.st_ino


def _remaining(connection: socket.socket, deadline: float) -> None:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise _refuse()
    connection.settimeout(remaining)


def _exact(connection: socket.socket, length: int, deadline: float) -> bytes:
    chunks = []
    while length:
        _remaining(connection, deadline)
        chunk = connection.recv(length)
        if not chunk:
            raise _refuse()
        chunks.append(chunk)
        length -= len(chunk)
    return b"".join(chunks)


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise _refuse()
        result[key] = value
    return result


def _constant(value: str) -> None:
    raise _refuse()


def cluster_owner_socket_reader(path: Path, *, owner_uid: int) -> BodyReader:
    """Require an explicit server UID; verify real peer credentials per query."""
    if (
        isinstance(owner_uid, bool)
        or not isinstance(owner_uid, int)
        or not 0 <= owner_uid < 2**32
    ):
        raise _refuse()
    if not hasattr(socket, "SO_PEERCRED"):
        raise _refuse()

    def read(
        body_ref: str, embodiment_id: str, incarnation_id: str, evaluated_at_ms: int
    ) -> dict[str, Any]:
        try:
            identity = _socket_identity(path, owner_uid)
            request = {
                "schema": "dm.cluster-owner-body-read/v1",
                "body_ref": body_ref,
                "embodiment_id": embodiment_id,
                "incarnation_id": incarnation_id,
                "evaluated_at_ms": evaluated_at_ms,
            }
            raw = json.dumps(request, separators=(",", ":"), allow_nan=False).encode()
            if not 0 < len(raw) <= MAX_BYTES:
                raise _refuse()
            deadline = time.monotonic() + TIMEOUT_SECONDS
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                _remaining(connection, deadline)
                connection.connect(str(path))
                credentials = connection.getsockopt(
                    socket.SOL_SOCKET, socket.SO_PEERCRED, 12
                )
                if struct.unpack("3I", credentials)[1] != owner_uid:
                    raise _refuse()
                if _socket_identity(path, owner_uid) != identity:
                    raise _refuse()
                _remaining(connection, deadline)
                connection.sendall(struct.pack("!I", len(raw)) + raw)
                size = struct.unpack("!I", _exact(connection, 4, deadline))[0]
                if not 0 < size <= MAX_BYTES:
                    raise _refuse()
                response = json.loads(
                    _exact(connection, size, deadline),
                    object_pairs_hook=_pairs,
                    parse_constant=_constant,
                )
            if (
                not isinstance(response, dict)
                or set(response) != {"ok", "snapshot"}
                or response["ok"] is not True
            ):
                raise _refuse()
            return validate_body_snapshot(
                response["snapshot"],
                body_ref=body_ref,
                embodiment_id=embodiment_id,
                incarnation_id=incarnation_id,
                evaluated_at_ms=evaluated_at_ms,
            )
        except (OSError, ValueError, TypeError, struct.error) as error:
            raise _refuse() from error

    return read
