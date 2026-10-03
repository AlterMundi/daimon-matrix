"""Real local IPC rejects untrusted peers, frames and stale origin evidence."""

from __future__ import annotations

import json
import os
import socket
import struct
import tempfile
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any
from unittest import mock

import pytest

from daimon_matrix import cluster_owner_client as client
from daimon_matrix.cluster import BODY_SNAPSHOT_SCHEMA
from daimon_matrix.codex_body import CodexBodyError
from daimon_matrix.codex_matrix_binding import owner_cluster_body_reader

ORIGIN = ("codex:fixture:compaii", "embodiment:fixture", "incarnation:fixture", 1000)
SNAPSHOT = dict(
    schema=BODY_SNAPSHOT_SCHEMA,
    body_ref=ORIGIN[0],
    embodiment_id=ORIGIN[1],
    incarnation_id=ORIGIN[2],
    observed_at_ms=1000,
    state="running",
    resource_fences=[],
)


def exchange(
    reply: bytes,
    *,
    setup: Callable[[Path], None] | None = None,
    write: Callable[[socket.socket], None] | None = None,
) -> Any:
    with tempfile.TemporaryDirectory(prefix="dm-client-") as directory:
        root = Path(directory)
        root.chmod(0o700)
        path = root / "reader.sock"
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(str(path))
            path.chmod(0o600)
            listener.listen(1)
            listener.settimeout(2)
            requests = []

            def serve() -> None:
                try:
                    connection, _ = listener.accept()
                    with connection:
                        connection.settimeout(2)
                        deadline = client.time.monotonic() + 2
                        size = struct.unpack(
                            "!I", client._exact(connection, 4, deadline)
                        )[0]
                        requests.append(
                            json.loads(client._exact(connection, size, deadline))
                        )
                        if write:
                            write(connection)
                        else:
                            connection.sendall(reply)
                except (OSError, CodexBodyError):
                    pass

            thread = threading.Thread(target=serve)
            thread.start()
            try:
                if setup:
                    setup(path)
                result = client.cluster_owner_socket_reader(
                    path, owner_uid=os.geteuid()
                )(*ORIGIN)
                assert requests == [
                    {
                        "schema": "dm.cluster-owner-body-read/v1",
                        "body_ref": ORIGIN[0],
                        "embodiment_id": ORIGIN[1],
                        "incarnation_id": ORIGIN[2],
                        "evaluated_at_ms": ORIGIN[3],
                    }
                ]
                return result
            finally:
                thread.join(3)
                assert not thread.is_alive()


def raw_frame(raw: bytes) -> bytes:
    return struct.pack("!I", len(raw)) + raw


def frame(value: Any) -> bytes:
    return raw_frame(json.dumps(value).encode())


def test_real_socket_snapshot_and_exact_origin() -> None:
    assert exchange(frame({"ok": True, "snapshot": SNAPSHOT})) == SNAPSHOT


@pytest.mark.parametrize(
    "response",
    [
        {"ok": False, "error": "cluster_body_read_refused"},
        {"ok": 1, "snapshot": SNAPSHOT},
        {"ok": True, "snapshot": dict(SNAPSHOT, incarnation_id="other")},
        {"ok": True, "snapshot": dict(SNAPSHOT, observed_at_ms=1001)},
        {"ok": True, "snapshot": SNAPSHOT, "extra": "refused"},
    ],
)
def test_closed_response_and_native_snapshot_refusals(response: Any) -> None:
    with pytest.raises(CodexBodyError, match="owner_cluster_socket_rejected"):
        exchange(frame(response))


@pytest.mark.parametrize(
    "raw",
    [
        struct.pack("!I", 0),
        struct.pack("!I", client.MAX_BYTES + 1),
        struct.pack("!I", 8) + b"{}",
        frame({"ok": True, "snapshot": None}),
        raw_frame(b'{"ok":1,"ok":true}'),
        raw_frame(b'{"ok":NaN,"snapshot":null}'),
    ],
)
def test_invalid_or_incomplete_frames_refuse(raw: bytes) -> None:
    with pytest.raises(CodexBodyError, match="owner_cluster_socket_rejected"):
        exchange(raw)


def test_real_peer_uid_is_verified_before_sending_request() -> None:
    # The real socket path is owned by this UID; only the pre-connect metadata
    # seam is bypassed so the actual SO_PEERCRED check must reject the server.
    with tempfile.TemporaryDirectory(prefix="dm-peer-") as directory:
        path = Path(directory) / "reader.sock"
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(str(path))
            listener.listen(1)
            with (
                mock.patch.object(client, "_socket_identity", return_value=(1, 1)),
                pytest.raises(CodexBodyError),
            ):
                client.cluster_owner_socket_reader(path, owner_uid=os.geteuid() + 1)(
                    *ORIGIN
                )
            connection, _ = listener.accept()
            with connection:
                assert connection.recv(1) == b""


def test_unsafe_socket_mode_and_alias_refuse() -> None:
    with pytest.raises(CodexBodyError):
        exchange(
            frame({"ok": True, "snapshot": SNAPSHOT}), setup=lambda p: p.chmod(0o660)
        )
    with tempfile.TemporaryDirectory(prefix="dm-alias-") as directory:
        root = Path(directory)
        alias = root / "alias"
        alias.symlink_to(root / "unused")
        with pytest.raises(CodexBodyError):
            client.cluster_owner_socket_reader(alias, owner_uid=os.geteuid())(*ORIGIN)


def test_response_deadline_cannot_be_extended_by_dripping_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(client, "TIMEOUT_SECONDS", 0.2)

    def drip(connection: socket.socket) -> None:
        connection.sendall(struct.pack("!I", client.MAX_BYTES))
        deadline = client.time.monotonic() + 0.8
        while client.time.monotonic() < deadline:
            connection.sendall(b"x")
            threading.Event().wait(0.03)

    started = client.time.monotonic()
    with pytest.raises(CodexBodyError):
        exchange(b"", write=drip)
    assert client.time.monotonic() - started < 0.6


@pytest.mark.parametrize(
    "arguments",
    [
        {},
        {"socket_path": Path("/unused")},
        {"owner_uid": 0},
        {"socket_path": Path("/unused"), "owner_uid": 0, "checkout": Path("/unused")},
        {"checkout": Path("/unused")},
    ],
)
def test_transport_selection_never_falls_back(arguments: dict[str, Any]) -> None:
    values = dict(
        checkout=None,
        state_root=None,
        socket_path=None,
        owner_uid=None,
        embodiment_id="fixture",
    )
    values.update(arguments)
    with pytest.raises(CodexBodyError):
        owner_cluster_body_reader(**values)
