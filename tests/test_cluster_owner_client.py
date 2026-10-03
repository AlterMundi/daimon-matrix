"""Real local IPC rejects untrusted peers, frames and stale origin evidence."""

from __future__ import annotations

import json
import os
import socket
import struct
import tempfile
import threading
import time
import unittest
from collections.abc import Callable
from pathlib import Path
from typing import Any
from unittest import mock

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
                        deadline = time.monotonic() + 2
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


class ClusterOwnerClientTests(unittest.TestCase):
    def test_real_socket_snapshot_and_exact_origin(self) -> None:
        self.assertEqual(exchange(frame({"ok": True, "snapshot": SNAPSHOT})), SNAPSHOT)

    def test_closed_response_and_native_snapshot_refusals(self) -> None:
        responses = [
            {"ok": False, "error": "cluster_body_read_refused"},
            {"ok": 1, "snapshot": SNAPSHOT},
            {"ok": True, "snapshot": dict(SNAPSHOT, incarnation_id="other")},
            {"ok": True, "snapshot": dict(SNAPSHOT, observed_at_ms=1001)},
            {"ok": True, "snapshot": SNAPSHOT, "extra": "refused"},
        ]
        for response in responses:
            with (
                self.subTest(response=response),
                self.assertRaisesRegex(CodexBodyError, "owner_cluster_socket_rejected"),
            ):
                exchange(frame(response))

    def test_invalid_or_incomplete_frames_refuse(self) -> None:
        frames = [
            struct.pack("!I", 0),
            struct.pack("!I", client.MAX_BYTES + 1),
            struct.pack("!I", 8) + b"{}",
            frame({"ok": True, "snapshot": None}),
            raw_frame(b'{"ok":1,"ok":true}'),
            raw_frame(b'{"ok":NaN,"snapshot":null}'),
        ]
        for raw in frames:
            with (
                self.subTest(raw=raw),
                self.assertRaisesRegex(CodexBodyError, "owner_cluster_socket_rejected"),
            ):
                exchange(raw)

    def test_real_peer_uid_is_verified_before_sending_request(self) -> None:
        # Bypass only path metadata so actual SO_PEERCRED must reject the UID.
        with tempfile.TemporaryDirectory(prefix="dm-peer-") as directory:
            path = Path(directory) / "reader.sock"
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                listener.bind(str(path))
                listener.listen(1)
                with (
                    mock.patch.object(client, "_socket_identity", return_value=(1, 1)),
                    self.assertRaises(CodexBodyError),
                ):
                    client.cluster_owner_socket_reader(
                        path, owner_uid=os.geteuid() + 1
                    )(*ORIGIN)
                connection, _ = listener.accept()
                with connection:
                    self.assertEqual(connection.recv(1), b"")

    def test_unsafe_socket_mode_and_alias_refuse(self) -> None:
        with self.assertRaises(CodexBodyError):
            exchange(
                frame({"ok": True, "snapshot": SNAPSHOT}),
                setup=lambda p: p.chmod(0o660),
            )
        with tempfile.TemporaryDirectory(prefix="dm-alias-") as directory:
            root = Path(directory)
            alias = root / "alias"
            alias.symlink_to(root / "unused")
            with self.assertRaises(CodexBodyError):
                client.cluster_owner_socket_reader(alias, owner_uid=os.geteuid())(
                    *ORIGIN
                )

    def test_response_deadline_cannot_be_extended_by_dripping_bytes(self) -> None:
        def drip(connection: socket.socket) -> None:
            connection.sendall(struct.pack("!I", client.MAX_BYTES))
            deadline = time.monotonic() + 0.8
            while time.monotonic() < deadline:
                connection.sendall(b"x")
                threading.Event().wait(0.03)

        started = time.monotonic()
        with (
            mock.patch.object(client, "TIMEOUT_SECONDS", 0.2),
            self.assertRaises(CodexBodyError),
        ):
            exchange(b"", write=drip)
        self.assertLess(time.monotonic() - started, 0.6)

    def test_transport_selection_never_falls_back(self) -> None:
        cases: list[dict[str, Any]] = [
            {},
            {"socket_path": Path("/unused")},
            {"owner_uid": 0},
            {
                "socket_path": Path("/unused"),
                "owner_uid": 0,
                "checkout": Path("/unused"),
            },
            {"checkout": Path("/unused")},
        ]
        for arguments in cases:
            values: dict[str, Any] = dict(
                checkout=None,
                state_root=None,
                socket_path=None,
                owner_uid=None,
                embodiment_id="fixture",
            )
            values.update(arguments)
            with self.subTest(arguments=arguments), self.assertRaises(CodexBodyError):
                owner_cluster_body_reader(**values)

    def test_server_uid_is_explicit_unsigned_integer(self) -> None:
        invalid_uids: list[Any] = [True, -1, 2**32, "1000", None]
        for uid in invalid_uids:
            with self.subTest(uid=uid), self.assertRaises(CodexBodyError):
                client.cluster_owner_socket_reader(Path("/unused"), owner_uid=uid)
