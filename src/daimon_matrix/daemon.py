"""Owner-local AF_UNIX host for one Matrix embodiment runtime."""

from __future__ import annotations

import argparse
import fcntl
import http.server
import os
import secrets
import signal
import socket
import stat
import struct
import sys
import threading
import time
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from pathlib import Path
from typing import Final, cast

from .canonical import canonical_bytes
from .local_api import MAX_FRAME_BYTES, LocalApiError, decode_document, encode_frame
from .peer_transport import MAX_ENVELOPE_BYTES, PeerTransportBusy, PeerTransportError
from .runtime import HostedRuntime, RuntimeError, load_runtime

DEFAULT_TIMEOUT_SECONDS: Final = 5.0
MAX_WORKERS: Final = 8
MAX_IN_FLIGHT: Final = 16
FaultHook = Callable[[str], None]


class DaemonError(RuntimeError):
    """The local daemon cannot safely acquire or serve its state root."""


def _log(code: str) -> None:
    record = {"schema": "dm.runtime.diagnostic/v1", "code": code}
    sys.stderr.buffer.write(canonical_bytes(record) + b"\n")
    sys.stderr.buffer.flush()


def _state_root(path: Path) -> Path:
    root = Path(os.path.abspath(path))
    try:
        info = root.lstat()
    except FileNotFoundError as exception:
        raise DaemonError("state_root_missing") from exception
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise DaemonError("state_root_not_owner_only")
    return root


def acquire_lock(root: Path) -> int:
    """Acquire one non-blocking writer lock retained for process lifetime."""

    path = root / ".daimon-matrixd.lock"
    if path.is_symlink():
        raise DaemonError("runtime_lock_symlink")
    if path.exists():
        info = path.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & 0o077
        ):
            raise DaemonError("runtime_lock_not_owner_only")
    descriptor = os.open(
        path,
        os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        os.fchmod(descriptor, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _prepare_socket(path: Path) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    if (
        not stat.S_ISSOCK(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise DaemonError("unsafe_stale_socket")
    path.unlink()


def _peer_is_owner(connection: socket.socket) -> bool:
    if not hasattr(socket, "SO_PEERCRED"):
        return True
    raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
    _pid, uid, _gid = cast(tuple[int, int, int], struct.unpack("3i", raw))
    return uid == os.geteuid()


def _bind_private_socket(listener: socket.socket, path: Path) -> None:
    """Bind privately and publish only after the socket has mode 0600.

    ``bind(path)`` creates a filesystem entry before a following ``chmod`` can
    run.  Publishing a separately bound owner-only socket with ``replace``
    removes that observable permission race, including during daemon restart.
    """

    # Keep the private staging basename no longer than the public default
    # ``matrix.sock``.  AF_UNIX budgets the complete path; a longer hidden
    # basename made an otherwise valid relocated runtime fail only at bind.
    staged = path.with_name(f".s-{secrets.token_urlsafe(6)}")
    if staged.exists() or staged.is_symlink():
        raise DaemonError("socket_staging_collision")
    try:
        listener.bind(str(staged))
        os.chmod(staged, 0o600)
        listener.listen(MAX_IN_FLIGHT)
        os.replace(staged, path)
    except BaseException:
        with suppress(FileNotFoundError):
            staged.unlink()
        raise


def _receive(connection: socket.socket) -> dict[str, object]:
    header = _recv_exact(connection, 4)
    size = int.from_bytes(header, "big")
    if not 1 <= size <= MAX_FRAME_BYTES:
        raise LocalApiError("invalid_frame_size")
    body = _recv_exact(connection, size)
    timeout = connection.gettimeout()
    connection.setblocking(False)
    try:
        if connection.recv(1, socket.MSG_PEEK):
            raise LocalApiError("trailing_frame")
    except BlockingIOError:
        pass
    finally:
        connection.settimeout(timeout)
    return decode_document(body)


def _recv_exact(connection: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = connection.recv(remaining)
        if not chunk:
            raise LocalApiError("truncated_frame")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def serve_connection(
    runtime: HostedRuntime,
    connection: socket.socket,
    *,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    fault_hook: FaultHook | None = None,
) -> None:
    """Serve one bounded request; unauthenticated failures produce no oracle."""

    connection.settimeout(timeout_seconds)
    try:
        if not _peer_is_owner(connection):
            return
        request = _receive(connection)
        if fault_hook is not None:
            fault_hook("before_dispatch")
        response = runtime.service.handle(request)
        if fault_hook is not None:
            fault_hook("after_dispatch_before_write")
        connection.sendall(encode_frame(response))
    except (LocalApiError, TimeoutError, ConnectionError, OSError):
        return


class _BoundedPeerHTTPServer(http.server.ThreadingHTTPServer):
    """Reject excess connections before allocating their handler threads."""

    daemon_threads = True

    def __init__(
        self,
        server_address: tuple[str, int],
        handler: type[http.server.BaseHTTPRequestHandler],
    ) -> None:
        self._peer_slots = threading.BoundedSemaphore(MAX_IN_FLIGHT)
        super().__init__(server_address, handler)

    def process_request(
        self,
        request: socket.socket | tuple[bytes, socket.socket],
        client_address: tuple[str, int],
    ) -> None:
        if not self._peer_slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._peer_slots.release()
            raise

    def process_request_thread(
        self,
        request: socket.socket | tuple[bytes, socket.socket],
        client_address: tuple[str, int],
    ) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._peer_slots.release()


def create_peer_http_server(runtime: HostedRuntime) -> http.server.ThreadingHTTPServer:
    if runtime.peer_dispatcher is None or runtime.peer_listen is None:
        raise DaemonError("peer_transport_not_configured")
    dispatcher = runtime.peer_dispatcher

    class Handler(http.server.BaseHTTPRequestHandler):
        def setup(self) -> None:
            super().setup()
            self.connection.settimeout(DEFAULT_TIMEOUT_SECONDS)

        def _reject(self, status: int) -> None:
            self.send_response_only(status)
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()

        def do_POST(self) -> None:
            if (
                self.path != "/dm-peer/v1"
                or self.headers.get("Content-Type") != "application/vnd.daimon.peer+jcs"
            ):
                self._reject(404)
                return
            try:
                lengths = self.headers.get_all("Content-Length", failobj=[])
                size = int(lengths[0]) if len(lengths) == 1 else 0
            except ValueError:
                size = 0
            if not 1 <= size <= MAX_ENVELOPE_BYTES:
                self._reject(400)
                return
            try:
                raw = self.rfile.read(size)
            except (TimeoutError, OSError):
                return
            if len(raw) != size:
                self._reject(400)
                return
            try:
                response = dispatcher.dispatch(raw)
            except PeerTransportBusy:
                self._reject(503)
                return
            except PeerTransportError:
                self._reject(400)
                return
            self.send_response_only(200)
            self.send_header("Content-Type", "application/vnd.daimon.peer+jcs")
            self.send_header("Content-Length", str(len(response)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(response)

        def log_message(self, _format: str, *args: object) -> None:
            return

    return _BoundedPeerHTTPServer(runtime.peer_listen, Handler)


def serve_forever(
    runtime: HostedRuntime,
    *,
    stop: threading.Event | None = None,
    ready_descriptor: int | None = None,
    fault_hook: FaultHook | None = None,
) -> None:
    """Bind only after runtime verification and serve with fixed concurrency."""

    stopping = threading.Event() if stop is None else stop
    path = runtime.socket_path
    current_root = runtime.state_root.lstat()
    if (current_root.st_dev, current_root.st_ino) != runtime.state_identity:
        raise DaemonError("state_root_replaced")
    _prepare_socket(path)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    created: tuple[int, int] | None = None
    peer_server: http.server.ThreadingHTTPServer | None = None
    peer_thread: threading.Thread | None = None
    try:
        if runtime.peer_dispatcher is not None:
            peer_server = create_peer_http_server(runtime)
            peer_thread = threading.Thread(
                target=peer_server.serve_forever,
                name="daimon-matrix-peer-http",
                daemon=True,
            )
            peer_thread.start()
        _bind_private_socket(listener, path)
        info = path.lstat()
        created = (info.st_dev, info.st_ino)
        listener.settimeout(0.25)
        if ready_descriptor is not None:
            os.write(ready_descriptor, b"READY\n")
            os.close(ready_descriptor)
        _log("ready")
        slots = threading.BoundedSemaphore(MAX_IN_FLIGHT)

        def run(connection: socket.socket) -> None:
            try:
                with connection:
                    serve_connection(
                        runtime,
                        connection,
                        fault_hook=fault_hook,
                    )
            finally:
                slots.release()

        with ThreadPoolExecutor(
            max_workers=MAX_WORKERS, thread_name_prefix="daimon-matrixd"
        ) as workers:
            while not stopping.is_set():
                try:
                    connection, _ = listener.accept()
                except TimeoutError:
                    continue
                if not slots.acquire(blocking=False):
                    connection.close()
                    continue
                workers.submit(run, connection)
    finally:
        if peer_server is not None:
            peer_server.shutdown()
            peer_server.server_close()
        if peer_thread is not None:
            peer_thread.join(timeout=2)
        listener.close()
        if created is not None:
            try:
                current = path.lstat()
                if (current.st_dev, current.st_ino) == created:
                    path.unlink()
            except FileNotFoundError:
                pass
        _log("stopped")


def _password_reader(descriptor: int) -> Callable[[], bytearray]:
    used = False

    def read() -> bytearray:
        nonlocal used
        if used:
            raise RuntimeError("password_descriptor_reused")
        used = True
        try:
            value = os.read(descriptor, 4097)
        finally:
            os.close(descriptor)
        if not value or len(value) > 4096:
            raise RuntimeError("invalid_password_descriptor")
        return bytearray(value)

    return read


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--bundle", default="runtime.json")
    parser.add_argument("--password-fd", type=int, required=True)
    parser.add_argument("--ready-fd", type=int)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    lock_descriptor: int | None = None
    stopping = threading.Event()
    try:
        root = _state_root(args.state_root)
        lock_descriptor = acquire_lock(root)
        runtime = load_runtime(
            root,
            args.bundle,
            _password_reader(args.password_fd),
            clock=lambda: time.time_ns() // 1_000_000,
        )

        def request_stop(_number: int, _frame: object) -> None:
            stopping.set()

        signal.signal(signal.SIGTERM, request_stop)
        signal.signal(signal.SIGINT, request_stop)
        serve_forever(runtime, stop=stopping, ready_descriptor=args.ready_fd)
        return 0
    except Exception:
        _log("startup_refused")
        return 1
    finally:
        if lock_descriptor is not None:
            os.close(lock_descriptor)


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "DaemonError",
    "acquire_lock",
    "create_peer_http_server",
    "main",
    "serve_connection",
    "serve_forever",
]
