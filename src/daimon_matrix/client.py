"""Typed authenticated client for the owner-local DM-024 socket."""

from __future__ import annotations

import copy
import json
import os
import re
import secrets
import socket
import stat
import time
import uuid
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from .canonical import CanonicalError, canonical_bytes
from .local_api import (
    MAX_FRAME_BYTES,
    LocalApiError,
    LocalCapability,
    authenticate_request,
    create_request,
    decode_document,
    encode_frame,
    verify_response,
)
from .service import SERVICE_METHODS

CLIENT_CONFIG_SCHEMA_V3: Final = "dm.local.client-config/v3"
DEFAULT_TIMEOUT_SECONDS: Final = 5.0
Clock = Callable[[], int]
UUIDFactory = Callable[[], uuid.UUID]
NonceFactory = Callable[[int], bytes]


class ClientError(RuntimeError):
    """Local client configuration, transport, or response was rejected."""


def _closed(value: Any, fields: set[str], error: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ClientError(error)
    return value


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ClientError("duplicate_json_key")
        result[key] = value
    return result


def load_json_document(raw: bytes, *, require_object: bool = True) -> Any:
    """Load bounded human input while retaining duplicate-key rejection."""

    if not isinstance(raw, bytes) or not 1 <= len(raw) <= MAX_FRAME_BYTES:
        raise ClientError("invalid_document_size")
    try:
        value = json.loads(raw, object_pairs_hook=_unique_object)
        canonical_bytes(value)
    except (CanonicalError, UnicodeDecodeError, json.JSONDecodeError) as exception:
        raise ClientError("invalid_json_document") from exception
    if require_object and not isinstance(value, Mapping):
        raise ClientError("document_not_object")
    return copy.deepcopy(value)


def _owner_file(path: Path) -> bytes:
    try:
        before = path.lstat()
    except FileNotFoundError as exception:
        raise ClientError("client_config_missing") from exception
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_uid != os.geteuid()
        or stat.S_IMODE(before.st_mode) & 0o077
    ):
        raise ClientError("client_config_not_owner_only")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise ClientError("client_config_replaced")
        raw = _read_descriptor(descriptor, MAX_FRAME_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(raw) > MAX_FRAME_BYTES:
        raise ClientError("invalid_document_size")
    return raw


def _read_descriptor(descriptor: int, maximum: int) -> bytes:
    chunks: list[bytes] = []
    remaining = maximum
    while remaining:
        chunk = os.read(descriptor, remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def store_prepared_request(path: Path, request: Mapping[str, Any]) -> None:
    """Create one owner-only durable retry token without replacing any file."""

    target = Path(os.path.abspath(path))
    parent = target.parent
    try:
        parent_info = parent.lstat()
    except FileNotFoundError as exception:
        raise ClientError("request_store_parent_missing") from exception
    if (
        stat.S_ISLNK(parent_info.st_mode)
        or not stat.S_ISDIR(parent_info.st_mode)
        or parent_info.st_uid != os.geteuid()
        or stat.S_IMODE(parent_info.st_mode) & 0o077
    ):
        raise ClientError("request_store_parent_not_owner_only")
    raw = canonical_bytes(request)
    descriptor: int | None = None
    try:
        descriptor = os.open(
            target,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        written = 0
        while written < len(raw):
            written += os.write(descriptor, raw[written:])
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        directory = os.open(parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except FileExistsError as exception:
        raise ClientError("request_file_exists") from exception
    except OSError as exception:
        if descriptor is not None:
            with suppress(OSError):
                os.close(descriptor)
        with suppress(FileNotFoundError):
            target.unlink()
        raise ClientError("request_store_failed") from exception


def load_prepared_request(
    path: Path,
    capability: LocalCapability,
    *,
    method: str,
    params: Mapping[str, Any],
) -> dict[str, Any]:
    """Load and authenticate an exact retry token for one expected operation."""

    try:
        value = load_json_document(_owner_file(Path(os.path.abspath(path))))
        request, _ = authenticate_request(
            value,
            capability,
            now_ms=int(value["issued_at_ms"]),
        )
    except (KeyError, LocalApiError, TypeError, ValueError) as exception:
        raise ClientError("request_file_rejected") from exception
    if request["method"] != method or request["params"] != params:
        raise ClientError("request_operation_mismatch")
    return request


def read_capability_key(descriptor: int) -> bytearray:
    """Read exactly one 32-byte local capability key and close its descriptor."""

    if (
        not isinstance(descriptor, int)
        or isinstance(descriptor, bool)
        or descriptor < 0
    ):
        raise ClientError("invalid_capability_key_descriptor")
    try:
        value = _read_descriptor(descriptor, 33)
    except OSError as exception:
        raise ClientError("capability_key_unavailable") from exception
    finally:
        with suppress(OSError):
            os.close(descriptor)
    if len(value) != 32:
        raise ClientError("invalid_capability_key")
    return bytearray(value)


@dataclass(frozen=True)
class ClientConfig:
    capability: LocalCapability
    expected_server: Mapping[str, str]
    runtime_id: str
    runtime_label: str

    @classmethod
    def load(cls, path: Path, key: bytes | bytearray) -> ClientConfig:
        try:
            raw = load_json_document(_owner_file(Path(os.path.abspath(path))))
            if not isinstance(raw, Mapping):
                raise ClientError("invalid_client_config")
            if raw.get("schema") != CLIENT_CONFIG_SCHEMA_V3:
                raise ClientError("unsupported_client_config")
            value = _closed(
                raw,
                {
                    "capability",
                    "expected_server",
                    "runtime_id",
                    "runtime_label",
                    "schema",
                },
                "invalid_client_config",
            )
            server = _closed(
                value["expected_server"],
                {"body_ref", "embodiment_id", "incarnation_id", "principal_id"},
                "invalid_expected_server",
            )
            try:
                capability = LocalCapability.from_value(value["capability"], bytes(key))
            except LocalApiError as exception:
                raise ClientError("client_capability_rejected") from exception
            if any(
                not isinstance(item, str) or not 1 <= len(item.encode("utf-8")) <= 256
                for item in server.values()
            ):
                raise ClientError("invalid_expected_server")
            runtime_id = value["runtime_id"]
            runtime_label = value["runtime_label"]
            if (
                not isinstance(runtime_id, str)
                or re.fullmatch(r"dm:runtime:v1:[A-Za-z0-9_-]{43}", runtime_id) is None
                or not isinstance(runtime_label, str)
                or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", runtime_label)
                is None
            ):
                raise ClientError("invalid_client_runtime_identity")
            return cls(
                capability,
                copy.deepcopy(dict(server)),
                runtime_id,
                runtime_label,
            )
        finally:
            if isinstance(key, bytearray):
                key[:] = b"\x00" * len(key)


def _socket_is_owner_only(path: Path) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError as exception:
        raise ClientError("daemon_unavailable") from exception
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISSOCK(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o600
    ):
        raise ClientError("daemon_socket_untrusted")


def _recv_exact(connection: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = connection.recv(remaining)
        if not chunk:
            raise ClientError("daemon_response_truncated")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


@dataclass(frozen=True)
class LocalClient:
    """Closed typed client. Exact request documents are safe retry tokens."""

    socket_path: Path
    config: ClientConfig
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    clock: Clock = lambda: time.time_ns() // 1_000_000
    uuid_factory: UUIDFactory = uuid.uuid4
    nonce_factory: NonceFactory = secrets.token_bytes

    def __post_init__(self) -> None:
        if (
            not isinstance(self.timeout_seconds, (int, float))
            or isinstance(self.timeout_seconds, bool)
            or not 0.05 <= self.timeout_seconds <= 60.0
        ):
            raise ClientError("invalid_client_timeout")
        object.__setattr__(self, "socket_path", Path(os.path.abspath(self.socket_path)))

    def prepare(
        self,
        method: str,
        params: Mapping[str, Any],
        *,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        if method not in SERVICE_METHODS:
            raise ClientError("unsupported_client_method")
        return create_request(
            self.config.capability,
            request_id=str(self.uuid_factory()) if request_id is None else request_id,
            issued_at_ms=self.clock(),
            method=method,
            params=params,
            nonce=self.nonce_factory(16),
        )

    def send(self, request: Mapping[str, Any]) -> dict[str, Any]:
        """Send one exact prepared request and verify its exact authenticated reply."""

        try:
            normalized, digest = authenticate_request(
                request,
                self.config.capability,
                now_ms=int(request["issued_at_ms"]),
            )
        except (KeyError, LocalApiError, TypeError, ValueError) as exception:
            raise ClientError("client_request_rejected") from exception
        if normalized["method"] not in SERVICE_METHODS:
            raise ClientError("unsupported_client_method")
        _socket_is_owner_only(self.socket_path)
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(float(self.timeout_seconds))
                connection.connect(str(self.socket_path))
                connection.sendall(encode_frame(request))
                header = _recv_exact(connection, 4)
                size = int.from_bytes(header, "big")
                if not 1 <= size <= MAX_FRAME_BYTES:
                    raise ClientError("invalid_daemon_response_size")
                raw = _recv_exact(connection, size)
                try:
                    response = decode_document(raw)
                except LocalApiError as exception:
                    raise ClientError("daemon_response_rejected") from exception
                if connection.recv(1):
                    raise ClientError("trailing_daemon_response")
        except (TimeoutError, OSError) as exception:
            raise ClientError("daemon_unavailable") from exception
        try:
            return verify_response(
                response,
                self.config.capability,
                expected_request_id=str(normalized["request_id"]),
                expected_request_hash=digest,
                expected_server=self.config.expected_server,
            )
        except (KeyError, LocalApiError) as exception:
            raise ClientError("daemon_response_rejected") from exception

    def invoke(
        self,
        method: str,
        params: Mapping[str, Any],
        *,
        request_id: str | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        request = self.prepare(method, params, request_id=request_id)
        return request, self.send(request)

    def runtime_status(
        self, *, request_id: str | None = None
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        return self.invoke("runtime.status", {}, request_id=request_id)

    def scope_me(
        self, *, request_id: str | None = None
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        return self.invoke("scope.me", {}, request_id=request_id)

    def scope_we(
        self, *, request_id: str | None = None
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        return self.invoke("scope.we", {}, request_id=request_id)

    def scope_diff(
        self, *, request_id: str | None = None
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        return self.invoke("scope.we.diff", {}, request_id=request_id)

    def scope_sync_plan(
        self, params: Mapping[str, Any], *, request_id: str | None = None
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        return self.invoke("scope.we.sync-plan", params, request_id=request_id)

    def scope_resolve(
        self, params: Mapping[str, Any], *, request_id: str | None = None
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        return self.invoke("scope.resolve", params, request_id=request_id)

    def scope_tribe(
        self, tribe_ref: str, *, request_id: str | None = None
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        return self.invoke(
            "scope.tribe", {"tribe_ref": tribe_ref}, request_id=request_id
        )

    def memory_evaluate(
        self, params: Mapping[str, Any], *, request_id: str | None = None
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        return self.invoke("memory.evaluate", params, request_id=request_id)

    def memory_context(
        self, params: Mapping[str, Any], *, request_id: str | None = None
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        return self.invoke("memory.context", params, request_id=request_id)

    def memory_execute(
        self, params: Mapping[str, Any], *, request_id: str | None = None
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        return self.invoke("memory.execute", params, request_id=request_id)

    def curator_enqueue(
        self, item: Mapping[str, Any], *, request_id: str | None = None
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        return self.invoke("curator.enqueue", {"item": item}, request_id=request_id)

    def curator_claim(
        self, params: Mapping[str, Any], *, request_id: str | None = None
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        return self.invoke("curator.claim", params, request_id=request_id)

    def curator_complete(
        self, params: Mapping[str, Any], *, request_id: str | None = None
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        return self.invoke("curator.complete", params, request_id=request_id)

    def curator_inspect(
        self, item_id: str, *, request_id: str | None = None
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        return self.invoke(
            "curator.inspect", {"item_id": item_id}, request_id=request_id
        )

    def review_authorize(
        self, authorization: Mapping[str, Any], *, request_id: str | None = None
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        return self.invoke(
            "review.authorize",
            {"authorization": authorization},
            request_id=request_id,
        )

    def review_revoke(
        self, params: Mapping[str, Any], *, request_id: str | None = None
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        return self.invoke("review.revoke", params, request_id=request_id)

    def review_request(
        self, request: Mapping[str, Any], *, request_id: str | None = None
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        return self.invoke(
            "review.request", {"request": request}, request_id=request_id
        )

    def review_queue(
        self, params: Mapping[str, Any], *, request_id: str | None = None
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        return self.invoke("review.queue", params, request_id=request_id)

    def review_inspect(
        self, params: Mapping[str, Any], *, request_id: str | None = None
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        return self.invoke("review.inspect", params, request_id=request_id)

    def review_decision_draft(
        self, params: Mapping[str, Any], *, request_id: str | None = None
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        return self.invoke("review.decision.draft", params, request_id=request_id)

    def review_decision_submit(
        self, decision: Mapping[str, Any], *, request_id: str | None = None
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        return self.invoke(
            "review.decision.submit",
            {"decision": decision},
            request_id=request_id,
        )

    def review_execute(
        self, review_request_id: str, *, request_id: str | None = None
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        return self.invoke(
            "review.execute",
            {"review_request_id": review_request_id},
            request_id=request_id,
        )

    def we_heads(
        self, *, request_id: str | None = None
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        return self.invoke("we.heads", {}, request_id=request_id)

    def we_preview(
        self, events: list[Any], *, request_id: str | None = None
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        return self.invoke("we.preview", {"events": events}, request_id=request_id)

    def we_observe(
        self, params: Mapping[str, Any], *, request_id: str | None = None
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        return self.invoke("we.observe", params, request_id=request_id)

    def we_decide(
        self, params: Mapping[str, Any], *, request_id: str | None = None
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        return self.invoke("we.decide", params, request_id=request_id)

    def we_diff(
        self, params: Mapping[str, Any], *, request_id: str | None = None
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        return self.invoke("we.diff", params, request_id=request_id)

    def projection_get(
        self, *, request_id: str | None = None
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        return self.invoke("we.projection.get", {}, request_id=request_id)

    def projection_rebuild(
        self, *, request_id: str | None = None
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        return self.invoke("we.projection.rebuild", {}, request_id=request_id)

    def sync_request(
        self, params: Mapping[str, Any], *, request_id: str | None = None
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        return self.invoke("we.sync.request", params, request_id=request_id)

    def sync_peer_pull(
        self, params: Mapping[str, Any], *, request_id: str | None = None
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        return self.invoke("we.sync.peer-pull", params, request_id=request_id)

    def sync_serve(
        self, params: Mapping[str, Any], *, request_id: str | None = None
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        return self.invoke("we.sync.serve", params, request_id=request_id)

    def sync_pull(
        self, params: Mapping[str, Any], *, request_id: str | None = None
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        return self.invoke("we.sync.pull", params, request_id=request_id)

    def sync_validate_receipt(
        self, params: Mapping[str, Any], *, request_id: str | None = None
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        return self.invoke("we.sync.validate-receipt", params, request_id=request_id)


__all__ = [
    "CLIENT_CONFIG_SCHEMA_V3",
    "ClientConfig",
    "ClientError",
    "LocalClient",
    "load_json_document",
    "load_prepared_request",
    "read_capability_key",
    "store_prepared_request",
]
