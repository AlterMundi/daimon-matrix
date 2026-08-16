"""Authenticated canonical envelopes and framing for the owner-local API."""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import re
import secrets
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final, cast

from .canonical import CanonicalError, b64url, canonical_bytes, unb64url

REQUEST_SCHEMA: Final = "dm.local.request/v1"
RESPONSE_SCHEMA: Final = "dm.local.response/v1"
CAPABILITY_SCHEMA: Final = "dm.local.capability/v1"
REQUEST_DOMAIN: Final = b"daimon/local-api/request/v1\x00"
RESPONSE_DOMAIN: Final = b"daimon/local-api/response/v1\x00"
CAPABILITY_DOMAIN: Final = b"daimon/local-api/capability/v1\x00"
MAX_FRAME_BYTES: Final = 2 * 1024 * 1024
MAX_CLOCK_SKEW_MS: Final = 30_000
MAX_CAPABILITY_METHODS: Final = 128

_CLIENT_ID = re.compile(r"^[A-Za-z0-9._@:-]{1,128}$")
_METHOD = re.compile(r"^[a-z][a-z0-9.-]{0,127}$")


class LocalApiError(ValueError):
    """A local API frame, capability, or authenticated envelope is invalid."""


def _closed(value: Any, fields: set[str], error: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise LocalApiError(error)
    return value


def _uint(value: Any, error: str) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not 0 <= value <= 2**53 - 1
    ):
        raise LocalApiError(error)
    return value


def _uuid(value: Any, error: str) -> str:
    if not isinstance(value, str):
        raise LocalApiError(error)
    try:
        parsed = uuid.UUID(value)
    except ValueError as exception:
        raise LocalApiError(error) from exception
    if str(parsed) != value:
        raise LocalApiError(error)
    return value


def _hash(value: Any, error: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise LocalApiError(error)
    return value


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise LocalApiError("duplicate_json_key")
        result[key] = value
    return result


def decode_document(raw: bytes) -> dict[str, Any]:
    """Decode an exact canonical JSON object; duplicate/non-canonical bytes fail."""

    if not isinstance(raw, bytes) or not 1 <= len(raw) <= MAX_FRAME_BYTES:
        raise LocalApiError("invalid_frame_size")
    try:
        value = json.loads(raw, object_pairs_hook=_unique_object)
        if not isinstance(value, dict):
            raise LocalApiError("frame_document_not_object")
        if canonical_bytes(value) != raw:
            raise LocalApiError("noncanonical_frame")
    except (CanonicalError, UnicodeDecodeError, json.JSONDecodeError) as exception:
        raise LocalApiError("invalid_frame_json") from exception
    return value


def encode_frame(document: Mapping[str, Any]) -> bytes:
    raw = canonical_bytes(document)
    if not 1 <= len(raw) <= MAX_FRAME_BYTES:
        raise LocalApiError("invalid_frame_size")
    return len(raw).to_bytes(4, "big") + raw


def decode_frame(frame: bytes) -> dict[str, Any]:
    if not isinstance(frame, bytes) or len(frame) < 4:
        raise LocalApiError("truncated_frame")
    size = int.from_bytes(frame[:4], "big")
    if not 1 <= size <= MAX_FRAME_BYTES:
        raise LocalApiError("invalid_frame_size")
    if len(frame) != 4 + size:
        raise LocalApiError("truncated_or_trailing_frame")
    return decode_document(frame[4:])


def local_key_id(key: bytes) -> str:
    if not isinstance(key, bytes) or len(key) != 32:
        raise LocalApiError("invalid_capability_key")
    return "dm:local-key:v1:" + b64url(hashlib.sha256(key).digest())


def _capability_id(core: Mapping[str, Any]) -> str:
    return "dm:local-capability:v1:" + b64url(
        hashlib.sha256(CAPABILITY_DOMAIN + canonical_bytes(core)).digest()
    )


@dataclass(frozen=True)
class LocalCapability:
    """One purpose-limited symmetric capability loaded from protected custody."""

    descriptor: Mapping[str, Any]
    key: bytes

    @property
    def capability_id(self) -> str:
        return str(self.descriptor["capability_id"])

    @property
    def client_id(self) -> str:
        return str(self.descriptor["client_id"])

    @property
    def key_id(self) -> str:
        return str(self.descriptor["key_id"])

    @property
    def methods(self) -> tuple[str, ...]:
        return tuple(cast(Sequence[str], self.descriptor["methods"]))

    @classmethod
    def from_value(cls, value: Any, key: bytes) -> LocalCapability:
        descriptor = _closed(
            value,
            {
                "capability_id",
                "client_id",
                "key_id",
                "methods",
                "not_after_ms",
                "not_before_ms",
                "schema",
                "status",
            },
            "invalid_local_capability",
        )
        if descriptor["schema"] != CAPABILITY_SCHEMA:
            raise LocalApiError("unsupported_local_capability")
        client_id = descriptor["client_id"]
        if not isinstance(client_id, str) or _CLIENT_ID.fullmatch(client_id) is None:
            raise LocalApiError("invalid_local_capability")
        methods = descriptor["methods"]
        if (
            not isinstance(methods, list)
            or not 1 <= len(methods) <= MAX_CAPABILITY_METHODS
            or methods != sorted(set(methods))
            or any(
                not isinstance(method, str) or _METHOD.fullmatch(method) is None
                for method in methods
            )
        ):
            raise LocalApiError("invalid_local_capability")
        before = _uint(descriptor["not_before_ms"], "invalid_local_capability")
        after = _uint(descriptor["not_after_ms"], "invalid_local_capability")
        if after <= before or descriptor["status"] not in {"active", "revoked"}:
            raise LocalApiError("invalid_local_capability")
        if descriptor["key_id"] != local_key_id(key):
            raise LocalApiError("capability_key_mismatch")
        core = {
            item: copy.deepcopy(entry)
            for item, entry in descriptor.items()
            if item != "capability_id"
        }
        if descriptor["capability_id"] != _capability_id(core):
            raise LocalApiError("capability_id_mismatch")
        return cls(copy.deepcopy(dict(descriptor)), bytes(key))


def create_capability(
    key: bytes,
    *,
    client_id: str,
    methods: Sequence[str],
    not_before_ms: int,
    not_after_ms: int,
    status: str = "active",
) -> LocalCapability:
    core = {
        "schema": CAPABILITY_SCHEMA,
        "client_id": client_id,
        "key_id": local_key_id(key),
        "methods": sorted(set(methods)),
        "not_before_ms": not_before_ms,
        "not_after_ms": not_after_ms,
        "status": status,
    }
    value = {**core, "capability_id": _capability_id(core)}
    return LocalCapability.from_value(value, key)


def _request_preimage(core: Mapping[str, Any]) -> bytes:
    return REQUEST_DOMAIN + canonical_bytes(core)


def request_hash(request: Mapping[str, Any]) -> str:
    core = {
        key: copy.deepcopy(value) for key, value in request.items() if key != "auth"
    }
    return hashlib.sha256(_request_preimage(core)).hexdigest()


def create_request(
    capability: LocalCapability,
    *,
    request_id: str,
    issued_at_ms: int,
    method: str,
    params: Mapping[str, Any],
    nonce: bytes | None = None,
) -> dict[str, Any]:
    core = {
        "schema": REQUEST_SCHEMA,
        "request_id": request_id,
        "client_id": capability.client_id,
        "capability_id": capability.capability_id,
        "issued_at_ms": issued_at_ms,
        "nonce": b64url(secrets.token_bytes(16) if nonce is None else nonce),
        "method": method,
        "params": copy.deepcopy(dict(params)),
    }
    value = {
        **core,
        "auth": {
            "alg": "HMAC-SHA256",
            "key_id": capability.key_id,
            "value": b64url(
                hmac.digest(capability.key, _request_preimage(core), "sha256")
            ),
        },
    }
    authenticate_request(value, capability, now_ms=issued_at_ms)
    return value


def authenticate_request(
    value: Any,
    capability: LocalCapability,
    *,
    now_ms: int,
    allow_stale: bool = False,
) -> tuple[dict[str, Any], str]:
    """Authenticate a request. All capability/auth failures share one error."""

    try:
        request = _closed(
            value,
            {
                "auth",
                "capability_id",
                "client_id",
                "issued_at_ms",
                "method",
                "nonce",
                "params",
                "request_id",
                "schema",
            },
            "authentication_failed",
        )
        if request["schema"] != REQUEST_SCHEMA:
            raise LocalApiError("authentication_failed")
        _uuid(request["request_id"], "authentication_failed")
        issued = _uint(request["issued_at_ms"], "authentication_failed")
        _uint(now_ms, "authentication_failed")
        unb64url(request["nonce"], length=16)
        method = request["method"]
        if (
            request["client_id"] != capability.client_id
            or request["capability_id"] != capability.capability_id
            or not isinstance(method, str)
            or _METHOD.fullmatch(method) is None
            or method not in capability.methods
            or capability.descriptor["status"] != "active"
            or not capability.descriptor["not_before_ms"]
            <= issued
            < capability.descriptor["not_after_ms"]
            or not capability.descriptor["not_before_ms"]
            <= now_ms
            < capability.descriptor["not_after_ms"]
            or issued - now_ms > MAX_CLOCK_SKEW_MS
            or (not allow_stale and now_ms - issued > MAX_CLOCK_SKEW_MS)
            or not isinstance(request["params"], Mapping)
        ):
            raise LocalApiError("authentication_failed")
        auth = _closed(
            request["auth"], {"alg", "key_id", "value"}, "authentication_failed"
        )
        if auth["alg"] != "HMAC-SHA256" or auth["key_id"] != capability.key_id:
            raise LocalApiError("authentication_failed")
        signature = unb64url(auth["value"], length=32)
        core = {
            key: copy.deepcopy(item) for key, item in request.items() if key != "auth"
        }
        if not hmac.compare_digest(
            signature, hmac.digest(capability.key, _request_preimage(core), "sha256")
        ):
            raise LocalApiError("authentication_failed")
        normalized = copy.deepcopy(dict(request))
        return normalized, hashlib.sha256(_request_preimage(core)).hexdigest()
    except (
        CanonicalError,
        KeyError,
        LocalApiError,
        TypeError,
        ValueError,
    ) as exception:
        raise LocalApiError("authentication_failed") from exception


def _response_preimage(core: Mapping[str, Any]) -> bytes:
    return RESPONSE_DOMAIN + canonical_bytes(core)


def create_response(
    capability: LocalCapability,
    *,
    request_id: str,
    request_digest: str,
    server: Mapping[str, str],
    completed_at_ms: int,
    result: Mapping[str, Any] | None = None,
    error: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if (result is None) == (error is None):
        raise LocalApiError("response_requires_result_xor_error")
    core = {
        "schema": RESPONSE_SCHEMA,
        "request_id": request_id,
        "request_hash": request_digest,
        "server": copy.deepcopy(dict(server)),
        "completed_at_ms": completed_at_ms,
        "ok": error is None,
        "result": None if result is None else copy.deepcopy(dict(result)),
        "error": None if error is None else copy.deepcopy(dict(error)),
    }
    response = {
        **core,
        "auth": {
            "alg": "HMAC-SHA256",
            "key_id": capability.key_id,
            "value": b64url(
                hmac.digest(capability.key, _response_preimage(core), "sha256")
            ),
        },
    }
    verify_response(
        response,
        capability,
        expected_request_id=request_id,
        expected_request_hash=request_digest,
        expected_server=server,
    )
    return response


def verify_response(
    value: Any,
    capability: LocalCapability,
    *,
    expected_request_id: str,
    expected_request_hash: str,
    expected_server: Mapping[str, str],
) -> dict[str, Any]:
    response = _closed(
        value,
        {
            "auth",
            "completed_at_ms",
            "error",
            "ok",
            "request_hash",
            "request_id",
            "result",
            "schema",
            "server",
        },
        "invalid_local_response",
    )
    if response["schema"] != RESPONSE_SCHEMA:
        raise LocalApiError("invalid_local_response")
    _uuid(response["request_id"], "invalid_local_response")
    _hash(response["request_hash"], "invalid_local_response")
    _uint(response["completed_at_ms"], "invalid_local_response")
    if (
        response["request_id"] != expected_request_id
        or response["request_hash"] != expected_request_hash
        or response["server"] != expected_server
        or not isinstance(response["ok"], bool)
        or not isinstance(response["server"], Mapping)
        or (response["result"] is None) == (response["error"] is None)
        or (
            response["result"] is not None
            and not isinstance(response["result"], Mapping)
        )
        or (
            response["error"] is not None and not isinstance(response["error"], Mapping)
        )
        or response["ok"] != (response["error"] is None)
    ):
        raise LocalApiError("invalid_local_response")
    auth = _closed(
        response["auth"], {"alg", "key_id", "value"}, "invalid_local_response"
    )
    if auth["alg"] != "HMAC-SHA256" or auth["key_id"] != capability.key_id:
        raise LocalApiError("invalid_local_response")
    core = {key: copy.deepcopy(item) for key, item in response.items() if key != "auth"}
    try:
        signature = unb64url(auth["value"], length=32)
    except CanonicalError as exception:
        raise LocalApiError("invalid_local_response") from exception
    if not hmac.compare_digest(
        signature, hmac.digest(capability.key, _response_preimage(core), "sha256")
    ):
        raise LocalApiError("invalid_local_response")
    return copy.deepcopy(dict(response))


__all__ = [
    "CAPABILITY_SCHEMA",
    "MAX_CAPABILITY_METHODS",
    "MAX_CLOCK_SKEW_MS",
    "MAX_FRAME_BYTES",
    "REQUEST_SCHEMA",
    "RESPONSE_SCHEMA",
    "LocalApiError",
    "LocalCapability",
    "authenticate_request",
    "create_capability",
    "create_request",
    "create_response",
    "decode_document",
    "decode_frame",
    "encode_frame",
    "local_key_id",
    "request_hash",
    "verify_response",
]
