"""Closed offline conformance for DM-074 Matrix body-harness profiles.

The checker never invokes a vendor model.  It admits only evidence-bound
profiles, creates a disposable isolated harness home, and drives a real local
AF_UNIX fake Matrix process through lifecycle, retry, crash, refusal, cleanup,
and replacement scenarios.  The harness is never a being authority.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import socket
import stat
import tempfile
import threading
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Final

from daimon_matrix.canonical import CanonicalError, canonical_bytes

PROFILE_SCHEMA: Final = "dm.harness-profile/v0"
FIXTURE_SCHEMA: Final = "dm.harness-adoption-fixture/v0"
REPORT_SCHEMA: Final = "dm.harness-conformance-report/v0"
REQUEST_SCHEMA: Final = "dm.harness-probe-request/v0"
RESPONSE_SCHEMA: Final = "dm.harness-probe-response/v0"
STATE_SCHEMA: Final = "dm.fake-matrix-state/v0"
PROTOCOL_VERSION: Final = "0"

REQUIRED_TOOLS: Final = (
    "daimon_status",
    "scope_me",
    "scope_we",
    "we_heads",
    "we_projection_get",
    "we_observe",
)
WRITE_TOOLS: Final = ("we_observe",)
FORBIDDEN_METHODS: Final = (
    "audience.expand",
    "deploy.effect",
    "fence.satisfy",
    "key.rotate",
    "ledger.append",
    "membership.mint",
    "memory.admit",
    "presence.satisfy",
    "root.sign",
    "source.admit",
    "species.admit",
)
MANDATORY_CONTROLS: Final = (
    "profile_isolation",
    "lifecycle_boundaries",
    "instruction_precedence_audited",
    "required_matrix_boundary",
    "tool_allowlist",
    "write_approval",
    "network_default_deny",
    "native_memory_disabled",
    "history_persistence_disabled",
    "secret_custody",
    "receipt_retry",
    "proposal_only",
    "authority_refusal",
    "lifecycle_receipts",
    "version_pinned",
    "upgrade_migration_closed",
)
LIFECYCLE: Final = (
    ("process.start", "life-process-1"),
    ("session.start", "life-session-1"),
    ("turn.start", "life-turn-1"),
    ("tool.call", "life-tool-1"),
    ("tool.receipt", "life-receipt-1"),
    ("turn.end", "life-turn-end-1"),
    ("park", "life-park-1"),
    ("wake", "life-wake-1"),
    ("crash", "life-crash-1"),
    ("resume", "life-resume-1"),
    ("session.end", "life-session-end-1"),
    ("process.end", "life-process-end-1"),
)
CONTROL_STATES: Final = frozenset({"pass", "fail", "unknown"})
EVIDENCE_STATES: Final = frozenset(
    {"documented-candidate", "synthetic-conformant", "private-smoke", "live-supported"}
)
ADMISSION_STATES: Final = frozenset({"accepted", "refused"})
MAX_DOCUMENT_BYTES: Final = 1024 * 1024
MAX_LINE_BYTES: Final = 128 * 1024


class HarnessConformanceError(RuntimeError):
    """Stable fail-closed DM-074 profile, fixture, or checker error."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _canonical(value: Any, code: str) -> bytes:
    try:
        result = canonical_bytes(value)
    except CanonicalError as exception:
        raise HarnessConformanceError(code) from exception
    if len(result) > MAX_DOCUMENT_BYTES:
        raise HarnessConformanceError("harness_document_too_large")
    return result


def _closed(value: Any, fields: set[str], code: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise HarnessConformanceError(code)
    return value


def _text(value: Any, code: str, *, maximum: int = 512) -> str:
    if not isinstance(value, str):
        raise HarnessConformanceError(code)
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exception:
        raise HarnessConformanceError(code) from exception
    if not 1 <= len(encoded) <= maximum or any(
        ord(character) < 0x20 or ord(character) == 0x7F for character in value
    ):
        raise HarnessConformanceError(code)
    return value


def _slug(value: Any, code: str, *, maximum: int) -> str:
    result = _text(value, code, maximum=maximum)
    if (
        not result[0].isalnum()
        or not result[0].isascii()
        or any(
            not (character.isascii() and (character.islower() or character.isdigit()))
            and character != "-"
            for character in result
        )
    ):
        raise HarnessConformanceError(code)
    return result


def _digest(value: Any, code: str, *, optional: bool = False) -> str | None:
    if optional and value is None:
        return None
    result = _text(value, code, maximum=64)
    if len(result) != 64 or any(
        character not in "0123456789abcdef" for character in result
    ):
        raise HarnessConformanceError(code)
    return result


def _string_list(
    value: Any, code: str, *, allow_empty: bool = False
) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise HarnessConformanceError(code)
    result = tuple(_text(item, code, maximum=1024) for item in value)
    if (
        (not allow_empty and not result)
        or len(result) != len(set(result))
        or list(result) != sorted(result)
    ):
        raise HarnessConformanceError(code)
    return result


def validate_profile(value: Any) -> Mapping[str, Any]:
    """Validate one closed evidence profile and its authority boundary."""

    profile = _closed(
        value,
        {
            "admission",
            "artifact",
            "controls",
            "evidence_state",
            "harness",
            "launch",
            "matrix_boundary",
            "overlay",
            "profile_id",
            "schema",
        },
        "invalid_harness_profile",
    )
    if profile["schema"] != PROFILE_SCHEMA:
        raise HarnessConformanceError("unsupported_harness_profile_schema")
    _slug(profile["profile_id"], "invalid_harness_profile_id", maximum=96)
    if profile["evidence_state"] not in EVIDENCE_STATES:
        raise HarnessConformanceError("invalid_harness_evidence_state")

    harness = _closed(
        profile["harness"],
        {"name", "source_refs", "surface", "vendor", "version"},
        "invalid_harness_identity",
    )
    for field in ("name", "surface", "vendor", "version"):
        _text(harness[field], "invalid_harness_identity")
    _string_list(harness["source_refs"], "invalid_harness_source_refs")

    artifact = _closed(
        profile["artifact"],
        {
            "auto_update_policy",
            "config_precedence",
            "executable_sha256",
            "install_source",
            "limitations",
            "migration_policy",
            "state_roots",
        },
        "invalid_harness_artifact",
    )
    for field in (
        "auto_update_policy",
        "config_precedence",
        "install_source",
        "migration_policy",
    ):
        _text(artifact[field], "invalid_harness_artifact", maximum=1024)
    _digest(
        artifact["executable_sha256"],
        "invalid_harness_executable_digest",
        optional=True,
    )
    _string_list(artifact["limitations"], "invalid_harness_limitations")
    _string_list(artifact["state_roots"], "invalid_harness_state_roots")

    launch = _closed(
        profile["launch"],
        {"argv", "configuration", "environment", "status"},
        "invalid_harness_launch_overlay",
    )
    if launch["status"] not in {"reference-only", "synthetic-verified"}:
        raise HarnessConformanceError("invalid_harness_launch_status")
    if not isinstance(launch["argv"], list) or not launch["argv"]:
        raise HarnessConformanceError("invalid_harness_launch_argv")
    for argument in launch["argv"]:
        _text(argument, "invalid_harness_launch_argv", maximum=1024)
    _string_list(launch["configuration"], "invalid_harness_launch_configuration")
    _string_list(launch["environment"], "invalid_harness_launch_environment")

    controls = _closed(
        profile["controls"], set(MANDATORY_CONTROLS), "invalid_harness_controls"
    )
    blocking: list[str] = []
    for name in MANDATORY_CONTROLS:
        control = _closed(
            controls[name], {"evidence", "note", "state"}, "invalid_harness_control"
        )
        if control["state"] not in CONTROL_STATES:
            raise HarnessConformanceError("invalid_harness_control_state")
        _text(control["note"], "invalid_harness_control_note", maximum=1024)
        _string_list(control["evidence"], "invalid_harness_control_evidence")
        if control["state"] != "pass":
            blocking.append(name)

    boundary = _closed(
        profile["matrix_boundary"],
        {
            "forbidden_methods",
            "harness_is_being_authority",
            "harness_memory_is_canonical",
            "matrix_revalidates_effects",
            "protocol_version",
            "required_tools",
            "server_name",
            "transport",
            "write_tools",
        },
        "invalid_harness_matrix_boundary",
    )
    if (
        boundary["harness_is_being_authority"] is not False
        or boundary["harness_memory_is_canonical"] is not False
        or boundary["matrix_revalidates_effects"] is not True
        or boundary["protocol_version"] != PROTOCOL_VERSION
        or boundary["server_name"] != "matrix"
        or boundary["transport"] != "local-inherited-descriptor"
        or tuple(boundary["required_tools"]) != REQUIRED_TOOLS
        or tuple(boundary["write_tools"]) != WRITE_TOOLS
        or tuple(boundary["forbidden_methods"]) != FORBIDDEN_METHODS
    ):
        raise HarnessConformanceError("unsafe_harness_matrix_boundary")

    overlay = _closed(
        profile["overlay"],
        {
            "cleanup_policy",
            "credential_channel",
            "effective_config_inspection",
            "history_policy",
            "home_isolation",
            "instruction_policy",
            "lifecycle_policy",
            "log_policy",
            "memory_policy",
            "network_policy",
            "retry_policy",
        },
        "invalid_harness_overlay",
    )
    for field in overlay:
        _text(overlay[field], "invalid_harness_overlay_value", maximum=1024)
    if overlay["credential_channel"] != "inherited-descriptor-only":
        raise HarnessConformanceError("unsafe_harness_credential_channel")

    admission = _closed(
        profile["admission"],
        {"expected", "reason_code", "requires_real_vendor_smoke"},
        "invalid_harness_admission",
    )
    if admission["expected"] not in ADMISSION_STATES:
        raise HarnessConformanceError("invalid_harness_admission_state")
    _slug(admission["reason_code"], "invalid_harness_admission_reason", maximum=128)
    if not isinstance(admission["requires_real_vendor_smoke"], bool):
        raise HarnessConformanceError("invalid_harness_smoke_requirement")
    expected = "accepted" if not blocking else "refused"
    if admission["expected"] != expected:
        raise HarnessConformanceError("harness_admission_evidence_mismatch")
    if profile["evidence_state"] == "documented-candidate" and expected != "refused":
        raise HarnessConformanceError("documented_candidate_cannot_be_admitted")
    if profile["evidence_state"] != "documented-candidate" and expected != "accepted":
        raise HarnessConformanceError("conformant_harness_must_be_admitted")
    if expected == "accepted" and artifact["executable_sha256"] is None:
        raise HarnessConformanceError("admitted_harness_requires_executable_digest")
    expected_launch = (
        "synthetic-verified" if expected == "accepted" else "reference-only"
    )
    if launch["status"] != expected_launch:
        raise HarnessConformanceError("harness_launch_evidence_mismatch")
    return profile


def fixture_manifest() -> Mapping[str, Any]:
    """Return the normative vendor-neutral synthetic scenario."""

    return {
        "forbidden_methods": list(FORBIDDEN_METHODS),
        "lifecycle": [
            {"event": event, "event_id": event_id} for event, event_id in LIFECYCLE
        ],
        "limits": {
            "max_document_bytes": MAX_DOCUMENT_BYTES,
            "max_line_bytes": MAX_LINE_BYTES,
        },
        "protocol_version": PROTOCOL_VERSION,
        "required_tools": list(REQUIRED_TOOLS),
        "scenarios": [
            "adapter-disable-replace-rebuild",
            "ambiguous-timeout-crash-retry",
            "authority-refusal",
            "closed-negotiation-downgrade-refusal",
            "isolated-profile-effective-config",
            "lifecycle-stable-ids-stale-resume",
            "malformed-oversized-missing-receipt",
            "native-state-disabled-and-cleanup",
            "same-id-same-bytes-and-conflict",
            "tool-surface-and-observation-only",
            "transcript-export-log-scan-cleanup",
        ],
        "schema": FIXTURE_SCHEMA,
    }


def validate_fixture(value: Any) -> Mapping[str, Any]:
    fixture = _closed(
        value,
        {
            "forbidden_methods",
            "lifecycle",
            "limits",
            "protocol_version",
            "required_tools",
            "scenarios",
            "schema",
        },
        "invalid_harness_fixture",
    )
    if (
        fixture["schema"] != FIXTURE_SCHEMA
        or fixture["protocol_version"] != PROTOCOL_VERSION
    ):
        raise HarnessConformanceError("unsupported_harness_fixture")
    if (
        tuple(fixture["required_tools"]) != REQUIRED_TOOLS
        or tuple(fixture["forbidden_methods"]) != FORBIDDEN_METHODS
    ):
        raise HarnessConformanceError("unsafe_harness_fixture_boundary")
    limits = _closed(
        fixture["limits"],
        {"max_document_bytes", "max_line_bytes"},
        "invalid_harness_fixture_limits",
    )
    if limits != {
        "max_document_bytes": MAX_DOCUMENT_BYTES,
        "max_line_bytes": MAX_LINE_BYTES,
    }:
        raise HarnessConformanceError("invalid_harness_fixture_limits")
    lifecycle = fixture["lifecycle"]
    if (
        not isinstance(lifecycle, list)
        or tuple(
            (
                _closed(item, {"event", "event_id"}, "invalid_harness_lifecycle")[
                    "event"
                ],
                item["event_id"],
            )
            for item in lifecycle
        )
        != LIFECYCLE
    ):
        raise HarnessConformanceError("invalid_harness_lifecycle")
    _string_list(fixture["scenarios"], "invalid_harness_scenarios")
    return fixture


def _load_canonical(path: Path, *, kind: str) -> Any:
    try:
        raw = path.read_bytes()
    except OSError as exception:
        raise HarnessConformanceError(f"harness_{kind}_unreadable") from exception
    if len(raw) > MAX_DOCUMENT_BYTES:
        raise HarnessConformanceError("harness_document_too_large")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exception:
        raise HarnessConformanceError(f"invalid_harness_{kind}_json") from exception
    return raw, value


def load_profile(path: Path) -> Mapping[str, Any]:
    raw, value = _load_canonical(path, kind="profile")
    profile = validate_profile(value)
    if raw != json.dumps(profile, indent=2, sort_keys=True).encode() + b"\n":
        raise HarnessConformanceError("noncanonical_harness_profile_file")
    return profile


def load_fixture(path: Path) -> Mapping[str, Any]:
    raw, value = _load_canonical(path, kind="fixture")
    fixture = validate_fixture(value)
    if raw != json.dumps(fixture, indent=2, sort_keys=True).encode() + b"\n":
        raise HarnessConformanceError("noncanonical_harness_fixture_file")
    return fixture


def _receipt(response: Mapping[str, Any]) -> str:
    return hashlib.sha256(
        b"daimon/harness-probe-response/v0\x00"
        + _canonical(response, "invalid_probe_response")
    ).hexdigest()


def _response(
    *, request_id: str, request_hash: str, ok: bool, result: Any, error: str | None
) -> Mapping[str, Any]:
    body = {
        "error": error,
        "ok": ok,
        "request_hash": request_hash,
        "request_id": request_id,
        "result": result,
        "schema": RESPONSE_SCHEMA,
    }
    return {**body, "receipt": _receipt(body)}


class _FakeMatrix:
    def __init__(
        self, socket_path: Path, state_path: Path, fixture: Mapping[str, Any]
    ) -> None:
        self.socket_path = socket_path
        self.state_path = state_path
        self.fixture = fixture
        self.stop = threading.Event()
        self.ready = threading.Event()
        self.error: BaseException | None = None
        self.thread = threading.Thread(target=self._serve_guarded, daemon=True)

    def __enter__(self) -> _FakeMatrix:
        self.thread.start()
        if not self.ready.wait(timeout=5):
            raise HarnessConformanceError("fake_matrix_start_timeout")
        return self

    def __exit__(self, *_: object) -> None:
        self.stop.set()
        with (
            socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client,
            contextlib.suppress(OSError),
        ):
            client.connect(str(self.socket_path))
        self.thread.join(timeout=5)
        if self.thread.is_alive():
            raise HarnessConformanceError("fake_matrix_stop_timeout")
        if self.error is not None:
            raise HarnessConformanceError("fake_matrix_process_error") from self.error
        with contextlib.suppress(FileNotFoundError):
            self.socket_path.unlink()

    def _serve_guarded(self) -> None:
        try:
            self._serve()
        except BaseException as exception:  # pragma: no cover - surfaced by __exit__
            self.error = exception
            self.ready.set()

    def _serve(self) -> None:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(str(self.socket_path))
            server.listen(8)
            server.settimeout(0.2)
            self.ready.set()
            while not self.stop.is_set():
                try:
                    connection, _ = server.accept()
                except TimeoutError:
                    continue
                with connection:
                    if self.stop.is_set():
                        break
                    raw = b""
                    while b"\n" not in raw and len(raw) <= MAX_LINE_BYTES:
                        chunk = connection.recv(4096)
                        if not chunk:
                            break
                        raw += chunk
                    response, drop = self._handle(raw.partition(b"\n")[0])
                    if not drop:
                        with contextlib.suppress(BrokenPipeError, ConnectionResetError):
                            connection.sendall(response + b"\n")

    def _initial_state(self) -> dict[str, Any]:
        return {
            "adapter": "initial",
            "canonical_events": [],
            "journal": {},
            "lifecycle_index": 0,
            "schema": STATE_SCHEMA,
        }

    def _load_state(self) -> dict[str, Any]:
        if not self.state_path.exists():
            return self._initial_state()
        value = json.loads(self.state_path.read_bytes())
        if not isinstance(value, dict) or value.get("schema") != STATE_SCHEMA:
            raise HarnessConformanceError("invalid_fake_matrix_state")
        return value

    def _save_state(self, state: Mapping[str, Any]) -> None:
        temporary = self.state_path.with_suffix(".tmp")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(_canonical(state, "invalid_fake_matrix_state") + b"\n")
                stream.flush()
                os.fsync(stream.fileno())
            temporary.replace(self.state_path)
        finally:
            with contextlib.suppress(FileNotFoundError):
                temporary.unlink()

    def _handle(self, raw: bytes) -> tuple[bytes, bool]:
        request_hash = hashlib.sha256(raw).hexdigest()
        if len(raw) > MAX_LINE_BYTES:
            item = _response(
                request_id="invalid",
                request_hash=request_hash,
                ok=False,
                result=None,
                error="request_too_large",
            )
            return _canonical(item, "invalid_probe_response"), False
        try:
            request = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            item = _response(
                request_id="invalid",
                request_hash=request_hash,
                ok=False,
                result=None,
                error="invalid_json",
            )
            return _canonical(item, "invalid_probe_response"), False
        try:
            item = _closed(
                request,
                {"method", "params", "request_id", "schema", "session_id", "version"},
                "invalid_probe_request",
            )
            if item["schema"] != REQUEST_SCHEMA:
                raise HarnessConformanceError("invalid_probe_schema")
            request_id = _text(item["request_id"], "invalid_probe_request_id")
            _text(item["session_id"], "invalid_probe_session_id")
            method = _text(item["method"], "invalid_probe_method")
            if not isinstance(item["params"], Mapping):
                raise HarnessConformanceError("invalid_probe_params")
            request_bytes = _canonical(request, "invalid_probe_request")
        except HarnessConformanceError as exception:
            response = _response(
                request_id="invalid",
                request_hash=request_hash,
                ok=False,
                result=None,
                error=exception.code,
            )
            return _canonical(response, "invalid_probe_response"), False

        request_hash = hashlib.sha256(request_bytes).hexdigest()
        state = self._load_state()
        journal = state["journal"]
        previous = journal.get(request_id)
        if previous is not None:
            if previous["request_hash"] == request_hash:
                return _canonical(previous["response"], "invalid_probe_response"), False
            response = _response(
                request_id=request_id,
                request_hash=request_hash,
                ok=False,
                result=None,
                error="request_conflict",
            )
            return _canonical(response, "invalid_probe_response"), False

        result, error = self._dispatch(state, method, item["params"], item["version"])
        response = _response(
            request_id=request_id,
            request_hash=request_hash,
            ok=error is None,
            result=result,
            error=error,
        )
        journal[request_id] = {"request_hash": request_hash, "response": response}
        self._save_state(state)
        drop = (
            method == "we.observe"
            and item["params"].get("simulate_response_loss") is True
        )
        return _canonical(response, "invalid_probe_response"), drop

    def _dispatch(
        self,
        state: dict[str, Any],
        method: str,
        params: Mapping[str, Any],
        version: Any,
    ) -> tuple[Any, str | None]:
        if version != PROTOCOL_VERSION:
            return None, "protocol_version_refused"
        if method == "protocol.negotiate":
            if params != {
                "capabilities": list(REQUIRED_TOOLS),
                "version": PROTOCOL_VERSION,
            }:
                return None, "capability_negotiation_refused"
            return {
                "capability_digest": hashlib.sha256(
                    _canonical(list(REQUIRED_TOOLS), "invalid_capabilities")
                ).hexdigest(),
                "version": PROTOCOL_VERSION,
            }, None
        if method == "profile.preflight":
            expected = {
                "ambient_fallback": False,
                "history": "disabled",
                "isolated": True,
                "memory": "disabled",
                "tools": list(REQUIRED_TOOLS),
            }
            if set(params) != {*expected, "config_digest"} or any(
                params[key] != value for key, value in expected.items()
            ):
                return None, "profile_preflight_refused"
            if _digest(params["config_digest"], "invalid_config_digest") is None:
                return None, "profile_preflight_refused"
            return {"config_digest": params["config_digest"], "isolated": True}, None
        if method == "tools.list":
            return {"tools": list(REQUIRED_TOOLS)}, None
        if method == "lifecycle.emit":
            if set(params) != {"event", "event_id"}:
                return None, "invalid_lifecycle_event"
            event = params["event"]
            event_id = params["event_id"]
            known = {name for name, _ in LIFECYCLE}
            if event not in known:
                return None, "unknown_lifecycle_event"
            index = state["lifecycle_index"]
            if index >= len(LIFECYCLE) or (event, event_id) != LIFECYCLE[index]:
                return None, "stale_lifecycle_event"
            state["lifecycle_index"] = index + 1
            return {"event": event, "event_id": event_id, "index": index}, None
        if method == "we.observe":
            if set(params) != {"operation_id", "simulate_response_loss", "statement"}:
                return None, "invalid_observation"
            operation_id = _text(params["operation_id"], "invalid_operation_id")
            statement = _text(params["statement"], "invalid_observation")
            if not isinstance(params["simulate_response_loss"], bool):
                return None, "invalid_observation"
            event = {"operation_id": operation_id, "statement": statement}
            if event not in state["canonical_events"]:
                state["canonical_events"].append(event)
            receipt_hash = hashlib.sha256(
                b"daimon/harness-observation/v0\x00"
                + _canonical(event, "invalid_observation")
            ).hexdigest()
            return {"adopted": False, "receipt_hash": receipt_hash}, None
        if method == "state.rebuild":
            events = state["canonical_events"]
            return {
                "canonical_digest": hashlib.sha256(
                    _canonical(events, "invalid_canonical_events")
                ).hexdigest(),
                "effect_count": len(events),
            }, None
        if method == "harness.disable":
            state["adapter"] = "disabled"
            return {"adapter": "disabled"}, None
        if method == "harness.replace":
            if params != {"successor": "synthetic-successor-v0"}:
                return None, "replacement_refused"
            state["adapter"] = "synthetic-successor-v0"
            return {"adapter": "synthetic-successor-v0"}, None
        if method == "native.state":
            return None, "native_state_disabled"
        if method in FORBIDDEN_METHODS:
            return None, "authority_refused"
        return None, "unknown_method"


def _request(
    request_id: str,
    method: str,
    params: Mapping[str, Any],
    *,
    version: str = PROTOCOL_VERSION,
) -> Mapping[str, Any]:
    return {
        "method": method,
        "params": params,
        "request_id": request_id,
        "schema": REQUEST_SCHEMA,
        "session_id": "dm074-session-1",
        "version": version,
    }


def _exchange_raw(socket_path: Path, raw: bytes) -> bytes | None:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(5)
        client.connect(str(socket_path))
        client.sendall(raw + b"\n")
        response = b""
        while b"\n" not in response and len(response) <= MAX_LINE_BYTES:
            chunk = client.recv(4096)
            if not chunk:
                break
            response += chunk
    if not response:
        return None
    return response.partition(b"\n")[0]


def _exchange(socket_path: Path, request: Mapping[str, Any]) -> bytes | None:
    return _exchange_raw(socket_path, _canonical(request, "invalid_probe_request"))


def _validated_response(raw: bytes, request: Mapping[str, Any]) -> Mapping[str, Any]:
    if len(raw) > MAX_LINE_BYTES:
        raise HarnessConformanceError("probe_response_too_large")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exception:
        raise HarnessConformanceError("invalid_probe_response_json") from exception
    response = _closed(
        value,
        {"error", "ok", "receipt", "request_hash", "request_id", "result", "schema"},
        "invalid_probe_response",
    )
    if response["schema"] != RESPONSE_SCHEMA or not isinstance(response["ok"], bool):
        raise HarnessConformanceError("invalid_probe_response")
    request_hash = hashlib.sha256(
        _canonical(request, "invalid_probe_request")
    ).hexdigest()
    if (
        response["request_id"] != request["request_id"]
        or response["request_hash"] != request_hash
    ):
        raise HarnessConformanceError("probe_response_request_mismatch")
    receipt = response["receipt"]
    body = {key: item for key, item in response.items() if key != "receipt"}
    if receipt != _receipt(body):
        raise HarnessConformanceError("invalid_probe_receipt")
    return response


def _call(
    socket_path: Path, request: Mapping[str, Any]
) -> tuple[bytes, Mapping[str, Any]]:
    raw = _exchange(socket_path, request)
    if raw is None:
        raise HarnessConformanceError("missing_probe_response")
    return raw, _validated_response(raw, request)


def _effective_config(profile: Mapping[str, Any]) -> Mapping[str, Any]:
    return {
        "ambient_fallback": False,
        "credential_channel": profile["overlay"]["credential_channel"],
        "history": "disabled",
        "memory": "disabled",
        "network": "disabled",
        "profile_id": profile["profile_id"],
        "tools": list(REQUIRED_TOOLS),
    }


def _run_synthetic(
    profile: Mapping[str, Any], fixture: Mapping[str, Any]
) -> Mapping[str, Any]:
    temporary_path: Path | None = None
    with tempfile.TemporaryDirectory(prefix="dm074-harness-") as directory:
        temporary_path = Path(directory)
        ambient = temporary_path / "ambient"
        isolated = temporary_path / "isolated"
        ambient.mkdir(mode=0o700)
        isolated.mkdir(mode=0o700)
        (ambient / "default-profile-present").write_text("trap", encoding="utf-8")
        config = _effective_config(profile)
        config_path = isolated / "effective-config.json"
        config_path.write_bytes(_canonical(config, "invalid_effective_config") + b"\n")
        config_path.chmod(0o600)
        quarantine_marker = b"dm074-private-marker-must-not-publish"
        native_outputs = tuple(
            isolated / name
            for name in ("native-export.json", "native-tool.log", "transcript.jsonl")
        )
        for output in native_outputs:
            output.write_bytes(quarantine_marker)
            output.chmod(0o600)
        native_outputs_detected = all(
            quarantine_marker in output.read_bytes() for output in native_outputs
        )
        for output in native_outputs:
            output.unlink()
        isolated_ok = (
            stat.S_IMODE(isolated.stat().st_mode) == 0o700
            and stat.S_IMODE(config_path.stat().st_mode) == 0o600
            and tuple(path.name for path in isolated.iterdir())
            == ("effective-config.json",)
            and "default-profile-present" not in config_path.read_text()
        )
        config_digest = hashlib.sha256(
            _canonical(config, "invalid_effective_config")
        ).hexdigest()
        socket_path = temporary_path / "matrix.sock"
        state_path = temporary_path / "matrix-state.json"

        with _FakeMatrix(socket_path, state_path, fixture):
            negotiate = _request(
                "req-negotiate",
                "protocol.negotiate",
                {"capabilities": list(REQUIRED_TOOLS), "version": PROTOCOL_VERSION},
            )
            _, negotiated = _call(socket_path, negotiate)
            downgrade = _request(
                "req-downgrade",
                "protocol.negotiate",
                {"capabilities": list(REQUIRED_TOOLS), "version": "-1"},
                version="-1",
            )
            _, downgraded = _call(socket_path, downgrade)
            preflight = _request(
                "req-preflight",
                "profile.preflight",
                {
                    "ambient_fallback": False,
                    "config_digest": config_digest,
                    "history": "disabled",
                    "isolated": True,
                    "memory": "disabled",
                    "tools": list(REQUIRED_TOOLS),
                },
            )
            _, preflighted = _call(socket_path, preflight)
            _, tools = _call(socket_path, _request("req-tools", "tools.list", {}))
            for index, (event, event_id) in enumerate(LIFECYCLE[:9]):
                _, lifecycle = _call(
                    socket_path,
                    _request(
                        f"req-life-{index}",
                        "lifecycle.emit",
                        {"event": event, "event_id": event_id},
                    ),
                )
                if not lifecycle["ok"]:
                    raise HarnessConformanceError("synthetic_lifecycle_failed")
            observation = _request(
                "req-observe",
                "we.observe",
                {
                    "operation_id": "dm074-inert",
                    "simulate_response_loss": True,
                    "statement": "synthetic non-adopting observation",
                },
            )
            first_lost = _exchange(socket_path, observation) is None

        with _FakeMatrix(socket_path, state_path, fixture):
            retry_raw, retried = _call(socket_path, observation)
            retry_again_raw, _ = _call(socket_path, observation)
            conflict = _request(
                "req-observe",
                "we.observe",
                {
                    "operation_id": "dm074-inert",
                    "simulate_response_loss": False,
                    "statement": "changed",
                },
            )
            _, conflicted = _call(socket_path, conflict)
            stale = _request(
                "req-stale-resume",
                "lifecycle.emit",
                {"event": "resume", "event_id": "wrong-resume"},
            )
            _, stale_result = _call(socket_path, stale)
            unknown_lifecycle = _request(
                "req-unknown-life",
                "lifecycle.emit",
                {"event": "hibernate", "event_id": "unknown"},
            )
            _, unknown_lifecycle_result = _call(socket_path, unknown_lifecycle)
            for offset, (event, event_id) in enumerate(LIFECYCLE[9:], start=9):
                _, lifecycle = _call(
                    socket_path,
                    _request(
                        f"req-life-{offset}",
                        "lifecycle.emit",
                        {"event": event, "event_id": event_id},
                    ),
                )
                if not lifecycle["ok"]:
                    raise HarnessConformanceError("synthetic_lifecycle_failed")
            refusals = []
            for index, method in enumerate(FORBIDDEN_METHODS):
                _, refused = _call(
                    socket_path,
                    _request(f"req-refuse-{index}", method, {}),
                )
                refusals.append(refused["error"] == "authority_refused")
            _, native = _call(socket_path, _request("req-native", "native.state", {}))
            _, before = _call(
                socket_path, _request("req-rebuild-1", "state.rebuild", {})
            )
            _, disabled = _call(
                socket_path, _request("req-disable", "harness.disable", {})
            )
            _, replaced = _call(
                socket_path,
                _request(
                    "req-replace",
                    "harness.replace",
                    {"successor": "synthetic-successor-v0"},
                ),
            )
            _, after = _call(
                socket_path, _request("req-rebuild-2", "state.rebuild", {})
            )

            malformed_raw = _exchange_raw(socket_path, b"{")
            malformed = json.loads(malformed_raw or b"{}")
            oversized_raw = _exchange_raw(socket_path, b"x" * (MAX_LINE_BYTES + 1))
            oversized = json.loads(oversized_raw or b"{}")

        missing_receipt_refused = False
        with contextlib.suppress(HarnessConformanceError):
            _validated_response(
                _canonical(
                    {
                        "error": None,
                        "ok": True,
                        "request_hash": "0" * 64,
                        "request_id": "missing",
                        "result": {},
                        "schema": RESPONSE_SCHEMA,
                    },
                    "invalid_probe_response",
                ),
                _request("missing", "tools.list", {}),
            )
        try:
            _validated_response(
                b"x" * (MAX_LINE_BYTES + 1), _request("large", "tools.list", {})
            )
        except HarnessConformanceError as exception:
            oversized_response_refused = exception.code == "probe_response_too_large"
        else:  # pragma: no cover - fail-closed assertion
            oversized_response_refused = False
        try:
            _validated_response(b"{}", _request("missing", "tools.list", {}))
        except HarnessConformanceError as exception:
            missing_receipt_refused = exception.code == "invalid_probe_response"

        public_probe = {
            "adapter_disable_replace_rebuild": (
                disabled["ok"]
                and replaced["ok"]
                and before["result"] == after["result"]
                and before["result"]["effect_count"] == 1
            ),
            "authority_methods_refused": all(refusals),
            "changed_request_conflict": conflicted["error"] == "request_conflict",
            "effective_config_digest": config_digest,
            "exact_retry_after_crash": retry_raw == retry_again_raw,
            "isolated_profile": isolated_ok and preflighted["ok"],
            "lifecycle_stable_and_stale_refused": (
                state_path.exists()
                and json.loads(state_path.read_bytes())["lifecycle_index"]
                == len(LIFECYCLE)
                and stale_result["error"] == "stale_lifecycle_event"
                and unknown_lifecycle_result["error"] == "unknown_lifecycle_event"
            ),
            "malformed_and_oversized_refused": (
                malformed.get("error") == "invalid_json"
                and oversized.get("error") == "request_too_large"
                and oversized_response_refused
                and missing_receipt_refused
            ),
            "native_state_disabled": native["error"] == "native_state_disabled",
            "negotiation_and_downgrade_refusal": (
                negotiated["ok"] and downgraded["error"] == "protocol_version_refused"
            ),
            "response_loss_recovered_once": (
                first_lost and retried["ok"] and retried["result"]["adopted"] is False
            ),
            "tool_inventory_exact": tuple(tools["result"]["tools"]) == REQUIRED_TOOLS,
            "transcript_export_log_scan_and_quarantine": native_outputs_detected,
        }
    cleanup_ok = temporary_path is not None and not temporary_path.exists()
    return {**public_probe, "profile_cleanup": cleanup_ok}


def conformance_report(
    value: Any, fixture_value: Any | None = None
) -> Mapping[str, Any]:
    profile = validate_profile(value)
    fixture = validate_fixture(
        fixture_value if fixture_value is not None else fixture_manifest()
    )
    blocking = sorted(
        name
        for name in MANDATORY_CONTROLS
        if profile["controls"][name]["state"] != "pass"
    )
    observed = "accepted" if not blocking else "refused"
    if observed == "accepted":
        synthetic: Mapping[str, Any] = _run_synthetic(profile, fixture)
        synthetic_ok = all(
            bool(value)
            for key, value in synthetic.items()
            if key != "effective_config_digest"
        ) and bool(synthetic["effective_config_digest"])
    else:
        synthetic = {"skipped": "mandatory-controls-fail-closed"}
        synthetic_ok = bool(blocking)
    checks = [
        {"check": "closed-profile-and-fixture", "ok": True},
        {"check": "authority-boundary", "ok": True},
        {
            "check": "admission-matches-evidence",
            "ok": observed == profile["admission"]["expected"],
        },
        {"check": "offline-synthetic-corpus", "ok": synthetic_ok},
    ]
    return {
        "admission": {
            "blocking_controls": blocking,
            "expected": profile["admission"]["expected"],
            "observed": observed,
        },
        "checks": checks,
        "evidence_state": profile["evidence_state"],
        "fixture_sha256": hashlib.sha256(
            _canonical(fixture, "invalid_fixture")
        ).hexdigest(),
        "passed": all(bool(check["ok"]) for check in checks),
        "profile_id": profile["profile_id"],
        "profile_sha256": hashlib.sha256(
            _canonical(profile, "invalid_profile")
        ).hexdigest(),
        "schema": REPORT_SCHEMA,
        "synthetic": synthetic,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", required=True, type=Path)
    parser.add_argument("profiles", nargs="+", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    reports: list[Mapping[str, Any]] = []
    try:
        fixture = load_fixture(arguments.fixture)
        for path in arguments.profiles:
            reports.append(conformance_report(load_profile(path), fixture))
    except HarnessConformanceError as exception:
        print(json.dumps({"error": exception.code, "ok": False}, sort_keys=True))
        return 2
    print(json.dumps(reports, indent=2, sort_keys=True))
    return 0 if all(bool(report["passed"]) for report in reports) else 1


if __name__ == "__main__":
    raise SystemExit(main())
