"""Run the installed DM-060 synthetic birth acceptance journey.

The executable creates only fresh synthetic identities under one validated
owner-only temporary root.  It never reads a live profile, Matrix state,
Cluster service, provider account, Tribe store, HMK database, or harness
session.  Its report contains public content identifiers and bounded outcomes
only.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import secrets
import select
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, cast

from .birth import (
    BirthError,
    BirthRegistry,
    create_activation_receipt,
    create_birth_acceptance,
    create_birth_offer,
    validate_activation_receipt,
)
from .canonical import CanonicalError, canonical_bytes
from .client import CLIENT_CONFIG_SCHEMA
from .identity import (
    ControlState,
    create_embodiment_credential,
    create_incarnation_authorization,
    create_synthetic_genesis_in_process,
    ed25519_public,
    generate_ed25519_seed,
    generate_x25519_private,
    key_descriptor,
    verify_genesis,
    x25519_public,
)
from .keystore import EncryptedKeystore
from .ledger import Ledger
from .local_api import create_capability
from .weave import BeingManifest, RootAuthority

SCENARIO_SCHEMA: Final = "dm.synthetic-birth-scenario/v1"
REPORT_SCHEMA: Final = "dm.synthetic-birth-report/v1"
MAX_SCENARIO_BYTES: Final = 128 * 1024
MAX_PROCESS_OUTPUT: Final = 2 * 1024 * 1024
MCP_META: Final = {
    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
    "io.modelcontextprotocol/clientInfo": {
        "name": "dm060-synthetic-birth",
        "version": "1",
    },
    "io.modelcontextprotocol/clientCapabilities": {},
}


class SyntheticBirthError(RuntimeError):
    """The synthetic runner could not produce trustworthy bounded evidence."""


def _closed(value: Any, fields: set[str], code: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise SyntheticBirthError(code)
    return value


def _text(value: Any, code: str, *, maximum: int = 512) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value.encode("utf-8")) <= maximum
        or any(ord(character) < 0x20 for character in value)
    ):
        raise SyntheticBirthError(code)
    return value


def _uuid(value: Any, code: str) -> str:
    text = _text(value, code, maximum=36)
    try:
        if str(uuid.UUID(text)) != text:
            raise ValueError
    except (ValueError, AttributeError) as exception:
        raise SyntheticBirthError(code) from exception
    return text


def _safe_body_ref(value: Any) -> str:
    text = _text(value, "invalid_synthetic_body_ref", maximum=256)
    if (
        text.startswith(("/", "~"))
        or "\\" in text
        or "//" in text
        or any(part in {"", ".", ".."} for part in text.split(":"))
    ):
        raise SyntheticBirthError("invalid_synthetic_body_ref")
    return text


def _references(value: Any, code: str) -> list[str]:
    if not isinstance(value, list) or len(value) > 256:
        raise SyntheticBirthError(code)
    rows = [_text(item, code) for item in value]
    if rows != sorted(set(rows)):
        raise SyntheticBirthError(code)
    return rows


def _scenario(value: Any) -> dict[str, Any]:
    row = _closed(
        value,
        {
            "newborn_body_ref",
            "parent_body_ref",
            "scenario_id",
            "schema",
            "source_references",
            "species_release_id",
            "tribal_commitments",
            "witness_body_ref",
        },
        "invalid_synthetic_birth_scenario",
    )
    if row["schema"] != SCENARIO_SCHEMA:
        raise SyntheticBirthError("unsupported_synthetic_birth_scenario")
    commitments = row["tribal_commitments"]
    if not isinstance(commitments, list) or len(commitments) > 256:
        raise SyntheticBirthError("invalid_synthetic_birth_commitments")
    normalized = {
        "schema": SCENARIO_SCHEMA,
        "scenario_id": _uuid(row["scenario_id"], "invalid_synthetic_scenario_id"),
        "species_release_id": _text(
            row["species_release_id"], "invalid_synthetic_species"
        ),
        "source_references": _references(
            row["source_references"], "invalid_synthetic_sources"
        ),
        "tribal_commitments": copy.deepcopy(commitments),
        "parent_body_ref": _safe_body_ref(row["parent_body_ref"]),
        "newborn_body_ref": _safe_body_ref(row["newborn_body_ref"]),
        "witness_body_ref": _safe_body_ref(row["witness_body_ref"]),
    }
    try:
        if canonical_bytes(normalized) != canonical_bytes(value):
            raise SyntheticBirthError("noncanonical_synthetic_birth_scenario")
    except CanonicalError as exception:
        raise SyntheticBirthError("invalid_synthetic_birth_scenario") from exception
    return normalized


def load_scenario(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise SyntheticBirthError("synthetic_scenario_unavailable")
    raw = path.read_bytes()
    if not 1 <= len(raw) <= MAX_SCENARIO_BYTES:
        raise SyntheticBirthError("synthetic_scenario_size")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exception:
        raise SyntheticBirthError("invalid_synthetic_birth_scenario") from exception
    return _scenario(value)


def _owner_root(path: Path) -> Path:
    root = Path(os.path.abspath(path))
    try:
        info = root.lstat()
    except OSError as exception:
        raise SyntheticBirthError("synthetic_root_unavailable") from exception
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise SyntheticBirthError("synthetic_root_not_owner_only")
    if any(root.iterdir()):
        raise SyntheticBirthError("synthetic_root_not_empty")
    return root


def _directory(parent: Path, name: str) -> Path:
    path = parent / name
    path.mkdir(mode=0o700)
    return path


def _write_private(path: Path, value: Mapping[str, Any]) -> None:
    if path.exists() or path.is_symlink():
        raise SyntheticBirthError("synthetic_file_collision")
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        raw = canonical_bytes(value)
        written = 0
        while written < len(raw):
            written += os.write(descriptor, raw[written:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _transport(seed: bytes, principal_id: str) -> dict[str, Any]:
    return {
        "scheme": "synthetic-loopback",
        "principal_id": principal_id,
        "key": key_descriptor("Ed25519", ed25519_public(seed)),
    }


@dataclass(frozen=True)
class _SyntheticIdentity:
    root_seeds: tuple[bytes, ...]
    recovery_seeds: tuple[bytes, ...]
    genesis: Mapping[str, Any]
    state: ControlState
    signing_seed: bytes
    encryption_private: bytes
    transport_seed: bytes
    credential: Mapping[str, Any]
    incarnation: Mapping[str, Any]
    origin: Mapping[str, str]
    manifest: BeingManifest
    authority: RootAuthority


def _create_identity(
    label: str,
    body_ref: str,
    purposes: Sequence[str],
    *,
    now_ms: int,
    root_seeds: Sequence[bytes] | None = None,
    recovery_seeds: Sequence[bytes] | None = None,
    genesis: Mapping[str, Any] | None = None,
) -> _SyntheticIdentity:
    actual_roots = tuple(
        root_seeds
        if root_seeds is not None
        else (generate_ed25519_seed(), generate_ed25519_seed())
    )
    actual_recovery = tuple(
        recovery_seeds
        if recovery_seeds is not None
        else (generate_ed25519_seed(), generate_ed25519_seed())
    )
    actual_genesis = (
        create_synthetic_genesis_in_process(
            actual_roots,
            2,
            actual_recovery,
            2,
            created_at_ms=now_ms - 10_000,
        )
        if genesis is None
        else copy.deepcopy(dict(genesis))
    )
    state = verify_genesis(actual_genesis)
    signing_seed = generate_ed25519_seed()
    encryption_private = generate_x25519_private()
    transport_seed = generate_ed25519_seed()
    origin = {
        "body_ref": body_ref,
        "embodiment_id": f"embodiment:synthetic:{label}:{uuid.uuid4()}",
        "incarnation_id": f"incarnation:synthetic:{label}:{uuid.uuid4()}",
        "principal_id": f"synthetic-{label}-{uuid.uuid4()}@loopback",
    }
    credential = create_embodiment_credential(
        state,
        actual_roots,
        signing_seed,
        x25519_public(encryption_private),
        embodiment_id=origin["embodiment_id"],
        body_ref=body_ref,
        purposes=purposes,
        valid_from_ms=now_ms - 1_000,
        valid_until_ms=now_ms + 10 * 60_000,
        transport_principals=[_transport(transport_seed, origin["principal_id"])],
    )
    incarnation = create_incarnation_authorization(
        credential,
        signing_seed,
        incarnation_id=origin["incarnation_id"],
        incarnation_sequence=0,
        started_at_ms=now_ms - 100,
    )
    manifest = BeingManifest.from_value(
        {
            "schema": "being-manifest/v2",
            "being_ref": state.being_ref,
            "control_head": state.head,
            "history_binding_id": None,
            "revision": 1,
            "embodiments": [
                {
                    "body_ref": body_ref,
                    "embodiment_credential_id": credential["artifact_id"],
                    "embodiment_id": origin["embodiment_id"],
                    "incarnation_authorization_id": incarnation["artifact_id"],
                    "incarnation_id": origin["incarnation_id"],
                    "status": "active",
                }
            ],
        }
    )
    authority = RootAuthority(
        manifest,
        state,
        {credential["artifact_id"]: credential},
        {incarnation["artifact_id"]: incarnation},
    )
    return _SyntheticIdentity(
        actual_roots,
        actual_recovery,
        actual_genesis,
        state,
        signing_seed,
        encryption_private,
        transport_seed,
        credential,
        incarnation,
        origin,
        manifest,
        authority,
    )


def _runtime_bundle(
    runtime_root: Path,
    identity: _SyntheticIdentity,
    *,
    now_ms: int,
) -> tuple[dict[str, Any], bytes, bytes]:
    capability_key = secrets.token_bytes(32)
    capability = create_capability(
        capability_key,
        client_id="client:dm060-synthetic",
        methods=[
            "runtime.status",
            "scope.me",
            "scope.we",
            "we.heads",
            "we.projection.get",
        ],
        not_before_ms=now_ms - 60_000,
        not_after_ms=now_ms + 10 * 60_000,
    )
    signing_slot = "runtime.signing.v1:dm060"
    capability_slot = "runtime.capability.v1:dm060"
    runtime_password = secrets.token_bytes(32)
    EncryptedKeystore.create(
        runtime_root / "custody.json",
        lambda: bytearray(runtime_password),
        control_head=identity.state.head,
        secrets={
            signing_slot: identity.signing_seed,
            capability_slot: capability_key,
        },
    )
    bundle = {
        "schema": "dm.runtime.bundle/v3",
        "control_artifacts": [identity.genesis],
        "control_head": identity.state.head,
        "manifest": identity.manifest.value,
        "authority_history": [],
        "credentials": [identity.credential],
        "incarnations": [identity.incarnation],
        "binding": None,
        "binding_activation": None,
        "provisional_history": None,
        "local_origin": identity.origin,
        "ledger": "ledger.sqlite",
        "socket": "matrix.sock",
        "keystore": {
            "filename": "custody.json",
            "counter": 1,
            "signing_slot": signing_slot,
        },
        "capabilities": [
            {
                "descriptor": capability.descriptor,
                "secret_slot": capability_slot,
            }
        ],
        "routing": None,
        "scopes": None,
        "peer_transport": None,
    }
    _write_private(runtime_root / "runtime.json", bundle)
    _write_private(
        runtime_root / "client.json",
        {
            "schema": CLIENT_CONFIG_SCHEMA,
            "capability": capability.descriptor,
            "expected_server": identity.origin,
        },
    )
    _directory(runtime_root, "requests")
    return bundle, capability_key, runtime_password


def _read_bounded(stream: Any, limit: int = MAX_PROCESS_OUTPUT) -> bytes:
    raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise SyntheticBirthError("synthetic_process_output_too_large")
    return cast(bytes, raw)


def _run_cli(
    python_executable: str,
    runtime_root: Path,
    capability_key: bytes,
    arguments: Sequence[str],
) -> dict[str, Any]:
    read_descriptor, write_descriptor = os.pipe()
    os.write(write_descriptor, capability_key)
    os.close(write_descriptor)
    try:
        completed = subprocess.run(
            [
                python_executable,
                "-m",
                "daimon_matrix.cli",
                "--socket",
                os.fspath(runtime_root / "matrix.sock"),
                "--client-config",
                os.fspath(runtime_root / "client.json"),
                "--capability-key-fd",
                str(read_descriptor),
                "--json",
                *arguments,
            ],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            pass_fds=(read_descriptor,),
            timeout=15,
            check=False,
        )
    finally:
        os.close(read_descriptor)
    if (
        completed.returncode != 0
        or len(completed.stdout) > MAX_PROCESS_OUTPUT
        or len(completed.stderr) > MAX_PROCESS_OUTPUT
    ):
        raise SyntheticBirthError("synthetic_cli_failed")
    try:
        value = json.loads(completed.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as exception:
        raise SyntheticBirthError("synthetic_cli_invalid_output") from exception
    response = _closed(
        value,
        {"method", "request_id", "response", "schema"},
        "synthetic_cli_invalid_output",
    )
    body = response["response"]
    if (
        response["schema"] != "dm.cli.result/v1"
        or not isinstance(body, Mapping)
        or body.get("ok") is not True
    ):
        raise SyntheticBirthError("synthetic_cli_refused")
    return copy.deepcopy(dict(value))


def _run_mcp(
    python_executable: str,
    runtime_root: Path,
    capability_key: bytes,
) -> dict[str, Any]:
    read_descriptor, write_descriptor = os.pipe()
    os.write(write_descriptor, capability_key)
    os.close(write_descriptor)
    process = subprocess.Popen(
        [
            python_executable,
            "-m",
            "daimon_matrix.mcp_server",
            "--socket",
            os.fspath(runtime_root / "matrix.sock"),
            "--client-config",
            os.fspath(runtime_root / "client.json"),
            "--capability-key-fd",
            str(read_descriptor),
            "--request-dir",
            os.fspath(runtime_root / "requests"),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        pass_fds=(read_descriptor,),
    )
    os.close(read_descriptor)
    assert process.stdin is not None
    assert process.stdout is not None
    assert process.stderr is not None
    frame = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"_meta": MCP_META, "name": "scope_me", "arguments": {}},
    }
    try:
        process.stdin.write(canonical_bytes(frame) + b"\n")
        process.stdin.flush()
        ready, _, _ = select.select([process.stdout], [], [], 15)
        if not ready:
            raise SyntheticBirthError("synthetic_mcp_timeout")
        response_raw = process.stdout.readline(MAX_PROCESS_OUTPUT + 1)
        if len(response_raw) > MAX_PROCESS_OUTPUT:
            raise SyntheticBirthError("synthetic_process_output_too_large")
        process.stdin.close()
        return_code = process.wait(timeout=15)
        errors = _read_bounded(process.stderr)
        if return_code != 0 or errors:
            raise SyntheticBirthError("synthetic_mcp_failed")
        try:
            response = json.loads(response_raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exception:
            raise SyntheticBirthError("synthetic_mcp_invalid_output") from exception
        result = _closed(
            response,
            {"id", "jsonrpc", "result"},
            "synthetic_mcp_invalid_output",
        )
        result_body = result["result"]
        if not isinstance(result_body, Mapping):
            raise SyntheticBirthError("synthetic_mcp_invalid_output")
        structured = result_body.get("structuredContent")
        if not isinstance(structured, Mapping) or not structured.get("ok"):
            raise SyntheticBirthError("synthetic_mcp_refused")
        return copy.deepcopy(dict(response))
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=5)
        process.stdout.close()
        process.stderr.close()


def _start_daemon(
    python_executable: str,
    runtime_root: Path,
    runtime_password: bytes,
) -> subprocess.Popen[bytes]:
    password_read, password_write = os.pipe()
    ready_read, ready_write = os.pipe()
    process = subprocess.Popen(
        [
            python_executable,
            "-m",
            "daimon_matrix.daemon",
            "--state-root",
            os.fspath(runtime_root),
            "--password-fd",
            str(password_read),
            "--ready-fd",
            str(ready_write),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        pass_fds=(password_read, ready_write),
    )
    os.close(password_read)
    os.close(ready_write)
    try:
        os.write(password_write, runtime_password)
    finally:
        os.close(password_write)
    ready, _, _ = select.select([ready_read], [], [], 15)
    try:
        if not ready or os.read(ready_read, 6) != b"READY\n":
            process.terminate()
            try:
                process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate(timeout=5)
            raise SyntheticBirthError("synthetic_daemon_not_ready")
    finally:
        os.close(ready_read)
    return process


def _stop_daemon(process: subprocess.Popen[bytes]) -> tuple[bytes, bytes]:
    process.terminate()
    try:
        stdout, stderr = process.communicate(timeout=10)
    except subprocess.TimeoutExpired as exception:
        process.kill()
        process.communicate(timeout=5)
        raise SyntheticBirthError("synthetic_daemon_stop_timeout") from exception
    if (
        process.returncode != 0
        or len(stdout) > MAX_PROCESS_OUTPUT
        or len(stderr) > MAX_PROCESS_OUTPUT
    ):
        raise SyntheticBirthError("synthetic_daemon_failed")
    return stdout, stderr


def _result_hash(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def run_synthetic_birth(
    scenario: Mapping[str, Any],
    work_root: Path,
    *,
    python_executable: str = sys.executable,
    now_ms: int | None = None,
) -> dict[str, Any]:
    """Run one fresh isolated ceremony and return bounded public evidence."""

    value = _scenario(scenario)
    root = _owner_root(work_root)
    started_at_ms = time.time_ns() // 1_000_000 if now_ms is None else now_ms
    parent = _create_identity(
        "parent",
        value["parent_body_ref"],
        ["birth.offer", "dm.we"],
        now_ms=started_at_ms,
    )
    witness = _create_identity(
        "witness",
        value["witness_body_ref"],
        ["birth.witness", "dm.we"],
        now_ms=started_at_ms,
    )

    # Newborn root/recovery material exists before lineage acceptance; body
    # operational keys deliberately do not.
    newborn_roots = (generate_ed25519_seed(), generate_ed25519_seed())
    newborn_recovery = (generate_ed25519_seed(), generate_ed25519_seed())
    newborn_genesis = create_synthetic_genesis_in_process(
        newborn_roots,
        2,
        newborn_recovery,
        2,
        created_at_ms=started_at_ms,
    )
    newborn_state = verify_genesis(newborn_genesis)
    offline = _directory(root, "offline-custody")
    backup_root = _directory(root, "offline-backup")
    restore_root = _directory(root, "offline-restore")
    offline_password = secrets.token_bytes(32)
    offline_slots = {
        **{f"birth.root.v1:{index}": item for index, item in enumerate(newborn_roots)},
        **{
            f"birth.recovery.v1:{index}": item
            for index, item in enumerate(newborn_recovery)
        },
    }
    offline_store = EncryptedKeystore.create(
        offline / "being-root.json",
        lambda: bytearray(offline_password),
        control_head=newborn_state.head,
        secrets=offline_slots,
    )
    offline_store.backup(
        backup_root / "being-root.backup",
        lambda: bytearray(offline_password),
        minimum_counter=1,
    )
    restored = EncryptedKeystore.restore(
        backup_root / "being-root.backup",
        restore_root / "being-root.json",
        lambda: bytearray(offline_password),
        public_counter=1,
        public_control_head=newborn_state.head,
    )
    restored_contents = restored.open(
        lambda: bytearray(offline_password),
        minimum_counter=1,
        required_control_head=newborn_state.head,
    )
    if restored_contents.secrets != offline_slots:
        raise SyntheticBirthError("synthetic_custody_restore_mismatch")

    awakening_seed = generate_ed25519_seed()
    offer = create_birth_offer(
        parent.state,
        parent.credential,
        parent.signing_seed,
        ed25519_public(awakening_seed),
        parent_origin=parent.origin,
        species_release_id=value["species_release_id"],
        source_references=value["source_references"],
        tribal_commitments=value["tribal_commitments"],
        issued_at_ms=started_at_ms,
        expires_at_ms=started_at_ms + 60_000,
        offer_nonce=secrets.token_bytes(32),
        bootstrap_routes=None,
    )
    acceptance = create_birth_acceptance(
        offer,
        newborn_genesis,
        newborn_roots,
        awakening_seed,
        accepted_at_ms=started_at_ms + 1,
        acceptance_nonce=secrets.token_bytes(32),
    )
    registry = BirthRegistry(root / "birth-registry.sqlite")
    registry.observe_offer(
        offer,
        parent.state,
        parent.credential,
        observed_at_ms=started_at_ms,
    )
    registry.accept(
        acceptance,
        offer,
        parent.state,
        parent.credential,
        newborn_genesis,
        observed_at_ms=started_at_ms + 1,
    )

    # Only after durable acceptance do body operational keys and the first
    # incarnation come into existence.
    newborn = _create_identity(
        "newborn",
        value["newborn_body_ref"],
        ["birth.first-embodiment", "dm.we", "messages"],
        now_ms=started_at_ms + 2,
        root_seeds=newborn_roots,
        recovery_seeds=newborn_recovery,
        genesis=newborn_genesis,
    )
    runtime_root = _directory(root, "runtime")
    ledger = Ledger(
        runtime_root / "ledger.sqlite",
        authority=newborn.authority,
        local_origin=newborn.origin,
        clock=lambda: started_at_ms + 3,
    )
    ledger.initialize()
    activation = create_activation_receipt(
        acceptance,
        newborn.state,
        newborn.credential,
        newborn.incarnation,
        newborn.manifest,
        ledger,
        witness.state,
        witness.credential,
        witness.signing_seed,
        witness_origin=witness.origin,
        observed_at_ms=started_at_ms + 3,
    )
    validate_activation_receipt(
        activation,
        acceptance,
        newborn.state,
        newborn.credential,
        newborn.incarnation,
        newborn.manifest,
        ledger,
        witness.state,
        witness.credential,
    )
    registry.activate(
        activation,
        acceptance,
        newborn.state,
        newborn.credential,
        newborn.incarnation,
        newborn.manifest,
        ledger,
        witness.state,
        witness.credential,
    )
    inspection = registry.inspect(offer["offer_id"])

    _bundle, capability_key, runtime_password = _runtime_bundle(
        runtime_root, newborn, now_ms=started_at_ms + 3
    )
    daemon = _start_daemon(python_executable, runtime_root, runtime_password)
    try:
        cli_results = [
            _run_cli(
                python_executable,
                runtime_root,
                capability_key,
                arguments,
            )
            for arguments in (
                ("daemon", "status"),
                ("scope", "me"),
                ("scope", "we"),
                ("we", "heads"),
                ("we", "projection-get"),
            )
        ]
        mcp_result = _run_mcp(python_executable, runtime_root, capability_key)
    finally:
        daemon_stdout, daemon_stderr = _stop_daemon(daemon)
    if daemon_stdout:
        raise SyntheticBirthError("synthetic_daemon_unexpected_stdout")
    diagnostics = [line for line in daemon_stderr.splitlines() if line]
    if len(diagnostics) != 2:
        raise SyntheticBirthError("synthetic_daemon_diagnostics_invalid")
    try:
        diagnostic_codes = [json.loads(line)["code"] for line in diagnostics]
    except (json.JSONDecodeError, KeyError, TypeError) as exception:
        raise SyntheticBirthError("synthetic_daemon_diagnostics_invalid") from exception
    if diagnostic_codes != ["ready", "stopped"]:
        raise SyntheticBirthError("synthetic_daemon_diagnostics_invalid")

    cli_methods = [result["method"] for result in cli_results]
    cli_hashes = {result["method"]: _result_hash(result) for result in cli_results}
    scope_we = next(
        result["response"]["result"]
        for result in cli_results
        if result["method"] == "scope.we"
    )
    scope_me = next(
        result["response"]["result"]
        for result in cli_results
        if result["method"] == "scope.me"
    )
    if (
        scope_me["being_ref"] != newborn.state.being_ref
        or len(scope_we["embodiments"]) != 1
        or scope_we["embodiments"][0]["embodiment_id"]
        != newborn.origin["embodiment_id"]
    ):
        raise SyntheticBirthError("synthetic_scope_boundary_failed")
    if ledger.events(include_incomplete=True):
        raise SyntheticBirthError("synthetic_newborn_ledger_changed")

    report = {
        "schema": REPORT_SCHEMA,
        "scenario_id": value["scenario_id"],
        "claim": "synthetic protocol validation; no real being or deployment was born",
        "status": "pass",
        "started_at_ms": started_at_ms,
        "completed_at_ms": time.time_ns() // 1_000_000,
        "lineage": {
            "offer_id": offer["offer_id"],
            "acceptance_id": acceptance["acceptance_id"],
            "activation_id": activation["receipt_id"],
            "state": inspection["state"],
            "parent_being_ref": parent.state.being_ref,
            "newborn_being_ref": newborn.state.being_ref,
            "witness_being_ref": witness.state.being_ref,
            "distinct_being_roots": len(
                {
                    parent.state.being_ref,
                    newborn.state.being_ref,
                    witness.state.being_ref,
                }
            )
            == 3,
        },
        "first_embodiment": {
            "embodiment_id": newborn.origin["embodiment_id"],
            "incarnation_id": newborn.origin["incarnation_id"],
            "incarnation_sequence": 0,
            "credential_id": newborn.credential["artifact_id"],
            "incarnation_authorization_id": newborn.incarnation["artifact_id"],
            "manifest_hash": newborn.manifest.digest,
            "manifest_revision": 1,
        },
        "empty_memory": {
            "event_count": activation["body"]["event_count"],
            "memory_event_count": activation["body"]["memory_event_count"],
            "projection_record_count": activation["body"]["projection_record_count"],
            "ledger_state_hash": activation["body"]["ledger_state_hash"],
        },
        "custody": {
            "counter": restored_contents.counter,
            "control_head": restored_contents.control_head,
            "root_key_count": len(newborn_roots),
            "recovery_key_count": len(newborn_recovery),
            "restore_verified": True,
            "runtime_separated": True,
        },
        "context": {
            "species_release_id": value["species_release_id"],
            "source_reference_count": len(value["source_references"]),
            "tribal_commitment_count": len(value["tribal_commitments"]),
            "context_is_not_autobiography": True,
            "commitments_are_inert": True,
        },
        "boundaries": {
            "automatic_we_membership": False,
            "inherited_parent_credentials": 0,
            "inherited_parent_events": 0,
            "inherited_parent_routes": 0,
            "inherited_parent_sessions": 0,
            "newborn_we_embodiments": len(scope_we["embodiments"]),
        },
        "installed_surfaces": {
            "daemon": "ready-stopped",
            "cli_methods": cli_methods,
            "cli_result_hashes": cli_hashes,
            "mcp_method": "scope_me",
            "mcp_result_hash": _result_hash(mcp_result),
        },
    }
    if not report["lineage"]["distinct_being_roots"]:
        raise SyntheticBirthError("synthetic_identity_collision")
    return report


def _write_report(path: Path, report: Mapping[str, Any]) -> None:
    parent = path.parent
    if not parent.exists() or parent.is_symlink() or not parent.is_dir():
        raise SyntheticBirthError("synthetic_report_parent_unavailable")
    temporary = parent / f".{path.name}.{secrets.token_hex(8)}.tmp"
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        raw = canonical_bytes(report) + b"\n"
        written = 0
        while written < len(raw):
            written += os.write(descriptor, raw[written:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    directory_descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_descriptor)
    finally:
        os.close(directory_descriptor)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="daimon-synthetic-birth", description=__doc__)
    result.add_argument("--scenario", type=Path, required=True)
    result.add_argument("--output", type=Path, required=True)
    result.add_argument(
        "--work-root",
        type=Path,
        help="existing empty owner-only root; omitted uses a disposable temporary root",
    )
    return result


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        scenario = load_scenario(args.scenario)
        if args.work_root is None:
            with tempfile.TemporaryDirectory(
                prefix="dm060-installed-birth-"
            ) as directory:
                root = Path(directory)
                root.chmod(0o700)
                report = run_synthetic_birth(scenario, root)
        else:
            report = run_synthetic_birth(scenario, args.work_root)
        _write_report(args.output, report)
        print(
            json.dumps(
                {
                    "schema": REPORT_SCHEMA,
                    "scenario_id": report["scenario_id"],
                    "status": report["status"],
                    "report_sha256": hashlib.sha256(
                        canonical_bytes(report)
                    ).hexdigest(),
                },
                sort_keys=True,
            )
        )
        return 0
    except (BirthError, CanonicalError, OSError, SyntheticBirthError) as exception:
        print(str(exception), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "REPORT_SCHEMA",
    "SCENARIO_SCHEMA",
    "SyntheticBirthError",
    "load_scenario",
    "main",
    "parser",
    "run_synthetic_birth",
]
