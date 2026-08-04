"""Fail-closed loader for one public hosted-runtime bundle and secret custody."""

from __future__ import annotations

import copy
import json
import os
import re
import stat
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from .canonical import CanonicalError, canonical_bytes, unb64url
from .identity import (
    ControlChain,
    VerificationError,
    verify_binding_activation,
    verify_embodiment_credential,
    verify_incarnation_authorization,
)
from .keystore import EncryptedKeystore, KeystoreError, PasswordReader
from .ledger import Ledger
from .local_api import LocalCapability
from .service import METHODS, HostedWeave
from .weave import (
    BeingManifest,
    BoundHistoryAuthority,
    EventSigner,
    ProvisionalAuthority,
    RootAuthority,
    WeaveProtocolError,
)

BUNDLE_SCHEMA: Final = "dm.runtime.bundle/v1"
MAX_BUNDLE_BYTES: Final = 4 * 1024 * 1024
_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
Clock = Callable[[], int]


class RuntimeError(ValueError):
    """Public authority, paths, or custody cannot safely host a runtime."""


@dataclass(frozen=True)
class HostedRuntime:
    service: HostedWeave
    state_root: Path
    state_identity: tuple[int, int]
    socket_path: Path


def _closed(value: Any, fields: set[str]) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise RuntimeError("invalid_runtime_bundle")
    return value


def _owner_directory(path: Path) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError as exception:
        raise RuntimeError("state_root_missing") from exception
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise RuntimeError("state_root_not_owner_only")
    ancestor = path.parent
    while ancestor != ancestor.parent:
        if ancestor.is_symlink():
            raise RuntimeError("state_root_ancestor_symlink")
        ancestor = ancestor.parent


def _safe_file(root: Path, name: Any, *, must_exist: bool) -> Path:
    if not isinstance(name, str) or _SAFE_NAME.fullmatch(name) is None:
        raise RuntimeError("unsafe_runtime_filename")
    path = root / name
    if must_exist:
        try:
            info = path.lstat()
        except FileNotFoundError as exception:
            raise RuntimeError("runtime_file_missing") from exception
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & 0o077
        ):
            raise RuntimeError("runtime_file_not_owner_only")
    return path


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RuntimeError("runtime_bundle_duplicate_key")
        result[key] = value
    return result


def _read_bundle(path: Path) -> Mapping[str, Any]:
    before = path.lstat()
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise RuntimeError("runtime_bundle_replaced")
        raw = os.read(descriptor, MAX_BUNDLE_BYTES + 1)
        if not raw or len(raw) > MAX_BUNDLE_BYTES:
            raise RuntimeError("invalid_runtime_bundle_size")
    finally:
        os.close(descriptor)
    try:
        value = json.loads(raw, object_pairs_hook=_unique_object)
        if not isinstance(value, Mapping) or canonical_bytes(value) != raw:
            raise RuntimeError("runtime_bundle_not_canonical")
        return value
    except (CanonicalError, UnicodeDecodeError, json.JSONDecodeError) as exception:
        raise RuntimeError("invalid_runtime_bundle") from exception


def _indexed(values: Any) -> dict[str, Mapping[str, Any]]:
    if not isinstance(values, list) or not 1 <= len(values) <= 256:
        raise RuntimeError("invalid_runtime_bundle")
    result: dict[str, Mapping[str, Any]] = {}
    for value in values:
        if not isinstance(value, Mapping) or not isinstance(
            value.get("artifact_id"), str
        ):
            raise RuntimeError("invalid_runtime_artifact")
        artifact_id = value["artifact_id"]
        if artifact_id in result:
            raise RuntimeError("duplicate_runtime_artifact")
        result[artifact_id] = copy.deepcopy(dict(value))
    return result


def _event_index(values: Any) -> dict[str, Mapping[str, Any]]:
    if not isinstance(values, list) or len(values) > 65_536:
        raise RuntimeError("invalid_historical_events")
    result: dict[str, Mapping[str, Any]] = {}
    for value in values:
        if not isinstance(value, Mapping) or not isinstance(value.get("event_id"), str):
            raise RuntimeError("invalid_historical_event")
        event_id = value["event_id"]
        if event_id in result:
            raise RuntimeError("duplicate_historical_event")
        result[event_id] = copy.deepcopy(dict(value))
    return result


def load_runtime(
    state_root: Path,
    bundle_name: str,
    password_reader: PasswordReader,
    *,
    clock: Clock,
) -> HostedRuntime:
    """Verify all public/secret bindings before exposing a hosted service."""

    root = Path(os.path.abspath(state_root))
    _owner_directory(root)
    root_info = root.lstat()
    bundle_path = _safe_file(root, bundle_name, must_exist=True)
    bundle = _closed(
        _read_bundle(bundle_path),
        {
            "binding",
            "binding_activation",
            "capabilities",
            "control_artifacts",
            "control_head",
            "credentials",
            "incarnations",
            "keystore",
            "ledger",
            "local_origin",
            "manifest",
            "provisional_history",
            "schema",
            "socket",
        },
    )
    if bundle["schema"] != BUNDLE_SCHEMA:
        raise RuntimeError("unsupported_runtime_bundle")
    controls = bundle["control_artifacts"]
    if not isinstance(controls, list) or not 1 <= len(controls) <= 1024:
        raise RuntimeError("invalid_control_chain")
    try:
        chain = ControlChain(controls[0])
        for artifact in controls[1:]:
            chain.add(artifact)
        state = chain.state
        if bundle["control_head"] != state.head:
            raise RuntimeError("runtime_control_head_mismatch")

        binding = bundle["binding"]
        activation = bundle["binding_activation"]
        history = bundle["provisional_history"]
        if (binding is None) != (activation is None) or (binding is None) != (
            history is None
        ):
            raise RuntimeError("incomplete_history_binding")
        if binding is not None:
            if not isinstance(binding, Mapping) or not isinstance(activation, Mapping):
                raise RuntimeError("invalid_history_binding")
            state = verify_binding_activation(activation, binding, state)

        manifest = BeingManifest.from_value(bundle["manifest"])
        credentials = _indexed(bundle["credentials"])
        incarnations = _indexed(bundle["incarnations"])
        active = RootAuthority(manifest, state, credentials, incarnations)
        authority: RootAuthority | BoundHistoryAuthority = active
        if history is not None:
            history_value = _closed(history, {"events", "manifest", "public_keys"})
            public_keys = history_value["public_keys"]
            if not isinstance(public_keys, Mapping):
                raise RuntimeError("invalid_historical_keys")
            historical = ProvisionalAuthority(
                BeingManifest.from_value(history_value["manifest"]),
                public_keys,
            )
            authority = BoundHistoryAuthority(
                active,
                historical,
                binding,
                _event_index(history_value["events"]),
            )
    except (
        AttributeError,
        VerificationError,
        WeaveProtocolError,
        TypeError,
        KeyError,
    ) as exception:
        raise RuntimeError("runtime_authority_rejected") from exception

    local_origin = _closed(
        bundle["local_origin"],
        {"body_ref", "embodiment_id", "incarnation_id", "principal_id"},
    )
    try:
        member = authority.validate_origin(local_origin, require_active=True)
        credential = credentials[member["embodiment_credential_id"]]
        incarnation = incarnations[member["incarnation_authorization_id"]]
        credential_body = verify_embodiment_credential(credential, state, at_ms=clock())
        verify_incarnation_authorization(incarnation, credential, state, at_ms=clock())
    except (KeyError, VerificationError, WeaveProtocolError) as exception:
        raise RuntimeError("local_authorization_not_active") from exception

    custody = _closed(bundle["keystore"], {"counter", "filename", "signing_slot"})
    counter = custody["counter"]
    signing_slot = custody["signing_slot"]
    if (
        not isinstance(counter, int)
        or isinstance(counter, bool)
        or counter < 1
        or not isinstance(signing_slot, str)
        or not signing_slot.startswith("runtime.signing.v1:")
    ):
        raise RuntimeError("invalid_runtime_custody")
    keystore_path = _safe_file(root, custody["filename"], must_exist=True)
    ledger_path = _safe_file(root, bundle["ledger"], must_exist=False)
    socket_path = _safe_file(root, bundle["socket"], must_exist=False)
    filenames = {
        bundle_path.name,
        keystore_path.name,
        ledger_path.name,
        socket_path.name,
    }
    if len(filenames) != 4:
        raise RuntimeError("runtime_filename_collision")
    try:
        contents = EncryptedKeystore(keystore_path).open(
            password_reader,
            minimum_counter=counter,
            required_control_head=state.head,
        )
    except KeystoreError as exception:
        raise RuntimeError("runtime_custody_rejected") from exception
    capability_rows = bundle["capabilities"]
    if not isinstance(capability_rows, list) or not 1 <= len(capability_rows) <= 64:
        raise RuntimeError("runtime_requires_capability")
    required_slots = {signing_slot}
    capabilities: dict[str, LocalCapability] = {}
    for row in capability_rows:
        value = _closed(row, {"descriptor", "secret_slot"})
        slot = value["secret_slot"]
        if not isinstance(slot, str) or not slot.startswith("runtime.capability.v1:"):
            raise RuntimeError("invalid_capability_slot")
        if slot in required_slots:
            raise RuntimeError("duplicate_runtime_slot")
        required_slots.add(slot)
        key = contents.secrets.get(slot)
        if key is None:
            raise RuntimeError("missing_runtime_secret")
        capability = LocalCapability.from_value(value["descriptor"], key)
        if (
            not set(capability.methods) <= METHODS
            or capability.capability_id in capabilities
        ):
            raise RuntimeError("invalid_runtime_capability")
        capabilities[capability.capability_id] = capability
    if set(contents.secrets) != required_slots:
        raise RuntimeError("unexpected_runtime_secret_slot")
    seed = contents.secrets.get(signing_slot)
    if seed is None:
        raise RuntimeError("missing_runtime_secret")
    signer = EventSigner(credential_body["signing_key"]["key_id"], seed)
    if signer.public_key != unb64url(
        credential_body["signing_key"]["public"], length=32
    ):
        raise RuntimeError("runtime_signer_mismatch")

    ledger = Ledger(
        ledger_path,
        authority=authority,
        local_origin=local_origin,
        clock=clock,
    )
    service = HostedWeave(ledger, signer, capabilities, clock)
    ledger.integrity_check()
    final_root = root.lstat()
    identity = (root_info.st_dev, root_info.st_ino)
    if (final_root.st_dev, final_root.st_ino) != identity:
        raise RuntimeError("state_root_replaced")
    return HostedRuntime(service, root, identity, socket_path)


__all__ = ["BUNDLE_SCHEMA", "HostedRuntime", "RuntimeError", "load_runtime"]
