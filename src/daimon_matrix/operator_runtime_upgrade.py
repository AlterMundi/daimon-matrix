"""Trusted owner-local offline legacy conversion; never a model-facing tool.

Only the pinned 915c56c legacy source artifact is executable as a validator.
The owner must stop AND fence all consumers (including auto-restarts) before
using this module. Advisory daemon locks are not host lifecycle fencing.
Staging never changes the source. Failed stages are retained, not auto-repaired.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import stat
import subprocess
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager, nullcontext
from pathlib import Path
from typing import Any

from . import operator_capabilities as profiles
from .canonical import canonical_bytes
from .identity import signing_descriptor
from .keystore import EncryptedKeystore
from .local_api import create_capability
from .service import OPERATOR_CAPABILITY_PROFILES

LEGACY_REVISION = "915c56c8899fd53d683bd7c7c81c3465b600bed9"
# SHA256 of sorted compact JSON {relative src filename: SHA256(file bytes)}.
# All 48 files, not just runtime.py; no ambient/dynamic legacy imports.
LEGACY_SOURCE_SHA256 = (
    "f3f219144f58a46431304802ea8f887bc9e9376fc745bc60a9f28f13457de764"
)
LOCK = ".daimon-matrixd.lock"
MAX_FILE = 512 * 1024 * 1024


class UpgradeError(ValueError):
    """Bounded refusal; never includes custody or subprocess diagnostics."""


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _path(path: Path, *, private: bool = True) -> Path:
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts:
        raise UpgradeError("upgrade_absolute_path_required")
    for item in (*reversed(path.parents), path):
        info = item.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in {0, os.geteuid()}:
            raise UpgradeError("upgrade_unsafe_path")
        if (
            private
            and stat.S_IMODE(info.st_mode) & 0o022
            and not (info.st_uid == 0 and info.st_mode & stat.S_ISVTX)
        ):
            raise UpgradeError("upgrade_unsafe_ancestor")
    info = path.stat()
    if private and (info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077):
        raise UpgradeError("upgrade_private_directory_required")
    return path


def _snapshot(root: Path, *, private: bool = True) -> dict[str, bytes]:
    _path(root, private=private)
    result: dict[str, bytes] = {}

    def walk(fd: int, prefix: str) -> None:
        for name in sorted(os.listdir(fd)):
            child = os.open(
                name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd
            )
            try:
                info = os.fstat(child)
                if info.st_uid not in (
                    {os.geteuid()} if private else {0, os.geteuid()}
                ):
                    raise UpgradeError("upgrade_wrong_owner")
                if private and stat.S_IMODE(info.st_mode) & 0o077:
                    raise UpgradeError("upgrade_unsafe_mode")
                key = prefix + name
                if stat.S_ISDIR(info.st_mode):
                    if private:
                        result[key + "/"] = b""
                    walk(child, key + "/")
                elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                    if name.endswith(("-wal", "-shm", "-journal")):
                        raise UpgradeError("upgrade_sqlite_sidecar_requires_quiescence")
                    with os.fdopen(os.dup(child), "rb") as stream:
                        data = stream.read(MAX_FILE + 1)
                    if len(data) > MAX_FILE:
                        raise UpgradeError("upgrade_file_too_large")
                    result[key] = data
                else:
                    raise UpgradeError("upgrade_special_or_linked_file")
            finally:
                os.close(child)

    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        walk(fd, "")
    finally:
        os.close(fd)
    return result


def _inventory(snapshot: dict[str, bytes]) -> str:
    return _digest({k: hashlib.sha256(v).hexdigest() for k, v in snapshot.items()})


def inventory_digest(root: Path) -> str:
    """Read-only exact regular-file inventory; refuses unsafe custody metadata."""
    return _inventory(_snapshot(root))


def _sync(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _write(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    _sync(path.parent)


def _copy(snapshot: dict[str, bytes], root: Path) -> None:
    root.mkdir(mode=0o700)
    for name, data in snapshot.items():
        path = root / name
        missing = []
        parent = path.parent
        while not parent.exists():
            missing.append(parent)
            parent = parent.parent
        for directory in reversed(missing):
            directory.mkdir(mode=0o700)
            _sync(directory.parent)
        if name.endswith("/"):
            path.mkdir(mode=0o700, exist_ok=True)
            _sync(path.parent)
        else:
            _write(path, data)
    _sync(root)
    _sync(root.parent)


@contextmanager
def _locks(source: Path) -> Iterator[None]:
    # Require the pre-existing daemon lock: even lock creation would change the
    # exact source. Provision it while fencing consumers BEFORE inventory review.
    _path(source)
    _path(source.parent)
    parent = os.open(source.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    lock = -1
    try:
        fcntl.flock(parent, fcntl.LOCK_EX | fcntl.LOCK_NB)
        lock = os.open(source / LOCK, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
        info = os.fstat(lock)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & 0o077
        ):
            raise UpgradeError("upgrade_unsafe_runtime_lock")
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        if lock >= 0:
            os.close(lock)
        os.close(parent)


def _validate(root: Path, code: Path, password: bytes) -> None:
    script = """
import os,sys,time
sys.path.insert(0,sys.argv[1])
from pathlib import Path
from daimon_matrix.runtime import load_runtime
password=os.read(int(sys.argv[3]),4097)
load_runtime(Path(sys.argv[2]),'runtime.json',lambda:bytearray(password),clock=lambda:time.time_ns()//1000000)
"""
    read, write = os.pipe()
    try:
        os.write(write, password)
        os.close(write)
        write = -1
        result = subprocess.run(
            [sys.executable, "-I", "-B", "-c", script, str(code), str(root), str(read)],
            pass_fds=(read,),
            env={},
            capture_output=True,
            timeout=120,
        )
        if result.returncode:
            raise UpgradeError("upgrade_runtime_validation_rejected")
    finally:
        os.close(read)
        if write >= 0:
            os.close(write)


def _forward_authorization(bundle: dict[str, Any], expires_at_ms: int) -> int:
    """Legacy bindings are not admission: both required rows must be usable now."""
    now = time.time_ns() // 1000000
    for row in bundle["capabilities"]:
        descriptor = row["descriptor"]
        if descriptor["status"] != "active":
            raise UpgradeError("upgrade_legacy_authorization_inactive")
        if now < descriptor["not_before_ms"]:
            raise UpgradeError("upgrade_legacy_authorization_not_yet_valid")
        if now >= descriptor["not_after_ms"]:
            raise UpgradeError("upgrade_legacy_authorization_expired")
    if now >= expires_at_ms:
        raise UpgradeError("upgrade_authorization_expired")
    return now


def stage(
    *,
    source: Path,
    transaction: Path,
    legacy_source: Path,
    legacy_sha256: str,
    expected_source_sha256: str,
    expected_counter: int,
    expected_control_head: str,
    expected_being_ref: str,
    expected_origin: dict[str, Any],
    password: bytes,
    expires_at_ms: int,
    externally_quiesced: bool,
) -> dict[str, Any]:
    """Prepare a durable unpublished successor and untouched rollback evidence.

    Explicit pins are owner-reviewed inputs, not authorization obtained from a
    model or from the source bundle itself. No service or external client changes.
    """
    if not externally_quiesced or not 1 <= len(password) <= 4096:
        raise UpgradeError("upgrade_quiescence_and_password_required")
    if transaction.parent != source.parent or transaction == source:
        raise UpgradeError("upgrade_sibling_transaction_required")
    now = time.time_ns() // 1000000
    if not now < expires_at_ms <= now + profiles.OPERATOR_CAPABILITY_TTL_MS:
        raise UpgradeError("upgrade_invalid_expiry")
    code = _snapshot(legacy_source, private=False)
    if (
        legacy_sha256 != LEGACY_SOURCE_SHA256
        or _inventory(code) != LEGACY_SOURCE_SHA256
    ):
        raise UpgradeError("upgrade_legacy_artifact_mismatch")
    with _locks(source):
        snapshot = _snapshot(source)
        if _inventory(snapshot) != expected_source_sha256:
            raise UpgradeError("upgrade_source_conflict")
        bundle = json.loads(snapshot["runtime.json"])
        signing_slot = bundle["keystore"]["signing_slot"]
        label = signing_slot.removeprefix("runtime.signing.v1:")
        if (
            bundle.get("schema") != "dm.runtime.bundle/v7"
            or bundle["keystore"]["filename"] != "custody.json"
            or signing_slot != f"runtime.signing.v1:{label}"
            or len(bundle["capabilities"]) != 2
            or len({row["secret_slot"] for row in bundle["capabilities"]}) != 2
            or f"runtime.capability.v1:{label}"
            not in {row["secret_slot"] for row in bundle["capabilities"]}
            # The independently named observer must be the other distinct row,
            # even when the signing label itself begins with "status:".
            or not any(
                isinstance(row["secret_slot"], str)
                and row["secret_slot"] != f"runtime.capability.v1:{label}"
                and row["secret_slot"].startswith("runtime.capability.v1:status:")
                and row["secret_slot"] != "runtime.capability.v1:status:"
                and row["descriptor"]["methods"]
                == sorted(profiles.HOST_CAPABILITY_PROFILES["status"])
                for row in bundle["capabilities"]
            )
            or {"runtime_id", "runtime_label", "operator_capability_binding"}
            & bundle.keys()
        ):
            raise UpgradeError("upgrade_unsupported_legacy_shape")
        if (
            bundle["keystore"]["counter"] != expected_counter
            or bundle["control_head"] != expected_control_head
            or bundle["manifest"]["being_ref"] != expected_being_ref
            or bundle["local_origin"] != expected_origin
        ):
            raise UpgradeError("upgrade_identity_or_revision_conflict")
        _forward_authorization(bundle, expires_at_ms)
        transaction.mkdir(mode=0o700)
        _sync(transaction.parent)
        _copy(snapshot, transaction / "checkpoint")
        _copy(code, transaction / "legacy-code")
        _copy(snapshot, transaction / "validation")
        _validate(transaction / "validation", transaction / "legacy-code", password)
        if inventory_digest(transaction / "validation") != expected_source_sha256:
            raise UpgradeError("upgrade_legacy_validation_changed_copy")
        _forward_authorization(bundle, expires_at_ms)
        candidate = transaction / "successor"
        _copy(snapshot, candidate)
        store = EncryptedKeystore(candidate / "custody.json")
        current = store.open(
            lambda: bytearray(password),
            minimum_counter=expected_counter,
            required_control_head=expected_control_head,
        )
        if current.counter != expected_counter:
            raise UpgradeError("upgrade_custody_revision_conflict")
        slot = bundle["keystore"]["signing_slot"]
        label = slot.removeprefix("runtime.signing.v1:")
        seed = current.secrets[slot]
        rid = profiles.operator_runtime_id(
            label,
            expected_being_ref,
            expected_origin,
            signing_descriptor(seed)["key_id"],
        )
        retired = {row["secret_slot"] for row in bundle["capabilities"]}
        secrets = {
            key: value for key, value in current.secrets.items() if key not in retired
        }
        now = _forward_authorization(bundle, expires_at_ms)
        rows = []
        for names, methods, profile_fn, slot_fn, prefix in (
            (
                profiles.OPERATOR_PROFILE_NAMES,
                OPERATOR_CAPABILITY_PROFILES,
                profiles.operator_capability_profile,
                profiles.operator_capability_slot,
                "operator",
            ),
            (
                profiles.HOST_PROFILE_NAMES,
                profiles.HOST_CAPABILITY_PROFILES,
                profiles.host_capability_profile,
                profiles.host_capability_slot,
                "host",
            ),
        ):
            for name in names:
                capability = create_capability(
                    os.urandom(32),
                    client_id=f"client:{prefix}:{label}:{name}",
                    methods=sorted(methods[name]),
                    not_before_ms=now,
                    not_after_ms=expires_at_ms,
                )
                profile = profile_fn(name)
                secret_slot = slot_fn(label, name)
                secrets[secret_slot] = capability.key
                rows.append(
                    dict(
                        descriptor=capability.descriptor,
                        profile=profile,
                        runtime_id=rid,
                        secret_slot=secret_slot,
                    )
                )
                directory = candidate / profile["client_directory"]
                if directory.parent != candidate and directory != candidate:
                    directory.parent.mkdir(mode=0o700, exist_ok=True)
                directory.mkdir(mode=0o700, exist_ok=True)
                for filename, data in (
                    (
                        profile["client_config_filename"],
                        canonical_bytes(
                            dict(
                                schema="dm.local.client-config/v3",
                                capability=capability.descriptor,
                                expected_server=expected_origin,
                                runtime_id=rid,
                                runtime_label=label,
                            )
                        ),
                    ),
                    (profile["client_key_filename"], capability.key),
                ):
                    path = directory / filename
                    path.unlink(missing_ok=True)  # unpublished private copy only
                    _write(path, data)
        _forward_authorization(bundle, expires_at_ms)
        updated = store.rotate(
            lambda: bytearray(password),
            lambda: bytearray(password),
            expected_counter=current.counter,
            control_head=current.control_head,
            secrets=secrets,
        )
        bundle.update(
            runtime_id=rid,
            runtime_label=label,
            capabilities=rows,
            operator_capability_binding=profiles.create_operator_capability_binding(
                runtime_id=rid,
                runtime_label=label,
                being_ref=expected_being_ref,
                origin=expected_origin,
                signing_seed=seed,
                capability_rows=rows,
            ),
        )
        bundle["keystore"]["counter"] = updated.counter
        (candidate / "runtime.json").unlink()
        _write(candidate / "runtime.json", canonical_bytes(bundle))
        _validate(candidate, Path(__file__).resolve().parent.parent, password)
        after = _snapshot(candidate)
        replaced = {
            "runtime.json",
            "custody.json",
            ".custody.json.highwater",
            "client.json",
            "client.key",
        }
        for name, data in snapshot.items():
            if name not in replaced and after.get(name) != data:
                raise UpgradeError("upgrade_history_changed")
        # Persist the generated directory entries as well as each private file.
        for name in reversed(sorted(after)):
            if name.endswith("/"):
                _sync(candidate / name)
        _sync(candidate)
        _sync(transaction)
        if inventory_digest(source) != expected_source_sha256:
            raise UpgradeError("upgrade_source_conflict")
        receipt = dict(
            schema="dm.operator.runtime-upgrade/v1",
            source=str(source),
            transaction=str(transaction),
            legacy_revision=LEGACY_REVISION,
            legacy_sha256=legacy_sha256,
            source_sha256=expected_source_sha256,
            successor_sha256=_inventory(after),
            counter_before=expected_counter,
            counter_after=updated.counter,
            control_head=expected_control_head,
            being_ref=expected_being_ref,
            origin=expected_origin,
            runtime_id=rid,
            expires_at_ms=expires_at_ms,
        )
        # The bundle above now contains successor rows; admit against the exact
        # original legacy descriptors, not the newly issued authority.
        _forward_authorization(json.loads(snapshot["runtime.json"]), expires_at_ms)
        _write(transaction / "ready.json", canonical_bytes(receipt))
        return receipt


def _exchange(source: Path, successor: Path) -> None:
    """One Linux renameat2(RENAME_EXCHANGE), never a two-rename emulation."""
    import ctypes

    libc = ctypes.CDLL(None, use_errno=True)
    rename = getattr(libc, "renameat2", None)
    if rename is None:
        raise UpgradeError("upgrade_atomic_exchange_unavailable")
    rename.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    rename.restype = ctypes.c_int
    left = os.open(source.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    right = os.open(successor.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        if rename(
            left, os.fsencode(source.name), right, os.fsencode(successor.name), 2
        ):
            raise UpgradeError("upgrade_atomic_exchange_failed")
        os.fsync(left)
        os.fsync(right)
    finally:
        os.close(right)
        os.close(left)


def publish(
    *,
    source: Path,
    transaction: Path,
    expected_receipt_sha256: str,
    password: bytes,
    externally_quiesced: bool,
) -> dict[str, Any]:
    """Activate or recover the exact staged transaction, without rewinding.

    If the published tree has changed (including legitimate post-start effects),
    reject, retain ALL evidence, and require a separately reviewed recovery.
    Exact retry after exchange does not reissue keys or extend authorization.
    """
    if not externally_quiesced or not 1 <= len(password) <= 4096:
        raise UpgradeError("upgrade_quiescence_and_password_required")
    if transaction.parent != source.parent or transaction == source:
        raise UpgradeError("upgrade_sibling_transaction_required")
    _path(transaction)
    successor = transaction / "successor"
    with _locks(source), _locks(successor):
        # Securely read the owner-private receipt; caller pins the exact bytes.
        artifacts = _snapshot(transaction)
        raw = artifacts["ready.json"]
        if hashlib.sha256(raw).hexdigest() != expected_receipt_sha256:
            raise UpgradeError("upgrade_receipt_conflict")
        receipt = json.loads(raw)
        if (
            receipt["schema"] != "dm.operator.runtime-upgrade/v1"
            or receipt["source"] != str(source)
            or receipt["transaction"] != str(transaction)
            or receipt["legacy_revision"] != LEGACY_REVISION
            or receipt["legacy_sha256"] != LEGACY_SOURCE_SHA256
        ):
            raise UpgradeError("upgrade_receipt_binding_conflict")
        old = receipt["source_sha256"]
        new = receipt["successor_sha256"]
        if inventory_digest(transaction / "checkpoint") != old:
            raise UpgradeError("upgrade_checkpoint_conflict")
        pair = (inventory_digest(source), inventory_digest(successor))
        if pair == (old, new):
            if "published.json" in artifacts:
                raise UpgradeError("upgrade_rewind_detected")
            legacy_bundle = json.loads(artifacts["checkpoint/runtime.json"])
            _forward_authorization(legacy_bundle, receipt["expires_at_ms"])
            _validate(successor, Path(__file__).resolve().parent.parent, password)
            if (inventory_digest(source), inventory_digest(successor)) != (old, new):
                raise UpgradeError("upgrade_source_or_candidate_conflict")
            # Fresh publication needs live authority AFTER validation and final
            # inventory I/O, immediately before exchange. The committed (new, old)
            # branch intentionally bypasses admission: it acknowledges exact bytes.
            _forward_authorization(legacy_bundle, receipt["expires_at_ms"])
            _exchange(source, successor)
        elif pair != (new, old):
            raise UpgradeError("upgrade_ambiguous_state_preserved")
        # Covers lost return after exchange and before either parent fsync.
        _sync(source.parent)
        _sync(transaction)
        if (inventory_digest(source), inventory_digest(successor)) != (new, old):
            raise UpgradeError("upgrade_ambiguous_state_preserved")
        result = dict(
            schema="dm.operator.runtime-upgrade-publication/v1",
            state="published",
            ready_sha256=expected_receipt_sha256,
            source=str(source),
            successor_sha256=new,
            checkpoint=str(transaction / "checkpoint"),
            counter_after=receipt["counter_after"],
        )
        encoded = canonical_bytes(result)
        if "published.json" in artifacts:
            if artifacts["published.json"] != encoded:
                raise UpgradeError("upgrade_publication_receipt_conflict")
        else:
            temporary = transaction / (".published-" + os.urandom(16).hex())
            _write(temporary, encoded)
            os.rename(temporary, transaction / "published.json")
            _sync(transaction)
        return result


def _legacy_time(bundle: dict[str, Any]) -> None:
    now = time.time_ns() // 1000000
    if any(
        not row["descriptor"]["not_before_ms"]
        <= now
        < row["descriptor"]["not_after_ms"]
        for row in bundle["capabilities"]
    ):
        raise UpgradeError("rollback_legacy_authorization_expired")


def _rollback_context(source: Path, transaction: Path, pin: str) -> dict[str, Any]:
    artifacts = _snapshot(transaction)
    raw = artifacts["ready.json"]
    forward = json.loads(raw)
    if (
        hashlib.sha256(raw).hexdigest() != pin
        or forward["schema"] != "dm.operator.runtime-upgrade/v1"
        or forward["source"] != str(source)
        or forward["transaction"] != str(transaction)
        or forward["legacy_revision"] != LEGACY_REVISION
        or forward["legacy_sha256"] != LEGACY_SOURCE_SHA256
        or inventory_digest(transaction / "checkpoint") != forward["source_sha256"]
        or inventory_digest(transaction / "successor") != forward["source_sha256"]
        or _inventory(_snapshot(transaction / "legacy-code", private=False))
        != LEGACY_SOURCE_SHA256
        or forward["counter_after"] != forward["counter_before"] + 1
    ):
        raise UpgradeError("rollback_forward_binding_conflict")
    return dict(forward)


def _rollback_guard(
    source: Path, transaction: Path, password: bytes, quiesced: bool
) -> None:
    if not quiesced or not 1 <= len(password) <= 4096:
        raise UpgradeError("upgrade_quiescence_and_password_required")
    if transaction.parent != source.parent or transaction == source:
        raise UpgradeError("upgrade_sibling_transaction_required")
    _path(transaction)


def stage_rollback(
    *,
    source: Path,
    transaction: Path,
    expected_receipt_sha256: str,
    password: bytes,
    externally_quiesced: bool,
) -> dict[str, Any]:
    """Prepare only an exact pre-effect reverse conversion, never restore custody.

    The forward ready pin is the explicit request binding. Failed partial stages
    are retained and refuse; an existing complete stage never rotates again.
    """
    _rollback_guard(source, transaction, password, externally_quiesced)
    with (
        _locks(source),
        (
            _locks(transaction / "rollback")
            if (transaction / "rollback").exists()
            else nullcontext()
        ),
    ):
        forward = _rollback_context(source, transaction, expected_receipt_sha256)
        ready_path = transaction / "rollback-ready.json"
        if ready_path.exists():
            ready = json.loads(_snapshot(transaction)["rollback-ready.json"])
            _check_reverse(ready, forward, expected_receipt_sha256, source, transaction)
            pair = (
                inventory_digest(source),
                inventory_digest(transaction / "rollback"),
            )
            if pair not in (
                (ready["source_sha256"], ready["successor_sha256"]),
                (ready["successor_sha256"], ready["source_sha256"]),
            ):
                raise UpgradeError("rollback_ambiguous_state_preserved")
            return dict(ready)
        snapshot = _snapshot(source)
        if _inventory(snapshot) != forward["successor_sha256"]:
            raise UpgradeError("rollback_posteffect_or_unpublished_source")
        old = _snapshot(transaction / "checkpoint")
        _legacy_time(json.loads(old["runtime.json"]))
        # Validator/open may initialize files: operate only on a disposable copy.
        validation = transaction / "rollback-validation"
        _copy(old, validation)
        _validate(validation, transaction / "legacy-code", password)
        if inventory_digest(validation) != forward["source_sha256"]:
            raise UpgradeError("rollback_legacy_validation_changed_copy")
        legacy_bundle = json.loads(old["runtime.json"])
        legacy = EncryptedKeystore(validation / "custody.json").open(
            lambda: bytearray(password)
        )
        candidate = transaction / "rollback"
        _copy(snapshot, candidate)
        store = EncryptedKeystore(candidate / "custody.json")
        current = store.open(
            lambda: bytearray(password),
            minimum_counter=forward["counter_after"],
            required_control_head=forward["control_head"],
        )
        if current.counter != forward["counter_after"]:
            raise UpgradeError("rollback_counter_conflict")
        bundle = json.loads(snapshot["runtime.json"])
        retired = {row["secret_slot"] for row in bundle["capabilities"]}
        secrets = {
            key: value for key, value in current.secrets.items() if key not in retired
        }
        legacy_slots = {row["secret_slot"] for row in legacy_bundle["capabilities"]}
        for slot in legacy_slots:
            secrets[slot] = legacy.secrets[slot]
        if secrets != legacy.secrets:
            raise UpgradeError("rollback_identity_conflict")
        updated = store.rotate(
            lambda: bytearray(password),
            lambda: bytearray(password),
            expected_counter=current.counter,
            control_head=current.control_head,
            secrets=secrets,
        )
        for key in ("runtime_id", "runtime_label", "operator_capability_binding"):
            bundle.pop(key)
        bundle["capabilities"] = legacy_bundle["capabilities"]
        bundle["keystore"]["counter"] = updated.counter
        # Restore only the authorized legacy client pair, not encrypted custody.
        for name, data in {
            "runtime.json": canonical_bytes(bundle),
            "client.json": old["client.json"],
            "client.key": old["client.key"],
        }.items():
            (candidate / name).unlink()
            _write(candidate / name, data)
        before_validation = inventory_digest(candidate)
        _validate(candidate, transaction / "legacy-code", password)
        if inventory_digest(candidate) != before_validation:
            raise UpgradeError("rollback_validation_changed_candidate")
        if inventory_digest(source) != forward["successor_sha256"]:
            raise UpgradeError("rollback_posteffect_or_unpublished_source")
        ready = dict(
            schema="dm.operator.runtime-rollback/v1",
            source=str(source),
            transaction=str(transaction),
            forward_ready_sha256=expected_receipt_sha256,
            source_sha256=forward["successor_sha256"],
            successor_sha256=before_validation,
            counter_before=current.counter,
            counter_after=updated.counter,
        )
        _write(ready_path, canonical_bytes(ready))
        return ready


def _check_reverse(
    ready: dict[str, Any],
    forward: dict[str, Any],
    pin: str,
    source: Path,
    transaction: Path,
) -> None:
    if (
        set(ready)
        != {
            "schema",
            "source",
            "transaction",
            "forward_ready_sha256",
            "source_sha256",
            "successor_sha256",
            "counter_before",
            "counter_after",
        }
        or ready["schema"] != "dm.operator.runtime-rollback/v1"
        or ready["source"] != str(source)
        or ready["transaction"] != str(transaction)
        or ready["forward_ready_sha256"] != pin
        or ready["source_sha256"] != forward["successor_sha256"]
        or ready["counter_before"] != forward["counter_after"]
        or ready["counter_after"] != forward["counter_after"] + 1
    ):
        raise UpgradeError("rollback_ready_binding_conflict")


def publish_rollback(
    *,
    source: Path,
    transaction: Path,
    expected_receipt_sha256: str,
    password: bytes,
    externally_quiesced: bool,
) -> dict[str, Any]:
    """Exchange the exact approved reverse candidate; exact retry issues no keys."""
    _rollback_guard(source, transaction, password, externally_quiesced)
    candidate = transaction / "rollback"
    with _locks(source), _locks(candidate):
        artifacts = _snapshot(transaction)
        raw = artifacts["rollback-ready.json"]
        if hashlib.sha256(raw).hexdigest() != expected_receipt_sha256:
            raise UpgradeError("rollback_receipt_conflict")
        ready = json.loads(raw)
        pin = ready["forward_ready_sha256"]
        forward = _rollback_context(source, transaction, pin)
        _check_reverse(ready, forward, pin, source, transaction)
        old, new = ready["source_sha256"], ready["successor_sha256"]
        pair = (inventory_digest(source), inventory_digest(candidate))
        if pair == (old, new):
            if "rolled-back.json" in artifacts:
                raise UpgradeError("rollback_rewind_detected")
            expected_bundle = json.loads(artifacts["checkpoint/runtime.json"])
            expected_bundle["keystore"]["counter"] = ready["counter_after"]
            candidate_snapshot = _snapshot(candidate)
            if (
                json.loads(candidate_snapshot["runtime.json"]) != expected_bundle
                or json.loads(candidate_snapshot["custody.json"])["counter"]
                != ready["counter_after"]
            ):
                raise UpgradeError("rollback_candidate_contract_conflict")
            _legacy_time(json.loads(candidate_snapshot["runtime.json"]))
            _validate(candidate, transaction / "legacy-code", password)
            _legacy_time(json.loads(_snapshot(candidate)["runtime.json"]))
            if (inventory_digest(source), inventory_digest(candidate)) != (old, new):
                raise UpgradeError("rollback_source_or_candidate_conflict")
            _exchange(source, candidate)
        elif pair != (new, old):
            raise UpgradeError("rollback_ambiguous_state_preserved")
        _sync(source.parent)
        _sync(transaction)
        if (inventory_digest(source), inventory_digest(candidate)) != (new, old):
            raise UpgradeError("rollback_ambiguous_state_preserved")
        result = dict(
            schema="dm.operator.runtime-rollback-publication/v1",
            state="rolled-back",
            ready_sha256=expected_receipt_sha256,
            source=str(source),
            successor_sha256=new,
            counter_after=ready["counter_after"],
        )
        encoded = canonical_bytes(result)
        if "rolled-back.json" in artifacts:
            if artifacts["rolled-back.json"] != encoded:
                raise UpgradeError("rollback_publication_receipt_conflict")
        else:
            temporary = transaction / (".rolled-back-" + os.urandom(16).hex())
            _write(temporary, encoded)
            os.rename(temporary, transaction / "rolled-back.json")
            _sync(transaction)
        return result


def _read_request(path: Path, expected_sha256: str) -> dict[str, Any]:
    _path(path.parent)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & 0o077
        ):
            raise UpgradeError("upgrade_unsafe_request")
        data = stream.read(1024 * 1024 + 1)
    if len(data) > 1024 * 1024 or hashlib.sha256(data).hexdigest() != expected_sha256:
        raise UpgradeError("upgrade_request_conflict")
    request = json.loads(data)
    fields = {
        "source",
        "transaction",
        "legacy_source",
        "legacy_sha256",
        "expected_source_sha256",
        "expected_counter",
        "expected_control_head",
        "expected_being_ref",
        "expected_origin",
        "expires_at_ms",
    }
    if not isinstance(request, dict) or set(request) != fields:
        raise UpgradeError("upgrade_invalid_request")
    for key in ("source", "transaction", "legacy_source"):
        request[key] = Path(request[key])
    return request


def main(argv: list[str] | None = None) -> int:
    """Owner CLI: inventory; stage a reviewed request; publish/exact recovery.

    Rollback is a new monotonic pre-effect conversion, not a directory rewind.
    The checkpoint never authorizes post-effect recovery. Runtime/Cluster lifecycle
    and installed-package provenance remain separately reviewed owner actions.
    """
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    inventory = commands.add_parser(
        "inventory", help="read-only source inventory digest"
    )
    inventory.add_argument("--source", type=Path, required=True)
    staging = commands.add_parser(
        "stage", help="stage an exact owner-reviewed JSON request"
    )
    staging.add_argument("--request", type=Path, required=True)
    staging.add_argument("--request-sha256", required=True)
    publication = commands.add_parser(
        "publish", help="atomic activation or exact interrupted retry"
    )
    reverse_stage = commands.add_parser(
        "stage-rollback", help="prepare pre-effect monotonic legacy conversion"
    )
    reverse_publish = commands.add_parser(
        "publish-rollback", help="publish or retry approved reverse conversion"
    )
    for command in (publication, reverse_stage, reverse_publish):
        command.add_argument("--source", type=Path, required=True)
        command.add_argument("--transaction", type=Path, required=True)
        command.add_argument("--ready-sha256", required=True)
    for command in (staging, publication, reverse_stage, reverse_publish):
        command.add_argument("--password-fd", type=int, required=True)
        command.add_argument(
            "--externally-quiesced", action="store_true", required=True
        )
    args = parser.parse_args(argv)
    password = bytearray()
    try:
        if args.command == "inventory":
            print(inventory_digest(args.source))
            return 0
        # Read to EOF, bounded; no password argv, environment, prompt or logs.
        with os.fdopen(os.dup(args.password_fd), "rb") as stream:
            password.extend(stream.read(4097))
        if not 1 <= len(password) <= 4096:
            raise UpgradeError("upgrade_invalid_password_length")
        if args.command == "stage":
            result = stage(
                **_read_request(args.request, args.request_sha256),
                password=bytes(password),
                externally_quiesced=args.externally_quiesced,
            )
        else:
            operation = {
                "publish": publish,
                "stage-rollback": stage_rollback,
                "publish-rollback": publish_rollback,
            }[args.command]
            result = operation(
                source=args.source,
                transaction=args.transaction,
                expected_receipt_sha256=args.ready_sha256,
                password=bytes(password),
                externally_quiesced=args.externally_quiesced,
            )
        print(canonical_bytes(result).decode())
        return 0
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError):
        print(
            "runtime_upgrade_rejected; retain transaction and keep consumers fenced",
            file=sys.stderr,
        )
        return 1
    finally:
        password[:] = b"\x00" * len(password)


if __name__ == "__main__":
    raise SystemExit(main())
