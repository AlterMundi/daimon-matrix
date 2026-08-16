"""Distributed genesis ceremony with one encrypted store per key holder."""

from __future__ import annotations

import argparse
import copy
import json
import os
import shutil
import stat
import sys
import tempfile
import time
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from pathlib import Path
from typing import Any, Final, Literal

from .canonical import canonical_bytes
from .identity import (
    aggregate_genesis,
    create_genesis_holder_share,
    generate_ed25519_seed,
    prepare_genesis,
    signing_descriptor,
    verify_genesis,
)
from .keystore import EncryptedKeystore, KeystoreError

HOLDER_SCHEMA: Final = "dm.operator.genesis-holder/v1"
INTENT_SCHEMA: Final = "dm.operator.genesis-intent/v1"
PENDING_CONTROL_HEAD: Final = "dm:identity:genesis-pending:v1"
MAX_DOCUMENT_BYTES: Final = 4 * 1024 * 1024


class GenesisError(RuntimeError):
    """Distributed genesis input or custody failed closed."""


def _owner_directory(path: Path, code: str) -> Path:
    target = Path(os.path.abspath(path))
    try:
        info = target.lstat()
    except OSError as exception:
        raise GenesisError(code) from exception
    if (
        target.is_symlink()
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise GenesisError(code)
    return target


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _private_write(path: Path, value: Mapping[str, Any]) -> None:
    raw = canonical_bytes(value)
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        offset = 0
        while offset < len(raw):
            offset += os.write(descriptor, raw[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _document(path: Path, code: str) -> Any:
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or not 1 <= info.st_size <= MAX_DOCUMENT_BYTES
        ):
            raise GenesisError(code)
        chunks: list[bytes] = []
        size = 0
        while chunk := os.read(descriptor, 1024 * 1024):
            size += len(chunk)
            if size > MAX_DOCUMENT_BYTES:
                raise GenesisError(code)
            chunks.append(chunk)
        raw = b"".join(chunks)
        value = json.loads(raw)
        if canonical_bytes(value) != raw.rstrip(b"\n"):
            raise GenesisError(code)
        return value
    except GenesisError:
        raise
    except (OSError, ValueError) as exception:
        raise GenesisError(code) from exception
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _write_new(path: Path, value: Mapping[str, Any]) -> None:
    target = Path(os.path.abspath(path))
    _owner_directory(target.parent, "genesis_output_parent_rejected")
    if target.exists() or target.is_symlink():
        if target.is_file() and canonical_bytes(
            _document(target, "genesis_output_exists")
        ) == canonical_bytes(value):
            return
        raise GenesisError("genesis_output_exists")
    _private_write(target, value)
    _fsync_directory(target.parent)


def _password(descriptor: int) -> bytearray:
    if descriptor < 0:
        raise GenesisError("invalid_genesis_password_descriptor")
    try:
        raw = os.read(descriptor, 1025)
    except OSError as exception:
        raise GenesisError("genesis_password_unavailable") from exception
    finally:
        with suppress(OSError):
            os.close(descriptor)
    if not 12 <= len(raw) <= 1024:
        raise GenesisError("invalid_genesis_password_length")
    return bytearray(raw)


def _reader(password: bytearray) -> Callable[[], bytearray]:
    return lambda: bytearray(password)


def create_holder_package(
    output: Path,
    role: Literal["root", "recovery"],
    password_reader: Callable[[], bytes | bytearray],
) -> dict[str, Any]:
    """Atomically create one package containing exactly one private seed."""

    if role not in {"root", "recovery"}:
        raise GenesisError("invalid_genesis_holder_role")
    target = Path(os.path.abspath(output))
    parent = _owner_directory(target.parent, "genesis_holder_parent_rejected")
    if target.exists() or target.is_symlink():
        raise GenesisError("genesis_holder_exists")
    seed = generate_ed25519_seed()
    descriptor = {
        "schema": HOLDER_SCHEMA,
        "role": role,
        "key": signing_descriptor(seed),
    }
    staging: Path | None = None
    try:
        staging = Path(tempfile.mkdtemp(prefix=f".{target.name}.tmp-", dir=parent))
        staging.chmod(0o700)
        EncryptedKeystore.create(
            staging / "holder.json",
            password_reader,
            control_head=PENDING_CONTROL_HEAD,
            secrets={f"genesis.{role}.v1:holder": seed},
        )
        _private_write(staging / "descriptor.json", descriptor)
        _fsync_directory(staging)
        os.replace(staging, target)
        _fsync_directory(parent)
        staging = None
        return descriptor
    except KeystoreError as exception:
        raise GenesisError("genesis_holder_create_rejected") from exception
    finally:
        if staging is not None and staging.exists():
            shutil.rmtree(staging)


def create_intent(
    descriptors: Sequence[Any],
    *,
    root_threshold: int,
    recovery_threshold: int,
    created_at_ms: int,
    nonce: bytes,
) -> dict[str, Any]:
    """Freeze a genesis body using only public holder descriptors."""

    policies: dict[str, list[Mapping[str, Any]]] = {"root": [], "recovery": []}
    seen: set[str] = set()
    for value in descriptors:
        if (
            not isinstance(value, Mapping)
            or set(value) != {"schema", "role", "key"}
            or value.get("schema") != HOLDER_SCHEMA
            or value.get("role") not in policies
            or not isinstance(value.get("key"), Mapping)
        ):
            raise GenesisError("invalid_genesis_holder_descriptor")
        key_id = value["key"].get("key_id")
        if not isinstance(key_id, str) or key_id in seen:
            raise GenesisError("invalid_genesis_holder_descriptor")
        seen.add(key_id)
        policies[str(value["role"])].append(copy.deepcopy(dict(value["key"])))
    for values in policies.values():
        values.sort(key=lambda row: str(row["key_id"]))
    try:
        prepared = prepare_genesis(
            {"keys": policies["root"], "threshold": root_threshold},
            {"keys": policies["recovery"], "threshold": recovery_threshold},
            created_at_ms=created_at_ms,
            nonce=nonce,
        )
    except (TypeError, ValueError) as exception:
        raise GenesisError("genesis_intent_policy_rejected") from exception
    return {"schema": INTENT_SCHEMA, "prepared_genesis": prepared}


def create_holder_share(
    intent: Any,
    holder_package: Path,
    password_reader: Callable[[], bytes | bytearray],
) -> dict[str, Any]:
    """Open one holder package and emit its one public genesis signature."""

    if (
        not isinstance(intent, Mapping)
        or set(intent) != {"schema", "prepared_genesis"}
        or intent.get("schema") != INTENT_SCHEMA
        or not isinstance(intent.get("prepared_genesis"), Mapping)
    ):
        raise GenesisError("invalid_genesis_intent")
    package = _owner_directory(holder_package, "genesis_holder_package_rejected")
    descriptor = _document(
        package / "descriptor.json", "genesis_holder_descriptor_unavailable"
    )
    if (
        not isinstance(descriptor, Mapping)
        or set(descriptor) != {"schema", "role", "key"}
        or descriptor.get("schema") != HOLDER_SCHEMA
        or descriptor.get("role") not in {"root", "recovery"}
    ):
        raise GenesisError("invalid_genesis_holder_descriptor")
    role = str(descriptor["role"])
    try:
        contents = EncryptedKeystore(package / "holder.json").open(
            password_reader,
            minimum_counter=1,
            required_control_head=PENDING_CONTROL_HEAD,
        )
    except KeystoreError as exception:
        raise GenesisError("genesis_holder_store_rejected") from exception
    if len(contents.secrets) != 1:
        raise GenesisError("genesis_holder_store_rejected")
    slot, seed = next(iter(contents.secrets.items()))
    if (
        slot != f"genesis.{role}.v1:holder"
        or signing_descriptor(seed) != descriptor["key"]
    ):
        raise GenesisError("genesis_holder_store_rejected")
    try:
        signature = create_genesis_holder_share(
            intent["prepared_genesis"],
            seed,
            role=role,  # type: ignore[arg-type]
        )
    except (TypeError, ValueError) as exception:
        raise GenesisError("genesis_holder_not_authorized") from exception
    return {"schema": "dm.operator.genesis-share/v1", "signature": signature}


def aggregate_intent(intent: Any, shares: Sequence[Any]) -> dict[str, Any]:
    """Keyless aggregation of holder-produced public signatures."""

    if (
        not isinstance(intent, Mapping)
        or set(intent) != {"schema", "prepared_genesis"}
        or intent.get("schema") != INTENT_SCHEMA
        or not isinstance(intent.get("prepared_genesis"), Mapping)
    ):
        raise GenesisError("invalid_genesis_intent")
    signatures: list[Mapping[str, Any]] = []
    for share in shares:
        if (
            not isinstance(share, Mapping)
            or set(share) != {"schema", "signature"}
            or share.get("schema") != "dm.operator.genesis-share/v1"
            or not isinstance(share.get("signature"), Mapping)
        ):
            raise GenesisError("invalid_genesis_share")
        signatures.append(share["signature"])
    try:
        genesis = aggregate_genesis(intent["prepared_genesis"], signatures)
        verify_genesis(genesis)
        return genesis
    except (TypeError, ValueError) as exception:
        raise GenesisError("genesis_share_threshold_rejected") from exception


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="daimon-genesis", description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)
    holder = commands.add_parser("create-holder")
    holder.add_argument("--role", choices=("root", "recovery"), required=True)
    holder.add_argument("--password-fd", type=int, required=True)
    holder.add_argument("--output", type=Path, required=True)
    intent = commands.add_parser("create-intent")
    intent.add_argument("--descriptor", type=Path, action="append", required=True)
    intent.add_argument("--root-threshold", type=int, required=True)
    intent.add_argument("--recovery-threshold", type=int, required=True)
    intent.add_argument("--output", type=Path, required=True)
    sign = commands.add_parser("sign")
    sign.add_argument("--intent", type=Path, required=True)
    sign.add_argument("--holder", type=Path, required=True)
    sign.add_argument("--password-fd", type=int, required=True)
    sign.add_argument("--output", type=Path, required=True)
    aggregate = commands.add_parser("aggregate")
    aggregate.add_argument("--intent", type=Path, required=True)
    aggregate.add_argument("--share", type=Path, action="append", required=True)
    aggregate.add_argument("--output", type=Path, required=True)
    return result


def main(argv: Sequence[str] | None = None) -> int:
    password = bytearray()
    try:
        arguments = parser().parse_args(argv)
        if arguments.command == "create-holder":
            password = _password(arguments.password_fd)
            receipt = create_holder_package(
                arguments.output, arguments.role, _reader(password)
            )
        elif arguments.command == "create-intent":
            receipt = create_intent(
                [
                    _document(path, "genesis_holder_descriptor_unavailable")
                    for path in arguments.descriptor
                ],
                root_threshold=arguments.root_threshold,
                recovery_threshold=arguments.recovery_threshold,
                created_at_ms=time.time_ns() // 1_000_000,
                nonce=os.urandom(32),
            )
            _write_new(arguments.output, receipt)
        elif arguments.command == "sign":
            password = _password(arguments.password_fd)
            receipt = create_holder_share(
                _document(arguments.intent, "genesis_intent_unavailable"),
                arguments.holder,
                _reader(password),
            )
            _write_new(arguments.output, receipt)
        else:
            receipt = aggregate_intent(
                _document(arguments.intent, "genesis_intent_unavailable"),
                [
                    _document(path, "genesis_share_unavailable")
                    for path in arguments.share
                ],
            )
            _write_new(arguments.output, receipt)
        sys.stdout.buffer.write(canonical_bytes(receipt) + b"\n")
        return 0
    except GenesisError as exception:
        print(str(exception), file=sys.stderr)
        return 2
    except (OSError, TypeError, ValueError):
        print("genesis_failed", file=sys.stderr)
        return 1
    finally:
        password[:] = b"\x00" * len(password)


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "GenesisError",
    "aggregate_intent",
    "create_holder_package",
    "create_holder_share",
    "create_intent",
    "main",
    "parser",
]
