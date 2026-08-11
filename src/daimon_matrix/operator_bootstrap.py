"""One-shot operator ceremony for a new plural root-bound hosted being."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import sys
import tempfile
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from pathlib import Path
from typing import Any, Final

from .canonical import canonical_bytes
from .client import CLIENT_CONFIG_SCHEMA, load_json_document
from .identity import (
    create_embodiment_credential,
    create_genesis,
    create_incarnation_authorization,
    ed25519_public,
    generate_ed25519_seed,
    generate_x25519_private,
    key_descriptor,
    verify_genesis,
    x25519_public,
)
from .keystore import EncryptedKeystore
from .local_api import create_capability
from .peer_transport import PeerTransportError, http_peer_round_trip
from .service import SERVICE_METHODS
from .weave import BeingManifest, RootAuthority

PROFILE_SCHEMA: Final = "dm.operator.bootstrap-profile/v1"
AUTHORITY_SCHEMA: Final = "dm.operator.authority/v1"
RECEIPT_SCHEMA: Final = "dm.operator.bootstrap-receipt/v1"
MAX_TIME: Final = 2**53 - 1
STATUS_OBSERVER_METHODS: Final = frozenset(
    {
        "runtime.status",
        "scope.me",
        "scope.we",
        "scope.we.diff",
        "scope.we.sync-plan",
    }
)
_LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class BootstrapError(RuntimeError):
    """The requested ceremony could not be completed without unsafe state."""


def _private_write(path: Path, value: Mapping[str, Any] | bytes) -> None:
    raw = value if isinstance(value, bytes) else canonical_bytes(value)
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


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _password(descriptor: int) -> bytearray:
    if descriptor < 0:
        raise BootstrapError("invalid_password_descriptor")
    try:
        value = os.read(descriptor, 1025)
    except OSError as exception:
        raise BootstrapError("password_unavailable") from exception
    finally:
        with suppress(OSError):
            os.close(descriptor)
    if not 12 <= len(value) <= 1024:
        raise BootstrapError("invalid_password_length")
    return bytearray(value)


def _profile(path: Path) -> list[dict[str, Any]]:
    try:
        value = load_json_document(path.read_bytes())
    except (OSError, ValueError) as exception:
        raise BootstrapError("bootstrap_profile_unavailable") from exception
    if not isinstance(value, Mapping) or set(value) != {"embodiments", "schema"}:
        raise BootstrapError("invalid_bootstrap_profile")
    if value["schema"] != PROFILE_SCHEMA:
        raise BootstrapError("unsupported_bootstrap_profile")
    rows = value["embodiments"]
    if not isinstance(rows, list) or not 2 <= len(rows) <= 16:
        raise BootstrapError("invalid_bootstrap_profile")
    normalized: list[dict[str, Any]] = []
    fields = {
        "advertised_endpoint",
        "body_ref",
        "label",
        "listen_host",
        "listen_port",
        "principal_id",
    }
    for raw in rows:
        if not isinstance(raw, Mapping) or set(raw) != fields:
            raise BootstrapError("invalid_bootstrap_profile")
        row = dict(raw)
        if (
            not isinstance(row["label"], str)
            or _LABEL.fullmatch(row["label"]) is None
            or not all(
                isinstance(row[field], str)
                and 1 <= len(row[field].encode("utf-8")) <= maximum
                for field, maximum in (
                    ("body_ref", 256),
                    ("principal_id", 128),
                    ("listen_host", 255),
                    ("advertised_endpoint", 2048),
                )
            )
            or any(character.isspace() for character in row["listen_host"])
            or not isinstance(row["listen_port"], int)
            or isinstance(row["listen_port"], bool)
            or not 1 <= row["listen_port"] <= 65_535
        ):
            raise BootstrapError("invalid_bootstrap_profile")
        try:
            http_peer_round_trip(row["advertised_endpoint"], timeout_seconds=5.0)
        except PeerTransportError as exception:
            raise BootstrapError("invalid_bootstrap_profile") from exception
        normalized.append(row)
    labels = [str(row["label"]) for row in normalized]
    if labels != sorted(labels) or len(set(labels)) != len(labels):
        raise BootstrapError("bootstrap_profile_not_canonical")
    for field in ("body_ref", "principal_id", "advertised_endpoint"):
        if len({str(row[field]) for row in normalized}) != len(normalized):
            raise BootstrapError("duplicate_bootstrap_identity")
    return normalized


def _password_map(values: Sequence[str], labels: set[str]) -> dict[str, int]:
    result: dict[str, int] = {}
    for value in values:
        label, separator, raw_descriptor = value.partition("=")
        try:
            descriptor = int(raw_descriptor)
        except ValueError as exception:
            raise BootstrapError("invalid_password_descriptor") from exception
        if separator != "=" or label not in labels or label in result or descriptor < 0:
            raise BootstrapError("invalid_password_descriptor")
        result[label] = descriptor
    if set(result) != labels:
        raise BootstrapError("missing_runtime_password_descriptor")
    return result


def _transport_principal(seed: bytes, principal_id: str) -> dict[str, Any]:
    return {
        "scheme": "dm-peer-v1",
        "principal_id": principal_id,
        "key": key_descriptor("Ed25519", ed25519_public(seed)),
    }


def _password_reader(password: bytearray) -> Callable[[], bytearray]:
    def read() -> bytearray:
        return bytearray(password)

    return read


def _create(
    output: Path,
    profile_path: Path,
    root_password_fd: int,
    runtime_password_fds: Sequence[str],
) -> dict[str, Any]:
    rows = _profile(profile_path)
    descriptors = _password_map(
        runtime_password_fds, {str(row["label"]) for row in rows}
    )
    target = Path(os.path.abspath(output))
    parent = target.parent
    try:
        parent_info = parent.lstat()
    except FileNotFoundError as exception:
        raise BootstrapError("bootstrap_parent_missing") from exception
    if (
        target.exists()
        or target.is_symlink()
        or parent.is_symlink()
        or not stat.S_ISDIR(parent_info.st_mode)
        or parent_info.st_uid != os.geteuid()
    ):
        raise BootstrapError("bootstrap_target_rejected")

    root_password = bytearray()
    runtime_passwords: dict[str, bytearray] = {}
    staging: Path | None = None
    try:
        root_password = _password(root_password_fd)
        for label, descriptor in descriptors.items():
            runtime_passwords[label] = _password(descriptor)
        password_values = [
            bytes(root_password),
            *map(bytes, runtime_passwords.values()),
        ]
        if len(set(password_values)) != len(password_values):
            raise BootstrapError("password_reuse_rejected")
        staging = Path(tempfile.mkdtemp(prefix=f".{target.name}.tmp-", dir=parent))
        staging.chmod(0o700)
        created_at_ms = time.time_ns() // 1_000_000
        root_seeds = [generate_ed25519_seed() for _ in range(3)]
        recovery_seeds = [generate_ed25519_seed() for _ in range(3)]
        genesis = create_genesis(
            root_seeds,
            2,
            recovery_seeds,
            2,
            created_at_ms=created_at_ms,
        )
        state = verify_genesis(genesis)
        material: dict[str, dict[str, Any]] = {}
        credentials: dict[str, Mapping[str, Any]] = {}
        incarnations: dict[str, Mapping[str, Any]] = {}
        manifest_rows: list[dict[str, Any]] = []
        for row in rows:
            label = str(row["label"])
            signing_seed = generate_ed25519_seed()
            encryption_seed = generate_x25519_private()
            transport_seed = generate_ed25519_seed()
            capability_key = secrets.token_bytes(32)
            status_capability_key = secrets.token_bytes(32)
            origin = {
                "body_ref": row["body_ref"],
                "embodiment_id": f"embodiment:{uuid.uuid4()}",
                "incarnation_id": f"incarnation:{uuid.uuid4()}",
                "principal_id": row["principal_id"],
            }
            credential = create_embodiment_credential(
                state,
                root_seeds,
                signing_seed,
                x25519_public(encryption_seed),
                embodiment_id=origin["embodiment_id"],
                body_ref=origin["body_ref"],
                purposes=["dm.we", "messages"],
                valid_from_ms=created_at_ms,
                valid_until_ms=MAX_TIME,
                transport_principals=[
                    _transport_principal(transport_seed, origin["principal_id"])
                ],
            )
            incarnation = create_incarnation_authorization(
                credential,
                signing_seed,
                incarnation_id=origin["incarnation_id"],
                incarnation_sequence=0,
                started_at_ms=created_at_ms,
            )
            capability = create_capability(
                capability_key,
                client_id=f"client:operator:{label}",
                methods=sorted(SERVICE_METHODS),
                not_before_ms=max(0, created_at_ms - 60_000),
                not_after_ms=MAX_TIME,
            )
            status_capability = create_capability(
                status_capability_key,
                client_id=f"client:status-observer:{label}",
                methods=sorted(STATUS_OBSERVER_METHODS),
                not_before_ms=max(0, created_at_ms - 60_000),
                not_after_ms=MAX_TIME,
            )
            credentials[credential["artifact_id"]] = credential
            incarnations[incarnation["artifact_id"]] = incarnation
            manifest_rows.append(
                {
                    "body_ref": origin["body_ref"],
                    "embodiment_credential_id": credential["artifact_id"],
                    "embodiment_id": origin["embodiment_id"],
                    "incarnation_authorization_id": incarnation["artifact_id"],
                    "incarnation_id": origin["incarnation_id"],
                    "status": "active",
                }
            )
            material[label] = {
                "row": row,
                "origin": origin,
                "signing_seed": signing_seed,
                "encryption_seed": encryption_seed,
                "transport_seed": transport_seed,
                "capability": capability,
                "capability_key": capability_key,
                "status_capability": status_capability,
                "status_capability_key": status_capability_key,
            }
        manifest_rows.sort(
            key=lambda row: (row["embodiment_id"], row["incarnation_id"])
        )
        manifest = BeingManifest.from_value(
            {
                "schema": "being-manifest/v2",
                "being_ref": state.being_ref,
                "control_head": state.head,
                "history_binding_id": None,
                "revision": 1,
                "embodiments": manifest_rows,
            }
        )
        RootAuthority(manifest, state, credentials, incarnations)
        authority = {
            "schema": AUTHORITY_SCHEMA,
            "control_artifacts": [genesis],
            "control_head": state.head,
            "manifest": manifest.value,
            "credentials": list(credentials.values()),
            "incarnations": list(incarnations.values()),
        }
        _private_write(staging / "authority.json", authority)

        offline = staging / "offline"
        offline.mkdir(mode=0o700)
        EncryptedKeystore.create(
            offline / "root-custody.json",
            lambda: bytearray(root_password),
            control_head=state.head,
            secrets={
                **{
                    f"root.signing.v1:{index}": seed
                    for index, seed in enumerate(root_seeds)
                },
                **{
                    f"recovery.signing.v1:{index}": seed
                    for index, seed in enumerate(recovery_seeds)
                },
            },
        )

        runtimes = staging / "runtimes"
        runtimes.mkdir(mode=0o700)
        host_clients = staging / "host-clients"
        host_clients.mkdir(mode=0o700)
        for label, item in sorted(material.items()):
            runtime = runtimes / label
            runtime.mkdir(mode=0o700)
            signing_slot = f"runtime.signing.v1:{label}"
            capability_slot = f"runtime.capability.v1:{label}"
            status_capability_slot = f"runtime.capability.v1:status:{label}"
            encryption_slot = f"peer.encryption.v1:{label}"
            password = runtime_passwords[label]
            EncryptedKeystore.create(
                runtime / "custody.json",
                _password_reader(password),
                control_head=state.head,
                secrets={
                    signing_slot: item["signing_seed"],
                    capability_slot: item["capability_key"],
                    status_capability_slot: item["status_capability_key"],
                    encryption_slot: item["encryption_seed"],
                },
            )
            EncryptedKeystore.create(
                runtime / "transport-custody.json",
                _password_reader(password),
                control_head=state.head,
                secrets={f"transport.signing.v1:{label}": item["transport_seed"]},
            )
            targets = []
            for remote_label, remote in sorted(material.items()):
                if remote_label == label:
                    continue
                targets.append(
                    {
                        "embodiment_id": remote["origin"]["embodiment_id"],
                        "endpoint": remote["row"]["advertised_endpoint"],
                        "timeout_ms": 5_000,
                    }
                )
            targets.sort(key=lambda target: str(target["embodiment_id"]))
            bundle = {
                "schema": "dm.runtime.bundle/v7",
                "control_artifacts": [genesis],
                "control_head": state.head,
                "manifest": manifest.value,
                "authority_history": [],
                "credentials": list(credentials.values()),
                "incarnations": list(incarnations.values()),
                "binding": None,
                "binding_activation": None,
                "provisional_history": None,
                "local_origin": item["origin"],
                "ledger": "ledger.sqlite",
                "socket": "matrix.sock",
                "keystore": {
                    "filename": "custody.json",
                    "counter": 1,
                    "signing_slot": signing_slot,
                },
                "capabilities": [
                    {
                        "descriptor": item["capability"].descriptor,
                        "secret_slot": capability_slot,
                    },
                    {
                        "descriptor": item["status_capability"].descriptor,
                        "secret_slot": status_capability_slot,
                    },
                ],
                "routing": None,
                "scopes": {
                    "body_capabilities": [],
                    "relationships_filename": None,
                },
                "peer_transport": {
                    "enabled": True,
                    "encryption_slot": encryption_slot,
                    "exchange_filename": "peer-exchange.sqlite",
                    "listen_host": item["row"]["listen_host"],
                    "listen_port": item["row"]["listen_port"],
                    "outbox_filename": "peer-outbox.sqlite",
                    "targets": targets,
                },
                "species": None,
                "sources": {"cas_filename": "sources.sqlite3", "known_beings": []},
                "relationships": {
                    "known_being_refs": [],
                    "store_filename": "relationships.sqlite3",
                },
            }
            _private_write(runtime / "runtime.json", bundle)
            _private_write(
                runtime / "client.json",
                {
                    "schema": CLIENT_CONFIG_SCHEMA,
                    "capability": item["capability"].descriptor,
                    "expected_server": item["origin"],
                },
            )
            _private_write(runtime / "client.key", item["capability_key"])
            status_client = host_clients / label
            status_client.mkdir(mode=0o700)
            _private_write(
                status_client / "client.json",
                {
                    "schema": CLIENT_CONFIG_SCHEMA,
                    "capability": item["status_capability"].descriptor,
                    "expected_server": item["origin"],
                },
            )
            _private_write(
                status_client / "capability.key",
                item["status_capability_key"],
            )

        receipt = {
            "schema": RECEIPT_SCHEMA,
            "being_ref": state.being_ref,
            "control_head": state.head,
            "manifest_hash": manifest.digest,
            "created_at_ms": created_at_ms,
            "runtime_schema": "dm.runtime.bundle/v7",
            "embodiments": [
                {
                    "label": label,
                    "body_ref": item["origin"]["body_ref"],
                    "embodiment_id": item["origin"]["embodiment_id"],
                    "incarnation_id": item["origin"]["incarnation_id"],
                    "principal_id": item["origin"]["principal_id"],
                    "bundle_sha256": hashlib.sha256(
                        canonical_bytes(
                            json.loads((runtimes / label / "runtime.json").read_bytes())
                        )
                    ).hexdigest(),
                }
                for label, item in sorted(material.items())
            ],
        }
        _private_write(staging / "receipt.json", receipt)
        _fsync_directory(offline)
        for path in runtimes.iterdir():
            _fsync_directory(path)
        for path in host_clients.iterdir():
            _fsync_directory(path)
        _fsync_directory(runtimes)
        _fsync_directory(host_clients)
        _fsync_directory(staging)
        os.replace(staging, target)
        _fsync_directory(parent)
        return receipt
    except BaseException:
        if staging is not None and staging.exists():
            shutil.rmtree(staging)
        raise
    finally:
        root_password[:] = b"\x00" * len(root_password)
        for password in runtime_passwords.values():
            password[:] = b"\x00" * len(password)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="daimon-bootstrap", description=__doc__)
    result.add_argument("--output", type=Path, required=True)
    result.add_argument("--profile", type=Path, required=True)
    result.add_argument("--root-password-fd", type=int, required=True)
    result.add_argument(
        "--runtime-password-fd",
        action="append",
        default=[],
        metavar="LABEL=FD",
        help="one inherited password descriptor for every profile label",
    )
    return result


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = parser().parse_args(argv)
        receipt = _create(
            args.output,
            args.profile,
            args.root_password_fd,
            args.runtime_password_fd,
        )
        sys.stdout.buffer.write(canonical_bytes(receipt) + b"\n")
        return 0
    except BootstrapError as exception:
        print(str(exception), file=sys.stderr)
        return 2
    except (OSError, TypeError, ValueError):
        print("bootstrap_failed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "AUTHORITY_SCHEMA",
    "PROFILE_SCHEMA",
    "RECEIPT_SCHEMA",
    "STATUS_OBSERVER_METHODS",
    "BootstrapError",
    "main",
    "parser",
]
