"""Trusted operator provisioning of an external signed messaging application.

Never expose prepare(), renew(), or the password descriptor to an autonomous/model
tool. The daemon only verifies; it cannot renew or sign application enrollment.

Publication is a mandatory signed metadata pointer. Renewal changes that pointer
atomically while all stores and keys remain at their original paths. Run the CLI
with the daemon stopped: it takes the same runtime lock and reads the password
once. A published durability error is NOT a rollback: preserve the directory,
inspect diagnostics for its exact application_sha256, then use recover with
--expected-application-sha256. Neither recovery nor loading initializes stores.
"""

from __future__ import annotations

import copy
import ctypes
import hashlib
import json
import os
import secrets
import shutil
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from types import FrameType
from typing import Any

from .canonical import canonical_bytes
from .local_api import create_capability
from .messaging_config import (
    APPLICATION_SCHEMA,
    MessagingConfigError,
    _compose,
    _directory,
    config_digest,
    create_binding,
    load_application,
    protected_read,
    read_document,
    read_publication,
    validate_shape,
    verify_binding,
)
from .runtime import HostedRuntime
from .service import MESSAGING_METHODS


def _write(root: Path, name: str, raw: bytes) -> None:
    fd = os.open(
        root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
    )
    try:
        view = memoryview(raw)
        while view:
            written = os.write(fd, view)
            if not written:
                raise OSError()
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)


def _sync(root: Path) -> None:
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _publish(staging: Path, target: Path) -> None:
    # Linux renameat2 NOREPLACE: another provisioner must never be overwritten.
    libc = ctypes.CDLL(None, use_errno=True)
    rename = libc.renameat2
    rename.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    rename.restype = ctypes.c_int
    if rename(-100, os.fsencode(staging), -100, os.fsencode(target), 1) != 0:
        raise MessagingConfigError("messaging_destination_exists_or_unavailable")


def _publication(
    runtime: HostedRuntime, application: Any, generation: str, predecessor: str | None
) -> bytes:
    body = {
        "schema": "dm.messaging.publication/v1",
        "generation": generation,
        "application_sha256": config_digest(application),
        "predecessor_sha256": predecessor,
    }
    return canonical_bytes({"body": body, "binding": create_binding(runtime, body)})


def renew(
    runtime: HostedRuntime,
    app_directory: Path | str,
    *,
    expected_application_sha256: str,
) -> dict[str, Any]:
    """Trusted offline operator only; caller must hold the runtime daemon lock.

    Serialize operators on the app directory as well. Publish metadata only: no
    security-bearing database, transport key, or custody is copied or reset.
    The previous capability may be expired; current grants/identity may not.
    """
    import fcntl

    root = _directory(app_directory)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        previous, metadata = read_publication(runtime, root)
        if config_digest(previous) != expected_application_sha256:
            raise MessagingConfigError("messaging_renewal_conflict")
        application = copy.deepcopy(previous)
        key = protected_read(root / previous["client"]["secret_file"], size=32)
        # Verify the predecessor's client material even though its deadline may
        # have elapsed. No key rotation: callers use the same protected key path.
        old_config = read_document(metadata / "client.json")
        if (
            old_config
            != {
                "schema": "dm.local.client-config/v3",
                "capability": previous["client"]["descriptor"],
                "expected_server": dict(runtime.service.origin),
                "runtime_id": runtime.service.runtime_id,
                "runtime_label": runtime.service.runtime_label,
            }
            or hashlib.sha256(key).hexdigest() != previous["client"]["secret_sha256"]
        ):
            raise MessagingConfigError("messaging_renewal_conflict")
        now = runtime.service.clock()
        cap = create_capability(
            key,
            client_id=previous["client"]["descriptor"]["client_id"],
            methods=sorted(MESSAGING_METHODS),
            not_before_ms=now,
            not_after_ms=now + 30 * 86400000,
        )
        if (
            cap.descriptor["not_after_ms"]
            <= previous["client"]["descriptor"]["not_after_ms"]
        ):
            raise MessagingConfigError("messaging_renewal_conflict")
        application["client"]["descriptor"] = cap.descriptor
        validate_shape(application)
        generation = "generation-" + secrets.token_hex(16)
        destination = root / generation
        destination.mkdir(mode=0o700)
        # Failed candidate generations are retained for diagnosis, never selected.
        _write(destination, "application.json", canonical_bytes(application))
        _write(
            destination,
            "binding.json",
            canonical_bytes(create_binding(runtime, application)),
        )
        _write(
            destination,
            "client.json",
            canonical_bytes(
                {
                    "schema": "dm.local.client-config/v3",
                    "capability": cap.descriptor,
                    "expected_server": dict(runtime.service.origin),
                    "runtime_id": runtime.service.runtime_id,
                    "runtime_label": runtime.service.runtime_label,
                }
            ),
        )
        _compose(runtime, root, application, metadata_root=destination)
        _sync(destination)
        temporary = "publication-" + secrets.token_hex(16) + ".json"
        _write(
            root,
            temporary,
            _publication(runtime, application, generation, expected_application_sha256),
        )
        _sync(root)
        # Check again immediately before the sole visibility transition.
        current, _ = read_publication(runtime, root)
        if config_digest(current) != expected_application_sha256:
            raise MessagingConfigError("messaging_renewal_conflict")
        os.replace(root / temporary, root / "publication.json")
        try:
            _sync(root)
        except OSError:
            raise MessagingConfigError(
                "messaging_published_durability_uncertain"
            ) from None
        try:
            load_application(runtime, root)
        except Exception:
            raise MessagingConfigError(
                "messaging_published_validation_failed"
            ) from None
        return {
            "status": "renewed",
            "application_sha256": config_digest(application),
            "predecessor_sha256": expected_application_sha256,
            "client_config": generation + "/client.json",
            "client_key": "client.key",
        }
    except MessagingConfigError:
        raise
    except Exception:
        raise MessagingConfigError("messaging_renewal_rejected") from None
    finally:
        os.close(fd)


def recover(
    runtime: HostedRuntime,
    app_directory: Path | str,
    *,
    expected_application_sha256: str,
) -> dict[str, Any]:
    """Validate exact published state and retry durability, never recreate/delete it."""
    target = _directory(app_directory)
    application, _metadata = read_publication(runtime, target)
    if config_digest(application) != expected_application_sha256:
        raise MessagingConfigError("messaging_recovery_conflict")
    load_application(runtime, target)
    try:
        _sync(target)
        _sync(target.parent)
    except OSError:
        raise MessagingConfigError("messaging_published_durability_uncertain") from None
    return {"status": "configured", "application_sha256": expected_application_sha256}


def prepare(
    runtime: HostedRuntime,
    app_directory: Path | str,
    specification: Any,
    *,
    secret_sources: Mapping[str, Path | str],
) -> dict[str, Any]:
    """Provision a NEW app directory from reviewed public spec and protected keys.

    secret_sources maps each exact route secret_file to an owner-only source Path.
    Keys must already have been exchanged by an independent trusted operation.
    No grant, identity, transport key or foreign ledger is invented here.
    """
    staging = None
    try:
        target = Path(os.path.abspath(app_directory))
        _directory(target.parent)
        if target.exists() or target.is_symlink():
            raise MessagingConfigError("messaging_destination_exists_or_unavailable")
        if target == runtime.state_root or runtime.state_root in target.parents:
            raise ValueError()
        validate_shape(specification, specification=True)
        application = copy.deepcopy(specification)
        names = {
            r["secret_file"]
            for d in ("incoming", "outgoing")
            for r in application[d]["routes"].values()
        }
        if set(secret_sources) != names:
            raise ValueError()
        route_keys = {
            name: protected_read(secret_sources[name], size=32) for name in names
        }
        staging = Path(
            tempfile.mkdtemp(prefix=".messaging-prepare-", dir=target.parent)
        )
        for name, key in route_keys.items():
            _write(staging, name, key)
        key = secrets.token_bytes(32)
        now = runtime.service.clock()
        cap = create_capability(
            key,
            client_id="client:messaging:" + secrets.token_hex(16),
            methods=sorted(MESSAGING_METHODS),
            not_before_ms=now,
            not_after_ms=now + 30 * 86400000,
        )
        application["client"] = {
            "descriptor": cap.descriptor,
            "secret_file": "client.key",
            "secret_sha256": hashlib.sha256(key).hexdigest(),
        }
        validate_shape(application)
        _write(staging, "client.key", key)
        _write(
            staging,
            "client.json",
            canonical_bytes(
                {
                    "schema": "dm.local.client-config/v3",
                    "capability": cap.descriptor,
                    "expected_server": dict(runtime.service.origin),
                    "runtime_id": runtime.service.runtime_id,
                    "runtime_label": runtime.service.runtime_label,
                }
            ),
        )
        _write(staging, "application.json", canonical_bytes(application))
        _write(
            staging,
            "binding.json",
            canonical_bytes(create_binding(runtime, application)),
        )
        persisted = read_document(staging / "application.json")
        verify_binding(runtime, persisted, read_document(staging / "binding.json"))
        _compose(runtime, staging, persisted, initialize=True)
        _write(staging, "publication.json", _publication(runtime, persisted, ".", None))
        load_application(runtime, staging)
        _sync(staging)
        _publish(staging, target)
        staging = None  # rename succeeded: published state must never be cleaned up
        try:
            _sync(target.parent)
        except OSError:
            raise MessagingConfigError(
                "messaging_published_durability_uncertain"
            ) from None
        try:
            load_application(runtime, target)
        except Exception:
            raise MessagingConfigError(
                "messaging_published_validation_failed"
            ) from None
        return {
            "status": "configured",
            "application_sha256": config_digest(application),
            "schema": APPLICATION_SCHEMA,
            "runtime_id": runtime.service.runtime_id,
            "capability_id": cap.capability_id,
            "application_directory": str(target),
            "client_config": "client.json",
            "client_key": "client.key",
            "mirror_enabled": False,
        }
    except MessagingConfigError:
        raise
    except Exception:
        raise MessagingConfigError("messaging_prepare_rejected") from None
    finally:
        if staging is not None:
            shutil.rmtree(staging)


def main(argv: Sequence[str] | None = None) -> int:
    """Trusted prepare/renew/recover and read-only diagnostics/run entrypoints."""
    import argparse
    import signal
    import sys
    import threading
    import time

    from . import daemon
    from .messaging_config import read_document
    from .runtime import load_runtime

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command", choices=("prepare", "renew", "recover", "diagnostics", "run")
    )
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--bundle", default="runtime.json")
    parser.add_argument("--app-dir", type=Path, required=True)
    parser.add_argument("--password-fd", type=int, required=True)
    parser.add_argument(
        "--spec",
        type=Path,
        help="Reviewed canonical public specification (prepare only)",
    )
    parser.add_argument(
        "--secret-dir",
        type=Path,
        help="Owner-only named transport key sources (prepare only)",
    )
    parser.add_argument("--expected-application-sha256")
    parser.add_argument("--ready-fd", type=int)
    args = parser.parse_args(argv)
    lock = None
    previous_signals = {}
    try:
        if args.command in {"renew", "recover"}:
            import re

            if (
                args.ready_fd is not None
                or re.fullmatch(r"[0-9a-f]{64}", args.expected_application_sha256 or "")
                is None
            ):
                raise ValueError()
        elif args.expected_application_sha256 is not None:
            raise ValueError()
        if args.command == "prepare":
            if (
                args.spec is None
                or args.secret_dir is None
                or args.ready_fd is not None
            ):
                raise ValueError()
        elif args.spec is not None or args.secret_dir is not None:
            raise ValueError()
        root = daemon._state_root(args.state_root)
        lock = daemon.acquire_lock(root)
        runtime = load_runtime(
            root,
            args.bundle,
            daemon._password_reader(args.password_fd),
            clock=lambda: time.time_ns() // 1000000,
        )
        if args.command == "prepare":
            assert args.spec is not None and args.secret_dir is not None
            spec = read_document(args.spec)
            validate_shape(spec, specification=True)
            source_root = _directory(args.secret_dir)
            sources = {
                r["secret_file"]: source_root / r["secret_file"]
                for d in ("incoming", "outgoing")
                for r in spec[d]["routes"].values()
            }
            result = prepare(runtime, args.app_dir, spec, secret_sources=sources)
        elif args.command in {"renew", "recover"}:
            operation = renew if args.command == "renew" else recover
            result = operation(
                runtime,
                args.app_dir,
                expected_application_sha256=args.expected_application_sha256,
            )
        else:
            application, metadata = read_publication(runtime, _directory(args.app_dir))
            runtime = load_application(runtime, args.app_dir)
            if args.command == "run":
                stop = threading.Event()

                def request_stop(_number: int, _frame: FrameType | None) -> None:
                    stop.set()

                for number in (signal.SIGTERM, signal.SIGINT):
                    previous_signals[number] = signal.signal(number, request_stop)
                daemon.serve_forever(runtime, stop=stop, ready_descriptor=args.ready_fd)
                return 0
            assert runtime.service.messaging is not None
            result = {
                "status": "ready",
                "application_sha256": config_digest(application),
                "client_config": str(metadata / "client.json"),
                "client_key": str(args.app_dir / "client.key"),
                "runtime_id": runtime.service.runtime_id,
                "application_schema": APPLICATION_SCHEMA,
                "incoming_channels": sorted(runtime.service.messaging.channels),
                "outgoing_channels": sorted(runtime.service.messaging.deliveries),
                "mirror_enabled": False,
            }
        print(json.dumps(result, sort_keys=True))
        return 0
    except MessagingConfigError as error:
        print(str(error), file=sys.stderr)
        return 1
    except Exception:
        print("messaging_operator_refused", file=sys.stderr)
        return 1
    finally:
        for number, handler in previous_signals.items():
            signal.signal(number, handler)
        if lock is not None:
            os.close(lock)


if __name__ == "__main__":
    raise SystemExit(main())
