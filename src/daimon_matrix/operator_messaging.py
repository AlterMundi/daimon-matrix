"""Trusted operator provisioning of an external signed messaging application.

Never expose prepare(), renew(), republish(), or the password descriptor to an
autonomous/model tool. The daemon only verifies; it cannot renew, re-publish or sign
application enrollment.

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
import re
import secrets
import shutil
import stat
import sys
import tempfile
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from types import FrameType
from typing import Any, cast

from .authority_epochs import RootHistoryAuthority
from .canonical import canonical_bytes, unb64url
from .local_api import create_messaging_capability
from .messaging_config import (
    APPLICATION_SCHEMA,
    MessagingConfigError,
    _capability_journal_names,
    _capability_state_chain,
    _compose,
    _directory,
    _public_identity,
    _read_publication,
    _validate_store_schema,
    capability_state_record,
    config_digest,
    create_binding,
    load_application,
    protected_read,
    read_capability_state,
    read_document,
    read_publication,
    validate_shape,
    verify_binding,
    verify_binding_within_history,
    verify_public_binding,
)
from .messaging_store import MessagingInboxStore
from .native_egress import (
    VISIBILITY_SCHEMA_VERSION,
    MandatoryEgressController,
    load_owner_visibility_file,
)
from .operator_rebirth import (
    AUTHORITY_SCHEMA,
    authority_from_document,
    authority_from_runtime_bundle,
)
from .runtime import HostedRuntime, VisibilityFactory, VisibilityFactoryContext
from .service import MESSAGING_METHODS
from .weave import RootAuthority


def _application_authorities(
    application: Mapping[str, Any],
) -> dict[str, RootAuthority]:
    """Index one application's pinned authorities by being, rejecting duplicates."""

    authorities: dict[str, RootAuthority] = {}
    for document in application["authorities"]:
        authority = authority_from_document(document)
        being_ref = authority.manifest.being_ref
        if being_ref in authorities:
            raise MessagingConfigError("messaging_visibility_installation_rejected")
        authorities[being_ref] = authority
    return authorities


def _current_epoch(
    authority: RootAuthority | RootHistoryAuthority,
) -> RootAuthority:
    """Narrow a possibly history-preserving authority to its present epoch."""

    return (
        authority.active if isinstance(authority, RootHistoryAuthority) else authority
    )


def _runtime_authority(
    runtime: HostedRuntime,
) -> RootAuthority | RootHistoryAuthority:
    """One loaded runtime's authority, narrowed and fail-closed.

    The ledger types its authority more widely than the root chain this module
    signs against, so the same narrowing ``_identity`` already performs is the
    only shape accepted here.
    """

    authority = runtime.service.ledger.authority
    if not isinstance(authority, (RootAuthority, RootHistoryAuthority)):
        raise MessagingConfigError("messaging_binding_rejected")
    return authority


def _runtime_epoch(runtime: HostedRuntime) -> RootAuthority:
    """The present epoch of one loaded runtime."""

    return _current_epoch(_runtime_authority(runtime))


def _verify_visibility_participant(
    authorities: Mapping[str, RootAuthority],
    participant: str,
    document: Any,
    binding: Any,
    *,
    at_ms: int,
) -> None:
    authority = authorities[participant]
    body = binding["body"]
    identity = _public_identity(
        authority,
        body["origin"],
        body["runtime_id"],
        body["runtime_label"],
        at_ms,
    )
    credential = authority.credentials[identity["credential_id"]]
    public_key = unb64url(credential["body"]["signing_key"]["public"], length=32)
    verify_public_binding(identity, public_key, document, binding)


def _owner_visibility_controller(
    *,
    authorities: Mapping[str, RootAuthority],
    application_sha256: str,
    installation_path: Path,
    authority: RootAuthority | RootHistoryAuthority,
    origin: Mapping[str, Any],
    runtime_id: str,
    runtime_label: str,
    signer_public_key: bytes,
    clock: Callable[[], int],
    catalog_mode: str,
    presentation_resolver: Callable[[str], str] | None = None,
) -> MandatoryEgressController:
    """Bind one owner installation to a selected app and the present epoch.

    Shared by the daemon's visibility factory and by ``republish`` so that the
    verification a re-issued installation has to survive is literally the one the
    daemon applies, not a second implementation that can drift from it.
    """

    owner_identity = _public_identity(
        authority,
        origin,
        runtime_id,
        runtime_label,
        clock(),
    )
    selected_owner = authorities.get(owner_identity["being_ref"])
    # The application pins the current public authority, not the wrapper
    # that additionally verifies events from earlier credential epochs.
    if selected_owner != _current_epoch(authority):
        raise MessagingConfigError("messaging_visibility_installation_rejected")

    def verify_owner(document: Any, binding: Any) -> None:
        verify_public_binding(
            owner_identity,
            signer_public_key,
            document,
            binding,
        )

    def verify_participant(participant: str, document: Any, binding: Any) -> None:
        _verify_visibility_participant(
            authorities,
            participant,
            document,
            binding,
            at_ms=clock(),
        )

    return load_owner_visibility_file(
        installation_path,
        expected_application_sha256=application_sha256,
        verify_owner_binding=verify_owner,
        verify_participant_binding=verify_participant,
        clock=clock,
        catalog_mode=cast(Any, catalog_mode),
        presentation_resolver=presentation_resolver,
    )


def _visibility_factory(
    application: Mapping[str, Any],
    installation_path: Path,
    *,
    clock: Callable[[], int],
    catalog_mode: str,
) -> VisibilityFactory:
    """Bind an owner installation to the selected app and current authorities."""

    validate_shape(application)
    application_sha256 = config_digest(application)
    authorities = _application_authorities(application)

    def factory(context: VisibilityFactoryContext) -> MandatoryEgressController:
        return _owner_visibility_controller(
            authorities=authorities,
            application_sha256=application_sha256,
            installation_path=installation_path,
            authority=context.authority,
            origin=context.origin,
            runtime_id=context.runtime_id,
            runtime_label=context.runtime_label,
            signer_public_key=context.signer_public_key,
            clock=clock,
            presentation_resolver=context.display_identity,
            catalog_mode=catalog_mode,
        )

    return factory


def host_visibility_factory(
    app_directory: Path | str,
    installation_path: Path | str,
    *,
    clock: Callable[[], int],
) -> VisibilityFactory:
    """Verify an existing app and installation for a host under its runtime lock.

    Pass this factory to load_runtime together with read_application_authorities;
    then load_application before readiness. No signing, migration or network I/O.
    Unlike the bare daemon, the installation binds the messaging application,
    not the runtime bundle. An invalid publication fails before opening stores.
    """

    def factory(context: VisibilityFactoryContext) -> MandatoryEgressController:
        identity = _public_identity(
            context.authority,
            context.origin,
            context.runtime_id,
            context.runtime_label,
            clock(),
        )
        application, _ = _read_publication(
            _directory(app_directory),
            lambda value, binding: verify_public_binding(
                identity, context.signer_public_key, value, binding
            ),
        )
        return _visibility_factory(
            application, Path(installation_path), clock=clock, catalog_mode="validate"
        )(context)

    return factory


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


_CAPABILITY_ENTRY_STAGE_LIMIT = 8
_CAPABILITY_ENTRY_MAX_BYTES = 4 * 1024 * 1024


def _cleanup_capability_entry_staging(root: Path, final_name: str) -> None:
    """Remove only bounded, private residue for one exact journal entry."""
    prefix = final_name + ".stage-"
    pattern = re.compile(re.escape(prefix) + r"[0-9a-f]{32}$")
    candidates: list[Path] = []
    for path in root.iterdir():
        if not path.name.startswith(prefix):
            continue
        candidates.append(path)
        if len(candidates) > _CAPABILITY_ENTRY_STAGE_LIMIT:
            raise MessagingConfigError("messaging_capability_state_rejected")
    removed = False
    for path in candidates:
        if pattern.fullmatch(path.name) is None:
            raise MessagingConfigError("messaging_capability_state_rejected")
        try:
            info = path.lstat()
        except OSError as exception:
            raise MessagingConfigError(
                "messaging_capability_state_rejected"
            ) from exception
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1
            or info.st_size > _CAPABILITY_ENTRY_MAX_BYTES
        ):
            raise MessagingConfigError("messaging_capability_state_rejected")
        path.unlink()
        removed = True
    if removed:
        _sync(root)


def _publish_capability_entry(root: Path, final_name: str, raw: bytes) -> None:
    """Install complete fsynced journal bytes atomically and without replacement."""
    final_path = root / final_name
    try:
        final_path.lstat()
    except FileNotFoundError:
        pass
    except OSError as exception:
        raise MessagingConfigError("messaging_capability_state_rejected") from exception
    else:
        if protected_read(final_path) != raw:
            raise MessagingConfigError("messaging_capability_state_rejected")
        _cleanup_capability_entry_staging(root, final_name)
        _sync(root)
        return

    _cleanup_capability_entry_staging(root, final_name)
    staging_name = final_name + ".stage-" + secrets.token_hex(16)
    _write(root, staging_name, raw)
    _publish(root / staging_name, final_path)
    _sync(root)


def _initialize_capability_state(
    runtime: HostedRuntime, descriptor: Mapping[str, Any]
) -> None:
    """Publish the immutable authenticated genesis outside app generations."""
    _, stem = _capability_journal_names(runtime, descriptor)
    record = capability_state_record(
        runtime,
        descriptor,
        sequence=0,
        predecessor_sha256=None,
        action="activate",
        occurred_at_ms=runtime.service.clock(),
    )
    raw = canonical_bytes(record)
    _publish_capability_entry(
        runtime.state_root,
        stem + "-00000000000000000000.json",
        raw,
    )
    _write(runtime.state_root, stem + "-current.json", raw)
    _write(runtime.state_root, stem + "-floor.json", raw)
    _sync(runtime.state_root)
    read_capability_state(runtime, descriptor)


def _publish_capability_pointers(
    runtime: HostedRuntime,
    stem: str,
    raw: bytes,
) -> None:
    temporary = stem + "-current-" + secrets.token_hex(16) + ".json"
    floor_temporary = stem + "-floor-" + secrets.token_hex(16) + ".json"
    _write(runtime.state_root, temporary, raw)
    _write(runtime.state_root, floor_temporary, raw)
    _sync(runtime.state_root)
    os.replace(
        runtime.state_root / floor_temporary,
        runtime.state_root / (stem + "-floor.json"),
    )
    os.replace(
        runtime.state_root / temporary,
        runtime.state_root / (stem + "-current.json"),
    )
    _sync(runtime.state_root)


def _repair_capability_pointers(
    runtime: HostedRuntime,
    descriptor: Mapping[str, Any],
) -> dict[str, Any]:
    """Move interrupted pointers forward to the exact authenticated chain head."""
    _identity, stem, chain = _capability_state_chain(runtime, descriptor)
    latest, latest_raw = chain[-1]
    expected = {
        "capability_id": descriptor["capability_id"],
        "client_id": descriptor["client_id"],
        "key_id": descriptor["key_id"],
        "descriptor_sha256": config_digest(descriptor),
    }
    if any(latest[field] != value for field, value in expected.items()):
        raise MessagingConfigError("messaging_capability_stale")
    retained = {raw for _body, raw in chain}
    for suffix in ("current", "floor"):
        pointer = protected_read(runtime.state_root / f"{stem}-{suffix}.json")
        if pointer not in retained:
            raise MessagingConfigError("messaging_capability_state_rejected")
    _publish_capability_pointers(runtime, stem, latest_raw)
    return read_capability_state(runtime, descriptor, require_active=False)


def _replace_capability_state(
    runtime: HostedRuntime,
    previous_descriptor: Mapping[str, Any],
    descriptor: Mapping[str, Any],
) -> None:
    """Append the authenticated successor and durably move both high-water pointers."""
    state = read_capability_state(runtime, previous_descriptor)
    old_identity, stem = _capability_journal_names(runtime, previous_descriptor)
    new_identity, new_stem = _capability_journal_names(runtime, descriptor)
    if (
        old_identity != new_identity
        or stem != new_stem
        or previous_descriptor["client_id"] != descriptor["client_id"]
        or previous_descriptor["key_id"] != descriptor["key_id"]
    ):
        raise MessagingConfigError("messaging_capability_state_rejected")
    current = protected_read(runtime.state_root / (stem + "-current.json"))
    record = capability_state_record(
        runtime,
        descriptor,
        sequence=state["sequence"] + 1,
        predecessor_sha256=hashlib.sha256(current).hexdigest(),
        action="replace",
        occurred_at_ms=max(runtime.service.clock(), state["occurred_at_ms"]),
    )
    raw = canonical_bytes(record)
    _publish_capability_entry(
        runtime.state_root,
        stem + f"-{state['sequence'] + 1:020d}.json",
        raw,
    )
    _publish_capability_pointers(runtime, stem, raw)
    read_capability_state(runtime, descriptor)


def _publish(staging: Path, target: Path) -> None:
    # Never emulate exclusive publication with exists()+rename(): another
    # provisioner could create even an empty destination between those calls.
    if sys.platform not in {"linux", "darwin"}:
        raise MessagingConfigError("messaging_exclusive_publication_unsupported")
    libc = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "darwin":
        # Apple's <sys/stdio.h>: renamex_np(..., RENAME_EXCL=0x4).
        rename = getattr(libc, "renamex_np", None)
        arguments = (os.fsencode(staging), os.fsencode(target), 0x4)
        types = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
    else:
        rename = getattr(libc, "renameat2", None)
        arguments = (-100, os.fsencode(staging), -100, os.fsencode(target), 1)
        types = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
    if rename is None:
        raise MessagingConfigError("messaging_exclusive_publication_unsupported")
    rename.argtypes = types
    rename.restype = ctypes.c_int
    if rename(*arguments) != 0:
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


def upgrade_semantic_receipts(
    runtime: HostedRuntime,
    app_directory: Path | str,
    *,
    expected_application_sha256: str,
) -> dict[str, Any]:
    """Offline, runtime-lock-held V1 -> V2 successor; never a model RPC.

    Metadata staging precedes the irreversible schema transition. Exact retry
    selects the same signed successor after interruption. No store/key is copied.
    A communication anchor mismatch remains a recovery error, not permission to
    reconstruct history. The V1 binding domain already signs the application hash.
    """
    import fcntl

    from .messaging_config import APPLICATION_SCHEMA_V2

    root = _directory(app_directory)

    def upgrade_inbox_admission(application: Mapping[str, Any]) -> None:
        for name in ("inbox", "outgoing-context"):
            path = root / application["stores"][name]
            _validate_store_schema(name, path)
            MessagingInboxStore.upgrade_admission_path(path)

    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        previous, metadata = read_publication(runtime, root)
        publication = read_document(root / "publication.json")
        if previous["schema"] == APPLICATION_SCHEMA_V2:
            if publication["body"]["predecessor_sha256"] != expected_application_sha256:
                raise MessagingConfigError("messaging_semantic_migration_conflict")
            upgrade_inbox_admission(previous)
            load_application(runtime, root)
            _sync(root)
            return {
                "status": "semantic-v2",
                "application_sha256": config_digest(previous),
                "predecessor_sha256": expected_application_sha256,
            }
        if config_digest(previous) != expected_application_sha256:
            raise MessagingConfigError("messaging_semantic_migration_conflict")
        communication = runtime.service.communication
        assert communication is not None
        application = {**previous, "schema": APPLICATION_SCHEMA_V2}
        validate_shape(application)
        digest = config_digest(application)
        generation = "generation-" + digest[:32]
        destination = root / generation
        # An already staged exact generation is continuation evidence, not new
        # admission. Always reverify its signature and exact predecessor bytes.
        if destination.exists():
            if read_document(
                destination / "application.json"
            ) != application or protected_read(
                destination / "client.json"
            ) != protected_read(metadata / "client.json"):
                raise MessagingConfigError("messaging_semantic_migration_conflict")
            verify_binding(
                runtime, application, read_document(destination / "binding.json")
            )
            staged_publication = read_document(destination / "successor.json")
            verify_binding(
                runtime, staged_publication["body"], staged_publication["binding"]
            )
            if staged_publication["body"] != {
                "schema": "dm.messaging.publication/v1",
                "generation": generation,
                "application_sha256": digest,
                "predecessor_sha256": expected_application_sha256,
            }:
                raise MessagingConfigError("messaging_semantic_migration_conflict")
        else:
            if communication.receipts_v2:
                raise MessagingConfigError(
                    "messaging_semantic_migration_evidence_missing"
                )
            load_application(
                runtime, root
            )  # complete predecessor/current authority validation
            # Finish V1 reserved authoring before switching producer request hashes.
            import sqlite3
            from contextlib import closing

            with closing(
                sqlite3.connect(
                    (root / previous["stores"]["outbox"]).as_uri() + "?mode=ro",
                    uri=True,
                )
            ) as database:
                for (raw_plan,) in database.execute(
                    "SELECT plan FROM messaging_outbox WHERE evidence IS NULL"
                ):
                    deadline = json.loads(raw_plan).get("expires_at_ms")
                    # Expired reservations remain byte-identical and nonrenewable;
                    # they cannot prevent migration forever or authorize new work.
                    if type(deadline) is not int or deadline > runtime.service.clock():
                        raise MessagingConfigError(
                            "messaging_semantic_migration_drain_required"
                        )
            staging = Path(tempfile.mkdtemp(prefix="semantic-stage-", dir=root))
            _write(staging, "application.json", canonical_bytes(application))
            _write(
                staging,
                "binding.json",
                canonical_bytes(create_binding(runtime, application)),
            )
            _write(staging, "client.json", protected_read(metadata / "client.json"))
            _write(
                staging,
                "successor.json",
                _publication(
                    runtime, application, generation, expected_application_sha256
                ),
            )
            _sync(staging)
            _publish(staging, destination)
            _sync(root)
        # This is the durable V2 admission boundary. Existing authenticated rows
        # become explicit V1 rows before the communication schema can commit V2.
        upgrade_inbox_admission(previous)
        if not communication.receipts_v2:
            communication.upgrade_receipts_v2()
        # Catalogs, current grants, and exact client material before selection.
        _compose(runtime, root, application, metadata_root=destination)
        temporary = "publication-" + secrets.token_hex(16) + ".json"
        _write(root, temporary, protected_read(destination / "successor.json"))
        _sync(root)
        current, _ = read_publication(runtime, root)
        if config_digest(current) != expected_application_sha256:
            raise MessagingConfigError("messaging_semantic_migration_conflict")
        os.replace(root / temporary, root / "publication.json")
        try:
            _sync(root)
        except OSError:
            raise MessagingConfigError(
                "messaging_published_durability_uncertain"
            ) from None
        load_application(runtime, root)
        return {
            "status": "semantic-v2",
            "application_sha256": digest,
            "predecessor_sha256": expected_application_sha256,
        }
    finally:
        os.close(fd)


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
        cap = create_messaging_capability(
            key,
            client_id=previous["client"]["descriptor"]["client_id"],
            methods=sorted(MESSAGING_METHODS),
            not_before_ms=now,
        )
        if (
            previous["client"]["descriptor"]["schema"] == "dm.local.capability/v2"
            and now <= previous["client"]["descriptor"]["validity"]["not_before_ms"]
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
        _compose(
            runtime,
            root,
            application,
            metadata_root=destination,
            capability_predecessor=previous["client"]["descriptor"],
        )
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
        _replace_capability_state(
            runtime, previous["client"]["descriptor"], cap.descriptor
        )
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


def revoke_capability(
    runtime: HostedRuntime,
    app_directory: Path | str,
    *,
    expected_application_sha256: str,
) -> dict[str, Any]:
    """Irreversibly revoke one published messaging capability while offline."""
    import fcntl

    root = _directory(app_directory)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        application, _ = read_publication(runtime, root)
        if config_digest(application) != expected_application_sha256:
            raise MessagingConfigError("messaging_capability_revocation_conflict")
        descriptor = application["client"]["descriptor"]
        try:
            state = read_capability_state(runtime, descriptor, require_active=False)
        except MessagingConfigError as exception:
            if str(exception) != "messaging_capability_state_rejected":
                raise
            state = _repair_capability_pointers(runtime, descriptor)
        if state["action"] == "revoke":
            return {
                "status": "revoked",
                "application_sha256": expected_application_sha256,
                "capability_id": descriptor["capability_id"],
                "sequence": state["sequence"],
            }
        _, stem = _capability_journal_names(runtime, descriptor)
        current = protected_read(runtime.state_root / (stem + "-current.json"))
        record = capability_state_record(
            runtime,
            descriptor,
            sequence=state["sequence"] + 1,
            predecessor_sha256=hashlib.sha256(current).hexdigest(),
            action="revoke",
            occurred_at_ms=max(runtime.service.clock(), state["occurred_at_ms"]),
        )
        raw = canonical_bytes(record)
        entry_name = stem + f"-{state['sequence'] + 1:020d}.json"
        _publish_capability_entry(runtime.state_root, entry_name, raw)
        _publish_capability_pointers(runtime, stem, raw)
        confirmed = read_capability_state(runtime, descriptor, require_active=False)
        if confirmed["action"] != "revoke":
            raise MessagingConfigError("messaging_capability_state_rejected")
        return {
            "status": "revoked",
            "application_sha256": expected_application_sha256,
            "capability_id": descriptor["capability_id"],
            "sequence": confirmed["sequence"],
        }
    except MessagingConfigError:
        raise
    except Exception:
        raise MessagingConfigError("messaging_capability_revocation_rejected") from None
    finally:
        os.close(fd)


def _published_predecessor_descriptor(
    runtime: HostedRuntime,
    root: Path,
    application: Mapping[str, Any],
) -> Mapping[str, Any]:
    """Recover the exact signed predecessor selected by publication metadata."""
    publication = read_document(root / "publication.json")
    predecessor_sha256 = publication["body"]["predecessor_sha256"]
    if predecessor_sha256 is None:
        raise MessagingConfigError("messaging_capability_state_rejected")
    matches: list[Mapping[str, Any]] = []
    metadata_roots = [root]
    for candidate in root.iterdir():
        if candidate.name.startswith("generation-") and candidate.is_dir():
            metadata_roots.append(_directory(candidate))
    for metadata_root in metadata_roots:
        candidate_path = metadata_root / "application.json"
        if not candidate_path.exists():
            continue
        candidate = read_document(candidate_path)
        if config_digest(candidate) != predecessor_sha256:
            continue
        validate_shape(candidate)
        verify_binding(
            runtime,
            candidate,
            read_document(metadata_root / "binding.json"),
        )
        matches.append(candidate)
    if not matches or any(candidate != matches[0] for candidate in matches[1:]):
        raise MessagingConfigError("messaging_capability_state_rejected")
    predecessor = matches[0]["client"]["descriptor"]
    descriptor = application["client"]["descriptor"]
    if (
        predecessor["client_id"] != descriptor["client_id"]
        or predecessor["key_id"] != descriptor["key_id"]
    ):
        raise MessagingConfigError("messaging_capability_state_rejected")
    return cast(Mapping[str, Any], predecessor)


def recover(
    runtime: HostedRuntime,
    app_directory: Path | str,
    *,
    expected_application_sha256: str,
) -> dict[str, Any]:
    """Validate exact published state and finish an interrupted renewal journal."""
    import fcntl

    target = _directory(app_directory)
    fd = os.open(target, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        application, _metadata = read_publication(runtime, target)
        if config_digest(application) != expected_application_sha256:
            raise MessagingConfigError("messaging_recovery_conflict")
        try:
            load_application(runtime, target)
        except MessagingConfigError as exception:
            if str(exception) == "messaging_capability_stale":
                predecessor = _published_predecessor_descriptor(
                    runtime, target, application
                )
                _replace_capability_state(
                    runtime,
                    predecessor,
                    application["client"]["descriptor"],
                )
            elif str(exception) == "messaging_capability_state_rejected":
                state = _repair_capability_pointers(
                    runtime, application["client"]["descriptor"]
                )
                if state["action"] == "revoke":
                    raise MessagingConfigError("messaging_capability_revoked") from None
            else:
                raise
            load_application(runtime, target)
        try:
            _sync(target)
            _sync(target.parent)
        except OSError:
            raise MessagingConfigError(
                "messaging_published_durability_uncertain"
            ) from None
        return {
            "status": "configured",
            "application_sha256": expected_application_sha256,
        }
    finally:
        os.close(fd)


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
        cap = create_messaging_capability(
            key,
            client_id="client:messaging:" + secrets.token_hex(16),
            methods=sorted(MESSAGING_METHODS),
            not_before_ms=now,
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
        _initialize_capability_state(runtime, cap.descriptor)
        existing_catalogs = runtime.egress.registered_catalog_ids()
        _compose(runtime, staging, persisted, initialize=True)
        if runtime.egress.catalog_mode == "migrate" and runtime.egress.release_enabled:
            new_catalogs = runtime.egress.registered_catalog_ids() - existing_catalogs
            runtime.egress.migrate_registered_catalogs(
                new_catalogs, version=VISIBILITY_SCHEMA_VERSION
            )
            runtime.egress.validate_registered_catalogs(new_catalogs)
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


def _current_authority_document(
    runtime: HostedRuntime, bundle_name: str = "runtime.json"
) -> dict[str, Any]:
    """Project the runtime's present epoch as one public authority document.

    Reads public bundle data only. The projection is verified twice before it is
    returned: it must parse as an authority document, and both it and the bundle
    it came from must equal the epoch the loaded runtime is actually serving, so
    a stale file on disk can never be published as the present epoch.
    """

    from .runtime import _read_bundle, _safe_file

    bundle = _read_bundle(
        _safe_file(Path(runtime.state_root), bundle_name, must_exist=True)
    )
    document: dict[str, Any] = {
        "schema": AUTHORITY_SCHEMA,
        **{
            key: bundle[key]
            for key in (
                "control_artifacts",
                "control_head",
                "manifest",
                "credentials",
                "incarnations",
            )
        },
    }
    projected = authority_from_document(document)
    current = _runtime_epoch(runtime)
    if (
        projected != current
        or _current_epoch(authority_from_runtime_bundle(bundle)) != current
    ):
        raise MessagingConfigError("messaging_republish_epoch_mismatch")
    return document


def _reissue_installation(
    runtime: HostedRuntime,
    installation: Path | str,
    *,
    application_sha256: str,
) -> dict[str, Any]:
    """Re-sign one owner installation against a new application digest.

    A manifest advance moves the epoch that the owner's own attestations name, so
    two owner-side pins have to be re-issued: the installation's
    ``application_sha256``, and the owner's entry in ``acceptance_set.bindings``,
    which is a binding over the disclosure signed by this same embodiment key and
    therefore carries the epoch's manifest digest in its body.

    Everything a foreign participant accepted is carried over byte-identical. The
    ``disclosure`` does not change, so ``acceptance_set.disclosure_sha256`` does not
    change, and every binding whose actor is not this being still verifies against
    exactly the bytes it was issued over. No foreign acceptance is re-requested,
    widened, or silently reused for a different disclosure: what moves is
    owner-local authority over an unchanged disclosure.

    The installation generation advances because the policy's acceptance digest
    changed, which also fail-closes any echo retry command issued against the
    previous installation instead of letting it resolve ambiguously against a
    policy that is no longer current.

    The installation being replaced is kept beside the new one, so the operation
    stays reversible together with the runtime bundle it was issued under.
    """

    path = Path(os.path.abspath(installation))
    directory = _directory(path.parent)
    envelope = read_document(path)
    if not isinstance(envelope, dict) or set(envelope) != {"document", "binding"}:
        raise MessagingConfigError("messaging_visibility_installation_rejected")
    previous = envelope["document"]
    if not isinstance(previous, dict) or set(previous) != {
        "schema",
        "generation",
        "runtime_id",
        "application_sha256",
        "disclosure",
        "acceptance_set",
        "policy",
        "secrets",
        "telegram_qualification",
    }:
        raise MessagingConfigError("messaging_visibility_installation_rejected")
    if previous["application_sha256"] == application_sha256:
        return {
            "reissued": False,
            "installation_sha256": config_digest(previous),
        }
    # The installation being replaced must be authentic at the epoch it names.
    verify_binding_within_history(runtime, previous, envelope["binding"])

    being_ref = _runtime_epoch(runtime).manifest.being_ref
    if (
        previous["schema"] != "dm.messaging.visibility-installation/v1"
        or type(previous["generation"]) is not int
        or previous["runtime_id"] != runtime.service.runtime_id
    ):
        raise MessagingConfigError("messaging_visibility_installation_rejected")
    disclosure = previous["disclosure"]
    acceptance = previous["acceptance_set"]
    policy = previous["policy"]
    participants = disclosure["participants"]
    bindings = acceptance["bindings"]
    if (
        not isinstance(participants, list)
        or not isinstance(bindings, list)
        or len(bindings) != len(participants)
        or participants.count(being_ref) != 1
        or acceptance["disclosure_sha256"] != config_digest(disclosure)
        or policy["generation"] != previous["generation"]
        or policy["acceptance_digest"] != config_digest(acceptance)
    ):
        raise MessagingConfigError("messaging_visibility_installation_rejected")

    owner_index = participants.index(being_ref)
    foreign_before = [row for i, row in enumerate(bindings) if i != owner_index]
    # The owner re-attests the very same disclosure at the present epoch.
    successor_bindings = list(bindings)
    successor_bindings[owner_index] = create_binding(runtime, disclosure)
    successor_acceptance = {**acceptance, "bindings": successor_bindings}
    generation = previous["generation"] + 1
    document = {
        **previous,
        "generation": generation,
        "application_sha256": application_sha256,
        "acceptance_set": successor_acceptance,
        "policy": {
            **policy,
            "generation": generation,
            "acceptance_digest": config_digest(successor_acceptance),
        },
    }
    # Only owner-side pins moved. Everything a foreign participant accepted, and
    # every secret reference and qualification evidence, is carried over exactly.
    if (
        document["disclosure"] != previous["disclosure"]
        or document["secrets"] != previous["secrets"]
        or document["telegram_qualification"] != previous["telegram_qualification"]
        or successor_acceptance["disclosure_sha256"] != acceptance["disclosure_sha256"]
        or [row for i, row in enumerate(successor_bindings) if i != owner_index]
        != foreign_before
    ):
        raise MessagingConfigError("messaging_visibility_installation_rejected")

    successor = {"document": document, "binding": create_binding(runtime, document)}
    backup = path.with_name(path.name + ".pre-republish-" + secrets.token_hex(8))
    _write(directory, backup.name, canonical_bytes(envelope))
    temporary = ".installation-" + secrets.token_hex(16) + ".json"
    _write(directory, temporary, canonical_bytes(successor))
    _sync(directory)
    os.replace(directory / temporary, path)
    try:
        _sync(directory)
    except OSError:
        raise MessagingConfigError("messaging_published_durability_uncertain") from None
    return {
        "reissued": True,
        "installation_sha256": config_digest(document),
        "installation_generation": generation,
        "foreign_acceptances_preserved": len(foreign_before),
        "previous_installation_backup": backup.name,
    }


def republish(
    runtime: HostedRuntime,
    app_directory: Path | str,
    *,
    installation: Path | None = None,
    bundle_name: str = "runtime.json",
) -> dict[str, Any]:
    """Re-publish the current application against the runtime's present epoch.

    Enrolling another embodiment advances the being manifest, and an application
    publication together with its visibility installation are current-state
    documents that deliberately pin the epoch they were issued under. Nothing else
    about them is stale, so one enrollment used to strand a working link with no
    supported repair: ``renew``, ``recover`` and ``migrate-visibility`` all begin
    from a publication verified against the *current* epoch, and therefore refuse
    the very document that needs repairing.

    This derives one successor from the published application changing exactly one
    field: the local being's entry in ``authorities``, replaced by the present
    epoch's public authority document. Routes, stores, ``relationship_mode``, the
    client descriptor and every secret reference are carried over untouched, and no
    capability is re-minted and no key is rotated -- that is ``renew``, not this.

    The previous publication is first proved authentic with
    ``verify_binding_within_history``, so the successor is derived from a document
    this same embodiment signing key really issued at the epoch it names. An
    unverified file on disk is not a predecessor.

    Idempotent: when the published application already pins the present epoch the
    call reports the current digest and appends no generation.
    """

    import fcntl

    root = _directory(app_directory)
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        current_authority = _runtime_epoch(runtime)
        being_ref = current_authority.manifest.being_ref
        current_document = _current_authority_document(runtime, bundle_name)

        publication = read_document(root / "publication.json")
        previous, metadata = _read_publication(root, lambda _document, _binding: None)
        if not isinstance(publication, dict) or set(publication) != {"body", "binding"}:
            raise MessagingConfigError("messaging_publication_rejected")
        verify_binding_within_history(
            runtime, previous, read_document(metadata / "binding.json")
        )
        verify_binding_within_history(
            runtime, publication["body"], publication["binding"]
        )
        predecessor_sha256 = config_digest(previous)
        if publication["body"]["application_sha256"] != predecessor_sha256:
            raise MessagingConfigError("messaging_republish_conflict")

        successor = copy.deepcopy(previous)
        replaced = [
            index
            for index, entry in enumerate(successor["authorities"])
            if authority_from_document(entry).manifest.being_ref == being_ref
        ]
        if len(replaced) != 1 or set(previous) != set(successor):
            raise MessagingConfigError("messaging_republish_conflict")
        successor["authorities"][replaced[0]] = copy.deepcopy(current_document)
        # Exactly one authority entry may differ, and nothing else at all. A
        # re-publication is not a way to smuggle in a route, a store or a client.
        if any(
            key != "authorities" and previous[key] != successor[key] for key in previous
        ):
            raise MessagingConfigError("messaging_republish_conflict")
        if successor == previous:
            return {
                "status": "current",
                "schema": APPLICATION_SCHEMA,
                "application_sha256": predecessor_sha256,
                "generation": publication["body"]["generation"],
                "manifest_revision": current_authority.manifest.value["revision"],
                "installation": {"reissued": False},
            }
        validate_shape(successor)

        generation = "generation-" + secrets.token_hex(16)
        destination = root / generation
        destination.mkdir(mode=0o700)
        # Failed candidate generations are retained for diagnosis, never selected.
        _write(destination, "application.json", canonical_bytes(successor))
        _write(
            destination,
            "binding.json",
            canonical_bytes(create_binding(runtime, successor)),
        )
        client_config = {
            "schema": "dm.local.client-config/v3",
            "capability": successor["client"]["descriptor"],
            "expected_server": dict(runtime.service.origin),
            "runtime_id": runtime.service.runtime_id,
            "runtime_label": runtime.service.runtime_label,
        }
        if read_document(metadata / "client.json") != client_config:
            raise MessagingConfigError("messaging_republish_conflict")
        _write(destination, "client.json", canonical_bytes(client_config))
        _sync(destination)

        successor_sha256 = config_digest(successor)
        temporary = "publication-" + secrets.token_hex(16) + ".json"
        _write(
            root,
            temporary,
            _publication(runtime, successor, generation, predecessor_sha256),
        )
        _sync(root)
        # Check again immediately before the sole visibility transition.
        if (
            read_document(root / "publication.json")["body"]["application_sha256"]
            != predecessor_sha256
        ):
            raise MessagingConfigError("messaging_republish_conflict")
        os.replace(root / temporary, root / "publication.json")
        try:
            _sync(root)
        except OSError:
            raise MessagingConfigError(
                "messaging_published_durability_uncertain"
            ) from None

        installation_result: dict[str, Any] = {"reissued": False}
        if installation is not None:
            installation_result = _reissue_installation(
                runtime, installation, application_sha256=successor_sha256
            )

        # Read back what is now published, verifying against the present epoch, and
        # then prove the installation survives the daemon's own check.
        republished, republished_metadata = read_publication(runtime, root)
        if (
            config_digest(republished) != successor_sha256
            or republished_metadata.name != generation
        ):
            raise MessagingConfigError("messaging_republish_conflict")
        if installation is not None:
            _owner_visibility_controller(
                authorities=_application_authorities(republished),
                application_sha256=successor_sha256,
                installation_path=Path(installation),
                authority=_runtime_authority(runtime),
                origin=runtime.service.origin,
                runtime_id=runtime.service.runtime_id,
                runtime_label=runtime.service.runtime_label,
                signer_public_key=runtime.service.signer.public_key,
                clock=runtime.service.clock,
                catalog_mode="validate",
            )
        return {
            "status": "republished",
            "schema": APPLICATION_SCHEMA,
            "previous_application_sha256": predecessor_sha256,
            "application_sha256": successor_sha256,
            "generation": generation,
            "manifest_revision": current_authority.manifest.value["revision"],
            "runtime_id": runtime.service.runtime_id,
            "installation": installation_result,
        }
    except MessagingConfigError:
        raise
    except Exception:
        raise MessagingConfigError("messaging_republish_rejected") from None
    finally:
        os.close(descriptor)


def visibility_presentation(
    runtime: HostedRuntime,
    app_directory: Path | None,
    installation: Path,
    *,
    command: str,
    representation: str | None = None,
    proposal: Mapping[str, Any] | None = None,
    bundle_name: str = "runtime.json",
) -> dict[str, Any]:
    """Offline same-audience successor, signed by each existing participant.

    Propose/accept/apply require the existing runtime lock. The old installation
    is authenticated first. Only issued time and versioned representation may
    change in the shared disclosure; credentials, audience, channels, stores,
    keys, qualification and retained proof bytes remain in their existing homes.
    """
    from .telegram_mirror import REPRESENTATIONS

    root = _directory(installation.parent)
    if app_directory is None:
        if Path(bundle_name).name != bundle_name:
            raise MessagingConfigError("messaging_visibility_presentation_invalid")
        application_sha256 = config_digest(
            read_document(runtime.state_root / bundle_name)
        )
        authority = _runtime_epoch(runtime)
        authorities = {authority.manifest.being_ref: authority}
    else:
        application, _ = read_publication(runtime, _directory(app_directory))
        application_sha256 = config_digest(application)
        authorities = _application_authorities(application)
    previous_envelope = read_document(installation)
    previous = previous_envelope["document"]
    controller = _owner_visibility_controller(
        authorities=authorities,
        application_sha256=application_sha256,
        installation_path=installation,
        authority=_runtime_authority(runtime),
        origin=runtime.service.origin,
        runtime_id=runtime.service.runtime_id,
        runtime_label=runtime.service.runtime_label,
        signer_public_key=runtime.service.signer.public_key,
        clock=runtime.service.clock,
        catalog_mode="validate",
    )
    if controller.installation_digest != config_digest(previous):
        raise MessagingConfigError("messaging_visibility_presentation_conflict")
    owner = _runtime_epoch(runtime).manifest.being_ref
    if command == "visibility-propose":
        if proposal is not None or representation not in REPRESENTATIONS:
            raise MessagingConfigError("messaging_visibility_presentation_invalid")
        disclosure = copy.deepcopy(previous["disclosure"])
        disclosure["issued_at_ms"] = runtime.service.clock()
        disclosure["destination"]["representation"] = representation
        return {
            "schema": "dm.messaging.presentation-proposal/v1",
            "disclosure": disclosure,
            "bindings": [create_binding(runtime, disclosure)],
            "predecessor": {
                "disclosure": previous["disclosure"],
                "acceptance_set": previous["acceptance_set"],
            },
        }
    if (
        command not in {"visibility-accept", "visibility-apply"}
        or proposal is None
        or representation is not None
        or set(proposal) != {"schema", "disclosure", "bindings", "predecessor"}
        or proposal["schema"] != "dm.messaging.presentation-proposal/v1"
    ):
        raise MessagingConfigError("messaging_visibility_presentation_invalid")
    predecessor = proposal["predecessor"]
    if not isinstance(predecessor, dict) or set(predecessor) != {
        "disclosure",
        "acceptance_set",
    }:
        raise MessagingConfigError("messaging_visibility_presentation_invalid")
    old_disclosure = predecessor["disclosure"]
    old_acceptance = predecessor["acceptance_set"]
    current = previous["disclosure"]
    pins = ("bot_id", "chat_id", "topic_id")
    if (
        set(old_disclosure) != set(current)
        or set(old_disclosure["destination"]) != set(current["destination"])
        or canonical_bytes({key: old_disclosure["destination"][key] for key in pins})
        != canonical_bytes({key: current["destination"][key] for key in pins})
        or old_disclosure["participants"] != current["participants"]
        or old_disclosure["schema"] != current["schema"]
        or old_disclosure["risk"] != current["risk"]
        or old_disclosure["scope"]["mode"] != current["scope"]["mode"]
        or old_disclosure["scope"]["projected_content"]
        != current["scope"]["projected_content"]
        or old_disclosure["scope_sha256"] != config_digest(old_disclosure["scope"])
        or set(old_acceptance) != {"schema", "disclosure_sha256", "bindings"}
        or old_acceptance["schema"] != "dm.messaging.visibility-acceptance-set/v1"
        or old_acceptance["disclosure_sha256"] != config_digest(old_disclosure)
        or len(old_acceptance["bindings"]) != len(current["participants"])
    ):
        raise MessagingConfigError("messaging_visibility_presentation_scope_change")
    # Each endpoint has a different directional disclosure. Existing acceptance
    # by ALL participants authenticates that exact predecessor; the peer's local
    # directional configuration is never replaced by the foreign one.
    for actor, binding in zip(
        current["participants"], old_acceptance["bindings"], strict=True
    ):
        if binding["body"]["being_ref"] != actor:
            raise MessagingConfigError("messaging_visibility_presentation_invalid")
        _verify_visibility_participant(
            authorities, actor, old_disclosure, binding, at_ms=runtime.service.clock()
        )
    disclosure = proposal["disclosure"]
    expected = copy.deepcopy(old_disclosure)
    expected["destination"]["representation"] = disclosure["destination"][
        "representation"
    ]
    expected["issued_at_ms"] = disclosure["issued_at_ms"]
    if (
        expected != disclosure
        or expected["destination"]["representation"] not in REPRESENTATIONS
        or type(disclosure["issued_at_ms"]) is not int
        or not old_disclosure["issued_at_ms"]
        <= disclosure["issued_at_ms"]
        <= runtime.service.clock()
        or not isinstance(proposal["bindings"], list)
        or not 1 <= len(proposal["bindings"]) <= len(disclosure["participants"])
    ):
        raise MessagingConfigError("messaging_visibility_presentation_scope_change")
    bindings = {}
    for binding in proposal["bindings"]:
        actor = binding["body"]["being_ref"]
        if actor not in disclosure["participants"] or actor in bindings:
            raise MessagingConfigError("messaging_visibility_presentation_invalid")
        _verify_visibility_participant(
            authorities, actor, disclosure, binding, at_ms=runtime.service.clock()
        )
        bindings[actor] = binding
    if command == "visibility-accept":
        bindings[owner] = create_binding(runtime, disclosure)
        return {**proposal, "bindings": [bindings[actor] for actor in sorted(bindings)]}
    if set(bindings) != set(disclosure["participants"]):
        raise MessagingConfigError(
            "messaging_visibility_presentation_acceptance_missing"
        )
    acceptance = {
        "schema": "dm.messaging.visibility-acceptance-set/v1",
        "disclosure_sha256": config_digest(disclosure),
        "bindings": [bindings[actor] for actor in disclosure["participants"]],
    }
    if disclosure == previous["disclosure"]:
        if acceptance != previous["acceptance_set"]:
            raise MessagingConfigError("messaging_visibility_presentation_conflict")
        return {"status": "unchanged", "installation_sha256": config_digest(previous)}
    if (
        old_disclosure != previous["disclosure"]
        or old_acceptance != previous["acceptance_set"]
    ):
        raise MessagingConfigError("messaging_visibility_presentation_conflict")
    generation = previous["generation"] + 1
    document = {
        **previous,
        "generation": generation,
        "disclosure": disclosure,
        "acceptance_set": acceptance,
        "policy": {
            **previous["policy"],
            "generation": generation,
            "representation": disclosure["destination"]["representation"],
            "acceptance_digest": config_digest(acceptance),
        },
    }
    successor = {"document": document, "binding": create_binding(runtime, document)}
    temporary = root / (".presentation-" + secrets.token_hex(16) + ".json")
    try:
        _write(root, temporary.name, canonical_bytes(successor))
        # Validate the complete candidate through the production signature,
        # qualification and policy loader BEFORE changing the selected file.
        _owner_visibility_controller(
            authorities=authorities,
            application_sha256=application_sha256,
            installation_path=temporary,
            authority=_runtime_authority(runtime),
            origin=runtime.service.origin,
            runtime_id=runtime.service.runtime_id,
            runtime_label=runtime.service.runtime_label,
            signer_public_key=runtime.service.signer.public_key,
            clock=runtime.service.clock,
            catalog_mode="validate",
        )
        if read_document(installation) != previous_envelope:
            raise MessagingConfigError("messaging_visibility_presentation_conflict")
        backup = installation.name + ".pre-presentation-" + secrets.token_hex(8)
        _write(root, backup, canonical_bytes(previous_envelope))
        _sync(root)
        os.replace(temporary, installation)
        try:
            _sync(root)
        except OSError:
            raise MessagingConfigError(
                "messaging_published_durability_uncertain"
            ) from None
    finally:
        temporary.unlink(missing_ok=True)
    return {
        "status": "presentation-selected",
        "representation": document["policy"]["representation"],
        "installation_sha256": config_digest(document),
        "generation": generation,
        "previous_installation_backup": backup,
        "audience_unchanged": True,
        "proof_key_preserved": True,
    }


def main(argv: Sequence[str] | None = None) -> int:
    """Trusted prepare/renew/revoke/recover and read-only operator entrypoints."""
    import argparse
    import signal
    import sys
    import threading
    import time

    from . import daemon
    from .messaging_config import read_document
    from .native_egress import closed_visibility
    from .runtime import load_runtime

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command",
        choices=(
            "prepare",
            "visibility-propose",
            "visibility-accept",
            "visibility-apply",
            "migrate-visibility",
            "renew",
            "republish",
            "revoke",
            "recover",
            "diagnostics",
            "run",
        ),
    )
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--bundle", default="runtime.json")
    parser.add_argument("--app-dir", type=Path)
    parser.add_argument("--password-fd", type=int, required=True)
    parser.add_argument("--visibility-installation", type=Path)
    parser.add_argument("--visibility-schema-version", type=int)
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
    parser.add_argument("--proposal", type=Path)
    parser.add_argument(
        "--representation",
        choices=("plain-json/v2", "compact-html/v1", "compact-text/v1"),
    )
    parser.add_argument("--output", type=Path)
    parser.add_argument("--ready-fd", type=int)
    args = parser.parse_args(argv)
    lock = None
    previous_signals = {}
    try:
        presentation_command = args.command.startswith("visibility-")
        if not presentation_command and args.app_dir is None:
            raise ValueError()
        if presentation_command:
            if args.ready_fd is not None or args.visibility_installation is None:
                raise ValueError()
            if args.command == "visibility-propose":
                if (
                    args.representation is None
                    or args.proposal is not None
                    or args.output is None
                ):
                    raise ValueError()
            elif (
                args.proposal is None
                or args.representation is not None
                or (args.command == "visibility-accept" and args.output is None)
            ):
                raise ValueError()
        elif (
            args.proposal is not None
            or args.representation is not None
            or args.output is not None
        ):
            raise ValueError()
        if args.command == "republish":
            # A re-publication is derived from what is already published, so it
            # takes no expected digest, and it never serves traffic.
            if (
                args.ready_fd is not None
                or args.expected_application_sha256 is not None
            ):
                raise ValueError()
        elif args.command in {"renew", "revoke", "recover"}:
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
        if (
            args.command not in {"prepare", "republish"}
            and args.visibility_installation is None
        ):
            raise ValueError()
        if args.command == "migrate-visibility":
            if (
                args.visibility_schema_version != VISIBILITY_SCHEMA_VERSION
                or args.ready_fd is not None
            ):
                raise ValueError()
        elif args.visibility_schema_version is not None:
            raise ValueError()
        root = daemon._state_root(args.state_root)
        lock = daemon.acquire_lock(root)

        def clock() -> int:
            return time.time_ns() // 1000000

        if presentation_command and args.app_dir is None:
            visibility = None
            visibility_factory = daemon._visibility_factory(
                args.visibility_installation, clock=clock
            )
        elif presentation_command or args.command in {"prepare", "republish"}:
            # Signing an app presentation must not authenticate the base native
            # catalogs with that app's different proof key. The closed bootstrap
            # cannot send and leaves catalogs intact; visibility_presentation
            # authenticates the selected installation and complete successor.
            # Re-publication also repairs the document its factory would reject.
            visibility = closed_visibility(clock=clock, catalog_mode="migrate")
            visibility_factory = None
        else:
            assert args.visibility_installation is not None
            selected_application, _selected_metadata = _read_publication(
                _directory(args.app_dir), lambda _document, _binding: None
            )
            visibility = None
            visibility_factory = _visibility_factory(
                selected_application,
                args.visibility_installation,
                clock=clock,
                catalog_mode=(
                    "migrate" if args.command == "migrate-visibility" else "validate"
                ),
            )
        runtime = load_runtime(
            root,
            args.bundle,
            daemon._password_reader(args.password_fd),
            clock=clock,
            egress=visibility,
            egress_factory=visibility_factory,
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
        elif presentation_command:
            assert args.visibility_installation is not None
            proposal = (
                read_document(args.proposal) if args.proposal is not None else None
            )
            result = visibility_presentation(
                runtime,
                args.app_dir,
                args.visibility_installation,
                command=args.command,
                representation=args.representation,
                proposal=proposal,
                bundle_name=args.bundle,
            )
            if args.command != "visibility-apply":
                assert args.output is not None
                _write(
                    _directory(args.output.parent),
                    args.output.name,
                    canonical_bytes(result),
                )
                result = {
                    "status": "presentation-proposal-signed",
                    "proposal_sha256": config_digest(result),
                }
        elif args.command == "migrate-visibility":
            application, _metadata = read_publication(runtime, _directory(args.app_dir))
            runtime = load_application(runtime, args.app_dir)
            runtime.egress.migrate_registered_catalogs(
                version=VISIBILITY_SCHEMA_VERSION
            )
            runtime.egress.validate_registered_catalogs()
            result = {
                "status": "visibility-migrated",
                "visibility_schema_version": VISIBILITY_SCHEMA_VERSION,
                "application_sha256": config_digest(application),
                "catalog_count": len(runtime.egress.registered_catalog_ids()),
            }
        elif args.command == "republish":
            result = republish(
                runtime,
                args.app_dir,
                installation=args.visibility_installation,
                bundle_name=args.bundle,
            )
        elif args.command in {"renew", "revoke", "recover"}:
            operation = {
                "renew": renew,
                "revoke": revoke_capability,
                "recover": recover,
            }[args.command]
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
