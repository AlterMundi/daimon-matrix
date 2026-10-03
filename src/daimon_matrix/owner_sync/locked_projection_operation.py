"""Prepared projection operation, only after approved intake/cutoff/backups.

No live CLI/activation or credential loading. Caller must validate complete
native distribution/interpreter and prepared source-history preservation.
"""

import hashlib
import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from daimon_matrix.daemon import acquire_lock
from daimon_matrix.ledger import Ledger
from daimon_matrix.runtime import _owner_directory, _read_bundle, _safe_file
from daimon_matrix.weave import verify_event

from .public_history_authority import public_history_authority
from .selected_projection_kernel import NativeTransport, project_selected


@contextmanager
def bound_projection_runtime(
    *,
    plan: dict[str, Any],
    transport: NativeTransport,
    expected_initial_pool_sha256: str | None = None,
) -> Iterator[tuple[Ledger, Path]]:
    """Bind current public authority, destination and official writer lock.

    No custody loader or daemon fallback; a running owner refuses the lock.
    Optional initial digest belongs only to initial projection, never rebuild.
    """
    root = Path(plan["target_runtime_root"])
    _owner_directory(root)
    descriptor = acquire_lock(root)
    try:
        bundle = _read_bundle(_safe_file(root, "runtime.json", must_exist=True))
        authority = public_history_authority(bundle)
        if authority.manifest.being_ref != plan["same_being_ref"]:
            raise ValueError("prepared_being_mismatch")
        if authority.manifest.digest != plan["expected_current_manifest_hash"]:
            raise ValueError("prepared_current_authority_mismatch")
        if bundle["local_origin"] != plan["target_origin"]:
            raise ValueError("prepared_target_origin_mismatch")
        authority.validate_origin(bundle["local_origin"], require_active=True)
        ledger_file = _safe_file(root, bundle["ledger"], must_exist=True)
        pool = Path(plan["target_pool_proposal"])
        _owner_directory(pool)
        database = _safe_file(pool, "library.db", must_exist=True)
        if not isinstance(transport, NativeTransport):
            raise ValueError("prepared_native_transport_required")
        if (
            transport.environment["HMK_AGENT_MEMORY_BASE"] != str(pool)
            or transport.environment["HMK_DB_PATH"] != str(database)
            or transport.environment["HMK_INSTANCE_ID"] != plan["target_instance"]
            or transport.command[0] != plan["exact_sdk_release"] + "/bin/python"
            or transport.command[-1] != plan["target_instance"]
        ):
            raise ValueError("prepared_native_destination_mismatch")
        if expected_initial_pool_sha256 is not None:
            pool_descriptor = os.open(database, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(pool_descriptor, "rb") as stream:
                observed_pool_digest = hashlib.file_digest(stream, "sha256").hexdigest()
            if observed_pool_digest != expected_initial_pool_sha256:
                raise ValueError("prepared_initial_pool_digest_mismatch")
        ledger = Ledger(
            ledger_file, authority=authority, local_origin=bundle["local_origin"]
        )
        ledger_before = hashlib.sha256(ledger_file.read_bytes()).hexdigest()
        try:
            yield ledger, database
        finally:
            if hashlib.sha256(ledger_file.read_bytes()).hexdigest() != ledger_before:
                raise ValueError("selected_projection_changed_source_ledger")
    finally:
        os.close(descriptor)


def execute_selected_projection(
    *,
    plan: dict[str, Any],
    profile_root: Path | str,
    content_root: Path | str,
    transport: NativeTransport,
    expected_initial_pool_sha256: str,
) -> list[dict[str, Any]]:
    """Initial selected-head operation. No direct SQL/native projection edits.

    The prepared initial pool digest is deliberately not an arbitrary retry
    authority: after a partial effect, use the approved backup/recovery procedure
    or reconcile preserved SDK journals and observed effects before continuing.
    """
    with bound_projection_runtime(
        plan=plan,
        transport=transport,
        expected_initial_pool_sha256=expected_initial_pool_sha256,
    ) as (ledger, _):
        for entry in plan["entries"]:
            event = ledger.event(entry["event_id"], include_incomplete=False)
            if event is None:
                raise ValueError("prepared_selected_event_not_accepted")
            verified = verify_event(event, ledger.authority)
            if verified["content_hash"] != entry["event_hash"]:
                raise ValueError("prepared_original_event_hash_mismatch")
        return project_selected(
            ledger=ledger,
            entries=plan["entries"],
            profile_root=profile_root,
            content_root=content_root,
            transport=transport,
        )
