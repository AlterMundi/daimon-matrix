"""Private, no-overwrite SDK plan retention and restart. Does not confer consent."""

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from daimon_matrix.canonical import canonical_bytes
from daimon_matrix.ledger import Ledger
from daimon_matrix.memory_projection import (
    HMK_REBUILD_REQUEST_SCHEMA,
    MemoryProjectionAdapter,
    MemoryProjectionError,
    ProjectionJournal,
    _expected_manifest_hash,
    _expected_states,
    _rebuild_entries,
    _validate_hmk_rebuild_plan,
    projection_checkpoint,
    validate_rebuild_plan,
)
from daimon_matrix.runtime import _owner_directory, _safe_file

from .namespace_rebuild_operation import RebuildTransport, preflight_namespaces
from .selected_projection_kernel import checked_bytes

SCHEMA = "compaii.private-saved-namespace-rebuild/v1"
MAX_PACKET_BYTES = 16 * 1024 * 1024  # Same admission ceiling as checked_bytes on load.


def save_rebuild_packet(
    prepared: list[tuple[dict[str, Any], MemoryProjectionAdapter, dict[str, Any]]],
    path: Path | str,
) -> str:
    path = Path(path).absolute()
    _owner_directory(path.parent)
    _safe_file(path.parent, path.name, must_exist=False)
    document = {
        "schema": SCHEMA,
        "entries": [entry for entry, _, _ in prepared],
        "plans": [validate_rebuild_plan(plan) for _, _, plan in prepared],
    }
    raw = canonical_bytes(document) + b"\n"
    if len(raw) > MAX_PACKET_BYTES:
        raise ValueError("saved_rebuild_packet_too_large")
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=path.parent, prefix=".rebuild-packet-", delete=False
        ) as stream:
            temporary = Path(stream.name)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        # Hard-link publication refuses an existing path; rename would overwrite it.
        os.link(temporary, path, follow_symlinks=False)
        descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return hashlib.sha256(raw).hexdigest()


def load_saved_rebuilds(
    *,
    ledger: Ledger,
    path: Path | str,
    sha256: str,
    profile_root: Path | str,
    content_root: Path | str,
    transport: RebuildTransport,
) -> list[tuple[dict[str, Any], MemoryProjectionAdapter, dict[str, Any]]]:
    path = Path(path).absolute()
    _owner_directory(path.parent)
    _safe_file(path.parent, path.name, must_exist=True)
    packet = json.loads(checked_bytes(path, sha256))
    if set(packet) != {"schema", "entries", "plans"} or packet["schema"] != SCHEMA:
        raise ValueError("unsupported_saved_rebuild_packet")
    if len(packet["entries"]) != len(packet["plans"]):
        raise ValueError("saved_rebuild_count_mismatch")
    validated = preflight_namespaces(
        ledger=ledger,
        entries=packet["entries"],
        profile_root=profile_root,
        content_root=content_root,
    )
    checkpoint = projection_checkpoint(ledger)
    current = {"sequence": checkpoint["sequence"], "hash": checkpoint["hash"]}
    bound = []
    # Validate all saved plans against accepted truth before any journal/effect.
    for (entry, profile, resolve), raw_plan in zip(
        validated, packet["plans"], strict=True
    ):
        plan = validate_rebuild_plan(raw_plan)
        if plan["adapter_id"] != profile["adapter_id"]:
            raise MemoryProjectionError("rebuild_adapter_mismatch")
        if plan["matrix_checkpoint"] != current:
            raise MemoryProjectionError("rebuild_matrix_checkpoint_drift")
        if plan["matrix_manifest_hash"] != _expected_manifest_hash(
            _expected_states(profile, ledger, resolve)
        ):
            raise MemoryProjectionError("rebuild_matrix_manifest_drift")
        native = plan["hmk_plan"]
        if (
            native["request_id"] != entry["request_id"]
            or native["idempotency_key"] != entry["idempotency_key"]
        ):
            raise ValueError("saved_rebuild_intent_mismatch")
        expected = {
            "schema": HMK_REBUILD_REQUEST_SCHEMA,
            "request_id": entry["request_id"],
            "idempotency_key": entry["idempotency_key"],
            "target": profile["target"],
            "source_instance": profile["source_instance"],
            "subject_me_id": ledger.authority.manifest.being_ref,
            "projector": profile["projector"],
            "source_checkpoint": current,
            "entries": _rebuild_entries(profile, ledger, resolve),
        }
        _validate_hmk_rebuild_plan(native, request=expected, profile=profile)
        bound.append((entry, profile, resolve, plan))
    return [
        (
            entry,
            MemoryProjectionAdapter(
                ledger=ledger,
                profile=profile,
                transport=transport,
                content_resolver=resolve,
                journal=ProjectionJournal(entry["journal_path"]),
            ),
            plan,
        )
        for entry, profile, resolve, plan in bound
    ]
