"""Prepared SDK kernel. Caller must establish approved cutoff, backup and runtime lock.

Import performs no I/O. This module contains no live CLI, credential loader,
service control, memory witness creation, ledger intake or adoption authority.
"""

import hashlib
import json
import os
import subprocess
from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

from daimon_matrix.canonical import canonical_bytes
from daimon_matrix.ledger import Ledger
from daimon_matrix.memory_projection import (
    MemoryProjectionAdapter,
    MemoryProjectionError,
    ProjectionJournal,
    _head_event,
    _namespace_id,
    validate_projection_profile,
)


def checked_bytes(path: Path | str, digest: str, length: int | None = None) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read(16 * 1024 * 1024 + 1)
    finally:
        os.close(descriptor)
    if len(raw) > 16 * 1024 * 1024 or hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError("prepared_artifact_digest_mismatch")
    if length is not None and len(raw) != length:
        raise ValueError("prepared_content_length_mismatch")
    return raw


class NativeTransport:
    def __init__(
        self,
        *,
        python: Path | str,
        script: Path | str,
        script_sha256: str,
        pool: Path | str,
        instance: str,
        isolated_home: Path | str,
    ) -> None:
        checked_bytes(Path(script), script_sha256)
        self.command = [str(python), str(script), "--instance-id", instance]
        self.environment = {
            "HOME": str(isolated_home),
            "PATH": "/usr/bin:/bin",
            "LANG": "C.UTF-8",
            "PYTHONNOUSERSITE": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "HMK_AGENT_MEMORY_BASE": str(pool),
            "HERMES_AGENT_MEMORY_BASE": str(pool),
            "HMK_DB_PATH": str(Path(pool) / "library.db"),
            "HMK_INSTANCE_ID": instance,
        }

    def __call__(
        self, operation: str, document: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        if operation not in {"apply", "inspect", "verify"}:
            raise ValueError("unselected_projection_operation")
        result = subprocess.run(
            [*self.command, operation],
            input=canonical_bytes(document) + b"\n",
            capture_output=True,
            env=self.environment,
            timeout=30,
            check=False,
        )
        if result.returncode:
            try:
                diagnostic = json.loads(result.stderr)
                code = diagnostic["code"]
            except (ValueError, KeyError, TypeError):
                code = "native_hmk_projection_failed"
            raise MemoryProjectionError(code)
        return cast(dict[str, Any], json.loads(result.stdout))


def project_selected(
    *,
    ledger: Ledger,
    entries: list[dict[str, Any]],
    profile_root: Path | str,
    content_root: Path | str,
    transport: NativeTransport,
) -> list[dict[str, Any]]:
    """Use only accepted heads through SDK; preserve original source namespaces.

    All prepared profile/content pins and selected event identities are checked
    before constructing any projection journal. Native pool cutoff and owner
    authorization belong to the outer operation, not this kernel.
    """
    prepared = []
    selected_content = {}
    for entry in entries:
        profile = validate_projection_profile(
            json.loads(
                checked_bytes(
                    Path(profile_root) / entry["profile_file"],
                    entry["profile_sha256"],
                )
            )
        )
        if profile["source_instance"] != entry["source_instance"]:
            raise ValueError("prepared_source_instance_mismatch")
        event = ledger.event(entry["event_id"], include_incomplete=False)
        if (
            event is None
            or event["kind"] != "memory.recorded"
            or event["content_hash"] != entry["event_hash"]
        ):
            raise ValueError("prepared_accepted_head_missing_or_changed")
        if event["payload"]["memory_id"] != entry["memory_id"]:
            raise ValueError("prepared_memory_id_mismatch")
        if not profile["source_instance"].startswith("matrix:embodiment:"):
            raise ValueError("prepared_original_embodiment_required")
        lane, current = _head_event(ledger, entry["memory_id"], profile)
        if profile["source_instance"] != "matrix:" + lane[0]["origin"]["embodiment_id"]:
            raise ValueError("prepared_assertion_origin_mismatch")
        if (
            current["event_id"] != entry["event_id"]
            or current["content_hash"] != entry["event_hash"]
        ):
            raise ValueError("prepared_current_head_mismatch")
        if (
            _namespace_id(profile, ledger.authority.manifest.being_ref)
            != entry["namespace_id"]
        ):
            raise ValueError("prepared_namespace_identity_mismatch")
        raw = checked_bytes(
            Path(content_root) / entry["statement_sha256"],
            entry["statement_sha256"],
            entry["statement_length"],
        )
        selected_content[entry["statement_sha256"]] = raw
        prepared.append((entry, profile))

    def resolve(reference: Mapping[str, Any]) -> bytes:
        raw = selected_content[reference["sha256"]]
        if len(raw) != reference["byte_length"]:
            raise ValueError("selected_statement_length_mismatch")
        return raw

    summaries = []
    for entry, profile in prepared:
        adapter = MemoryProjectionAdapter(
            ledger=ledger,
            profile=profile,
            transport=transport,
            content_resolver=resolve,
            journal=ProjectionJournal(entry["journal_path"]),
        )
        first = adapter.project(
            event_id=entry["event_id"], idempotency_key=entry["idempotency_key"]
        )
        repeated = adapter.project(
            event_id=entry["event_id"], idempotency_key=entry["idempotency_key"]
        )
        if first != repeated:
            raise ValueError("repeated_projection_receipt_mismatch")
        observed = adapter.inspect(memory_id=entry["memory_id"])["projection"]
        recalled = adapter.recall(memory_id=entry["memory_id"])
        if (
            observed["namespace_id"] != entry["namespace_id"]
            or recalled["origin"]["source_instance"] != entry["source_instance"]
        ):
            raise ValueError("selected_original_namespace_mismatch")
        if (
            recalled["origin"]["head"]["event_id"] != entry["event_id"]
            or recalled["origin"]["head"]["event_hash"] != entry["event_hash"]
        ):
            raise ValueError("selected_original_head_mismatch")
        statement = recalled["statement"]
        if (
            statement["sha256"] != entry["statement_sha256"]
            or statement["byte_length"] != entry["statement_length"]
        ):
            raise ValueError("selected_original_statement_mismatch")
        summaries.append(
            {
                "event_id": entry["event_id"],
                "event_hash": entry["event_hash"],
                "memory_id": entry["memory_id"],
                "source_instance": entry["source_instance"],
                "namespace_id": entry["namespace_id"],
                "receipt_id": first["receipt_id"],
                "repeat_same_receipt": True,
                "verified_original_head_and_statement": True,
            }
        )
    return summaries
