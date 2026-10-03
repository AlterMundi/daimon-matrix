"""Owner-private SDK namespace rebuild composition; no live CLI or authority loader.

Caller establishes approved scope, complete accepted sync history, writer cutoff,
backup and runtime lock. Exact prepared heads/content are checked for ALL namespaces
before journals/native calls. Native receipts recover uncertain committed effects.
"""

import json
import subprocess
from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

from daimon_matrix.canonical import canonical_bytes
from daimon_matrix.ledger import Ledger
from daimon_matrix.memory_projection import (
    ContentResolver,
    MemoryProjectionAdapter,
    MemoryProjectionError,
    ProjectionJournal,
    _expected_states,
    _head_event,
    _namespace_id,
    projection_checkpoint,
    validate_projection_profile,
)

from .selected_projection_kernel import NativeTransport, checked_bytes


class RebuildTransport(NativeTransport):
    def __call__(
        self, operation: str, document: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        if operation not in {"rebuild-plan", "rebuild-apply"}:
            return super().__call__(operation, document)
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
                code = json.loads(result.stderr)["code"]
            except (ValueError, KeyError, TypeError):
                code = "native_hmk_rebuild_failed"
            raise MemoryProjectionError(code)
        return cast(dict[str, Any], json.loads(result.stdout))


def selection_summary(state: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "memory_id": state["memory_id"],
        "event_id": state["head"]["event_id"],
        "event_hash": state["head"]["event_hash"],
        "active": state["active"],
        "statement_sha256": state["statement"]["sha256"],
        "statement_length": state["statement"]["byte_length"],
    }


def preflight_namespaces(
    *,
    ledger: Ledger,
    entries: list[dict[str, Any]],
    profile_root: Path | str,
    content_root: Path | str,
) -> list[tuple[dict[str, Any], dict[str, Any], ContentResolver]]:
    """Prepare SDK plans without logging statement bytes or creating memory events."""
    validated: list[tuple[dict[str, Any], dict[str, Any], ContentResolver]] = []
    namespaces = set()
    journals = set()
    for entry in entries:
        profile = validate_projection_profile(
            json.loads(
                checked_bytes(
                    Path(profile_root) / entry["profile_file"], entry["profile_sha256"]
                )
            )
        )
        if profile["source_instance"] != entry["source_instance"] or not profile[
            "source_instance"
        ].startswith("matrix:embodiment:"):
            raise ValueError("rebuild_original_embodiment_required")
        namespace = _namespace_id(profile, ledger.authority.manifest.being_ref)
        if namespace != entry["namespace_id"] or namespace in namespaces:
            raise ValueError("rebuild_namespace_identity_mismatch")
        namespaces.add(namespace)
        journal = str(Path(entry["journal_path"]).absolute())
        if journal in journals:
            raise ValueError("rebuild_journal_reused_for_namespace")
        journals.add(journal)
        selected = entry["selected_heads"]
        if len({item["memory_id"] for item in selected}) != len(selected):
            raise ValueError("rebuild_duplicate_selected_memory")
        contents = {}
        for item in selected:
            lane, current = _head_event(ledger, item["memory_id"], profile)
            if (
                profile["source_instance"]
                != "matrix:" + lane[0]["origin"]["embodiment_id"]
            ):
                raise ValueError("rebuild_assertion_origin_mismatch")
            if (
                current["event_id"] != item["event_id"]
                or current["content_hash"] != item["event_hash"]
            ):
                raise ValueError("rebuild_selected_head_drift")
            sha = item["statement_sha256"]
            contents[sha] = checked_bytes(
                Path(content_root) / sha, sha, item["statement_length"]
            )

        def resolve(
            reference: Mapping[str, Any], contents: dict[str, bytes] = contents
        ) -> bytes:
            if reference["sha256"] not in contents:
                raise ValueError("rebuild_unselected_content")
            raw = contents[reference["sha256"]]
            if len(raw) != reference["byte_length"]:
                raise ValueError("rebuild_content_length_mismatch")
            return raw

        states = _expected_states(profile, ledger, resolve)
        if sorted(
            (selection_summary(state) for state in states), key=lambda x: x["memory_id"]
        ) != sorted(selected, key=lambda x: x["memory_id"]):
            raise ValueError("rebuild_namespace_selection_mismatch")
        validated.append((entry, profile, resolve))
    return validated


def prepare_rebuilds(
    *,
    ledger: Ledger,
    entries: list[dict[str, Any]],
    profile_root: Path | str,
    content_root: Path | str,
    transport: RebuildTransport,
) -> list[tuple[dict[str, Any], MemoryProjectionAdapter, dict[str, Any]]]:
    validated = preflight_namespaces(
        ledger=ledger,
        entries=entries,
        profile_root=profile_root,
        content_root=content_root,
    )
    prepared = []
    for entry, profile, resolve in validated:
        adapter = MemoryProjectionAdapter(
            ledger=ledger,
            profile=profile,
            transport=transport,
            content_resolver=resolve,
            journal=ProjectionJournal(entry["journal_path"]),
        )
        plan = adapter.rebuild_plan(
            request_id=entry["request_id"], idempotency_key=entry["idempotency_key"]
        )
        prepared.append((entry, adapter, plan))
    return prepared


def apply_rebuilds(
    prepared: list[tuple[dict[str, Any], MemoryProjectionAdapter, dict[str, Any]]],
) -> list[dict[str, Any]]:
    """Repeat exact saved plans after uncertainty; SDK/HMK bind drift and receipts.

    Plans contain private statement bytes and must be retained owner-only by caller.
    No automatic replan, namespace substitution or rollback of unrelated memories.
    """
    # Refuse common ledger drift before applying even the first namespace.
    for _entry, adapter, plan in prepared:
        current = projection_checkpoint(adapter.ledger)
        if {"sequence": current["sequence"], "hash": current["hash"]} != plan[
            "matrix_checkpoint"
        ]:
            raise MemoryProjectionError("rebuild_matrix_checkpoint_drift")
    summaries = []
    for entry, adapter, plan in prepared:
        receipt = adapter.rebuild_apply(plan)
        verified = adapter.verify()
        summaries.append(
            {
                "namespace_id": entry["namespace_id"],
                "plan_id": plan["plan_id"],
                "receipt_id": receipt["receipt_id"],
                "generation": receipt["generation"],
                "verified_manifest_hash": verified["manifest_hash"],
            }
        )
    return summaries
