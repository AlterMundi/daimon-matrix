#!/usr/bin/env python3
"""Generate deterministic DM-034 Matrix-to-HMK interoperability vectors."""

from __future__ import annotations

import argparse
import copy
import hashlib
import sys
from pathlib import Path
from typing import Any, cast

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from daimon_matrix.canonical import canonical_bytes  # noqa: E402
from daimon_matrix.memory_policy import create_content_ref  # noqa: E402
from daimon_matrix.memory_projection import (  # noqa: E402
    CHECKPOINT_DOMAIN,
    CHECKPOINT_SCHEMA,
    HMK_COMMIT,
    HMK_PROJECTION_DOMAIN,
    HMK_REBUILD_PLAN_DOMAIN,
    HMK_REBUILD_RECEIPT_DOMAIN,
    HMK_RECEIPT_DOMAIN,
    INTENT_SCHEMA,
    PROJECTOR_ID,
    PROJECTOR_VERSION,
    REBUILD_PLAN_DOMAIN,
    REBUILD_PLAN_SCHEMA,
    REBUILD_RECEIPT_DOMAIN,
    REBUILD_RECEIPT_SCHEMA,
    RECALL_SCHEMA,
    RECONCILIATION_SCHEMA,
    _derived,
    _matrix_receipt,
    _namespace_id,
    _projection_id,
    _validate_hmk_rebuild_plan,
    _validate_hmk_rebuild_receipt,
    _validate_hmk_receipt,
    create_projection_manifest,
    create_projection_profile,
    negotiate_projection_manifest,
    validate_projection_receipt,
    validate_rebuild_plan,
    validate_rebuild_receipt,
)

DEFAULT_OUTPUT = ROOT / "vectors" / "memory-projection" / "v1"
SUBJECT = "dm:being:v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
SOURCE = "matrix:vector-instance"
TARGET = "hmk:vector-instance"
EVENT_ID = "a9f98b1d-115b-5979-b98d-88b8501667b6"
MEMORY_ID = "6ed1c3bd-24d9-513e-9430-41ff147a11c8"
REQUEST_ID = "07a93487-ee36-5c92-887a-b0af1457026c"
REBUILD_REQUEST_ID = "1f3557a7-782c-50a0-b436-7d132ff44888"
TEXT = "The orchard gate opens at dawn."


def _hash(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _write(output: Path, relative: str, value: Any) -> None:
    path = output / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_bytes(value) + b"\n")


def generate(output: Path) -> None:
    profile = create_projection_profile(
        source_instance=SOURCE,
        target_instance=TARGET,
    )
    manifest = create_projection_manifest()
    negotiation = negotiate_projection_manifest(manifest, accepted_versions=["v1"])
    event_hash = hashlib.sha256(b"dm034-vector:event").hexdigest()
    root_manifest_hash = hashlib.sha256(b"dm034-vector:manifest").hexdigest()
    checkpoint_core = {
        "schema": CHECKPOINT_SCHEMA,
        "being_ref": SUBJECT,
        "manifest_hash": root_manifest_hash,
        "events": [{"event_id": EVENT_ID, "event_hash": event_hash}],
    }
    checkpoint = {
        **checkpoint_core,
        "sequence": 1,
        "hash": hashlib.sha256(
            CHECKPOINT_DOMAIN + canonical_bytes(checkpoint_core)
        ).hexdigest(),
    }
    short_checkpoint = {
        "sequence": checkpoint["sequence"],
        "hash": checkpoint["hash"],
    }
    content_ref = create_content_ref(
        sha256=hashlib.sha256(TEXT.encode()).hexdigest(),
        byte_length=len(TEXT.encode()),
        media_type="text/plain",
        classification="protected",
    )
    statement = {
        "sha256": content_ref["sha256"],
        "byte_length": content_ref["byte_length"],
        "media_type": content_ref["media_type"],
        "classification": content_ref["classification"],
        "text": TEXT,
    }
    hmk_request = {
        "schema": "hmk.daimon-projection.request/v1",
        "adapter": {"id": "hmk-daimon-projection", "version": "1.0.0"},
        "request_id": REQUEST_ID,
        "idempotency_key": "vector:project",
        "operation": "project",
        "target": copy.deepcopy(profile["target"]),
        "source_instance": SOURCE,
        "subject_me_id": SUBJECT,
        "author_me_id": SUBJECT,
        "memory_id": MEMORY_ID,
        "category": "personal-insight",
        "head": {
            "event_id": EVENT_ID,
            "event_hash": event_hash,
            "sequence": 1,
            "predecessor_event_id": None,
            "predecessor_hash": None,
        },
        "statement": statement,
        "projector": {"id": PROJECTOR_ID, "version": PROJECTOR_VERSION},
        "source_checkpoint": short_checkpoint,
    }
    namespace_id = _namespace_id(profile, SUBJECT)
    projection_id = _projection_id(profile, SUBJECT, MEMORY_ID)
    state = {
        "projection_id": projection_id,
        "namespace_id": namespace_id,
        "memory_id": MEMORY_ID,
        "author_me_id": SUBJECT,
        "category": "personal-insight",
        "head": {
            "event_id": EVENT_ID,
            "event_hash": event_hash,
            "sequence": 1,
        },
        "statement": {key: statement[key] for key in statement if key != "text"},
        "source_checkpoint": short_checkpoint,
        "active": True,
    }
    manifest_entry = {
        key: state[key]
        for key in (
            "projection_id",
            "memory_id",
            "author_me_id",
            "category",
            "head",
            "statement",
            "active",
        )
    }
    hmk_manifest_hash = _hash([manifest_entry])
    hmk_receipt_body = {
        "schema": "hmk.daimon-projection.receipt/v1",
        "request_id": REQUEST_ID,
        "idempotency_key": "vector:project",
        "request_hash": _hash(hmk_request),
        "operation": "project",
        "outcome": "applied",
        "target": copy.deepcopy(profile["target"]),
        "namespace": {
            "namespace_id": namespace_id,
            "generation": 1,
            "manifest_hash": hmk_manifest_hash,
            "source_checkpoint": short_checkpoint,
        },
        "previous": None,
        "current": state,
    }
    hmk_receipt = {
        **hmk_receipt_body,
        "receipt_id": _derived(
            "hmk:daimon-receipt:v1:", HMK_RECEIPT_DOMAIN, hmk_receipt_body
        ),
    }
    _validate_hmk_receipt(hmk_receipt, request=hmk_request, profile=profile)
    intent = {
        "schema": INTENT_SCHEMA,
        "adapter_id": profile["adapter_id"],
        "hmk_commit": HMK_COMMIT,
        "operation": "project",
        "source_event": {
            "event_id": EVENT_ID,
            "event_hash": event_hash,
            "memory_id": MEMORY_ID,
            "sequence": 1,
            "category": "personal-insight",
            "author_me_id": SUBJECT,
            "evidence_hash": _hash([]),
            "content_ref": content_ref,
        },
        "source_checkpoint": short_checkpoint,
        "target": copy.deepcopy(profile["target"]),
        "projector": copy.deepcopy(profile["projector"]),
        "hmk_request_hash": _hash(hmk_request),
    }
    receipt = _matrix_receipt(
        profile=profile,
        intent=intent,
        hmk_request=hmk_request,
        hmk_receipt=hmk_receipt,
    )
    validate_projection_receipt(receipt)
    reconciliation = {
        "schema": RECONCILIATION_SCHEMA,
        "receipt_id": receipt["receipt_id"],
        "status": "verified",
        "reason": "effect-truth-matches",
    }
    recall = {
        "schema": RECALL_SCHEMA,
        "origin": {
            "kind": "daimon-projection",
            "source_instance": SOURCE,
            "subject_me_id": SUBJECT,
            "author_me_id": SUBJECT,
            "memory_id": MEMORY_ID,
            "category": "personal-insight",
            "head": copy.deepcopy(state["head"]),
            "classification": content_ref["classification"],
            "projector": copy.deepcopy(profile["projector"]),
        },
        "statement": statement,
        "verified_against": {
            "checkpoint": short_checkpoint,
            "manifest_hash": hmk_manifest_hash,
        },
    }
    rebuild_entry = {
        "memory_id": MEMORY_ID,
        "author_me_id": SUBJECT,
        "category": "personal-insight",
        "head": copy.deepcopy(state["head"]),
        "statement": statement,
    }
    namespace = {
        "source_instance": SOURCE,
        "subject_me_id": SUBJECT,
        "projector_id": PROJECTOR_ID,
        "projector_version": PROJECTOR_VERSION,
    }
    hmk_plan_body = {
        "schema": "hmk.daimon-projection.rebuild-plan/v1",
        "request_id": REBUILD_REQUEST_ID,
        "idempotency_key": "vector:rebuild",
        "target": copy.deepcopy(profile["target"]),
        "namespace": namespace,
        "namespace_id": namespace_id,
        "source_checkpoint": short_checkpoint,
        "entries": [rebuild_entry],
        "manifest_hash": hmk_manifest_hash,
        "prior": {
            "generation": 1,
            "manifest_hash": hmk_manifest_hash,
            "source_checkpoint": short_checkpoint,
        },
    }
    hmk_plan = {
        **hmk_plan_body,
        "plan_id": _derived(
            "hmk:daimon-rebuild-plan:v1:",
            HMK_REBUILD_PLAN_DOMAIN,
            hmk_plan_body,
        ),
    }
    rebuild_request = {
        "schema": "hmk.daimon-projection.rebuild-request/v1",
        "request_id": REBUILD_REQUEST_ID,
        "idempotency_key": "vector:rebuild",
        "target": copy.deepcopy(profile["target"]),
        "source_instance": SOURCE,
        "subject_me_id": SUBJECT,
        "projector": copy.deepcopy(profile["projector"]),
        "source_checkpoint": short_checkpoint,
        "entries": [rebuild_entry],
    }
    _validate_hmk_rebuild_plan(hmk_plan, request=rebuild_request, profile=profile)
    matrix_plan_body = {
        "schema": REBUILD_PLAN_SCHEMA,
        "adapter_id": profile["adapter_id"],
        "hmk_commit": HMK_COMMIT,
        "matrix_checkpoint": short_checkpoint,
        "matrix_manifest_hash": hmk_manifest_hash,
        "hmk_plan_hash": _hash(hmk_plan),
        "hmk_plan": hmk_plan,
    }
    matrix_plan = {
        **matrix_plan_body,
        "plan_id": _derived(
            "dm:memory-projection-rebuild-plan:v1:",
            REBUILD_PLAN_DOMAIN,
            matrix_plan_body,
        ),
    }
    validate_rebuild_plan(matrix_plan)
    hmk_rebuild_receipt_body = {
        "schema": "hmk.daimon-projection.rebuild-receipt/v1",
        "plan_id": hmk_plan["plan_id"],
        "plan_hash": _hash(hmk_plan),
        "target": copy.deepcopy(profile["target"]),
        "namespace_id": namespace_id,
        "generation": 2,
        "source_checkpoint": short_checkpoint,
        "manifest_hash": hmk_manifest_hash,
        "projection_ids": [projection_id],
        "outcome": "rebuilt",
    }
    hmk_rebuild_receipt = {
        **hmk_rebuild_receipt_body,
        "receipt_id": _derived(
            "hmk:daimon-rebuild-receipt:v1:",
            HMK_REBUILD_RECEIPT_DOMAIN,
            hmk_rebuild_receipt_body,
        ),
    }
    _validate_hmk_rebuild_receipt(
        hmk_rebuild_receipt,
        hmk_plan=hmk_plan,
        profile=profile,
    )
    matrix_rebuild_receipt_body = {
        "schema": REBUILD_RECEIPT_SCHEMA,
        "plan_id": matrix_plan["plan_id"],
        "adapter_id": profile["adapter_id"],
        "hmk_commit": HMK_COMMIT,
        "matrix_checkpoint": short_checkpoint,
        "matrix_manifest_hash": hmk_manifest_hash,
        "hmk_receipt_id": hmk_rebuild_receipt["receipt_id"],
        "hmk_receipt_hash": _hash(hmk_rebuild_receipt),
        "namespace_id": namespace_id,
        "generation": 2,
        "outcome": "rebuilt",
    }
    matrix_rebuild_receipt = {
        **matrix_rebuild_receipt_body,
        "receipt_id": _derived(
            "dm:memory-projection-rebuild-receipt:v1:",
            REBUILD_RECEIPT_DOMAIN,
            matrix_rebuild_receipt_body,
        ),
    }
    validate_rebuild_receipt(matrix_rebuild_receipt)
    negative = copy.deepcopy(receipt)
    negative["effect"]["namespace_id"] = _derived(
        "hmk:daimon-namespace:v1:",
        HMK_PROJECTION_DOMAIN,
        {"substitution": True},
    )
    artifacts = {
        "manifest": manifest,
        "profile": profile,
        "negotiation": negotiation,
        "checkpoint": checkpoint,
        "intent": intent,
        "hmk_request": hmk_request,
        "hmk_receipt": hmk_receipt,
        "receipt": receipt,
        "reconciliation": reconciliation,
        "recall": recall,
        "hmk_rebuild_plan": hmk_plan,
        "rebuild_plan": matrix_plan,
        "hmk_rebuild_receipt": hmk_rebuild_receipt,
        "rebuild_receipt": matrix_rebuild_receipt,
        "negative_receipt": negative,
    }
    filenames = {
        "manifest": "manifest.json",
        "profile": "profile.json",
        "negotiation": "negotiation.json",
        "checkpoint": "checkpoint.json",
        "intent": "intent.json",
        "hmk_request": "interop/hmk-project.request.json",
        "hmk_receipt": "interop/hmk-project.receipt.json",
        "receipt": "project.receipt.json",
        "reconciliation": "project.reconciliation.json",
        "recall": "recall.json",
        "hmk_rebuild_plan": "interop/hmk-rebuild.plan.json",
        "rebuild_plan": "rebuild.plan.json",
        "hmk_rebuild_receipt": "interop/hmk-rebuild.receipt.json",
        "rebuild_receipt": "rebuild.receipt.json",
        "negative_receipt": "negative/receipt-namespace-substitution.json",
    }
    for name, relative in filenames.items():
        _write(output, relative, artifacts[name])
    index = {
        "schema": "dm.memory-projection.vectors/v1",
        "hmk_commit": HMK_COMMIT,
        "artifacts": dict(sorted(filenames.items())),
        "sha256": {name: _hash(value) for name, value in sorted(artifacts.items())},
    }
    _write(output, "index.json", index)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    arguments = parser.parse_args()
    generate(cast(Path, arguments.output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
