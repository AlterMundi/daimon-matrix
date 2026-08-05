#!/usr/bin/env python3
"""Generate deterministic DM-035 publication contracts and interop vectors."""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from types import ModuleType
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import daimon_matrix.publication as publication  # noqa: E402
from daimon_matrix.canonical import b64url, canonical_bytes  # noqa: E402

DEFAULT_OUTPUT = ROOT / "vectors" / "publication" / "v1"
DEFAULT_SCHEMA = ROOT / "schemas" / "publication" / "v1" / "contracts.schema.json"
SUBJECT = "dm:being:v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
SOURCE_EVENT = "35000000-0000-4000-8000-000000000001"
REQUEST_EVENT = "35000000-0000-4000-8000-000000000002"
CLAIM_ID = "35000000-0000-4000-8000-000000000003"
PROVIDER_REQUEST = "35000000-0000-4000-8000-000000000004"
REVIEW_ID = "35000000-0000-4000-8000-000000000005"
NOW = 1_800_000_000_000
BODY = "Synthetic reviewed identity summary."


def obj(required: list[str], properties: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": required,
        "properties": properties,
    }


def schema() -> dict[str, Any]:
    hash_value = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    derived = {"type": "string", "pattern": "^[A-Za-z0-9_-]{43}$"}
    token = {
        "type": "string",
        "pattern": "^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,255}$",
    }
    uint = {"type": "integer", "minimum": 0, "maximum": 9_007_199_254_740_991}
    uuid4 = {"type": "string", "format": "uuid"}
    event_ref = obj(
        ["event_id", "event_hash"], {"event_id": uuid4, "event_hash": hash_value}
    )
    provider_event_ref = obj(
        ["event_id", "event_hash"], {"event_id": token, "event_hash": hash_value}
    )
    high_waters = {
        "type": "object",
        "minProperties": 1,
        "propertyNames": {"pattern": "^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,63}$"},
        "additionalProperties": uint,
    }
    content_ref = obj(
        ["schema", "media_type", "byte_length", "sha256"],
        {
            "schema": {"const": publication.CONTENT_REF_SCHEMA},
            "media_type": {"const": "text/markdown"},
            "byte_length": {**uint, "minimum": 1},
            "sha256": hash_value,
        },
    )
    reviewer = obj(
        ["principal", "key_id", "public_key"],
        {"principal": token, "key_id": token, "public_key": derived},
    )
    target_policy = obj(
        ["kind", "namespace", "artifact_classes", "classifications", "licenses"],
        {
            "kind": {"enum": sorted(publication.TARGET_KINDS)},
            "namespace": {"const": "daimon-matrix"},
            "artifact_classes": {
                "type": "array",
                "uniqueItems": True,
                "items": {"enum": sorted(publication.ARTIFACT_CLASSES)},
            },
            "classifications": {
                "type": "array",
                "uniqueItems": True,
                "items": {"enum": sorted(publication.CLASSIFICATIONS)},
            },
            "licenses": {"type": "array", "uniqueItems": True, "items": token},
        },
    )
    provider = obj(
        [
            "commit",
            "adapter_id",
            "api_version",
            "schema_version",
            "contract_version",
            "policy_id",
            "policy_hash",
            "hmk_commit",
        ],
        {
            "commit": {"const": publication.COMPAII_STATE_COMMIT},
            "adapter_id": {"const": publication.PROVIDER_ADAPTER_ID},
            "api_version": {"const": publication.PROVIDER_API_VERSION},
            "schema_version": {"const": 1},
            "contract_version": {"const": "v1"},
            "policy_id": {"const": publication.PROVIDER_POLICY_ID},
            "policy_hash": {"const": publication.PROVIDER_POLICY_HASH},
            "hmk_commit": {"const": publication.HMK_COMMIT},
        },
    )
    policy = obj(
        [
            "schema",
            "policy_id",
            "subject_me_id",
            "version",
            "predecessor_policy_id",
            "publisher_principal",
            "renderer",
            "provider",
            "reviewers",
            "targets",
            "max_content_bytes",
            "max_pending",
        ],
        {
            "schema": {"const": publication.POLICY_SCHEMA},
            "policy_id": token,
            "subject_me_id": token,
            "version": {**uint, "minimum": 1},
            "predecessor_policy_id": {"type": ["string", "null"]},
            "publisher_principal": {"const": publication.PUBLISHER_PRINCIPAL},
            "renderer": obj(
                ["id", "version"], {"id": token, "version": {"const": "1.0.0"}}
            ),
            "provider": provider,
            "reviewers": {
                "type": "array",
                "minItems": 1,
                "uniqueItems": True,
                "items": reviewer,
            },
            "targets": {
                "type": "array",
                "minItems": 2,
                "maxItems": 2,
                "items": target_policy,
            },
            "max_content_bytes": {"const": publication.MAX_CONTENT_BYTES},
            "max_pending": {"type": "integer", "minimum": 1, "maximum": 128},
        },
    )
    checkpoint = obj(
        [
            "schema",
            "checkpoint_id",
            "checkpoint_hash",
            "being_ref",
            "manifest_hash",
            "source_events",
            "high_waters",
            "captured_at_ms",
        ],
        {
            "schema": {"const": publication.CHECKPOINT_SCHEMA},
            "checkpoint_id": token,
            "checkpoint_hash": hash_value,
            "being_ref": token,
            "manifest_hash": hash_value,
            "source_events": {
                "type": "array",
                "minItems": 1,
                "uniqueItems": True,
                "items": event_ref,
            },
            "high_waters": obj(["ledger-events"], {"ledger-events": uint}),
            "captured_at_ms": uint,
        },
    )
    target = obj(
        ["kind", "logical_id"],
        {
            "kind": {"enum": sorted(publication.TARGET_KINDS)},
            "logical_id": {
                "type": "string",
                "pattern": (
                    "^(project|projection)/daimon-matrix/[a-z0-9][a-z0-9-]{0,62}$"
                ),
            },
        },
    )
    governance = obj(
        ["classification", "consent", "license", "derivation_ref"],
        {
            "classification": {"enum": sorted(publication.CLASSIFICATIONS)},
            "consent": {"const": "explicit"},
            "license": token,
            "derivation_ref": token,
        },
    )
    predecessor = obj(
        [
            "acceptance_event_id",
            "acceptance_event_hash",
            "provider_receipt_id",
            "provider_receipt_hash",
        ],
        {
            "acceptance_event_id": uuid4,
            "acceptance_event_hash": hash_value,
            "provider_receipt_id": token,
            "provider_receipt_hash": derived,
        },
    )
    proposal = obj(
        [
            "schema",
            "proposal_id",
            "provider_request_id",
            "review_decision_id",
            "requested_at_ms",
            "operation",
            "artifact_class",
            "source",
            "title",
            "body_ref",
            "rendered_ref",
            "target",
            "governance",
            "matrix_policy_id",
            "matrix_policy_hash",
            "provider_policy_id",
            "provider_policy_hash",
            "predecessor",
            "relation",
        ],
        {
            "schema": {"const": publication.PROPOSAL_SCHEMA},
            "proposal_id": token,
            "provider_request_id": uuid4,
            "review_decision_id": uuid4,
            "requested_at_ms": uint,
            "operation": {"enum": sorted(publication.OPERATIONS)},
            "artifact_class": {"enum": sorted(publication.ARTIFACT_CLASSES)},
            "source": obj(
                [
                    "subject_me_id",
                    "author_me_id",
                    "event_refs",
                    "release_ref",
                    "checkpoint",
                ],
                {
                    "subject_me_id": token,
                    "author_me_id": token,
                    "event_refs": {
                        "type": "array",
                        "minItems": 1,
                        "items": event_ref,
                    },
                    "release_ref": {
                        "oneOf": [
                            {"type": "null"},
                            obj(
                                ["release_id", "release_hash"],
                                {"release_id": uuid4, "release_hash": hash_value},
                            ),
                        ]
                    },
                    "checkpoint": checkpoint,
                },
            ),
            "title": {"type": "string", "minLength": 1, "maxLength": 160},
            "body_ref": {"oneOf": [{"type": "null"}, content_ref]},
            "rendered_ref": obj(
                ["media_type", "byte_length", "sha256"],
                {
                    "media_type": {"const": "text/markdown; charset=utf-8"},
                    "byte_length": {**uint, "minimum": 1},
                    "sha256": hash_value,
                },
            ),
            "target": target,
            "governance": governance,
            "matrix_policy_id": token,
            "matrix_policy_hash": hash_value,
            "provider_policy_id": {"const": publication.PROVIDER_POLICY_ID},
            "provider_policy_hash": {"const": publication.PROVIDER_POLICY_HASH},
            "predecessor": {"oneOf": [{"type": "null"}, predecessor]},
            "relation": obj(
                ["supersedes_acceptance_event_id", "compensates_acceptance_event_id"],
                {
                    "supersedes_acceptance_event_id": {"type": ["string", "null"]},
                    "compensates_acceptance_event_id": {"type": ["string", "null"]},
                },
            ),
        },
    )
    review = obj(
        [
            "schema",
            "decision_id",
            "proposal_id",
            "proposal_hash",
            "decision",
            "reviewer",
            "issued_at_ms",
            "expires_at_ms",
            "signature",
            "decision_hash",
        ],
        {
            "schema": {"const": publication.REVIEW_SCHEMA},
            "decision_id": uuid4,
            "proposal_id": token,
            "proposal_hash": hash_value,
            "decision": {"const": "approved"},
            "reviewer": reviewer,
            "issued_at_ms": uint,
            "expires_at_ms": uint,
            "signature": {"type": "string", "pattern": "^[A-Za-z0-9_-]{86}$"},
            "decision_hash": hash_value,
        },
    )
    request = obj(
        ["schema", "request_id", "proposal", "policy", "review"],
        {
            "schema": {"const": publication.REQUEST_SCHEMA},
            "request_id": token,
            "proposal": proposal,
            "policy": policy,
            "review": review,
        },
    )
    claim = obj(
        [
            "schema",
            "claim_id",
            "request_event_id",
            "request_event_hash",
            "target",
            "generation",
            "actor_origin",
            "issued_at_ms",
            "lease_until_ms",
            "content_hash",
        ],
        {
            "schema": {"const": publication.CLAIM_SCHEMA},
            "claim_id": uuid4,
            "request_event_id": uuid4,
            "request_event_hash": hash_value,
            "target": target,
            "generation": {**uint, "minimum": 1},
            "actor_origin": obj(
                ["body_ref", "embodiment_id", "incarnation_id", "principal_id"],
                {
                    "body_ref": token,
                    "embodiment_id": token,
                    "incarnation_id": token,
                    "principal_id": token,
                },
            ),
            "issued_at_ms": uint,
            "lease_until_ms": uint,
            "content_hash": hash_value,
        },
    )
    nullable_token = {"oneOf": [{"type": "null"}, token]}
    provider_release_ref = obj(
        ["release_id", "release_hash"],
        {"release_id": token, "release_hash": hash_value},
    )
    provider_source = obj(
        ["subject_me_id", "author_me_id", "event_refs", "release_ref", "checkpoint"],
        {
            "subject_me_id": token,
            "author_me_id": token,
            "event_refs": {
                "type": "array",
                "minItems": 1,
                "uniqueItems": True,
                "items": provider_event_ref,
            },
            "release_ref": {"oneOf": [{"type": "null"}, provider_release_ref]},
            "checkpoint": obj(
                ["checkpoint_id", "checkpoint_hash", "high_waters"],
                {
                    "checkpoint_id": token,
                    "checkpoint_hash": hash_value,
                    "high_waters": high_waters,
                },
            ),
        },
    )
    provider_relation = obj(
        ["supersedes_receipt_id", "compensates_receipt_id"],
        {
            "supersedes_receipt_id": nullable_token,
            "compensates_receipt_id": nullable_token,
        },
    )
    provider_governance = governance
    provider_policy_ref = obj(
        ["policy_id", "policy_hash"],
        {
            "policy_id": {"const": publication.PROVIDER_POLICY_ID},
            "policy_hash": {"const": publication.PROVIDER_POLICY_HASH},
        },
    )
    provider_review = obj(
        [
            "decision_id",
            "decision_hash",
            "decision",
            "reviewer_principal",
            "expires_at_ms",
        ],
        {
            "decision_id": token,
            "decision_hash": hash_value,
            "decision": {"const": "approved"},
            "reviewer_principal": token,
            "expires_at_ms": uint,
        },
    )
    provider_request = obj(
        [
            "schema",
            "request_id",
            "idempotency_key",
            "requested_at_ms",
            "operation",
            "artifact_class",
            "source",
            "content",
            "target",
            "governance",
            "policy",
            "review",
            "publisher_principal",
            "predecessor",
            "relation",
        ],
        {
            "schema": {"const": publication.PROVIDER_REQUEST_SCHEMA},
            "request_id": uuid4,
            "idempotency_key": derived,
            "requested_at_ms": uint,
            "operation": {"enum": sorted(publication.OPERATIONS)},
            "artifact_class": {"enum": sorted(publication.ARTIFACT_CLASSES)},
            "source": provider_source,
            "content": obj(
                ["media_type", "text", "byte_length", "sha256"],
                {
                    "media_type": {"const": "text/markdown; charset=utf-8"},
                    "text": {"type": "string", "minLength": 1},
                    "byte_length": {**uint, "minimum": 1},
                    "sha256": hash_value,
                },
            ),
            "target": target,
            "governance": provider_governance,
            "policy": provider_policy_ref,
            "review": provider_review,
            "publisher_principal": {"const": publication.PUBLISHER_PRINCIPAL},
            "predecessor": {
                "oneOf": [
                    {"type": "null"},
                    obj(
                        ["receipt_id", "receipt_hash"],
                        {"receipt_id": token, "receipt_hash": derived},
                    ),
                ]
            },
            "relation": provider_relation,
        },
    )
    provider_effect = obj(
        [
            "role",
            "handle",
            "media_type",
            "text",
            "byte_length",
            "before_sha256",
            "after_sha256",
        ],
        {
            "role": {
                "enum": [
                    "artifact",
                    "audit-log",
                    "evidence",
                    "machine-index",
                    "visible-index",
                ]
            },
            "handle": token,
            "media_type": {
                "enum": ["application/json", "text/markdown; charset=utf-8"]
            },
            "text": {"type": "string"},
            "byte_length": uint,
            "before_sha256": {"oneOf": [{"type": "null"}, hash_value]},
            "after_sha256": hash_value,
        },
    )
    provider_plan = obj(
        [
            "schema",
            "plan_id",
            "adapter",
            "hmk_commit",
            "request",
            "request_hash",
            "policy_hash",
            "target",
            "sequence",
            "predecessor_receipt_id",
            "effects",
            "scan",
            "expected_result_hash",
        ],
        {
            "schema": {"const": publication.PROVIDER_PLAN_SCHEMA},
            "plan_id": token,
            "adapter": obj(
                ["id", "version", "schema_version"],
                {
                    "id": {"const": publication.PROVIDER_ADAPTER_ID},
                    "version": {"const": publication.PROVIDER_API_VERSION},
                    "schema_version": {"const": 1},
                },
            ),
            "hmk_commit": {"const": publication.HMK_COMMIT},
            "request": provider_request,
            "request_hash": hash_value,
            "policy_hash": {"const": publication.PROVIDER_POLICY_HASH},
            "target": target,
            "sequence": {**uint, "minimum": 1},
            "predecessor_receipt_id": nullable_token,
            "effects": {
                "type": "array",
                "minItems": 4,
                "maxItems": 5,
                "uniqueItems": True,
                "items": provider_effect,
            },
            "scan": obj(
                ["engine", "result"],
                {
                    "engine": {"const": "compaii-state-secret-scan/v1"},
                    "result": {"const": "clean"},
                },
            ),
            "expected_result_hash": hash_value,
        },
    )
    provider_receipt = obj(
        [
            "schema",
            "request_id",
            "request_hash",
            "plan_id",
            "expected_result_hash",
            "target",
            "artifact_class",
            "operation",
            "sequence",
            "predecessor_receipt_id",
            "relation",
            "source_event_refs",
            "source_release_ref",
            "source_checkpoint_id",
            "source_checkpoint_hash",
            "source_checkpoint_high_waters",
            "policy",
            "review",
            "governance",
            "publisher_principal",
            "transaction_id",
            "lease",
            "effects",
            "artifact_sha256",
            "audit_head_sha256",
            "hmk",
            "outcome",
            "committed_at_ms",
            "receipt_id",
            "receipt_hash",
        ],
        {
            "schema": {"const": publication.PROVIDER_RECEIPT_SCHEMA},
            "request_id": uuid4,
            "request_hash": hash_value,
            "plan_id": token,
            "expected_result_hash": hash_value,
            "target": target,
            "artifact_class": {"enum": sorted(publication.ARTIFACT_CLASSES)},
            "operation": {"enum": sorted(publication.OPERATIONS)},
            "sequence": {**uint, "minimum": 1},
            "predecessor_receipt_id": nullable_token,
            "relation": provider_relation,
            "source_event_refs": {
                "type": "array",
                "minItems": 1,
                "uniqueItems": True,
                "items": provider_event_ref,
            },
            "source_release_ref": {"oneOf": [{"type": "null"}, provider_release_ref]},
            "source_checkpoint_id": token,
            "source_checkpoint_hash": hash_value,
            "source_checkpoint_high_waters": high_waters,
            "policy": provider_policy_ref,
            "review": provider_review,
            "governance": provider_governance,
            "publisher_principal": {"const": publication.PUBLISHER_PRINCIPAL},
            "transaction_id": token,
            "lease": obj(
                ["lease_id", "generation"],
                {"lease_id": token, "generation": {**uint, "minimum": 1}},
            ),
            "effects": {
                "type": "array",
                "minItems": 4,
                "maxItems": 5,
                "uniqueItems": True,
                "items": obj(
                    ["role", "handle", "sha256", "byte_length"],
                    {
                        "role": {
                            "enum": [
                                "artifact",
                                "audit-log",
                                "evidence",
                                "machine-index",
                                "visible-index",
                            ]
                        },
                        "handle": token,
                        "sha256": hash_value,
                        "byte_length": uint,
                    },
                ),
            },
            "artifact_sha256": hash_value,
            "audit_head_sha256": hash_value,
            "hmk": obj(
                [
                    "artifact_chapter_id",
                    "evidence_chapter_id",
                    "artifact_sha256",
                    "evidence_sha256",
                    "derived_from",
                    "state_hash",
                ],
                {
                    "artifact_chapter_id": {**uint, "minimum": 1},
                    "evidence_chapter_id": {**uint, "minimum": 1},
                    "artifact_sha256": hash_value,
                    "evidence_sha256": hash_value,
                    "derived_from": {"const": True},
                    "state_hash": hash_value,
                },
            ),
            "outcome": {
                "enum": ["published", "superseded", "tombstoned", "rolled-back"]
            },
            "committed_at_ms": uint,
            "receipt_id": token,
            "receipt_hash": derived,
        },
    )
    acceptance = obj(
        [
            "schema",
            "acceptance_id",
            "request_event_id",
            "request_event_hash",
            "request_id",
            "proposal_id",
            "target",
            "operation",
            "sequence",
            "predecessor_acceptance_event_id",
            "claim_id",
            "claim_generation",
            "provider_commit",
            "provider_receipt",
            "accepted_at_ms",
        ],
        {
            "schema": {"const": publication.ACCEPTANCE_SCHEMA},
            "acceptance_id": token,
            "request_event_id": uuid4,
            "request_event_hash": hash_value,
            "request_id": token,
            "proposal_id": token,
            "target": target,
            "operation": {"enum": sorted(publication.OPERATIONS)},
            "sequence": {**uint, "minimum": 1},
            "predecessor_acceptance_event_id": {"oneOf": [{"type": "null"}, uuid4]},
            "claim_id": uuid4,
            "claim_generation": {**uint, "minimum": 1},
            "provider_commit": {"const": publication.COMPAII_STATE_COMMIT},
            "provider_receipt": provider_receipt,
            "accepted_at_ms": uint,
        },
    )
    queue = obj(
        ["schema", "cutoff", "items"],
        {
            "schema": {"const": publication.QUEUE_SCHEMA},
            "cutoff": obj(
                ["events", "checkpoint_id"],
                {
                    "events": {"type": "array", "items": event_ref},
                    "checkpoint_id": token,
                },
            ),
            "items": {
                "type": "array",
                "uniqueItems": True,
                "items": obj(
                    [
                        "request_event_id",
                        "request_event_hash",
                        "request_id",
                        "proposal_id",
                        "target",
                        "operation",
                        "state",
                        "acceptance_event_id",
                    ],
                    {
                        "request_event_id": uuid4,
                        "request_event_hash": hash_value,
                        "request_id": token,
                        "proposal_id": token,
                        "target": target,
                        "operation": {"enum": sorted(publication.OPERATIONS)},
                        "state": {"enum": ["pending", "completed"]},
                        "acceptance_event_id": {"oneOf": [{"type": "null"}, uuid4]},
                    },
                ),
            },
        },
    )
    reconciliation = obj(
        ["schema", "acceptance_event_id", "status"],
        {
            "schema": {"const": publication.RECONCILIATION_SCHEMA},
            "acceptance_event_id": uuid4,
            "status": {
                "enum": [
                    "verified",
                    "superseded",
                    "effect-truth-discrepancy",
                    "effect-truth-unverifiable",
                ]
            },
        },
    )
    profile = obj(
        [
            "schema",
            "profile_id",
            "source_instance",
            "provider_commit",
            "provider_adapter_id",
            "provider_api_version",
            "provider_contract_version",
            "provider_policy_id",
            "provider_policy_hash",
            "hmk_commit",
            "publisher_principal",
        ],
        {
            "schema": {"const": publication.PROFILE_SCHEMA},
            "profile_id": token,
            "source_instance": token,
            "provider_commit": {"const": publication.COMPAII_STATE_COMMIT},
            "provider_adapter_id": {"const": publication.PROVIDER_ADAPTER_ID},
            "provider_api_version": {"const": publication.PROVIDER_API_VERSION},
            "provider_contract_version": {"const": "v1"},
            "provider_policy_id": {"const": publication.PROVIDER_POLICY_ID},
            "provider_policy_hash": {"const": publication.PROVIDER_POLICY_HASH},
            "hmk_commit": {"const": publication.HMK_COMMIT},
            "publisher_principal": {"const": publication.PUBLISHER_PRINCIPAL},
        },
    )
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://daimon.network/schemas/publication/v1/contracts.schema.json",
        "oneOf": [
            {"$ref": f"#/$defs/{name}"}
            for name in (
                "profile",
                "policy",
                "proposal",
                "review",
                "request",
                "claim",
                "providerPlan",
                "providerReceipt",
                "acceptance",
                "queue",
                "reconciliation",
            )
        ],
        "$defs": {
            "profile": profile,
            "policy": policy,
            "proposal": proposal,
            "review": review,
            "request": request,
            "claim": claim,
            "providerPlan": provider_plan,
            "providerReceipt": provider_receipt,
            "acceptance": acceptance,
            "queue": queue,
            "reconciliation": reconciliation,
        },
    }


def load_provider(root: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "dm035_vector_provider", root / "matrix_publisher.py"
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("provider module unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(root))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(root))
    return module


def verify_checkout(root: Path, expected: str, label: str) -> None:
    try:
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError) as exception:
        raise RuntimeError(f"{label} checkout unavailable") from exception
    if head != expected:
        raise RuntimeError(f"{label} checkout must be exact commit {expected}")


def write(path: Path, value: Any, *, pretty: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = (
        (
            json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
        ).encode()
        if pretty
        else canonical_bytes(value) + b"\n"
    )
    path.write_bytes(raw)


def generate(
    output: Path,
    schema_path: Path,
    provider_root: Path,
    hmk_root: Path,
) -> None:
    verify_checkout(provider_root, publication.COMPAII_STATE_COMMIT, "compaii-state")
    verify_checkout(hmk_root, publication.HMK_COMMIT, "HMK")
    reviewer_key = Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(b"dm035-vector-reviewer").digest()
    )
    reviewer = publication.reviewer_descriptor(
        "reviewer@vector", reviewer_key.public_key()
    )
    policy = publication.create_publication_policy(
        subject_me_id=SUBJECT,
        version=1,
        predecessor_policy_id=None,
        reviewers=[reviewer],
        max_pending=8,
    )
    profile = publication.create_publication_profile(source_instance="matrix:vector")
    event_hash = hashlib.sha256(b"dm035-vector-source").hexdigest()
    checkpoint_core = {
        "schema": publication.CHECKPOINT_SCHEMA,
        "being_ref": SUBJECT,
        "manifest_hash": hashlib.sha256(b"dm035-vector-manifest").hexdigest(),
        "source_events": [{"event_id": SOURCE_EVENT, "event_hash": event_hash}],
        "high_waters": {"ledger-events": 1},
        "captured_at_ms": NOW,
    }
    checkpoint_hash = hashlib.sha256(
        publication.CHECKPOINT_DOMAIN + canonical_bytes(checkpoint_core)
    ).hexdigest()
    checkpoint = {
        **checkpoint_core,
        "checkpoint_id": "dm:publication-checkpoint:v1:" + checkpoint_hash,
        "checkpoint_hash": checkpoint_hash,
    }
    body_ref = publication.create_content_ref(BODY.encode())
    proposal_core: dict[str, Any] = {
        "schema": publication.PROPOSAL_SCHEMA,
        "provider_request_id": PROVIDER_REQUEST,
        "review_decision_id": REVIEW_ID,
        "requested_at_ms": NOW,
        "operation": "publish",
        "artifact_class": "identity-summary",
        "source": {
            "subject_me_id": SUBJECT,
            "author_me_id": SUBJECT,
            "event_refs": checkpoint["source_events"],
            "release_ref": None,
            "checkpoint": checkpoint,
        },
        "title": "CompAII",
        "body_ref": body_ref,
        "rendered_ref": {
            "media_type": "text/markdown; charset=utf-8",
            "byte_length": 1,
            "sha256": "0" * 64,
        },
        "target": {
            "kind": "llm-wiki",
            "logical_id": "project/daimon-matrix/compaii",
        },
        "governance": {
            "classification": "public",
            "consent": "explicit",
            "license": "CC-BY-SA-4.0",
            "derivation_ref": "derivation:matrix:vector",
        },
        "matrix_policy_id": policy["policy_id"],
        "matrix_policy_hash": hashlib.sha256(canonical_bytes(policy)).hexdigest(),
        "provider_policy_id": publication.PROVIDER_POLICY_ID,
        "provider_policy_hash": publication.PROVIDER_POLICY_HASH,
        "predecessor": None,
        "relation": {
            "supersedes_acceptance_event_id": None,
            "compensates_acceptance_event_id": None,
        },
    }
    rendered = publication._render(proposal_core, BODY, validate_ref=False)
    proposal_core["rendered_ref"] = {
        "media_type": "text/markdown; charset=utf-8",
        "byte_length": len(rendered.encode()),
        "sha256": hashlib.sha256(rendered.encode()).hexdigest(),
    }
    proposal = publication.validate_publication_proposal(
        {
            **proposal_core,
            "proposal_id": publication._identifier(
                "dm:publication-proposal:v1:",
                publication.PROPOSAL_DOMAIN,
                proposal_core,
            ),
        }
    )
    review = publication.sign_publication_review(
        proposal,
        reviewer=reviewer,
        private_key=reviewer_key,
        issued_at_ms=NOW - 1,
        expires_at_ms=NOW + 600_000,
    )
    request = publication.create_publication_request(proposal, policy, review)
    provider_request = publication._provider_request(request, rendered)
    provider_module = load_provider(provider_root)
    with tempfile.TemporaryDirectory(prefix="dm035-vectors-") as temporary:
        base = Path(temporary)
        project = base / "wiki" / "projects" / "daimon-matrix"
        project.mkdir(parents=True)
        (project / "index.md").write_text("# Daimon Matrix\n")
        api = provider_module.MatrixPublisher(
            wiki_root=base / "wiki",
            projection_root=base / "state",
            runtime_root=base / "runtime",
            hmk_root=hmk_root,
            hmk_base=base / "hmk",
            policy_path=provider_root / "policies" / "matrix-publisher-v1.json",
            clock_ms=lambda: NOW,
        )
        plan = publication._provider_plan(api.plan(provider_request), provider_request)
        lease = publication._provider_lease(
            api.acquire_lease(
                target_kind="llm-wiki",
                namespace="daimon-matrix",
                owner=publication.PUBLISHER_PRINCIPAL,
                ttl_ms=600_000,
            ),
            target=proposal["target"],
            now=NOW,
        )
        provider_receipt = publication._provider_receipt(
            api.apply(plan, lease), request=provider_request, plan=plan, lease=lease
        )
    request_event_hash = hashlib.sha256(b"dm035-vector-request-event").hexdigest()
    claim_core = {
        "schema": publication.CLAIM_SCHEMA,
        "claim_id": CLAIM_ID,
        "request_event_id": REQUEST_EVENT,
        "request_event_hash": request_event_hash,
        "target": copy.deepcopy(proposal["target"]),
        "generation": 1,
        "actor_origin": {
            "body_ref": "cluster:vector:compaii",
            "embodiment_id": "embodiment:vector",
            "incarnation_id": "incarnation:vector:0",
            "principal_id": "compaii@vector",
        },
        "issued_at_ms": NOW,
        "lease_until_ms": NOW + 600_000,
    }
    claim = publication.validate_publication_claim(
        {
            **claim_core,
            "content_hash": hashlib.sha256(
                publication.CLAIM_DOMAIN + canonical_bytes(claim_core)
            ).hexdigest(),
        }
    )
    acceptance_core = {
        "schema": publication.ACCEPTANCE_SCHEMA,
        "request_event_id": REQUEST_EVENT,
        "request_event_hash": request_event_hash,
        "request_id": request["request_id"],
        "proposal_id": proposal["proposal_id"],
        "target": copy.deepcopy(proposal["target"]),
        "operation": "publish",
        "sequence": 1,
        "predecessor_acceptance_event_id": None,
        "claim_id": CLAIM_ID,
        "claim_generation": 1,
        "provider_commit": publication.COMPAII_STATE_COMMIT,
        "provider_receipt": provider_receipt,
        "accepted_at_ms": NOW,
    }
    acceptance = publication.validate_publication_acceptance(
        {
            **acceptance_core,
            "acceptance_id": publication._identifier(
                "dm:publication-acceptance:v1:",
                publication.ACCEPTANCE_DOMAIN,
                acceptance_core,
            ),
        }
    )
    queue = {
        "schema": publication.QUEUE_SCHEMA,
        "cutoff": {
            "events": [{"event_id": REQUEST_EVENT, "event_hash": request_event_hash}],
            "checkpoint_id": "dm:publication-queue-checkpoint:v1:"
            + b64url(
                hashlib.sha256(
                    b"daimon/publication/queue-checkpoint/v1\x00"
                    + canonical_bytes(
                        {
                            "events": [
                                {
                                    "event_id": REQUEST_EVENT,
                                    "event_hash": request_event_hash,
                                }
                            ]
                        }
                    )
                ).digest()
            ),
        },
        "items": [
            {
                "request_event_id": REQUEST_EVENT,
                "request_event_hash": request_event_hash,
                "request_id": request["request_id"],
                "proposal_id": proposal["proposal_id"],
                "target": proposal["target"],
                "operation": "publish",
                "state": "pending",
                "acceptance_event_id": None,
            }
        ],
    }
    reconciliation = {
        "schema": publication.RECONCILIATION_SCHEMA,
        "acceptance_event_id": "35000000-0000-4000-8000-000000000006",
        "status": "verified",
    }
    vectors = {
        "profile.json": profile,
        "policy.json": policy,
        "proposal.json": proposal,
        "review.json": review,
        "request.json": request,
        "claim.json": claim,
        "provider-plan.json": plan,
        "provider-receipt.json": provider_receipt,
        "acceptance.json": acceptance,
        "queue.json": queue,
        "reconciliation.json": reconciliation,
    }
    negative = copy.deepcopy(proposal)
    negative["host_path"] = "/tmp/forbidden"
    vectors["negative/proposal-host-path.json"] = negative
    for name, value in vectors.items():
        write(output / name, value)
    index = {
        "schema": "dm.publication.vector-index/v1",
        "compaii_state_commit": publication.COMPAII_STATE_COMMIT,
        "hmk_commit": publication.HMK_COMMIT,
        "schema_path": "schemas/publication/v1/contracts.schema.json",
        "entries": [
            {
                "path": name,
                "expect": "reject" if name.startswith("negative/") else "accept",
                "sha256": hashlib.sha256((output / name).read_bytes()).hexdigest(),
            }
            for name in sorted(vectors)
        ],
    }
    write(output / "index.json", index)
    write(schema_path, schema(), pretty=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--provider-root", type=Path, required=True)
    parser.add_argument("--hmk-root", type=Path, required=True)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    args = parser.parse_args()
    generate(args.out, args.schema, args.provider_root, args.hmk_root)


if __name__ == "__main__":
    main()
