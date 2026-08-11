#!/usr/bin/env python3
"""Generate deterministic DM-041 schemas, provenance and public vectors."""

from __future__ import annotations

import argparse
import copy
import hashlib
import os
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import daimon_matrix.hermes_body as hermes_body  # noqa: E402
import daimon_matrix.memory_projection as memory_projection  # noqa: E402
from daimon_matrix.canonical import b64url, canonical_bytes  # noqa: E402
from daimon_matrix.memory_policy import create_content_ref  # noqa: E402

HASH = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
DERIVED = {
    "type": "string",
    "pattern": "^dm:[a-z0-9-]+:v[01]:[A-Za-z0-9_-]{43}$",
}
OPAQUE_ID = {"type": "string", "minLength": 1, "maxLength": 192}
UUID = {"type": "string", "format": "uuid"}
UINT = {"type": "integer", "minimum": 0, "maximum": 2**53 - 1}


def closed(
    properties: dict[str, Any], required: list[str] | None = None
) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": properties,
        "required": required or list(properties),
        "additionalProperties": False,
    }


def signature_schema() -> dict[str, Any]:
    return closed(
        {
            "alg": {"const": "Ed25519"},
            "kid": {"type": "string", "minLength": 1, "maxLength": 192},
            "value": {"type": "string", "pattern": "^[A-Za-z0-9_-]{86}$"},
        }
    )


def bootstrap_schema() -> dict[str, Any]:
    return closed(
        {
            "schema": {"const": hermes_body.BOOTSTRAP_SCHEMA},
            "being_ref": {
                "type": "string",
                "pattern": "^dm:being:v1:[A-Za-z0-9_-]{43}$",
            },
            "body_ref": OPAQUE_ID,
            "embodiment_id": OPAQUE_ID,
            "incarnation_id": OPAQUE_ID,
            "matrix_session_id": DERIVED,
            "matrix_high_water": HASH,
            "capability_set_hash": HASH,
            "certificate_hash": HASH,
            "issued_at_ms": UINT,
            "expires_at_ms": UINT,
            "signature": signature_schema(),
        }
    )


def memory_entry_schema() -> dict[str, Any]:
    return closed(
        {
            "event_id": UUID,
            "event_hash": HASH,
            "memory_id": UUID,
            "sequence": {**UINT, "minimum": 1},
            "category": {
                "enum": ["personal-experience", "personal-insight", "personal-skill"]
            },
            "author_me_id": {
                "type": "string",
                "pattern": "^dm:being:v1:[A-Za-z0-9_-]{43}$",
            },
            "context": {"type": "string", "minLength": 1, "maxLength": 128},
            "content_ref": closed(
                {
                    "schema": {"const": "dm.memory.content-ref/v1"},
                    "content_id": DERIVED,
                    "sha256": HASH,
                    "byte_length": {**UINT, "minimum": 1},
                    "media_type": {"enum": ["text/plain", "text/markdown"]},
                    "classification": {
                        "enum": ["public", "personal", "private", "protected"]
                    },
                }
            ),
            "evidence_refs": {
                "type": "array",
                "maxItems": 256,
                "uniqueItems": True,
                "items": UUID,
            },
            "policy_id": DERIVED,
            "candidate_id": DERIVED,
            "decision_id": DERIVED,
            "origin": closed(
                {
                    "body_ref": {"type": "string", "minLength": 1, "maxLength": 256},
                    "embodiment_id": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 256,
                    },
                    "incarnation_id": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 256,
                    },
                    "principal_id": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 256,
                    },
                }
            ),
        }
    )


def contracts_schema() -> dict[str, Any]:
    python = closed(
        {
            "implementation": {"const": "cpython"},
            "version": {"type": "string", "pattern": "^3\\.(11|12|13)\\.[0-9]+$"},
            "executable_sha256": HASH,
            "supported_interval": {"const": ">=3.11,<3.14"},
        }
    )
    matrix_package = closed(
        {
            "modules": {
                "type": "array",
                "minItems": 1,
                "maxItems": 256,
                "uniqueItems": True,
                "items": closed(
                    {
                        "name": {
                            "type": "string",
                            "pattern": "^[A-Za-z0-9_./-]+[.]py$",
                            "maxLength": 256,
                        },
                        "sha256": HASH,
                    }
                ),
            },
            "contract_schema_sha256": HASH,
            "current_memory_schema_sha256": HASH,
            "tree_sha256": HASH,
        }
    )
    handle = closed(
        {
            "schema": {"const": hermes_body.RUNTIME_HANDLE_SCHEMA},
            "plan_id": DERIVED,
            "profile_id": DERIVED,
            "hermes_session_id": {"type": "string", "minLength": 1, "maxLength": 256},
            "matrix_high_water": HASH,
            "generation": {**UINT, "minimum": 1},
            "state": {"enum": sorted(hermes_body.RUNTIME_TRANSITIONS)},
            "predecessor_handle_id": {"oneOf": [DERIVED, {"type": "null"}]},
            "handle_id": DERIVED,
        }
    )
    compatibility = closed(
        {
            "schema": {"const": hermes_body.COMPATIBILITY_SCHEMA},
            "version": {"const": hermes_body.HERMES_VERSION},
            "commit": {"const": hermes_body.HERMES_COMMIT},
            "tree": {"const": hermes_body.HERMES_TREE},
            "archive_sha256": {"const": hermes_body.HERMES_ARCHIVE_SHA256},
            "contract_digests": {"const": hermes_body.HERMES_CONTRACT_DIGESTS},
        }
    )
    profile_manifest = closed(
        {
            "schema": {"const": hermes_body.PROFILE_MANIFEST_SCHEMA},
            "plan_hash": HASH,
            "adapter_version": {"const": "1.0.0"},
            "hermes_version": {"const": hermes_body.HERMES_VERSION},
            "hermes_commit": {"const": hermes_body.HERMES_COMMIT},
            "hermes_python": python,
            "matrix_package": matrix_package,
            "being_ref": {
                "type": "string",
                "pattern": "^dm:being:v1:[A-Za-z0-9_-]{43}$",
            },
            "body_ref": OPAQUE_ID,
            "embodiment_id": OPAQUE_ID,
            "incarnation_id": OPAQUE_ID,
            "matrix_session_id": DERIVED,
            "workspace_ref": DERIVED,
            "files": {
                "type": "array",
                "minItems": len(hermes_body.PROFILE_FILES),
                "maxItems": len(hermes_body.PROFILE_FILES),
                "uniqueItems": True,
                "items": closed(
                    {
                        "name": {"enum": list(hermes_body.PROFILE_FILES)},
                        "sha256": HASH,
                    }
                ),
            },
            "profile_id": DERIVED,
        }
    )
    provider_config = closed(
        {
            "schema": {"const": hermes_body.PROVIDER_CONFIG_SCHEMA},
            "plan_id": DERIVED,
            "being_ref": {
                "type": "string",
                "pattern": "^dm:being:v1:[A-Za-z0-9_-]{43}$",
            },
            "body_ref": OPAQUE_ID,
            "embodiment_id": OPAQUE_ID,
            "incarnation_id": OPAQUE_ID,
            "matrix_session_id": DERIVED,
            "matrix_high_water": HASH,
            "expires_at_ms": UINT,
            "socket_path": {"type": "string", "pattern": "^/", "maxLength": 4096},
            "client_config_path": {
                "type": "string",
                "pattern": "^/",
                "maxLength": 4096,
            },
            "capability_fd": {**UINT, "minimum": 3, "maximum": 4096},
            "ready_fd": {**UINT, "minimum": 3, "maximum": 4096},
            "max_context_bytes": {"const": hermes_body.MAX_CONTEXT_BYTES},
            "max_query_bytes": {"const": hermes_body.MAX_QUERY_BYTES},
            "tool_names": {"const": list(hermes_body.PROVIDER_TOOL_NAMES)},
        }
    )
    checkpoint = closed({"sequence": UINT, "hash": HASH})
    context = closed(
        {
            "schema": {"const": hermes_body.CONTEXT_SCHEMA},
            "being_ref": DERIVED,
            "body_ref": OPAQUE_ID,
            "embodiment_id": OPAQUE_ID,
            "incarnation_id": OPAQUE_ID,
            "matrix_session_id": DERIVED,
            "hermes_session_id": {"type": "string", "minLength": 1, "maxLength": 256},
            "query_hash": HASH,
            "matrix_high_water": HASH,
            "projection_hash": HASH,
            "memory_checkpoint": checkpoint,
            "entries": {
                "type": "array",
                "maxItems": 64,
                "items": memory_entry_schema(),
            },
            "truncated": {"type": "boolean"},
            "context_id": DERIVED,
        }
    )
    scope_result = closed(
        {
            "schema": {"const": hermes_body.SCOPE_RESULT_SCHEMA},
            "being_ref": DERIVED,
            "body_ref": OPAQUE_ID,
            "embodiment_id": OPAQUE_ID,
            "incarnation_id": OPAQUE_ID,
            "matrix_high_water": HASH,
            "projection_hash": HASH,
        }
    )
    effect_receipt = closed(
        {
            "schema": {"const": hermes_body.EFFECT_RECEIPT_SCHEMA},
            "operation": {"const": "propose-observation"},
            "operation_id": UUID,
            "event_id": UUID,
            "event_hash": HASH,
            "being_ref": DERIVED,
            "body_ref": OPAQUE_ID,
            "embodiment_id": OPAQUE_ID,
            "incarnation_id": OPAQUE_ID,
            "matrix_high_water": HASH,
            "sensitivity": {"enum": ["personal", "private", "shareable"]},
            "adopted": {"const": False},
            "receipt_id": DERIVED,
        }
    )
    tool_error = closed(
        {
            "schema": {"const": hermes_body.TOOL_ERROR_SCHEMA},
            "ok": {"const": False},
            "code": {
                "type": "string",
                "pattern": "^[a-z][a-z0-9_]{0,127}$",
            },
            "retryable": {"type": "boolean"},
        }
    )
    plan = closed(
        {
            "schema": {"const": hermes_body.PLAN_SCHEMA},
            "adapter_version": {"const": "1.0.0"},
            "workspace_ref": DERIVED,
            "bootstrap": bootstrap_schema(),
            "hermes": closed(
                {
                    "version": {"const": hermes_body.HERMES_VERSION},
                    "commit": {"const": hermes_body.HERMES_COMMIT},
                    "tree": {"const": hermes_body.HERMES_TREE},
                    "archive_sha256": {"const": hermes_body.HERMES_ARCHIVE_SHA256},
                    "contract_digests": {"const": hermes_body.HERMES_CONTRACT_DIGESTS},
                    "model": {"type": "string", "minLength": 1, "maxLength": 256},
                    "provider": {"type": "string", "minLength": 1, "maxLength": 256},
                }
            ),
            "profile_policy": {
                "const": {
                    "context_engine": "compressor",
                    "external_memory_provider": hermes_body.PROVIDER_NAME,
                    "general_plugins": [],
                    "native_memory": False,
                    "project_plugins": False,
                    "provider_tools": list(hermes_body.PROVIDER_TOOL_NAMES),
                    "shell_hooks": False,
                    "toolsets": ["memory"],
                }
            },
        }
    )
    ready = closed(
        {
            "schema": {"const": hermes_body.PROVIDER_READY_SCHEMA},
            "plan_id": DERIVED,
            "being_ref": DERIVED,
            "body_ref": OPAQUE_ID,
            "embodiment_id": OPAQUE_ID,
            "incarnation_id": OPAQUE_ID,
            "matrix_session_id": DERIVED,
            "hermes_session_id": {"type": "string", "minLength": 1, "maxLength": 256},
            "matrix_high_water": HASH,
            "at_ms": UINT,
            "ready_id": DERIVED,
        }
    )
    park_request = closed(
        {
            "schema": {"const": hermes_body.PARK_REQUEST_SCHEMA},
            "plan_id": DERIVED,
            "profile_id": DERIVED,
            "being_ref": DERIVED,
            "body_ref": OPAQUE_ID,
            "embodiment_id": OPAQUE_ID,
            "incarnation_id": OPAQUE_ID,
            "matrix_session_id": DERIVED,
            "hermes_session_id": {"type": "string", "minLength": 1, "maxLength": 256},
            "matrix_high_water": HASH,
            "active_handle_id": DERIVED,
            "parking_handle_id": DERIVED,
            "outstanding_request_ids": {
                "type": "array",
                "maxItems": 256,
                "uniqueItems": True,
                "items": UUID,
            },
            "park_request_id": DERIVED,
        }
    )
    park_receipt = closed(
        {
            "schema": {"const": hermes_body.PARK_RECEIPT_SCHEMA},
            "park_request_id": DERIVED,
            "profile_id": DERIVED,
            "being_ref": DERIVED,
            "body_ref": OPAQUE_ID,
            "embodiment_id": OPAQUE_ID,
            "incarnation_id": OPAQUE_ID,
            "matrix_session_id": DERIVED,
            "hermes_session_id": {"type": "string", "minLength": 1, "maxLength": 256},
            "matrix_high_water": HASH,
            "handoff_receipt_ref": DERIVED,
            "presence_receipt_ref": DERIVED,
            "presence_state": {"const": "relinquished"},
            "committed_at_ms": UINT,
            "park_receipt_id": DERIVED,
        }
    )
    launch = closed(
        {
            "schema": {"const": hermes_body.LAUNCH_RECEIPT_SCHEMA},
            "plan_id": DERIVED,
            "profile_id": DERIVED,
            "hermes_version": {"const": hermes_body.HERMES_VERSION},
            "hermes_commit": {"const": hermes_body.HERMES_COMMIT},
            "hermes_python": python,
            "matrix_package": matrix_package,
            "hermes_session_id": {"type": "string", "minLength": 1, "maxLength": 256},
            "matrix_high_water": HASH,
            "starting_handle_id": DERIVED,
            "active_handle_id": DERIVED,
            "provider_ready_id": DERIVED,
            "deployment": {"const": "synthetic-isolated"},
            "launch_receipt_id": DERIVED,
        }
    )
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://daimon.invalid/schemas/hermes/v1/contracts.schema.json",
        "title": "DM-041 Hermes body contracts",
        "oneOf": [
            bootstrap_schema(),
            compatibility,
            plan,
            profile_manifest,
            provider_config,
            ready,
            handle,
            context,
            scope_result,
            effect_receipt,
            tool_error,
            launch,
            park_request,
            park_receipt,
        ],
    }


def current_projection_schema() -> dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://daimon.invalid/schemas/memory-projection/v1/current.schema.json",
        "title": "Current provenance-only personal-memory projection",
        **closed(
            {
                "schema": {"const": memory_projection.CURRENT_PROJECTION_SCHEMA},
                "being_ref": DERIVED,
                "manifest_hash": HASH,
                "checkpoint": closed({"sequence": UINT, "hash": HASH}),
                "entries": {
                    "type": "array",
                    "maxItems": 64,
                    "items": memory_entry_schema(),
                },
                "total_active": UINT,
                "truncated": {"type": "boolean"},
                "projection_hash": HASH,
            }
        ),
    }


def derived(kind: str, label: str) -> str:
    return f"dm:{kind}:v1:" + b64url(hashlib.sha256(label.encode()).digest())


def bootstrap_vector() -> dict[str, Any]:
    return {
        "schema": hermes_body.BOOTSTRAP_SCHEMA,
        "being_ref": derived("being", "dm041-being"),
        "body_ref": derived("body", "dm041-body"),
        "embodiment_id": derived("embodiment", "dm041-embodiment"),
        "incarnation_id": derived("incarnation", "dm041-incarnation"),
        "matrix_session_id": derived("session", "dm041-matrix-session"),
        "matrix_high_water": hashlib.sha256(b"dm041-high-water").hexdigest(),
        "capability_set_hash": hashlib.sha256(b"dm041-capability").hexdigest(),
        "certificate_hash": hashlib.sha256(b"dm041-certificate").hexdigest(),
        "issued_at_ms": 1_800_000_000_000,
        "expires_at_ms": 1_800_003_600_000,
        "signature": {
            "alg": "Ed25519",
            "kid": derived("key", "dm041-bootstrap-key"),
            "value": b64url(bytes(range(64))),
        },
    }


def handle_vector(
    plan: dict[str, Any],
    profile_id: str,
    *,
    generation: int,
    state: str,
    predecessor: str | None,
) -> dict[str, Any]:
    core = {
        "schema": hermes_body.RUNTIME_HANDLE_SCHEMA,
        "plan_id": hermes_body.plan_id(plan),
        "profile_id": profile_id,
        "hermes_session_id": "hermes-session-vector",
        "matrix_high_water": plan["bootstrap"]["matrix_high_water"],
        "generation": generation,
        "state": state,
        "predecessor_handle_id": predecessor,
    }
    return hermes_body.validate_runtime_handle(
        {
            **core,
            "handle_id": hermes_body._derived(
                "dm:hermes-handle:v1:", hermes_body.HANDLE_DOMAIN, core
            ),
        }
    )


def memory_entry(bootstrap: dict[str, Any]) -> dict[str, Any]:
    raw = b"Synthetic DM-041 personal-memory projection."
    return {
        "event_id": "41000000-0000-4000-8000-000000000001",
        "event_hash": hashlib.sha256(b"dm041-memory-event").hexdigest(),
        "memory_id": "41000000-0000-4000-8000-000000000002",
        "sequence": 1,
        "category": "personal-insight",
        "author_me_id": bootstrap["being_ref"],
        "context": "synthetic-vector",
        "content_ref": create_content_ref(
            sha256=hashlib.sha256(raw).hexdigest(),
            byte_length=len(raw),
            media_type="text/plain",
            classification="personal",
        ),
        "evidence_refs": ["41000000-0000-4000-8000-000000000003"],
        "policy_id": derived("memory-policy", "dm041-policy"),
        "candidate_id": derived("memory-candidate", "dm041-candidate"),
        "decision_id": derived("memory-decision", "dm041-decision"),
        "origin": {
            "body_ref": bootstrap["body_ref"],
            "embodiment_id": bootstrap["embodiment_id"],
            "incarnation_id": bootstrap["incarnation_id"],
            "principal_id": derived("principal", "dm041-principal"),
        },
    }


def json_bytes(value: Any) -> bytes:
    return canonical_bytes(value) + b"\n"


def outputs() -> dict[Path, bytes]:
    bootstrap = bootstrap_vector()
    plan = hermes_body.create_plan_value(
        bootstrap=bootstrap,
        model="synthetic/model",
        provider="synthetic",
        workspace_ref=derived("workspace", "dm041-workspace"),
    )
    profile_id = derived("hermes-profile", "dm041-profile")
    starting = handle_vector(
        plan, profile_id, generation=1, state="starting", predecessor=None
    )
    active = handle_vector(
        plan,
        profile_id,
        generation=2,
        state="active",
        predecessor=starting["handle_id"],
    )
    parking = handle_vector(
        plan,
        profile_id,
        generation=3,
        state="parking",
        predecessor=active["handle_id"],
    )
    dummy_plan = hermes_body.HermesBodyPlan(
        plan,
        Path("/dm041/vector/profile"),
        Path("/dm041/vector/workspace"),
        Path("/dm041/vector/hermes"),
        Path("/dm041/vector/python"),
        Path("/dm041/vector/matrix.sock"),
        Path("/dm041/vector/client.json"),
        7,
        8,
    )
    compatibility = {
        "schema": hermes_body.COMPATIBILITY_SCHEMA,
        "version": hermes_body.HERMES_VERSION,
        "commit": hermes_body.HERMES_COMMIT,
        "tree": hermes_body.HERMES_TREE,
        "archive_sha256": hermes_body.HERMES_ARCHIVE_SHA256,
        "contract_digests": hermes_body.HERMES_CONTRACT_DIGESTS,
    }
    provider_config = hermes_body.validate_provider_config(
        hermes_body._provider_config(dummy_plan)
    )
    profile_files = hermes_body._profile_files(dummy_plan)
    profile_core = {
        "schema": hermes_body.PROFILE_MANIFEST_SCHEMA,
        "plan_hash": hashlib.sha256(
            hermes_body.PLAN_DOMAIN + canonical_bytes(plan)
        ).hexdigest(),
        "adapter_version": "1.0.0",
        "hermes_version": hermes_body.HERMES_VERSION,
        "hermes_commit": hermes_body.HERMES_COMMIT,
        "hermes_python": {
            "implementation": "cpython",
            "version": "3.13.5",
            "executable_sha256": hashlib.sha256(b"dm041-python").hexdigest(),
            "supported_interval": ">=3.11,<3.14",
        },
        "matrix_package": hermes_body.matrix_package_evidence(),
        "being_ref": bootstrap["being_ref"],
        "body_ref": bootstrap["body_ref"],
        "embodiment_id": bootstrap["embodiment_id"],
        "incarnation_id": bootstrap["incarnation_id"],
        "matrix_session_id": bootstrap["matrix_session_id"],
        "workspace_ref": plan["workspace_ref"],
        "files": [
            {"name": name, "sha256": hashlib.sha256(raw).hexdigest()}
            for name, (raw, _mode) in sorted(profile_files.items())
        ],
    }
    profile_manifest = {
        **profile_core,
        "profile_id": hermes_body._derived(
            "dm:hermes-profile:v1:", hermes_body.PROFILE_DOMAIN, profile_core
        ),
    }
    ready_core = {
        "schema": hermes_body.PROVIDER_READY_SCHEMA,
        "plan_id": hermes_body.plan_id(plan),
        **{
            key: bootstrap[key]
            for key in (
                "being_ref",
                "body_ref",
                "embodiment_id",
                "incarnation_id",
                "matrix_session_id",
            )
        },
        "hermes_session_id": "hermes-session-vector",
        "matrix_high_water": bootstrap["matrix_high_water"],
        "at_ms": 1_800_000_000_100,
    }
    ready = {
        **ready_core,
        "ready_id": hermes_body._derived(
            "dm:hermes-ready:v1:", hermes_body.READY_DOMAIN, ready_core
        ),
    }
    profile = {
        "profile_id": profile_id,
        "hermes_python": profile_manifest["hermes_python"],
        "matrix_package": profile_manifest["matrix_package"],
    }
    launch = hermes_body.create_launch_receipt(
        dummy_plan,
        profile=profile,
        starting_handle=starting,
        active_handle=active,
        ready=ready,
    )
    park_request = hermes_body.create_park_request(
        dummy_plan,
        active_handle=active,
        parking_handle=parking,
        outstanding_request_ids=["41000000-0000-4000-8000-000000000004"],
    )
    park_receipt = hermes_body.create_park_receipt(
        park_request,
        matrix_high_water=bootstrap["matrix_high_water"],
        handoff_receipt_ref=derived("handoff", "dm041-handoff"),
        presence_receipt_ref=derived("presence", "dm041-presence"),
        committed_at_ms=1_800_000_000_200,
    )
    entry = memory_entry(bootstrap)
    projection_core = {
        "schema": memory_projection.CURRENT_PROJECTION_SCHEMA,
        "being_ref": bootstrap["being_ref"],
        "manifest_hash": hashlib.sha256(b"dm041-manifest").hexdigest(),
        "checkpoint": {
            "sequence": 1,
            "hash": hashlib.sha256(b"dm041-memory-checkpoint").hexdigest(),
        },
        "entries": [entry],
        "total_active": 1,
        "truncated": False,
    }
    projection = memory_projection.validate_current_memory_projection(
        {
            **projection_core,
            "projection_hash": hashlib.sha256(
                memory_projection.CURRENT_PROJECTION_DOMAIN
                + canonical_bytes(projection_core)
            ).hexdigest(),
        }
    )
    context_core = {
        "schema": hermes_body.CONTEXT_SCHEMA,
        "being_ref": bootstrap["being_ref"],
        "body_ref": bootstrap["body_ref"],
        "embodiment_id": bootstrap["embodiment_id"],
        "incarnation_id": bootstrap["incarnation_id"],
        "matrix_session_id": bootstrap["matrix_session_id"],
        "hermes_session_id": "hermes-session-vector",
        "query_hash": hashlib.sha256(b"synthetic query").hexdigest(),
        "matrix_high_water": bootstrap["matrix_high_water"],
        "projection_hash": projection["projection_hash"],
        "memory_checkpoint": projection["checkpoint"],
        "entries": projection["entries"],
        "truncated": False,
    }
    context = hermes_body.validate_hermes_context(
        {
            **context_core,
            "context_id": hermes_body._derived(
                "dm:hermes-context:v1:", hermes_body.CONTEXT_DOMAIN, context_core
            ),
        }
    )
    scope_result = {
        "schema": hermes_body.SCOPE_RESULT_SCHEMA,
        "being_ref": bootstrap["being_ref"],
        "body_ref": bootstrap["body_ref"],
        "embodiment_id": bootstrap["embodiment_id"],
        "incarnation_id": bootstrap["incarnation_id"],
        "matrix_high_water": bootstrap["matrix_high_water"],
        "projection_hash": hashlib.sha256(b"dm041-scope-projection").hexdigest(),
    }
    effect_core = {
        "schema": hermes_body.EFFECT_RECEIPT_SCHEMA,
        "operation": "propose-observation",
        "operation_id": "41000000-0000-4000-8000-000000000005",
        "event_id": "41000000-0000-4000-8000-000000000006",
        "event_hash": hashlib.sha256(b"dm041-observation-event").hexdigest(),
        "being_ref": bootstrap["being_ref"],
        "body_ref": bootstrap["body_ref"],
        "embodiment_id": bootstrap["embodiment_id"],
        "incarnation_id": bootstrap["incarnation_id"],
        "matrix_high_water": bootstrap["matrix_high_water"],
        "sensitivity": "personal",
        "adopted": False,
    }
    effect_receipt = {
        **effect_core,
        "receipt_id": hermes_body._derived(
            "dm:hermes-effect:v1:", hermes_body.EFFECT_DOMAIN, effect_core
        ),
    }
    tool_error = {
        "schema": hermes_body.TOOL_ERROR_SCHEMA,
        "ok": False,
        "code": "matrix_daemon_unavailable",
        "retryable": True,
    }
    vectors: dict[str, Any] = {
        "valid/bootstrap.json": bootstrap,
        "valid/compatibility.json": compatibility,
        "valid/plan.json": plan,
        "valid/profile-manifest.json": profile_manifest,
        "valid/provider-config.json": provider_config,
        "valid/provider-ready.json": ready,
        "valid/runtime-starting.json": starting,
        "valid/runtime-active.json": active,
        "valid/runtime-parking.json": parking,
        "valid/launch-receipt.json": launch,
        "valid/park-request.json": park_request,
        "valid/park-receipt.json": park_receipt,
        "valid/context.json": context,
        "valid/scope-result.json": scope_result,
        "valid/effect-receipt.json": effect_receipt,
        "valid/tool-error.json": tool_error,
        "valid/current-memory-projection.json": projection,
        "negative/plan-unknown-field.json": {**copy.deepcopy(plan), "unknown": True},
        "negative/context-id-tampered.json": {
            **copy.deepcopy(context),
            "context_id": derived("hermes-context", "wrong"),
        },
        "negative/park-presence-not-relinquished.json": {
            **copy.deepcopy(park_receipt),
            "presence_state": "active",
        },
    }
    result = {
        ROOT / "schemas/hermes/v1/contracts.schema.json": json_bytes(
            contracts_schema()
        ),
        ROOT / "schemas/memory-projection/v1/current.schema.json": json_bytes(
            current_projection_schema()
        ),
        ROOT / "provenance/hermes-agent-0.19.0.json": json_bytes(
            {
                "schema": "dm.hermes-body.provenance/v1",
                "audited_at": "2026-08-05",
                "repository": "https://github.com/nicoechaniz/hermes-agent",
                "license": "MIT",
                "version": hermes_body.HERMES_VERSION,
                "commit": hermes_body.HERMES_COMMIT,
                "tree": hermes_body.HERMES_TREE,
                "git_archive_sha256": hermes_body.HERMES_ARCHIVE_SHA256,
                "python_interval": ">=3.11,<3.14",
                "contract_digests": hermes_body.HERMES_CONTRACT_DIGESTS,
                "supported_surfaces": [
                    "external-memory-provider",
                    "profile-plugin-discovery",
                    "memory-manager",
                    "current-user-api-content-sidecar",
                    "session-lifecycle-hooks",
                    "static-system-prompt-block",
                ],
                "matrix_payload": {
                    "provider_name": hermes_body.PROVIDER_NAME,
                    "tools": list(hermes_body.PROVIDER_TOOL_NAMES),
                    "soul_sha256": hashlib.sha256(
                        hermes_body.SOUL_TEMPLATE.encode()
                    ).hexdigest(),
                    "skill_sha256": hashlib.sha256(
                        hermes_body.SKILL_TEMPLATE.encode()
                    ).hexdigest(),
                    "plugin_sha256": hashlib.sha256(
                        hermes_body.PLUGIN_TEMPLATE.encode()
                    ).hexdigest(),
                    "plugin_manifest_sha256": hashlib.sha256(
                        hermes_body.PLUGIN_MANIFEST_TEMPLATE.encode()
                    ).hexdigest(),
                    "contract_schema_sha256": (
                        hermes_body.HERMES_CONTRACT_SCHEMA_SHA256
                    ),
                    "current_memory_schema_sha256": (
                        hermes_body.CURRENT_MEMORY_SCHEMA_SHA256
                    ),
                    "package_tree_sha256": hermes_body.matrix_package_evidence()[
                        "tree_sha256"
                    ],
                },
                "copy_policy": (
                    "No Hermes source or private profile bytes are distributed."
                ),
            }
        ),
    }
    vector_root = ROOT / "vectors/hermes/v1"
    for relative, value in vectors.items():
        result[vector_root / relative] = json_bytes(value)
    result[vector_root / "index.json"] = json_bytes(
        {
            "schema": "dm.hermes-body.vector-index/v1",
            "hermes_version": hermes_body.HERMES_VERSION,
            "hermes_commit": hermes_body.HERMES_COMMIT,
            "files": [
                {
                    "name": relative,
                    "sha256": hashlib.sha256(json_bytes(value)).hexdigest(),
                    "valid": relative.startswith("valid/"),
                }
                for relative, value in sorted(vectors.items())
            ],
        }
    )
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    expected = outputs()
    if args.check:
        drift = [
            os.fspath(path.relative_to(ROOT))
            for path, raw in expected.items()
            if not path.exists() or path.read_bytes() != raw
        ]
        if drift:
            print(
                "DM-041 generated artifact drift: " + ", ".join(drift), file=sys.stderr
            )
            return 1
        return 0
    for path, raw in expected.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists() or path.read_bytes() != raw:
            path.write_bytes(raw)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
