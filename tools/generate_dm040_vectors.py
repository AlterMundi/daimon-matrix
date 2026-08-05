#!/usr/bin/env python3
"""Generate deterministic DM-040 contracts, templates, provenance and vectors."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import daimon_matrix.codex_body as codex_body  # noqa: E402
from daimon_matrix.canonical import b64url, canonical_bytes  # noqa: E402

HASH_PATTERN = "^[0-9a-f]{64}$"
DERIVED_PATTERN = "^dm:[a-z0-9-]+:v[01]:[A-Za-z0-9_-]{43}$"
BEING_PATTERN = "^dm:being:v1:[A-Za-z0-9_-]{43}$"
EMBODIMENT_PATTERN = "^embodiment:[A-Za-z0-9._:-]{1,240}$"
INCARNATION_PATTERN = "^incarnation:[A-Za-z0-9._:-]{1,240}$"
TOKEN_PATTERN = "^[A-Za-z0-9._:-]{1,192}$"
UINT = {"type": "integer", "minimum": 0, "maximum": 2**53 - 1}
HASH = {"type": "string", "pattern": HASH_PATTERN}
DERIVED = {"type": "string", "pattern": DERIVED_PATTERN}
BODY_REF = {"type": "string", "minLength": 1, "maxLength": 256}
EMBODIMENT = {"type": "string", "pattern": EMBODIMENT_PATTERN}
INCARNATION = {"type": "string", "pattern": INCARNATION_PATTERN}


def closed(
    properties: dict[str, Any], required: list[str] | None = None
) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": properties,
        "required": required or list(properties),
        "additionalProperties": False,
    }


def contracts_schema() -> dict[str, Any]:
    signature = closed(
        {
            "alg": {"const": "Ed25519"},
            "kid": {"type": "string", "minLength": 1, "maxLength": 192},
            "value": {"type": "string", "pattern": "^[A-Za-z0-9_-]{86}$"},
        }
    )
    bootstrap = closed(
        {
            "schema": {"const": codex_body.BOOTSTRAP_SCHEMA},
            "being_ref": {"type": "string", "pattern": BEING_PATTERN},
            "body_ref": BODY_REF,
            "embodiment_id": EMBODIMENT,
            "incarnation_id": INCARNATION,
            "matrix_session_id": DERIVED,
            "matrix_high_water": HASH,
            "capability_set_hash": HASH,
            "certificate_hash": HASH,
            "issued_at_ms": UINT,
            "expires_at_ms": UINT,
            "signature": signature,
        }
    )
    codex = closed(
        {
            "version": {"const": codex_body.CODEX_VERSION},
            "binary_sha256": {"const": codex_body.CODEX_BINARY_SHA256},
            "app_server_schema_digest": {"const": codex_body.APP_SERVER_SCHEMA_DIGEST},
            "app_server_typescript_digest": {
                "const": codex_body.APP_SERVER_TYPESCRIPT_DIGEST
            },
            "model": {"type": "string", "pattern": TOKEN_PATTERN},
            "provider": {"type": "string", "pattern": TOKEN_PATTERN},
        }
    )
    profile_policy = closed(
        {
            "sandbox": {"const": "workspace-write"},
            "approval_policy": {"const": "on-request"},
            "network": {"const": "disabled"},
            "history_persistence": {"const": "none"},
            "matrix_tools": {
                "const": list(codex_body.MATRIX_TOOLS),
            },
            "mcp_env_names": {"const": list(codex_body.SAFE_MCP_ENV_NAMES)},
        }
    )
    plan = closed(
        {
            "schema": {"const": codex_body.PLAN_SCHEMA},
            "adapter_version": {"const": "1.0.0"},
            "workspace_ref": DERIVED,
            "bootstrap": bootstrap,
            "codex": codex,
            "profile_policy": profile_policy,
        }
    )
    profile_file = closed(
        {
            "name": {
                "enum": [
                    "AGENTS.md",
                    "bootstrap.json",
                    "config.toml",
                    "hooks/lifecycle.py",
                ]
            },
            "sha256": HASH,
        }
    )
    profile_manifest = closed(
        {
            "schema": {"const": codex_body.PROFILE_MANIFEST_SCHEMA},
            "profile_id": {
                "type": "string",
                "pattern": "^dm:codex-profile:v1:[A-Za-z0-9_-]{43}$",
            },
            "plan_hash": HASH,
            "adapter_version": {"const": "1.0.0"},
            "codex_version": {"const": codex_body.CODEX_VERSION},
            "codex_binary_sha256": {"const": codex_body.CODEX_BINARY_SHA256},
            "matrix_mcp_binary_sha256": HASH,
            "hook_python_sha256": HASH,
            "being_ref": {"type": "string", "pattern": BEING_PATTERN},
            "body_ref": BODY_REF,
            "embodiment_id": EMBODIMENT,
            "incarnation_id": INCARNATION,
            "matrix_session_id": DERIVED,
            "workspace_ref": DERIVED,
            "files": {
                "type": "array",
                "minItems": 4,
                "maxItems": 4,
                "uniqueItems": True,
                "items": profile_file,
            },
        }
    )
    launch_receipt = closed(
        {
            "schema": {"const": codex_body.LAUNCH_RECEIPT_SCHEMA},
            "receipt_id": {
                "type": "string",
                "pattern": "^dm:codex-launch-receipt:v1:[A-Za-z0-9_-]{43}$",
            },
            "outcome": {"enum": ["started", "resumed"]},
            "observed_at_ms": UINT,
            "profile_id": {
                "type": "string",
                "pattern": "^dm:codex-profile:v1:[A-Za-z0-9_-]{43}$",
            },
            "plan_hash": HASH,
            "compatibility": closed(
                {
                    "adapter_version": {"const": "1.0.0"},
                    "codex_version": {"const": codex_body.CODEX_VERSION},
                    "codex_binary_sha256": {"const": codex_body.CODEX_BINARY_SHA256},
                    "app_server_schema_digest": {
                        "const": codex_body.APP_SERVER_SCHEMA_DIGEST
                    },
                    "app_server_typescript_digest": {
                        "const": codex_body.APP_SERVER_TYPESCRIPT_DIGEST
                    },
                    "matrix_mcp_name": {"const": "daimon-matrix"},
                    "matrix_mcp_binary_sha256": HASH,
                    "matrix_mcp_version": {"const": "0.0.0"},
                    "hook_python_sha256": HASH,
                    "matrix_tools": {"const": list(codex_body.MATRIX_TOOLS)},
                }
            ),
            "reviewed_files": closed(
                {
                    "agents_sha256": HASH,
                    "bootstrap_sha256": HASH,
                    "config_sha256": HASH,
                    "hook_sha256": HASH,
                }
            ),
            "runtime": closed(
                {
                    "model": {"type": "string", "pattern": TOKEN_PATTERN},
                    "provider": {"type": "string", "pattern": TOKEN_PATTERN},
                    "workspace_ref": DERIVED,
                    "sandbox": {"const": "workspace-write"},
                    "approval_policy": {"const": "on-request"},
                    "network": {"const": "disabled"},
                    "thread_id": {"type": "string", "pattern": TOKEN_PATTERN},
                    "session_tree_id": {
                        "type": "string",
                        "pattern": TOKEN_PATTERN,
                    },
                    "turn_id": {
                        "oneOf": [
                            {"type": "string", "pattern": TOKEN_PATTERN},
                            {"type": "null"},
                        ]
                    },
                }
            ),
            "matrix_binding": closed(
                {
                    "being_ref": {"type": "string", "pattern": BEING_PATTERN},
                    "body_ref": BODY_REF,
                    "embodiment_id": EMBODIMENT,
                    "incarnation_id": INCARNATION,
                    "matrix_session_id": DERIVED,
                    "matrix_high_water": HASH,
                }
            ),
        }
    )
    runtime_handle = closed(
        {
            "schema": {"const": codex_body.RUNTIME_HANDLE_SCHEMA},
            "handle_id": {
                "type": "string",
                "pattern": "^dm:codex-handle:v1:[A-Za-z0-9_-]{43}$",
            },
            "generation": UINT,
            "previous_handle_id": {
                "oneOf": [
                    {
                        "type": "string",
                        "pattern": "^dm:codex-handle:v1:[A-Za-z0-9_-]{43}$",
                    },
                    {"type": "null"},
                ]
            },
            "being_ref": {"type": "string", "pattern": BEING_PATTERN},
            "body_ref": BODY_REF,
            "embodiment_id": EMBODIMENT,
            "incarnation_id": INCARNATION,
            "matrix_session_id": DERIVED,
            "matrix_high_water": HASH,
            "thread_id": {"type": "string", "pattern": TOKEN_PATTERN},
            "session_tree_id": {"type": "string", "pattern": TOKEN_PATTERN},
            "turn_id": {
                "oneOf": [
                    {"type": "string", "pattern": TOKEN_PATTERN},
                    {"type": "null"},
                ]
            },
            "state": {"enum": ["starting", "resuming", "active", "parked"]},
            "observed_at_ms": UINT,
        }
    )
    observation = closed(
        {
            "schema": {"const": codex_body.OBSERVATION_SCHEMA},
            "observation_id": {
                "type": "string",
                "pattern": "^dm:codex-observation:v1:[A-Za-z0-9_-]{43}$",
            },
            "event": {
                "enum": [
                    "session-start",
                    "user-prompt-submit",
                    "stop",
                    "session-end",
                ]
            },
            "observed_at_ms": UINT,
            "session_id": {"type": "string", "pattern": TOKEN_PATTERN},
            "model": {"type": "string", "pattern": TOKEN_PATTERN},
            "body_ref": BODY_REF,
            "embodiment_id": EMBODIMENT,
            "incarnation_id": INCARNATION,
            "matrix_session_id": DERIVED,
            "outcome": {"const": "observed"},
        }
    )
    compatibility = closed(
        {
            "schema": {"const": codex_body.COMPATIBILITY_SCHEMA},
            "codex_version": {"const": codex_body.CODEX_VERSION},
            "codex_binary_sha256": {"const": codex_body.CODEX_BINARY_SHA256},
            "app_server_schema_files": {"const": codex_body.APP_SERVER_SCHEMA_FILES},
            "app_server_schema_digest": {"const": codex_body.APP_SERVER_SCHEMA_DIGEST},
            "app_server_typescript_files": {
                "const": codex_body.APP_SERVER_TYPESCRIPT_FILES
            },
            "app_server_typescript_digest": {
                "const": codex_body.APP_SERVER_TYPESCRIPT_DIGEST
            },
            "status": {"const": "supported"},
        }
    )
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://schemas.altermundi.net/daimon-matrix/codex/v1/contracts.schema.json",
        "title": "Daimon Matrix Codex body V1 contracts",
        "oneOf": [
            {"$ref": "#/$defs/bootstrap"},
            {"$ref": "#/$defs/plan"},
            {"$ref": "#/$defs/profile_manifest"},
            {"$ref": "#/$defs/launch_receipt"},
            {"$ref": "#/$defs/runtime_handle"},
            {"$ref": "#/$defs/observation"},
            {"$ref": "#/$defs/compatibility"},
        ],
        "$defs": {
            "bootstrap": bootstrap,
            "plan": plan,
            "profile_manifest": profile_manifest,
            "launch_receipt": launch_receipt,
            "runtime_handle": runtime_handle,
            "observation": observation,
            "compatibility": compatibility,
        },
    }


def derived(kind: str, label: str) -> str:
    return f"dm:{kind}:v1:" + b64url(hashlib.sha256(label.encode()).digest())


def bootstrap_vector() -> dict[str, Any]:
    return {
        "schema": codex_body.BOOTSTRAP_SCHEMA,
        "being_ref": derived("being", "dm040-vector-being"),
        "body_ref": "cluster:synthetic:dm040-vector-body",
        "embodiment_id": "embodiment:synthetic:dm040-vector-embodiment",
        "incarnation_id": "incarnation:synthetic:dm040-vector-incarnation:0",
        "matrix_session_id": derived("session", "dm040-vector-session"),
        "matrix_high_water": hashlib.sha256(b"dm040-vector-high-water").hexdigest(),
        "capability_set_hash": hashlib.sha256(b"dm040-vector-capabilities").hexdigest(),
        "certificate_hash": hashlib.sha256(b"dm040-vector-certificate").hexdigest(),
        "issued_at_ms": 1_800_000_000_000,
        "expires_at_ms": 1_800_003_600_000,
        "signature": {
            "alg": "Ed25519",
            "kid": derived("key", "dm040-vector-key"),
            "value": b64url(bytes(range(64))),
        },
    }


def runtime_handle_vector(bootstrap: Mapping[str, Any]) -> dict[str, Any]:
    core = {
        "schema": codex_body.RUNTIME_HANDLE_SCHEMA,
        "generation": 0,
        "previous_handle_id": None,
        "being_ref": bootstrap["being_ref"],
        "body_ref": bootstrap["body_ref"],
        "embodiment_id": bootstrap["embodiment_id"],
        "incarnation_id": bootstrap["incarnation_id"],
        "matrix_session_id": bootstrap["matrix_session_id"],
        "matrix_high_water": bootstrap["matrix_high_water"],
        "thread_id": "019abcde-0000-7000-8000-000000000001",
        "session_tree_id": "019abcde-0000-7000-8000-000000000002",
        "turn_id": None,
        "state": "active",
        "observed_at_ms": 1_800_000_001_000,
    }
    result = {
        **core,
        "handle_id": "dm:codex-handle:v1:"
        + b64url(
            hashlib.sha256(codex_body.HANDLE_DOMAIN + canonical_bytes(core)).digest()
        ),
    }
    return codex_body.validate_runtime_handle(result)


def launch_receipt_vector(
    plan: Mapping[str, Any], handle: Mapping[str, Any]
) -> dict[str, Any]:
    core = {
        "schema": codex_body.LAUNCH_RECEIPT_SCHEMA,
        "outcome": "started",
        "observed_at_ms": handle["observed_at_ms"],
        "profile_id": derived("codex-profile", "dm040-vector-profile"),
        "plan_hash": hashlib.sha256(canonical_bytes(plan)).hexdigest(),
        "compatibility": {
            "adapter_version": "1.0.0",
            "codex_version": codex_body.CODEX_VERSION,
            "codex_binary_sha256": codex_body.CODEX_BINARY_SHA256,
            "app_server_schema_digest": codex_body.APP_SERVER_SCHEMA_DIGEST,
            "app_server_typescript_digest": (codex_body.APP_SERVER_TYPESCRIPT_DIGEST),
            "matrix_mcp_name": "daimon-matrix",
            "matrix_mcp_binary_sha256": hashlib.sha256(
                b"dm040-vector-matrix-mcp"
            ).hexdigest(),
            "matrix_mcp_version": "0.0.0",
            "hook_python_sha256": hashlib.sha256(
                b"dm040-vector-hook-python"
            ).hexdigest(),
            "matrix_tools": list(codex_body.MATRIX_TOOLS),
        },
        "reviewed_files": {
            "agents_sha256": hashlib.sha256(b"dm040-vector-agents").hexdigest(),
            "bootstrap_sha256": hashlib.sha256(b"dm040-vector-bootstrap").hexdigest(),
            "config_sha256": hashlib.sha256(b"dm040-vector-config").hexdigest(),
            "hook_sha256": hashlib.sha256(b"dm040-vector-hook").hexdigest(),
        },
        "runtime": {
            "model": plan["codex"]["model"],
            "provider": plan["codex"]["provider"],
            "workspace_ref": plan["workspace_ref"],
            "sandbox": "workspace-write",
            "approval_policy": "on-request",
            "network": "disabled",
            "thread_id": handle["thread_id"],
            "session_tree_id": handle["session_tree_id"],
            "turn_id": handle["turn_id"],
        },
        "matrix_binding": {
            key: handle[key]
            for key in (
                "being_ref",
                "body_ref",
                "embodiment_id",
                "incarnation_id",
                "matrix_session_id",
                "matrix_high_water",
            )
        },
    }
    value = {
        **core,
        "receipt_id": "dm:codex-launch-receipt:v1:"
        + b64url(
            hashlib.sha256(codex_body.LAUNCH_DOMAIN + canonical_bytes(core)).digest()
        ),
    }
    return codex_body.validate_launch_receipt(value)


def json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False).encode() + b"\n"
    )


def outputs() -> dict[Path, bytes]:
    bootstrap = bootstrap_vector()
    plan = codex_body.create_plan_value(
        bootstrap=bootstrap,
        model="gpt-5.6-terra",
        provider="openai",
        workspace_ref=derived("workspace", "dm040-vector-workspace"),
    )
    handle = runtime_handle_vector(bootstrap)
    launch = launch_receipt_vector(plan, handle)
    vectors: dict[str, Any] = {
        "valid/bootstrap.json": bootstrap,
        "valid/plan.json": plan,
        "valid/runtime-handle.json": handle,
        "valid/launch-receipt.json": launch,
        "negative/plan-unknown-field.json": {**copy.deepcopy(plan), "unknown": True},
        "negative/bootstrap-short-signature.json": {
            **copy.deepcopy(bootstrap),
            "signature": {**bootstrap["signature"], "value": b64url(b"short")},
        },
    }
    result = {
        ROOT / "schemas/codex/v1/contracts.schema.json": json_bytes(contracts_schema()),
        ROOT / "templates/codex/v1/AGENTS.md": codex_body.AGENTS_TEMPLATE.encode(),
        ROOT
        / "templates/codex/v1/lifecycle_hook.py": codex_body.HOOK_TEMPLATE.encode(),
        ROOT / "provenance/codex-cli-0.146.0.json": json_bytes(
            {
                "schema": "dm.codex-body.provenance/v1",
                "audited_at": "2026-08-05",
                "codex_version": codex_body.CODEX_VERSION,
                "native_binary_sha256": codex_body.CODEX_BINARY_SHA256,
                "npm_wrapper_sha256": (
                    "134063e133f0b4244fa3b251acf973d4fe4b4aeeacbdc135211bf480f59f1477"
                ),
                "feature_snapshot": {
                    "line_count": 100,
                    "sha256": (
                        "b338bae6ecd46ad6bc02de695a89d4bc"
                        "80c9ae77ab1294384880fca0dc251384"
                    ),
                    "relevant": {
                        "apps": ["stable", True],
                        "browser_use": ["stable", True],
                        "chronicle": ["under development", False],
                        "computer_use": ["stable", True],
                        "external_agent_memory_import": [
                            "under development",
                            False,
                        ],
                        "hooks": ["stable", True],
                        "memories": ["stable", False],
                        "plugins": ["stable", True],
                    },
                },
                "app_server": {
                    "status": "experimental",
                    "schema_files": codex_body.APP_SERVER_SCHEMA_FILES,
                    "normalized_schema_digest": codex_body.APP_SERVER_SCHEMA_DIGEST,
                    "typescript_files": codex_body.APP_SERVER_TYPESCRIPT_FILES,
                    "typescript_digest": codex_body.APP_SERVER_TYPESCRIPT_DIGEST,
                    "raw_schema_is_byte_deterministic": False,
                    "normalization": "relative-path + NUL + canonical-json + NUL",
                },
                "official_sources": [
                    "https://developers.openai.com/codex/codex-manual.md",
                    "https://learn.chatgpt.com/docs/app-server",
                    "https://learn.chatgpt.com/docs/config-file/config-reference",
                    "https://learn.chatgpt.com/docs/hooks",
                    "https://learn.chatgpt.com/docs/customization/memories",
                    "https://learn.chatgpt.com/docs/non-interactive-mode",
                ],
            }
        ),
    }
    vector_root = ROOT / "vectors/codex/v1"
    for relative, value in vectors.items():
        result[vector_root / relative] = json_bytes(value)
    index = {
        "schema": "dm.codex-body.vector-index/v1",
        "codex_version": codex_body.CODEX_VERSION,
        "files": [
            {
                "name": relative,
                "sha256": hashlib.sha256(json_bytes(value)).hexdigest(),
                "valid": relative.startswith("valid/"),
            }
            for relative, value in sorted(vectors.items())
        ],
    }
    result[vector_root / "index.json"] = json_bytes(index)
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
                "DM-040 generated artifact drift: " + ", ".join(drift), file=sys.stderr
            )
            return 1
        return 0
    for path, raw in expected.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
