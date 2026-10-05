#!/usr/bin/env python3
"""Freeze successor wire contracts and deterministic public synthetic vectors.

These records prove codec/signature conformance, not a native launch or live
CompAII authority. Historical DM-040 artifacts are inputs and never rewritten.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from daimon_matrix import codex_body as body  # noqa: E402
from daimon_matrix import codex_matrix_binding as bridge  # noqa: E402
from daimon_matrix.canonical import b64url, canonical_bytes  # noqa: E402
from tests.test_codex_matrix_binding import MatrixBindingTests  # noqa: E402
from tests.test_dm022_ledger import NOW  # noqa: E402
from tools.generate_dm040_vectors import (  # noqa: E402
    HASH,
    UINT,
    closed,
    json_bytes,
)
from tools.generate_dm040_vectors import (  # noqa: E402
    contracts_schema as historical_schema,
)
from tools.generate_dm074_profiles import (  # noqa: E402
    codex_successor_candidate,
    codex_successor_report,
)


def contracts_schema(
    release: body.CodexReleaseContract = body.SUCCESSOR_RELEASE,
) -> dict[str, Any]:
    wire = 3 if release == body.CURRENT_RELEASE else 2
    schema = copy.deepcopy(historical_schema())
    schema["$id"] = (
        f"https://schemas.altermundi.net/daimon-matrix/codex/v{wire}/contracts.schema.json"
    )
    schema["title"] = f"Daimon Matrix Codex {release.version} successor contracts"
    definitions = schema["$defs"]
    definitions.pop("observation")
    bootstrap = definitions["bootstrap"]
    bootstrap["properties"]["schema"]["const"] = body.ATTESTED_BOOTSTRAP_SCHEMA
    descriptor = copy.deepcopy(bootstrap["properties"])
    for name in ("signature", "matrix_high_water"):
        descriptor.pop(name)
    definitions["bootstrap_attestation"] = closed(
        {
            "schema": {"const": "dm.codex-body.bootstrap-attestation/v1"},
            "bootstrap": closed(descriptor),
            "runtime_id": {"type": "string", "minLength": 1, "maxLength": 512},
            "capability_id": {"type": "string", "minLength": 1, "maxLength": 512},
            "client_id": {"type": "string", "minLength": 1, "maxLength": 512},
            "manifest_hash": HASH,
        }
    )
    event_reference = {"$ref": "../../weave/v1/event.schema.json"}
    bootstrap["properties"]["attestation"] = {
        "allOf": [
            event_reference,
            {
                "properties": {
                    "kind": {"const": "experience.observed"},
                    "subject": {"const": "codex-body/bootstrap"},
                    "sensitivity": {"const": "private"},
                    "payload": {"$ref": "#/$defs/bootstrap_attestation"},
                },
            },
        ]
    }
    bootstrap["required"].append("attestation")
    replacements = {
        body.CODEX_VERSION: release.version,
        body.CODEX_BINARY_SHA256: release.binary_sha256,
        body.APP_SERVER_SCHEMA_DIGEST: release.schema_digest,
        body.APP_SERVER_TYPESCRIPT_DIGEST: release.typescript_digest,
        "1.0.0": f"{wire}.0.0",
    }

    def replace(value: Any) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                if key == "const" and isinstance(item, str):
                    value[key] = replacements.get(item, item)
                elif key == "pattern" and isinstance(item, str):
                    for kind in (
                        "codex-profile",
                        "codex-handle",
                        "codex-launch-receipt",
                    ):
                        value[key] = value[key].replace(
                            f"dm:{kind}:v1:", f"dm:{kind}:v{wire}:"
                        )
                else:
                    replace(item)
        elif isinstance(value, list):
            for item in value:
                replace(item)

    replace(definitions)
    for kind in (
        "plan",
        "profile_manifest",
        "launch_receipt",
        "runtime_handle",
        "compatibility",
    ):
        old = definitions[kind]["properties"]["schema"]["const"]
        definitions[kind]["properties"]["schema"]["const"] = old.replace(
            "/v1", f"/v{wire}"
        )
    plan = definitions["plan"]["properties"]
    plan["bootstrap"] = {
        "oneOf": [
            {"$ref": "#/$defs/bootstrap"},
            {"$ref": "../v1/contracts.schema.json#/$defs/bootstrap"},
        ]
    }
    relative = {
        "type": "string",
        "minLength": 1,
        "maxLength": 1024,
        "pattern": r"^(?!/)(?!.*(?:^|/)\.\.?(?:/|$))(?!.*//)(?!.*\\)[^\x00-\x1f\x7f]+$",
    }
    file_entry = closed(
        dict(path=relative, sha256=HASH, bytes=UINT, executable={"type": "boolean"})
    )
    plan["skill_packages"] = closed(
        dict(
            schema={"const": "dm.codex-skill-packages/v1"},
            packages={
                "type": "array",
                "minItems": 1,
                "items": closed(
                    dict(
                        path=relative,
                        sha256=HASH,
                        files={"type": "array", "minItems": 1, "items": file_entry},
                    )
                ),
            },
        )
    )
    plan["continuity"] = closed(
        {
            "schema": {"const": "dm.codex-continuity/v1"},
            "files": closed(
                {
                    name: closed(
                        {
                            "bytes": {
                                "type": "integer",
                                "minimum": 1,
                                "maximum": 24000,
                            },
                            "sha256": HASH,
                            "source_ref": {
                                "type": "string",
                                "minLength": 1,
                                "maxLength": 192,
                                "pattern": r"^[^\x00-\x1f\x7f]+$",
                            },
                        }
                    )
                    for name in body.CONTINUITY_NAMES
                }
            ),
        }
    )
    policy = plan["profile_policy"]
    policy["properties"].update(
        hooks={"const": "disabled"}, lifecycle={"const": "human-request-only"}
    )
    policy["required"].extend(("hooks", "lifecycle"))
    effort = {
        "enum": ["none", "minimal", "low", "medium", "high", "xhigh", "max", "ultra"]
    }
    plan["codex"]["properties"]["reasoning_effort"] = effort
    plan["codex"]["properties"]["provider_auth"] = {"const": "chatgpt-external"}
    plan["codex"]["dependentSchemas"] = {
        "provider_auth": {"properties": {"provider": {"const": "openai"}}}
    }
    restricted = copy.deepcopy(policy)
    unrestricted = copy.deepcopy(policy)
    for key, value in body._execution_policy(True).items():
        unrestricted["properties"][key] = {"const": value}
    plan["profile_policy"] = {"oneOf": [restricted, unrestricted]}
    manifest = definitions["profile_manifest"]
    manifest["properties"].pop("hook_python_sha256")
    manifest["required"].remove("hook_python_sha256")
    manifest["properties"]["lifecycle"] = {"const": "human-request-only"}
    manifest["required"].append("lifecycle")
    files = manifest["properties"]["files"]
    files.update(minItems=3)
    files.pop("maxItems", None)
    files["items"]["properties"]["name"] = {
        "oneOf": [
            {
                "enum": [
                    "AGENTS.md",
                    "bootstrap.json",
                    "config.toml",
                    *body.CONTINUITY_NAMES,
                ]
            },
            {
                "type": "string",
                "pattern": (
                    r"^\.agents/skills/(?!.*(?:/\.\.?/|//|\\))" r"[^\x00-\x1f\x7f]+$"
                ),
            },
        ]
    }
    launch = definitions["launch_receipt"]["properties"]
    compatibility = launch["compatibility"]
    compatibility["properties"].pop("hook_python_sha256")
    compatibility["required"].remove("hook_python_sha256")
    compatibility["properties"]["lifecycle"] = {"const": "human-request-only"}
    compatibility["required"].append("lifecycle")
    launch["reviewed_files"]["properties"].pop("hook_sha256")
    launch["reviewed_files"]["required"].remove("hook_sha256")
    restricted_runtime = copy.deepcopy(launch["runtime"])
    unrestricted_runtime = copy.deepcopy(launch["runtime"])
    for key, value in body._execution_policy(True).items():
        unrestricted_runtime["properties"][key] = {"const": value}
    launch["runtime"] = {"oneOf": [restricted_runtime, unrestricted_runtime]}
    handle = definitions["runtime_handle"]
    handle["properties"]["state"]["enum"].extend(("parking", "turning"))
    binding = {
        "profile_id": manifest["properties"]["profile_id"],
        "plan_hash": HASH,
        "codex_version": {"const": release.version},
        "capability_set_hash": HASH,
        "certificate_hash": HASH,
    }
    handle["properties"].update(binding)
    handle["required"].extend(binding)
    definitions["turn_intent"] = closed(
        {
            **{
                name: copy.deepcopy(handle["properties"][name])
                for name in sorted(body._TURN_BINDING_FIELDS)
            },
            "schema": {"const": body.TURN_INTENT_SCHEMA},
            "intent_id": {
                "type": "string",
                "pattern": r"^dm:codex-turn-intent:v1:[A-Za-z0-9_-]{43}$",
            },
            "request_id": {
                "type": "string",
                "format": "uuid",
                "pattern": r"^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$",
            },
            "active_handle_id": copy.deepcopy(handle["properties"]["handle_id"]),
            "input_sha256": HASH,
            "input_bytes": {**UINT, "minimum": 1, "maximum": 4096},
            "timeout_seconds": {**UINT, "minimum": 1, "maximum": 300},
            "max_response_bytes": {**UINT, "minimum": 1, "maximum": 65536},
            "retain_until_ms": UINT,
        }
    )
    native_item: dict[str, Any] = {
        "type": "object",
        "required": ["id", "type"],
        "properties": {
            "id": {"type": "string", "pattern": r"^[A-Za-z0-9._:-]{1,192}$"},
            "type": {
                "enum": sorted(
                    {
                        "agentMessage",
                        "plan",
                        "reasoning",
                        "userMessage",
                        "functionCallOutput",
                        "commandExecution",
                        "fileChange",
                        "mcpToolCall",
                        "dynamicToolCall",
                        "collabAgentToolCall",
                        "subAgentActivity",
                        "webSearch",
                        "imageView",
                        "sleep",
                        "imageGeneration",
                        "enteredReviewMode",
                        "exitedReviewMode",
                        "contextCompaction",
                    }
                )
            },
        },
        "allOf": [
            {
                "if": {"properties": {"type": {"enum": ["agentMessage", "plan"]}}},
                "then": {
                    "required": ["text"],
                    "properties": {"text": {"type": "string"}},
                },
            },
            {
                "if": {"properties": {"type": {"const": "reasoning"}}},
                "then": {
                    "properties": {
                        name: {"type": "array", "items": {"type": "string"}}
                        for name in ("content", "summary")
                    }
                },
            },
        ],
    }
    native_turn = {
        "type": "object",
        "additionalProperties": False,
        "required": ["id", "items", "status"],
        "properties": {
            "id": native_item["properties"]["id"],
            "items": {"type": "array", "items": native_item},
            "status": {"enum": ["completed", "failed", "interrupted"]},
            "error": {"type": "null"},
            "itemsView": {"enum": ["notLoaded", "summary", "full"]},
            **{
                name: {
                    "type": ["integer", "null"],
                    "minimum": -(2**63),
                    "maximum": 2**63 - 1,
                }
                for name in ("startedAt", "completedAt", "durationMs")
            },
        },
    }
    definitions["turn_result"] = closed(
        {
            "schema": {"const": "dm.codex-body.turn-result/v1"},
            "request_id": definitions["turn_intent"]["properties"]["request_id"],
            "intent_id": definitions["turn_intent"]["properties"]["intent_id"],
            "pending_handle_id": copy.deepcopy(handle["properties"]["handle_id"]),
            "native_turn": native_turn,
            "result_id": {
                "type": "string",
                "pattern": r"^dm:codex-turn-result:v1:[A-Za-z0-9_-]{43}$",
            },
        }
    )
    artifact = definitions["compatibility"]["properties"]
    artifact["app_server_schema_files"]["const"] = release.schema_files
    artifact["app_server_typescript_files"]["const"] = release.typescript_files
    artifact["status"]["const"] = "artifact-verified"
    definitions["session_witness"] = closed(
        {
            "schema": {"const": "dm.codex-body.session-witness/v1"},
            "matrix_session_id": descriptor["matrix_session_id"],
            "bootstrap_event_hash": HASH,
            "previous_event_hash": HASH,
            "previous_event_id": {"type": "string", "format": "uuid"},
            "witness_sequence": {**UINT, "minimum": 1},
        }
    )
    definitions["session_proof_record"] = closed(
        {
            "schema": {"const": "dm.codex-body.session-proof-record/v1"},
            "bootstrap_hash": HASH,
            "generation": UINT,
            "previous_record_hash": {"oneOf": [HASH, {"type": "null"}]},
            "event": event_reference,
            "record_hash": HASH,
        }
    )
    schema["oneOf"] = [{"$ref": f"#/$defs/{name}"} for name in definitions]
    return schema


def codec_profile(plan: dict[str, Any]) -> dict[str, Any]:
    """Path-free synthetic file hashes; this is not an installed profile."""
    bootstrap = plan["bootstrap"]
    profile = body._profile_contract(plan)
    release = profile.release
    wire = profile.wire_version
    core = {
        "schema": f"dm.codex-body.profile-manifest/v{wire}",
        "plan_hash": hashlib.sha256(
            f"daimon/codex-body/plan/v{wire}\x00".encode("ascii")
            + canonical_bytes(plan)
        ).hexdigest(),
        "adapter_version": f"{wire}.0.0",
        "codex_version": release.version,
        "codex_binary_sha256": release.binary_sha256,
        "matrix_mcp_binary_sha256": hashlib.sha256(b"synthetic-mcp").hexdigest(),
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
        "workspace_ref": plan["workspace_ref"],
        "lifecycle": "human-request-only",
        "files": [
            {"name": name, "sha256": hashlib.sha256(content).hexdigest()}
            for name, content in (
                ("AGENTS.md", b"synthetic-agents"),
                ("bootstrap.json", canonical_bytes(bootstrap) + b"\n"),
                ("config.toml", b"synthetic-config"),
            )
        ],
    }
    return {
        **core,
        "profile_id": body._derived(
            f"dm:codex-profile:v{wire}:",
            f"daimon/codex-body/profile/v{wire}\x00".encode("ascii"),
            core,
        ),
    }


def codec_launch(
    plan: dict[str, Any], manifest: dict[str, Any], handle: dict[str, Any]
) -> dict[str, Any]:
    profile = body._profile_contract(plan)
    release = profile.release
    wire = profile.wire_version
    core = {
        "schema": f"dm.codex-body.launch-receipt/v{wire}",
        "outcome": "started",
        "observed_at_ms": handle["observed_at_ms"],
        "profile_id": manifest["profile_id"],
        "plan_hash": manifest["plan_hash"],
        "compatibility": {
            "adapter_version": f"{wire}.0.0",
            "codex_version": release.version,
            "codex_binary_sha256": release.binary_sha256,
            "app_server_schema_digest": release.schema_digest,
            "app_server_typescript_digest": release.typescript_digest,
            "matrix_mcp_name": "daimon-matrix",
            "matrix_mcp_binary_sha256": manifest["matrix_mcp_binary_sha256"],
            "matrix_mcp_version": "0.1.0rc1",
            "matrix_tools": list(body.MATRIX_TOOLS),
            "lifecycle": "human-request-only",
        },
        "reviewed_files": {
            name: manifest["files"][index]["sha256"]
            for index, name in enumerate(
                ("agents_sha256", "bootstrap_sha256", "config_sha256")
            )
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
            "turn_id": None,
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
    return body.validate_launch_receipt(
        {
            **core,
            "receipt_id": body._derived(
                f"dm:codex-launch-receipt:v{wire}:",
                f"daimon/codex-body/launch-receipt/v{wire}\x00".encode("ascii"),
                core,
            ),
        }
    )


def outputs(
    release: body.CodexReleaseContract = body.SUCCESSOR_RELEASE,
) -> dict[Path, bytes]:
    wire = 3 if release == body.CURRENT_RELEASE else 2
    fixture = MatrixBindingTests()
    fixture.setUp()
    try:
        payload = bridge.bootstrap_attestation_payload(
            fixture.check(),
            matrix_session_id="dm:session:v1:"
            + b64url(hashlib.sha256(b"codex-v2-vector").digest()),
            expires_at_ms=NOW + 30_000,
        )
        event = fixture.ledger_a.append_local(
            kind="experience.observed",
            subject="codex-body/bootstrap",
            payload=payload,
            signer=fixture.signers["legion"],
            sensitivity="private",
            occurred_at_ms=NOW,
            event_id="00000205-0000-4000-8000-000000000001",
        )
        bootstrap = bridge.bootstrap_from_attestation(
            event, fixture.authority, **fixture.admission()
        )
        plan = body.create_plan_value(
            bootstrap=bootstrap,
            model="dm_probe",
            provider="openai",
            workspace_ref="dm:workspace:v1:"
            + b64url(hashlib.sha256(b"codex-v2-workspace").digest()),
            release=release.version,
        )
        manifest = codec_profile(plan)
        handle_core = {
            "schema": f"dm.codex-body.runtime-handle/v{wire}",
            "generation": 0,
            "previous_handle_id": None,
            **{
                key: bootstrap[key]
                for key in (
                    "being_ref",
                    "body_ref",
                    "embodiment_id",
                    "incarnation_id",
                    "matrix_session_id",
                    "matrix_high_water",
                    "capability_set_hash",
                    "certificate_hash",
                )
            },
            "profile_id": manifest["profile_id"],
            "plan_hash": manifest["plan_hash"],
            "codex_version": release.version,
            "thread_id": "synthetic-native-thread",
            "session_tree_id": "synthetic-native-session",
            "turn_id": None,
            "state": "parking",
            "observed_at_ms": NOW,
        }
        handle = body.validate_runtime_handle(
            {
                **handle_core,
                "handle_id": body._derived(
                    f"dm:codex-handle:v{wire}:",
                    f"daimon/codex-body/runtime-handle/v{wire}\x00".encode("ascii"),
                    handle_core,
                ),
            }
        )
        active_core = {**handle_core, "state": "active"}
        active_id = body._derived(
            f"dm:codex-handle:v{wire}:",
            f"daimon/codex-body/runtime-handle/v{wire}\x00".encode("ascii"),
            active_core,
        )
        turning_core = {
            **active_core,
            "state": "turning",
            "generation": 1,
            "previous_handle_id": active_id,
            "turn_id": "synthetic-native-turn",
        }
        turning = body.validate_runtime_handle(
            {
                **turning_core,
                "handle_id": body._derived(
                    f"dm:codex-handle:v{wire}:",
                    f"daimon/codex-body/runtime-handle/v{wire}\x00".encode("ascii"),
                    turning_core,
                ),
            }
        )
        input_bytes = b"Synthetic native input"
        intent_core = {
            **{name: handle[name] for name in sorted(body._TURN_BINDING_FIELDS)},
            "schema": body.TURN_INTENT_SCHEMA,
            "request_id": "00000205-0000-4000-8000-000000000003",
            "active_handle_id": active_id,
            "input_sha256": hashlib.sha256(input_bytes).hexdigest(),
            "input_bytes": len(input_bytes),
            "timeout_seconds": 30,
            "max_response_bytes": 4096,
            "retain_until_ms": NOW + 60_000,
        }
        intent = body.validate_turn_intent(
            {
                **intent_core,
                "intent_id": body._derived(
                    "dm:codex-turn-intent:v1:",
                    body.TURN_INTENT_DOMAIN,
                    intent_core,
                ),
            }
        )
        result_core = {
            "schema": "dm.codex-body.turn-result/v1",
            "request_id": intent["request_id"],
            "intent_id": intent["intent_id"],
            "pending_handle_id": turning["handle_id"],
            "native_turn": {
                "id": "synthetic-native-turn",
                "status": "completed",
                "items": [
                    {
                        "id": "synthetic-answer",
                        "type": "agentMessage",
                        "text": "Synthetic native result",
                    }
                ],
            },
        }
        turn_result = body.validate_native_turn_result(
            {
                **result_core,
                "result_id": body._derived(
                    "dm:codex-turn-result:v1:",
                    b"daimon/codex-body/turn-result/v1\x00",
                    result_core,
                ),
            }
        )
        witness_payload = bridge.session_witness_payload(bootstrap, event, sequence=1)
        witness = fixture.ledger_a.append_local(
            kind="experience.observed",
            subject="codex-body/session-witness",
            payload=witness_payload,
            signer=fixture.signers["legion"],
            sensitivity="private",
            occurred_at_ms=NOW,
            causal_parents=[event["event_id"]],
            event_id="00000205-0000-4000-8000-000000000002",
        )
        proof_path = fixture.root_path / "successor-session.jsonl"
        journal = bridge.SessionProofJournal(proof_path, bootstrap=bootstrap)
        journal.append(
            witness,
            expected_high_water=bootstrap["matrix_high_water"],
            verifier=lambda proofs, tip: bridge.verify_session_continuity(
                bootstrap,
                proofs,
                fixture.authority,
                expected_high_water=tip,
                **fixture.admission(),
            ),
        )
        values = {
            "valid/bootstrap.json": bootstrap,
            "valid/plan.json": plan,
            "valid/full-access-plan.json": body.validate_plan(
                {
                    **plan,
                    "codex": {**plan["codex"], "reasoning_effort": "medium"},
                    "profile_policy": {
                        **plan["profile_policy"],
                        **body._execution_policy(True),
                    },
                }
            ),
            "valid/profile-manifest.json": manifest,
            "valid/launch-receipt.json": codec_launch(plan, manifest, handle),
            "valid/session-witness.json": witness_payload,
            "valid/session-proof-record.json": json.loads(proof_path.read_bytes()),
            "valid/parking-handle.json": handle,
            "valid/turning-handle.json": turning,
            "valid/turn-intent.json": intent,
            "valid/turn-result.json": turn_result,
            "negative/mixed-plan.json": {**plan, "adapter_version": "1.0.0"},
            "negative/hook-policy.json": {
                **plan,
                "profile_policy": {**plan["profile_policy"], "hooks": "enabled"},
            },
        }
        selected_plan = copy.deepcopy(plan)
        selected_plan["continuity"] = {
            "schema": "dm.codex-continuity/v1",
            "files": {
                name: {
                    "bytes": len(raw),
                    "sha256": hashlib.sha256(raw).hexdigest(),
                    "source_ref": "public-synthetic:" + name,
                }
                for name in body.CONTINUITY_NAMES
                for raw in [("Synthetic owner-selected " + name + "\n").encode()]
            },
        }
        values["valid/continuity-plan.json"] = body.validate_plan(selected_plan)
        values["negative/continuity-prefetch.json"] = {
            **selected_plan,
            "continuity": {**selected_plan["continuity"], "automatic_prefetch": True},
        }
    finally:
        fixture.tearDown()
    vector_root = ROOT / f"vectors/codex/v{wire}"
    result = {
        ROOT / f"schemas/codex/v{wire}/contracts.schema.json": json_bytes(
            contracts_schema(release)
        )
    }
    if release == body.SUCCESSOR_RELEASE:
        candidate = codex_successor_candidate()
        result[vector_root / "adoption/profile.json"] = json_bytes(candidate)
        result[vector_root / "adoption/report.json"] = json_bytes(
            codex_successor_report(candidate)
        )
        result[vector_root / "adoption/sources.json"] = json_bytes(
            {
                "schema": "dm.harness-source-inventory/v0",
                "accessed_on": "2026-10-03",
                "sources": [
                    {
                        "source_id": "codex-0-155-1-candidate",
                        "owner": "AlterMundi",
                        "title": "Exact Codex 0.155.1 provenance and acceptance",
                        "url": "provenance/codex-cli-0.155.1.json",
                        "pin": "rust-v0.155.1/be2951ea34f0d295ed0becf97079f92fa5f6950e",
                        "content_digest": "sha256:"
                        + hashlib.sha256(
                            (ROOT / "provenance/codex-cli-0.155.1.json").read_bytes()
                        ).hexdigest(),
                        "accessed_on": "2026-10-03",
                    }
                ],
            }
        )
    for name, value in values.items():
        result[vector_root / name] = json_bytes(value)
    result[vector_root / "index.json"] = json_bytes(
        {
            "schema": f"dm.codex-body.vector-index/v{wire}",
            "codex_version": release.version,
            "scope": (
                "public deterministic signed fixture and synthetic codec records; "
                "no native launch or live authority proof"
            ),
            "files": [
                {
                    "name": name,
                    "sha256": hashlib.sha256(json_bytes(value)).hexdigest(),
                    "valid": name.startswith("valid/"),
                }
                for name, value in sorted(values.items())
            ],
        }
    )
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    expected = outputs()
    drift = [
        path
        for path, raw in expected.items()
        if not path.exists() or path.read_bytes() != raw
    ]
    if args.check:
        if drift:
            print(
                "Codex successor artifact drift: "
                + ", ".join(str(path.relative_to(ROOT)) for path in drift),
                file=sys.stderr,
            )
        return int(bool(drift))
    for path in drift:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(expected[path])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
