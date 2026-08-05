"""Closed MCP stdio adapter for authenticated Matrix runtime access."""

from __future__ import annotations

import argparse
import asyncio
import copy
import hashlib
import json
import os
import sys
import uuid
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Final, cast

import anyio
import mcp_types as types
from mcp.server.context import ServerRequestContext
from mcp.server.lowlevel import Server
from mcp.server.runner import (
    _has_modern_envelope,
    _replay_from_opening_request,
    _serve_legacy_stream,
    _serve_modern_stream,
)
from mcp.server.stdio import stdio_server
from mcp.shared.exceptions import MCPError
from mcp.shared.message import SessionMessage

from .canonical import canonical_bytes
from .client import (
    ClientConfig,
    ClientError,
    LocalClient,
    load_prepared_request,
    read_capability_key,
    store_prepared_request,
)
from .local_api import MAX_FRAME_BYTES

MCP_PROTOCOL_VERSION: Final = "2026-07-28"
CODEX_MCP_PROTOCOL_VERSION: Final = "2025-06-18"
MCP_PROTOCOL_VERSIONS: Final = (CODEX_MCP_PROTOCOL_VERSION, MCP_PROTOCOL_VERSION)
MCP_RESOURCE_MEDIA_TYPE: Final = "application/vnd.daimon-matrix+json"

_UUID = {"type": "string", "format": "uuid", "maxLength": 36}
_NULLABLE_UUID = {"anyOf": [_UUID, {"type": "null"}]}
_NULLABLE_TEXT = {
    "anyOf": [{"type": "string", "minLength": 1, "maxLength": 256}, {"type": "null"}]
}
_OPERATION = {"operation_id": _UUID}


def _object_schema(
    properties: Mapping[str, Any], required: Sequence[str] = ()
) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {**copy.deepcopy(dict(properties)), **copy.deepcopy(_OPERATION)},
        "required": list(required),
        "additionalProperties": False,
    }


TOOL_CONTRACTS: Final[dict[str, tuple[str, dict[str, Any], bool]]] = {
    "daimon_status": ("runtime.status", _object_schema({}), True),
    "curator_enqueue": (
        "curator.enqueue",
        _object_schema({"item": {"type": "object"}}, ("item",)),
        False,
    ),
    "curator_claim": (
        "curator.claim",
        _object_schema(
            {
                "item_id": {
                    "type": "string",
                    "pattern": "^dm:curator-item:v1:[A-Za-z0-9_-]{43}$",
                },
                "claim_id": _UUID,
                "expected_generation": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": 2**53 - 1,
                },
                "lease_until_ms": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": 2**53 - 1,
                },
                "fence_evidence": {"anyOf": [{"type": "object"}, {"type": "null"}]},
            },
            (
                "item_id",
                "claim_id",
                "expected_generation",
                "lease_until_ms",
                "fence_evidence",
            ),
        ),
        False,
    ),
    "curator_complete": (
        "curator.complete",
        _object_schema(
            {
                "claim_id": _UUID,
                "expected_generation": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 2**53 - 1,
                },
                "outcome": {"enum": ["completed", "proposed", "deferred", "failed"]},
                "output_refs": {
                    "type": "array",
                    "maxItems": 256,
                    "uniqueItems": True,
                    "items": {"type": "string", "minLength": 1, "maxLength": 256},
                },
                "effect_receipt": {"anyOf": [{"type": "object"}, {"type": "null"}]},
            },
            (
                "claim_id",
                "expected_generation",
                "outcome",
                "output_refs",
                "effect_receipt",
            ),
        ),
        False,
    ),
    "curator_inspect": (
        "curator.inspect",
        _object_schema(
            {
                "item_id": {
                    "type": "string",
                    "pattern": "^dm:curator-item:v1:[A-Za-z0-9_-]{43}$",
                }
            },
            ("item_id",),
        ),
        True,
    ),
    "memory_evaluate": (
        "memory.evaluate",
        _object_schema(
            {"policy": {"type": "object"}, "candidate": {"type": "object"}},
            ("policy", "candidate"),
        ),
        True,
    ),
    "memory_execute": (
        "memory.execute",
        _object_schema(
            {
                "policy": {"type": "object"},
                "candidate": {"type": "object"},
                "plan": {"type": "object"},
            },
            ("policy", "candidate", "plan"),
        ),
        False,
    ),
    "review_request": (
        "review.request",
        _object_schema({"request": {"type": "object"}}, ("request",)),
        False,
    ),
    "review_queue": (
        "review.queue",
        _object_schema(
            {
                "authorization_id": {
                    "type": "string",
                    "pattern": "^dm:review-authorization:v1:[A-Za-z0-9_-]{43}$",
                },
                "access_proof": {"type": "object"},
                "after": {
                    "anyOf": [
                        {
                            "type": "string",
                            "pattern": "^dm:review-request:v1:[A-Za-z0-9_-]{43}$",
                        },
                        {"type": "null"},
                    ]
                },
                "limit": {"type": "integer", "minimum": 1, "maximum": 100},
            },
            ("authorization_id", "access_proof", "operation_id"),
        ),
        True,
    ),
    "review_inspect": (
        "review.inspect",
        _object_schema(
            {
                "review_request_id": {
                    "type": "string",
                    "pattern": "^dm:review-request:v1:[A-Za-z0-9_-]{43}$",
                },
                "authorization_id": {
                    "type": "string",
                    "pattern": "^dm:review-authorization:v1:[A-Za-z0-9_-]{43}$",
                },
                "access_proof": {"type": "object"},
            },
            (
                "review_request_id",
                "authorization_id",
                "access_proof",
                "operation_id",
            ),
        ),
        True,
    ),
    "review_decision_draft": (
        "review.decision.draft",
        _object_schema(
            {
                "review_request_id": {"type": "string", "maxLength": 160},
                "authorization_id": {"type": "string", "maxLength": 160},
                "action": {"enum": ["accept", "edit", "reject", "defer"]},
                "replacement": {"anyOf": [{"type": "object"}, {"type": "null"}]},
                "reason": {
                    "enum": [
                        "consent-or-safety-concern",
                        "content-correction",
                        "evidence-insufficient",
                        "evidence-sufficient",
                        "policy-conflict",
                        "reconsideration-needed",
                        "superseded",
                    ]
                },
                "note_ref": _NULLABLE_TEXT,
                "decision_nonce": _UUID,
                "decided_at_ms": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": 2**53 - 1,
                },
                "predecessor_decision_id": {
                    "anyOf": [{"type": "string", "maxLength": 160}, {"type": "null"}]
                },
            },
            (
                "review_request_id",
                "authorization_id",
                "action",
                "decision_nonce",
                "replacement",
                "reason",
                "note_ref",
                "decided_at_ms",
                "predecessor_decision_id",
            ),
        ),
        True,
    ),
    "review_decision_submit": (
        "review.decision.submit",
        _object_schema({"decision": {"type": "object"}}, ("decision",)),
        False,
    ),
    "scope_me": ("scope.me", _object_schema({}), True),
    "scope_we": ("scope.we", _object_schema({}), True),
    "scope_we_diff": ("scope.we.diff", _object_schema({}), True),
    "scope_we_sync_plan": (
        "scope.we.sync-plan",
        _object_schema(
            {
                "request_id": _UUID,
                "limit": {"type": "integer", "minimum": 1, "maximum": 256},
            },
            ("request_id",),
        ),
        False,
    ),
    "scope_resolve": (
        "scope.resolve",
        _object_schema(
            {
                "request_id": _UUID,
                "scope": {"enum": ["/me", "/we", "/tribe"]},
                "tribe_ref": _NULLABLE_TEXT,
            },
            ("request_id", "scope"),
        ),
        True,
    ),
    "scope_tribe": (
        "scope.tribe",
        _object_schema(
            {"tribe_ref": {"type": "string", "minLength": 1, "maxLength": 256}},
            ("tribe_ref",),
        ),
        True,
    ),
    "species_genesis_ingest": (
        "species.genesis.ingest",
        _object_schema({"artifact": {"type": "object"}}, ("artifact", "operation_id")),
        False,
    ),
    "species_release_ingest": (
        "species.release.ingest",
        _object_schema({"artifact": {"type": "object"}}, ("artifact", "operation_id")),
        False,
    ),
    "species_incoming": (
        "species.incoming",
        _object_schema(
            {
                "expected_occupied_positions_hash": {
                    "anyOf": [
                        {
                            "type": "string",
                            "pattern": "^[A-Za-z0-9_-]{43}$",
                        },
                        {"type": "null"},
                    ]
                },
                "page_index": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": 2**53 - 1,
                },
                "selected_candidate_id": {
                    "anyOf": [
                        {
                            "type": "string",
                            "pattern": "^dm:species-release:v0:[A-Za-z0-9_-]{43}$",
                        },
                        {"type": "null"},
                    ]
                },
            }
        ),
        True,
    ),
    "species_apply": (
        "species.apply",
        _object_schema({"snapshot": {"type": "object"}}, ("operation_id", "snapshot")),
        False,
    ),
    "species_rollback": (
        "species.rollback",
        _object_schema(
            {
                "reason": {
                    "type": "string",
                    "enum": ["release-fork", "runtime-failure"],
                },
                "snapshot": {"type": "object"},
            },
            ("operation_id", "reason", "snapshot"),
        ),
        False,
    ),
    "source_content_put": (
        "source.content.put",
        _object_schema(
            {
                "data": {"type": "string", "pattern": "^[A-Za-z0-9_-]*$"},
                "media_type": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 128,
                    "pattern": "^[ -~]+$",
                },
            },
            ("data", "media_type"),
        ),
        False,
    ),
    "source_claim": (
        "source.claim",
        _object_schema({"payload": {"type": "object"}}, ("payload",)),
        False,
    ),
    "source_assess": (
        "source.assess",
        _object_schema({"payload": {"type": "object"}}, ("payload",)),
        False,
    ),
    "source_publication_append": (
        "source.publication.append",
        _object_schema({"payload": {"type": "object"}}, ("payload",)),
        False,
    ),
    "source_import_decide": (
        "source.import.decide",
        _object_schema({"payload": {"type": "object"}}, ("payload",)),
        False,
    ),
    "source_status": (
        "source.status",
        _object_schema({"selector": {"type": "object"}}, ("selector",)),
        True,
    ),
    "source_cursor_create": (
        "source.cursor.create",
        _object_schema({"selector": {"type": "object"}}, ("selector",)),
        False,
    ),
    "source_diff": (
        "source.diff",
        _object_schema(
            {
                "continuation": {"anyOf": [{"type": "object"}, {"type": "null"}]},
                "max_bytes": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 268_435_456,
                },
                "max_items": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 4096,
                },
                "request_event_id": _UUID,
                "requester_cursor": {"type": "object"},
                "requester_me_id": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 240,
                },
                "selector": {"type": "object"},
            },
            (
                "max_bytes",
                "max_items",
                "request_event_id",
                "requester_cursor",
                "requester_me_id",
                "selector",
            ),
        ),
        True,
    ),
    "source_incoming": (
        "source.incoming",
        _object_schema({"bundle": {"type": "object"}}, ("bundle",)),
        True,
    ),
    "source_pull": (
        "source.pull",
        _object_schema(
            {"bundle": {"type": "object"}, "preview": {"type": "object"}},
            ("bundle", "operation_id", "preview"),
        ),
        False,
    ),
    "source_promote": (
        "source.promote",
        _object_schema(
            {
                "evidence_snapshot_ref": {"type": "object"},
                "policy_ref": {"type": "object"},
                "publication_id": {
                    "type": "string",
                    "pattern": "^dm:source-publication:v0:[A-Za-z0-9_-]{43}$",
                },
            },
            ("evidence_snapshot_ref", "policy_ref", "publication_id"),
        ),
        False,
    ),
    "source_projection": (
        "source.projection",
        _object_schema(
            {
                "publication_id": {
                    "type": "string",
                    "pattern": "^dm:source-publication:v0:[A-Za-z0-9_-]{43}$",
                }
            },
            ("publication_id",),
        ),
        True,
    ),
    "we_heads": ("we.heads", _object_schema({}), True),
    "we_diff": (
        "we.diff",
        _object_schema(
            {
                "after": _NULLABLE_UUID,
                "kind": _NULLABLE_TEXT,
                "limit": {"type": "integer", "minimum": 1, "maximum": 256},
                "subject": _NULLABLE_TEXT,
            }
        ),
        True,
    ),
    "we_preview": (
        "we.preview",
        _object_schema(
            {"events": {"type": "array", "maxItems": 256, "items": {"type": "object"}}},
            ("events",),
        ),
        True,
    ),
    "we_projection_get": ("we.projection.get", _object_schema({}), True),
    "we_observe": (
        "we.observe",
        _object_schema(
            {
                "subject": {"type": "string", "minLength": 1, "maxLength": 256},
                "payload": {"type": "object"},
                "sensitivity": {"enum": ["personal", "private", "shareable"]},
                "causal_parents": {
                    "type": "array",
                    "maxItems": 64,
                    "items": _UUID,
                    "uniqueItems": True,
                },
                "occurred_at_ms": {
                    "anyOf": [
                        {"type": "integer", "minimum": 0, "maximum": 2**53 - 1},
                        {"type": "null"},
                    ]
                },
                "event_id": _NULLABLE_UUID,
            },
            ("subject", "payload"),
        ),
        False,
    ),
    "we_decide": (
        "we.decide",
        _object_schema(
            {
                "target_event_id": _UUID,
                "decision": {"enum": ["adopt", "reject", "defer", "revert"]},
                "reason": {"type": "string", "minLength": 1, "maxLength": 1024},
                "supersedes": _NULLABLE_UUID,
                "sensitivity": {"enum": ["personal", "private", "shareable"]},
                "occurred_at_ms": {
                    "anyOf": [
                        {"type": "integer", "minimum": 0, "maximum": 2**53 - 1},
                        {"type": "null"},
                    ]
                },
                "event_id": _NULLABLE_UUID,
            },
            ("target_event_id", "decision", "reason"),
        ),
        False,
    ),
    "we_projection_rebuild": (
        "we.projection.rebuild",
        _object_schema({}),
        False,
    ),
    "we_sync_request": (
        "we.sync.request",
        _object_schema(
            {
                "request_id": _UUID,
                "limit": {"type": "integer", "minimum": 1, "maximum": 256},
            },
            ("request_id",),
        ),
        False,
    ),
    "we_sync_serve": (
        "we.sync.serve",
        _object_schema(
            {
                "request": {"type": "object"},
                "transport": {
                    "type": "object",
                    "properties": {
                        "scheme": {"type": "string", "minLength": 1, "maxLength": 128},
                        "principal_id": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": 128,
                        },
                    },
                    "required": ["scheme", "principal_id"],
                    "additionalProperties": False,
                },
            },
            ("request", "transport"),
        ),
        False,
    ),
    "we_sync_pull": (
        "we.sync.pull",
        _object_schema(
            {
                "delta": {"type": "object"},
                "transport": {
                    "type": "object",
                    "properties": {
                        "scheme": {"type": "string", "minLength": 1, "maxLength": 128},
                        "principal_id": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": 128,
                        },
                    },
                    "required": ["scheme", "principal_id"],
                    "additionalProperties": False,
                },
            },
            ("delta", "transport"),
        ),
        False,
    ),
    "we_sync_validate_receipt": (
        "we.sync.validate-receipt",
        _object_schema(
            {
                "receipt": {"type": "object"},
                "transport": {
                    "type": "object",
                    "properties": {
                        "scheme": {"type": "string", "minLength": 1, "maxLength": 128},
                        "principal_id": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": 128,
                        },
                    },
                    "required": ["scheme", "principal_id"],
                    "additionalProperties": False,
                },
            },
            ("receipt", "transport"),
        ),
        False,
    ),
}

_DEFAULTS: Final[dict[str, Any]] = {
    "after": None,
    "causal_parents": [],
    "continuation": None,
    "event_id": None,
    "expected_occupied_positions_hash": None,
    "kind": None,
    "limit": 100,
    "occurred_at_ms": None,
    "page_index": 0,
    "sensitivity": "personal",
    "selected_candidate_id": None,
    "subject": None,
    "supersedes": None,
    "tribe_ref": None,
}


def _public_response(response: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: copy.deepcopy(value) for key, value in response.items() if key != "auth"
    }


def _tool_params(name: str, arguments: Any) -> tuple[str, dict[str, Any], str | None]:
    if name not in TOOL_CONTRACTS:
        raise MCPError(types.METHOD_NOT_FOUND, "Unknown Daimon tool", name)
    if arguments is None:
        arguments = {}
    if not isinstance(arguments, Mapping):
        raise MCPError(types.INVALID_PARAMS, "Tool arguments must be an object")
    schema = TOOL_CONTRACTS[name][1]
    allowed = set(schema["properties"])
    required = set(schema.get("required", []))
    if not required <= set(arguments) or not set(arguments) <= allowed:
        raise MCPError(types.INVALID_PARAMS, "Tool arguments violate the closed schema")
    params = {
        key: copy.deepcopy(value)
        for key, value in arguments.items()
        if key != "operation_id"
    }
    method = TOOL_CONTRACTS[name][0]
    expected = {
        "runtime.status": set(),
        "memory.evaluate": {"candidate", "policy"},
        "memory.execute": {"candidate", "plan", "policy"},
        "review.request": {"request"},
        "review.queue": {"access_proof", "after", "authorization_id", "limit"},
        "review.inspect": {
            "access_proof",
            "authorization_id",
            "review_request_id",
        },
        "review.decision.draft": {
            "action",
            "authorization_id",
            "decision_nonce",
            "decided_at_ms",
            "note_ref",
            "predecessor_decision_id",
            "reason",
            "replacement",
            "review_request_id",
        },
        "review.decision.submit": {"decision"},
        "scope.me": set(),
        "scope.we": set(),
        "scope.we.diff": set(),
        "scope.we.sync-plan": {"limit", "request_id"},
        "scope.resolve": {"request_id", "scope", "tribe_ref"},
        "scope.tribe": {"tribe_ref"},
        "species.genesis.ingest": {"artifact"},
        "species.release.ingest": {"artifact"},
        "species.incoming": {
            "expected_occupied_positions_hash",
            "page_index",
            "selected_candidate_id",
        },
        "species.apply": {"snapshot"},
        "species.rollback": {"reason", "snapshot"},
        "source.content.put": {"data", "media_type"},
        "source.claim": {"payload"},
        "source.assess": {"payload"},
        "source.publication.append": {"payload"},
        "source.import.decide": {"payload"},
        "source.status": {"selector"},
        "source.cursor.create": {"selector"},
        "source.diff": {
            "continuation",
            "max_bytes",
            "max_items",
            "request_event_id",
            "requester_cursor",
            "requester_me_id",
            "selector",
        },
        "source.incoming": {"bundle"},
        "source.pull": {"bundle", "preview"},
        "source.promote": {
            "evidence_snapshot_ref",
            "policy_ref",
            "publication_id",
        },
        "source.projection": {"publication_id"},
        "we.heads": set(),
        "we.diff": {"after", "kind", "limit", "subject"},
        "we.preview": {"events"},
        "we.observe": {
            "causal_parents",
            "event_id",
            "occurred_at_ms",
            "payload",
            "sensitivity",
            "subject",
        },
        "we.decide": {
            "decision",
            "event_id",
            "occurred_at_ms",
            "reason",
            "sensitivity",
            "supersedes",
            "target_event_id",
        },
        "we.projection.get": set(),
        "we.projection.rebuild": set(),
        "we.sync.request": {"limit", "request_id"},
        "we.sync.serve": {"request", "transport"},
        "we.sync.pull": {"delta", "transport"},
        "we.sync.validate-receipt": {"receipt", "transport"},
    }[method]
    for field in expected - set(params):
        params[field] = copy.deepcopy(_DEFAULTS[field])
    operation_id = arguments.get("operation_id")
    if operation_id is not None:
        try:
            if str(uuid.UUID(operation_id)) != operation_id:
                raise ValueError
        except (AttributeError, TypeError, ValueError) as exception:
            raise MCPError(
                types.INVALID_PARAMS, "operation_id must be a canonical UUID"
            ) from exception
    if method in {"source.pull", "species.apply", "species.rollback"}:
        if operation_id is None:
            raise MCPError(
                types.INVALID_PARAMS,
                f"{method.replace('.', '_')} requires operation_id",
            )
        params["operation_id"] = operation_id
    canonical_bytes(params)
    return method, params, operation_id


class DaimonMcp:
    """MCP handlers with no authority beyond one typed local client."""

    def __init__(self, client: LocalClient, request_dir: Path) -> None:
        self.client = client
        self.request_dir = Path(os.path.abspath(request_dir))
        info = self.request_dir.lstat()
        if (
            not self.request_dir.is_dir()
            or self.request_dir.is_symlink()
            or info.st_uid != os.geteuid()
            or info.st_mode & 0o077
        ):
            raise ClientError("request_store_parent_not_owner_only")

    def _request_id(self, operation_id: str) -> tuple[str, Path]:
        request_id = operation_id
        marker = f"explicit:{operation_id}"
        name = hashlib.sha256(marker.encode()).hexdigest() + ".json"
        return request_id, self.request_dir / name

    def _prepare_operation(
        self, method: str, params: Mapping[str, Any], operation_id: str | None
    ) -> dict[str, Any]:
        if operation_id is None:
            return self.client.prepare(method, params)
        request_id, request_path = self._request_id(operation_id)
        if request_path.exists():
            return load_prepared_request(
                request_path,
                self.client.config.capability,
                method=method,
                params=params,
            )
        request = self.client.prepare(method, params, request_id=request_id)
        try:
            store_prepared_request(request_path, request)
            return request
        except ClientError as exception:
            if str(exception) != "request_file_exists":
                raise
        return load_prepared_request(
            request_path,
            self.client.config.capability,
            method=method,
            params=params,
        )

    async def list_tools(
        self,
        ctx: ServerRequestContext[Any, Any],
        params: types.PaginatedRequestParams | None,
    ) -> types.ListToolsResult:
        del ctx
        if params is not None and params.cursor is not None:
            raise MCPError(types.INVALID_PARAMS, "Pagination is not supported")
        tools = []
        for name, (method, schema, read_only) in TOOL_CONTRACTS.items():
            tools.append(
                types.Tool(
                    name=name,
                    description=f"Typed Daimon operation {method}",
                    input_schema=copy.deepcopy(schema),
                    annotations=types.ToolAnnotations(
                        read_only_hint=read_only,
                        destructive_hint=name == "we_decide",
                        idempotent_hint=read_only,
                        open_world_hint=False,
                    ),
                )
            )
        return types.ListToolsResult(tools=tools, ttl_ms=0, cache_scope="private")

    async def call_tool(
        self,
        ctx: ServerRequestContext[Any, Any],
        params: types.CallToolRequestParams,
    ) -> types.CallToolResult:
        del ctx
        method, method_params, operation_id = _tool_params(
            params.name, params.arguments
        )
        if method == "review.decision.submit":
            raise MCPError(
                types.INVALID_REQUEST,
                "Human review decisions require the human-held signing CLI",
            )
        request = self._prepare_operation(method, method_params, operation_id)
        try:
            response = await anyio.to_thread.run_sync(self.client.send, request)
        except ClientError as exception:
            raise MCPError(
                types.INTERNAL_ERROR, "Daimon runtime unavailable"
            ) from exception
        public = _public_response(response)
        return types.CallToolResult(
            content=[
                types.TextContent(
                    text=json.dumps(public, ensure_ascii=False, sort_keys=True)
                )
            ],
            structured_content=public,
            is_error=not bool(response["ok"]),
        )

    def _resource_index(self) -> dict[str, tuple[str, str | None]]:
        return {
            "daimon:contract/server": ("Daimon server descriptor", None),
            "daimon:contract/tools": ("Closed MCP tool contract", None),
            "daimon:contract/local-api": ("DM-024 local protocol descriptor", None),
            "daimon:runtime/status": ("Redacted runtime status", "daimon_status"),
            "daimon:scope/me": ("Exact local embodiment viewpoint", "scope_me"),
            "daimon:scope/we": ("Same-being manifest topology", "scope_we"),
            "daimon:we/heads": ("Signed Weave heads", "we_heads"),
            "daimon:we/projection": (
                "Authorized local projection",
                "we_projection_get",
            ),
        }

    async def list_resources(
        self,
        ctx: ServerRequestContext[Any, Any],
        params: types.PaginatedRequestParams | None,
    ) -> types.ListResourcesResult:
        del ctx
        if params is not None and params.cursor is not None:
            raise MCPError(types.INVALID_PARAMS, "Pagination is not supported")
        resources = [
            types.Resource(
                name=title,
                uri=uri,
                description=title,
                mime_type=MCP_RESOURCE_MEDIA_TYPE,
            )
            for uri, (title, _) in self._resource_index().items()
        ]
        return types.ListResourcesResult(
            resources=resources, ttl_ms=0, cache_scope="private"
        )

    async def read_resource(
        self,
        ctx: ServerRequestContext[Any, Any],
        params: types.ReadResourceRequestParams,
    ) -> types.ReadResourceResult:
        del ctx
        resources = self._resource_index()
        if params.uri not in resources:
            raise MCPError(types.INVALID_PARAMS, "Unknown Daimon resource")
        tool = resources[params.uri][1]
        if params.uri == "daimon:contract/server":
            document: Any = {
                "schema": "dm.mcp.server/v1",
                "protocol": MCP_PROTOCOL_VERSION,
                "server": copy.deepcopy(dict(self.client.config.expected_server)),
            }
        elif params.uri == "daimon:contract/tools":
            document = {
                "schema": "dm.mcp.tools/v1",
                "protocol": MCP_PROTOCOL_VERSION,
                "tools": [
                    {"name": name, "method": value[0], "input_schema": value[1]}
                    for name, value in TOOL_CONTRACTS.items()
                ],
            }
        elif params.uri == "daimon:contract/local-api":
            document = {
                "schema": "dm.local.protocol-index/v1",
                "frame_max_bytes": MAX_FRAME_BYTES,
                "methods": sorted(value[0] for value in TOOL_CONTRACTS.values()),
            }
        else:
            assert tool is not None
            method, method_params, operation_id = _tool_params(tool, {})
            request = self._prepare_operation(method, method_params, operation_id)
            response = await anyio.to_thread.run_sync(self.client.send, request)
            document = _public_response(response)
        raw = canonical_bytes(document)
        envelope = {
            "schema": "dm.mcp.resource/v1",
            "uri": params.uri,
            "media_type": MCP_RESOURCE_MEDIA_TYPE,
            "content_sha256": hashlib.sha256(raw).hexdigest(),
            "provenance": copy.deepcopy(dict(self.client.config.expected_server)),
            "document": document,
        }
        return types.ReadResourceResult(
            contents=[
                types.TextResourceContents(
                    uri=params.uri,
                    mime_type=MCP_RESOURCE_MEDIA_TYPE,
                    text=canonical_bytes(envelope).decode(),
                )
            ],
            ttl_ms=0,
            cache_scope="private",
        )

    def server(self) -> Server[Any]:
        return Server(
            "daimon-matrix",
            version="0.0.0",
            description="Closed owner-local Daimon Matrix adapter",
            on_list_tools=self.list_tools,
            on_call_tool=self.call_tool,
            on_list_resources=self.list_resources,
            on_read_resource=self.read_resource,
        )


class _BoundedStdin:
    """Strict UTF-8 newline reader that rejects frames above the local bound."""

    def __init__(self) -> None:
        self.failed = False

    def __aiter__(self) -> _BoundedStdin:
        return self

    async def __anext__(self) -> str:
        if self.failed:
            raise StopAsyncIteration
        raw = cast(
            bytes,
            await anyio.to_thread.run_sync(
                sys.stdin.buffer.readline, MAX_FRAME_BYTES + 2
            ),
        )
        if not raw:
            raise StopAsyncIteration
        if len(raw) > MAX_FRAME_BYTES + 1 or not raw.endswith(b"\n"):
            self.failed = True
            return "{\n"
        try:
            text = raw.decode("utf-8", errors="strict")
            json.loads(text, object_pairs_hook=_reject_duplicate_keys)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            self.failed = True
            return "{\n"
        return text


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate MCP JSON key")
        result[key] = value
    return result


async def _run_stdio(server: Server[Any]) -> None:
    async with (
        stdio_server(stdin=_BoundedStdin()) as (read_stream, write_stream),  # type: ignore[arg-type]
        server.lifespan(server) as lifespan_context,
    ):
        try:
            async with _replay_from_opening_request(read_stream) as (
                opening,
                replayed,
            ):
                opens_modern = (
                    opening is not None
                    and opening.method != "initialize"
                    and _has_modern_envelope(opening.params)
                )
                if opens_modern:
                    await _serve_modern_stream(
                        server,
                        replayed,
                        write_stream,
                        lifespan_state=lifespan_context,
                        raise_exceptions=False,
                    )
                elif opening is not None:
                    params = opening.params
                    requested = (
                        params.get("protocolVersion")
                        if isinstance(params, Mapping)
                        else None
                    )
                    if (
                        opening.method == "initialize"
                        and requested != CODEX_MCP_PROTOCOL_VERSION
                    ):
                        await write_stream.send(
                            SessionMessage(
                                types.JSONRPCError(
                                    jsonrpc="2.0",
                                    id=opening.id,
                                    error=types.ErrorData(
                                        code=types.UNSUPPORTED_PROTOCOL_VERSION,
                                        message="unsupported MCP handshake version",
                                        data={"supported": list(MCP_PROTOCOL_VERSIONS)},
                                    ),
                                )
                            )
                        )
                    else:
                        await _serve_legacy_stream(
                            server,
                            replayed,
                            write_stream,
                            lifespan_state=lifespan_context,
                            session_id=None,
                            init_options=server.create_initialization_options(),
                            raise_exceptions=False,
                        )
        finally:
            await write_stream.aclose()


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="daimon-mcp", description=__doc__)
    result.add_argument("--socket", type=Path, required=True)
    result.add_argument("--client-config", type=Path, required=True)
    result.add_argument("--capability-key-fd", type=int, required=True)
    result.add_argument("--request-dir", type=Path, required=True)
    result.add_argument("--timeout", type=float, default=5.0)
    return result


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = parser().parse_args(argv)
        key = read_capability_key(args.capability_key_fd)
        config = ClientConfig.load(args.client_config, key)
        bridge = DaimonMcp(
            LocalClient(args.socket, config, args.timeout), args.request_dir
        )
        asyncio.run(_run_stdio(bridge.server()))
        return 0
    except (ClientError, OSError, ValueError) as exception:
        print(str(exception), file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "CODEX_MCP_PROTOCOL_VERSION",
    "MCP_PROTOCOL_VERSION",
    "MCP_PROTOCOL_VERSIONS",
    "TOOL_CONTRACTS",
    "DaimonMcp",
    "main",
    "parser",
]
