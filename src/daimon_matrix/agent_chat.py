"""Attach an existing agent to messaging, without creating a being or daemon."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any

import mcp_types as types
from mcp.server.context import ServerRequestContext
from mcp.shared.exceptions import MCPError

from .client import ClientConfig, ClientError, LocalClient, load_json_document
from .mcp_server import (
    MESSAGING_TOOL_CONTRACTS,
    DaimonMcp,
    _run_stdio,
)
from .messaging_config import _directory, protected_read

SCHEMA = "dm.agent-chat.binding/v1"


def load_binding(path: Path) -> dict[str, Any]:
    value = load_json_document(protected_read(path))
    fields = {
        "schema",
        "socket",
        "client_config",
        "client_key",
        "request_dir",
        "incoming_channels",
        "outgoing_channels",
    }
    if set(value) != fields or value["schema"] != SCHEMA:
        raise ValueError("agent_chat_binding_invalid")
    for field in ("socket", "client_config", "client_key", "request_dir"):
        if not isinstance(value[field], str) or not Path(value[field]).is_absolute():
            raise ValueError("agent_chat_binding_path_invalid")
    for field in ("incoming_channels", "outgoing_channels"):
        channels = value[field]
        if (
            not isinstance(channels, list)
            or len(channels) > 64
            or any(not isinstance(c, str) or not c or len(c) > 128 for c in channels)
            or len(channels) != len(set(channels))
        ):
            raise ValueError("agent_chat_channels_invalid")
    return dict(value)


class AgentChatMcp(DaimonMcp):
    """The same restricted, exact-retry contract for CLI, Hermes and MCP."""

    def __init__(self, client: LocalClient, binding: dict[str, Any]) -> None:
        self.binding = binding
        super().__init__(
            client, _directory(Path(binding["request_dir"])), messaging_only=True
        )

    async def list_tools(
        self,
        ctx: ServerRequestContext[Any, Any],
        params: types.PaginatedRequestParams | None,
    ) -> types.ListToolsResult:
        result = await super().list_tools(ctx, params)
        for tool in result.tools:
            tool.description = (
                "Only on human request; never read or act autonomously. "
                + (tool.description or "")
            )
        return result

    async def call_tool(
        self,
        ctx: ServerRequestContext[Any, Any],
        params: types.CallToolRequestParams,
    ) -> types.CallToolResult:
        try:
            arguments = checked_arguments(self.binding, params.name, params.arguments)
        except ValueError as error:
            raise MCPError(types.INVALID_PARAMS, str(error)) from error
        return await super().call_tool(
            ctx, types.CallToolRequestParams(name=params.name, arguments=arguments)
        )


def bridge(binding: dict[str, Any], *, timeout: float = 45) -> AgentChatMcp:
    key = protected_read(Path(binding["client_key"]), size=32)
    config = ClientConfig.load(Path(binding["client_config"]), key)
    if not set(config.capability.methods) <= {
        row[0] for row in MESSAGING_TOOL_CONTRACTS.values()
    }:
        raise ValueError("agent_chat_requires_messaging_only_capability")
    return AgentChatMcp(LocalClient(Path(binding["socket"]), config, timeout), binding)


def checked_arguments(
    binding: dict[str, Any],
    name: str,
    arguments: Any,
) -> dict[str, Any]:
    if name not in MESSAGING_TOOL_CONTRACTS:
        raise ValueError("agent_chat_unknown_tool")
    if not isinstance(arguments, dict):
        raise ValueError("agent_chat_arguments_invalid")
    direction = (
        "incoming_channels" if name == "messaging_inbox" else "outgoing_channels"
    )
    if arguments.get("channel_id") not in binding[direction]:
        raise ValueError("agent_chat_channel_not_configured")
    if (
        name == "messaging_reply"
        and arguments.get("received_channel_id") not in binding["incoming_channels"]
    ):
        raise ValueError("agent_chat_channel_not_configured")
    arguments = dict(arguments)
    if name in {"messaging_send", "messaging_reply"}:
        # Stable send IDs also key durable authenticated exact-retry requests.
        # A changed payload under the same ID is refused, never silently resent.
        if arguments.get("operation_id", arguments.get("send_id")) != arguments.get(
            "send_id"
        ):
            raise ValueError("agent_chat_operation_id_must_match_send_id")
        arguments["operation_id"] = arguments.get("send_id")
    return dict(arguments)


async def call(
    binding: dict[str, Any],
    name: str,
    arguments: dict[str, Any],
    *,
    timeout: float = 45,
) -> dict[str, Any]:
    result = await bridge(binding, timeout=timeout).call_tool(
        None,  # type: ignore[arg-type]
        types.CallToolRequestParams(name=name, arguments=arguments),
    )
    assert result.structured_content is not None
    return dict(result.structured_content)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binding", type=Path, required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("channels")
    commands.add_parser("mcp")
    invoke = commands.add_parser("call")
    invoke.add_argument("name", choices=tuple(MESSAGING_TOOL_CONTRACTS))
    invoke.add_argument("--timeout", type=float, default=45)
    args = parser.parse_args(argv)
    try:
        binding = load_binding(args.binding)
        if args.command == "channels":
            output = {k: binding[k] for k in ("incoming_channels", "outgoing_channels")}
            output["receiving"] = "human-request-only; no automatic reads or actions"
        elif args.command == "mcp":
            asyncio.run(_run_stdio(bridge(binding).server()))
            return 0
        else:
            if not 0 < args.timeout <= 60:
                raise ValueError("agent_chat_timeout_invalid")
            arguments = load_json_document(sys.stdin.buffer.read(1_048_577))
            output = asyncio.run(
                call(binding, args.name, arguments, timeout=args.timeout)
            )
        print(json.dumps(output, ensure_ascii=False, sort_keys=True))
        return 0 if output.get("ok", True) else 1
    except Exception as error:
        # Do not expose paths, input text, capability material or remote errors.
        code = (
            str(error)
            if isinstance(error, (ClientError, ValueError))
            else "agent_chat_unavailable"
        )
        if not code.replace("_", "").isalnum() or len(code) > 100:
            code = "agent_chat_unavailable"
        print(json.dumps({"ok": False, "error": code}), file=sys.stdout)
        return 1


if __name__ == "__main__":
    os.umask(0o077)
    raise SystemExit(main())
