"""Thin existing-Hermes attachment; all protocol work stays in Matrix."""

import json
import subprocess
from pathlib import Path
from typing import Any, cast


def _settings() -> dict[str, Any]:
    return cast(
        dict[str, Any],
        json.loads(Path(__file__).with_name("connection.json").read_text()),
    )


def _run(
    command: list[str],
    arguments: dict[str, Any] | None = None,
    *,
    timeout: int = 50,
) -> dict[str, Any]:
    settings = _settings()
    result = subprocess.run(
        [*settings["command"], *command],
        input=json.dumps(arguments or {}),
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if len(result.stdout) > 1_048_576:
        return {"ok": False, "error": "agent_chat_response_too_large"}
    try:
        value = json.loads(result.stdout)
        if not isinstance(value, dict):
            raise ValueError()
        return value
    except (ValueError, TypeError):
        return {"ok": False, "error": "agent_chat_unavailable"}


def register(ctx: Any) -> None:
    settings = _settings()
    for schema in settings["tools"]:
        name = schema["name"]

        def handler(
            args: dict[str, Any],
            *,
            _name: str = name,
            **kwargs: Any,
        ) -> str:
            del kwargs
            try:
                command = (
                    ["channels"] if _name == "messaging_channels" else ["call", _name]
                )
                return json.dumps(_run(command, args), ensure_ascii=False)
            except (OSError, subprocess.TimeoutExpired):
                return json.dumps({"ok": False, "error": "agent_chat_unavailable"})

        ctx.register_tool(
            name=name,
            toolset="messaging",
            schema=schema,
            handler=handler,
            description=schema["description"],
            emoji="📨",
        )
