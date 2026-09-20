"""Fixed standalone child; stdlib only until inside the mandatory OS sandbox.

No Matrix imports, signing/native credentials, profile discovery or scheduler.
The loopback relay can reach ONLY the host gate's mounted Unix socket. A fresh
network namespace, not SDK options, removes all other provider egress.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import select
import socket
import socketserver
import sys
import threading
from pathlib import Path


class GateRelay(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = False


class RelayHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as upstream:
            upstream.connect("/gate.sock")
            sockets = [upstream, self.request]
            while True:
                ready, _, _ = select.select(sockets, [], [], 1)
                for source in ready:
                    raw = source.recv(65536)
                    if not raw:
                        return
                    target = self.request if source is upstream else upstream
                    target.sendall(raw)


def main() -> None:
    raw = sys.stdin.buffer.readline(1048577)
    if len(raw) > 1048576 or not raw.endswith(b"\n"):
        raise ValueError("invalid worker input")
    data = json.loads(raw)
    if set(data) != {
        "cycle_id",
        "session_id",
        "host_netns",
        "token",
        "provider",
        "model",
        "api_mode",
        "max_tokens",
        "prompt",
        "scopes",
    }:
        raise ValueError("closed worker input required")
    if os.readlink("/proc/self/ns/net") == data["host_netns"]:
        raise ValueError("network namespace isolation missing")
    home = Path(os.environ["HERMES_HOME"])
    home.mkdir(mode=0o700)
    # Fixed config only. Blank private home contains no copied user content.
    (home / "config.yaml").write_text(
        "compression:\n  enabled: false\nagent:\n  api_max_retries: 1\n"
        "display:\n  streaming: false\nmemory:\n  memory_enabled: false\n"
        "  user_profile_enabled: false\n"
        "plugins:\n  enabled: []\n",
        encoding="utf-8",
    )
    sys.path.insert(0, "/hermes-source")
    # Do not let import/init progress contaminate the bounded result channel.
    with (
        open(os.devnull, "w", encoding="utf-8") as quiet,
        contextlib.redirect_stdout(quiet),
    ):
        from run_agent import AIAgent  # type: ignore[import-not-found]

        with GateRelay(("127.0.0.1", 0), RelayHandler) as relay:
            thread = threading.Thread(target=relay.serve_forever, daemon=True)
            thread.start()
            agent = AIAgent(
                base_url=f"http://127.0.0.1:{relay.server_address[1]}/v1",
                api_key=data["token"],
                provider=data["provider"],
                api_mode=data["api_mode"],
                model=data["model"],
                max_iterations=1,
                max_tokens=data["max_tokens"],
                enabled_toolsets=[],
                save_trajectories=False,
                quiet_mode=True,
                session_id=data["session_id"],
                skip_context_files=True,
                load_soul_identity=False,
                skip_memory=True,
                session_db=None,
                fallback_model=None,
                credential_pool=None,
                checkpoints_enabled=False,
            )
            if agent.tools or agent.valid_tool_names:
                raise ValueError("resolved tools not empty")
            if (
                agent.model != data["model"]
                or agent.provider != data["provider"]
                or agent.api_mode != data["api_mode"]
                or agent.session_id != data["session_id"]
            ):
                raise ValueError("effective Hermes selection changed")
            result = agent.run_conversation(
                data["prompt"],
                task_id=data["cycle_id"],
                system_message=(
                    'Return only JSON: {"action":"none"}, {"scope":INDEX} for inbox, '
                    'or {"scope":INDEX,"text":TEXT} for send/reply. No tools. '
                    "Approved scopes: " + json.dumps(data["scopes"])
                ),
            )
            relay.shutdown()
            thread.join(1)
    text = result.get("final_response")
    if not isinstance(text, str) or len(text.encode()) > data["max_tokens"]:
        raise ValueError("invalid bounded final response")
    # load_config seeds this upstream default even with persona loading off.
    # Bind its exact bytes rather than claiming the fresh home stays empty.
    seeded_soul = hashlib.sha256((home / "SOUL.md").read_bytes()).hexdigest()
    evidence = dict(
        session_id=agent.session_id,
        task_id=data["cycle_id"],
        tools=agent.tools,
        seeded_soul_sha256=seeded_soul,
        provider=agent.provider,
        model=agent.model,
        api_mode=agent.api_mode,
        text=text,
        isolated_network=True,
        environment_keys=sorted(os.environ),
        home_files=sorted(
            str(p.relative_to(home)) for p in home.rglob("*") if p.is_file()
        ),
    )
    output = json.dumps(
        evidence, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()
    if len(output) > 1048576:
        raise ValueError("oversized worker evidence")
    sys.stdout.buffer.write(output + b"\n")
    sys.stdout.buffer.flush()


if __name__ == "__main__":
    main()
