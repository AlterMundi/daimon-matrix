from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .core import (
    Ledger,
    SpikeError,
    incoming_from_peer,
    ingest,
    init_state,
    load_config,
    observe,
    preview,
    pull_from_peer,
    sync_with_peer,
    trust_incarnation,
)


def _print(value: Any) -> None:
    print(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2))


def _stdin_events() -> tuple[list[dict[str, Any]], str]:
    data = json.load(sys.stdin)
    events = data.get("events")
    if not isinstance(events, list):
        raise SpikeError("stdin payload must contain an events list")
    return events, str(data.get("source") or "stdin")


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        description="Disposable Daimon Matrix /we synchronization spike"
    )
    root.add_argument("--state-dir", required=True, type=Path)
    sub = root.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init")
    init.add_argument("--me-id", required=True)
    init.add_argument("--incarnation-id", required=True)
    init.add_argument("--host", required=True)
    init.add_argument("--harness", required=True)
    init.add_argument("--hmk-wrapper")
    init.add_argument("--hmk-base")
    init.add_argument("--hermes-home")

    trust = sub.add_parser("trust")
    trust.add_argument("--incarnation-id", required=True)
    trust.add_argument("--public-key", required=True)
    trust.add_argument("--peer-id")
    trust.add_argument("--ssh-host")
    trust.add_argument("--remote-python")
    trust.add_argument("--remote-state-dir")

    observation = sub.add_parser("observe")
    observation.add_argument("--title", required=True)
    observation.add_argument("--content", required=True)
    observation.add_argument("--tags", default="")

    sub.add_parser("status")
    sub.add_parser("export")
    sub.add_parser("preview-stdin")
    sub.add_parser("ingest-stdin")

    incoming = sub.add_parser("incoming")
    incoming.add_argument("peer")
    pull = sub.add_parser("pull")
    pull.add_argument("peer")
    sync = sub.add_parser("sync")
    sync.add_argument("peer")
    sync.add_argument("--stop-after-push", action="store_true")
    return root


def run(args: argparse.Namespace) -> Any:
    state_dir: Path = args.state_dir.expanduser().resolve()
    if args.command == "init":
        config = init_state(
            state_dir,
            me_id=args.me_id,
            incarnation_id=args.incarnation_id,
            host=args.host,
            harness=args.harness,
            hmk_wrapper=args.hmk_wrapper,
            hmk_base=args.hmk_base,
            hermes_home=args.hermes_home,
        )
        return {
            "experimental": True,
            "state_dir": str(state_dir),
            "me_id": config["me_id"],
            "incarnation_id": config["incarnation_id"],
            "public_key": config["public_key"],
            "key_id": config["key_id"],
        }
    if args.command == "trust":
        config = trust_incarnation(
            state_dir,
            incarnation_id=args.incarnation_id,
            public_key=args.public_key,
            peer_id=args.peer_id,
            ssh_host=args.ssh_host,
            remote_python=args.remote_python,
            remote_state_dir=args.remote_state_dir,
        )
        return {
            "trusted": args.incarnation_id,
            "peer": config.get("peers", {}).get(args.peer_id) if args.peer_id else None,
        }
    if args.command == "observe":
        tags = [tag.strip() for tag in args.tags.split(",") if tag.strip()]
        return observe(state_dir, title=args.title, content=args.content, tags=tags)
    if args.command == "status":
        config = load_config(state_dir)
        return {
            "experimental": True,
            "me_id": config["me_id"],
            "incarnation_id": config["incarnation_id"],
            "embodiment": config["embodiment"],
            "ledger": Ledger(state_dir).status(),
        }
    if args.command == "export":
        return {"events": Ledger(state_dir).envelopes()}
    if args.command == "preview-stdin":
        events, _ = _stdin_events()
        return preview(state_dir, events)
    if args.command == "ingest-stdin":
        events, source = _stdin_events()
        return ingest(state_dir, events, imported_from=source)
    if args.command == "incoming":
        return incoming_from_peer(state_dir, args.peer)
    if args.command == "pull":
        return pull_from_peer(state_dir, args.peer)
    if args.command == "sync":
        return sync_with_peer(
            state_dir, args.peer, stop_after_push=args.stop_after_push
        )
    raise SpikeError(f"unknown command: {args.command}")


def main() -> None:
    try:
        _print(run(parser().parse_args()))
    except (SpikeError, json.JSONDecodeError) as exc:
        _print({"ok": False, "error": str(exc)})
        raise SystemExit(2) from exc


if __name__ == "__main__":
    main()
