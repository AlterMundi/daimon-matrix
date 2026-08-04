"""Human-oriented command line client for the DM-024 hosted runtime."""

from __future__ import annotations

import argparse
import copy
import json
import sys
from collections.abc import Mapping, Sequence
from contextlib import suppress
from pathlib import Path
from typing import Any, Final

from .canonical import canonical_bytes
from .client import (
    ClientConfig,
    ClientError,
    LocalClient,
    load_json_document,
    load_prepared_request,
    read_capability_key,
    store_prepared_request,
)
from .local_api import MAX_FRAME_BYTES

EXIT_OK: Final = 0
EXIT_USAGE: Final = 2
EXIT_AUTH: Final = 3
EXIT_DAEMON: Final = 4
EXIT_REFUSED: Final = 5
EXIT_PROTOCOL: Final = 6


def _bounded_file(value: str, *, object_required: bool = True) -> Any:
    if value == "-":
        raw = sys.stdin.buffer.read(MAX_FRAME_BYTES + 1)
    else:
        try:
            path = Path(value)
            if path.is_symlink() or not path.is_file():
                raise ClientError("input_document_unavailable")
            raw = path.read_bytes()
        except OSError as exception:
            raise ClientError("input_document_unavailable") from exception
    return load_json_document(raw, require_object=object_required)


def _transport(args: argparse.Namespace) -> dict[str, str]:
    return {
        "scheme": str(args.transport_scheme),
        "principal_id": str(args.transport_principal),
    }


def _method_params(args: argparse.Namespace) -> tuple[str, dict[str, Any]]:
    command = (args.family, args.command)
    if command == ("daemon", "status"):
        return "runtime.status", {}
    if command == ("scope", "me"):
        return "scope.me", {}
    if command == ("scope", "we"):
        return "scope.we", {}
    if command == ("scope", "diff"):
        return "scope.we.diff", {}
    if command == ("scope", "sync-plan"):
        return "scope.we.sync-plan", {
            "request_id": args.scope_request_id,
            "limit": args.limit,
        }
    if command == ("scope", "resolve"):
        return "scope.resolve", {
            "request_id": args.scope_request_id,
            "scope": args.scope,
            "tribe_ref": args.tribe_ref,
        }
    if command == ("scope", "tribe"):
        return "scope.tribe", {"tribe_ref": args.tribe_ref}
    if command == ("we", "heads"):
        return "we.heads", {}
    if command == ("we", "diff"):
        return "we.diff", {
            "after": args.after,
            "kind": args.kind,
            "limit": args.limit,
            "subject": args.subject,
        }
    if command == ("we", "preview"):
        events = _bounded_file(args.events, object_required=False)
        if not isinstance(events, list):
            raise ClientError("events_document_not_array")
        return "we.preview", {"events": events}
    if command == ("we", "observe"):
        payload = _bounded_file(args.payload)
        return "we.observe", {
            "subject": args.subject,
            "payload": payload,
            "sensitivity": args.sensitivity,
            "causal_parents": sorted(set(args.causal_parent)),
            "occurred_at_ms": args.occurred_at_ms,
            "event_id": args.event_id,
        }
    if command == ("we", "decide"):
        return "we.decide", {
            "target_event_id": args.target_event_id,
            "decision": args.decision,
            "reason": args.reason,
            "supersedes": args.supersedes,
            "sensitivity": args.sensitivity,
            "occurred_at_ms": args.occurred_at_ms,
            "event_id": args.event_id,
        }
    if command == ("we", "projection-get"):
        return "we.projection.get", {}
    if command == ("we", "projection-rebuild"):
        return "we.projection.rebuild", {}
    if command == ("sync", "request"):
        return "we.sync.request", {
            "request_id": args.sync_request_id,
            "limit": args.limit,
        }
    if command == ("sync", "serve"):
        return "we.sync.serve", {
            "request": _bounded_file(args.document),
            "transport": _transport(args),
        }
    if command == ("sync", "pull"):
        return "we.sync.pull", {
            "delta": _bounded_file(args.document),
            "transport": _transport(args),
        }
    if command == ("sync", "validate-receipt"):
        return "we.sync.validate-receipt", {
            "receipt": _bounded_file(args.document),
            "transport": _transport(args),
        }
    raise ClientError("unsupported_cli_command")


def _common_document(command: argparse.ArgumentParser) -> None:
    command.add_argument("--document", required=True, help="JSON file, or - for stdin")
    command.add_argument("--transport-scheme", required=True)
    command.add_argument("--transport-principal", required=True)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="daimon", description=__doc__)
    result.add_argument("--socket", type=Path, required=True)
    result.add_argument("--client-config", type=Path, required=True)
    result.add_argument("--capability-key-fd", type=int, required=True)
    result.add_argument("--timeout", type=float, default=5.0)
    result.add_argument("--rpc-request-id")
    result.add_argument(
        "--request-file",
        type=Path,
        help="owner-only durable exact-retry token; created on first attempt",
    )
    result.add_argument("--json", action="store_true", dest="json_output")
    families = result.add_subparsers(dest="family", required=True)

    daemon = families.add_parser("daemon", help="hosted daemon operations")
    daemon_commands = daemon.add_subparsers(dest="command", required=True)
    daemon_commands.add_parser("status", help="redacted integrity and counts")

    scope = families.add_parser("scope", help="root-authorized viewpoint and audience")
    scope_commands = scope.add_subparsers(dest="command", required=True)
    scope_commands.add_parser("me", help="exact local embodiment viewpoint")
    scope_commands.add_parser("we", help="same-being manifest topology")
    scope_commands.add_parser("diff", help="payload-free local projection summary")
    sync_plan = scope_commands.add_parser(
        "sync-plan", help="one exact DM-023 request per active remote origin"
    )
    sync_plan.add_argument("--scope-request-id", required=True)
    sync_plan.add_argument("--limit", type=int, default=100)
    resolve = scope_commands.add_parser(
        "resolve", help="authoritative target plan for /me, /we, or /tribe"
    )
    resolve.add_argument("--scope-request-id", required=True)
    resolve.add_argument("--scope", choices=("/me", "/we", "/tribe"), required=True)
    resolve.add_argument("--tribe-ref")
    tribe = scope_commands.add_parser("tribe", help="one verified tribe snapshot")
    tribe.add_argument("--tribe-ref", required=True)

    we = families.add_parser("we", help="local Weave ledger and projection")
    we_commands = we.add_subparsers(dest="command", required=True)
    we_commands.add_parser("heads", help="signed origin heads")
    diff = we_commands.add_parser("diff", help="deterministic projection differences")
    diff.add_argument("--after")
    diff.add_argument("--kind")
    diff.add_argument("--limit", type=int, default=100)
    diff.add_argument("--subject")
    preview = we_commands.add_parser("preview", help="validate without mutation")
    preview.add_argument("--events", required=True, help="JSON array file, or -")
    observe = we_commands.add_parser("observe", help="author one local observation")
    observe.add_argument("--subject", required=True)
    observe.add_argument("--payload", required=True, help="JSON object file, or -")
    observe.add_argument(
        "--sensitivity",
        choices=("personal", "private", "shareable"),
        default="personal",
    )
    observe.add_argument("--causal-parent", action="append", default=[])
    observe.add_argument("--occurred-at-ms", type=int)
    observe.add_argument("--event-id")
    decide = we_commands.add_parser(
        "decide", help="author one explicit local decision successor"
    )
    decide.add_argument("--target-event-id", required=True)
    decide.add_argument(
        "--decision", choices=("adopt", "reject", "defer", "revert"), required=True
    )
    decide.add_argument("--reason", required=True)
    decide.add_argument("--supersedes")
    decide.add_argument(
        "--sensitivity",
        choices=("personal", "private", "shareable"),
        default="personal",
    )
    decide.add_argument("--occurred-at-ms", type=int)
    decide.add_argument("--event-id")
    we_commands.add_parser("projection-get", help="read validated disposable cache")
    we_commands.add_parser("projection-rebuild", help="rebuild disposable projection")

    sync = families.add_parser("sync", help="exact DM-023 sync documents")
    sync_commands = sync.add_subparsers(dest="command", required=True)
    request = sync_commands.add_parser("request", help="issue one sync request")
    request.add_argument("--sync-request-id", required=True)
    request.add_argument("--limit", type=int, default=100)
    for name in ("serve", "pull", "validate-receipt"):
        _common_document(sync_commands.add_parser(name))
    return result


def _write_result(
    method: str,
    request: Mapping[str, Any],
    response: Mapping[str, Any],
    *,
    json_output: bool,
) -> None:
    public_response = {
        key: copy.deepcopy(value) for key, value in response.items() if key != "auth"
    }
    if json_output:
        envelope = {
            "schema": "dm.cli.result/v1",
            "method": method,
            "request_id": request["request_id"],
            "response": public_response,
        }
        sys.stdout.buffer.write(canonical_bytes(envelope) + b"\n")
        sys.stdout.buffer.flush()
        return
    state = "ok" if response["ok"] else f"refused:{response['error']['code']}"
    print(f"{method} {state} request={request['request_id']}")
    content = (
        public_response["result"] if public_response["ok"] else public_response["error"]
    )
    print(json.dumps(content, ensure_ascii=False, indent=2, sort_keys=True))


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        key = read_capability_key(args.capability_key_fd)
        config = ClientConfig.load(args.client_config, key)
        client = LocalClient(args.socket, config, args.timeout)
        method, params = _method_params(args)
        if args.request_file is not None and args.request_file.exists():
            request = load_prepared_request(
                args.request_file,
                config.capability,
                method=method,
                params=params,
            )
        else:
            request = client.prepare(method, params, request_id=args.rpc_request_id)
            if args.request_file is not None:
                store_prepared_request(args.request_file, request)
        response = client.send(request)
        _write_result(method, request, response, json_output=args.json_output)
        return EXIT_OK if response["ok"] else EXIT_REFUSED
    except ClientError as exception:
        code = str(exception)
        print(code, file=sys.stderr)
        if code == "daemon_unavailable":
            return EXIT_DAEMON
        if code.startswith("daemon_response") or code in {
            "invalid_daemon_response_size",
            "trailing_daemon_response",
        }:
            return EXIT_PROTOCOL
        if code.startswith(("client_", "capability_", "request_", "daemon_socket_")):
            return EXIT_AUTH
        if code in {
            "invalid_capability_key",
            "invalid_capability_key_descriptor",
            "invalid_expected_server",
            "unsupported_client_config",
        }:
            return EXIT_AUTH
        return EXIT_USAGE
    except BrokenPipeError:
        with suppress(OSError):
            sys.stdout.close()
        return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["main", "parser"]
