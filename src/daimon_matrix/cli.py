"""Human-oriented command line client for the DM-024 hosted runtime."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import sys
from collections.abc import Mapping, Sequence
from contextlib import suppress
from pathlib import Path
from typing import Any, Final

from .canonical import b64url, canonical_bytes
from .client import (
    ClientConfig,
    ClientError,
    LocalClient,
    load_json_document,
    load_prepared_request,
    read_capability_key,
    store_prepared_request,
)
from .human_review import DECISION_REASONS
from .local_api import MAX_FRAME_BYTES

EXIT_OK: Final = 0
EXIT_USAGE: Final = 2
EXIT_AUTH: Final = 3
EXIT_DAEMON: Final = 4
EXIT_REFUSED: Final = 5
EXIT_PROTOCOL: Final = 6
REVIEW_METHOD_PREFIX: Final = "review."


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


def _bounded_bytes(value: str) -> bytes:
    try:
        path = Path(value)
        if path.is_symlink() or not path.is_file():
            raise ClientError("input_document_unavailable")
        raw = path.read_bytes()
    except OSError as exception:
        raise ClientError("input_document_unavailable") from exception
    if len(raw) > 67_108_864:
        raise ClientError("input_document_too_large")
    return raw


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
    if command == ("memory", "evaluate"):
        return "memory.evaluate", {
            "policy": _bounded_file(args.policy),
            "candidate": _bounded_file(args.candidate),
        }
    if command == ("memory", "execute"):
        return "memory.execute", {
            "policy": _bounded_file(args.policy),
            "candidate": _bounded_file(args.candidate),
            "plan": _bounded_file(args.plan),
        }
    if command == ("curator", "enqueue"):
        return "curator.enqueue", {"item": _bounded_file(args.item)}
    if command == ("curator", "claim"):
        return "curator.claim", {
            "item_id": args.item_id,
            "claim_id": args.claim_id,
            "expected_generation": args.expected_generation,
            "lease_until_ms": args.lease_until_ms,
            "fence_evidence": None
            if args.fence_evidence is None
            else _bounded_file(args.fence_evidence),
        }
    if command == ("curator", "complete"):
        return "curator.complete", {
            "claim_id": args.claim_id,
            "expected_generation": args.expected_generation,
            "outcome": args.outcome,
            "output_refs": sorted(set(args.output_ref)),
            "effect_receipt": None
            if args.effect_receipt is None
            else _bounded_file(args.effect_receipt),
        }
    if command == ("curator", "inspect"):
        return "curator.inspect", {"item_id": args.item_id}
    if command == ("review", "authorize"):
        return "review.authorize", {"authorization": _bounded_file(args.authorization)}
    if command == ("review", "revoke"):
        return "review.revoke", {
            "authorization_id": args.authorization_id,
            "reason": args.reason,
        }
    if command == ("review", "request"):
        return "review.request", {"request": _bounded_file(args.review_request)}
    if command == ("review", "queue"):
        return "review.queue", {
            "authorization_id": args.authorization_id,
            "access_proof": _bounded_file(args.access_proof),
            "after": args.after,
            "limit": args.limit,
        }
    if command == ("review", "inspect"):
        return "review.inspect", {
            "review_request_id": args.review_request_id,
            "authorization_id": args.authorization_id,
            "access_proof": _bounded_file(args.access_proof),
        }
    if command == ("review", "draft"):
        return "review.decision.draft", {
            "review_request_id": args.review_request_id,
            "authorization_id": args.authorization_id,
            "action": args.action,
            "replacement": None
            if args.replacement is None
            else _bounded_file(args.replacement),
            "reason": args.reason,
            "note_ref": args.note_ref,
            "decision_nonce": args.decision_nonce,
            "decided_at_ms": args.decided_at_ms,
            "predecessor_decision_id": args.predecessor_decision_id,
        }
    if command == ("review", "submit"):
        return "review.decision.submit", {
            "decision": _bounded_file(args.signed_decision)
        }
    if command == ("review", "execute"):
        return "review.execute", {"review_request_id": args.review_request_id}
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
    if command == ("species", "genesis-ingest"):
        return "species.genesis.ingest", {"artifact": _bounded_file(args.artifact)}
    if command == ("species", "release-ingest"):
        return "species.release.ingest", {"artifact": _bounded_file(args.artifact)}
    if command == ("species", "incoming"):
        return "species.incoming", {
            "expected_occupied_positions_hash": args.expected_occupied_positions_hash,
            "page_index": args.page_index,
            "selected_candidate_id": args.selected_candidate_id,
        }
    if command == ("species", "apply"):
        return "species.apply", {
            "operation_id": args.operation_id,
            "snapshot": _bounded_file(args.snapshot),
        }
    if command == ("species", "rollback"):
        return "species.rollback", {
            "operation_id": args.operation_id,
            "reason": args.reason,
            "snapshot": _bounded_file(args.snapshot),
        }
    if command == ("source", "content-put"):
        return "source.content.put", {
            "data": b64url(_bounded_bytes(args.content)),
            "media_type": args.media_type,
        }
    if command in {
        ("source", "claim"),
        ("source", "assess"),
        ("source", "publication-append"),
        ("source", "import-decide"),
    }:
        methods = {
            "claim": "source.claim",
            "assess": "source.assess",
            "publication-append": "source.publication.append",
            "import-decide": "source.import.decide",
        }
        return methods[args.command], {"payload": _bounded_file(args.payload)}
    if command == ("source", "status"):
        return "source.status", {"selector": _bounded_file(args.selector)}
    if command == ("source", "cursor-create"):
        return "source.cursor.create", {"selector": _bounded_file(args.selector)}
    if command == ("source", "diff"):
        return "source.diff", {
            "continuation": (
                None if args.continuation is None else _bounded_file(args.continuation)
            ),
            "max_bytes": args.max_bytes,
            "max_items": args.max_items,
            "request_event_id": args.source_request_id,
            "requester_cursor": _bounded_file(args.requester_cursor),
            "requester_me_id": args.requester_me_id,
            "selector": _bounded_file(args.selector),
        }
    if command == ("source", "incoming"):
        return "source.incoming", {"bundle": _bounded_file(args.bundle)}
    if command == ("source", "pull"):
        return "source.pull", {
            "bundle": _bounded_file(args.bundle),
            "operation_id": args.operation_id,
            "preview": _bounded_file(args.preview),
        }
    if command == ("source", "promote"):
        return "source.promote", {
            "evidence_snapshot_ref": _bounded_file(args.evidence_snapshot_ref),
            "policy_ref": _bounded_file(args.policy_ref),
            "publication_id": args.publication_id,
        }
    if command == ("source", "projection"):
        return "source.projection", {"publication_id": args.publication_id}
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

    species = families.add_parser(
        "species", help="DM-014 lineage verification and local application"
    )
    species_commands = species.add_subparsers(dest="command", required=True)
    species_genesis = species_commands.add_parser(
        "genesis-ingest", help="ingest one signed species genesis"
    )
    species_genesis.add_argument("--artifact", required=True)
    species_release = species_commands.add_parser(
        "release-ingest", help="ingest one signed species release"
    )
    species_release.add_argument("--artifact", required=True)
    species_incoming = species_commands.add_parser(
        "incoming", help="read one content-bound /species.incoming page"
    )
    species_incoming.add_argument("--selected-candidate-id")
    species_incoming.add_argument("--page-index", type=int, default=0)
    species_incoming.add_argument("--expected-occupied-positions-hash")
    species_apply = species_commands.add_parser(
        "apply", help="apply one complete verified compatible snapshot"
    )
    species_apply.add_argument("--operation-id", required=True)
    species_apply.add_argument("--snapshot", required=True)
    species_rollback = species_commands.add_parser(
        "rollback", help="restore a prior applied runtime with frozen evidence"
    )
    species_rollback.add_argument("--operation-id", required=True)
    species_rollback.add_argument(
        "--reason", choices=("release-fork", "runtime-failure"), required=True
    )
    species_rollback.add_argument("--snapshot", required=True)

    source = families.add_parser(
        "source", help="DM-015 attributed ancestry and quarantined knowledge"
    )
    source_commands = source.add_subparsers(dest="command", required=True)
    content_put = source_commands.add_parser(
        "content-put", help="store exact owner-local bytes in the source CAS"
    )
    content_put.add_argument("--content", required=True)
    content_put.add_argument("--media-type", required=True)
    for name, help_text in (
        ("claim", "author one evidence-bound self claim"),
        ("assess", "author one receiver-local claim assessment"),
        ("publication-append", "append one publication or tombstone"),
        ("import-decide", "append one explicit local import decision"),
    ):
        command_parser = source_commands.add_parser(name, help=help_text)
        command_parser.add_argument("--payload", required=True)
    for name, help_text in (
        ("status", "resolve one exact source locally"),
        ("cursor-create", "author one portable observer-relative cursor"),
    ):
        command_parser = source_commands.add_parser(name, help=help_text)
        command_parser.add_argument("--selector", required=True)
    source_diff = source_commands.add_parser(
        "diff", help="serve one disclosure-authorized portable diff page"
    )
    source_diff.add_argument("--selector", required=True)
    source_diff.add_argument("--source-request-id", required=True)
    source_diff.add_argument("--requester-me-id", required=True)
    source_diff.add_argument("--requester-cursor", required=True)
    source_diff.add_argument("--max-items", type=int, default=64)
    source_diff.add_argument("--max-bytes", type=int, default=4_194_304)
    source_diff.add_argument("--continuation")
    source_incoming = source_commands.add_parser(
        "incoming", help="side-effect-free validation of one diff bundle"
    )
    source_incoming.add_argument("--bundle", required=True)
    source_pull = source_commands.add_parser(
        "pull", help="durably land one exact preview in quarantine"
    )
    source_pull.add_argument("--operation-id", required=True)
    source_pull.add_argument("--bundle", required=True)
    source_pull.add_argument("--preview", required=True)
    source_promote = source_commands.add_parser(
        "promote", help="separately promote reviewed content as external-reference"
    )
    source_promote.add_argument("--publication-id", required=True)
    source_promote.add_argument("--policy-ref", required=True)
    source_promote.add_argument("--evidence-snapshot-ref", required=True)
    source_projection = source_commands.add_parser(
        "projection", help="rebuild one attributed promotion projection"
    )
    source_projection.add_argument("--publication-id", required=True)

    memory = families.add_parser("memory", help="deterministic personal-memory policy")
    memory_commands = memory.add_subparsers(dest="command", required=True)
    evaluate = memory_commands.add_parser(
        "evaluate", help="produce one content-addressed transition plan"
    )
    evaluate.add_argument("--policy", required=True, help="closed policy JSON file")
    evaluate.add_argument(
        "--candidate", required=True, help="closed candidate JSON file"
    )
    execute = memory_commands.add_parser(
        "execute", help="commit one still-current eligible transition plan"
    )
    execute.add_argument("--policy", required=True, help="exact policy JSON file")
    execute.add_argument("--candidate", required=True, help="exact candidate JSON file")
    execute.add_argument("--plan", required=True, help="exact plan JSON file")

    curator = families.add_parser(
        "curator", help="resource-scoped curator work coordination"
    )
    curator_commands = curator.add_subparsers(dest="command", required=True)
    enqueue = curator_commands.add_parser(
        "enqueue", help="enqueue one immutable curator item"
    )
    enqueue.add_argument("--item", required=True, help="closed item JSON file")
    claim = curator_commands.add_parser(
        "claim", help="claim one item with generation compare-and-swap"
    )
    claim.add_argument("--item-id", required=True)
    claim.add_argument("--claim-id", required=True)
    claim.add_argument("--expected-generation", type=int, required=True)
    claim.add_argument("--lease-until-ms", type=int, required=True)
    claim.add_argument("--fence-evidence", help="closed Cluster fence evidence JSON")
    complete = curator_commands.add_parser(
        "complete", help="record one claim-bound terminal result"
    )
    complete.add_argument("--claim-id", required=True)
    complete.add_argument("--expected-generation", type=int, required=True)
    complete.add_argument(
        "--outcome",
        choices=("completed", "proposed", "deferred", "failed"),
        required=True,
    )
    complete.add_argument("--output-ref", action="append", default=[])
    complete.add_argument("--effect-receipt", help="closed effect receipt JSON")
    inspect = curator_commands.add_parser("inspect", help="inspect one queue item")
    inspect.add_argument("--item-id", required=True)

    review = families.add_parser(
        "review", help="purpose-limited human review of sensitive memory"
    )
    review_commands = review.add_subparsers(dest="command", required=True)
    authorize = review_commands.add_parser(
        "authorize", help="register an exact reviewer-accepted delegation"
    )
    authorize.add_argument("--authorization", required=True)
    revoke = review_commands.add_parser("revoke", help="revoke one delegation")
    revoke.add_argument("--authorization-id", required=True)
    revoke.add_argument("--reason", required=True)
    request_review = review_commands.add_parser(
        "request", help="register one exact immutable review request"
    )
    request_review.add_argument("--review-request", required=True)
    queue = review_commands.add_parser(
        "queue", help="list authorized payload-minimized review work"
    )
    queue.add_argument("--authorization-id", required=True)
    queue.add_argument("--access-proof", required=True)
    queue.add_argument("--after")
    queue.add_argument("--limit", type=int, default=25)
    inspect_review = review_commands.add_parser(
        "inspect", help="inspect exact evidence after reviewer possession proof"
    )
    inspect_review.add_argument("--review-request-id", required=True)
    inspect_review.add_argument("--authorization-id", required=True)
    inspect_review.add_argument("--access-proof", required=True)
    draft = review_commands.add_parser(
        "draft", help="prepare an unsigned, content-bound decision"
    )
    draft.add_argument("--review-request-id", required=True)
    draft.add_argument("--authorization-id", required=True)
    draft.add_argument(
        "--action", choices=("accept", "edit", "reject", "defer"), required=True
    )
    draft.add_argument("--replacement")
    draft.add_argument("--reason", choices=sorted(DECISION_REASONS), required=True)
    draft.add_argument("--note-ref")
    draft.add_argument("--decision-nonce", required=True)
    draft.add_argument("--decided-at-ms", type=int, required=True)
    draft.add_argument("--predecessor-decision-id")
    submit = review_commands.add_parser(
        "submit", help="submit a pre-existing human-signed decision"
    )
    submit.add_argument("--signed-decision", required=True)
    execute_review = review_commands.add_parser(
        "execute", help="subject-revalidate and execute a reached decision"
    )
    execute_review.add_argument("--review-request-id", required=True)

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
    if method.startswith(REVIEW_METHOD_PREFIX):
        raw = canonical_bytes(content)
        print(
            "untrusted-review-data "
            "encoding=canonical-json-utf8-hex "
            f"bytes={len(raw)} sha256={hashlib.sha256(raw).hexdigest()}"
        )
        for offset in range(0, len(raw), 32):
            print(f"{offset:08x}  {raw[offset : offset + 32].hex()}")
        return
    print(json.dumps(content, ensure_ascii=False, indent=2, sort_keys=True))


def _ensure_safe_output(method: str, *, json_output: bool, terminal: bool) -> None:
    if method.startswith(REVIEW_METHOD_PREFIX) and json_output and terminal:
        raise ClientError("review_json_tty_refused")


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        key = read_capability_key(args.capability_key_fd)
        config = ClientConfig.load(args.client_config, key)
        client = LocalClient(args.socket, config, args.timeout)
        method, params = _method_params(args)
        _ensure_safe_output(
            method,
            json_output=args.json_output,
            terminal=sys.stdout.isatty(),
        )
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
