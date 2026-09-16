"""Offline operator control plane; never exposed as an agent tool.

This CLI consumes proof from a separately provisioned human frontend. Selecting
a trust file here is operator administration, NOT human authentication. Deploy
with immutable trust configuration and an isolated store inaccessible to models.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .execution_instruction import ApprovalVerifier, ExecutionDenied, Instruction
from .execution_store import ExecutionStore


def _read(path: str) -> dict[str, Any]:
    def closed_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ExecutionDenied("duplicate JSON member")
            result[key] = value
        return result

    data = json.loads(
        Path(path).read_text(encoding="utf-8"), object_pairs_hook=closed_pairs
    )
    if not isinstance(data, dict):
        raise ExecutionDenied("JSON object required")
    return data


def main(
    argv: Sequence[str] | None = None, *, clock: Callable[[], float] = time.time
) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--store", required=True, type=Path)
    parser.add_argument(
        "--trust", required=True, help="isolated frontend public keys JSON"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("init", help="explicitly provision a fresh, empty journal")
    commands.add_parser("status")
    propose = commands.add_parser("propose")
    propose.add_argument("instruction")
    for name in ("approve", "renew"):
        command = commands.add_parser(name)
        command.add_argument("instruction")
        command.add_argument("proof")
    for name in ("cancel", "cancellation-payload"):
        command = commands.add_parser(name)
        command.add_argument("identity")
        command.add_argument("revision", type=int)
        if name == "cancel":
            command.add_argument("proof")
    args = parser.parse_args(argv)
    try:
        verifier = ApprovalVerifier(
            {
                principal: Ed25519PublicKey.from_public_bytes(bytes.fromhex(key))
                for principal, key in _read(args.trust).items()
            }
        )
        if args.command == "init":
            store = ExecutionStore.create(args.store, verifier, clock=clock)
            result: object = {"store_id": store.store_id}
        else:
            store = ExecutionStore(args.store, verifier, clock=clock)
            if args.command == "status":
                statuses = store.statuses()
                result = {
                    "store_id": store.store_id,
                    "instructions": statuses,
                    "summary": "human execution instruction present"
                    if any(s["state"] == "active" for s in statuses)
                    else "passive inbox; no agent review scheduled",
                }
            elif args.command == "cancellation-payload":
                result = store.cancellation_payload(args.identity, args.revision)
            elif args.command == "cancel":
                result = store.cancel(args.identity, args.revision, _read(args.proof))
            else:
                instruction = Instruction.from_dict(_read(args.instruction))
                if args.command == "propose":
                    store.propose(instruction)
                else:
                    if (args.command == "renew") != (instruction.revision > 1):
                        raise ExecutionDenied(
                            "use approve for revision 1; renew for successors"
                        )
                    store.approve(instruction, _read(args.proof))
                result = store.status(instruction.instruction_id, instruction.revision)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (ExecutionDenied, OSError, ValueError, TypeError, sqlite3.Error) as exc:
        print(
            json.dumps({"error": type(exc).__name__, "status": "execution denied"}),
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
