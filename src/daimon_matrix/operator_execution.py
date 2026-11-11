"""Offline operator control plane; never exposed as an agent tool.

This CLI consumes proof from a separately provisioned human frontend. Selecting
a trust file here is operator administration, NOT human authentication. Deploy
with immutable trust configuration and an isolated store inaccessible to models.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any, Literal

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .execution_instruction import ApprovalVerifier, ExecutionDenied, Instruction
from .execution_store import ExecutionStore
from .human_execution_frontend import HumanExecutionFrontend, HumanTurn
from .review_runner import CycleContext, ReviewController


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


def funding_control_payload(
    store: ExecutionStore,
    account_id: str,
    principal: str,
    expected_revision: int,
    paused: bool,
) -> dict[str, Any]:
    """Bind a human's selected state to the exact observed control revision.

    Reading an account or constructing this payload grants no authority. The
    existing journal still verifies the external signature and revision atomically.
    """
    if (
        type(expected_revision) is not int
        or expected_revision < 0
        or type(paused) is not bool
    ):
        raise ExecutionDenied("invalid funding control selection")
    current = store.funding_status(account_id)
    if (
        current["principal"] != principal
        or current["control_revision"] != expected_revision
    ):
        raise ExecutionDenied("funding control authority/revision mismatch")
    return {
        "schema": "execution/funding-control/v1",
        "store_id": store.store_id,
        "principal": principal,
        "account_id": account_id,
        "revision": expected_revision + 1,
        "paused": paused,
    }


class HumanExecutionOperator:
    """Human controls for selected stores and optional Codex/Hermes reviewers.

    Store-only bindings provide account controls without preparing an inference
    runner. Reviews and runtime cancellation still require their selected adapter.
    The host frontend retains only externally supplied authenticator/signer
    callbacks; it never accepts private-key bytes, passes neither callback into
    the execution store/controller/runner, and stores no trust root in its journal.
    """

    def __init__(
        self,
        *,
        challenge_path: Path,
        bindings: Mapping[str, tuple[ExecutionStore, ReviewController | None]],
        authenticate: Callable[[HumanTurn], bool],
        signer: Callable[[str, bytes], bytes],
        clock: Callable[[], float] = time.time,
        challenge_id: Callable[[], str],
    ) -> None:
        if not bindings or not set(bindings) <= {"codex", "hermes"}:
            raise ExecutionDenied("selected Codex/Hermes operator bindings required")
        self.bindings = dict(bindings)
        for kind, (store, controller) in self.bindings.items():
            if not isinstance(store, ExecutionStore):
                raise ExecutionDenied("existing execution store required")
            # Account controls do not start/recover an inference runner. A native
            # owner need not construct a pinned one-call reviewer just to pause.
            if controller is None:
                continue
            if kind == "codex":
                from .codex_review import CodexReviewRunner

                expected: type = CodexReviewRunner
            else:
                from .hermes_review import HermesReviewRunner

                expected = HermesReviewRunner
            if controller.store is not store or not isinstance(
                controller.runner, expected
            ):
                raise ExecutionDenied("wrong operator runner/controller boundary")
        self.frontend = HumanExecutionFrontend(
            challenge_path,
            authenticate=authenticate,
            signer=signer,
            clock=clock,
            challenge_id=challenge_id,
        )

    def _selected_binding(
        self, runner_type: Literal["codex", "hermes"]
    ) -> tuple[ExecutionStore, ReviewController | None]:
        if runner_type not in self.bindings:
            raise ExecutionDenied("unsupported runner type")
        return self.bindings[runner_type]

    def _binding(
        self,
        runner_type: Literal["codex", "hermes"],
        instruction: Instruction,
        task: str,
    ) -> tuple[ExecutionStore, ReviewController]:
        store, controller = self._selected_binding(runner_type)
        if controller is None:
            raise ExecutionDenied("review runner is not selected")
        if (
            instruction.store_id != store.store_id
            or instruction.binding != controller.runner.binding
            or hashlib.sha256(task.encode("utf-8")).hexdigest()
            != instruction.task_sha256
        ):
            raise ExecutionDenied("instruction does not bind operator runner/task")
        return store, controller

    def prepare_review_now(
        self,
        turn: HumanTurn,
        runner_type: Literal["codex", "hermes"],
        instruction: Instruction,
        task: str,
    ) -> dict[str, Any]:
        if instruction.mode != "manual":
            raise ExecutionDenied("review-now requires manual one-cycle instruction")
        store, _ = self._binding(runner_type, instruction, task)
        self.frontend.authenticate(turn)
        store.propose(instruction)
        return self.frontend.issue(
            turn,
            operation="review-now",
            runner_type=runner_type,
            payload=instruction.to_dict(),
            task=task,
        )

    def prepare_finite_periodic(
        self,
        turn: HumanTurn,
        runner_type: Literal["codex", "hermes"],
        instruction: Instruction,
        task: str,
    ) -> dict[str, Any]:
        if (
            instruction.mode != "periodic"
            or instruction.interval is None
            or instruction.end <= instruction.start
        ):
            raise ExecutionDenied("finite periodic instruction required")
        store, _ = self._binding(runner_type, instruction, task)
        self.frontend.authenticate(turn)
        store.propose(instruction)
        return self.frontend.issue(
            turn,
            operation="finite-periodic",
            runner_type=runner_type,
            payload=instruction.to_dict(),
            task=task,
        )

    def status(
        self, turn: HumanTurn, runner_type: Literal["codex", "hermes"]
    ) -> list[dict[str, Any]]:
        self.frontend.authenticate(turn)
        return self._selected_binding(runner_type)[0].statuses()

    def prepare_funding_control(
        self,
        turn: HumanTurn,
        runner_type: Literal["codex", "hermes"],
        account_id: str,
        expected_revision: int,
        *,
        paused: bool,
    ) -> dict[str, Any]:
        """Use the existing human frontend; never sign from a model tool."""
        self.frontend.authenticate(turn)
        store, _ = self._selected_binding(runner_type)
        payload = funding_control_payload(
            store, account_id, turn.principal, expected_revision, paused
        )
        return self.frontend.issue(
            turn,
            operation="funding-control",
            runner_type=runner_type,
            payload=payload,
            task=None,
        )

    def prepare_cancel(
        self,
        turn: HumanTurn,
        runner_type: Literal["codex", "hermes"],
        identity: str,
        revision: int,
    ) -> dict[str, Any]:
        self.frontend.authenticate(turn)
        store, controller = self._selected_binding(runner_type)
        if controller is None:
            raise ExecutionDenied("cancellation adapter is not selected")
        return self.frontend.issue(
            turn,
            operation="cancel",
            runner_type=runner_type,
            payload=store.cancellation_payload(identity, revision),
            task=None,
        )

    def confirm_cancel(
        self, turn: HumanTurn, challenge_id: str, displayed: Mapping[str, Any]
    ) -> dict[str, Any]:
        challenge = self.frontend.consume(turn, challenge_id, displayed)
        if challenge.operation != "cancel":
            raise ExecutionDenied("cancellation confirmation required")
        store, controller = self._selected_binding(challenge.runner_type)
        if controller is None:
            raise ExecutionDenied("cancellation adapter is not selected")
        payload = challenge.payload
        identity = str(payload["instruction_id"])
        revision = int(payload["revision"])
        instruction = store.get_instruction(identity, revision)
        cancelled = store.cancel(identity, revision, challenge.proof)
        interruption, cycles = controller.cancel_active(
            identity, revision, instruction.cleanup_seconds
        )
        return {
            "instruction_id": identity,
            "revision": revision,
            "state": str(cancelled["state"]),
            "interruption": interruption,
            "cycles": list(cycles),
        }

    def confirm(
        self, turn: HumanTurn, challenge_id: str, displayed: Mapping[str, Any]
    ) -> CycleContext | dict[str, Any]:
        challenge = self.frontend.consume(turn, challenge_id, displayed)
        if challenge.operation == "funding-control":
            store, _ = self._selected_binding(challenge.runner_type)
            store.control_funding(challenge.payload, challenge.proof)
            return {
                "control": challenge.payload,
                "account": store.funding_status(challenge.payload["account_id"]),
                "execution_started": False,
            }
        if challenge.operation not in {"review-now", "finite-periodic"}:
            raise ExecutionDenied("review confirmation required")
        if challenge.task is None:
            raise ExecutionDenied("approved task missing")
        instruction = Instruction.from_dict(challenge.payload)
        store, controller = self._binding(
            challenge.runner_type, instruction, challenge.task
        )
        store.approve(instruction, challenge.proof)
        if challenge.operation == "finite-periodic":
            return store.status(instruction.instruction_id, instruction.revision)
        context = controller.run_due_once(
            instruction.instruction_id, instruction.revision, challenge.task
        )
        if context is None:
            raise ExecutionDenied("approved review-now cycle unavailable")
        return context


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
    episode = commands.add_parser("episode-status")
    episode.add_argument("account_id")
    commands.add_parser("enable-episode-reporting")
    notice = commands.add_parser("episode-notice")
    notice.add_argument("account_id")
    report = commands.add_parser("episode-report")
    report.add_argument("account_id")
    control_payload = commands.add_parser("funding-control-payload")
    control_payload.add_argument("account_id")
    control_payload.add_argument("expected_revision", type=int)
    control_payload.add_argument("state", choices=("pause", "resume"))
    control = commands.add_parser("funding-control")
    control.add_argument("payload")
    control.add_argument("proof")
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
            if args.command == "enable-episode-reporting":
                store.enable_episode_reporting()
                result = {
                    "store_id": store.store_id,
                    "reporting_enabled": True,
                    "execution_started": False,
                }
            elif args.command == "funding-control-payload":
                account = store.funding_status(args.account_id)
                result = funding_control_payload(
                    store,
                    args.account_id,
                    account["principal"],
                    args.expected_revision,
                    args.state == "pause",
                )
            elif args.command == "funding-control":
                payload = _read(args.payload)
                store.control_funding(payload, _read(args.proof))
                result = {
                    "control": payload,
                    "account": store.funding_status(payload["account_id"]),
                    "execution_started": False,
                }
            elif args.command == "episode-report":
                result = store.episode_report(args.account_id)
            elif args.command == "episode-notice":
                result = store.episode_notice(args.account_id)
            elif args.command == "episode-status":
                result = store.episode_status(args.account_id)
            elif args.command == "status":
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
