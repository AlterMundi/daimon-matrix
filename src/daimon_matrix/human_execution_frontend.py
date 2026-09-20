"""Direct-human challenge ceremonies outside model-accessible execution state.

The caller supplies a direct-human authenticator and an external signing callback.
This module stores neither private signing material nor public trust roots. Its
SQLite journal contains only immutable public payloads, displays and challenge
state, and must be owner-isolated from every model/runtime profile.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import stat
import time
from collections.abc import Callable, Mapping
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from .execution_instruction import ExecutionDenied, canonical, digest


@dataclass(frozen=True)
class HumanTurn:
    """Host-authentication input; origin metadata is not itself authentication."""

    principal: str
    turn_id: str
    origin: str
    authentication: str


@dataclass(frozen=True)
class ConsumedChallenge:
    operation: Literal["review-now", "finite-periodic", "cancel"]
    runner_type: Literal["codex", "hermes"]
    payload: dict[str, Any]
    task: str | None
    proof: dict[str, Any]


class HumanExecutionFrontend:
    """Single-use immutable displays backed by an owner-only challenge journal."""

    def __init__(
        self,
        path: Path,
        *,
        authenticate: Callable[[HumanTurn], bool],
        signer: Callable[[str, bytes], bytes],
        clock: Callable[[], float] = time.time,
        challenge_id: Callable[[], str],
        ttl_seconds: int = 120,
    ) -> None:
        if type(ttl_seconds) is not int or not 1 <= ttl_seconds <= 300:
            raise ExecutionDenied("invalid challenge lifetime")
        self.path = Path(path)
        self._authenticate = authenticate
        self._signer = signer
        self._clock = clock
        self._challenge_id = challenge_id
        self._ttl = ttl_seconds
        if self.path.exists():
            self._validate_state()
        else:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(fd)
            with closing(self._connect()) as database:
                database.executescript(
                    "CREATE TABLE challenges("
                    "challenge_id TEXT PRIMARY KEY, operation TEXT NOT NULL, "
                    "runner_type TEXT NOT NULL, principal TEXT NOT NULL, "
                    "created REAL NOT NULL, expires REAL NOT NULL, "
                    "display TEXT NOT NULL, used INTEGER NOT NULL DEFAULT 0);"
                    "CREATE TABLE turns(turn_id TEXT PRIMARY KEY, "
                    "principal TEXT NOT NULL);"
                )

    def _validate_state(self) -> None:
        info = self.path.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_mode & 0o077
            or info.st_nlink != 1
        ):
            raise ExecutionDenied("unsafe challenge journal")

    def _connect(self) -> sqlite3.Connection:
        self._validate_state()
        database = sqlite3.connect(
            self.path.absolute().as_uri() + "?mode=rw", uri=True, isolation_level=None
        )
        database.row_factory = sqlite3.Row
        database.execute("PRAGMA synchronous=FULL")
        return database

    def authenticate(self, turn: HumanTurn) -> None:
        if (
            type(turn) is not HumanTurn
            or turn.origin != "direct-human"
            or not re.fullmatch(r"[A-Za-z0-9:._/-]{1,200}", turn.principal)
            or not re.fullmatch(r"[A-Za-z0-9:._/-]{1,200}", turn.turn_id)
            or self._authenticate(turn) is not True
        ):
            raise ExecutionDenied("direct human authentication required")

    def issue(
        self,
        turn: HumanTurn,
        *,
        operation: Literal["review-now", "finite-periodic", "cancel"],
        runner_type: Literal["codex", "hermes"],
        payload: Mapping[str, Any],
        task: str | None,
    ) -> dict[str, Any]:
        self.authenticate(turn)
        if operation not in {"review-now", "finite-periodic", "cancel"}:
            raise ExecutionDenied("unsupported human operation")
        if runner_type not in {"codex", "hermes"}:
            raise ExecutionDenied("unsupported runner type")
        challenge_id = self._challenge_id()
        if not re.fullmatch(r"[A-Za-z0-9:._/-]{1,200}", challenge_id):
            raise ExecutionDenied("invalid challenge identifier")
        now = self._clock()
        display = {
            "challenge_id": challenge_id,
            "operation": operation,
            "runner_type": runner_type,
            "principal": turn.principal,
            "created": now,
            "expires": now + self._ttl,
            "payload": dict(payload),
            "task": task,
        }
        encoded = canonical(display).decode("ascii")
        with closing(self._connect()) as database:
            database.execute("BEGIN IMMEDIATE")
            try:
                database.execute(
                    "INSERT INTO turns VALUES (?,?)", (turn.turn_id, turn.principal)
                )
                database.execute(
                    "INSERT INTO challenges VALUES (?,?,?,?,?,?,?,0)",
                    (
                        challenge_id,
                        operation,
                        runner_type,
                        turn.principal,
                        now,
                        now + self._ttl,
                        encoded,
                    ),
                )
                database.commit()
            except sqlite3.IntegrityError as error:
                database.rollback()
                raise ExecutionDenied("human turn or challenge replay") from error
        return display

    def consume(
        self, turn: HumanTurn, challenge_id: str, displayed: Mapping[str, Any]
    ) -> ConsumedChallenge:
        self.authenticate(turn)
        with closing(self._connect()) as database:
            database.execute("BEGIN IMMEDIATE")
            row = database.execute(
                "SELECT * FROM challenges WHERE challenge_id=?", (challenge_id,)
            ).fetchone()
            if row is None:
                database.rollback()
                raise ExecutionDenied("unknown challenge")
            if row["used"]:
                database.rollback()
                raise ExecutionDenied("challenge replay")
            if self._clock() >= row["expires"]:
                database.execute(
                    "UPDATE challenges SET used=1 WHERE challenge_id=?", (challenge_id,)
                )
                database.commit()
                raise ExecutionDenied("stale challenge")
            encoded = canonical(dict(displayed)).decode("ascii")
            if turn.principal != row["principal"] or encoded != row["display"]:
                database.rollback()
                raise ExecutionDenied("challenge display changed")
            database.execute(
                "UPDATE challenges SET used=1 WHERE challenge_id=? AND used=0",
                (challenge_id,),
            )
            database.commit()
        stored = json.loads(row["display"])
        payload = stored["payload"]
        purpose = "cancel" if row["operation"] == "cancel" else "approve"
        proof_body = {
            "purpose": "execution/v1/" + purpose,
            "event_id": challenge_id,
            "principal": row["principal"],
            "payload_sha256": digest(payload),
        }
        signature = self._signer(row["principal"], canonical(proof_body))
        if not isinstance(signature, bytes) or len(signature) != 64:
            raise ExecutionDenied("external signer rejected challenge")
        return ConsumedChallenge(
            operation=row["operation"],
            runner_type=row["runner_type"],
            payload=payload,
            task=stored["task"],
            proof=proof_body | {"signature": signature.hex()},
        )
