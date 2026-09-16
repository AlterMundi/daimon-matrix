"""Owner-isolated SQLite execution journal. Never reconstructed from messages."""

from __future__ import annotations

import json
import math
import os
import secrets
import sqlite3
import time
import uuid
from collections.abc import Callable, Iterator, Mapping
from contextlib import closing, contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TypeVar, cast

from .execution_instruction import (
    ApprovalVerifier,
    ExecutionDenied,
    Instruction,
    Scope,
    canonical,
    digest,
)

T = TypeVar("T")


@dataclass(frozen=True)
class Cycle:
    cycle_id: str
    instruction_id: str
    revision: int
    slot: int
    deadline: float
    token: str = field(repr=False)


class ExecutionStore:
    def __init__(
        self,
        path: Path,
        verifier: ApprovalVerifier,
        *,
        clock: Callable[[], float] = time.time,
    ):
        self.path = Path(path)
        self.verifier = verifier
        self.clock = clock
        if not self.path.is_file():
            raise ExecutionDenied(
                "execution store missing; explicit provisioning required"
            )
        with closing(self._connect()) as db:
            if db.execute("PRAGMA user_version").fetchone()[0] != 1:
                raise ExecutionDenied("unsupported execution store")
            self.store_id = db.execute("SELECT store_id FROM metadata").fetchone()[0]

    @classmethod
    def create(
        cls,
        path: Path,
        verifier: ApprovalVerifier,
        *,
        clock: Callable[[], float] = time.time,
    ) -> ExecutionStore:
        path = Path(path)
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        with closing(sqlite3.connect(path, isolation_level=None)) as db:
            db.executescript("""
                PRAGMA user_version=1;
                CREATE TABLE metadata(store_id TEXT NOT NULL, high_water REAL NOT NULL,
                                      clock_fault INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE instructions(
                    id TEXT NOT NULL, revision INTEGER NOT NULL, payload TEXT NOT NULL,
                    proof TEXT, state TEXT NOT NULL,
                    generation INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY(id,revision));
                CREATE TABLE cycles(
                    cycle_id TEXT PRIMARY KEY, id TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    slot INTEGER NOT NULL, binding TEXT NOT NULL,
                    deadline REAL NOT NULL,
                    generation INTEGER NOT NULL, token_hash TEXT NOT NULL,
                    state TEXT NOT NULL, outcome TEXT,
                    UNIQUE(id,revision,slot));
                CREATE UNIQUE INDEX single_flight ON cycles(binding)
                    WHERE state IN ('intent','ambiguous');
                CREATE TABLE operations(
                    operation_id TEXT PRIMARY KEY, cycle_id TEXT NOT NULL,
                    kind TEXT NOT NULL, scope TEXT, state TEXT NOT NULL);
                CREATE TABLE events(event_id TEXT PRIMARY KEY, principal TEXT NOT NULL,
                                    action TEXT NOT NULL, proof TEXT NOT NULL);
            """)
            db.execute(
                "INSERT INTO metadata(store_id,high_water) VALUES (?,0)",
                (str(uuid.uuid4()),),
            )
        return cls(path, verifier, clock=clock)

    def _connect(self) -> sqlite3.Connection:
        # mode=rw is essential: a lost journal must not silently become a new journal.
        db = sqlite3.connect(
            self.path.resolve().as_uri() + "?mode=rw",
            uri=True,
            timeout=10,
            isolation_level=None,
        )
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA synchronous=FULL")
        return db

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def _now(self, db: sqlite3.Connection) -> float:
        now = self.clock()
        meta = db.execute("SELECT * FROM metadata").fetchone()
        if not math.isfinite(now) or now < meta["high_water"] or meta["clock_fault"]:
            db.execute("UPDATE metadata SET clock_fault=1")
            db.commit()  # persist the fault even though admission raises
            raise ExecutionDenied("clock rollback/untrusted clock; journal fenced")
        db.execute("UPDATE metadata SET high_water=?", (now,))
        return now

    @staticmethod
    def _row(
        db: sqlite3.Connection, identity: str, revision: int | None = None
    ) -> sqlite3.Row:
        if revision is None:
            row = db.execute(
                "SELECT * FROM instructions WHERE id=? ORDER BY revision DESC LIMIT 1",
                (identity,),
            ).fetchone()
        else:
            row = db.execute(
                "SELECT * FROM instructions WHERE id=? AND revision=?",
                (identity, revision),
            ).fetchone()
        if row is None:
            raise ExecutionDenied("unknown instruction")
        return cast(sqlite3.Row, row)

    def _instruction(self, row: sqlite3.Row) -> Instruction:
        instruction = Instruction.from_dict(json.loads(row["payload"]))
        if instruction.store_id != self.store_id:
            raise ExecutionDenied("wrong journal audience")
        if row["proof"] is not None:
            self.verifier.verify(
                "approve", instruction.to_dict(), json.loads(row["proof"])
            )
        return instruction

    def propose(self, instruction: Instruction) -> None:
        if instruction.store_id != self.store_id:
            raise ExecutionDenied("wrong journal audience")
        with self._transaction() as db:
            self._now(db)
            try:
                db.execute(
                    "INSERT INTO instructions(id,revision,payload,state) "
                    "VALUES (?,?,?,'pending')",
                    (
                        instruction.instruction_id,
                        instruction.revision,
                        canonical(instruction.to_dict()).decode(),
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ExecutionDenied("immutable revision already exists") from exc

    def _event(
        self,
        db: sqlite3.Connection,
        action: str,
        payload: dict[str, Any],
        proof: Mapping[str, Any],
    ) -> None:
        principal, event = self.verifier.verify(action, payload, proof)
        try:
            db.execute(
                "INSERT INTO events VALUES (?,?,?,?)",
                (event, principal, action, canonical(dict(proof)).decode()),
            )
        except sqlite3.IntegrityError as exc:
            raise ExecutionDenied("approval event replay") from exc

    def approve(self, instruction: Instruction, proof: Mapping[str, Any]) -> None:
        if instruction.store_id != self.store_id:
            raise ExecutionDenied("wrong journal audience")
        with self._transaction() as db:
            now = self._now(db)
            if now >= instruction.end:
                raise ExecutionDenied("expired approval")
            self._event(db, "approve", instruction.to_dict(), proof)
            rows = db.execute(
                "SELECT * FROM instructions WHERE id=? AND state!='pending' "
                "ORDER BY revision DESC",
                (instruction.instruction_id,),
            ).fetchall()
            if rows:
                previous = self._instruction(rows[0])
                if (
                    instruction.revision != previous.revision + 1
                    or instruction.predecessor != previous.sha256
                    or instruction.principal != previous.principal
                    or instruction.binding != previous.binding
                ):
                    raise ExecutionDenied(
                        "renewal must bind latest predecessor and identity"
                    )
            elif instruction.revision != 1:
                raise ExecutionDenied("missing predecessor")
            existing = db.execute(
                "SELECT * FROM instructions WHERE id=? AND revision=?",
                (instruction.instruction_id, instruction.revision),
            ).fetchone()
            payload = canonical(instruction.to_dict()).decode()
            if existing and (
                existing["state"] != "pending" or existing["payload"] != payload
            ):
                raise ExecutionDenied("immutable revision conflict")
            db.execute(
                "UPDATE instructions SET state='superseded',generation=generation+1 "
                "WHERE id=? AND state='active'",
                (instruction.instruction_id,),
            )
            db.execute(
                "INSERT OR REPLACE INTO instructions(id,revision,payload,proof,state) "
                "VALUES (?,?,?,?,'active')",
                (
                    instruction.instruction_id,
                    instruction.revision,
                    payload,
                    canonical(dict(proof)).decode(),
                ),
            )

    def cancellation_payload(self, identity: str, revision: int) -> dict[str, Any]:
        with closing(self._connect()) as db:
            instruction = self._instruction(self._row(db, identity, revision))
        return {
            "store_id": self.store_id,
            "instruction_id": identity,
            "revision": revision,
            "instruction_sha256": instruction.sha256,
            "principal": instruction.principal,
        }

    def cancel(
        self, identity: str, revision: int, proof: Mapping[str, Any]
    ) -> dict[str, Any]:
        payload = self.cancellation_payload(identity, revision)
        with self._transaction() as db:
            # Cancellation remains possible even when the wall clock is faulty.
            self._event(db, "cancel", payload, proof)
            db.execute(
                "UPDATE instructions SET state='cancelled',generation=generation+1 "
                "WHERE id=? AND revision=?",
                (identity, revision),
            )
            row = self._row(db, identity, revision)
            return {
                "instruction_id": identity,
                "revision": revision,
                "state": row["state"],
                "generation": row["generation"],
            }

    def status(self, identity: str, revision: int | None = None) -> dict[str, Any]:
        with self._transaction() as db:
            now = self._now(db)
            row = self._row(db, identity, revision)
            instruction = self._instruction(row)
            state = row["state"]
            if state == "active" and now >= instruction.end:
                state = "expired"
                db.execute(
                    "UPDATE instructions SET state='expired',generation=generation+1 "
                    "WHERE id=? AND revision=?",
                    (identity, row["revision"]),
                )
            cycles = db.execute(
                "SELECT cycle_id,slot,deadline,state,outcome FROM cycles "
                "WHERE id=? AND revision=? ORDER BY slot",
                (identity, row["revision"]),
            ).fetchall()
            inflight = [
                dict(c) for c in cycles if c["state"] in {"intent", "ambiguous"}
            ]
            next_slot = None
            session_busy = (
                db.execute(
                    "SELECT 1 FROM cycles WHERE binding=? "
                    "AND state IN ('intent','ambiguous') LIMIT 1",
                    (canonical(list(instruction.binding[2:])).decode(),),
                ).fetchone()
                is not None
            )
            if (
                state == "active"
                and not session_busy
                and len(cycles) < instruction.max_cycles
            ):
                if instruction.interval is None:
                    if not cycles:
                        next_slot = instruction.start
                else:
                    slot = max(
                        0, int((now - instruction.start) // instruction.interval)
                    )
                    if cycles:
                        slot = max(slot, cycles[-1]["slot"] + 1)
                    candidate = instruction.start + slot * instruction.interval
                    if candidate < instruction.end:
                        next_slot = candidate
            return instruction.to_dict() | {
                "state": state,
                "generation": row["generation"] + (state != row["state"]),
                "next_eligible_slot": next_slot,
                "in_flight": inflight,
                "last_outcome": dict(cycles[-1]) if cycles else None,
            }

    def statuses(self) -> list[dict[str, Any]]:
        with closing(self._connect()) as db:
            rows = db.execute(
                "SELECT id,revision FROM instructions ORDER BY id,revision"
            ).fetchall()
        return [self.status(row["id"], row["revision"]) for row in rows]

    def reserve(
        self, identity: str, revision: int, binding: tuple[str, str, str, str]
    ) -> Cycle | None:
        with self._transaction() as db:
            now = self._now(db)
            row = db.execute(
                "SELECT * FROM instructions WHERE id=? AND revision=?",
                (identity, revision),
            ).fetchone()
            if row is None or row["state"] != "active" or row["proof"] is None:
                return None
            instruction = self._instruction(row)
            if (
                instruction.binding != binding
                or not instruction.start <= now < instruction.end
            ):
                return None
            slot = (
                0
                if instruction.interval is None
                else int((now - instruction.start) // instruction.interval)
            )
            count = db.execute(
                "SELECT count(*) FROM cycles WHERE id=? AND revision=?",
                (identity, revision),
            ).fetchone()[0]
            if count >= instruction.max_cycles:
                return None
            token = secrets.token_urlsafe(32)
            cycle = Cycle(
                str(uuid.uuid4()),
                identity,
                revision,
                slot,
                min(instruction.end, now + instruction.max_cycle_seconds),
                token,
            )
            try:
                db.execute(
                    "INSERT INTO cycles VALUES (?,?,?,?,?,?,?,?,'intent',NULL)",
                    (
                        cycle.cycle_id,
                        identity,
                        revision,
                        slot,
                        canonical(list(binding[2:])).decode(),
                        cycle.deadline,
                        row["generation"],
                        digest(token),
                    ),
                )
            except sqlite3.IntegrityError:
                return None
            return cycle

    @staticmethod
    def _cycle(db: sqlite3.Connection, cycle: Cycle) -> sqlite3.Row:
        row = db.execute(
            "SELECT * FROM cycles WHERE cycle_id=?", (cycle.cycle_id,)
        ).fetchone()
        if row is None or not secrets.compare_digest(
            row["token_hash"], digest(cycle.token)
        ):
            raise ExecutionDenied("invalid cycle capability")
        if (row["id"], row["revision"], row["slot"], row["deadline"]) != (
            cycle.instruction_id,
            cycle.revision,
            cycle.slot,
            cycle.deadline,
        ):
            raise ExecutionDenied("tampered cycle context")
        return cast(sqlite3.Row, row)

    def get_instruction(self, identity: str, revision: int) -> Instruction:
        with closing(self._connect()) as db:
            return self._instruction(self._row(db, identity, revision))

    def _guard(self, db: sqlite3.Connection, cycle: Cycle) -> Instruction:
        now = self._now(db)
        cycle_row = self._cycle(db, cycle)
        row = self._row(db, cycle.instruction_id, cycle.revision)
        instruction = self._instruction(row)
        if (
            cycle_row["state"] != "intent"
            or row["state"] != "active"
            or row["proof"] is None
            or cycle_row["generation"] != row["generation"]
            or not instruction.start <= now < min(instruction.end, cycle.deadline)
        ):
            raise ExecutionDenied("cycle fenced")
        return instruction

    def check(self, cycle: Cycle) -> Instruction:
        with self._transaction() as db:
            return self._guard(db, cycle)

    def dispatch(
        self,
        cycle: Cycle,
        kind: str,
        scope: Scope | None,
        checkpoint: Callable[[], None],
        submit: Callable[[], T],
    ) -> T:
        """Trusted bounded submission only; never run a model/tool loop under the lock.

        Persist an intent BEFORE any I/O; then serialize the final admission and
        bounded transport submission with cancellation. Exceptions leave a durable
        unknown outcome, never an automatic retry. Callbacks must not reenter DB.
        """
        if kind not in {"inference", "native"}:
            raise ExecutionDenied("unsupported dispatch")
        operation_id = str(uuid.uuid4())
        with self._transaction() as db:
            instruction = self._guard(db, cycle)
            checkpoint()
            if kind == "native" and scope not in instruction.scope:
                raise ExecutionDenied("outside approved scope")
            if kind == "inference" and scope is not None:
                raise ExecutionDenied("invalid inference scope")
            count = db.execute(
                "SELECT count(*) FROM operations WHERE cycle_id=? AND kind=?",
                (cycle.cycle_id, kind),
            ).fetchone()[0]
            limit = 1 if kind == "inference" else instruction.max_effects
            if count >= limit:
                raise ExecutionDenied("cycle resource budget exhausted")
            db.execute(
                "INSERT INTO operations VALUES (?,?,?,?,'intent')",
                (
                    operation_id,
                    cycle.cycle_id,
                    kind,
                    canonical(scope.__dict__).decode() if scope else None,
                ),
            )
        try:
            with self._transaction() as db:
                self._guard(db, cycle)
                checkpoint()
                result = submit()
                db.execute(
                    "UPDATE operations SET state='returned' WHERE operation_id=?",
                    (operation_id,),
                )
            return result
        except BaseException:
            self.mark_ambiguous(cycle)
            raise

    def mark_ambiguous(self, cycle: Cycle) -> None:
        with self._transaction() as db:
            row = self._cycle(db, cycle)
            if row["state"] == "intent":
                db.execute(
                    "UPDATE cycles SET state='ambiguous' WHERE cycle_id=?",
                    (cycle.cycle_id,),
                )

    def finish(self, cycle: Cycle, outcome: str) -> None:
        """Trusted adapter reconciliation, NOT a model tool or a timeout reclaimer.

        Caller must prove the exact runtime turn stopped/completed, including
        all admitted effects. Without that evidence use mark_ambiguous instead.
        """
        if outcome not in {"completed", "stopped"}:
            raise ExecutionDenied("unsupported terminal outcome")
        with self._transaction() as db:
            row = self._cycle(db, cycle)
            if row["state"] not in {"intent", "ambiguous"}:
                raise ExecutionDenied("cycle already terminal")
            db.execute(
                "UPDATE cycles SET state=?,outcome=? WHERE cycle_id=?",
                (outcome, outcome, cycle.cycle_id),
            )
            instruction = self._instruction(self._row(db, row["id"], row["revision"]))
            count = db.execute(
                "SELECT count(*) FROM cycles WHERE id=? AND revision=?",
                (row["id"], row["revision"]),
            ).fetchone()[0]
            if count >= instruction.max_cycles:
                db.execute(
                    "UPDATE instructions SET state='completed' "
                    "WHERE id=? AND revision=? AND state='active'",
                    (row["id"], row["revision"]),
                )

    def cycle_status(self, cycle_id: str) -> dict[str, Any]:
        with closing(self._connect()) as db:
            row = db.execute(
                "SELECT cycle_id,id,revision,slot,deadline,state,outcome "
                "FROM cycles WHERE cycle_id=?",
                (cycle_id,),
            ).fetchone()
            if row is None:
                raise ExecutionDenied("unknown cycle")
            operations = db.execute(
                "SELECT operation_id,kind,scope,state FROM operations WHERE cycle_id=?",
                (cycle_id,),
            ).fetchall()
            return dict(row) | {"operations": [dict(op) for op in operations]}
