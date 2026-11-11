"""Owner-isolated SQLite execution journal. Never reconstructed from messages."""

from __future__ import annotations

import json
import math
import os
import secrets
import sqlite3
import threading
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
    coordination_metadata,
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
        usage_verifier: ApprovalVerifier | None = None,
    ):
        self.path = Path(path)
        self.verifier = verifier
        self.clock = clock
        self.usage_verifier = usage_verifier
        self._local = threading.local()
        if not self.path.is_file():
            raise ExecutionDenied(
                "execution store missing; explicit provisioning required"
            )
        with closing(self._connect()) as db:
            if db.execute("PRAGMA user_version").fetchone()[0] not in {1, 2, 3, 4, 5}:
                raise ExecutionDenied("unsupported execution store")
            self.store_id = db.execute("SELECT store_id FROM metadata").fetchone()[0]

    @classmethod
    def create(
        cls,
        path: Path,
        verifier: ApprovalVerifier,
        *,
        clock: Callable[[], float] = time.time,
        usage_verifier: ApprovalVerifier | None = None,
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
        return cls(path, verifier, clock=clock, usage_verifier=usage_verifier)

    def _connect(self, *, timeout: float = 10.0) -> sqlite3.Connection:
        # mode=rw is essential: a lost journal must not silently become a new journal.
        db = sqlite3.connect(
            self.path.resolve().as_uri() + "?mode=rw",
            uri=True,
            timeout=timeout,
            isolation_level=None,
        )
        try:
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA synchronous=FULL")
            return db
        except BaseException:
            db.close()
            raise

    @contextmanager
    def _transaction(self, *, timeout: float = 10.0) -> Iterator[sqlite3.Connection]:
        if getattr(self._local, "db", None) is not None:
            raise ExecutionDenied("submission callbacks must not reenter journal")
        db = self._connect(timeout=timeout)
        try:
            db.execute("BEGIN IMMEDIATE")
            db.execute("SAVEPOINT authority")
            self._local.db = db
            try:
                yield db
            except BaseException:
                # Clock observations survive rejected admissions, but NO proposed
                # instruction/event/operation mutation is committed on failure.
                observed = db.execute(
                    "SELECT high_water,clock_fault FROM metadata"
                ).fetchone()
                db.execute("ROLLBACK TO authority")
                if observed is not None:
                    db.execute(
                        "UPDATE metadata SET high_water=max(high_water,?), "
                        "clock_fault=max(clock_fault,?)",
                        tuple(observed),
                    )
                db.commit()
                raise
            db.execute("RELEASE authority")
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            self._local.db = None
            db.close()

    @staticmethod
    def _cancellation_timeout(remaining: float) -> float:
        if not math.isfinite(remaining) or remaining <= 0:
            raise ExecutionDenied("cleanup deadline reached")
        # Cancellation must never queue behind an unrelated SQLite writer. The
        # controller may still spend the shared deadline interrupting known work.
        return 0.0

    def observe_clock(self) -> float:
        """Persist every observation, including bounded checkpoints under dispatch.

        This is the sole deliberately reentrant operation; it never authorizes
        work. It joins the active transaction/savepoint without another lock.
        """
        active = getattr(self._local, "db", None)
        if active is not None:
            return self._now(active)
        with self._transaction() as db:
            return self._now(db)

    def _now(self, db: sqlite3.Connection) -> float:
        now = self.clock()
        meta = db.execute("SELECT * FROM metadata").fetchone()
        if not math.isfinite(now) or now < meta["high_water"] or meta["clock_fault"]:
            db.execute("UPDATE metadata SET clock_fault=1")
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

    def cancellation_status(
        self, identity: str, revision: int, remaining: float
    ) -> dict[str, Any]:
        """Read exact cancellation evidence without waiting for a SQLite writer."""
        timeout = self._cancellation_timeout(remaining)
        with closing(self._connect(timeout=timeout)) as db:
            row = self._row(db, identity, revision)
            self._instruction(row)
            cycles = db.execute(
                "SELECT cycle_id,slot,deadline,state,outcome FROM cycles "
                "WHERE id=? AND revision=? "
                "AND state IN ('intent','ambiguous') ORDER BY slot",
                (identity, revision),
            ).fetchall()
            return {
                "state": row["state"],
                "in_flight": [dict(c) for c in cycles],
            }

    def reserve(
        self,
        identity: str,
        revision: int,
        binding: tuple[str, str, str, str],
        *,
        work_id: str | None = None,
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
            if work_id is not None:
                work = self._work(db, work_id)
                if work["state"] != "queued":
                    return None
                if work["instruction_sha256"] != instruction.sha256:
                    raise ExecutionDenied("queued instruction mismatch")
                self._funding(db, instruction, required=True)
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
            if work_id is not None:
                db.execute(
                    "UPDATE coordination_work SET state='intent',cycle_id=? "
                    "WHERE work_id=?",
                    (cycle.cycle_id, work_id),
                )
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

    @staticmethod
    def _native_owner_allowance(
        db: sqlite3.Connection, cycle: Cycle
    ) -> dict[str, Any] | None:
        row = db.execute(
            "SELECT scope FROM operations WHERE cycle_id=? AND kind='native_owner'",
            (cycle.cycle_id,),
        ).fetchone()
        return json.loads(row["scope"]) if row is not None else None

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
        allowance = self._native_owner_allowance(db, cycle)
        if allowance is not None and now * 1000 >= allowance["deadlineUnixMs"]:
            raise ExecutionDenied("native owner deadline reached")
        self._funding(db, instruction)
        return instruction

    def check(self, cycle: Cycle) -> Instruction:
        with self._transaction() as db:
            return self._guard(db, cycle)

    def cancellation_check(
        self,
        cycle: Cycle,
        remaining: float,
        checkpoint: Callable[[], None],
    ) -> Instruction:
        """Recheck an owned cycle without queuing behind another writer."""
        timeout = self._cancellation_timeout(remaining)
        with self._transaction(timeout=timeout) as db:
            instruction = self._guard(db, cycle)
            checkpoint()
            return instruction

    def dispatch(
        self,
        cycle: Cycle,
        kind: str,
        scope: Scope | None,
        checkpoint: Callable[[], None],
        submit: Callable[[], T],
        *,
        exposure: Mapping[str, Any] | None = None,
    ) -> T:
        """Trusted bounded submission only; never run a model/tool loop under the lock.

        Persist an intent BEFORE any I/O; then serialize the final admission and
        bounded transport submission with cancellation. Exceptions leave a durable
        unknown outcome, never an automatic retry. Callbacks must not reenter DB.
        """
        if kind not in {"inference", "provider", "native"}:
            raise ExecutionDenied("unsupported dispatch")
        return self._dispatch(cycle, kind, scope, checkpoint, submit, exposure=exposure)

    def dispatch_provider_attempt(
        self,
        cycle: Cycle,
        operation_id: str,
        checkpoint: Callable[[], None],
        submit: Callable[[], T],
        *,
        exposure: Mapping[str, Any],
    ) -> T:
        """One physical send in an explicitly funded multi-attempt native cycle.

        The trusted adapter retains this attempt UUID before crossing the provider
        boundary. Reusing it NEVER calls submit again, even after a known return.
        Like dispatch, submit only enqueues bounded transport bytes: it must not
        run a model/tool loop or reenter the journal. This installs no native hook.
        """
        if not isinstance(operation_id, str):
            raise ExecutionDenied("canonical provider attempt UUID required")
        try:
            if str(uuid.UUID(operation_id)) != operation_id:
                raise ValueError("noncanonical attempt")
        except ValueError as exc:
            raise ExecutionDenied("canonical provider attempt UUID required") from exc
        return self._dispatch(
            cycle,
            "provider_attempt",
            None,
            checkpoint,
            submit,
            exposure=exposure,
            operation_id=operation_id,
        )

    def _dispatch(
        self,
        cycle: Cycle,
        kind: str,
        scope: Scope | None,
        checkpoint: Callable[[], None],
        submit: Callable[[], T],
        *,
        exposure: Mapping[str, Any] | None,
        operation_id: str | None = None,
    ) -> T:
        if kind not in {"inference", "provider", "provider_attempt", "native"}:
            raise ExecutionDenied("unsupported dispatch")
        operation_id = operation_id or str(uuid.uuid4())
        with self._transaction() as db:
            instruction = self._guard(db, cycle)
            checkpoint()
            if kind == "native" and scope not in instruction.scope:
                raise ExecutionDenied("outside approved scope")
            if (
                kind in {"inference", "provider", "provider_attempt"}
                and scope is not None
            ):
                raise ExecutionDenied("invalid inference scope")
            funding = self._funding(db, instruction)
            multi = (
                funding is not None
                and funding["schema"] == "execution/instruction-funding/v2"
            )
            if kind == "provider_attempt" and not multi:
                raise ExecutionDenied("explicit multi-attempt funding required")
            if kind == "provider" and multi:
                raise ExecutionDenied(
                    "multi-attempt funding requires exact attempt admission"
                )
            if (
                db.execute(
                    "SELECT 1 FROM operations WHERE operation_id=?", (operation_id,)
                ).fetchone()
                is not None
            ):
                raise ExecutionDenied(
                    "provider attempt already recorded; inspect original"
                )
            count = db.execute(
                "SELECT count(*) FROM operations WHERE cycle_id=? AND kind=?",
                (cycle.cycle_id, kind),
            ).fetchone()[0]
            limit = (
                funding["max_provider_attempts"]
                if kind == "provider_attempt" and funding is not None
                else 1
                if kind in {"inference", "provider"}
                else instruction.max_effects
            )
            allowance = self._native_owner_allowance(db, cycle)
            if kind == "provider_attempt" and allowance is not None:
                limit = min(limit, allowance["maxProviderAttempts"])
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
            if kind in {"provider", "provider_attempt"}:
                self._reserve_charge(db, cycle, instruction, operation_id, exposure)
        try:
            with self._transaction() as db:
                instruction = self._guard(db, cycle)
                if kind in {"provider", "provider_attempt"}:
                    funding = self._funding(db, instruction)
                    # This exact prepared attempt is the one uncertainty this
                    # owned submission may cross. Other retained intents fence
                    # new work, including after a process dies before this point.
                    if funding is not None and any(
                        self._balance(db, aid)["uncertain"]
                        > (1 if kind == "provider_attempt" else 0)
                        for aid in funding["accounts"]
                    ):
                        raise ExecutionDenied("shared funding became uncertain")
                checkpoint()
                # Source/pricing reads may consume the selected parent horizon.
                self._guard(db, cycle)
                result = submit()
                db.execute(
                    "UPDATE operations SET state='returned' WHERE operation_id=?",
                    (operation_id,),
                )
            return result
        except BaseException:
            self.mark_ambiguous(cycle)
            raise

    def enable_funding(self) -> None:
        """Explicit schema1 -> 2 additive migration; never a new budget journal.

        Existing instructions/cycles/proofs remain byte-identical. This enables
        deterministic storage only, not a runner, signing key or arrival hook.
        """
        statements = (
            "CREATE TABLE funding_accounts(account_id TEXT PRIMARY KEY, "
            "payload TEXT NOT NULL, proof TEXT NOT NULL, paused INTEGER NOT NULL "
            "DEFAULT 0, control_revision INTEGER NOT NULL DEFAULT 0)",
            "CREATE TABLE instruction_funding(instruction_sha256 TEXT PRIMARY KEY, "
            "payload TEXT NOT NULL, proof TEXT NOT NULL)",
            "CREATE TABLE funding_members(instruction_sha256 TEXT NOT NULL, "
            "account_id TEXT NOT NULL, PRIMARY KEY(instruction_sha256,account_id))",
            "CREATE INDEX funding_members_account ON funding_members(account_id)",
            "CREATE TABLE call_charges(cycle_id TEXT PRIMARY KEY, "
            "operation_id TEXT NOT NULL UNIQUE, instruction_sha256 TEXT NOT NULL, "
            "maximum INTEGER NOT NULL, actual INTEGER, receipt TEXT)",
            "CREATE INDEX call_charges_instruction ON call_charges(instruction_sha256)",
        )
        with self._transaction() as db:
            version = db.execute("PRAGMA user_version").fetchone()[0]
            if version in {2, 3, 4, 5}:
                return
            if version != 1:
                raise ExecutionDenied("unsupported funding migration")
            for statement in statements:
                db.execute(statement)
            db.execute("PRAGMA user_version=2")

    @staticmethod
    def _funding_schema(db: sqlite3.Connection) -> bool:
        return bool(db.execute("PRAGMA user_version").fetchone()[0] in {2, 3, 4, 5})

    @staticmethod
    def _positive(value: object, *, zero: bool = False) -> bool:
        return type(value) is int and (0 if zero else 1) <= value <= 2**53 - 1

    def grant_budget(
        self, payload: Mapping[str, Any], proof: Mapping[str, Any]
    ) -> None:
        """An isolated funding authority creates one immutable finite account.

        Charge units are explicit integers, never guessed prices or floating
        currency. A real adapter still needs an enforceable upper charge bound.
        """
        if set(payload) != {
            "schema",
            "store_id",
            "principal",
            "account_id",
            "kind",
            "subject",
            "start",
            "end",
            "unit",
            "max_calls",
            "max_charge",
            "max_active",
            "max_bindings",
        } or (
            payload["schema"] != "execution/funding-account/v1"
            or payload["store_id"] != self.store_id
            or payload["kind"] not in ("tribe", "being", "episode")
            or not all(
                isinstance(payload[k], str) and 0 < len(payload[k]) <= 200
                for k in ("principal", "account_id", "subject", "unit")
            )
            or not all(
                self._positive(payload[k])
                for k in ("start", "end", "max_calls", "max_active", "max_bindings")
            )
            or not self._positive(payload["max_charge"], zero=True)
            or payload["start"] >= payload["end"]
        ):
            raise ExecutionDenied("invalid funding account")
        with self._transaction() as db:
            if not self._funding_schema(db):
                raise ExecutionDenied("explicit funding migration required")
            if self._now(db) >= payload["end"]:
                raise ExecutionDenied("expired funding")
            self._event(db, "approve", dict(payload), proof)
            try:
                db.execute(
                    "INSERT INTO funding_accounts(account_id,payload,proof) "
                    "VALUES (?,?,?)",
                    (
                        payload["account_id"],
                        canonical(dict(payload)).decode(),
                        canonical(dict(proof)).decode(),
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ExecutionDenied("immutable funding account exists") from exc

    def _account(
        self, db: sqlite3.Connection, account_id: str
    ) -> tuple[dict[str, Any], sqlite3.Row]:
        if not isinstance(account_id, str) or not 0 < len(account_id) <= 200:
            raise ExecutionDenied("invalid funding account identity")
        row = db.execute(
            "SELECT * FROM funding_accounts WHERE account_id=?", (account_id,)
        ).fetchone()
        if row is None:
            raise ExecutionDenied("unknown funding account")
        payload = json.loads(row["payload"])
        self.verifier.verify("approve", payload, json.loads(row["proof"]))
        if payload["store_id"] != self.store_id or payload["account_id"] != account_id:
            raise ExecutionDenied("wrong funding audience")
        return payload, row

    def fund_instruction(
        self,
        instruction: Instruction,
        payload: Mapping[str, Any],
        proof: Mapping[str, Any],
    ) -> None:
        """Bind an exact approved instruction to the same three conserved ceilings.

        A renewed session/instruction does not renew these balances. Additional
        descendants require explicit signed bindings and consume shared accounts.
        """
        multi = payload.get("schema") == "execution/instruction-funding/v2"
        expected = {
            "schema",
            "store_id",
            "principal",
            "instruction_sha256",
            "accounts",
            "route",
            "max_charge",
        } | ({"max_provider_attempts"} if multi else set())
        if set(payload) != expected or (
            payload["schema"]
            not in {
                "execution/instruction-funding/v1",
                "execution/instruction-funding/v2",
            }
            or (multi and not self._positive(payload["max_provider_attempts"]))
            or payload["store_id"] != self.store_id
            or payload["principal"] != instruction.principal
            or payload["instruction_sha256"] != instruction.sha256
            or not isinstance(payload["accounts"], list)
            or len(payload["accounts"]) != 3
            or not all(isinstance(v, str) for v in payload["accounts"])
            or len(set(payload["accounts"])) != 3
            or not isinstance(payload["route"], str)
            or not 0 < len(payload["route"]) <= 200
            or not self._positive(payload["max_charge"], zero=True)
        ):
            raise ExecutionDenied("invalid instruction funding")
        with self._transaction() as db:
            if not self._funding_schema(db):
                raise ExecutionDenied("explicit funding migration required")
            if multi and db.execute("PRAGMA user_version").fetchone()[0] != 5:
                raise ExecutionDenied("explicit provider-attempt migration required")
            now = self._now(db)
            row = self._row(db, instruction.instruction_id, instruction.revision)
            if row["state"] != "active" or self._instruction(row) != instruction:
                raise ExecutionDenied("funding needs the exact active instruction")
            accounts = [self._account(db, aid) for aid in payload["accounts"]]
            if {p["kind"] for p, _ in accounts} != {"tribe", "being", "episode"}:
                raise ExecutionDenied("three distinct funding ceilings required")
            if len({p["unit"] for p, _ in accounts}) != 1:
                raise ExecutionDenied("funding charge units differ")
            for account, state in accounts:
                if (
                    account["principal"] != instruction.principal
                    or state["paused"]
                    or not account["start"] <= now < account["end"]
                    or not account["start"]
                    <= instruction.start
                    < instruction.end
                    <= account["end"]
                    or (
                        account["kind"] == "being"
                        and account["subject"] != instruction.being
                    )
                    or payload["max_charge"] > account["max_charge"]
                ):
                    raise ExecutionDenied("funding scope/window mismatch")
                count = db.execute(
                    "SELECT count(*) FROM funding_members WHERE account_id=?",
                    (account["account_id"],),
                ).fetchone()[0]
                if count >= account["max_bindings"]:
                    raise ExecutionDenied("funding fanout exhausted")
            self._event(db, "approve", dict(payload), proof)
            try:
                db.execute(
                    "INSERT INTO instruction_funding VALUES (?,?,?)",
                    (
                        instruction.sha256,
                        canonical(dict(payload)).decode(),
                        canonical(dict(proof)).decode(),
                    ),
                )
                db.executemany(
                    "INSERT INTO funding_members VALUES (?,?)",
                    [(instruction.sha256, aid) for aid in payload["accounts"]],
                )
            except sqlite3.IntegrityError as exc:
                raise ExecutionDenied("instruction already funded") from exc

    def _funding(
        self,
        db: sqlite3.Connection,
        instruction: Instruction,
        *,
        required: bool = False,
    ) -> dict[str, Any] | None:
        row = None
        if self._funding_schema(db):
            row = db.execute(
                "SELECT * FROM instruction_funding WHERE instruction_sha256=?",
                (instruction.sha256,),
            ).fetchone()
        if row is None:
            if required:
                raise ExecutionDenied(
                    "coordination requires explicit conserved funding"
                )
            return None
        payload = json.loads(row["payload"])
        self.verifier.verify("approve", payload, json.loads(row["proof"]))
        if (
            payload["store_id"] != self.store_id
            or payload["instruction_sha256"] != instruction.sha256
        ):
            raise ExecutionDenied("funding binding mismatch")
        now = self._now(db)
        for aid in payload["accounts"]:
            account, state = self._account(db, aid)
            if state["paused"] or not account["start"] <= now < account["end"]:
                raise ExecutionDenied("funding paused or expired")
        return cast(dict[str, Any], payload)

    def check_funding(self, instruction: Instruction) -> None:
        with self._transaction() as db:
            self._funding(db, instruction, required=True)

    def _reserve_charge(
        self,
        db: sqlite3.Connection,
        cycle: Cycle,
        instruction: Instruction,
        operation_id: str,
        exposure: Mapping[str, Any] | None,
    ) -> None:
        funding = self._funding(db, instruction)
        if funding is None:
            if exposure is not None:
                raise ExecutionDenied("exposure supplied without funding")
            return  # legacy explicit human review, never a coordination runner
        expected = {
            "route": funding["route"],
            "max_charge": funding["max_charge"],
            "provider": instruction.provider,
            "model": instruction.model,
            "max_input_tokens": instruction.max_input_tokens,
            "max_output_tokens": instruction.max_output_tokens,
        }
        if exposure is not None and "unit" in exposure:
            # Existing synthetic host-boundary callers use the original shape.
            # Real cost-bound adapters always bind their signed pricing unit.
            account, _ = self._account(db, funding["accounts"][0])
            expected["unit"] = account["unit"]
        if (
            exposure is None
            or dict(exposure) != expected
            or any(
                type(exposure.get(k)) is not int
                for k in ("max_charge", "max_input_tokens", "max_output_tokens")
            )
        ):
            raise ExecutionDenied("qualified adapter exposure required")
        for aid in funding["accounts"]:
            account, _ = self._account(db, aid)
            balance = self._balance(db, aid)
            if (
                balance["uncertain"]
                or balance["calls"] >= account["max_calls"]
                or balance["active"] >= account["max_active"]
                or balance["charged"] + funding["max_charge"] > account["max_charge"]
            ):
                raise ExecutionDenied("funding exhausted, busy or uncertain")
        db.execute(
            "INSERT INTO call_charges(cycle_id,operation_id,"
            "instruction_sha256,maximum) "
            "VALUES (?,?,?,?)",
            (cycle.cycle_id, operation_id, instruction.sha256, funding["max_charge"]),
        )

    @staticmethod
    def _balance(db: sqlite3.Connection, account_id: str) -> dict[str, int]:
        # Aggregate in SQLite; do not load complete paid-call history per admission.
        row = db.execute(
            "SELECT count(*) AS calls, "
            "coalesce(sum(coalesce(c.actual,0)),0) AS spent, "
            "coalesce(sum(CASE WHEN c.actual IS NULL THEN c.maximum ELSE 0 END),0) "
            "AS reserved, "
            "coalesce(sum(CASE WHEN o.kind='provider_attempt' "
            "THEN c.actual IS NULL OR o.state='intent' "
            "ELSE c.actual IS NULL OR y.state IN ('intent','ambiguous') END),0) "
            "AS active, "
            "coalesce(sum(o.operation_id IS NULL OR y.state='ambiguous' OR "
            "(o.kind='provider_attempt' AND o.state='intent') OR "
            "(c.actual IS NULL AND y.state!='intent')),0) AS uncertain "
            "FROM call_charges c JOIN funding_members m USING(instruction_sha256) "
            "JOIN cycles y USING(cycle_id) "
            "LEFT JOIN operations o ON o.operation_id=c.operation_id "
            "WHERE m.account_id=?",
            (account_id,),
        ).fetchone()
        result = {key: int(value) for key, value in dict(row).items()}
        result["charged"] = result["spent"] + result["reserved"]
        return result

    def funding_status(self, account_id: str) -> dict[str, Any]:
        with self._transaction() as db:
            if not self._funding_schema(db):
                raise ExecutionDenied("funding unavailable")
            account, row = self._account(db, account_id)
            balance = self._balance(db, account_id)
            return (
                account
                | balance
                | {
                    "paused": bool(row["paused"]),
                    "control_revision": row["control_revision"],
                    "available_calls": account["max_calls"] - balance["calls"],
                    "available_charge": account["max_charge"] - balance["charged"],
                }
            )

    def control_funding(
        self, payload: Mapping[str, Any], proof: Mapping[str, Any]
    ) -> None:
        """Signed monotonic pause/resume; restart and older controls never resume."""
        if set(payload) != {
            "schema",
            "store_id",
            "principal",
            "account_id",
            "revision",
            "paused",
        } or (
            payload["schema"] != "execution/funding-control/v1"
            or payload["store_id"] != self.store_id
            or not self._positive(payload["revision"])
            or type(payload["paused"]) is not bool
        ):
            raise ExecutionDenied("invalid funding control")
        with self._transaction() as db:
            if not self._funding_schema(db):
                raise ExecutionDenied("funding unavailable")
            account, row = self._account(db, payload["account_id"])
            if (
                payload["principal"] != account["principal"]
                or payload["revision"] != row["control_revision"] + 1
            ):
                raise ExecutionDenied("funding control authority/revision mismatch")
            self._event(db, "approve", dict(payload), proof)
            db.execute(
                "UPDATE funding_accounts SET paused=?,control_revision=? "
                "WHERE account_id=?",
                (payload["paused"], payload["revision"], payload["account_id"]),
            )

    def settle_charge(
        self, cycle: Cycle, payload: Mapping[str, Any], proof: Mapping[str, Any]
    ) -> None:
        """Trusted authenticated usage only; unavailable usage keeps full exposure.

        The store's usage verifier is operator-owned provider/accounting trust.
        Settlement does not imply delivery, completion or cancellation.
        """
        if set(payload) != {
            "schema",
            "store_id",
            "principal",
            "cycle_id",
            "operation_id",
            "actual",
        } or (
            payload["schema"] != "execution/usage/v1"
            or payload["store_id"] != self.store_id
            or payload["cycle_id"] != cycle.cycle_id
            or not self._positive(payload["actual"], zero=True)
        ):
            raise ExecutionDenied("invalid usage receipt")
        if self.usage_verifier is None:
            raise ExecutionDenied("no authenticated usage authority configured")
        self.usage_verifier.verify("approve", payload, proof)
        with self._transaction() as db:
            self._cycle(db, cycle)
            if not self._funding_schema(db):
                raise ExecutionDenied("funding unavailable")
            row = db.execute(
                "SELECT * FROM call_charges WHERE cycle_id=? AND operation_id=?",
                (cycle.cycle_id, payload["operation_id"]),
            ).fetchone()
            if (
                row is None
                or payload["operation_id"] != row["operation_id"]
                or payload["actual"] > row["maximum"]
            ):
                raise ExecutionDenied("usage exceeds or mismatches reservation")
            receipt = canonical(
                {"payload": dict(payload), "proof": dict(proof)}
            ).decode()
            if row["receipt"] is not None:
                if row["receipt"] != receipt:
                    raise ExecutionDenied("conflicting usage receipt")
                return
            db.execute(
                "UPDATE call_charges SET actual=?,receipt=? "
                "WHERE cycle_id=? AND operation_id=?",
                (payload["actual"], receipt, cycle.cycle_id, payload["operation_id"]),
            )

    def enable_coordination_queue(self) -> None:
        """Explicit additive schema2 -> 3 migration; no dispatcher is started."""
        self.enable_funding()
        with self._transaction() as db:
            if db.execute("PRAGMA user_version").fetchone()[0] in {3, 4, 5}:
                return
            db.execute(
                "CREATE TABLE episode_policies(account_id TEXT PRIMARY KEY, "
                "payload TEXT NOT NULL, proof TEXT NOT NULL)"
            )
            db.execute(
                "CREATE TABLE coordination_work(work_id TEXT PRIMARY KEY, "
                "account_id TEXT NOT NULL, instruction_sha256 TEXT NOT NULL, "
                "source TEXT NOT NULL, state TEXT NOT NULL, cycle_id TEXT UNIQUE, "
                "withdrawal TEXT)"
            )
            db.execute(
                "CREATE INDEX coordination_work_root "
                "ON coordination_work(account_id,state)"
            )
            db.execute("PRAGMA user_version=3")

    def configure_episode(
        self, payload: Mapping[str, Any], proof: Mapping[str, Any]
    ) -> None:
        """Immutable root eligibility from funding authority, not incoming text."""
        if set(payload) != {
            "schema",
            "store_id",
            "principal",
            "account_id",
            "participants",
            "instructions",
            "threads",
            "max_requests",
            "max_pending",
            "max_input_bytes",
        } or (
            payload["schema"] != "execution/episode-policy/v1"
            or payload["store_id"] != self.store_id
            or not all(
                self._positive(payload[k])
                for k in ("max_requests", "max_pending", "max_input_bytes")
            )
            or payload["max_pending"] > payload["max_requests"]
            or payload["max_input_bytes"] > 65536
        ):
            raise ExecutionDenied("invalid episode policy")
        for key in ("participants", "instructions", "threads"):
            values = payload[key]
            if (
                not isinstance(values, list)
                or not values
                or not all(isinstance(v, str) and 0 < len(v) <= 200 for v in values)
                or sorted(set(values)) != values
            ):
                raise ExecutionDenied("invalid episode eligibility")
        if len(canonical(dict(payload))) > 65536:
            raise ExecutionDenied("episode policy too large")
        with self._transaction() as db:
            if db.execute("PRAGMA user_version").fetchone()[0] not in {3, 4, 5}:
                raise ExecutionDenied("explicit queue migration required")
            account, state = self._account(db, payload["account_id"])
            if (
                account["kind"] != "episode"
                or payload["principal"] != account["principal"]
                or state["paused"]
                or not account["start"] <= self._now(db) < account["end"]
            ):
                raise ExecutionDenied("episode authority unavailable")
            for sha in payload["instructions"]:
                row = db.execute(
                    "SELECT payload FROM instruction_funding "
                    "WHERE instruction_sha256=?",
                    (sha,),
                ).fetchone()
                if (
                    row is None
                    or payload["account_id"]
                    not in json.loads(row["payload"])["accounts"]
                ):
                    raise ExecutionDenied(
                        "episode instruction is not funded by this root"
                    )
            self._event(db, "approve", dict(payload), proof)
            try:
                db.execute(
                    "INSERT INTO episode_policies(account_id,payload,proof) "
                    "VALUES (?,?,?)",
                    (
                        payload["account_id"],
                        canonical(dict(payload)).decode(),
                        canonical(dict(proof)).decode(),
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ExecutionDenied("immutable episode policy exists") from exc

    def _episode(self, db: sqlite3.Connection, account_id: str) -> dict[str, Any]:
        if db.execute("PRAGMA user_version").fetchone()[0] not in {3, 4, 5}:
            raise ExecutionDenied("coordination queue unavailable")
        row = db.execute(
            "SELECT * FROM episode_policies WHERE account_id=?", (account_id,)
        ).fetchone()
        if row is None:
            raise ExecutionDenied("unknown coordination episode")
        payload = json.loads(row["payload"])
        self.verifier.verify("approve", payload, json.loads(row["proof"]))
        if payload["store_id"] != self.store_id or payload["account_id"] != account_id:
            raise ExecutionDenied("episode audience mismatch")
        return cast(dict[str, Any], payload)

    def enqueue_coordination(
        self, message_id: str, read_message: Callable[[str], Mapping[str, Any]]
    ) -> str | None:
        """Explicit owner call with its CURRENT authenticated native reader.

        read_message must be the maintained native message lookup, not raw JSON,
        a model-supplied verifier or a cached Telegram echo. Receipt/status/result
        traffic has no eligibility; this method never launches a model.
        """
        source = read_message(message_id)
        if source.get("event_id") != message_id:
            raise ExecutionDenied("source lookup mismatch")
        if (
            source.get("kind") != "experience.observed"
            or source.get("subject") != "communication"
        ):
            return None
        body = source["payload"]["body"]
        request = body.get("coordination")
        if body.get("semantic_receipt") is not None or request is None:
            return None
        request = coordination_metadata(request)
        if request["kind"] != "work":
            return None  # answers, ACKs, reactions, errors never consume a queue slot
        record = {
            "message_id": message_id,
            "source_sha256": digest(source),
            "being": source["being_ref"],
            "origin": source["origin"]["embodiment_id"],
            "thread": source["payload"]["intent"]["thread_id"],
            "instruction_sha256": request["instruction_sha256"],
        }
        work_id = digest(
            {k: record[k] for k in ("message_id", "being", "instruction_sha256")}
        )
        with self._transaction() as db:
            policy = self._episode(db, request["account_id"])
            previous = db.execute(
                "SELECT * FROM coordination_work WHERE work_id=?", (work_id,)
            ).fetchone()
            if previous is not None:
                if (
                    previous["source"] != canonical(record).decode()
                    or previous["account_id"] != request["account_id"]
                ):
                    raise ExecutionDenied("immutable source/work conflict")
                return work_id  # inspect the same retained result; no replay or renewal
            if (
                record["being"] not in policy["participants"]
                or record["thread"] not in policy["threads"]
                or request["instruction_sha256"] not in policy["instructions"]
                or len(canonical(body)) > policy["max_input_bytes"]
            ):
                raise ExecutionDenied("source outside selected episode eligibility")
            account, state = self._account(db, request["account_id"])
            if (
                state["paused"]
                or not account["start"] <= self._now(db) < account["end"]
            ):
                raise ExecutionDenied("episode paused or expired")
            counts = db.execute(
                "SELECT count(*) AS total, coalesce(sum(w.state='queued' OR "
                "(w.state='intent' AND c.state IN ('intent','ambiguous'))),0) "
                "AS pending "
                "FROM coordination_work w LEFT JOIN cycles c USING(cycle_id) "
                "WHERE w.account_id=?",
                (request["account_id"],),
            ).fetchone()
            if (
                counts["total"] >= policy["max_requests"]
                or counts["pending"] >= policy["max_pending"]
            ):
                raise ExecutionDenied("episode backlog exhausted")
            db.execute(
                "INSERT INTO coordination_work(work_id,account_id,instruction_sha256,"
                "source,state,cycle_id) VALUES (?,?,?,?,'queued',NULL)",
                (
                    work_id,
                    request["account_id"],
                    request["instruction_sha256"],
                    canonical(record).decode(),
                ),
            )
        return work_id

    def _work(self, db: sqlite3.Connection, work_id: str) -> dict[str, Any]:
        if db.execute("PRAGMA user_version").fetchone()[0] not in {3, 4, 5}:
            raise ExecutionDenied("coordination queue unavailable")
        row = db.execute(
            "SELECT * FROM coordination_work WHERE work_id=?", (work_id,)
        ).fetchone()
        if row is None:
            raise ExecutionDenied("unknown coordination work")
        self._episode(db, row["account_id"])
        return dict(row) | {"source": json.loads(row["source"])}

    def coordination_work(self, work_id: str) -> dict[str, Any]:
        with closing(self._connect()) as db:
            return self._work(db, work_id)

    def episode_status(self, account_id: str) -> dict[str, Any]:
        """One bounded operator snapshot; no dispatch or budget/queue mutation."""
        with self._transaction() as db:
            return self._episode_status_snapshot(db, account_id)

    def _episode_status_snapshot(
        self, db: sqlite3.Connection, account_id: str
    ) -> dict[str, Any]:
        policy = self._episode(db, account_id)
        root, _ = self._account(db, account_id)
        try:
            observed_at: float | None = self._now(db)
        except ExecutionDenied:
            observed_at = None
        reasons = set()
        if observed_at is None:
            reasons.add("clock_untrusted")
        accounts: dict[str, dict[str, Any]] = {}
        instructions: list[dict[str, Any]] = []
        for sha in policy["instructions"]:
            row = db.execute(
                "SELECT payload,proof FROM instruction_funding "
                "WHERE instruction_sha256=?",
                (sha,),
            ).fetchone()
            if row is None:
                raise ExecutionDenied("episode funding missing")
            funding = json.loads(row["payload"])
            self.verifier.verify("approve", funding, json.loads(row["proof"]))
            if (
                funding["store_id"] != self.store_id
                or funding["instruction_sha256"] != sha
                or account_id not in funding["accounts"]
            ):
                raise ExecutionDenied("episode funding differs")
            local_reasons: set[str] = set()
            instructions.append(
                {
                    "instruction_sha256": sha,
                    "route": funding["route"],
                    "max_charge": funding["max_charge"],
                    "accounts": funding["accounts"],
                }
            )
            for identity in funding["accounts"]:
                if identity not in accounts:
                    account, state = self._account(db, identity)
                    balance = self._balance(db, identity)
                    accounts[identity] = (
                        account
                        | balance
                        | {
                            "paused": bool(state["paused"]),
                            "control_revision": state["control_revision"],
                            "available_calls": account["max_calls"] - balance["calls"],
                            "available_charge": account["max_charge"]
                            - balance["charged"],
                        }
                    )
                account = accounts[identity]
                if account["paused"]:
                    local_reasons.add("paused")
                if observed_at is not None:
                    if observed_at < account["start"]:
                        local_reasons.add("not_started")
                    if observed_at >= account["end"]:
                        local_reasons.add("expired")
                if account["available_calls"] <= 0:
                    local_reasons.add("call_fuel_exhausted")
                if account["available_charge"] < funding["max_charge"]:
                    local_reasons.add("charge_exposure_unavailable")
                if account["active"] >= account["max_active"]:
                    local_reasons.add("concurrency_full")
                if account["uncertain"]:
                    local_reasons.add("uncertain_exposure")
            instructions[-1]["funding_constraints"] = sorted(local_reasons)
            reasons.update(local_reasons)
        counts = {
            row["state"]: row["total"]
            for row in db.execute(
                "SELECT state,count(*) AS total FROM coordination_work "
                "WHERE account_id=? GROUP BY state",
                (account_id,),
            )
        }
        return {
            "schema": "execution/episode-status/v1",
            "store_id": self.store_id,
            "account_id": account_id,
            "principal": root["principal"],
            "participants": policy["participants"],
            "instructions": instructions,
            "start": root["start"],
            "end": root["end"],
            "observed_at": observed_at,
            "funding_constraints": sorted(reasons),
            "accounts": [accounts[k] for k in sorted(accounts)],
            "work": counts,
            "pending_limit": policy["max_pending"],
            "request_limit": policy["max_requests"],
            "execution": (
                "Funding snapshot only; constraints can affect different routes. "
                "Current source/instruction/writer admission remains required."
            ),
        }

    def enable_episode_reporting(self) -> None:
        """Explicit additive schema3 -> 4; one retained notice slot per root."""
        self.enable_coordination_queue()
        with self._transaction() as db:
            if db.execute("PRAGMA user_version").fetchone()[0] in {4, 5}:
                return
            db.execute("ALTER TABLE episode_policies ADD COLUMN notice TEXT")
            db.execute("PRAGMA user_version=4")

    def enable_provider_attempts(self) -> None:
        """Explicit schema4 -> 5; preserve all original charges and signed records.

        This changes charge identity, not accounts, approvals, balances or active
        native work. v1 funding/dispatch keeps its original single-call contract.
        Only a signed v2 funding binding admits multiple physical attempts.
        """
        self.enable_episode_reporting()
        with self._transaction() as db:
            if db.execute("PRAGMA user_version").fetchone()[0] == 5:
                return
            db.execute(
                "CREATE TABLE call_charges_multi(cycle_id TEXT NOT NULL, "
                "operation_id TEXT PRIMARY KEY, instruction_sha256 TEXT NOT NULL, "
                "maximum INTEGER NOT NULL, actual INTEGER, receipt TEXT)"
            )
            db.execute("INSERT INTO call_charges_multi SELECT * FROM call_charges")
            db.execute("DROP TABLE call_charges")
            db.execute("ALTER TABLE call_charges_multi RENAME TO call_charges")
            db.execute(
                "CREATE INDEX call_charges_instruction "
                "ON call_charges(instruction_sha256)"
            )
            db.execute("CREATE INDEX call_charges_cycle ON call_charges(cycle_id)")
            db.execute("PRAGMA user_version=5")

    def episode_report(self, account_id: str) -> dict[str, Any]:
        """One consistent operator card/notice observation; no external effects."""
        with self._transaction() as db:
            snapshot = self._episode_status_snapshot(db, account_id)
            enabled = db.execute("PRAGMA user_version").fetchone()[0] in {4, 5}
            return {
                "schema": "execution/episode-report/v1",
                "snapshot": snapshot,
                "reporting_enabled": enabled,
                "notice": self._episode_notice_snapshot(db, account_id, snapshot)
                if enabled
                else None,
            }

    def episode_notice(self, account_id: str) -> dict[str, Any] | None:
        """Return one retained passive notice; not a sender or execution grant."""
        with self._transaction() as db:
            if db.execute("PRAGMA user_version").fetchone()[0] not in {4, 5}:
                raise ExecutionDenied("explicit reporting migration required")
            return self._episode_notice_snapshot(
                db, account_id, self._episode_status_snapshot(db, account_id)
            )

    def _episode_notice_snapshot(
        self, db: sqlite3.Connection, account_id: str, snapshot: Mapping[str, Any]
    ) -> dict[str, Any] | None:
        previous = db.execute(
            "SELECT notice FROM episode_policies WHERE account_id=?", (account_id,)
        ).fetchone()["notice"]
        if previous is not None:
            return cast(dict[str, Any], json.loads(previous))
        unavailable = {"call_fuel_exhausted", "charge_exposure_unavailable"}
        routes = snapshot["instructions"]
        if not all(
            unavailable.intersection(row["funding_constraints"]) for row in routes
        ):
            return None
        notice = {
            "schema": "execution/episode-notice/v1",
            "notice_id": digest(
                {
                    "store_id": self.store_id,
                    "account_id": account_id,
                    "kind": "funding_unavailable",
                }
            ),
            "store_id": self.store_id,
            "account_id": account_id,
            "kind": "funding_unavailable",
            "observed_at": snapshot["observed_at"],
            "instructions": [row["instruction_sha256"] for row in routes],
            "constraints": sorted(
                unavailable.intersection(snapshot["funding_constraints"])
            ),
            "execution": (
                "No model activated; inspect retained reservations and episode controls"
            ),
        }
        db.execute(
            "UPDATE episode_policies SET notice=? WHERE account_id=?",
            (canonical(notice).decode(), account_id),
        )
        return notice

    def withdraw_coordination(
        self, payload: Mapping[str, Any], proof: Mapping[str, Any]
    ) -> None:
        """Signed withdrawal is terminal for a queued original, not an input replay.

        An intent may already be executing: use exact instruction cancellation
        and the existing bounded controller interruption instead of erasing it.
        """
        if set(payload) != {
            "schema",
            "store_id",
            "principal",
            "work_id",
            "source_sha256",
        } or (
            payload["schema"] != "execution/work-withdrawal/v1"
            or payload["store_id"] != self.store_id
        ):
            raise ExecutionDenied("invalid work withdrawal")
        self.verifier.verify("approve", payload, proof)
        with self._transaction() as db:
            work = self._work(db, payload["work_id"])
            policy = self._episode(db, work["account_id"])
            if (
                payload["principal"] != policy["principal"]
                or payload["source_sha256"] != work["source"]["source_sha256"]
            ):
                raise ExecutionDenied("withdrawal authority/source mismatch")
            receipt = canonical(
                {"payload": dict(payload), "proof": dict(proof)}
            ).decode()
            if work["state"] == "withdrawn":
                if work["withdrawal"] != receipt:
                    raise ExecutionDenied("conflicting withdrawal")
                return
            if work["state"] != "queued":
                raise ExecutionDenied(
                    "retained intent requires exact native cancellation"
                )
            self._event(db, "approve", dict(payload), proof)
            db.execute(
                "UPDATE coordination_work SET state='withdrawn',withdrawal=? "
                "WHERE work_id=?",
                (receipt, payload["work_id"]),
            )

    def check_work_source(
        self, work_id: str, read_message: Callable[[str], Mapping[str, Any]]
    ) -> Mapping[str, Any]:
        work = self.coordination_work(work_id)
        source = work["source"]
        original = read_message(source["message_id"])
        if digest(original) != source["source_sha256"]:
            raise ExecutionDenied("queued source changed or lost authorization")
        return original

    def mark_ambiguous(self, cycle: Cycle) -> None:
        with self._transaction() as db:
            row = self._cycle(db, cycle)
            if row["state"] == "intent":
                db.execute(
                    "UPDATE cycles SET state='ambiguous' WHERE cycle_id=?",
                    (cycle.cycle_id,),
                )

    def cancellation_mark_ambiguous(self, cycle: Cycle, remaining: float) -> None:
        """Persist cancellation uncertainty without waiting for a writer."""
        timeout = self._cancellation_timeout(remaining)
        with self._transaction(timeout=timeout) as db:
            row = self._cycle(db, cycle)
            if row["state"] == "intent":
                db.execute(
                    "UPDATE cycles SET state='ambiguous' WHERE cycle_id=?",
                    (cycle.cycle_id,),
                )

    def finish(
        self, cycle: Cycle, outcome: str, *, require_unstarted: bool = False
    ) -> None:
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
            if require_unstarted and (
                outcome != "stopped"
                or db.execute(
                    "SELECT count(*) FROM operations WHERE cycle_id=? "
                    "AND kind='native_owner' AND state='returned'",
                    (cycle.cycle_id,),
                ).fetchone()[0]
                != 1
                or db.execute(
                    "SELECT 1 FROM operations WHERE cycle_id=? "
                    "AND kind!='native_owner'",
                    (cycle.cycle_id,),
                ).fetchone()
                is not None
            ):
                raise ExecutionDenied("unstarted native cycle has admitted operations")
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

    def cancellation_finish(self, cycle: Cycle, outcome: str, remaining: float) -> None:
        """Reconcile a stopped runtime without waiting beyond cleanup budget."""
        if outcome not in {"completed", "stopped"}:
            raise ExecutionDenied("unsupported terminal outcome")
        timeout = self._cancellation_timeout(remaining)
        with self._transaction(timeout=timeout) as db:
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
        return self._cycle_status(cycle_id, timeout=10.0)

    def cancellation_cycle_status(
        self, cycle_id: str, remaining: float
    ) -> dict[str, Any]:
        """Read one owned cycle without waiting for a SQLite writer."""
        return self._cycle_status(
            cycle_id, timeout=self._cancellation_timeout(remaining)
        )

    def _cycle_status(self, cycle_id: str, *, timeout: float) -> dict[str, Any]:
        with closing(self._connect(timeout=timeout)) as db:
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
