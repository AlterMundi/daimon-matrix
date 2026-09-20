"""Model-free dispatch core. No scheduler, default job, intake hook or harness.

Adapters are trusted enforcement components, not model-selected callbacks. They
must provide bounded submission, supervised deadline/interrupt enforcement, token
budgets, and exclusive tool mediation before being registered by the operator.
"""

from __future__ import annotations

import hashlib
import math
import sqlite3
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Literal, Protocol

from .execution_instruction import ExecutionDenied, Instruction, Scope
from .execution_store import Cycle, ExecutionStore


@dataclass(frozen=True)
class ReviewRequest:
    instruction: Instruction
    task: str
    cycle_id: str
    deadline: float


class ReviewRunner(Protocol):
    @property
    def expected_principal(self) -> str: ...

    @property
    def binding(self) -> tuple[str, str, str, str]: ...

    def start(
        self, request: ReviewRequest, context: CycleContext, timeout: float
    ) -> None:
        """Submit ONE inference, return within timeout; no reentrant tool calls.

        Enforce exact provider/model, input/output budgets and task; deny any
        alternate model, tool, shell or scheduling route. Later native calls must
        use context. Independently supervise its deadline; never merely abandon
        an uninterruptible thread. Retain cycle_id -> runtime-turn correlation.
        """
        ...

    def interrupt(self, cycle_id: str, timeout: float) -> Literal["stopped", "unknown"]:
        """Stop only this cycle. 'stopped' requires all admitted work reconciled."""
        ...


class NativeBroker(Protocol):
    def authorize(self, scope: Scope) -> bool:
        """Recheck current communication grant/policy, independently of execution."""
        ...

    def submit(
        self, scope: Scope, payload: Mapping[str, Any], timeout: float
    ) -> object:
        """Bounded native submission to EXACT scope, not a payload-chosen destination.

        Reject destination/tool/action overrides. Enforce daemon authorization too.
        A returned receipt is technical evidence, not a semantic outcome. Never
        retry unknown sends with a fresh UUID. No direct credentials for the model.
        """
        ...


@dataclass
class _CleanupBudget:
    monotonic: Callable[[], float]
    deadline: float
    last: float
    readable: bool = True

    @classmethod
    def start(cls, monotonic: Callable[[], float], timeout: float) -> _CleanupBudget:
        try:
            now = monotonic()
        except Exception:
            return cls(monotonic, float("nan"), float("nan"), False)
        deadline = now + timeout
        readable = (
            math.isfinite(now)
            and math.isfinite(timeout)
            and timeout > 0
            and math.isfinite(deadline)
        )
        return cls(monotonic, deadline, now, readable)

    def remaining(self) -> float | None:
        if not self.readable:
            return None
        try:
            now = self.monotonic()
        except Exception:
            self.readable = False
            return None
        if not math.isfinite(now) or now < self.last:
            self.readable = False
            return None
        self.last = now
        remaining = self.deadline - now
        if not math.isfinite(remaining) or remaining <= 0:
            return None
        return remaining


def _sqlite_busy(error: Exception) -> bool:
    return isinstance(error, sqlite3.OperationalError) and getattr(
        error, "sqlite_errorcode", None
    ) in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED}


class CycleContext:
    """Host-only capability; do not serialize token or expose this object to models."""

    def __init__(
        self,
        store: ExecutionStore,
        cycle: Cycle,
        instruction: Instruction,
        broker: NativeBroker,
        monotonic: Callable[[], float],
        monotonic_deadline: float,
        on_terminal: Callable[[CycleContext], None] | None = None,
    ):
        self.cycle = cycle
        self.instruction = instruction
        self._store = store
        self._broker = broker
        self._monotonic = monotonic
        self._monotonic_deadline = monotonic_deadline
        self._on_terminal = on_terminal
        self._last_monotonic = monotonic_deadline - instruction.max_cycle_seconds
        self._clock_fault = False
        self._last_wall = float("-inf")
        self._fenced = False

    def remaining(self) -> float:
        if self._fenced:
            raise ExecutionDenied("cycle context irreversibly fenced")
        now = self._monotonic()
        if self._clock_fault or not math.isfinite(now) or now < self._last_monotonic:
            self._clock_fault = True
            raise ExecutionDenied("monotonic clock fault")
        self._last_monotonic = now
        try:
            wall = self._store.observe_clock()
        except Exception:
            self._fenced = True
            raise
        if not math.isfinite(wall) or wall < self._last_wall:
            self._fenced = True
            raise ExecutionDenied("wall clock fault")
        self._last_wall = wall
        remaining = min(
            self._monotonic_deadline - now,
            self.cycle.deadline - wall,
        )
        if not math.isfinite(remaining) or remaining <= 0:
            self._fenced = True
            raise ExecutionDenied("cycle deadline reached")
        return remaining

    def _checkpoint(self) -> None:
        self.remaining()

    def _finish(self, outcome: Literal["completed", "stopped"]) -> None:
        self._store.finish(self.cycle, outcome)
        self._fenced = True
        if self._on_terminal is not None:
            self._on_terminal(self)

    def check(self) -> None:
        try:
            # Persist the observation even on rejected absolute-deadline checks.
            self._store.check(self.cycle)
            self._checkpoint()
        except Exception:
            self._fenced = True
            raise

    def inference(self, submit: Callable[[], object]) -> object:
        """One actual provider request after asynchronous startup, no retries.

        submit must only enqueue bounded transport bytes, not wait for a model;
        like native submission it may not reenter the store. This additional
        durable gate closes the queue-to-provider cancellation race.
        """
        self.check()
        return self._store.dispatch(
            self.cycle, "provider", None, self._checkpoint, submit
        )

    def native(self, scope: Scope, payload: Mapping[str, Any]) -> object:
        self.check()
        if scope not in self.instruction.scope or not self._broker.authorize(scope):
            raise ExecutionDenied("scope or communication authorization denied")

        def submit() -> object:
            if not self._broker.authorize(scope):
                raise ExecutionDenied("communication authorization revoked")
            return self._broker.submit(scope, payload, min(1.0, self.remaining()))

        return self._store.dispatch(
            self.cycle, "native", scope, self._checkpoint, submit
        )


class ReviewController:
    def __init__(
        self,
        store: ExecutionStore,
        runner: ReviewRunner,
        broker: NativeBroker,
        *,
        monotonic: Callable[[], float] = time.monotonic,
    ):
        self.store = store
        self.runner = runner
        self.broker = broker
        self.monotonic = monotonic
        self._contexts: dict[tuple[str, int, str], CycleContext] = {}
        self._contexts_lock = threading.Lock()

    def _forget(self, context: CycleContext) -> None:
        key = (
            context.cycle.instruction_id,
            context.cycle.revision,
            context.cycle.cycle_id,
        )
        with self._contexts_lock:
            self._contexts.pop(key, None)

    def run_due_once(
        self, identity: str, revision: int, task: str
    ) -> CycleContext | None:
        # Scheduling metadata and arrival text never create an instruction.
        try:
            status = self.store.status(identity, revision)
        except ExecutionDenied:
            return None
        if status["state"] != "active":
            return None
        instruction = self.store.get_instruction(identity, revision)
        if instruction.principal != self.runner.expected_principal:
            raise ExecutionDenied(
                "instruction principal is not the registered principal"
            )
        if hashlib.sha256(task.encode("utf-8")).hexdigest() != instruction.task_sha256:
            raise ExecutionDenied("task digest mismatch")
        start_mono = self.monotonic()
        if not math.isfinite(start_mono):
            raise ExecutionDenied("untrusted monotonic clock")
        cycle = self.store.reserve(identity, revision, self.runner.binding)
        if cycle is None:
            return None
        context = CycleContext(
            self.store,
            cycle,
            instruction,
            self.broker,
            self.monotonic,
            start_mono + instruction.max_cycle_seconds,
            self._forget,
        )
        with self._contexts_lock:
            self._contexts[(identity, revision, cycle.cycle_id)] = context
        request = ReviewRequest(instruction, task, cycle.cycle_id, cycle.deadline)
        self.store.dispatch(
            cycle,
            "inference",
            None,
            context._checkpoint,
            lambda: self.runner.start(request, context, min(1.0, context.remaining())),
        )
        return context

    def enforce(
        self,
        context: CycleContext,
        timeout: float | None = None,
        *,
        _budget: _CleanupBudget | None = None,
    ) -> Literal["stopped", "unknown"]:
        """Called by the supervising adapter on cancellation/deadline notifications.

        This is not a background watchdog; an adapter without independent bounded
        supervision is not a supported runner. Ambiguity is never timeout-reclaimed.
        """
        budget = _budget or _CleanupBudget.start(
            self.monotonic,
            context.instruction.cleanup_seconds if timeout is None else timeout,
        )
        remaining = budget.remaining()
        if remaining is None:
            context._fenced = True
            return "unknown"
        persistence_error = None
        try:
            cycle_state = self.store.cancellation_cycle_status(
                context.cycle.cycle_id, remaining
            )["state"]
            if budget.remaining() is None:
                context._fenced = True
                return "unknown"
            if cycle_state in {
                "completed",
                "stopped",
            }:
                self._forget(context)
                return "stopped"
            remaining = budget.remaining()
            if remaining is None:
                context._fenced = True
                return "unknown"
            self.store.cancellation_check(context.cycle, remaining, context._checkpoint)
            return "unknown"
        except ExecutionDenied:
            pass
        except Exception as exc:
            persistence_error = exc
        context._fenced = True
        remaining = budget.remaining()
        if remaining is None:
            return "unknown"
        try:
            self.store.cancellation_mark_ambiguous(context.cycle, remaining)
        except Exception as exc:
            persistence_error = persistence_error or exc
        # Re-read the one shared deadline immediately before interrupting. A lost
        # or corrupt journal still cannot prevent a bounded stop of known work.
        remaining = budget.remaining()
        if remaining is None:
            return "unknown"
        result = self.runner.interrupt(context.cycle.cycle_id, remaining)
        if persistence_error is not None:
            if _sqlite_busy(persistence_error):
                return "unknown"
            raise persistence_error  # no replacement journal or invented receipt
        if result != "stopped":
            return result
        remaining = budget.remaining()
        if remaining is None:
            return "unknown"
        self.store.cancellation_finish(context.cycle, "stopped", remaining)
        self._forget(context)
        if budget.remaining() is None:
            return "unknown"
        return "stopped"

    def cancel_active(
        self, identity: str, revision: int, timeout: float
    ) -> tuple[Literal["stopped", "unknown"], tuple[str, ...]]:
        """Boundedly interrupt exact contexts after their authority is tombstoned."""
        budget = _CleanupBudget.start(self.monotonic, timeout)
        with self._contexts_lock:
            matches = [
                context
                for (context_id, context_revision, _), context in self._contexts.items()
                if (context_id, context_revision) == (identity, revision)
            ]
        matches.sort(key=lambda context: context.cycle.cycle_id)
        cycle_ids = {context.cycle.cycle_id for context in matches}
        outcome: Literal["stopped", "unknown"] = "stopped"
        for context in matches:
            if budget.remaining() is None:
                outcome = "unknown"
                break
            try:
                if self.enforce(context, _budget=budget) != "stopped":
                    outcome = "unknown"
            except Exception:
                outcome = "unknown"
        remaining = budget.remaining()
        if remaining is None:
            return "unknown", tuple(sorted(cycle_ids))
        try:
            audit = self.store.cancellation_status(identity, revision, remaining)
            in_flight = audit["in_flight"]
            cycle_ids.update(str(cycle["cycle_id"]) for cycle in in_flight)
            if budget.remaining() is None:
                return "unknown", tuple(sorted(cycle_ids))
            if in_flight:
                outcome = "unknown"
        except Exception:
            outcome = "unknown"
        return outcome, tuple(sorted(cycle_ids))
