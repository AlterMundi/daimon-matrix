"""Model-free dispatch core. No scheduler, default job, intake hook or harness.

Adapters are trusted enforcement components, not model-selected callbacks. They
must provide bounded submission, supervised deadline/interrupt enforcement, token
budgets, and exclusive tool mediation before being registered by the operator.
"""

from __future__ import annotations

import hashlib
import math
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
    ):
        self.cycle = cycle
        self.instruction = instruction
        self._store = store
        self._broker = broker
        self._monotonic = monotonic
        self._monotonic_deadline = monotonic_deadline
        self._last_monotonic = monotonic_deadline - instruction.max_cycle_seconds
        self._clock_fault = False

    def remaining(self) -> float:
        now = self._monotonic()
        if self._clock_fault or not math.isfinite(now) or now < self._last_monotonic:
            self._clock_fault = True
            raise ExecutionDenied("monotonic clock fault")
        self._last_monotonic = now
        remaining = min(
            self._monotonic_deadline - now,
            self.cycle.deadline - self._store.clock(),
        )
        if not math.isfinite(remaining) or remaining <= 0:
            raise ExecutionDenied("cycle deadline reached")
        return remaining

    def _checkpoint(self) -> None:
        self.remaining()

    def check(self) -> None:
        self._checkpoint()
        self._store.check(self.cycle)

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
        )
        request = ReviewRequest(instruction, task, cycle.cycle_id, cycle.deadline)
        self.store.dispatch(
            cycle,
            "inference",
            None,
            context._checkpoint,
            lambda: self.runner.start(request, context, min(1.0, context.remaining())),
        )
        return context

    def enforce(self, context: CycleContext) -> None:
        """Called by the supervising adapter on cancellation/deadline notifications.

        This is not a background watchdog; an adapter without independent bounded
        supervision is not a supported runner. Ambiguity is never timeout-reclaimed.
        """
        if self.store.cycle_status(context.cycle.cycle_id)["state"] in {
            "completed",
            "stopped",
        }:
            return
        try:
            context.check()
        except ExecutionDenied:
            self.store.mark_ambiguous(context.cycle)
            result = self.runner.interrupt(
                context.cycle.cycle_id, context.instruction.cleanup_seconds
            )
            if result == "stopped":
                self.store.finish(context.cycle, "stopped")
