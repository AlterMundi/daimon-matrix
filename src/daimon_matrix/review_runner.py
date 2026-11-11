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
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, fields
from typing import Any, Literal, Protocol

from .execution_instruction import (
    ApprovalVerifier,
    ExecutionDenied,
    Instruction,
    Scope,
    canonical,
    digest,
)
from .execution_store import Cycle, ExecutionStore


@dataclass(frozen=True)
class ReviewRequest:
    instruction: Instruction
    task: str
    cycle_id: str
    deadline: float
    work: Mapping[str, Any] | None = None


@dataclass(frozen=True)
class ProviderCostBound:
    """Operator-verified conservative pricing for one exact fenced registration.

    No prices, providers or activation defaults. An actual provider contract and
    isolated credential route must independently qualify the declared bound.
    """

    schema: str
    principal: str
    store_id: str
    registration_sha256: str
    route: str
    unit: str
    expires: int
    max_input_tokens: int
    max_output_tokens: int
    input_price: int
    output_price: int
    fixed_charge: int

    @classmethod
    def verify(
        cls,
        payload: Mapping[str, Any],
        proof: Mapping[str, Any],
        verifier: ApprovalVerifier,
    ) -> ProviderCostBound:
        if set(payload) != {f.name for f in fields(cls)}:
            raise ExecutionDenied("closed provider cost bound required")
        verifier.verify("approve", payload, proof)
        result = cls(**payload)
        if (
            result.schema != "execution/provider-cost-bound/v1"
            or not all(
                isinstance(payload[k], str) and 0 < len(payload[k]) <= 200
                for k in ("principal", "store_id", "route", "unit")
            )
            or not isinstance(result.registration_sha256, str)
            or len(result.registration_sha256) != 64
            or any(c not in "0123456789abcdef" for c in result.registration_sha256)
            or not all(
                ExecutionStore._positive(payload[k])
                for k in ("expires", "max_input_tokens", "max_output_tokens")
            )
            or not all(
                ExecutionStore._positive(payload[k], zero=True)
                for k in ("input_price", "output_price", "fixed_charge")
            )
        ):
            raise ExecutionDenied("invalid provider cost bound")
        return result

    def exposure(
        self, context: CycleContext, registration: Mapping[str, Any]
    ) -> dict[str, Any]:
        instruction = context.instruction
        if (
            digest(dict(registration)) != self.registration_sha256
            or self.principal != instruction.principal
            or self.store_id != instruction.store_id
            or registration.get("store_id") != self.store_id
            or registration.get("principal") != self.principal
            or registration.get("provider") != instruction.provider
            or registration.get("model") != instruction.model
            or instruction.max_input_tokens > self.max_input_tokens
            or instruction.max_output_tokens > self.max_output_tokens
            or context.cycle.deadline > self.expires
            or context._store.observe_clock() >= self.expires
        ):
            raise ExecutionDenied("provider cost registration/bounds mismatch")
        amount = (
            self.fixed_charge
            + self.input_price * instruction.max_input_tokens
            + self.output_price * instruction.max_output_tokens
        )
        if not ExecutionStore._positive(amount, zero=True):
            raise ExecutionDenied("provider exposure outside exact integer range")
        return {
            "route": self.route,
            "unit": self.unit,
            "max_charge": amount,
            "provider": instruction.provider,
            "model": instruction.model,
            "max_input_tokens": instruction.max_input_tokens,
            "max_output_tokens": instruction.max_output_tokens,
        }


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
        broker: NativeBroker | None,
        monotonic: Callable[[], float],
        monotonic_deadline: float,
        on_terminal: Callable[[CycleContext], None] | None = None,
        source_check: Callable[[], Mapping[str, Any]] | None = None,
        work: Mapping[str, Any] | None = None,
    ):
        self.work = work
        self.cycle = cycle
        self.instruction = instruction
        self._store = store
        self._broker = broker
        self._monotonic = monotonic
        self._monotonic_deadline = monotonic_deadline
        self._on_terminal = on_terminal
        self._source_check = source_check
        self._last_monotonic = monotonic_deadline - instruction.max_cycle_seconds
        self._clock_fault = False
        self._last_wall = float("-inf")
        self._fenced = False

    @classmethod
    def prepare(
        cls,
        store: ExecutionStore,
        broker: NativeBroker | None,
        identity: str,
        revision: int,
        task: str,
        *,
        principal: str,
        binding: tuple[str, str, str, str],
        work_id: str | None = None,
        require_funding: bool = True,
        require_queued_source: bool = True,
        read_message: Callable[[str], Mapping[str, Any]] | None = None,
        host_source: Mapping[str, Any] | None = None,
        monotonic: Callable[[], float] = time.monotonic,
        on_terminal: Callable[[CycleContext], None] | None = None,
    ) -> CycleContext | None:
        """Reserve the existing signed work without starting a runner.

        The trusted host supplies its fixed principal/binding and current reader.
        This retains the capability in this process, never serializes its token,
        creates no authority or account, and cannot recover a dispatched cycle.
        Owner construction must happen hereafter, outside a dispatch transaction.
        """
        # Scheduling metadata and arrival text never create an instruction.
        if require_queued_source and work_id is None and host_source is None:
            raise ExecutionDenied("peer execution requires a selected original")
        source_check = None
        work = None
        if work_id is not None:
            reader = read_message
            if reader is None:
                raise ExecutionDenied("no current authenticated source reader")

            def source_check() -> Mapping[str, Any]:
                return store.check_work_source(work_id, reader)

            source_check()
            work = store.coordination_work(work_id)
        if host_source is not None:
            # Host API only: the App owns its original queue. No peer metadata
            # or second coordination row is required for this accounting mode.
            if (
                work_id is not None
                or not require_funding
                or broker is not None
                or read_message is None
                or set(host_source)
                != {"channel_id", "message_id", "message_hash", "local_execution_id"}
                or not isinstance(host_source["channel_id"], str)
                or not isinstance(host_source["message_id"], str)
                or not isinstance(host_source["message_hash"], str)
                or len(host_source["message_hash"]) != 64
                or any(c not in "0123456789abcdef" for c in host_source["message_hash"])
                or not ExecutionStore._positive(host_source["local_execution_id"])
            ):
                raise ExecutionDenied("exclusive funded host source required")
            expected = dict(host_source)
            host_reader = read_message
            first = host_reader(expected["message_id"])
            original_digest = digest(dict(first))

            def source_check() -> Mapping[str, Any]:
                original = host_reader(expected["message_id"])
                if (
                    original.get("event_id") != expected["message_id"]
                    or original.get("content_hash") != expected["message_hash"]
                    or digest(dict(original)) != original_digest
                ):
                    raise ExecutionDenied("host original changed")
                return original

            source_check()
            work = {
                "source_mode": "app_owned_inbox",
                **expected,
                "document_sha256": original_digest,
            }
        try:
            status = store.status(identity, revision)
        except ExecutionDenied:
            return None
        if status["state"] != "active":
            return None
        instruction = store.get_instruction(identity, revision)
        if host_source is not None and not any(
            scope.channel == host_source["channel_id"] for scope in instruction.scope
        ):
            raise ExecutionDenied("host source channel outside signed scope")
        if require_funding:
            # Explicit operator profile, never selected by peer/model text. The
            # actual provider boundary independently requires exact exposure.
            store.check_funding(instruction)
        if instruction.principal != principal:
            raise ExecutionDenied(
                "instruction principal is not the registered principal"
            )
        if hashlib.sha256(task.encode("utf-8")).hexdigest() != instruction.task_sha256:
            raise ExecutionDenied("task digest mismatch")
        start_mono = monotonic()
        if not math.isfinite(start_mono):
            raise ExecutionDenied("untrusted monotonic clock")
        cycle = (
            store.reserve(identity, revision, binding)
            if work_id is None
            else store.reserve(identity, revision, binding, work_id=work_id)
        )
        if cycle is None:
            return None
        return cls(
            store,
            cycle,
            instruction,
            broker,
            monotonic,
            start_mono + instruction.max_cycle_seconds,
            on_terminal,
            source_check,
            work,
        )

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
        if self._source_check is not None:
            self._source_check()
            # A bounded authorization read can still consume the remaining
            # horizon. Never submit using the pre-read time observation.
            self.remaining()

    def selected_original(self) -> Mapping[str, Any] | None:
        """Exact currently authorized queued source, never a whole inbox import.

        The returned peer speech is untrusted context. Funding and task/scope
        authority remain the signed instruction and controller, not this text.
        """
        if self._source_check is None:
            return None
        try:
            self._store.check(self.cycle)
            self.remaining()
            original = self._source_check()
            self.remaining()
            return original
        except Exception:
            self._fenced = True
            raise

    def _finish(
        self,
        outcome: Literal["completed", "stopped"],
        *,
        require_unstarted: bool = False,
    ) -> None:
        self._store.finish(self.cycle, outcome, require_unstarted=require_unstarted)
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

    def inference(
        self, submit: Callable[[], object], *, exposure: Mapping[str, Any] | None = None
    ) -> object:
        """One actual provider request after asynchronous startup, no retries.

        submit must only enqueue bounded transport bytes, not wait for a model;
        like native submission it may not reenter the store. This additional
        durable gate closes the queue-to-provider cancellation race.
        """
        self.check()
        return self._store.dispatch(
            self.cycle, "provider", None, self._checkpoint, submit, exposure=exposure
        )

    def native(self, scope: Scope, payload: Mapping[str, Any]) -> object:
        self.check()
        broker = self._broker
        if (
            broker is None
            or scope not in self.instruction.scope
            or not broker.authorize(scope)
        ):
            raise ExecutionDenied("scope or communication authorization denied")

        def submit() -> object:
            if not broker.authorize(scope):
                raise ExecutionDenied("communication authorization revoked")
            return broker.submit(scope, payload, min(1.0, self.remaining()))

        return self._store.dispatch(
            self.cycle, "native", scope, self._checkpoint, submit
        )

    def provider_attempt(
        self,
        operation_id: str,
        submit: Callable[[], object],
        *,
        cost_bound: ProviderCostBound,
        registration: Mapping[str, Any],
    ) -> object:
        """Reserve one native physical attempt in this existing work context.

        The owner supplies its verified cost contract and exact registration,
        never a model-supplied charge estimate. Recheck them at both journal
        checkpoints, including after a source authorization read. ``submit``
        only writes the bounded authorization response; it must not await the
        native model, reenter the journal, or claim that provider I/O occurred.
        Lost responses retain the original UUID/exposure; they are not replayed.
        This method selects no account, signer, transport or native execution.
        """
        self.check()
        exposure = cost_bound.exposure(self, registration)

        def checkpoint() -> None:
            self._checkpoint()
            cost_bound.exposure(self, registration)

        return self._store.dispatch_provider_attempt(
            self.cycle, operation_id, checkpoint, submit, exposure=exposure
        )


class NativeProviderOwner:
    """Host-only Core17 reservation consumer over an existing work capability.

    The embedding owner selects the currently owned native thread and supplies
    the already-reserved parent allowance, verified pricing and actual adapter
    registration. None comes from a model, RPC body or new balance database.
    The registration's max_request_bytes participates in its signed cost hash;
    that assertion still requires independent full-exposure/route qualification.
    Do not reconstruct this owner to restart dispatched/uncertain native work.
    """

    def __init__(
        self,
        context: CycleContext,
        *,
        thread_id: str,
        parent_allowance: Mapping[str, Any],
        cost_bound: ProviderCostBound,
        registration: Mapping[str, Any],
    ) -> None:
        context.check()
        if (
            not isinstance(thread_id, str)
            or not 0 < len(thread_id.encode("utf-8")) <= 200
            or any(ord(c) < 32 for c in thread_id)
            or set(parent_allowance)
            != {"maxProviderAttempts", "maxRequestBytes", "deadlineUnixMs"}
            or not all(ExecutionStore._positive(v) for v in parent_allowance.values())
            or not ExecutionStore._positive(registration.get("max_request_bytes"))
            or registration["max_request_bytes"] > 64 * 1024 * 1024
        ):
            raise ExecutionDenied("bounded native owner registration required")
        cost_bound.exposure(context, registration)
        with context._store._transaction() as db:
            context._store._guard(db, context.cycle)
            funding = context._store._funding(db, context.instruction, required=True)
            if (
                funding is None
                or funding["schema"] != "execution/instruction-funding/v2"
            ):
                raise ExecutionDenied("native owner requires multi-attempt funding")
            # Claim once in the existing shared journal, before any dispatch.
            # Object-local counters cannot conserve an inherited parent cap.
            if (
                db.execute(
                    "SELECT 1 FROM operations WHERE cycle_id=? "
                    "AND kind IN ('native_owner','provider','provider_attempt')",
                    (context.cycle.cycle_id,),
                ).fetchone()
                is not None
            ):
                raise ExecutionDenied(
                    "native provider owner already selected or dispatched"
                )
            self._allowance = {
                "maxProviderAttempts": min(
                    parent_allowance["maxProviderAttempts"],
                    funding["max_provider_attempts"],
                    2**32 - 1,
                ),
                "maxRequestBytes": min(
                    parent_allowance["maxRequestBytes"],
                    registration["max_request_bytes"],
                ),
                "deadlineUnixMs": min(
                    parent_allowance["deadlineUnixMs"],
                    int(context.cycle.deadline * 1000),
                ),
            }
            remaining_ms = self._allowance["deadlineUnixMs"] - int(
                context._store._now(db) * 1000
            )
            if not 0 < remaining_ms <= 600_000:
                raise ExecutionDenied("native owner horizon unavailable")
            db.execute(
                "INSERT INTO operations VALUES (?,?,?,?,'returned')",
                (
                    str(uuid.uuid4()),
                    context.cycle.cycle_id,
                    "native_owner",
                    canonical(
                        self._allowance
                        | (
                            {"source": context.work}
                            if context.work is not None
                            and context.work.get("source_mode") == "app_owned_inbox"
                            else {}
                        )
                    ).decode(),
                ),
            )
        self._context = context
        self._thread_id = thread_id
        self._cost_bound = cost_bound
        self._registration = registration
        self._ordinals: set[int] = set()
        self._attempts: dict[str, int] = {}
        self._lock = threading.Lock()
        self._closed = False

    def _check(self) -> None:
        if self._closed:
            raise ExecutionDenied("native provider owner is fenced")
        self._context.check()
        self._cost_bound.exposure(self._context, self._registration)
        if (
            self._context._store.observe_clock() * 1000
            >= self._allowance["deadlineUnixMs"]
        ):
            raise ExecutionDenied("native owner deadline reached")

    def descriptor(self) -> dict[str, Any]:
        """Exact immutable bounded-start fields; never the cycle capability token."""
        with self._lock:
            self._check()
            return {
                "threadId": self._thread_id,
                "providerReservationCycleId": self._context.cycle.cycle_id,
                "allowance": dict(self._allowance),
            }

    def reserve(
        self,
        request: Mapping[str, Any],
        publish: Callable[[dict[str, Any]], object],
    ) -> object:
        """Reserve before publishing this exact authorization response once.

        publish only enqueues bounded owner-channel bytes, without reentering
        this owner/journal or waiting for native inference. If it fails after a
        possible write, the existing journal preserves ambiguity and exposure.
        Refusal fences this owner; no retry, refund or new cycle follows here.
        """
        with self._lock:
            try:
                self._check()
                if not isinstance(request, Mapping) or not callable(publish):
                    raise ExecutionDenied(
                        "native request and bounded publisher required"
                    )
                attempt_id = request.get("attemptId")
                try:
                    canonical_attempt = (
                        isinstance(attempt_id, str)
                        and str(uuid.UUID(attempt_id)) == attempt_id
                    )
                except ValueError:
                    canonical_attempt = False
                if (
                    set(request)
                    != {
                        "threadId",
                        "cycleId",
                        "attemptId",
                        "ordinal",
                        "maxRequestBytes",
                        "deadlineUnixMs",
                    }
                    or request["threadId"] != self._thread_id
                    or request["cycleId"] != self._context.cycle.cycle_id
                    or not canonical_attempt
                    or not ExecutionStore._positive(request["ordinal"])
                    or request["ordinal"] > self._allowance["maxProviderAttempts"]
                    or request["ordinal"] in self._ordinals
                    or any(
                        type(request[k]) is not int or request[k] != self._allowance[k]
                        for k in ("maxRequestBytes", "deadlineUnixMs")
                    )
                ):
                    raise ExecutionDenied(
                        "native reservation differs from owned execution"
                    )
                self._ordinals.add(request["ordinal"])
                response = {
                    "cycleId": self._context.cycle.cycle_id,
                    "attemptId": request["attemptId"],
                    "authorized": True,
                }

                def submit() -> object:
                    # The surrounding context already rechecks source/pricing
                    # inside the journal. Do not reenter its transaction here.
                    if (
                        self._context._store.observe_clock() * 1000
                        >= self._allowance["deadlineUnixMs"]
                    ):
                        raise ExecutionDenied("native owner deadline reached")
                    return publish(response)

                result = self._context.provider_attempt(
                    request["attemptId"],
                    submit,
                    cost_bound=self._cost_bound,
                    registration=self._registration,
                )
                self._attempts[request["attemptId"]] = request["ordinal"]
                return result
            except BaseException:
                self._closed = True
                raise

    def record_usage(self, request: Mapping[str, Any]) -> dict[str, Any]:
        """Current host's exact attempt evidence, never a signed settlement.

        Do not use admission/source guards: an already admitted response may
        arrive after a pause. No new call, effect, refund or balance is created.
        """
        with self._lock:
            if (
                set(request)
                != {
                    "threadId",
                    "cycleId",
                    "attemptId",
                    "ordinal",
                    "responseId",
                    "model",
                    "tokenUsage",
                    "usageMetadata",
                }
                or request["threadId"] != self._thread_id
                or request["cycleId"] != self._context.cycle.cycle_id
                or not isinstance(request["attemptId"], str)
                or self._attempts.get(request["attemptId"]) != request["ordinal"]
                or not ExecutionStore._positive(request["ordinal"])
                or not isinstance(request["responseId"], str)
                or not 0 < len(request["responseId"].encode()) <= 200
                or (
                    request["model"] is not None
                    and (
                        not isinstance(request["model"], str)
                        or not 0 < len(request["model"].encode()) <= 200
                    )
                )
            ):
                raise ExecutionDenied(
                    "provider observation differs from reserved owner"
                )
            tokens = request["tokenUsage"]
            if tokens is not None and (
                not isinstance(tokens, Mapping)
                or set(tokens)
                != {
                    "totalTokens",
                    "inputTokens",
                    "cachedInputTokens",
                    "cacheWriteInputTokens",
                    "outputTokens",
                    "reasoningOutputTokens",
                }
                or not all(
                    ExecutionStore._positive(v, zero=True) for v in tokens.values()
                )
            ):
                raise ExecutionDenied("invalid observed token usage")
            metadata = request["usageMetadata"]
            if metadata is not None and (
                not isinstance(metadata, Mapping)
                or set(metadata) != {"amount", "metadata"}
                or (
                    metadata["amount"] is not None
                    and not isinstance(metadata["amount"], str)
                )
            ):
                raise ExecutionDenied("invalid observed usage metadata")
            observation = {
                "schema": "execution/provider-usage-observation/v1",
                **dict(request),
            }
            self._context._store.record_provider_usage(
                self._context.cycle, request["attemptId"], observation
            )
            return {
                "cycleId": request["cycleId"],
                "attemptId": request["attemptId"],
                "recorded": True,
            }


class ReviewController:
    def __init__(
        self,
        store: ExecutionStore,
        runner: ReviewRunner,
        broker: NativeBroker,
        *,
        monotonic: Callable[[], float] = time.monotonic,
        require_funding: bool = False,
        require_queued_source: bool = False,
        read_message: Callable[[str], Mapping[str, Any]] | None = None,
    ):
        self.store = store
        self.runner = runner
        self.broker = broker
        self.monotonic = monotonic
        self.require_funding = require_funding or require_queued_source
        self.require_queued_source = require_queued_source
        # Owner-registered current native lookup; never a model-supplied verifier
        # or a cached echo. Like NativeBroker, it must be independently bounded.
        self.read_message = read_message
        self._contexts: dict[tuple[str, int, str], CycleContext] = {}
        self._contexts_lock = threading.Lock()

    def enqueue_native(self, message_id: str) -> str | None:
        """Explicit passive intake through this owner's registered native reader."""
        if self.read_message is None:
            raise ExecutionDenied("no current authenticated source reader")
        return self.store.enqueue_coordination(message_id, self.read_message)

    def _forget(self, context: CycleContext) -> None:
        key = (
            context.cycle.instruction_id,
            context.cycle.revision,
            context.cycle.cycle_id,
        )
        with self._contexts_lock:
            self._contexts.pop(key, None)

    def run_due_once(
        self, identity: str, revision: int, task: str, *, work_id: str | None = None
    ) -> CycleContext | None:
        context = CycleContext.prepare(
            self.store,
            self.broker,
            identity,
            revision,
            task,
            principal=self.runner.expected_principal,
            binding=self.runner.binding,
            work_id=work_id,
            require_funding=self.require_funding,
            require_queued_source=self.require_queued_source,
            read_message=self.read_message,
            monotonic=self.monotonic,
            on_terminal=self._forget,
        )
        if context is None:
            return None
        cycle, instruction = context.cycle, context.instruction
        with self._contexts_lock:
            self._contexts[(identity, revision, cycle.cycle_id)] = context
        request = ReviewRequest(
            instruction, task, cycle.cycle_id, cycle.deadline, context.work
        )
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
