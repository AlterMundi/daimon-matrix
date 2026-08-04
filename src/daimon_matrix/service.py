"""Authenticated method dispatcher for one hosted embodiment Weave runtime."""

from __future__ import annotations

import copy
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Final

from .ledger import (
    SCHEMA_VERSION,
    Ledger,
    LedgerEquivocationError,
    LedgerError,
    LedgerGapError,
    LedgerStateError,
)
from .local_api import (
    MAX_CLOCK_SKEW_MS,
    LocalApiError,
    LocalCapability,
    authenticate_request,
    create_response,
    verify_response,
)
from .projections import ProjectionEngine, ProjectionError
from .sync import SyncEngine, SyncProtocolError, validate_receipt
from .weave import DECISIONS, SENSITIVITIES, EventSigner, WeaveProtocolError

METHODS: Final = frozenset(
    {
        "runtime.status",
        "we.decide",
        "we.diff",
        "we.heads",
        "we.observe",
        "we.preview",
        "we.projection.get",
        "we.projection.rebuild",
        "we.sync.pull",
        "we.sync.request",
        "we.sync.serve",
        "we.sync.validate-receipt",
    }
)

Clock = Callable[[], int]


class ServiceError(ValueError):
    """A fully authenticated method request was invalid or refused."""

    def __init__(self, code: str, *, retryable: bool = False) -> None:
        super().__init__(code)
        self.code = code
        self.retryable = retryable


def _closed(value: Any, fields: set[str]) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ServiceError("invalid_params")
    return value


def _uuid(value: Any) -> str:
    if not isinstance(value, str):
        raise ServiceError("invalid_params")
    try:
        parsed = uuid.UUID(value)
    except ValueError as exception:
        raise ServiceError("invalid_params") from exception
    if str(parsed) != value:
        raise ServiceError("invalid_params")
    return value


def _uint(value: Any, *, minimum: int = 0, maximum: int = 2**53 - 1) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not minimum <= value <= maximum
    ):
        raise ServiceError("invalid_params")
    return value


def _optional_text(value: Any, maximum: int) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not 1 <= len(value.encode("utf-8")) <= maximum:
        raise ServiceError("invalid_params")
    return value


def _event_ids(value: Any) -> list[str]:
    if not isinstance(value, list) or len(value) > 64 or value != sorted(set(value)):
        raise ServiceError("invalid_params")
    return [_uuid(item) for item in value]


def _transport(value: Any) -> Mapping[str, str]:
    transport = _closed(value, {"principal_id", "scheme"})
    for field in ("scheme", "principal_id"):
        item = transport[field]
        if not isinstance(item, str) or not 1 <= len(item.encode("utf-8")) <= 128:
            raise ServiceError("invalid_transport_binding")
    return copy.deepcopy(dict(transport))


@dataclass(frozen=True)
class HostedWeave:
    """One root-authorized ledger, signer, and authenticated local API."""

    ledger: Ledger
    signer: EventSigner
    capabilities: Mapping[str, LocalCapability]
    clock: Clock

    def __post_init__(self) -> None:
        if self.ledger.authority.manifest.trust_mode != "root-bound":
            raise ServiceError("hosted_runtime_requires_root_authority")
        if not self.capabilities:
            raise ServiceError("runtime_requires_capability")
        seen_clients: set[tuple[str, str]] = set()
        for capability_id, capability in self.capabilities.items():
            if capability_id != capability.capability_id:
                raise ServiceError("capability_index_mismatch")
            if not set(capability.methods) <= METHODS:
                raise ServiceError("unsupported_capability_method")
            marker = (capability.client_id, capability.capability_id)
            if marker in seen_clients:
                raise ServiceError("duplicate_capability")
            seen_clients.add(marker)
        self.ledger.authority.validate_origin(
            self.ledger.local_origin, require_active=True
        )
        self.ledger.initialize()

    @property
    def origin(self) -> dict[str, str]:
        return copy.deepcopy(self.ledger.local_origin)

    def handle(self, value: Any) -> dict[str, Any]:
        """Authenticate, journal, dispatch, and return one exact response."""

        if not isinstance(value, Mapping):
            raise LocalApiError("authentication_failed")
        capability_id = value.get("capability_id")
        capability = (
            self.capabilities.get(capability_id)
            if isinstance(capability_id, str)
            else None
        )
        if capability is None:
            raise LocalApiError("authentication_failed")
        now = self.clock()
        request, digest = authenticate_request(
            value, capability, now_ms=now, allow_stale=True
        )
        client_id = capability.client_id
        request_id = request["request_id"]
        method = request["method"]
        if now - request[
            "issued_at_ms"
        ] > MAX_CLOCK_SKEW_MS and not self.ledger.rpc_request_matches(
            client_id=client_id,
            request_id=request_id,
            request_hash=digest,
            method=method,
        ):
            raise LocalApiError("authentication_failed")
        try:
            cached = self.ledger.begin_rpc(
                client_id=client_id,
                request_id=request_id,
                request_hash=digest,
                method=method,
            )
        except LedgerEquivocationError:
            return create_response(
                capability,
                request_id=request_id,
                request_digest=digest,
                server=self.origin,
                completed_at_ms=self.clock(),
                error={"code": "request_conflict", "retryable": False},
            )
        if cached is not None:
            return verify_response(
                cached,
                capability,
                expected_request_id=request_id,
                expected_request_hash=digest,
                expected_server=self.origin,
            )
        try:
            result = self._dispatch(
                method,
                request["params"],
                client_id=client_id,
                request_id=request_id,
                request_hash=digest,
            )
            response = create_response(
                capability,
                request_id=request_id,
                request_digest=digest,
                server=self.origin,
                completed_at_ms=self.clock(),
                result=result,
            )
        except ServiceError as exception:
            response = create_response(
                capability,
                request_id=request_id,
                request_digest=digest,
                server=self.origin,
                completed_at_ms=self.clock(),
                error={"code": exception.code, "retryable": exception.retryable},
            )
        except LedgerEquivocationError:
            response = create_response(
                capability,
                request_id=request_id,
                request_digest=digest,
                server=self.origin,
                completed_at_ms=self.clock(),
                error={"code": "durable_conflict", "retryable": False},
            )
        except LedgerGapError:
            response = create_response(
                capability,
                request_id=request_id,
                request_digest=digest,
                server=self.origin,
                completed_at_ms=self.clock(),
                error={"code": "causal_gap", "retryable": True},
            )
        except (SyncProtocolError, WeaveProtocolError):
            response = create_response(
                capability,
                request_id=request_id,
                request_digest=digest,
                server=self.origin,
                completed_at_ms=self.clock(),
                error={"code": "protocol_rejected", "retryable": False},
            )
        except ProjectionError:
            response = create_response(
                capability,
                request_id=request_id,
                request_digest=digest,
                server=self.origin,
                completed_at_ms=self.clock(),
                error={"code": "projection_invalid", "retryable": False},
            )
        except (LedgerError, LedgerStateError):
            response = create_response(
                capability,
                request_id=request_id,
                request_digest=digest,
                server=self.origin,
                completed_at_ms=self.clock(),
                error={"code": "runtime_unavailable", "retryable": True},
            )
        except Exception:
            response = create_response(
                capability,
                request_id=request_id,
                request_digest=digest,
                server=self.origin,
                completed_at_ms=self.clock(),
                error={"code": "internal_error", "retryable": True},
            )
        stored = self.ledger.finish_rpc(
            client_id=client_id,
            request_id=request_id,
            request_hash=digest,
            method=method,
            response=response,
        )
        return verify_response(
            stored,
            capability,
            expected_request_id=request_id,
            expected_request_hash=digest,
            expected_server=self.origin,
        )

    def _dispatch(
        self,
        method: str,
        params: Any,
        *,
        client_id: str,
        request_id: str,
        request_hash: str,
    ) -> dict[str, Any]:
        if method == "runtime.status":
            _closed(params, set())
            self.ledger.integrity_check()
            return {
                "schema": "dm.runtime.status/v1",
                "being_ref": self.ledger.authority.manifest.being_ref,
                "manifest_hash": self.ledger.authority.manifest.digest,
                "local_origin": self.origin,
                "ledger_schema_version": SCHEMA_VERSION,
                "integrity": "ok",
                "counts": self.ledger.status_counts(),
            }
        if method == "we.heads":
            _closed(params, set())
            return SyncEngine(self.ledger).heads()
        if method == "we.preview":
            page = _closed(params, {"events"})["events"]
            if not isinstance(page, list):
                raise ServiceError("invalid_params")
            return self.ledger.preview(page)
        if method == "we.sync.request":
            request_params = _closed(params, {"limit", "request_id"})
            return SyncEngine(self.ledger).request(
                request_id=_uuid(request_params["request_id"]),
                limit=_uint(request_params["limit"], minimum=1, maximum=256),
            )
        if method == "we.sync.serve":
            request_params = _closed(params, {"request", "transport"})
            request_document = request_params["request"]
            if not isinstance(request_document, Mapping):
                raise ServiceError("invalid_params")
            self._bind_transport(
                _transport(request_params["transport"]),
                request_document.get("requester"),
            )
            return SyncEngine(self.ledger).serve(request_document)
        if method == "we.sync.pull":
            pull_params = _closed(params, {"delta", "transport"})
            delta = pull_params["delta"]
            if not isinstance(delta, Mapping):
                raise ServiceError("invalid_params")
            self._bind_transport(
                _transport(pull_params["transport"]), delta.get("sender")
            )
            return SyncEngine(self.ledger).pull(delta)
        if method == "we.sync.validate-receipt":
            receipt_params = _closed(params, {"receipt", "transport"})
            receipt = receipt_params["receipt"]
            if not isinstance(receipt, Mapping):
                raise ServiceError("invalid_params")
            self._bind_transport(
                _transport(receipt_params["transport"]), receipt.get("receiver")
            )
            return validate_receipt(
                receipt,
                self.ledger.authority,
                expected_sender=self.origin,
            )
        if method == "we.observe":
            return self._observe(
                params,
                client_id=client_id,
                request_id=request_id,
                request_hash=request_hash,
            )
        if method == "we.decide":
            return self._decide(
                params,
                client_id=client_id,
                request_id=request_id,
                request_hash=request_hash,
            )
        if method == "we.diff":
            return self._diff(params)
        if method == "we.projection.get":
            _closed(params, set())
            return {
                "schema": "dm.we.projection-cache/v1",
                "snapshot": ProjectionEngine(self.ledger).cached(),
            }
        if method == "we.projection.rebuild":
            _closed(params, set())
            return ProjectionEngine(self.ledger).rebuild()
        raise ServiceError("unknown_method")

    def _bind_transport(self, transport: Mapping[str, str], origin: Any) -> None:
        if not isinstance(origin, Mapping):
            raise ServiceError("invalid_transport_binding")
        try:
            self.ledger.authority.validate_transport_principal(
                origin,
                scheme=transport["scheme"],
                principal_id=transport["principal_id"],
            )
        except WeaveProtocolError as exception:
            raise ServiceError("invalid_transport_binding") from exception

    def _observe(
        self,
        params: Any,
        *,
        client_id: str,
        request_id: str,
        request_hash: str,
    ) -> dict[str, Any]:
        value = _closed(
            params,
            {
                "causal_parents",
                "event_id",
                "occurred_at_ms",
                "payload",
                "sensitivity",
                "subject",
            },
        )
        if not isinstance(value["payload"], Mapping):
            raise ServiceError("invalid_params")
        subject = _optional_text(value["subject"], 256)
        if subject is None or value["sensitivity"] not in SENSITIVITIES:
            raise ServiceError("invalid_params")
        occurred = value["occurred_at_ms"]
        event_id = value["event_id"]
        event = self.ledger.append_local_idempotent(
            client_id=client_id,
            request_id=request_id,
            request_hash=request_hash,
            kind="experience.observed",
            subject=subject,
            payload=value["payload"],
            signer=self.signer,
            sensitivity=value["sensitivity"],
            causal_parents=_event_ids(value["causal_parents"]),
            occurred_at_ms=None if occurred is None else _uint(occurred),
            event_id=None if event_id is None else _uuid(event_id),
        )
        return {"schema": "dm.we.observe-result/v1", "event": event}

    def _decide(
        self,
        params: Any,
        *,
        client_id: str,
        request_id: str,
        request_hash: str,
    ) -> dict[str, Any]:
        value = _closed(
            params,
            {
                "decision",
                "event_id",
                "occurred_at_ms",
                "reason",
                "sensitivity",
                "supersedes",
                "target_event_id",
            },
        )
        target_id = _uuid(value["target_event_id"])
        target = self.ledger.event(target_id)
        if target is None:
            raise ServiceError("unknown_target")
        decision = value["decision"]
        reason = _optional_text(value["reason"], 1024)
        supersedes = value["supersedes"]
        if (
            decision not in DECISIONS
            or reason is None
            or value["sensitivity"] not in SENSITIVITIES
            or (supersedes is not None and not isinstance(supersedes, str))
        ):
            raise ServiceError("invalid_params")
        snapshot = ProjectionEngine(self.ledger).snapshot()
        entry = next(
            (item for item in snapshot["entries"] if item["event_id"] == target_id),
            None,
        )
        if entry is None:
            raise ServiceError("target_not_projectable")
        if entry["state"] == "failed":
            raise ServiceError("decision_chain_failed")
        chain = entry["local_decision_chain"]
        expected = None if not chain else chain[-1]
        if supersedes != expected or (decision == "revert" and expected is None):
            raise ServiceError("decision_predecessor_mismatch")
        occurred = value["occurred_at_ms"]
        event_id = value["event_id"]
        event = self.ledger.append_local_idempotent(
            client_id=client_id,
            request_id=request_id,
            request_hash=request_hash,
            kind="adoption.decided",
            subject=target["subject"],
            payload={
                "target_event_id": target_id,
                "decision": decision,
                "reason": reason,
            },
            signer=self.signer,
            sensitivity=value["sensitivity"],
            causal_parents=[target_id],
            supersedes=expected,
            occurred_at_ms=None if occurred is None else _uint(occurred),
            event_id=None if event_id is None else _uuid(event_id),
        )
        return {"schema": "dm.we.decision-result/v1", "event": event}

    def _diff(self, params: Any) -> dict[str, Any]:
        value = _closed(params, {"after", "kind", "limit", "subject"})
        kind = _optional_text(value["kind"], 128)
        subject = _optional_text(value["subject"], 256)
        after = value["after"]
        if after is not None:
            after = _uuid(after)
        limit = _uint(value["limit"], minimum=1, maximum=256)
        snapshot = ProjectionEngine(self.ledger).snapshot()
        entries = [
            entry
            for entry in snapshot["entries"]
            if (kind is None or entry["kind"] == kind)
            and (subject is None or entry["subject"] == subject)
            and (after is None or entry["event_id"] > after)
        ]
        page = entries[:limit]
        more = len(entries) > limit
        return {
            "schema": "dm.we.diff-page/v1",
            "projection_hash": snapshot["projection_hash"],
            "entries": page,
            "more": more,
            "next_after": page[-1]["event_id"] if more and page else None,
        }


__all__ = ["METHODS", "HostedWeave", "ServiceError"]
