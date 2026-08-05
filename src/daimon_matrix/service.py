"""Authenticated method dispatcher for one hosted embodiment Weave runtime."""

from __future__ import annotations

import copy
import hashlib
import unicodedata
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Final

from .canonical import CanonicalError, b64url, canonical_bytes, unb64url
from .communication import CommunicationError, CommunicationStore
from .curator import CuratorCoordinator, CuratorError
from .human_review import HumanReviewCoordinator, HumanReviewError
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
from .memory_policy import (
    MemoryExecutionError,
    MemoryPolicyError,
    MemoryPolicyExecutor,
    evaluate_memory_candidate,
    memory_checkpoint,
)
from .memory_projection import MemoryProjectionError, current_memory_projection
from .projections import ProjectionEngine, ProjectionError
from .routes import RouteCoordinator, RouteError
from .scopes import ScopeError, ScopeResolver
from .sources import SourceError, SourceServiceContext
from .species import APPLICATION_EVENT_KIND, SpeciesError, SpeciesServiceContext
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
COMMUNICATION_METHODS: Final = frozenset(
    {
        "communication.accept",
        "communication.attempt",
        "communication.claim",
        "communication.compact",
        "communication.cursor.advance",
        "communication.delivery",
        "communication.page",
        "communication.rebuild-plan",
        "communication.receipt.record",
        "communication.result",
        "communication.route-ack",
    }
)
ROUTE_METHODS: Final = frozenset({"route.inspect", "route.submit"})
MEMORY_METHODS: Final = frozenset({"memory.evaluate", "memory.execute"})
BODY_METHODS: Final = frozenset({"memory.context"})
CURATOR_METHODS: Final = frozenset(
    {"curator.claim", "curator.complete", "curator.enqueue", "curator.inspect"}
)
REVIEW_METHODS: Final = frozenset(
    {
        "review.authorize",
        "review.revoke",
        "review.request",
        "review.queue",
        "review.inspect",
        "review.decision.draft",
        "review.decision.submit",
        "review.execute",
    }
)
SCOPE_METHODS: Final = frozenset(
    {
        "scope.me",
        "scope.resolve",
        "scope.tribe",
        "scope.we",
        "scope.we.diff",
        "scope.we.sync-plan",
    }
)
SPECIES_METHODS: Final = frozenset(
    {
        "species.apply",
        "species.genesis.ingest",
        "species.incoming",
        "species.release.ingest",
        "species.rollback",
    }
)
SOURCE_METHODS: Final = frozenset(
    {
        "source.assess",
        "source.claim",
        "source.content.put",
        "source.cursor.create",
        "source.diff",
        "source.incoming",
        "source.import.decide",
        "source.projection",
        "source.promote",
        "source.publication.append",
        "source.pull",
        "source.status",
    }
)
SERVICE_METHODS: Final = (
    BODY_METHODS
    | METHODS
    | COMMUNICATION_METHODS
    | CURATOR_METHODS
    | MEMORY_METHODS
    | REVIEW_METHODS
    | ROUTE_METHODS
    | SCOPE_METHODS
    | SPECIES_METHODS
    | SOURCE_METHODS
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


def _text_refs(value: Any) -> list[str]:
    if (
        not isinstance(value, list)
        or len(value) > 256
        or value != sorted(set(value))
        or any(
            not isinstance(item, str) or not 1 <= len(item.encode("utf-8")) <= 256
            for item in value
        )
    ):
        raise ServiceError("invalid_params")
    return list(value)


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
    communication: CommunicationStore | None = None
    router: RouteCoordinator | None = None
    scopes: ScopeResolver | None = None
    curator: CuratorCoordinator | None = None
    review: HumanReviewCoordinator | None = None
    species: SpeciesServiceContext | None = None
    sources: SourceServiceContext | None = None

    def __post_init__(self) -> None:
        if self.ledger.authority.manifest.trust_mode != "root-bound":
            raise ServiceError("hosted_runtime_requires_root_authority")
        if not self.capabilities:
            raise ServiceError("runtime_requires_capability")
        seen_clients: set[tuple[str, str]] = set()
        for capability_id, capability in self.capabilities.items():
            if capability_id != capability.capability_id:
                raise ServiceError("capability_index_mismatch")
            if not set(capability.methods) <= SERVICE_METHODS:
                raise ServiceError("unsupported_capability_method")
            marker = (capability.client_id, capability.capability_id)
            if marker in seen_clients:
                raise ServiceError("duplicate_capability")
            seen_clients.add(marker)
        self.ledger.authority.validate_origin(
            self.ledger.local_origin, require_active=True
        )
        self.ledger.initialize()
        communication = self.communication
        if communication is None:
            communication = CommunicationStore(self.ledger, clock=self.clock)
            object.__setattr__(self, "communication", communication)
        elif communication.ledger is not self.ledger:
            raise ServiceError("communication_ledger_mismatch")
        communication.initialize()
        if self.router is not None and self.router.store is not communication:
            raise ServiceError("route_store_mismatch")
        scopes = self.scopes
        if scopes is None:
            scopes = ScopeResolver(self.ledger, clock=self.clock, router=self.router)
            object.__setattr__(self, "scopes", scopes)
        elif scopes.ledger is not self.ledger or scopes.router is not self.router:
            raise ServiceError("scope_resolver_mismatch")
        curator = self.curator
        if curator is None:
            curator = CuratorCoordinator(self.ledger, self.clock)
            object.__setattr__(self, "curator", curator)
        elif curator.ledger is not self.ledger:
            raise ServiceError("curator_ledger_mismatch")
        curator.initialize()
        review = self.review
        if review is None:
            review = HumanReviewCoordinator(self.ledger, self.signer, self.clock)
            object.__setattr__(self, "review", review)
        elif review.ledger is not self.ledger or review.signer is not self.signer:
            raise ServiceError("review_coordinator_mismatch")
        if self.sources is not None:
            if self.sources.registry.ledger is not self.ledger:
                raise ServiceError("source_registry_ledger_mismatch")
            self.sources.registry.initialize()

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
            verified = verify_response(
                cached,
                capability,
                expected_request_id=request_id,
                expected_request_hash=digest,
                expected_server=self.origin,
            )
            if method == "curator.complete" and verified["ok"]:
                curator = self.curator
                result = verified["result"]
                if curator is None or not isinstance(result, Mapping):
                    raise LocalApiError("invalid_local_response")
                try:
                    curator.verify_result_truth(result)
                except CuratorError as exception:
                    return create_response(
                        capability,
                        request_id=request_id,
                        request_digest=digest,
                        server=self.origin,
                        completed_at_ms=self.clock(),
                        error={
                            "code": exception.code,
                            "retryable": exception.retryable,
                        },
                    )
            return verified
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
        except CommunicationError as exception:
            response = create_response(
                capability,
                request_id=request_id,
                request_digest=digest,
                server=self.origin,
                completed_at_ms=self.clock(),
                error={"code": exception.code, "retryable": exception.retryable},
            )
        except RouteError as exception:
            response = create_response(
                capability,
                request_id=request_id,
                request_digest=digest,
                server=self.origin,
                completed_at_ms=self.clock(),
                error={"code": exception.code, "retryable": exception.retryable},
            )
        except ScopeError as exception:
            response = create_response(
                capability,
                request_id=request_id,
                request_digest=digest,
                server=self.origin,
                completed_at_ms=self.clock(),
                error={"code": exception.code, "retryable": exception.retryable},
            )
        except MemoryPolicyError:
            response = create_response(
                capability,
                request_id=request_id,
                request_digest=digest,
                server=self.origin,
                completed_at_ms=self.clock(),
                error={"code": "memory_artifact_rejected", "retryable": False},
            )
        except MemoryExecutionError as exception:
            response = create_response(
                capability,
                request_id=request_id,
                request_digest=digest,
                server=self.origin,
                completed_at_ms=self.clock(),
                error={"code": str(exception), "retryable": False},
            )
        except CuratorError as exception:
            response = create_response(
                capability,
                request_id=request_id,
                request_digest=digest,
                server=self.origin,
                completed_at_ms=self.clock(),
                error={"code": exception.code, "retryable": exception.retryable},
            )
        except HumanReviewError as exception:
            response = create_response(
                capability,
                request_id=request_id,
                request_digest=digest,
                server=self.origin,
                completed_at_ms=self.clock(),
                error={"code": exception.code, "retryable": exception.retryable},
            )
        except SpeciesError as exception:
            response = create_response(
                capability,
                request_id=request_id,
                request_digest=digest,
                server=self.origin,
                completed_at_ms=self.clock(),
                error={"code": exception.code, "retryable": exception.incomplete},
            )
        except SourceError as exception:
            response = create_response(
                capability,
                request_id=request_id,
                request_digest=digest,
                server=self.origin,
                completed_at_ms=self.clock(),
                error={
                    "code": exception.code,
                    "retryable": exception.retryable or exception.incomplete,
                },
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
        communication = self.communication
        if communication is None:  # established in __post_init__
            raise ServiceError("communication_unavailable")
        scopes = self.scopes
        if scopes is None:  # established in __post_init__
            raise ServiceError("scope_resolver_absent")
        if method == "scope.me":
            _closed(params, set())
            return scopes.me()
        if method == "scope.we":
            _closed(params, set())
            return scopes.we()
        if method == "scope.we.diff":
            _closed(params, set())
            return scopes.diff()
        if method == "scope.we.sync-plan":
            value = _closed(params, {"limit", "request_id"})
            return scopes.sync_plan(
                request_id=_uuid(value["request_id"]),
                limit=_uint(value["limit"], minimum=1, maximum=256),
            )
        if method == "scope.tribe":
            value = _closed(params, {"tribe_ref"})
            tribe_ref = _optional_text(value["tribe_ref"], 256)
            if tribe_ref is None:
                raise ServiceError("invalid_params")
            return scopes.tribe(tribe_ref=tribe_ref)
        if method == "scope.resolve":
            value = _closed(params, {"request_id", "scope", "tribe_ref"})
            scope = _optional_text(value["scope"], 32)
            tribe_ref = _optional_text(value["tribe_ref"], 256)
            if scope is None:
                raise ServiceError("invalid_params")
            return scopes.resolution(
                scope=scope,
                request_id=_uuid(value["request_id"]),
                tribe_ref=tribe_ref,
            )
        if method.startswith("source."):
            sources = self.sources
            if sources is None:
                raise ServiceError("source_runtime_unavailable")
            registry = sources.registry
            if method == "source.content.put":
                value = _closed(params, {"data", "media_type"})
                data = value["data"]
                media_type = value["media_type"]
                if not isinstance(data, str) or not isinstance(media_type, str):
                    raise ServiceError("invalid_params")
                try:
                    raw = unb64url(data)
                except CanonicalError as exception:
                    raise ServiceError("invalid_params") from exception
                return registry.cas.put(raw, media_type)
            if method in {
                "source.claim",
                "source.assess",
                "source.publication.append",
                "source.import.decide",
            }:
                value = _closed(params, {"payload"})
                payload = value["payload"]
                if not isinstance(payload, Mapping):
                    raise ServiceError("invalid_params")
                if method == "source.claim":
                    return registry.append_claim(payload, signer=self.signer)
                if method == "source.assess":
                    return registry.append_assessment(payload, signer=self.signer)
                if method == "source.publication.append":
                    return registry.append_publication(payload, signer=self.signer)
                return registry.append_import_decision(payload, signer=self.signer)
            if method == "source.status":
                value = _closed(params, {"selector"})
                selector = value["selector"]
                if not isinstance(selector, Mapping):
                    raise ServiceError("invalid_params")
                return registry.status(selector)
            if method == "source.cursor.create":
                value = _closed(params, {"selector"})
                selector = value["selector"]
                if not isinstance(selector, Mapping):
                    raise ServiceError("invalid_params")
                return registry.create_cursor(selector, signer=self.signer)
            if method == "source.diff":
                value = _closed(
                    params,
                    {
                        "continuation",
                        "max_bytes",
                        "max_items",
                        "request_event_id",
                        "requester_cursor",
                        "requester_me_id",
                        "selector",
                    },
                )
                for field in ("selector", "requester_cursor"):
                    if not isinstance(value[field], Mapping):
                        raise ServiceError("invalid_params")
                continuation = value["continuation"]
                if continuation is not None and not isinstance(continuation, Mapping):
                    raise ServiceError("invalid_params")
                requester = _optional_text(value["requester_me_id"], 240)
                if requester is None:
                    raise ServiceError("invalid_params")
                return registry.diff(
                    selector=value["selector"],
                    request_event_id=_uuid(value["request_event_id"]),
                    requester_me_id=requester,
                    requester_cursor=value["requester_cursor"],
                    max_items=_uint(value["max_items"], minimum=1, maximum=4096),
                    max_bytes=_uint(value["max_bytes"], minimum=1, maximum=268_435_456),
                    continuation=continuation,
                )
            if method == "source.incoming":
                value = _closed(params, {"bundle"})
                if not isinstance(value["bundle"], Mapping):
                    raise ServiceError("invalid_params")
                return registry.incoming(value["bundle"])
            if method == "source.pull":
                value = _closed(params, {"bundle", "operation_id", "preview"})
                if not isinstance(value["bundle"], Mapping) or not isinstance(
                    value["preview"], Mapping
                ):
                    raise ServiceError("invalid_params")
                return registry.pull(
                    operation_id=_uuid(value["operation_id"]),
                    bundle=value["bundle"],
                    preview=value["preview"],
                    signer=self.signer,
                )
            if method == "source.promote":
                value = _closed(
                    params,
                    {
                        "evidence_snapshot_ref",
                        "policy_ref",
                        "publication_id",
                    },
                )
                if not isinstance(value["policy_ref"], Mapping) or not isinstance(
                    value["evidence_snapshot_ref"], Mapping
                ):
                    raise ServiceError("invalid_params")
                publication_identifier = _optional_text(value["publication_id"], 160)
                if publication_identifier is None:
                    raise ServiceError("invalid_params")
                return registry.promote(
                    publication_identifier=publication_identifier,
                    policy_ref=value["policy_ref"],
                    evidence_snapshot_ref=value["evidence_snapshot_ref"],
                    signer=self.signer,
                )
            if method == "source.projection":
                value = _closed(params, {"publication_id"})
                publication_identifier = _optional_text(value["publication_id"], 160)
                if publication_identifier is None:
                    raise ServiceError("invalid_params")
                return registry.promotion_projection(publication_identifier)
            raise ServiceError("unsupported_method")
        if method.startswith("species."):
            species = self.species
            if species is None:
                raise ServiceError("species_runtime_unavailable")
            if method == "species.genesis.ingest":
                value = _closed(params, {"artifact"})
                artifact = value["artifact"]
                if not isinstance(artifact, Mapping):
                    raise ServiceError("invalid_params")
                return species.registry.ingest_genesis(artifact)
            if method == "species.release.ingest":
                value = _closed(params, {"artifact"})
                artifact = value["artifact"]
                if not isinstance(artifact, Mapping):
                    raise ServiceError("invalid_params")
                ingested = species.registry.ingest_release(artifact)
                if (
                    ingested["state"] == "quarantined"
                    and ingested["species_id"] == species.species_id
                    and species.pointer_path.exists()
                ):
                    snapshot = species.registry.incoming(
                        subject_me_id=self.ledger.authority.manifest.being_ref,
                        species_id=species.species_id,
                        enrollment_release_id=species.enrollment_release_id,
                        local_policy_ref=species.local_policy_ref,
                    )
                    core = snapshot["snapshot_core"]
                    if core["effective_applied_release"] is not None and any(
                        item["kind"] == "release-position"
                        for item in core["conflict_refs"]
                    ):
                        application_head = core["application_head"]
                        if application_head is None:
                            raise SpeciesError(
                                "species_release_fork_without_application"
                            )
                        rollback_operation = str(
                            uuid.uuid5(
                                uuid.NAMESPACE_URL,
                                "daimon/species-release-fork-rollback/v0\x00"
                                + self.ledger.authority.manifest.being_ref
                                + "\x00"
                                + ingested["artifact_id"]
                                + "\x00"
                                + application_head["event_id"],
                            )
                        )
                        fork_capability_hash = b64url(
                            hashlib.sha256(
                                canonical_bytes(sorted(self.capabilities))
                            ).digest()
                        )

                        def append_release_fork_rollback(
                            payload: Mapping[str, Any],
                        ) -> Mapping[str, Any]:
                            previous = payload["previous_application"]
                            causal = [] if previous is None else [previous["event_id"]]
                            return self.ledger.append_local(
                                kind=APPLICATION_EVENT_KIND,
                                subject=self.ledger.authority.manifest.being_ref,
                                payload=payload,
                                signer=self.signer,
                                sensitivity="private",
                                causal_parents=causal,
                                occurred_at_ms=payload["applied_at_ms"],
                                event_id=str(
                                    uuid.uuid5(
                                        uuid.UUID(rollback_operation),
                                        APPLICATION_EVENT_KIND,
                                    )
                                ),
                            )

                        ingested["rollback"] = species.registry.rollback(
                            operation_id=rollback_operation,
                            snapshot=snapshot,
                            local_policy_ref=species.local_policy_ref,
                            capability_grant_set_hash=fork_capability_hash,
                            pointer_path=species.pointer_path,
                            applied_at_ms=self.clock(),
                            reason="release-fork",
                            append_event=append_release_fork_rollback,
                        )
                return ingested
            if method == "species.incoming":
                value = _closed(
                    params,
                    {
                        "expected_occupied_positions_hash",
                        "page_index",
                        "selected_candidate_id",
                    },
                )
                return species.registry.incoming(
                    subject_me_id=self.ledger.authority.manifest.being_ref,
                    species_id=species.species_id,
                    enrollment_release_id=species.enrollment_release_id,
                    selected_candidate_id=_optional_text(
                        value["selected_candidate_id"], 160
                    ),
                    local_policy_ref=species.local_policy_ref,
                    page_index=_uint(value["page_index"]),
                    expected_occupied_positions_hash=_optional_text(
                        value["expected_occupied_positions_hash"], 43
                    ),
                )
            if method == "species.apply":
                value = _closed(params, {"operation_id", "snapshot"})
                snapshot = value["snapshot"]
                if not isinstance(snapshot, Mapping):
                    raise ServiceError("invalid_params")
                operation_id = _uuid(value["operation_id"])
                apply_capability_digest = hashlib.sha256(
                    canonical_bytes(sorted(self.capabilities))
                ).digest()

                def append_application(
                    payload: Mapping[str, Any],
                ) -> Mapping[str, Any]:
                    previous = payload["previous_application"]
                    causal = [] if previous is None else [previous["event_id"]]
                    event_id = str(
                        uuid.uuid5(uuid.UUID(operation_id), APPLICATION_EVENT_KIND)
                    )
                    return self.ledger.append_local(
                        kind=APPLICATION_EVENT_KIND,
                        subject=self.ledger.authority.manifest.being_ref,
                        payload=payload,
                        signer=self.signer,
                        sensitivity="private",
                        causal_parents=causal,
                        occurred_at_ms=payload["applied_at_ms"],
                        event_id=event_id,
                    )

                return species.registry.apply(
                    operation_id=operation_id,
                    snapshot=snapshot,
                    local_policy_ref=species.local_policy_ref,
                    capability_grant_set_hash=b64url(apply_capability_digest),
                    pointer_path=species.pointer_path,
                    applied_at_ms=self.clock(),
                    append_event=append_application,
                )
            if method == "species.rollback":
                value = _closed(params, {"operation_id", "reason", "snapshot"})
                snapshot = value["snapshot"]
                reason = value["reason"]
                if not isinstance(snapshot, Mapping) or reason not in {
                    "release-fork",
                    "runtime-failure",
                }:
                    raise ServiceError("invalid_params")
                operation_id = _uuid(value["operation_id"])
                rollback_capability_digest = hashlib.sha256(
                    canonical_bytes(sorted(self.capabilities))
                ).digest()

                def append_rollback(
                    payload: Mapping[str, Any],
                ) -> Mapping[str, Any]:
                    previous = payload["previous_application"]
                    causal = [] if previous is None else [previous["event_id"]]
                    event_id = str(
                        uuid.uuid5(uuid.UUID(operation_id), APPLICATION_EVENT_KIND)
                    )
                    return self.ledger.append_local(
                        kind=APPLICATION_EVENT_KIND,
                        subject=self.ledger.authority.manifest.being_ref,
                        payload=payload,
                        signer=self.signer,
                        sensitivity="private",
                        causal_parents=causal,
                        occurred_at_ms=payload["applied_at_ms"],
                        event_id=event_id,
                    )

                return species.registry.rollback(
                    operation_id=operation_id,
                    snapshot=snapshot,
                    local_policy_ref=species.local_policy_ref,
                    capability_grant_set_hash=b64url(rollback_capability_digest),
                    pointer_path=species.pointer_path,
                    applied_at_ms=self.clock(),
                    reason=reason,
                    append_event=append_rollback,
                )
        if method == "review.authorize":
            value = _closed(params, {"authorization"})
            if not isinstance(value["authorization"], Mapping):
                raise ServiceError("invalid_params")
            if self.review is None:
                raise ServiceError("review_unavailable")
            return self.review.authorize(
                value["authorization"],
                client_id=client_id,
                request_id=request_id,
            )
        if method == "review.revoke":
            value = _closed(params, {"authorization_id", "reason"})
            authorization_id = _optional_text(value["authorization_id"], 160)
            reason = _optional_text(value["reason"], 256)
            if authorization_id is None or reason is None:
                raise ServiceError("invalid_params")
            if self.review is None:
                raise ServiceError("review_unavailable")
            return self.review.revoke(
                authorization_id,
                reason=reason,
                client_id=client_id,
                request_id=request_id,
            )
        if method == "review.request":
            value = _closed(params, {"request"})
            if not isinstance(value["request"], Mapping):
                raise ServiceError("invalid_params")
            if self.review is None:
                raise ServiceError("review_unavailable")
            return self.review.request_review(
                value["request"],
                client_id=client_id,
                request_id=request_id,
            )
        if method == "review.queue":
            value = _closed(
                params,
                {"access_proof", "after", "authorization_id", "limit"},
            )
            if not isinstance(value["access_proof"], Mapping):
                raise ServiceError("invalid_params")
            authorization_id = _optional_text(value["authorization_id"], 160)
            after = _optional_text(value["after"], 160)
            if authorization_id is None:
                raise ServiceError("invalid_params")
            if self.review is None:
                raise ServiceError("review_unavailable")
            return self.review.queue(
                authorization_id=authorization_id,
                access_proof=value["access_proof"],
                rpc_request_id=request_id,
                after=after,
                limit=_uint(value["limit"], minimum=1, maximum=100),
            )
        if method == "review.inspect":
            value = _closed(
                params,
                {"access_proof", "authorization_id", "review_request_id"},
            )
            if not isinstance(value["access_proof"], Mapping):
                raise ServiceError("invalid_params")
            authorization_id = _optional_text(value["authorization_id"], 160)
            review_request_id = _optional_text(value["review_request_id"], 160)
            if authorization_id is None or review_request_id is None:
                raise ServiceError("invalid_params")
            if self.review is None:
                raise ServiceError("review_unavailable")
            return self.review.inspect(
                review_request_id=review_request_id,
                authorization_id=authorization_id,
                access_proof=value["access_proof"],
                rpc_request_id=request_id,
            )
        if method == "review.decision.draft":
            value = _closed(
                params,
                {
                    "action",
                    "authorization_id",
                    "decision_nonce",
                    "decided_at_ms",
                    "note_ref",
                    "predecessor_decision_id",
                    "reason",
                    "replacement",
                    "review_request_id",
                },
            )
            if self.review is None:
                raise ServiceError("review_unavailable")
            review_request_id = _optional_text(value["review_request_id"], 160)
            authorization_id = _optional_text(value["authorization_id"], 160)
            action = _optional_text(value["action"], 32)
            reason = _optional_text(value["reason"], 1024)
            note_ref = _optional_text(value["note_ref"], 256)
            decision_nonce = _optional_text(value["decision_nonce"], 36)
            predecessor = _optional_text(value["predecessor_decision_id"], 160)
            replacement = value["replacement"]
            if replacement is not None and not isinstance(replacement, Mapping):
                raise ServiceError("invalid_params")
            if (
                review_request_id is None
                or authorization_id is None
                or action is None
                or reason is None
                or decision_nonce is None
            ):
                raise ServiceError("invalid_params")
            return self.review.draft(
                review_request_id=review_request_id,
                authorization_id=authorization_id,
                action=action,
                replacement=replacement,
                reason=reason,
                note_ref=note_ref,
                decision_nonce=decision_nonce,
                decided_at_ms=_uint(value["decided_at_ms"]),
                predecessor_decision_id=predecessor,
            )
        if method == "review.decision.submit":
            value = _closed(params, {"decision"})
            if not isinstance(value["decision"], Mapping):
                raise ServiceError("invalid_params")
            if self.review is None:
                raise ServiceError("review_unavailable")
            return self.review.submit(
                value["decision"],
                client_id=client_id,
                request_id=request_id,
            )
        if method == "review.execute":
            value = _closed(params, {"review_request_id"})
            review_request_id = _optional_text(value["review_request_id"], 160)
            if review_request_id is None:
                raise ServiceError("invalid_params")
            if self.review is None:
                raise ServiceError("review_unavailable")
            return self.review.execute(
                review_request_id,
                client_id=client_id,
                request_id=request_id,
            )
        if method == "memory.evaluate":
            value = _closed(params, {"candidate", "policy"})
            if not isinstance(value["candidate"], Mapping) or not isinstance(
                value["policy"], Mapping
            ):
                raise ServiceError("invalid_params")
            evaluated_at_ms = self.clock()
            checkpoint = memory_checkpoint(
                self.ledger,
                value["candidate"],
                captured_at_ms=evaluated_at_ms,
            )
            return evaluate_memory_candidate(
                value["policy"],
                value["candidate"],
                checkpoint,
                evaluated_at_ms=evaluated_at_ms,
            )
        if method == "memory.context":
            value = _closed(params, {"limit", "query"})
            query = value["query"]
            if not isinstance(query, str):
                raise ServiceError("invalid_params")
            normalized_query = unicodedata.normalize("NFC", query)
            try:
                query_bytes = normalized_query.encode("utf-8")
            except UnicodeEncodeError as exception:
                raise ServiceError("invalid_params") from exception
            if not 1 <= len(query_bytes) <= 4096 or any(
                ord(character) < 0x20 or ord(character) == 0x7F for character in query
            ):
                raise ServiceError("invalid_params")
            limit = _uint(value["limit"], minimum=1, maximum=64)
            try:
                projection = current_memory_projection(self.ledger, limit=limit)
            except MemoryProjectionError as exception:
                raise ServiceError(
                    exception.code, retryable=exception.retryable
                ) from exception
            return {
                "schema": "dm.memory.context/v1",
                "query_hash": hashlib.sha256(
                    normalized_query.encode("utf-8")
                ).hexdigest(),
                "projection": projection,
            }
        if method == "memory.execute":
            value = _closed(params, {"candidate", "plan", "policy"})
            if any(
                not isinstance(value[field], Mapping)
                for field in ("candidate", "plan", "policy")
            ):
                raise ServiceError("invalid_params")
            return MemoryPolicyExecutor(
                self.ledger,
                self.signer,
                self.clock,
            ).execute(
                value["plan"],
                value["policy"],
                value["candidate"],
                client_id=client_id,
                request_id=request_id,
            )
        if method == "curator.enqueue":
            value = _closed(params, {"item"})
            if not isinstance(value["item"], Mapping):
                raise ServiceError("invalid_params")
            if self.curator is None:
                raise ServiceError("curator_unavailable")
            return self.curator.enqueue(
                value["item"], client_id=client_id, request_id=request_id
            )
        if method == "curator.claim":
            value = _closed(
                params,
                {
                    "claim_id",
                    "expected_generation",
                    "fence_evidence",
                    "item_id",
                    "lease_until_ms",
                },
            )
            fence_evidence = value["fence_evidence"]
            if fence_evidence is not None and not isinstance(fence_evidence, Mapping):
                raise ServiceError("invalid_params")
            if self.curator is None:
                raise ServiceError("curator_unavailable")
            return self.curator.claim(
                item_id=str(value["item_id"]),
                claim_id=_uuid(value["claim_id"]),
                expected_generation=_uint(value["expected_generation"]),
                lease_until_ms=_uint(value["lease_until_ms"]),
                fence_evidence=fence_evidence,
                client_id=client_id,
                request_id=request_id,
            )
        if method == "curator.complete":
            value = _closed(
                params,
                {
                    "claim_id",
                    "effect_receipt",
                    "expected_generation",
                    "outcome",
                    "output_refs",
                },
            )
            effect_receipt = value["effect_receipt"]
            if effect_receipt is not None and not isinstance(effect_receipt, Mapping):
                raise ServiceError("invalid_params")
            if not isinstance(value["outcome"], str):
                raise ServiceError("invalid_params")
            if self.curator is None:
                raise ServiceError("curator_unavailable")
            return self.curator.complete(
                claim_id=_uuid(value["claim_id"]),
                expected_generation=_uint(value["expected_generation"], minimum=1),
                outcome=value["outcome"],
                output_refs=_text_refs(value["output_refs"]),
                effect_receipt=effect_receipt,
                client_id=client_id,
                request_id=request_id,
            )
        if method == "curator.inspect":
            value = _closed(params, {"item_id"})
            if not isinstance(value["item_id"], str):
                raise ServiceError("invalid_params")
            if self.curator is None:
                raise ServiceError("curator_unavailable")
            return self.curator.inspect(value["item_id"])
        if method == "route.inspect":
            value = _closed(params, {"leg_id"})
            if self.router is None:
                raise ServiceError("route_profile_absent")
            return self.router.inspect(leg_id=value["leg_id"])
        if method == "route.submit":
            value = _closed(params, {"deadline_ms", "envelope", "leg_id"})
            if self.router is None:
                raise ServiceError("route_profile_absent")
            try:
                envelope = unb64url(value["envelope"])
            except (CanonicalError, TypeError, ValueError) as exception:
                raise ServiceError("invalid_params") from exception
            return self.router.dispatch(
                leg_id=value["leg_id"],
                envelope=envelope,
                deadline_ms=_uint(value["deadline_ms"]),
            )
        if method == "communication.accept":
            value = _closed(params, {"message_event_id", "resolution_event_id"})
            return communication.accept(
                message_event_id=_uuid(value["message_event_id"]),
                resolution_event_id=_uuid(value["resolution_event_id"]),
            )
        if method == "communication.result":
            value = _closed(params, {"message_id", "require_terminal"})
            if not isinstance(value["require_terminal"], bool):
                raise ServiceError("invalid_params")
            return communication.result(
                _uuid(value["message_id"]),
                require_terminal=value["require_terminal"],
            )
        if method == "communication.rebuild-plan":
            value = _closed(params, {"message_id"})
            return communication.rebuild_plan(_uuid(value["message_id"]))
        if method == "communication.attempt":
            value = _closed(params, {"attempt"})
            return communication.record_attempt(value["attempt"])
        if method == "communication.claim":
            value = _closed(
                params,
                {
                    "claim_id",
                    "consumer_id",
                    "lease_until_ms",
                    "limit",
                    "recipient_id",
                },
            )
            return communication.claim(
                recipient_id=value["recipient_id"],
                consumer_id=value["consumer_id"],
                claim_id=_uuid(value["claim_id"]),
                limit=_uint(value["limit"], minimum=1, maximum=256),
                lease_until_ms=_uint(value["lease_until_ms"]),
            )
        if method == "communication.delivery":
            value = _closed(params, {"attempt_id", "delivery_id", "envelope_hash"})
            return communication.record_delivery(
                attempt_id=_uuid(value["attempt_id"]),
                delivery_id=_uuid(value["delivery_id"]),
                envelope_hash=value["envelope_hash"],
            )
        if method == "communication.route-ack":
            value = _closed(params, {"ack", "attempt_id", "failed"})
            if not isinstance(value["ack"], Mapping) or not isinstance(
                value["failed"], bool
            ):
                raise ServiceError("invalid_params")
            return communication.record_route_ack(
                attempt_id=_uuid(value["attempt_id"]),
                ack=value["ack"],
                failed=value["failed"],
            )
        if method == "communication.receipt.record":
            value = _closed(params, {"receipt_event_id"})
            return communication.record_receipt(_uuid(value["receipt_event_id"]))
        if method == "communication.page":
            value = _closed(
                params,
                {
                    "consumer_id",
                    "cursor",
                    "limit",
                    "recipient_id",
                    "request_id",
                },
            )
            cursor = value["cursor"]
            if cursor is not None and not isinstance(cursor, str):
                raise ServiceError("invalid_params")
            return communication.page(
                recipient_id=value["recipient_id"],
                consumer_id=value["consumer_id"],
                request_id=_uuid(value["request_id"]),
                cursor=cursor,
                limit=_uint(value["limit"], minimum=1, maximum=256),
            )
        if method == "communication.cursor.advance":
            value = _closed(params, {"consumer_id", "recipient_id", "sequence"})
            return communication.advance_consumer(
                recipient_id=value["recipient_id"],
                consumer_id=value["consumer_id"],
                sequence=_uint(value["sequence"]),
            )
        if method == "communication.compact":
            value = _closed(params, {"recipient_id", "through_sequence"})
            return communication.compact(
                recipient_id=value["recipient_id"],
                through_sequence=_uint(value["through_sequence"]),
            )
        if method == "runtime.status":
            _closed(params, set())
            self.ledger.integrity_check()
            accepted = tuple(
                getattr(
                    self.ledger.authority,
                    "accepted_manifest_hashes",
                    (self.ledger.authority.manifest.digest,),
                )
            )
            return {
                "schema": "dm.runtime.status/v1",
                "being_ref": self.ledger.authority.manifest.being_ref,
                "manifest_hash": self.ledger.authority.manifest.digest,
                "local_origin": self.origin,
                "ledger_schema_version": SCHEMA_VERSION,
                "integrity": "ok",
                "counts": self.ledger.status_counts(),
                "authority_epoch": {
                    "schema": "dm.we.authority-epoch-status/v1",
                    "active_manifest_hash": self.ledger.authority.manifest.digest,
                    "accepted_manifest_hashes": list(accepted),
                    "epoch_count": len(accepted),
                },
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


__all__ = [
    "BODY_METHODS",
    "COMMUNICATION_METHODS",
    "MEMORY_METHODS",
    "METHODS",
    "SCOPE_METHODS",
    "SERVICE_METHODS",
    "SOURCE_METHODS",
    "HostedWeave",
    "ServiceError",
]
