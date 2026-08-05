"""Deterministic personal-memory policy and guarded ledger executor."""

from __future__ import annotations

import copy
import hashlib
import re
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

from .canonical import CanonicalError, b64url, canonical_bytes, unb64url
from .ledger import Ledger, LedgerStateError
from .projections import ProjectionEngine
from .weave import Event, EventSigner

POLICY_SCHEMA: Final = "dm.memory.policy/v1"
CONTENT_REF_SCHEMA: Final = "dm.memory.content-ref/v1"
CANDIDATE_SCHEMA: Final = "dm.memory.candidate/v1"
CHECKPOINT_SCHEMA: Final = "dm.memory.checkpoint/v1"
PLAN_SCHEMA: Final = "dm.memory.transition-plan/v1"
DECISION_SCHEMA: Final = "dm.memory.policy-decision/v1"
RECORD_SCHEMA: Final = "dm.memory.record/v1"
EXECUTION_SCHEMA: Final = "dm.memory.execution/v1"

POLICY_DOMAIN: Final = b"daimon/memory/policy/v1\x00"
CONTENT_DOMAIN: Final = b"daimon/memory/content-ref/v1\x00"
CANDIDATE_DOMAIN: Final = b"daimon/memory/candidate/v1\x00"
PLAN_DOMAIN: Final = b"daimon/memory/transition-plan/v1\x00"
DECISION_DOMAIN: Final = b"daimon/memory/policy-decision/v1\x00"

PERSONAL_CATEGORIES: Final = frozenset(
    {"personal-experience", "personal-insight", "personal-skill"}
)
ATTRIBUTED_CATEGORIES: Final = frozenset(
    {
        "peer-attributed",
        "external-reference",
        "tribal-knowledge",
        "species-inheritance",
        "incarnation-state",
    }
)
CATEGORIES: Final = PERSONAL_CATEGORIES | ATTRIBUTED_CATEGORIES
DERIVATIONS: Final = frozenset(
    {
        "body-occurrence",
        "local-synthesis",
        "peer-origin",
        "external-source",
        "tribe-retrieval",
        "species-application",
        "incarnation-observation",
    }
)
DERIVATION_CATEGORY: Final = {
    "body-occurrence": "personal-experience",
    "peer-origin": "peer-attributed",
    "external-source": "external-reference",
    "tribe-retrieval": "tribal-knowledge",
    "species-application": "species-inheritance",
    "incarnation-observation": "incarnation-state",
}
CLASSIFICATIONS: Final = frozenset({"public", "personal", "private", "protected"})
OUTCOMES: Final = frozenset(
    {
        "eligible",
        "review-required",
        "deferred:incomplete",
        "quarantined",
        "rejected",
    }
)
OPERATIONS: Final = frozenset({"assert", "correct", "retract"})
EFFECTS: Final = frozenset({"local-only", "public", "destructive"})
CONSENTS: Final = frozenset({"granted", "unknown", "denied"})
SAFETY: Final = frozenset({"clear", "uncertain", "unsafe"})
CONTRADICTIONS: Final = frozenset({"none", "ordinary", "sensitive"})
MAX_CONTENT_BYTES: Final = 16 * 1024 * 1024
MAX_EVIDENCE_REFS: Final = 256

_SCOPED = re.compile(r"^[A-Za-z0-9._:@-]{1,256}$")
_MEDIA = re.compile(r"^[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+$")


class MemoryPolicyError(ValueError):
    """A closed memory artifact or transition was refused."""


class MemoryExecutionError(RuntimeError):
    """A valid plan could not be committed against current evidence."""


def _canonical(value: Any) -> bytes:
    try:
        return canonical_bytes(value)
    except CanonicalError as exception:
        raise MemoryPolicyError("invalid_canonical_value") from exception


def _closed(value: Any, fields: set[str], error: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise MemoryPolicyError(error)
    return value


def _text(value: Any, error: str, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > maximum:
        raise MemoryPolicyError(error)
    _canonical(value)
    return value


def _scoped(value: Any, error: str) -> str:
    normalized = _text(value, error)
    if _SCOPED.fullmatch(normalized) is None:
        raise MemoryPolicyError(error)
    return normalized


def _uint(value: Any, error: str, *, minimum: int = 0) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not minimum <= value <= 2**53 - 1
    ):
        raise MemoryPolicyError(error)
    return value


def _hash(value: Any, error: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise MemoryPolicyError(error)
    return value


def _uuid(value: Any, error: str) -> str:
    if not isinstance(value, str):
        raise MemoryPolicyError(error)
    try:
        parsed = uuid.UUID(value)
    except ValueError as exception:
        raise MemoryPolicyError(error) from exception
    if str(parsed) != value:
        raise MemoryPolicyError(error)
    return value


def _derived(prefix: str, domain: bytes, value: Mapping[str, Any]) -> str:
    return prefix + b64url(hashlib.sha256(domain + _canonical(value)).digest())


def _derived_id(value: Any, prefix: str, error: str) -> str:
    normalized = _text(value, error, 160)
    if not normalized.startswith(prefix) or len(normalized.removeprefix(prefix)) != 43:
        raise MemoryPolicyError(error)
    try:
        unb64url(normalized.removeprefix(prefix), length=32)
    except CanonicalError as exception:
        raise MemoryPolicyError(error) from exception
    return normalized


def _refs(value: Any, error: str) -> list[str]:
    if (
        not isinstance(value, list)
        or len(value) > MAX_EVIDENCE_REFS
        or value != sorted(set(value))
    ):
        raise MemoryPolicyError(error)
    for item in value:
        _scoped(item, error)
    return list(value)


def create_memory_policy(
    *,
    subject_me_id: str,
    version: int,
    predecessor_policy_id: str | None,
    automatic_categories: Sequence[str],
    review_classifications: Sequence[str],
    max_content_bytes: int = MAX_CONTENT_BYTES,
    plan_ttl_ms: int = 300_000,
) -> dict[str, Any]:
    core = {
        "schema": POLICY_SCHEMA,
        "subject_me_id": subject_me_id,
        "version": version,
        "predecessor_policy_id": predecessor_policy_id,
        "automatic_categories": sorted(set(automatic_categories)),
        "review_classifications": sorted(set(review_classifications)),
        "max_content_bytes": max_content_bytes,
        "plan_ttl_ms": plan_ttl_ms,
    }
    value = {
        **core,
        "policy_id": _derived("dm:memory-policy:v1:", POLICY_DOMAIN, core),
    }
    return validate_memory_policy(value)


def validate_memory_policy(value: Any) -> dict[str, Any]:
    fields = {
        "schema",
        "policy_id",
        "subject_me_id",
        "version",
        "predecessor_policy_id",
        "automatic_categories",
        "review_classifications",
        "max_content_bytes",
        "plan_ttl_ms",
    }
    policy = _closed(value, fields, "invalid_memory_policy")
    if policy["schema"] != POLICY_SCHEMA:
        raise MemoryPolicyError("unsupported_memory_policy")
    _scoped(policy["subject_me_id"], "invalid_memory_subject")
    version = _uint(policy["version"], "invalid_memory_policy_version", minimum=1)
    predecessor = policy["predecessor_policy_id"]
    if version == 1:
        if predecessor is not None:
            raise MemoryPolicyError("unexpected_policy_predecessor")
    elif predecessor is None:
        raise MemoryPolicyError("missing_policy_predecessor")
    else:
        _derived_id(predecessor, "dm:memory-policy:v1:", "invalid_policy_predecessor")
    automatic = policy["automatic_categories"]
    if (
        not isinstance(automatic, list)
        or automatic != sorted(set(automatic))
        or any(item not in CATEGORIES for item in automatic)
    ):
        raise MemoryPolicyError("invalid_automatic_categories")
    review = policy["review_classifications"]
    if (
        not isinstance(review, list)
        or review != sorted(set(review))
        or any(item not in CLASSIFICATIONS for item in review)
    ):
        raise MemoryPolicyError("invalid_review_classifications")
    maximum = _uint(policy["max_content_bytes"], "invalid_content_limit", minimum=1)
    if maximum > MAX_CONTENT_BYTES:
        raise MemoryPolicyError("invalid_content_limit")
    ttl = _uint(policy["plan_ttl_ms"], "invalid_plan_ttl", minimum=1)
    if ttl > 86_400_000:
        raise MemoryPolicyError("invalid_plan_ttl")
    core = {
        key: copy.deepcopy(item) for key, item in policy.items() if key != "policy_id"
    }
    expected = _derived("dm:memory-policy:v1:", POLICY_DOMAIN, core)
    if policy["policy_id"] != expected:
        raise MemoryPolicyError("memory_policy_id_mismatch")
    return copy.deepcopy(dict(policy))


def validate_policy_successor(
    previous: Mapping[str, Any], successor: Mapping[str, Any]
) -> dict[str, Any]:
    """Validate one immutable, non-retroactive policy succession edge."""

    prior = validate_memory_policy(previous)
    following = validate_memory_policy(successor)
    if (
        following["subject_me_id"] != prior["subject_me_id"]
        or following["version"] != prior["version"] + 1
        or following["predecessor_policy_id"] != prior["policy_id"]
    ):
        raise MemoryPolicyError("invalid_memory_policy_successor")
    return following


def create_content_ref(
    *, sha256: str, byte_length: int, media_type: str, classification: str
) -> dict[str, Any]:
    core = {
        "schema": CONTENT_REF_SCHEMA,
        "sha256": sha256,
        "byte_length": byte_length,
        "media_type": media_type,
        "classification": classification,
    }
    value = {
        **core,
        "content_id": _derived("dm:memory-content:v1:", CONTENT_DOMAIN, core),
    }
    return validate_content_ref(value)


def validate_content_ref(value: Any) -> dict[str, Any]:
    reference = _closed(
        value,
        {
            "schema",
            "content_id",
            "sha256",
            "byte_length",
            "media_type",
            "classification",
        },
        "invalid_memory_content_ref",
    )
    if reference["schema"] != CONTENT_REF_SCHEMA:
        raise MemoryPolicyError("unsupported_memory_content_ref")
    _hash(reference["sha256"], "invalid_memory_content_hash")
    _uint(reference["byte_length"], "invalid_memory_content_size", minimum=1)
    media = _text(reference["media_type"], "invalid_memory_media_type", 128)
    if _MEDIA.fullmatch(media) is None:
        raise MemoryPolicyError("invalid_memory_media_type")
    if reference["classification"] not in CLASSIFICATIONS:
        raise MemoryPolicyError("invalid_memory_classification")
    core = {
        key: copy.deepcopy(item)
        for key, item in reference.items()
        if key != "content_id"
    }
    expected = _derived("dm:memory-content:v1:", CONTENT_DOMAIN, core)
    if reference["content_id"] != expected:
        raise MemoryPolicyError("memory_content_id_mismatch")
    return copy.deepcopy(dict(reference))


def _validate_body_evidence(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    evidence = _closed(
        value,
        {
            "body_ref",
            "embodiment_id",
            "incarnation_id",
            "session_ref",
            "lease_ref",
            "committed_cutoff_event_id",
        },
        "invalid_memory_body_evidence",
    )
    for field in (
        "body_ref",
        "embodiment_id",
        "incarnation_id",
        "session_ref",
        "lease_ref",
    ):
        _scoped(evidence[field], "invalid_memory_body_evidence")
    cutoff = evidence["committed_cutoff_event_id"]
    if cutoff is not None:
        _uuid(cutoff, "invalid_memory_body_evidence")
    return copy.deepcopy(dict(evidence))


def _validate_lane(value: Any) -> dict[str, Any]:
    lane = _closed(
        value,
        {
            "memory_id",
            "operation",
            "sequence",
            "predecessor_event_id",
            "predecessor_hash",
        },
        "invalid_memory_lane",
    )
    _uuid(lane["memory_id"], "invalid_memory_id")
    if lane["operation"] not in OPERATIONS:
        raise MemoryPolicyError("invalid_memory_operation")
    sequence = _uint(lane["sequence"], "invalid_memory_sequence", minimum=1)
    if sequence == 1:
        if (
            lane["operation"] != "assert"
            or lane["predecessor_event_id"] is not None
            or lane["predecessor_hash"] is not None
        ):
            raise MemoryPolicyError("invalid_memory_lane_start")
    else:
        if (
            lane["operation"] == "assert"
            or lane["predecessor_event_id"] is None
            or lane["predecessor_hash"] is None
        ):
            raise MemoryPolicyError("invalid_memory_lane_successor")
        _uuid(lane["predecessor_event_id"], "invalid_memory_lane_successor")
        _hash(lane["predecessor_hash"], "invalid_memory_lane_successor")
    return copy.deepcopy(dict(lane))


def create_memory_candidate(
    *,
    subject_me_id: str,
    author_me_id: str,
    category: str,
    derivation: str,
    context: str,
    content_ref: Mapping[str, Any] | None,
    evidence_refs: Sequence[str],
    classification: str,
    consent: str,
    safety: str,
    contradiction: str,
    effect: str,
    lane: Mapping[str, Any],
    body_evidence: Mapping[str, Any] | None = None,
    predecessor_decision_id: str | None = None,
) -> dict[str, Any]:
    core = {
        "schema": CANDIDATE_SCHEMA,
        "subject_me_id": subject_me_id,
        "author_me_id": author_me_id,
        "category": category,
        "derivation": derivation,
        "context": context,
        "content_ref": None
        if content_ref is None
        else copy.deepcopy(dict(content_ref)),
        "evidence_refs": sorted(set(evidence_refs)),
        "classification": classification,
        "consent": consent,
        "safety": safety,
        "contradiction": contradiction,
        "effect": effect,
        "lane": copy.deepcopy(dict(lane)),
        "body_evidence": None
        if body_evidence is None
        else copy.deepcopy(dict(body_evidence)),
        "predecessor_decision_id": predecessor_decision_id,
    }
    value = {
        **core,
        "candidate_id": _derived("dm:memory-candidate:v1:", CANDIDATE_DOMAIN, core),
    }
    return validate_memory_candidate(value)


def validate_memory_candidate(value: Any) -> dict[str, Any]:
    fields = {
        "schema",
        "candidate_id",
        "subject_me_id",
        "author_me_id",
        "category",
        "derivation",
        "context",
        "content_ref",
        "evidence_refs",
        "classification",
        "consent",
        "safety",
        "contradiction",
        "effect",
        "lane",
        "body_evidence",
        "predecessor_decision_id",
    }
    candidate = _closed(value, fields, "invalid_memory_candidate")
    if candidate["schema"] != CANDIDATE_SCHEMA:
        raise MemoryPolicyError("unsupported_memory_candidate")
    _scoped(candidate["subject_me_id"], "invalid_memory_subject")
    _scoped(candidate["author_me_id"], "invalid_memory_author")
    if candidate["category"] not in CATEGORIES:
        raise MemoryPolicyError("invalid_memory_category")
    if candidate["derivation"] not in DERIVATIONS:
        raise MemoryPolicyError("invalid_memory_derivation")
    _scoped(candidate["context"], "invalid_memory_context")
    content = candidate["content_ref"]
    lane = _validate_lane(candidate["lane"])
    predecessor_decision = candidate["predecessor_decision_id"]
    if lane["sequence"] > 1 and predecessor_decision is None:
        raise MemoryPolicyError("missing_predecessor_decision")
    if predecessor_decision is not None:
        _derived_id(
            predecessor_decision,
            "dm:memory-decision:v1:",
            "invalid_predecessor_decision",
        )
    if lane["operation"] == "retract":
        if content is not None:
            raise MemoryPolicyError("retraction_content_forbidden")
    elif content is None:
        raise MemoryPolicyError("memory_content_required")
    else:
        validate_content_ref(content)
    _refs(candidate["evidence_refs"], "invalid_memory_evidence_refs")
    if candidate["classification"] not in CLASSIFICATIONS:
        raise MemoryPolicyError("invalid_memory_classification")
    if candidate["consent"] not in CONSENTS:
        raise MemoryPolicyError("invalid_memory_consent")
    if candidate["safety"] not in SAFETY:
        raise MemoryPolicyError("invalid_memory_safety")
    if candidate["contradiction"] not in CONTRADICTIONS:
        raise MemoryPolicyError("invalid_memory_contradiction")
    if candidate["effect"] not in EFFECTS:
        raise MemoryPolicyError("invalid_memory_effect")
    _validate_body_evidence(candidate["body_evidence"])
    core = {
        key: copy.deepcopy(item)
        for key, item in candidate.items()
        if key != "candidate_id"
    }
    expected = _derived("dm:memory-candidate:v1:", CANDIDATE_DOMAIN, core)
    if candidate["candidate_id"] != expected:
        raise MemoryPolicyError("memory_candidate_id_mismatch")
    return copy.deepcopy(dict(candidate))


def validate_memory_checkpoint(value: Any) -> dict[str, Any]:
    checkpoint = _closed(
        value,
        {
            "schema",
            "being_ref",
            "manifest_hash",
            "local_origin",
            "ledger_state_hash",
            "projection_hash",
            "evidence_refs",
            "body_evidence_state",
            "lane_state",
            "lane_event_ids",
            "lane_head",
            "captured_at_ms",
        },
        "invalid_memory_checkpoint",
    )
    if checkpoint["schema"] != CHECKPOINT_SCHEMA:
        raise MemoryPolicyError("unsupported_memory_checkpoint")
    _scoped(checkpoint["being_ref"], "invalid_memory_checkpoint")
    _hash(checkpoint["manifest_hash"], "invalid_memory_checkpoint")
    origin = _closed(
        checkpoint["local_origin"],
        {"body_ref", "embodiment_id", "incarnation_id", "principal_id"},
        "invalid_memory_checkpoint",
    )
    for item in origin.values():
        _scoped(item, "invalid_memory_checkpoint")
    _hash(checkpoint["ledger_state_hash"], "invalid_memory_checkpoint")
    _hash(checkpoint["projection_hash"], "invalid_memory_checkpoint")
    _refs(checkpoint["evidence_refs"], "invalid_memory_checkpoint")
    if checkpoint["body_evidence_state"] not in {
        "absent",
        "verified",
        "unavailable",
        "mismatch",
    }:
        raise MemoryPolicyError("invalid_memory_checkpoint")
    if checkpoint["lane_state"] not in {"empty", "linear", "forked"}:
        raise MemoryPolicyError("invalid_memory_checkpoint")
    lane_event_ids = checkpoint["lane_event_ids"]
    if (
        not isinstance(lane_event_ids, list)
        or lane_event_ids != sorted(set(lane_event_ids))
        or len(lane_event_ids) > MAX_EVIDENCE_REFS
    ):
        raise MemoryPolicyError("invalid_memory_checkpoint")
    for event_id in lane_event_ids:
        _uuid(event_id, "invalid_memory_checkpoint")
    head = checkpoint["lane_head"]
    if head is not None:
        head = _closed(
            head,
            {
                "event_id",
                "content_hash",
                "memory_id",
                "sequence",
                "category",
                "author_me_id",
                "context",
                "decision_id",
            },
            "invalid_memory_lane_head",
        )
        _uuid(head["event_id"], "invalid_memory_lane_head")
        _hash(head["content_hash"], "invalid_memory_lane_head")
        _uuid(head["memory_id"], "invalid_memory_lane_head")
        _uint(head["sequence"], "invalid_memory_lane_head", minimum=1)
        if head["category"] not in CATEGORIES:
            raise MemoryPolicyError("invalid_memory_lane_head")
        _scoped(head["author_me_id"], "invalid_memory_lane_head")
        _scoped(head["context"], "invalid_memory_lane_head")
        _derived_id(
            head["decision_id"],
            "dm:memory-decision:v1:",
            "invalid_memory_lane_head",
        )
    if checkpoint["lane_state"] == "empty":
        if head is not None or lane_event_ids:
            raise MemoryPolicyError("invalid_memory_checkpoint")
    elif checkpoint["lane_state"] == "linear":
        if head is None or not lane_event_ids or head["event_id"] not in lane_event_ids:
            raise MemoryPolicyError("invalid_memory_checkpoint")
    elif head is not None or len(lane_event_ids) < 2:
        raise MemoryPolicyError("invalid_memory_checkpoint")
    _uint(checkpoint["captured_at_ms"], "invalid_memory_checkpoint")
    return copy.deepcopy(dict(checkpoint))


def _memory_lane_snapshot(events: Sequence[Mapping[str, Any]]) -> tuple[str, Any]:
    """Return an exact linear head, or retain every event ID as fork evidence."""

    if not events:
        return "empty", None
    ordered = sorted(
        events,
        key=lambda event: (event["payload"]["sequence"], event["event_id"]),
    )
    previous: Mapping[str, Any] | None = None
    invariant: tuple[str, str, str] | None = None
    for expected_sequence, event in enumerate(ordered, start=1):
        payload = event["payload"]
        current_invariant = (
            payload["category"],
            payload["author_me_id"],
            payload["context"],
        )
        if invariant is None:
            invariant = current_invariant
        expected_predecessor = None if previous is None else previous["event_id"]
        expected_hash = None if previous is None else previous["content_hash"]
        expected_operation = "assert" if previous is None else None
        if (
            payload["sequence"] != expected_sequence
            or payload["predecessor_event_id"] != expected_predecessor
            or payload["predecessor_hash"] != expected_hash
            or current_invariant != invariant
            or (
                expected_operation is not None
                and payload["operation"] != expected_operation
            )
            or (previous is not None and payload["operation"] == "assert")
            or (
                previous is not None
                and payload["predecessor_decision_id"]
                != previous["payload"]["decision_id"]
            )
            or event["supersedes"] != expected_predecessor
        ):
            return "forked", None
        previous = event
    if previous is None:  # pragma: no cover - guarded by the non-empty branch
        return "empty", None
    payload = previous["payload"]
    return (
        "linear",
        {
            "event_id": previous["event_id"],
            "content_hash": previous["content_hash"],
            "memory_id": payload["memory_id"],
            "sequence": payload["sequence"],
            "category": payload["category"],
            "author_me_id": payload["author_me_id"],
            "context": payload["context"],
            "decision_id": payload["decision_id"],
        },
    )


def memory_checkpoint(
    ledger: Ledger, candidate: Mapping[str, Any], *, captured_at_ms: int
) -> dict[str, Any]:
    normalized = validate_memory_candidate(candidate)
    memory_id = normalized["lane"]["memory_id"]
    lane_events = [
        event
        for event in ledger.events(include_incomplete=False)
        if event["kind"] == "memory.recorded"
        and event["payload"].get("memory_id") == memory_id
    ]
    lane_state, head = _memory_lane_snapshot(lane_events)
    evidence = [
        reference
        for reference in normalized["evidence_refs"]
        if ledger.event(reference, include_incomplete=False) is not None
    ]
    body = normalized["body_evidence"]
    body_state = "absent"
    if body is not None:
        cutoff_id = body["committed_cutoff_event_id"]
        cutoff = (
            None
            if cutoff_id is None
            else ledger.event(cutoff_id, include_incomplete=False)
        )
        if cutoff is None:
            body_state = "unavailable"
        elif (
            cutoff_id not in normalized["evidence_refs"]
            or any(
                cutoff["origin"][field] != body[field]
                for field in ("body_ref", "embodiment_id", "incarnation_id")
            )
            or any(
                cutoff["payload"].get(field) != body[field]
                for field in ("session_ref", "lease_ref")
            )
        ):
            body_state = "mismatch"
        else:
            body_state = "verified"
    projection = ProjectionEngine(ledger).snapshot()
    return validate_memory_checkpoint(
        {
            "schema": CHECKPOINT_SCHEMA,
            "being_ref": ledger.authority.manifest.being_ref,
            "manifest_hash": ledger.authority.manifest.digest,
            "local_origin": copy.deepcopy(ledger.local_origin),
            "ledger_state_hash": ledger.state_hash(),
            "projection_hash": projection["projection_hash"],
            "evidence_refs": evidence,
            "body_evidence_state": body_state,
            "lane_state": lane_state,
            "lane_event_ids": sorted(event["event_id"] for event in lane_events),
            "lane_head": head,
            "captured_at_ms": captured_at_ms,
        }
    )


def _lane_reason(
    candidate: Mapping[str, Any], checkpoint: Mapping[str, Any]
) -> str | None:
    lane = candidate["lane"]
    if checkpoint["lane_state"] == "forked":
        return "memory-lane-forked"
    head = checkpoint["lane_head"]
    if lane["sequence"] == 1:
        return None if head is None else "memory-lane-already-exists"
    if head is None:
        return "memory-lane-head-missing"
    if (
        lane["memory_id"] != head["memory_id"]
        or lane["sequence"] != head["sequence"] + 1
        or lane["predecessor_event_id"] != head["event_id"]
        or lane["predecessor_hash"] != head["content_hash"]
        or candidate["predecessor_decision_id"] != head["decision_id"]
    ):
        return "memory-lane-predecessor-mismatch"
    if any(
        candidate[field] != head[field]
        for field in ("category", "author_me_id", "context")
    ):
        return "memory-lane-invariant-mismatch"
    return None


def evaluate_memory_candidate(
    policy: Mapping[str, Any],
    candidate: Mapping[str, Any],
    checkpoint: Mapping[str, Any],
    *,
    evaluated_at_ms: int,
) -> dict[str, Any]:
    policy_value = validate_memory_policy(policy)
    candidate_value = validate_memory_candidate(candidate)
    checkpoint_value = validate_memory_checkpoint(checkpoint)
    evaluated = _uint(evaluated_at_ms, "invalid_memory_evaluation_time")
    if evaluated < checkpoint_value["captured_at_ms"]:
        raise MemoryPolicyError("memory_evaluation_precedes_checkpoint")
    reasons: list[str] = []
    outcome = "eligible"
    if (
        policy_value["subject_me_id"] != candidate_value["subject_me_id"]
        or checkpoint_value["being_ref"] != candidate_value["subject_me_id"]
    ):
        outcome, reasons = "rejected", ["wrong-memory-subject"]
    elif (
        candidate_value["classification"]
        != (
            candidate_value["content_ref"]
            or {"classification": candidate_value["classification"]}
        )["classification"]
    ):
        outcome, reasons = "rejected", ["classification-mismatch"]
    elif not set(candidate_value["evidence_refs"]).issubset(
        checkpoint_value["evidence_refs"]
    ):
        outcome, reasons = "deferred:incomplete", ["evidence-incomplete"]
    elif (
        candidate_value["category"] in PERSONAL_CATEGORIES
        and candidate_value["author_me_id"] != candidate_value["subject_me_id"]
    ):
        outcome, reasons = "rejected", ["false-personal-author"]
    elif (
        candidate_value["derivation"] == "local-synthesis"
        and candidate_value["category"] not in {"personal-insight", "personal-skill"}
    ) or (
        candidate_value["derivation"] != "local-synthesis"
        and DERIVATION_CATEGORY.get(candidate_value["derivation"])
        != candidate_value["category"]
    ):
        outcome, reasons = "rejected", ["category-derivation-mismatch"]
    elif candidate_value["derivation"] == "body-occurrence" and (
        candidate_value["body_evidence"] is None
        or checkpoint_value["body_evidence_state"] != "verified"
        or any(
            candidate_value["body_evidence"][field]
            != checkpoint_value["local_origin"][field]
            for field in ("body_ref", "embodiment_id", "incarnation_id")
        )
    ):
        outcome, reasons = "rejected", ["body-evidence-mismatch"]
    else:
        lane_error = _lane_reason(candidate_value, checkpoint_value)
        if lane_error is not None:
            outcome, reasons = "quarantined", [lane_error]
        elif candidate_value["safety"] == "unsafe":
            outcome, reasons = "quarantined", ["unsafe-content"]
        elif candidate_value["consent"] == "denied":
            outcome, reasons = "rejected", ["consent-denied"]
        elif candidate_value["consent"] == "unknown":
            outcome, reasons = "review-required", ["consent-uncertain"]
        elif candidate_value["safety"] == "uncertain":
            outcome, reasons = "review-required", ["safety-uncertain"]
        elif candidate_value["contradiction"] == "sensitive":
            outcome, reasons = "review-required", ["sensitive-contradiction"]
        elif (
            candidate_value["classification"] in policy_value["review_classifications"]
        ):
            outcome, reasons = "review-required", ["classification-requires-review"]
        elif candidate_value["effect"] != "local-only":
            outcome, reasons = "review-required", ["external-effect-requires-review"]
        elif candidate_value["category"] not in policy_value["automatic_categories"]:
            outcome, reasons = "review-required", ["category-requires-review"]
    content = candidate_value["content_ref"]
    if (
        content is not None
        and content["byte_length"] > policy_value["max_content_bytes"]
    ):
        outcome, reasons = "rejected", ["content-limit-exceeded"]
    expires_at = evaluated + policy_value["plan_ttl_ms"]
    decision_core = {
        "schema": DECISION_SCHEMA,
        "policy_id": policy_value["policy_id"],
        "candidate_id": candidate_value["candidate_id"],
        "predecessor_decision_id": candidate_value["predecessor_decision_id"],
        "subject_me_id": candidate_value["subject_me_id"],
        "checkpoint": copy.deepcopy(checkpoint_value),
        "evaluated_at_ms": evaluated,
        "expires_at_ms": expires_at,
        "outcome": outcome,
        "reasons": reasons,
    }
    decision_id = _derived("dm:memory-decision:v1:", DECISION_DOMAIN, decision_core)
    preview = None
    if outcome in {"eligible", "review-required"}:
        preview = {
            "kind": "memory.recorded",
            "subject": candidate_value["subject_me_id"],
            "sensitivity": "private"
            if candidate_value["classification"] in {"private", "protected"}
            else "personal",
            "payload": {
                "schema": RECORD_SCHEMA,
                "memory_id": candidate_value["lane"]["memory_id"],
                "sequence": candidate_value["lane"]["sequence"],
                "operation": candidate_value["lane"]["operation"],
                "predecessor_event_id": candidate_value["lane"]["predecessor_event_id"],
                "predecessor_hash": candidate_value["lane"]["predecessor_hash"],
                "category": candidate_value["category"],
                "author_me_id": candidate_value["author_me_id"],
                "context": candidate_value["context"],
                "content_ref": copy.deepcopy(content),
                "evidence_refs": copy.deepcopy(candidate_value["evidence_refs"]),
                "policy_id": policy_value["policy_id"],
                "candidate_id": candidate_value["candidate_id"],
                "decision_id": decision_id,
                "predecessor_decision_id": candidate_value["predecessor_decision_id"],
            },
        }
    core = {
        "schema": PLAN_SCHEMA,
        "policy_id": policy_value["policy_id"],
        "candidate_id": candidate_value["candidate_id"],
        "decision_id": decision_id,
        "predecessor_decision_id": candidate_value["predecessor_decision_id"],
        "subject_me_id": candidate_value["subject_me_id"],
        "checkpoint": copy.deepcopy(checkpoint_value),
        "evaluated_at_ms": evaluated,
        "expires_at_ms": expires_at,
        "outcome": outcome,
        "reasons": reasons,
        "event_preview": preview,
    }
    result = {
        **core,
        "plan_id": _derived("dm:memory-plan:v1:", PLAN_DOMAIN, core),
    }
    return validate_memory_plan(result)


def validate_memory_plan(value: Any) -> dict[str, Any]:
    plan = _closed(
        value,
        {
            "schema",
            "plan_id",
            "policy_id",
            "candidate_id",
            "decision_id",
            "predecessor_decision_id",
            "subject_me_id",
            "checkpoint",
            "evaluated_at_ms",
            "expires_at_ms",
            "outcome",
            "reasons",
            "event_preview",
        },
        "invalid_memory_plan",
    )
    if plan["schema"] != PLAN_SCHEMA:
        raise MemoryPolicyError("unsupported_memory_plan")
    _derived_id(plan["policy_id"], "dm:memory-policy:v1:", "invalid_memory_plan")
    _derived_id(plan["candidate_id"], "dm:memory-candidate:v1:", "invalid_memory_plan")
    _derived_id(plan["decision_id"], "dm:memory-decision:v1:", "invalid_memory_plan")
    predecessor_decision = plan["predecessor_decision_id"]
    if predecessor_decision is not None:
        _derived_id(
            predecessor_decision,
            "dm:memory-decision:v1:",
            "invalid_memory_plan",
        )
    _scoped(plan["subject_me_id"], "invalid_memory_plan")
    validate_memory_checkpoint(plan["checkpoint"])
    evaluated = _uint(plan["evaluated_at_ms"], "invalid_memory_plan")
    expires = _uint(plan["expires_at_ms"], "invalid_memory_plan")
    if expires <= evaluated:
        raise MemoryPolicyError("invalid_memory_plan")
    if plan["outcome"] not in OUTCOMES:
        raise MemoryPolicyError("invalid_memory_plan")
    reasons = plan["reasons"]
    if (
        not isinstance(reasons, list)
        or reasons != sorted(set(reasons))
        or any(not isinstance(reason, str) or not reason for reason in reasons)
    ):
        raise MemoryPolicyError("invalid_memory_plan")
    preview = plan["event_preview"]
    if plan["outcome"] in {"eligible", "review-required"}:
        _closed(
            preview,
            {"kind", "subject", "sensitivity", "payload"},
            "invalid_memory_plan",
        )
        if preview["kind"] != "memory.recorded":
            raise MemoryPolicyError("invalid_memory_plan")
    elif preview is not None:
        raise MemoryPolicyError("invalid_memory_plan")
    core = {key: copy.deepcopy(item) for key, item in plan.items() if key != "plan_id"}
    expected = _derived("dm:memory-plan:v1:", PLAN_DOMAIN, core)
    if plan["plan_id"] != expected:
        raise MemoryPolicyError("memory_plan_id_mismatch")
    decision_core = {
        "schema": DECISION_SCHEMA,
        "policy_id": plan["policy_id"],
        "candidate_id": plan["candidate_id"],
        "predecessor_decision_id": plan["predecessor_decision_id"],
        "subject_me_id": plan["subject_me_id"],
        "checkpoint": copy.deepcopy(plan["checkpoint"]),
        "evaluated_at_ms": plan["evaluated_at_ms"],
        "expires_at_ms": plan["expires_at_ms"],
        "outcome": plan["outcome"],
        "reasons": copy.deepcopy(plan["reasons"]),
    }
    expected_decision = _derived(
        "dm:memory-decision:v1:", DECISION_DOMAIN, decision_core
    )
    if plan["decision_id"] != expected_decision:
        raise MemoryPolicyError("memory_decision_id_mismatch")
    return copy.deepcopy(dict(plan))


def memory_decision(plan: Mapping[str, Any]) -> dict[str, Any]:
    """Extract the immutable policy decision addressed by one valid plan."""

    normalized = validate_memory_plan(plan)
    return validate_memory_decision(
        {
            "schema": DECISION_SCHEMA,
            "decision_id": normalized["decision_id"],
            "policy_id": normalized["policy_id"],
            "candidate_id": normalized["candidate_id"],
            "predecessor_decision_id": normalized["predecessor_decision_id"],
            "subject_me_id": normalized["subject_me_id"],
            "checkpoint": copy.deepcopy(normalized["checkpoint"]),
            "evaluated_at_ms": normalized["evaluated_at_ms"],
            "expires_at_ms": normalized["expires_at_ms"],
            "outcome": normalized["outcome"],
            "reasons": copy.deepcopy(normalized["reasons"]),
        }
    )


def validate_memory_decision(value: Any) -> dict[str, Any]:
    decision = _closed(
        value,
        {
            "schema",
            "decision_id",
            "policy_id",
            "candidate_id",
            "predecessor_decision_id",
            "subject_me_id",
            "checkpoint",
            "evaluated_at_ms",
            "expires_at_ms",
            "outcome",
            "reasons",
        },
        "invalid_memory_decision",
    )
    if decision["schema"] != DECISION_SCHEMA:
        raise MemoryPolicyError("unsupported_memory_decision")
    _derived_id(
        decision["decision_id"],
        "dm:memory-decision:v1:",
        "invalid_memory_decision",
    )
    _derived_id(
        decision["policy_id"], "dm:memory-policy:v1:", "invalid_memory_decision"
    )
    _derived_id(
        decision["candidate_id"],
        "dm:memory-candidate:v1:",
        "invalid_memory_decision",
    )
    predecessor_decision = decision["predecessor_decision_id"]
    if predecessor_decision is not None:
        _derived_id(
            predecessor_decision,
            "dm:memory-decision:v1:",
            "invalid_memory_decision",
        )
    _scoped(decision["subject_me_id"], "invalid_memory_decision")
    validate_memory_checkpoint(decision["checkpoint"])
    evaluated = _uint(decision["evaluated_at_ms"], "invalid_memory_decision")
    expires = _uint(decision["expires_at_ms"], "invalid_memory_decision")
    if expires <= evaluated or decision["outcome"] not in OUTCOMES:
        raise MemoryPolicyError("invalid_memory_decision")
    reasons = decision["reasons"]
    if (
        not isinstance(reasons, list)
        or reasons != sorted(set(reasons))
        or any(not isinstance(reason, str) or not reason for reason in reasons)
    ):
        raise MemoryPolicyError("invalid_memory_decision")
    core = {
        key: copy.deepcopy(item)
        for key, item in decision.items()
        if key != "decision_id"
    }
    expected = _derived("dm:memory-decision:v1:", DECISION_DOMAIN, core)
    if decision["decision_id"] != expected:
        raise MemoryPolicyError("memory_decision_id_mismatch")
    return copy.deepcopy(dict(decision))


def validate_memory_record(value: Any) -> dict[str, Any]:
    record = _closed(
        value,
        {
            "schema",
            "memory_id",
            "sequence",
            "operation",
            "predecessor_event_id",
            "predecessor_hash",
            "category",
            "author_me_id",
            "context",
            "content_ref",
            "evidence_refs",
            "policy_id",
            "candidate_id",
            "decision_id",
            "predecessor_decision_id",
        },
        "invalid_memory_record",
    )
    if record["schema"] != RECORD_SCHEMA:
        raise MemoryPolicyError("unsupported_memory_record")
    lane = _validate_lane(
        {
            "memory_id": record["memory_id"],
            "operation": record["operation"],
            "sequence": record["sequence"],
            "predecessor_event_id": record["predecessor_event_id"],
            "predecessor_hash": record["predecessor_hash"],
        }
    )
    content = record["content_ref"]
    if lane["operation"] == "retract":
        if content is not None:
            raise MemoryPolicyError("retraction_content_forbidden")
    elif content is None:
        raise MemoryPolicyError("memory_content_required")
    else:
        validate_content_ref(content)
    if record["category"] not in CATEGORIES:
        raise MemoryPolicyError("invalid_memory_category")
    _scoped(record["author_me_id"], "invalid_memory_author")
    _scoped(record["context"], "invalid_memory_context")
    _refs(record["evidence_refs"], "invalid_memory_evidence_refs")
    _derived_id(record["policy_id"], "dm:memory-policy:v1:", "invalid_memory_record")
    _derived_id(
        record["candidate_id"],
        "dm:memory-candidate:v1:",
        "invalid_memory_record",
    )
    _derived_id(
        record["decision_id"], "dm:memory-decision:v1:", "invalid_memory_record"
    )
    predecessor_decision = record["predecessor_decision_id"]
    if lane["sequence"] > 1 and predecessor_decision is None:
        raise MemoryPolicyError("missing_predecessor_decision")
    if predecessor_decision is not None:
        _derived_id(
            predecessor_decision,
            "dm:memory-decision:v1:",
            "invalid_memory_record",
        )
    return copy.deepcopy(dict(record))


@dataclass(frozen=True)
class MemoryPolicyExecutor:
    ledger: Ledger
    signer: EventSigner
    clock: Callable[[], int]

    def execute(
        self,
        plan: Mapping[str, Any],
        policy: Mapping[str, Any],
        candidate: Mapping[str, Any],
        *,
        client_id: str,
        request_id: str,
    ) -> dict[str, Any]:
        normalized = validate_memory_plan(plan)
        now = _uint(self.clock(), "invalid_memory_execution_time")
        if normalized["outcome"] != "eligible":
            raise MemoryExecutionError("memory_plan_not_automatically_executable")
        if now > normalized["expires_at_ms"]:
            raise MemoryExecutionError("memory_plan_expired")
        regenerated = evaluate_memory_candidate(
            policy,
            candidate,
            normalized["checkpoint"],
            evaluated_at_ms=normalized["evaluated_at_ms"],
        )
        if regenerated != normalized:
            raise MemoryExecutionError("memory_plan_revalidation_mismatch")
        if normalized["subject_me_id"] != self.ledger.authority.manifest.being_ref:
            raise MemoryExecutionError("memory_executor_subject_mismatch")
        preview = normalized["event_preview"]
        if not isinstance(preview, Mapping):
            raise MemoryExecutionError("memory_plan_missing_preview")
        request_hash = hashlib.sha256(
            canonical_bytes(
                {
                    "schema": EXECUTION_SCHEMA,
                    "plan_id": normalized["plan_id"],
                }
            )
        ).hexdigest()
        event_id = str(
            uuid.uuid5(uuid.NAMESPACE_URL, "daimon-memory:" + normalized["plan_id"])
        )
        try:
            event: Event = self.ledger.append_local_idempotent(
                client_id=client_id,
                request_id=request_id,
                request_hash=request_hash,
                kind=str(preview["kind"]),
                subject=str(preview["subject"]),
                payload=copy.deepcopy(dict(preview["payload"])),
                signer=self.signer,
                sensitivity=str(preview["sensitivity"]),
                causal_parents=tuple(normalized["checkpoint"]["evidence_refs"]),
                supersedes=normalized["checkpoint"]["lane_head"]["event_id"]
                if normalized["checkpoint"]["lane_head"] is not None
                else None,
                occurred_at_ms=normalized["evaluated_at_ms"],
                event_id=event_id,
                expected_state_hash=normalized["checkpoint"]["ledger_state_hash"],
            )
        except LedgerStateError as exception:
            raise MemoryExecutionError("memory_plan_stale") from exception
        return {
            "schema": EXECUTION_SCHEMA,
            "plan_id": normalized["plan_id"],
            "event": event,
        }

    def execute_reviewed(
        self,
        plan: Mapping[str, Any],
        policy: Mapping[str, Any],
        candidate: Mapping[str, Any],
        *,
        review_request_id: str,
        decision_ids: Sequence[str],
        client_id: str,
        request_id: str,
    ) -> dict[str, Any]:
        """Commit only an exact plan released by the DM-033 review protocol.

        This entry point is intentionally separate from ``execute``: callers
        cannot turn arbitrary review-required plans into automatic ones with a
        boolean flag.  The purpose-separated review references are bound into
        the local-operation hash; the human review coordinator remains
        responsible for verifying signatures, scope, quorum, and revocation.
        """

        normalized = validate_memory_plan(plan)
        now = _uint(self.clock(), "invalid_memory_execution_time")
        if normalized["outcome"] != "review-required":
            raise MemoryExecutionError("memory_plan_not_review_executable")
        if now > normalized["expires_at_ms"]:
            raise MemoryExecutionError("memory_plan_expired")
        if (
            not isinstance(review_request_id, str)
            or not review_request_id.startswith("dm:review-request:v1:")
            or not isinstance(decision_ids, Sequence)
            or isinstance(decision_ids, (str, bytes))
            or not decision_ids
            or list(decision_ids) != sorted(set(decision_ids))
            or any(
                not isinstance(item, str)
                or not item.startswith("dm:review-decision:v1:")
                for item in decision_ids
            )
        ):
            raise MemoryExecutionError("invalid_memory_review_guard")
        regenerated = evaluate_memory_candidate(
            policy,
            candidate,
            normalized["checkpoint"],
            evaluated_at_ms=normalized["evaluated_at_ms"],
        )
        if regenerated != normalized:
            raise MemoryExecutionError("memory_plan_revalidation_mismatch")
        current_checkpoint = memory_checkpoint(
            self.ledger,
            candidate,
            captured_at_ms=now,
        )
        evidence_fields = (
            "being_ref",
            "manifest_hash",
            "local_origin",
            "projection_hash",
            "evidence_refs",
            "body_evidence_state",
            "lane_state",
            "lane_event_ids",
            "lane_head",
        )
        if any(
            current_checkpoint[field] != normalized["checkpoint"][field]
            for field in evidence_fields
        ):
            raise MemoryExecutionError("memory_plan_stale")
        if normalized["subject_me_id"] != self.ledger.authority.manifest.being_ref:
            raise MemoryExecutionError("memory_executor_subject_mismatch")
        preview = normalized["event_preview"]
        if not isinstance(preview, Mapping):
            raise MemoryExecutionError("memory_plan_missing_preview")
        request_hash = hashlib.sha256(
            canonical_bytes(
                {
                    "schema": EXECUTION_SCHEMA,
                    "plan_id": normalized["plan_id"],
                    "review_request_id": review_request_id,
                    "decision_ids": list(decision_ids),
                }
            )
        ).hexdigest()
        event_id = str(
            uuid.uuid5(uuid.NAMESPACE_URL, "daimon-memory:" + normalized["plan_id"])
        )
        try:
            event: Event = self.ledger.append_local_idempotent(
                client_id=client_id,
                request_id=request_id,
                request_hash=request_hash,
                kind=str(preview["kind"]),
                subject=str(preview["subject"]),
                payload=copy.deepcopy(dict(preview["payload"])),
                signer=self.signer,
                sensitivity=str(preview["sensitivity"]),
                causal_parents=tuple(normalized["checkpoint"]["evidence_refs"]),
                supersedes=normalized["checkpoint"]["lane_head"]["event_id"]
                if normalized["checkpoint"]["lane_head"] is not None
                else None,
                occurred_at_ms=normalized["evaluated_at_ms"],
                event_id=event_id,
                expected_state_hash=current_checkpoint["ledger_state_hash"],
            )
        except LedgerStateError as exception:
            raise MemoryExecutionError("memory_plan_stale") from exception
        return {
            "schema": EXECUTION_SCHEMA,
            "plan_id": normalized["plan_id"],
            "review_request_id": review_request_id,
            "decision_ids": list(decision_ids),
            "event": event,
        }


__all__ = [
    "ATTRIBUTED_CATEGORIES",
    "CANDIDATE_SCHEMA",
    "CHECKPOINT_SCHEMA",
    "CONTENT_REF_SCHEMA",
    "DECISION_SCHEMA",
    "EXECUTION_SCHEMA",
    "PERSONAL_CATEGORIES",
    "PLAN_SCHEMA",
    "POLICY_SCHEMA",
    "RECORD_SCHEMA",
    "MemoryExecutionError",
    "MemoryPolicyError",
    "MemoryPolicyExecutor",
    "create_content_ref",
    "create_memory_candidate",
    "create_memory_policy",
    "evaluate_memory_candidate",
    "memory_checkpoint",
    "memory_decision",
    "validate_content_ref",
    "validate_memory_candidate",
    "validate_memory_checkpoint",
    "validate_memory_decision",
    "validate_memory_plan",
    "validate_memory_policy",
    "validate_memory_record",
    "validate_policy_successor",
]
