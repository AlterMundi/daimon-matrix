"""Purpose-limited human review authority for sensitive memory transitions.

Review decisions are signed by a dedicated reviewer key.  The hosted runtime
never receives that private key: it verifies an already-signed decision and
records the verified artifact in the being's canonical ledger.  Ledger event
signatures authorize the subject-side registration, but never substitute for
the human signature.
"""

from __future__ import annotations

import copy
import hashlib
import re
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .canonical import CanonicalError, b64url, canonical_bytes, unb64url
from .curator_worker import CuratorWorkerError, validate_worker_proposal
from .identity import key_id, signing_descriptor
from .ledger import Ledger
from .memory_policy import (
    CATEGORIES,
    CLASSIFICATIONS,
    CONSENTS,
    MemoryExecutionError,
    MemoryPolicyError,
    MemoryPolicyExecutor,
    evaluate_memory_candidate,
    memory_checkpoint,
    validate_memory_candidate,
    validate_memory_plan,
    validate_memory_policy,
)
from .weave import (
    BoundHistoryAuthority,
    EventSigner,
    ProvisionalAuthority,
    RootAuthority,
)

AUTHORIZATION_SCHEMA: Final = "dm.review.authorization/v1"
REVOCATION_SCHEMA: Final = "dm.review.revocation/v1"
REQUEST_SCHEMA: Final = "dm.review.request/v1"
DECISION_SCHEMA: Final = "dm.review.human-decision/v1"
RECEIPT_SCHEMA: Final = "dm.review.execution-receipt/v1"
ACCESS_PROOF_SCHEMA: Final = "dm.review.access-proof/v1"
QUEUE_SCHEMA: Final = "dm.review.queue/v1"
REQUESTED_ACTION: Final = "memory-transition"

AUTHORIZATION_DOMAIN: Final = b"daimon/review/authorization/v1\x00"
AUTHORIZATION_ACCEPTANCE_DOMAIN: Final = (
    b"daimon/review/authorization-acceptance/v1\x00"
)
REVOCATION_DOMAIN: Final = b"daimon/review/revocation/v1\x00"
REQUEST_DOMAIN: Final = b"daimon/review/request/v1\x00"
DECISION_DOMAIN: Final = b"daimon/review/human-decision/v1\x00"
ACCESS_PROOF_DOMAIN: Final = b"daimon/review/access-proof/v1\x00"
RECEIPT_DOMAIN: Final = b"daimon/review/execution-receipt/v1\x00"
GROUP_DOMAIN: Final = b"daimon/review/group/v1\x00"

AUTHORIZATION_KIND: Final = "review.authorization.issued"
REVOCATION_KIND: Final = "review.authorization.revoked"
REQUEST_KIND: Final = "review.requested"
DECISION_KIND: Final = "review.decided"
RECEIPT_KIND: Final = "review.executed"

ACTIONS: Final = frozenset({"accept", "edit", "reject", "defer"})
TERMINAL_ACTIONS: Final = frozenset({"accept", "edit", "reject"})
DECISION_REASONS_BY_ACTION: Final = {
    "accept": frozenset({"evidence-sufficient"}),
    "edit": frozenset({"content-correction"}),
    "reject": frozenset(
        {
            "consent-or-safety-concern",
            "evidence-insufficient",
            "policy-conflict",
            "superseded",
        }
    ),
    "defer": frozenset({"evidence-insufficient", "reconsideration-needed"}),
}
DECISION_REASONS: Final = frozenset(
    reason for reasons in DECISION_REASONS_BY_ACTION.values() for reason in reasons
)
MAX_REVIEWERS: Final = 16
MAX_DECISIONS: Final = 4096
MAX_TEXT_BYTES: Final = 1024
MAX_UINT: Final = 2**53 - 1
_SCOPED: Final = re.compile(r"^[A-Za-z0-9._:@-]{1,256}$")


class HumanReviewError(RuntimeError):
    """Stable fail-closed review error."""

    def __init__(self, code: str, *, retryable: bool = False) -> None:
        super().__init__(code)
        self.code = code
        self.retryable = retryable


Clock = Callable[[], int]


def _canonical(value: Any, code: str) -> bytes:
    try:
        return canonical_bytes(value)
    except CanonicalError as exception:
        raise HumanReviewError(code) from exception


def _closed(value: Any, fields: set[str], code: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise HumanReviewError(code)
    return value


def _text(value: Any, code: str, maximum: int = 256) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value.encode("utf-8")) <= maximum
        or any(ord(character) < 0x20 for character in value)
    ):
        raise HumanReviewError(code)
    _canonical(value, code)
    return value


def _scoped(value: Any, code: str) -> str:
    result = _text(value, code)
    if _SCOPED.fullmatch(result) is None:
        raise HumanReviewError(code)
    return result


def _uint(value: Any, code: str, minimum: int = 0) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not minimum <= value <= MAX_UINT
    ):
        raise HumanReviewError(code)
    return value


def _hash(value: Any, code: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise HumanReviewError(code)
    return value


def _derived(prefix: str, domain: bytes, core: Mapping[str, Any]) -> str:
    return prefix + b64url(
        hashlib.sha256(domain + _canonical(core, "invalid_review_artifact")).digest()
    )


def _derived_id(value: Any, prefix: str, code: str) -> str:
    result = _text(value, code, 160)
    if not result.startswith(prefix) or len(result.removeprefix(prefix)) != 43:
        raise HumanReviewError(code)
    try:
        unb64url(result.removeprefix(prefix), length=32)
    except CanonicalError as exception:
        raise HumanReviewError(code) from exception
    return result


def _uuid(value: Any, code: str) -> str:
    if not isinstance(value, str):
        raise HumanReviewError(code)
    try:
        parsed = uuid.UUID(value)
    except ValueError as exception:
        raise HumanReviewError(code) from exception
    if str(parsed) != value:
        raise HumanReviewError(code)
    return value


def _sorted_enum(value: Any, allowed: frozenset[str], code: str) -> list[str]:
    if (
        not isinstance(value, list)
        or value != sorted(set(value))
        or not value
        or any(item not in allowed for item in value)
    ):
        raise HumanReviewError(code)
    return list(value)


def _signature(value: Any, key_id: str, code: str) -> dict[str, str]:
    row = _closed(value, {"alg", "kid", "value"}, code)
    if row["alg"] != "Ed25519" or row["kid"] != key_id:
        raise HumanReviewError(code)
    try:
        unb64url(row["value"], length=64)
    except (CanonicalError, TypeError) as exception:
        raise HumanReviewError(code) from exception
    return {"alg": "Ed25519", "kid": key_id, "value": str(row["value"])}


def _reviewer(value: Any) -> dict[str, str]:
    row = _closed(value, {"algorithm", "key_id", "public"}, "invalid_reviewer_key")
    if row["algorithm"] != "Ed25519":
        raise HumanReviewError("invalid_reviewer_key")
    try:
        public = unb64url(row["public"], length=32)
    except (CanonicalError, TypeError) as exception:
        raise HumanReviewError("invalid_reviewer_key") from exception
    if row["key_id"] != key_id("Ed25519", public):
        raise HumanReviewError("reviewer_key_id_mismatch")
    return {key: str(row[key]) for key in ("algorithm", "key_id", "public")}


def review_group_id(member_key_ids: Sequence[str], threshold: int) -> str:
    members = sorted(set(member_key_ids))
    return _derived(
        "dm:review-group:v1:",
        GROUP_DOMAIN,
        {"member_key_ids": members, "threshold": threshold},
    )


def authorization_core(
    *,
    subject_me_id: str,
    policy_id: str,
    policy_hash: str,
    reviewer: Mapping[str, Any],
    group_id: str,
    member_key_ids: Sequence[str],
    threshold: int,
    categories: Sequence[str],
    classifications: Sequence[str],
    actions: Sequence[str],
    valid_from_ms: int,
    expires_at_ms: int,
    max_outstanding_decisions: int,
    control_position: Mapping[str, Any],
    issued_at_ms: int,
) -> dict[str, Any]:
    """Create the exact unsigned delegation body a reviewer must accept."""

    core = {
        "schema": AUTHORIZATION_SCHEMA,
        "subject_me_id": subject_me_id,
        "policy_id": policy_id,
        "policy_hash": policy_hash,
        "reviewer": copy.deepcopy(dict(reviewer)),
        "group": {
            "group_id": group_id,
            "member_key_ids": sorted(set(member_key_ids)),
            "threshold": threshold,
        },
        "scopes": {
            "categories": sorted(set(categories)),
            "classifications": sorted(set(classifications)),
            "actions": sorted(set(actions)),
        },
        "valid_from_ms": valid_from_ms,
        "expires_at_ms": expires_at_ms,
        "max_outstanding_decisions": max_outstanding_decisions,
        "control_position": copy.deepcopy(dict(control_position)),
        "issued_at_ms": issued_at_ms,
    }
    validate_authorization_core(core)
    return copy.deepcopy(core)


def validate_authorization_core(value: Any) -> dict[str, Any]:
    row = _closed(
        value,
        {
            "schema",
            "subject_me_id",
            "policy_id",
            "policy_hash",
            "reviewer",
            "group",
            "scopes",
            "valid_from_ms",
            "expires_at_ms",
            "max_outstanding_decisions",
            "control_position",
            "issued_at_ms",
        },
        "invalid_reviewer_authorization",
    )
    if row["schema"] != AUTHORIZATION_SCHEMA:
        raise HumanReviewError("unsupported_reviewer_authorization")
    _scoped(row["subject_me_id"], "invalid_reviewer_authorization")
    _derived_id(
        row["policy_id"], "dm:memory-policy:v1:", "invalid_reviewer_authorization"
    )
    _hash(row["policy_hash"], "invalid_reviewer_authorization")
    reviewer = _reviewer(row["reviewer"])
    group = _closed(
        row["group"],
        {"group_id", "member_key_ids", "threshold"},
        "invalid_reviewer_group",
    )
    _derived_id(group["group_id"], "dm:review-group:v1:", "invalid_reviewer_group")
    members = group["member_key_ids"]
    if (
        not isinstance(members, list)
        or not 1 <= len(members) <= MAX_REVIEWERS
        or members != sorted(set(members))
        or reviewer["key_id"] not in members
    ):
        raise HumanReviewError("invalid_reviewer_group")
    for member in members:
        _derived_id(member, "dm:key:v1:", "invalid_reviewer_group")
    threshold = _uint(group["threshold"], "invalid_reviewer_group", 1)
    if threshold > len(members):
        raise HumanReviewError("invalid_reviewer_group")
    if group["group_id"] != review_group_id(members, threshold):
        raise HumanReviewError("review_group_id_mismatch")
    scopes = _closed(
        row["scopes"],
        {"categories", "classifications", "actions"},
        "invalid_reviewer_scope",
    )
    _sorted_enum(scopes["categories"], CATEGORIES, "invalid_reviewer_scope")
    _sorted_enum(scopes["classifications"], CLASSIFICATIONS, "invalid_reviewer_scope")
    _sorted_enum(scopes["actions"], ACTIONS, "invalid_reviewer_scope")
    start = _uint(row["valid_from_ms"], "invalid_reviewer_authorization")
    end = _uint(row["expires_at_ms"], "invalid_reviewer_authorization", 1)
    issued = _uint(row["issued_at_ms"], "invalid_reviewer_authorization")
    if not issued <= start < end:
        raise HumanReviewError("invalid_reviewer_authorization_window")
    _uint(
        row["max_outstanding_decisions"],
        "invalid_reviewer_authorization",
        1,
    )
    control = _closed(
        row["control_position"],
        {"manifest_hash", "embodiment_id", "incarnation_id"},
        "invalid_reviewer_control_position",
    )
    _hash(control["manifest_hash"], "invalid_reviewer_control_position")
    _scoped(control["embodiment_id"], "invalid_reviewer_control_position")
    _scoped(control["incarnation_id"], "invalid_reviewer_control_position")
    return copy.deepcopy(dict(row))


def accept_authorization(
    core: Mapping[str, Any], reviewer_seed: bytes
) -> dict[str, Any]:
    normalized = validate_authorization_core(core)
    descriptor = signing_descriptor(reviewer_seed)
    if descriptor != normalized["reviewer"]:
        raise HumanReviewError("reviewer_seed_mismatch")
    authorization_id = _derived(
        "dm:review-authorization:v1:", AUTHORIZATION_DOMAIN, normalized
    )
    signature = Ed25519PrivateKey.from_private_bytes(reviewer_seed).sign(
        AUTHORIZATION_ACCEPTANCE_DOMAIN + authorization_id.encode("ascii")
    )
    return validate_reviewer_authorization(
        {
            **normalized,
            "authorization_id": authorization_id,
            "acceptance": {
                "alg": "Ed25519",
                "kid": descriptor["key_id"],
                "value": b64url(signature),
            },
        }
    )


def validate_reviewer_authorization(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise HumanReviewError("invalid_reviewer_authorization")
    expected_fields = set(
        validate_authorization_core(
            {
                key: item
                for key, item in value.items()
                if key not in {"authorization_id", "acceptance"}
            }
        )
    )
    if set(value) != expected_fields | {"authorization_id", "acceptance"}:
        raise HumanReviewError("invalid_reviewer_authorization")
    core = validate_authorization_core(
        {key: copy.deepcopy(value[key]) for key in expected_fields}
    )
    identifier = _derived("dm:review-authorization:v1:", AUTHORIZATION_DOMAIN, core)
    if value["authorization_id"] != identifier:
        raise HumanReviewError("reviewer_authorization_id_mismatch")
    reviewer = _reviewer(core["reviewer"])
    signature = _signature(
        value["acceptance"], reviewer["key_id"], "invalid_reviewer_acceptance"
    )
    try:
        Ed25519PublicKey.from_public_bytes(
            unb64url(reviewer["public"], length=32)
        ).verify(
            unb64url(signature["value"], length=64),
            AUTHORIZATION_ACCEPTANCE_DOMAIN + identifier.encode("ascii"),
        )
    except (CanonicalError, InvalidSignature) as exception:
        raise HumanReviewError("invalid_reviewer_acceptance") from exception
    return copy.deepcopy(dict(value))


def validate_revocation(value: Any) -> dict[str, Any]:
    fields = {
        "schema",
        "revocation_id",
        "authorization_id",
        "authorization_event_id",
        "reason",
        "revoked_at_ms",
    }
    row = _closed(value, fields, "invalid_review_revocation")
    if row["schema"] != REVOCATION_SCHEMA:
        raise HumanReviewError("unsupported_review_revocation")
    _derived_id(
        row["authorization_id"],
        "dm:review-authorization:v1:",
        "invalid_review_revocation",
    )
    _uuid(row["authorization_event_id"], "invalid_review_revocation")
    _scoped(row["reason"], "invalid_review_revocation")
    _uint(row["revoked_at_ms"], "invalid_review_revocation")
    core = {key: copy.deepcopy(row[key]) for key in row if key != "revocation_id"}
    if row["revocation_id"] != _derived(
        "dm:review-revocation:v1:", REVOCATION_DOMAIN, core
    ):
        raise HumanReviewError("review_revocation_id_mismatch")
    return copy.deepcopy(dict(row))


def create_revocation(
    *,
    authorization_id: str,
    authorization_event_id: str,
    reason: str,
    revoked_at_ms: int,
) -> dict[str, Any]:
    core = {
        "schema": REVOCATION_SCHEMA,
        "authorization_id": authorization_id,
        "authorization_event_id": authorization_event_id,
        "reason": reason,
        "revoked_at_ms": revoked_at_ms,
    }
    return validate_revocation(
        {
            **core,
            "revocation_id": _derived(
                "dm:review-revocation:v1:", REVOCATION_DOMAIN, core
            ),
        }
    )


def create_review_request(
    *,
    policy: Mapping[str, Any],
    candidate: Mapping[str, Any],
    plan: Mapping[str, Any],
    proposal: Mapping[str, Any] | None,
    authorization_ids: Sequence[str],
    group_id: str,
    threshold: int,
    requested_at_ms: int,
    expires_at_ms: int,
    predecessor_review_request_id: str | None = None,
) -> dict[str, Any]:
    normalized_policy = validate_memory_policy(policy)
    normalized_candidate = validate_memory_candidate(candidate)
    normalized_plan = validate_memory_plan(plan)
    normalized_proposal = None
    if proposal is not None:
        try:
            normalized_proposal = validate_worker_proposal(proposal)
        except CuratorWorkerError as exception:
            raise HumanReviewError("invalid_review_proposal") from exception
    core = {
        "schema": REQUEST_SCHEMA,
        "subject_me_id": normalized_plan["subject_me_id"],
        "policy": normalized_policy,
        "policy_hash": hashlib.sha256(
            _canonical(normalized_policy, "invalid_review_request")
        ).hexdigest(),
        "candidate": normalized_candidate,
        "candidate_hash": hashlib.sha256(
            _canonical(normalized_candidate, "invalid_review_request")
        ).hexdigest(),
        "plan": normalized_plan,
        "plan_hash": hashlib.sha256(
            _canonical(normalized_plan, "invalid_review_request")
        ).hexdigest(),
        "proposal": normalized_proposal,
        "proposal_hash": None
        if normalized_proposal is None
        else hashlib.sha256(
            _canonical(normalized_proposal, "invalid_review_request")
        ).hexdigest(),
        "authorization_ids": sorted(set(authorization_ids)),
        "group_id": group_id,
        "threshold": threshold,
        "requested_action": REQUESTED_ACTION,
        "predecessor_review_request_id": predecessor_review_request_id,
        "classification": normalized_candidate["classification"],
        "consent": normalized_candidate["consent"],
        "reasons": normalized_plan["reasons"],
        "projected_effect_hash": hashlib.sha256(
            _canonical(normalized_plan["event_preview"], "invalid_review_request")
        ).hexdigest(),
        "requested_at_ms": requested_at_ms,
        "expires_at_ms": expires_at_ms,
    }
    return validate_review_request(
        {
            **core,
            "review_request_id": _derived(
                "dm:review-request:v1:", REQUEST_DOMAIN, core
            ),
        }
    )


def validate_review_request(value: Any) -> dict[str, Any]:
    fields = {
        "schema",
        "review_request_id",
        "subject_me_id",
        "policy",
        "policy_hash",
        "candidate",
        "candidate_hash",
        "plan",
        "plan_hash",
        "proposal",
        "proposal_hash",
        "authorization_ids",
        "group_id",
        "threshold",
        "requested_action",
        "predecessor_review_request_id",
        "classification",
        "consent",
        "reasons",
        "projected_effect_hash",
        "requested_at_ms",
        "expires_at_ms",
    }
    row = _closed(value, fields, "invalid_review_request")
    if row["schema"] != REQUEST_SCHEMA:
        raise HumanReviewError("unsupported_review_request")
    policy = validate_memory_policy(row["policy"])
    candidate = validate_memory_candidate(row["candidate"])
    plan = validate_memory_plan(row["plan"])
    if (
        plan["outcome"] != "review-required"
        or row["subject_me_id"] != plan["subject_me_id"]
        or plan["policy_id"] != policy["policy_id"]
        or plan["candidate_id"] != candidate["candidate_id"]
        or row["classification"] != candidate["classification"]
        or row["consent"] != candidate["consent"]
        or row["reasons"] != plan["reasons"]
    ):
        raise HumanReviewError("review_request_memory_mismatch")
    for artifact, field in (
        (policy, "policy_hash"),
        (candidate, "candidate_hash"),
        (plan, "plan_hash"),
    ):
        if (
            row[field]
            != hashlib.sha256(
                _canonical(artifact, "invalid_review_request")
            ).hexdigest()
        ):
            raise HumanReviewError("review_request_hash_mismatch")
    proposal = row["proposal"]
    if proposal is None:
        if row["proposal_hash"] is not None:
            raise HumanReviewError("review_request_proposal_mismatch")
    else:
        try:
            normalized_proposal = validate_worker_proposal(proposal)
        except CuratorWorkerError as exception:
            raise HumanReviewError("invalid_review_proposal") from exception
        if (
            row["proposal_hash"]
            != hashlib.sha256(
                _canonical(normalized_proposal, "invalid_review_request")
            ).hexdigest()
        ):
            raise HumanReviewError("review_request_proposal_mismatch")
        content = candidate["content_ref"]
        proposed_content = normalized_proposal["content_ref"]
        if (
            content is None
            or content["sha256"] != proposed_content["sha256"]
            or content["byte_length"] != proposed_content["byte_length"]
            or candidate["category"] != normalized_proposal["category"]
            or candidate["derivation"] != normalized_proposal["derivation"]
            or candidate["evidence_refs"] != normalized_proposal["evidence_refs"]
        ):
            raise HumanReviewError("review_request_proposal_mismatch")
    identifiers = row["authorization_ids"]
    if (
        not isinstance(identifiers, list)
        or not 1 <= len(identifiers) <= MAX_REVIEWERS
        or identifiers != sorted(set(identifiers))
    ):
        raise HumanReviewError("invalid_review_request_authorizations")
    for identifier in identifiers:
        _derived_id(
            identifier,
            "dm:review-authorization:v1:",
            "invalid_review_request_authorizations",
        )
    _derived_id(row["group_id"], "dm:review-group:v1:", "invalid_review_request_group")
    threshold = _uint(row["threshold"], "invalid_review_request_group", 1)
    if threshold > len(identifiers):
        raise HumanReviewError("invalid_review_request_group")
    if row["classification"] not in CLASSIFICATIONS or row["consent"] not in CONSENTS:
        raise HumanReviewError("invalid_review_request")
    if row["requested_action"] != REQUESTED_ACTION:
        raise HumanReviewError("invalid_review_request_action")
    predecessor_request = row["predecessor_review_request_id"]
    if predecessor_request is not None:
        _derived_id(
            predecessor_request,
            "dm:review-request:v1:",
            "invalid_review_request_predecessor",
        )
    reasons = row["reasons"]
    if not isinstance(reasons, list) or reasons != sorted(set(reasons)) or not reasons:
        raise HumanReviewError("invalid_review_request")
    for reason in reasons:
        _scoped(reason, "invalid_review_request")
    _hash(row["projected_effect_hash"], "invalid_review_request")
    projected = hashlib.sha256(
        _canonical(plan["event_preview"], "invalid_review_request")
    ).hexdigest()
    if row["projected_effect_hash"] != projected:
        raise HumanReviewError("review_request_effect_mismatch")
    requested = _uint(row["requested_at_ms"], "invalid_review_request")
    expires = _uint(row["expires_at_ms"], "invalid_review_request", 1)
    if not requested < expires <= plan["expires_at_ms"]:
        raise HumanReviewError("invalid_review_request_window")
    core = {key: copy.deepcopy(row[key]) for key in row if key != "review_request_id"}
    expected = _derived("dm:review-request:v1:", REQUEST_DOMAIN, core)
    if row["review_request_id"] != expected:
        raise HumanReviewError("review_request_id_mismatch")
    return copy.deepcopy(dict(row))


def create_decision_draft(
    *,
    request: Mapping[str, Any],
    authorization_id: str,
    reviewer_key_id: str,
    action: str,
    replacement: Mapping[str, Any] | None,
    reason: str,
    note_ref: str | None,
    decision_nonce: str,
    decided_at_ms: int,
    predecessor_decision_id: str | None,
) -> dict[str, Any]:
    normalized_request = validate_review_request(request)
    core = {
        "schema": DECISION_SCHEMA,
        "review_request_id": normalized_request["review_request_id"],
        "review_request_hash": hashlib.sha256(
            _canonical(normalized_request, "invalid_review_decision")
        ).hexdigest(),
        "authorization_id": authorization_id,
        "reviewer_key_id": reviewer_key_id,
        "action": action,
        "replacement": None
        if replacement is None
        else copy.deepcopy(dict(replacement)),
        "reason": reason,
        "note_ref": note_ref,
        "decision_nonce": decision_nonce,
        "decided_at_ms": decided_at_ms,
        "predecessor_decision_id": predecessor_decision_id,
    }
    validate_decision_core(core)
    return copy.deepcopy(core)


def _validate_replacement(value: Any) -> dict[str, Any]:
    row = _closed(
        value, {"policy", "candidate", "plan", "proposal"}, "invalid_review_replacement"
    )
    request = create_review_request(
        policy=row["policy"],
        candidate=row["candidate"],
        plan=row["plan"],
        proposal=row["proposal"],
        authorization_ids=["dm:review-authorization:v1:" + "A" * 43],
        group_id="dm:review-group:v1:" + "A" * 43,
        threshold=1,
        requested_at_ms=row["plan"]["evaluated_at_ms"],
        expires_at_ms=row["plan"]["expires_at_ms"],
    )
    try:
        regenerated = evaluate_memory_candidate(
            request["policy"],
            request["candidate"],
            request["plan"]["checkpoint"],
            evaluated_at_ms=request["plan"]["evaluated_at_ms"],
        )
    except MemoryPolicyError as exception:
        raise HumanReviewError("review_replacement_policy_mismatch") from exception
    if regenerated != request["plan"]:
        raise HumanReviewError("review_replacement_policy_mismatch")
    return {
        key: copy.deepcopy(request[key])
        for key in ("policy", "candidate", "plan", "proposal")
    }


def validate_decision_core(value: Any) -> dict[str, Any]:
    row = _closed(
        value,
        {
            "schema",
            "review_request_id",
            "review_request_hash",
            "authorization_id",
            "reviewer_key_id",
            "action",
            "replacement",
            "reason",
            "note_ref",
            "decision_nonce",
            "decided_at_ms",
            "predecessor_decision_id",
        },
        "invalid_review_decision",
    )
    if row["schema"] != DECISION_SCHEMA or row["action"] not in ACTIONS:
        raise HumanReviewError("invalid_review_decision")
    _derived_id(
        row["review_request_id"], "dm:review-request:v1:", "invalid_review_decision"
    )
    _hash(row["review_request_hash"], "invalid_review_decision")
    _derived_id(
        row["authorization_id"],
        "dm:review-authorization:v1:",
        "invalid_review_decision",
    )
    _text(row["reviewer_key_id"], "invalid_review_decision", 128)
    if not row["reviewer_key_id"].startswith("dm:key:v1:"):
        raise HumanReviewError("invalid_review_decision")
    if row["action"] == "edit":
        _validate_replacement(row["replacement"])
    elif row["replacement"] is not None:
        raise HumanReviewError("review_replacement_forbidden")
    if row["reason"] not in DECISION_REASONS_BY_ACTION[row["action"]]:
        raise HumanReviewError("invalid_review_decision_reason")
    if row["note_ref"] is not None:
        _scoped(row["note_ref"], "invalid_review_decision")
    _uuid(row["decision_nonce"], "invalid_review_decision")
    _uint(row["decided_at_ms"], "invalid_review_decision")
    predecessor = row["predecessor_decision_id"]
    if predecessor is not None:
        _derived_id(predecessor, "dm:review-decision:v1:", "invalid_review_decision")
    return copy.deepcopy(dict(row))


def sign_review_decision(
    core: Mapping[str, Any], reviewer_seed: bytes
) -> dict[str, Any]:
    normalized = validate_decision_core(core)
    descriptor = signing_descriptor(reviewer_seed)
    if normalized["reviewer_key_id"] != descriptor["key_id"]:
        raise HumanReviewError("reviewer_seed_mismatch")
    decision_id = _derived("dm:review-decision:v1:", DECISION_DOMAIN, normalized)
    value = Ed25519PrivateKey.from_private_bytes(reviewer_seed).sign(
        DECISION_DOMAIN + decision_id.encode("ascii")
    )
    return {
        **normalized,
        "decision_id": decision_id,
        "signature": {
            "alg": "Ed25519",
            "kid": descriptor["key_id"],
            "value": b64url(value),
        },
    }


def validate_human_decision(
    value: Any, authorization: Mapping[str, Any], request: Mapping[str, Any]
) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != set(
        validate_decision_core(
            {
                key: item
                for key, item in value.items()
                if key not in {"decision_id", "signature"}
            }
        )
    ) | {"decision_id", "signature"}:
        raise HumanReviewError("invalid_review_decision")
    core = validate_decision_core(
        {
            key: copy.deepcopy(item)
            for key, item in value.items()
            if key not in {"decision_id", "signature"}
        }
    )
    auth = validate_reviewer_authorization(authorization)
    review_request = validate_review_request(request)
    if (
        core["review_request_id"] != review_request["review_request_id"]
        or core["review_request_hash"]
        != hashlib.sha256(
            _canonical(review_request, "invalid_review_decision")
        ).hexdigest()
        or core["authorization_id"] != auth["authorization_id"]
        or core["reviewer_key_id"] != auth["reviewer"]["key_id"]
        or core["action"] not in auth["scopes"]["actions"]
    ):
        raise HumanReviewError("review_decision_scope_mismatch")
    identifier = _derived("dm:review-decision:v1:", DECISION_DOMAIN, core)
    if value["decision_id"] != identifier:
        raise HumanReviewError("review_decision_id_mismatch")
    signature = _signature(
        value["signature"], core["reviewer_key_id"], "invalid_review_decision_signature"
    )
    try:
        Ed25519PublicKey.from_public_bytes(
            unb64url(auth["reviewer"]["public"], length=32)
        ).verify(
            unb64url(signature["value"], length=64),
            DECISION_DOMAIN + identifier.encode("ascii"),
        )
    except (CanonicalError, InvalidSignature) as exception:
        raise HumanReviewError("invalid_review_decision_signature") from exception
    return copy.deepcopy(dict(value))


def validate_signed_decision_shape(value: Any) -> dict[str, Any]:
    """Validate content addressing and signature shape without an authorization.

    Cryptographic verification remains context-dependent and is performed by
    :func:`validate_human_decision` once the exact request and delegation are
    available.
    """

    if not isinstance(value, Mapping):
        raise HumanReviewError("invalid_review_decision")
    core_value = {
        key: item
        for key, item in value.items()
        if key not in {"decision_id", "signature"}
    }
    core = validate_decision_core(core_value)
    if set(value) != set(core) | {"decision_id", "signature"}:
        raise HumanReviewError("invalid_review_decision")
    identifier = _derived("dm:review-decision:v1:", DECISION_DOMAIN, core)
    if value["decision_id"] != identifier:
        raise HumanReviewError("review_decision_id_mismatch")
    _signature(
        value["signature"],
        core["reviewer_key_id"],
        "invalid_review_decision_signature",
    )
    return copy.deepcopy(dict(value))


def create_access_proof(
    *,
    authorization_id: str,
    rpc_request_id: str,
    issued_at_ms: int,
    expires_at_ms: int,
    reviewer_seed: bytes,
) -> dict[str, Any]:
    descriptor = signing_descriptor(reviewer_seed)
    core = {
        "schema": ACCESS_PROOF_SCHEMA,
        "authorization_id": authorization_id,
        "reviewer_key_id": descriptor["key_id"],
        "rpc_request_id": rpc_request_id,
        "issued_at_ms": issued_at_ms,
        "expires_at_ms": expires_at_ms,
    }
    _derived_id(
        authorization_id,
        "dm:review-authorization:v1:",
        "invalid_review_access_proof",
    )
    _uuid(rpc_request_id, "invalid_review_access_proof")
    issued = _uint(issued_at_ms, "invalid_review_access_proof")
    expires = _uint(expires_at_ms, "invalid_review_access_proof", 1)
    if not issued < expires <= issued + 60_000:
        raise HumanReviewError("invalid_review_access_proof")
    proof_id = _derived("dm:review-access:v1:", ACCESS_PROOF_DOMAIN, core)
    signature = Ed25519PrivateKey.from_private_bytes(reviewer_seed).sign(
        ACCESS_PROOF_DOMAIN + proof_id.encode("ascii")
    )
    return {
        **core,
        "proof_id": proof_id,
        "signature": {
            "alg": "Ed25519",
            "kid": descriptor["key_id"],
            "value": b64url(signature),
        },
    }


def validate_access_proof(
    value: Any,
    authorization: Mapping[str, Any],
    *,
    rpc_request_id: str,
    now_ms: int,
) -> dict[str, Any]:
    fields = {
        "schema",
        "proof_id",
        "authorization_id",
        "reviewer_key_id",
        "rpc_request_id",
        "issued_at_ms",
        "expires_at_ms",
        "signature",
    }
    row = _closed(value, fields, "invalid_review_access_proof")
    auth = validate_reviewer_authorization(authorization)
    if (
        row["schema"] != ACCESS_PROOF_SCHEMA
        or row["authorization_id"] != auth["authorization_id"]
        or row["reviewer_key_id"] != auth["reviewer"]["key_id"]
        or row["rpc_request_id"] != rpc_request_id
    ):
        raise HumanReviewError("invalid_review_access_proof")
    _uuid(row["rpc_request_id"], "invalid_review_access_proof")
    issued = _uint(row["issued_at_ms"], "invalid_review_access_proof")
    expires = _uint(row["expires_at_ms"], "invalid_review_access_proof", 1)
    if not issued <= now_ms <= expires <= issued + 60_000:
        raise HumanReviewError("review_access_proof_not_current")
    core = {
        key: copy.deepcopy(row[key])
        for key in row
        if key not in {"proof_id", "signature"}
    }
    identifier = _derived("dm:review-access:v1:", ACCESS_PROOF_DOMAIN, core)
    if row["proof_id"] != identifier:
        raise HumanReviewError("review_access_proof_id_mismatch")
    signature = _signature(
        row["signature"],
        auth["reviewer"]["key_id"],
        "invalid_review_access_signature",
    )
    try:
        Ed25519PublicKey.from_public_bytes(
            unb64url(auth["reviewer"]["public"], length=32)
        ).verify(
            unb64url(signature["value"], length=64),
            ACCESS_PROOF_DOMAIN + identifier.encode("ascii"),
        )
    except (CanonicalError, InvalidSignature) as exception:
        raise HumanReviewError("invalid_review_access_signature") from exception
    return copy.deepcopy(dict(row))


def validate_execution_receipt(value: Any) -> dict[str, Any]:
    fields = {
        "schema",
        "receipt_id",
        "review_request_id",
        "request_event_id",
        "action",
        "decision_ids",
        "memory_event_id",
        "successor_request_id",
        "result",
        "executed_at_ms",
    }
    row = _closed(value, fields, "invalid_review_execution_receipt")
    if row["schema"] != RECEIPT_SCHEMA or row["action"] not in TERMINAL_ACTIONS:
        raise HumanReviewError("invalid_review_execution_receipt")
    _derived_id(
        row["review_request_id"],
        "dm:review-request:v1:",
        "invalid_review_execution_receipt",
    )
    _uuid(row["request_event_id"], "invalid_review_execution_receipt")
    decisions = row["decision_ids"]
    if (
        not isinstance(decisions, list)
        or not decisions
        or decisions != sorted(set(decisions))
    ):
        raise HumanReviewError("invalid_review_execution_receipt")
    for identifier in decisions:
        _derived_id(
            identifier,
            "dm:review-decision:v1:",
            "invalid_review_execution_receipt",
        )
    memory_event_id = row["memory_event_id"]
    successor = row["successor_request_id"]
    if row["action"] == "accept":
        _uuid(memory_event_id, "invalid_review_execution_receipt")
        if successor is not None or row["result"] != "applied":
            raise HumanReviewError("invalid_review_execution_receipt")
    elif row["action"] == "edit":
        _derived_id(
            successor,
            "dm:review-request:v1:",
            "invalid_review_execution_receipt",
        )
        if memory_event_id is not None or row["result"] != "successor-requested":
            raise HumanReviewError("invalid_review_execution_receipt")
    elif (
        memory_event_id is not None or successor is not None or row["result"] != "no-op"
    ):
        raise HumanReviewError("invalid_review_execution_receipt")
    _uint(row["executed_at_ms"], "invalid_review_execution_receipt")
    core = {key: copy.deepcopy(row[key]) for key in row if key != "receipt_id"}
    if row["receipt_id"] != _derived("dm:review-receipt:v1:", RECEIPT_DOMAIN, core):
        raise HumanReviewError("review_execution_receipt_id_mismatch")
    return copy.deepcopy(dict(row))


def create_execution_receipt(
    *,
    review_request_id: str,
    request_event_id: str,
    action: str,
    decision_ids: Sequence[str],
    memory_event_id: str | None,
    successor_request_id: str | None,
    executed_at_ms: int,
) -> dict[str, Any]:
    result = (
        "applied"
        if action == "accept"
        else "no-op"
        if action == "reject"
        else "successor-requested"
    )
    core = {
        "schema": RECEIPT_SCHEMA,
        "review_request_id": review_request_id,
        "request_event_id": request_event_id,
        "action": action,
        "decision_ids": sorted(set(decision_ids)),
        "memory_event_id": memory_event_id,
        "successor_request_id": successor_request_id,
        "result": result,
        "executed_at_ms": executed_at_ms,
    }
    return validate_execution_receipt(
        {
            **core,
            "receipt_id": _derived("dm:review-receipt:v1:", RECEIPT_DOMAIN, core),
        }
    )


@dataclass(frozen=True)
class HumanReviewCoordinator:
    ledger: Ledger
    signer: EventSigner
    clock: Clock

    def _reserved_authority_key_ids(self) -> set[str]:
        """Keys already carrying being/embodiment authority cannot review."""

        reserved = {self.signer.key_id}
        authority = self.ledger.authority
        if isinstance(authority, ProvisionalAuthority):
            reserved.update(authority.public_keys)
            return reserved
        root = (
            authority.active
            if isinstance(authority, BoundHistoryAuthority)
            else authority
        )
        if not isinstance(
            root, RootAuthority
        ):  # pragma: no cover - closed authority set
            return reserved
        for policy in (root.state.root_policy, root.state.recovery_policy):
            keys = policy.get("keys")
            if isinstance(keys, list):
                reserved.update(
                    str(descriptor.get("key_id"))
                    for descriptor in keys
                    if isinstance(descriptor, Mapping)
                )
        for credential in root.credentials.values():
            body = credential.get("body")
            if not isinstance(body, Mapping):
                continue
            signing_key = body.get("signing_key")
            if isinstance(signing_key, Mapping) and isinstance(
                signing_key.get("key_id"), str
            ):
                reserved.add(signing_key["key_id"])
        return reserved

    def _validate_current_control(self, authorization: Mapping[str, Any]) -> None:
        origin = self.ledger.local_origin
        position = authorization["control_position"]
        if (
            position["manifest_hash"] != self.ledger.authority.manifest.digest
            or position["embodiment_id"] != origin["embodiment_id"]
            or position["incarnation_id"] != origin["incarnation_id"]
        ):
            raise HumanReviewError("review_authorization_control_not_current")
        self.ledger.authority.validate_origin(origin, require_active=True)
        if authorization["reviewer"]["key_id"] in self._reserved_authority_key_ids():
            raise HumanReviewError("reviewer_authority_not_separate")

    def _events(self, kind: str) -> list[dict[str, Any]]:
        return [
            event
            for event in self.ledger.events(include_incomplete=False)
            if event["kind"] == kind
        ]

    def _existing(
        self,
        kind: str,
        identifier_field: str,
        identifier: str,
    ) -> tuple[dict[str, Any], dict[str, Any]] | None:
        matches = [
            event
            for event in self._events(kind)
            if event["payload"].get(identifier_field) == identifier
        ]
        if len(matches) > 1:
            raise HumanReviewError("review_artifact_equivocation")
        if not matches:
            return None
        return copy.deepcopy(matches[0]["payload"]), matches[0]

    @staticmethod
    def _event_uuid(prefix: str, identifier: str) -> str:
        return str(uuid.uuid5(uuid.NAMESPACE_URL, prefix + identifier))

    def _append(
        self,
        *,
        kind: str,
        subject: str,
        payload: Mapping[str, Any],
        identifier: str,
        client_id: str,
        request_id: str,
        causal_parents: Sequence[str] = (),
        sensitivity: str = "private",
    ) -> dict[str, Any]:
        request_hash = hashlib.sha256(
            _canonical({"kind": kind, "payload": payload}, "invalid_review_event")
        ).hexdigest()
        return self.ledger.append_local_idempotent(
            client_id=client_id,
            request_id=request_id,
            request_hash=request_hash,
            kind=kind,
            subject=subject,
            payload=payload,
            signer=self.signer,
            sensitivity=sensitivity,
            causal_parents=causal_parents,
            event_id=self._event_uuid("daimon-review-event:", identifier),
        )

    def authorization(
        self, authorization_id: str
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        for event in self._events(AUTHORIZATION_KIND):
            payload = validate_reviewer_authorization(event["payload"])
            if payload["authorization_id"] == authorization_id:
                control = payload["control_position"]
                if (
                    event["being_ref"] != payload["subject_me_id"]
                    or event["subject"] != payload["subject_me_id"]
                    or event["manifest_hash"] != control["manifest_hash"]
                    or event["origin"]["embodiment_id"] != control["embodiment_id"]
                    or event["origin"]["incarnation_id"] != control["incarnation_id"]
                ):
                    raise HumanReviewError("review_authorization_control_mismatch")
                return payload, event
        raise HumanReviewError("review_authorization_unknown")

    def authorize(
        self, authorization: Mapping[str, Any], *, client_id: str, request_id: str
    ) -> dict[str, Any]:
        value = validate_reviewer_authorization(authorization)
        origin = self.ledger.local_origin
        position = value["control_position"]
        if (
            value["subject_me_id"] != self.ledger.authority.manifest.being_ref
            or position["manifest_hash"] != self.ledger.authority.manifest.digest
            or position["embodiment_id"] != origin["embodiment_id"]
            or position["incarnation_id"] != origin["incarnation_id"]
        ):
            raise HumanReviewError("review_authorization_control_mismatch")
        self._validate_current_control(value)
        existing = self._existing(
            AUTHORIZATION_KIND,
            "authorization_id",
            value["authorization_id"],
        )
        if existing is not None:
            payload, event = existing
            if payload != value:
                raise HumanReviewError("review_artifact_equivocation")
            return {
                "schema": "dm.review.authorization-result/v1",
                "authorization": value,
                "event": event,
            }
        event = self._append(
            kind=AUTHORIZATION_KIND,
            subject=value["subject_me_id"],
            payload=value,
            identifier=value["authorization_id"],
            client_id=client_id,
            request_id=request_id,
        )
        return {
            "schema": "dm.review.authorization-result/v1",
            "authorization": value,
            "event": event,
        }

    def revoked(self, authorization_id: str, at_ms: int) -> bool:
        return any(
            event["payload"].get("authorization_id") == authorization_id
            and event["payload"].get("revoked_at_ms", MAX_UINT) <= at_ms
            for event in self._events(REVOCATION_KIND)
        )

    def revoke(
        self, authorization_id: str, *, reason: str, client_id: str, request_id: str
    ) -> dict[str, Any]:
        authorization, authorization_event = self.authorization(authorization_id)
        now = _uint(self.clock(), "invalid_review_time")
        _scoped(reason, "invalid_review_revocation")
        revocation = create_revocation(
            authorization_id=authorization_id,
            authorization_event_id=authorization_event["event_id"],
            reason=reason,
            revoked_at_ms=now,
        )
        existing = self._existing(
            REVOCATION_KIND,
            "revocation_id",
            revocation["revocation_id"],
        )
        if existing is not None:
            payload, event = existing
            if payload != revocation:
                raise HumanReviewError("review_artifact_equivocation")
            return {
                "schema": "dm.review.revocation-result/v1",
                "revocation": revocation,
                "event": event,
            }
        event = self._append(
            kind=REVOCATION_KIND,
            subject=authorization["subject_me_id"],
            payload=revocation,
            identifier=revocation["revocation_id"],
            client_id=client_id,
            request_id=request_id,
            causal_parents=[authorization_event["event_id"]],
        )
        return {
            "schema": "dm.review.revocation-result/v1",
            "revocation": revocation,
            "event": event,
        }

    def _active_authorizations(
        self, request: Mapping[str, Any], at_ms: int
    ) -> list[tuple[dict[str, Any], dict[str, Any]]]:
        result = [
            self.authorization(identifier)
            for identifier in request["authorization_ids"]
        ]
        candidate = request["candidate"]
        expected_members: list[str] | None = None
        for authorization, _event in result:
            self._validate_current_control(authorization)
            group = authorization["group"]
            if (
                authorization["subject_me_id"] != request["subject_me_id"]
                or authorization["policy_id"] != request["policy"]["policy_id"]
                or authorization["policy_hash"] != request["policy_hash"]
                or group["group_id"] != request["group_id"]
                or group["threshold"] != request["threshold"]
                or not authorization["valid_from_ms"]
                <= at_ms
                <= authorization["expires_at_ms"]
                or self.revoked(authorization["authorization_id"], at_ms)
                or candidate["category"] not in authorization["scopes"]["categories"]
                or candidate["classification"]
                not in authorization["scopes"]["classifications"]
            ):
                raise HumanReviewError("review_authorization_not_current")
            members = group["member_key_ids"]
            if expected_members is None:
                expected_members = members
            elif expected_members != members:
                raise HumanReviewError("review_group_mismatch")
        actual_members = sorted(
            authorization["reviewer"]["key_id"] for authorization, _event in result
        )
        if expected_members != actual_members:
            raise HumanReviewError("review_group_incomplete")
        return result

    def request_review(
        self, request: Mapping[str, Any], *, client_id: str, request_id: str
    ) -> dict[str, Any]:
        value = validate_review_request(request)
        now = _uint(self.clock(), "invalid_review_time")
        if value["requested_at_ms"] != now or now >= value["expires_at_ms"]:
            raise HumanReviewError("review_request_not_current")
        authorizations = self._active_authorizations(value, now)
        if value["expires_at_ms"] > min(
            auth["expires_at_ms"] for auth, _event in authorizations
        ):
            raise HumanReviewError("review_request_exceeds_authorization")
        existing = self._existing(
            REQUEST_KIND,
            "review_request_id",
            value["review_request_id"],
        )
        if existing is not None:
            payload, event = existing
            if payload != value:
                raise HumanReviewError("review_artifact_equivocation")
            return {
                "schema": "dm.review.request-result/v1",
                "request": value,
                "event": event,
            }
        event = self._append(
            kind=REQUEST_KIND,
            subject=value["subject_me_id"],
            payload=value,
            identifier=value["review_request_id"],
            client_id=client_id,
            request_id=request_id,
            causal_parents=[event["event_id"] for _auth, event in authorizations],
        )
        return {
            "schema": "dm.review.request-result/v1",
            "request": value,
            "event": event,
        }

    def review_request(
        self, review_request_id: str
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        for event in self._events(REQUEST_KIND):
            payload = validate_review_request(event["payload"])
            if payload["review_request_id"] == review_request_id:
                if (
                    event["being_ref"] != payload["subject_me_id"]
                    or event["subject"] != payload["subject_me_id"]
                ):
                    raise HumanReviewError("review_request_subject_mismatch")
                return payload, event
        raise HumanReviewError("review_request_unknown")

    def submit(
        self, decision: Mapping[str, Any], *, client_id: str, request_id: str
    ) -> dict[str, Any]:
        if not isinstance(decision, Mapping):
            raise HumanReviewError("invalid_review_decision")
        review_request, request_event = self.review_request(
            str(decision.get("review_request_id", ""))
        )
        authorization, authorization_event = self.authorization(
            str(decision.get("authorization_id", ""))
        )
        value = validate_human_decision(decision, authorization, review_request)
        now = _uint(self.clock(), "invalid_review_time")
        self._active_authorizations(review_request, now)
        if authorization["authorization_id"] not in review_request["authorization_ids"]:
            raise HumanReviewError("review_decision_scope_mismatch")
        if (
            not authorization["valid_from_ms"]
            <= value["decided_at_ms"]
            <= now
            <= authorization["expires_at_ms"]
            or value["decided_at_ms"] < review_request["requested_at_ms"]
            or now > review_request["expires_at_ms"]
            or self.revoked(authorization["authorization_id"], now)
        ):
            raise HumanReviewError("review_decision_not_current")
        if (
            review_request["candidate"]["category"]
            not in authorization["scopes"]["categories"]
            or review_request["classification"]
            not in authorization["scopes"]["classifications"]
        ):
            raise HumanReviewError("review_decision_scope_mismatch")
        existing = self._existing(
            DECISION_KIND,
            "decision_id",
            value["decision_id"],
        )
        if existing is not None:
            payload, event = existing
            if payload != value:
                raise HumanReviewError("review_artifact_equivocation")
            return {
                "schema": "dm.review.decision-result/v1",
                "decision": value,
                "event": event,
                "state": self.state(review_request["review_request_id"]),
            }
        outstanding_request_ids = {
            event["payload"].get("review_request_id")
            for event in self._events(DECISION_KIND)
            if event["payload"].get("authorization_id")
            == authorization["authorization_id"]
        }
        closed_request_ids = {
            event["payload"].get("review_request_id")
            for event in self._events(RECEIPT_KIND)
        }
        closed_request_ids.update(
            event["payload"].get("predecessor_review_request_id")
            for event in self._events(REQUEST_KIND)
            if event["payload"].get("predecessor_review_request_id") is not None
        )
        outstanding_request_ids.difference_update(closed_request_ids)
        outstanding_request_ids.discard(review_request["review_request_id"])
        outstanding_request_ids = {
            identifier
            for identifier in outstanding_request_ids
            if isinstance(identifier, str)
            and self.review_request(identifier)[0]["expires_at_ms"] >= now
        }
        if len(outstanding_request_ids) >= authorization["max_outstanding_decisions"]:
            raise HumanReviewError("review_decision_limit_exhausted")
        prior = [
            event["payload"]
            for event in self._events(DECISION_KIND)
            if event["payload"].get("review_request_id")
            == review_request["review_request_id"]
            and event["payload"].get("reviewer_key_id") == value["reviewer_key_id"]
        ]
        heads = [
            item
            for item in prior
            if not any(
                other.get("predecessor_decision_id") == item.get("decision_id")
                for other in prior
            )
        ]
        expected_predecessor = None if not heads else heads[0]["decision_id"]
        if len(heads) > 1 or value["predecessor_decision_id"] != expected_predecessor:
            raise HumanReviewError("review_decision_conflict")
        if heads and heads[0]["action"] in TERMINAL_ACTIONS:
            raise HumanReviewError("review_decision_terminal")
        causal = [request_event["event_id"], authorization_event["event_id"]]
        if expected_predecessor is not None:
            causal.extend(
                event["event_id"]
                for event in self._events(DECISION_KIND)
                if event["payload"].get("decision_id") == expected_predecessor
            )
        event = self._append(
            kind=DECISION_KIND,
            subject=review_request["subject_me_id"],
            payload=value,
            identifier=value["decision_id"],
            client_id=client_id,
            request_id=request_id,
            causal_parents=causal,
        )
        return {
            "schema": "dm.review.decision-result/v1",
            "decision": value,
            "event": event,
            "state": self.state(review_request["review_request_id"]),
        }

    def state(self, review_request_id: str) -> dict[str, Any]:
        request, request_event = self.review_request(review_request_id)
        decisions: list[dict[str, Any]] = []
        invalid_decision_event_ids: list[str] = []
        for event in self._events(DECISION_KIND):
            payload = event["payload"]
            if payload.get("review_request_id") != review_request_id:
                continue
            try:
                authorization, _authorization_event = self.authorization(
                    payload["authorization_id"]
                )
                validate_human_decision(payload, authorization, request)
                if (
                    payload["authorization_id"] not in request["authorization_ids"]
                    or event["subject"] != request["subject_me_id"]
                    or event["being_ref"] != request["subject_me_id"]
                    or not authorization["valid_from_ms"]
                    <= payload["decided_at_ms"]
                    <= authorization["expires_at_ms"]
                    or self.revoked(
                        authorization["authorization_id"],
                        payload["decided_at_ms"],
                    )
                ):
                    raise HumanReviewError("review_decision_not_current")
            except (HumanReviewError, KeyError, TypeError):
                invalid_decision_event_ids.append(event["event_id"])
            else:
                decisions.append(payload)
        by_reviewer: dict[str, list[dict[str, Any]]] = {}
        for decision in decisions:
            by_reviewer.setdefault(decision["reviewer_key_id"], []).append(decision)
        heads: list[dict[str, Any]] = []
        conflict = bool(invalid_decision_event_ids)
        for rows in by_reviewer.values():
            candidates = [
                row
                for row in rows
                if not any(
                    other.get("predecessor_decision_id") == row["decision_id"]
                    for other in rows
                )
            ]
            if len(candidates) != 1:
                conflict = True
            else:
                heads.append(candidates[0])
        votes: dict[tuple[str, str | None], list[str]] = {}
        for decision in heads:
            replacement_hash = (
                None
                if decision["replacement"] is None
                else hashlib.sha256(
                    _canonical(decision["replacement"], "invalid_review_decision")
                ).hexdigest()
            )
            votes.setdefault((decision["action"], replacement_hash), []).append(
                decision["decision_id"]
            )
        winners = [
            (key, sorted(ids))
            for key, ids in votes.items()
            if key[0] in TERMINAL_ACTIONS and len(ids) >= request["threshold"]
        ]
        if len(winners) > 1:
            conflict = True
        status: str
        action: str | None
        decision_ids: list[str]
        if conflict:
            status, action, decision_ids = "conflict", None, []
        elif winners:
            (action, _replacement_hash), decision_ids = sorted(winners)[0]
            status = "decided"
        elif self.clock() > request["expires_at_ms"]:
            status, action, decision_ids = "expired", None, []
        else:
            status, action, decision_ids = "pending", None, []
        receipt_events = [
            event
            for event in self._events(RECEIPT_KIND)
            if event["payload"].get("review_request_id") == review_request_id
        ]
        if receipt_events:
            status = "executed"
        elif any(
            event["payload"].get("predecessor_review_request_id") == review_request_id
            for event in self._events(REQUEST_KIND)
        ):
            status, action, decision_ids = "superseded", None, []
        return {
            "schema": "dm.review.state/v1",
            "review_request_id": review_request_id,
            "request_event_id": request_event["event_id"],
            "status": status,
            "action": action,
            "decision_ids": decision_ids,
            "decision_count": len(decisions),
            "invalid_decision_event_ids": sorted(invalid_decision_event_ids),
            "receipt": None
            if not receipt_events
            else copy.deepcopy(receipt_events[0]["payload"]),
        }

    def queue(
        self,
        *,
        authorization_id: str,
        access_proof: Mapping[str, Any],
        rpc_request_id: str,
        after: str | None,
        limit: int,
    ) -> dict[str, Any]:
        """Project an authorization-scoped, payload-minimized queue."""

        authorization, _event = self.authorization(authorization_id)
        now = _uint(self.clock(), "invalid_review_time")
        if self.revoked(authorization_id, now):
            raise HumanReviewError("review_authorization_not_current")
        validate_access_proof(
            access_proof,
            authorization,
            rpc_request_id=rpc_request_id,
            now_ms=now,
        )
        if after is not None:
            _derived_id(after, "dm:review-request:v1:", "invalid_review_cursor")
        size = _uint(limit, "invalid_review_limit", 1)
        if size > 100:
            raise HumanReviewError("invalid_review_limit")
        rows: list[dict[str, Any]] = []
        for event in self._events(REQUEST_KIND):
            request = validate_review_request(event["payload"])
            if authorization_id not in request["authorization_ids"]:
                continue
            if after is not None and request["review_request_id"] <= after:
                continue
            state = self.state(request["review_request_id"])
            rows.append(
                {
                    "review_request_id": request["review_request_id"],
                    "requested_at_ms": request["requested_at_ms"],
                    "expires_at_ms": request["expires_at_ms"],
                    "category": request["candidate"]["category"],
                    "classification": request["classification"],
                    "action": state["action"],
                    "status": state["status"],
                    "plan_id": request["plan"]["plan_id"],
                    "plan_hash": request["plan_hash"],
                    "projected_effect_hash": request["projected_effect_hash"],
                    "reasons": copy.deepcopy(request["reasons"]),
                }
            )
        rows.sort(key=lambda row: row["review_request_id"])
        page = rows[:size]
        return {
            "schema": QUEUE_SCHEMA,
            "authorization_id": authorization_id,
            "cutoff_ms": now,
            "after": after,
            "items": page,
            "next": None if len(rows) <= size else page[-1]["review_request_id"],
        }

    def inspect(
        self,
        *,
        review_request_id: str,
        authorization_id: str,
        access_proof: Mapping[str, Any],
        rpc_request_id: str,
    ) -> dict[str, Any]:
        """Disclose exact immutable evidence only after reviewer possession."""

        authorization, _event = self.authorization(authorization_id)
        now = _uint(self.clock(), "invalid_review_time")
        if self.revoked(authorization_id, now):
            raise HumanReviewError("review_authorization_not_current")
        validate_access_proof(
            access_proof,
            authorization,
            rpc_request_id=rpc_request_id,
            now_ms=now,
        )
        try:
            request, event = self.review_request(review_request_id)
        except HumanReviewError as exception:
            if exception.code != "review_request_unknown":
                raise
            raise HumanReviewError("review_disclosure_unavailable") from exception
        if authorization_id not in request["authorization_ids"]:
            raise HumanReviewError("review_disclosure_unavailable")
        return {
            "schema": "dm.review.inspection/v1",
            "request": request,
            "request_event": event,
            "state": self.state(review_request_id),
        }

    def draft(
        self,
        *,
        review_request_id: str,
        authorization_id: str,
        action: str,
        replacement: Mapping[str, Any] | None,
        reason: str,
        note_ref: str | None,
        decision_nonce: str,
        decided_at_ms: int,
        predecessor_decision_id: str | None,
    ) -> dict[str, Any]:
        """Prepare, but never sign, a decision bound to current authority."""

        request, _request_event = self.review_request(review_request_id)
        authorization, _authorization_event = self.authorization(authorization_id)
        now = _uint(self.clock(), "invalid_review_time")
        self._active_authorizations(request, now)
        if (
            authorization_id not in request["authorization_ids"]
            or action not in authorization["scopes"]["actions"]
            or not request["requested_at_ms"] <= decided_at_ms <= now
            or now > request["expires_at_ms"]
        ):
            raise HumanReviewError("review_decision_scope_mismatch")
        return create_decision_draft(
            request=request,
            authorization_id=authorization_id,
            reviewer_key_id=authorization["reviewer"]["key_id"],
            action=action,
            replacement=replacement,
            reason=reason,
            note_ref=note_ref,
            decision_nonce=decision_nonce,
            decided_at_ms=decided_at_ms,
            predecessor_decision_id=predecessor_decision_id,
        )

    def _create_revalidation_successor(
        self,
        request: Mapping[str, Any],
        request_event: Mapping[str, Any],
        decision_ids: Sequence[str],
        *,
        now: int,
        client_id: str,
        request_id: str,
    ) -> dict[str, Any] | None:
        checkpoint = memory_checkpoint(
            self.ledger, request["candidate"], captured_at_ms=now
        )
        plan = evaluate_memory_candidate(
            request["policy"],
            request["candidate"],
            checkpoint,
            evaluated_at_ms=now,
        )
        if plan["outcome"] != "review-required" or plan == request["plan"]:
            return None
        authorizations = self._active_authorizations(request, now)
        expires_at = min(
            plan["expires_at_ms"],
            *(authorization["expires_at_ms"] for authorization, _ in authorizations),
        )
        if expires_at <= now:
            return None
        successor = create_review_request(
            policy=request["policy"],
            candidate=request["candidate"],
            plan=plan,
            proposal=request["proposal"],
            authorization_ids=request["authorization_ids"],
            group_id=request["group_id"],
            threshold=request["threshold"],
            requested_at_ms=now,
            expires_at_ms=expires_at,
            predecessor_review_request_id=request["review_request_id"],
        )
        existing = self._existing(
            REQUEST_KIND,
            "review_request_id",
            successor["review_request_id"],
        )
        if existing is not None:
            payload, _event = existing
            if payload != successor:
                raise HumanReviewError("review_artifact_equivocation")
            return successor
        decision_events = [
            event
            for event in self._events(DECISION_KIND)
            if event["payload"].get("decision_id") in decision_ids
        ]
        self._append(
            kind=REQUEST_KIND,
            subject=successor["subject_me_id"],
            payload=successor,
            identifier=successor["review_request_id"],
            client_id=client_id + ":review-revalidation",
            request_id=request_id,
            causal_parents=[
                request_event["event_id"],
                *(event["event_id"] for event in decision_events),
                *(event["event_id"] for _authorization, event in authorizations),
            ],
        )
        return successor

    def execute(
        self, review_request_id: str, *, client_id: str, request_id: str
    ) -> dict[str, Any]:
        request, request_event = self.review_request(review_request_id)
        state = self.state(review_request_id)
        if state["status"] == "executed":
            return {
                "schema": "dm.review.execution-result/v1",
                "receipt": state["receipt"],
            }
        if state["status"] != "decided":
            raise HumanReviewError("review_not_executable")
        now = _uint(self.clock(), "invalid_review_time")
        self._active_authorizations(request, now)
        regenerated = evaluate_memory_candidate(
            request["policy"],
            request["candidate"],
            request["plan"]["checkpoint"],
            evaluated_at_ms=request["plan"]["evaluated_at_ms"],
        )
        if regenerated != request["plan"]:
            raise HumanReviewError("review_revalidation_mismatch")
        action = state["action"]
        memory_event = None
        successor_event = None
        successor_request_id = None
        if action == "accept":
            try:
                execution = MemoryPolicyExecutor(
                    self.ledger, self.signer, self.clock
                ).execute_reviewed(
                    request["plan"],
                    request["policy"],
                    request["candidate"],
                    review_request_id=review_request_id,
                    decision_ids=state["decision_ids"],
                    client_id=client_id + ":reviewed-memory",
                    request_id=request_id,
                )
            except MemoryExecutionError as exception:
                if (
                    str(exception) == "memory_plan_stale"
                    and self._create_revalidation_successor(
                        request,
                        request_event,
                        state["decision_ids"],
                        now=now,
                        client_id=client_id,
                        request_id=request_id,
                    )
                    is not None
                ):
                    raise HumanReviewError("review_revalidation_changed") from exception
                raise HumanReviewError(str(exception)) from exception
            memory_event = execution["event"]
        elif action == "edit":
            decision_events = [
                event
                for event in self._events(DECISION_KIND)
                if event["payload"].get("decision_id") in state["decision_ids"]
            ]
            decisions = [event["payload"] for event in decision_events]
            replacements = {
                hashlib.sha256(
                    _canonical(item["replacement"], "invalid_review_decision")
                ).hexdigest(): item["replacement"]
                for item in decisions
            }
            if len(replacements) != 1:
                raise HumanReviewError("review_edit_conflict")
            replacement = next(iter(replacements.values()))
            successor_requested_at = max(
                decision["decided_at_ms"] for decision in decisions
            )
            authorizations = self._active_authorizations(request, now)
            successor = create_review_request(
                policy=replacement["policy"],
                candidate=replacement["candidate"],
                plan=replacement["plan"],
                proposal=replacement["proposal"],
                authorization_ids=request["authorization_ids"],
                group_id=request["group_id"],
                threshold=request["threshold"],
                requested_at_ms=successor_requested_at,
                expires_at_ms=min(
                    replacement["plan"]["expires_at_ms"],
                    *(
                        authorization["expires_at_ms"]
                        for authorization, _event in authorizations
                    ),
                ),
                predecessor_review_request_id=review_request_id,
            )
            self._active_authorizations(successor, now)
            successor_event = self._append(
                kind=REQUEST_KIND,
                subject=successor["subject_me_id"],
                payload=successor,
                identifier=successor["review_request_id"],
                client_id=client_id + ":review-edit",
                request_id=request_id,
                causal_parents=[
                    *(event["event_id"] for event in decision_events),
                    *(event["event_id"] for _authorization, event in authorizations),
                ],
            )
            successor_request_id = successor["review_request_id"]
        receipt = create_execution_receipt(
            review_request_id=review_request_id,
            request_event_id=request_event["event_id"],
            action=action,
            decision_ids=state["decision_ids"],
            memory_event_id=None if memory_event is None else memory_event["event_id"],
            successor_request_id=successor_request_id,
            executed_at_ms=now,
        )
        causal = [request_event["event_id"]]
        causal.extend(
            event["event_id"]
            for event in self._events(DECISION_KIND)
            if event["payload"].get("decision_id") in state["decision_ids"]
        )
        if memory_event is not None:
            causal.append(memory_event["event_id"])
        if successor_event is not None:
            causal.append(successor_event["event_id"])
        event = self._append(
            kind=RECEIPT_KIND,
            subject=request["subject_me_id"],
            payload=receipt,
            identifier=receipt["receipt_id"],
            client_id=client_id,
            request_id=request_id,
            causal_parents=causal,
        )
        return {
            "schema": "dm.review.execution-result/v1",
            "receipt": receipt,
            "event": event,
            "memory_event": memory_event,
            "successor_request": None
            if successor_request_id is None
            else self.review_request(successor_request_id)[0],
            "successor_event": successor_event,
        }


__all__ = [
    name
    for name in globals()
    if name.startswith(
        (
            "AUTHORIZATION_",
            "REVOCATION_",
            "REQUEST_",
            "DECISION_",
            "RECEIPT_",
            "ACCESS_PROOF_",
            "QUEUE_",
        )
    )
] + [
    "ACTIONS",
    "HumanReviewCoordinator",
    "HumanReviewError",
    "accept_authorization",
    "authorization_core",
    "create_access_proof",
    "create_decision_draft",
    "create_execution_receipt",
    "create_review_request",
    "create_revocation",
    "review_group_id",
    "sign_review_decision",
    "validate_access_proof",
    "validate_authorization_core",
    "validate_decision_core",
    "validate_execution_receipt",
    "validate_human_decision",
    "validate_review_request",
    "validate_reviewer_authorization",
    "validate_revocation",
    "validate_signed_decision_shape",
]
