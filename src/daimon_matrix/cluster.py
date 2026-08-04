"""Closed Cluster evidence and effect-truth boundary for DM-037.

The helpers in this module canonicalize and validate evidence.  They do not
grant resource authority: live fence/high-water truth is accepted only through
an injected Cluster verifier.
"""

from __future__ import annotations

import copy
import hashlib
import re
import uuid
from collections.abc import Mapping
from typing import Any, Final, Protocol, cast

from .canonical import CanonicalError, canonical_bytes

BODY_SNAPSHOT_SCHEMA: Final = "dm.cluster-body-snapshot/v1"
FENCE_EVIDENCE_SCHEMA: Final = "dm.cluster-resource-fence-evidence/v1"
FENCE_VERIFICATION_SCHEMA: Final = "dm.cluster-resource-fence-verification/v1"
FENCE_POSITION_SCHEMA: Final = "dm.cluster-resource-fence-position/v1"
EFFECT_RECEIPT_SCHEMA: Final = "dm.cluster-effect-receipt/v1"
EFFECT_RECONCILIATION_SCHEMA: Final = "dm.cluster-effect-reconciliation/v1"
FENCE_EVIDENCE_DOMAIN: Final = b"daimon/cluster-resource-fence-evidence/v1\x00"
EFFECT_RECEIPT_DOMAIN: Final = b"daimon/cluster-effect-receipt/v1\x00"
MAX_DOCUMENT_BYTES: Final = 256 * 1024
MAX_POSTCONDITION_BYTES: Final = 64 * 1024
MAX_POSTCONDITION_DEPTH: Final = 12
MAX_POSTCONDITION_NODES: Final = 2048
MAX_RESOURCE_FENCES: Final = 256
MAX_UINT: Final = 2**53 - 1

_HEX_HASH: Final = re.compile(r"^[0-9a-f]{64}$")
_FORBIDDEN_KEY: Final = re.compile(
    r"(?:^|_)(?:address|api_key|bearer|credential|endpoint|password|passwd|"
    r"path|private|secret|socket|token|url)(?:$|_)",
    re.IGNORECASE,
)
_FORBIDDEN_VALUE: Final = re.compile(
    r"(?:-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|^(?:/|~[/\\]|file:|https?://))",
    re.IGNORECASE,
)


class ClusterEvidenceError(ValueError):
    """Stable fail-closed Cluster evidence error."""

    def __init__(self, code: str, *, retryable: bool = False) -> None:
        super().__init__(code)
        self.code = code
        self.retryable = retryable


class FenceVerificationUnavailable(ClusterEvidenceError):
    """The authoritative Cluster verifier could not observe current truth."""

    def __init__(self) -> None:
        super().__init__("fence_verifier_unavailable", retryable=True)


class FenceVerifier(Protocol):
    def __call__(
        self, evidence: Mapping[str, Any], at_ms: int
    ) -> Mapping[str, Any]: ...


def _closed(value: Any, fields: set[str], code: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ClusterEvidenceError(code)
    return value


def _text(value: Any, code: str, *, maximum: int = 240) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value.encode("utf-8")) <= maximum
        or any(ord(character) < 0x20 for character in value)
    ):
        raise ClusterEvidenceError(code)
    try:
        canonical_bytes(value)
    except CanonicalError as exception:
        raise ClusterEvidenceError(code) from exception
    return value


def _uint(value: Any, code: str) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not 0 <= value <= MAX_UINT
    ):
        raise ClusterEvidenceError(code)
    return value


def _hash(value: Any, code: str) -> str:
    if not isinstance(value, str) or _HEX_HASH.fullmatch(value) is None:
        raise ClusterEvidenceError(code)
    return value


def _uuid(value: Any, code: str) -> str:
    if not isinstance(value, str):
        raise ClusterEvidenceError(code)
    try:
        parsed = uuid.UUID(value)
    except ValueError as exception:
        raise ClusterEvidenceError(code) from exception
    if str(parsed) != value:
        raise ClusterEvidenceError(code)
    return value


def _canonical(value: Any, code: str) -> bytes:
    try:
        return canonical_bytes(value)
    except CanonicalError as exception:
        raise ClusterEvidenceError(code) from exception


def _content_hash(domain: bytes, value: Mapping[str, Any]) -> str:
    return hashlib.sha256(
        domain + _canonical(value, "invalid_canonical_value")
    ).hexdigest()


def _validate_postcondition(
    value: Any, *, depth: int = 0, counter: list[int] | None = None
) -> None:
    if counter is None:
        counter = [0]
    counter[0] += 1
    if counter[0] > MAX_POSTCONDITION_NODES or depth > MAX_POSTCONDITION_DEPTH:
        raise ClusterEvidenceError("postcondition_too_complex")
    if value is None or isinstance(value, (bool, int)):
        _canonical(value, "invalid_postcondition")
        return
    if isinstance(value, str):
        if len(value.encode("utf-8")) > 4096 or _FORBIDDEN_VALUE.search(value):
            raise ClusterEvidenceError("postcondition_disclosure_forbidden")
        _canonical(value, "invalid_postcondition")
        return
    if isinstance(value, list):
        for item in value:
            _validate_postcondition(item, depth=depth + 1, counter=counter)
        return
    if isinstance(value, Mapping):
        if len(value) > 64:
            raise ClusterEvidenceError("postcondition_too_complex")
        for key, item in value.items():
            if not isinstance(key, str) or _FORBIDDEN_KEY.search(key):
                raise ClusterEvidenceError("postcondition_disclosure_forbidden")
            _text(key, "invalid_postcondition", maximum=128)
            _validate_postcondition(item, depth=depth + 1, counter=counter)
        _canonical(value, "invalid_postcondition")
        return
    raise ClusterEvidenceError("invalid_postcondition")


def validate_observed_postcondition(value: Any) -> dict[str, Any]:
    """Validate a bounded, canonical and disclosure-safe observed state."""

    if not isinstance(value, Mapping):
        raise ClusterEvidenceError("invalid_postcondition")
    _validate_postcondition(value)
    if len(_canonical(value, "invalid_postcondition")) > MAX_POSTCONDITION_BYTES:
        raise ClusterEvidenceError("postcondition_too_large")
    return copy.deepcopy(dict(value))


def validate_body_snapshot(
    value: Any,
    *,
    body_ref: str,
    embodiment_id: str,
    incarnation_id: str,
    evaluated_at_ms: int,
) -> dict[str, Any]:
    """Validate the exact read-only Cluster snapshot for one local origin."""

    expected_body = _text(body_ref, "body_snapshot_rejected")
    expected_embodiment = _text(embodiment_id, "body_snapshot_rejected")
    expected_incarnation = _text(incarnation_id, "body_snapshot_rejected")
    evaluated = _uint(evaluated_at_ms, "body_snapshot_rejected")
    row = _closed(
        value,
        {
            "body_ref",
            "embodiment_id",
            "incarnation_id",
            "observed_at_ms",
            "resource_fences",
            "schema",
            "state",
        },
        "body_snapshot_rejected",
    )
    if (
        row["schema"] != BODY_SNAPSHOT_SCHEMA
        or row["body_ref"] != expected_body
        or row["embodiment_id"] != expected_embodiment
        or row["incarnation_id"] != expected_incarnation
        or row["state"] not in {"running", "stopped", "unavailable"}
    ):
        raise ClusterEvidenceError("body_snapshot_rejected")
    observed = _uint(row["observed_at_ms"], "body_snapshot_rejected")
    if observed > evaluated:
        raise ClusterEvidenceError("body_snapshot_rejected")
    fences = row["resource_fences"]
    if not isinstance(fences, list) or len(fences) > MAX_RESOURCE_FENCES:
        raise ClusterEvidenceError("body_snapshot_rejected")
    normalized: list[dict[str, Any]] = []
    for fence in fences:
        item = _closed(fence, {"epoch", "resource_ref"}, "body_snapshot_rejected")
        normalized.append(
            {
                "resource_ref": _text(item["resource_ref"], "body_snapshot_rejected"),
                "epoch": _uint(item["epoch"], "body_snapshot_rejected"),
            }
        )
    if normalized != sorted(normalized, key=lambda item: item["resource_ref"]):
        raise ClusterEvidenceError("body_snapshot_rejected")
    if len({item["resource_ref"] for item in normalized}) != len(normalized):
        raise ClusterEvidenceError("body_snapshot_rejected")
    if len(_canonical(row, "body_snapshot_rejected")) > MAX_DOCUMENT_BYTES:
        raise ClusterEvidenceError("body_snapshot_rejected")
    return copy.deepcopy(dict(row))


def create_resource_fence_evidence(
    *,
    body_ref: str,
    holder_embodiment_id: str,
    holder_incarnation_id: str,
    resource_ref: str,
    epoch: int,
    observed_at_ms: int,
    expires_at_ms: int,
    verification_ref: str,
) -> dict[str, Any]:
    """Canonicalize evidence; this constructor does not verify or grant a fence."""

    core = {
        "schema": FENCE_EVIDENCE_SCHEMA,
        "body_ref": body_ref,
        "holder_embodiment_id": holder_embodiment_id,
        "holder_incarnation_id": holder_incarnation_id,
        "resource_ref": resource_ref,
        "epoch": epoch,
        "observed_at_ms": observed_at_ms,
        "expires_at_ms": expires_at_ms,
        "verification_ref": verification_ref,
    }
    return validate_resource_fence_evidence(
        {**core, "content_hash": _content_hash(FENCE_EVIDENCE_DOMAIN, core)}
    )


def validate_resource_fence_evidence(value: Any) -> dict[str, Any]:
    """Validate frozen fence evidence without asserting that it is current."""

    fields = {
        "schema",
        "body_ref",
        "holder_embodiment_id",
        "holder_incarnation_id",
        "resource_ref",
        "epoch",
        "observed_at_ms",
        "expires_at_ms",
        "verification_ref",
        "content_hash",
    }
    row = _closed(value, fields, "invalid_fence_evidence")
    if row["schema"] != FENCE_EVIDENCE_SCHEMA:
        raise ClusterEvidenceError("invalid_fence_evidence")
    for field in (
        "body_ref",
        "holder_embodiment_id",
        "holder_incarnation_id",
        "resource_ref",
        "verification_ref",
    ):
        _text(row[field], "invalid_fence_evidence")
    _uint(row["epoch"], "invalid_fence_evidence")
    observed = _uint(row["observed_at_ms"], "invalid_fence_evidence")
    expires = _uint(row["expires_at_ms"], "invalid_fence_evidence")
    if expires < observed:
        raise ClusterEvidenceError("invalid_fence_evidence")
    core = {
        key: copy.deepcopy(item) for key, item in row.items() if key != "content_hash"
    }
    if _hash(row["content_hash"], "invalid_fence_evidence") != _content_hash(
        FENCE_EVIDENCE_DOMAIN, core
    ):
        raise ClusterEvidenceError("fence_evidence_hash_mismatch")
    if len(_canonical(row, "invalid_fence_evidence")) > MAX_DOCUMENT_BYTES:
        raise ClusterEvidenceError("fence_evidence_too_large")
    return copy.deepcopy(dict(row))


def verify_resource_fence_evidence(
    value: Any,
    *,
    at_ms: int,
    verifier: FenceVerifier,
    body_ref: str | None = None,
    holder_embodiment_id: str | None = None,
    holder_incarnation_id: str | None = None,
    resource_ref: str | None = None,
) -> dict[str, Any]:
    """Require current Cluster verification of one exact frozen fence."""

    evidence = validate_resource_fence_evidence(value)
    at = _uint(at_ms, "invalid_fence_verification_time")
    expected = {
        "body_ref": body_ref,
        "holder_embodiment_id": holder_embodiment_id,
        "holder_incarnation_id": holder_incarnation_id,
        "resource_ref": resource_ref,
    }
    if any(
        wanted is not None and evidence[field] != wanted
        for field, wanted in expected.items()
    ):
        raise ClusterEvidenceError("fence_binding_mismatch")
    if evidence["observed_at_ms"] > at or evidence["expires_at_ms"] < at:
        raise ClusterEvidenceError("fence_not_current")
    try:
        raw_verification = verifier(copy.deepcopy(evidence), at)
    except FenceVerificationUnavailable:
        raise
    except Exception as exception:
        raise ClusterEvidenceError("fence_verification_rejected") from exception
    verification = _closed(
        raw_verification,
        {
            "schema",
            "content_hash",
            "resource_ref",
            "holder_embodiment_id",
            "epoch",
            "verified_at_ms",
            "current",
        },
        "invalid_fence_verification",
    )
    verified_at = _uint(verification["verified_at_ms"], "invalid_fence_verification")
    if (
        verification["schema"] != FENCE_VERIFICATION_SCHEMA
        or verification["content_hash"] != evidence["content_hash"]
        or verification["resource_ref"] != evidence["resource_ref"]
        or verification["holder_embodiment_id"] != evidence["holder_embodiment_id"]
        or verification["epoch"] != evidence["epoch"]
        or verified_at < evidence["observed_at_ms"]
        or verified_at > at
    ):
        raise ClusterEvidenceError("invalid_fence_verification")
    if verification["current"] is not True:
        raise ClusterEvidenceError("fence_not_current")
    return evidence


def resource_fence_position(value: Any) -> dict[str, Any]:
    """Derive the only fence summary accepted inside a Matrix event."""

    evidence = validate_resource_fence_evidence(value)
    return {
        "schema": FENCE_POSITION_SCHEMA,
        "resource_ref": evidence["resource_ref"],
        "holder_embodiment_id": evidence["holder_embodiment_id"],
        "epoch": evidence["epoch"],
        "evidence_hash": evidence["content_hash"],
    }


def validate_resource_fence_position(value: Any) -> dict[str, Any]:
    row = _closed(
        value,
        {"schema", "resource_ref", "holder_embodiment_id", "epoch", "evidence_hash"},
        "invalid_resource_fence_position",
    )
    if row["schema"] != FENCE_POSITION_SCHEMA:
        raise ClusterEvidenceError("invalid_resource_fence_position")
    _text(row["resource_ref"], "invalid_resource_fence_position")
    _text(row["holder_embodiment_id"], "invalid_resource_fence_position")
    _uint(row["epoch"], "invalid_resource_fence_position")
    _hash(row["evidence_hash"], "invalid_resource_fence_position")
    return copy.deepcopy(dict(row))


def create_effect_receipt(
    *,
    effect_id: str,
    target_event_id: str,
    decision_event_id: str,
    adapter: str,
    preview_hash: str,
    intent_hash: str,
    actor: str,
    authority: str,
    resource_fence: Mapping[str, Any] | None,
    result: str,
    observed_postcondition: Mapping[str, Any],
    started_at_ms: int,
    completed_at_ms: int,
) -> dict[str, Any]:
    core = {
        "schema": EFFECT_RECEIPT_SCHEMA,
        "effect_id": effect_id,
        "target_event_id": target_event_id,
        "decision_event_id": decision_event_id,
        "adapter": adapter,
        "preview_hash": preview_hash,
        "intent_hash": intent_hash,
        "actor": actor,
        "authority": authority,
        "resource_fence": copy.deepcopy(resource_fence),
        "result": result,
        "observed_postcondition": copy.deepcopy(dict(observed_postcondition)),
        "started_at_ms": started_at_ms,
        "completed_at_ms": completed_at_ms,
    }
    return validate_effect_receipt(
        {**core, "content_hash": _content_hash(EFFECT_RECEIPT_DOMAIN, core)}
    )


def validate_effect_receipt(value: Any) -> dict[str, Any]:
    fields = {
        "schema",
        "effect_id",
        "target_event_id",
        "decision_event_id",
        "adapter",
        "preview_hash",
        "intent_hash",
        "actor",
        "authority",
        "resource_fence",
        "result",
        "observed_postcondition",
        "started_at_ms",
        "completed_at_ms",
        "content_hash",
    }
    row = _closed(value, fields, "invalid_effect_receipt")
    if row["schema"] != EFFECT_RECEIPT_SCHEMA:
        raise ClusterEvidenceError("invalid_effect_receipt")
    _uuid(row["effect_id"], "invalid_effect_receipt")
    _uuid(row["target_event_id"], "invalid_effect_receipt")
    _uuid(row["decision_event_id"], "invalid_effect_receipt")
    _text(row["adapter"], "invalid_effect_receipt", maximum=128)
    _hash(row["preview_hash"], "invalid_effect_receipt")
    _hash(row["intent_hash"], "invalid_effect_receipt")
    _text(row["actor"], "invalid_effect_receipt", maximum=128)
    if row["authority"] not in {"daimon", "human"}:
        raise ClusterEvidenceError("invalid_effect_receipt")
    if row["result"] not in {"applied", "failed", "reconciled", "stale"}:
        raise ClusterEvidenceError("invalid_effect_receipt")
    started = _uint(row["started_at_ms"], "invalid_effect_receipt")
    completed = _uint(row["completed_at_ms"], "invalid_effect_receipt")
    if completed < started:
        raise ClusterEvidenceError("invalid_effect_receipt")
    validate_observed_postcondition(row["observed_postcondition"])
    if row["resource_fence"] is not None:
        validate_resource_fence_position(row["resource_fence"])
    core = {
        key: copy.deepcopy(item) for key, item in row.items() if key != "content_hash"
    }
    if _hash(row["content_hash"], "invalid_effect_receipt") != _content_hash(
        EFFECT_RECEIPT_DOMAIN, core
    ):
        raise ClusterEvidenceError("effect_receipt_hash_mismatch")
    if len(_canonical(row, "invalid_effect_receipt")) > MAX_DOCUMENT_BYTES:
        raise ClusterEvidenceError("effect_receipt_too_large")
    return copy.deepcopy(dict(row))


def projection_receipt_payload(value: Any) -> dict[str, Any]:
    """Convert exact adapter evidence into a signed Matrix event payload."""

    receipt = validate_effect_receipt(value)
    fields = (
        "target_event_id",
        "decision_event_id",
        "adapter",
        "preview_hash",
        "intent_hash",
        "actor",
        "authority",
        "resource_fence",
        "result",
        "observed_postcondition",
        "started_at_ms",
        "completed_at_ms",
    )
    return {field: copy.deepcopy(receipt[field]) for field in fields}


def _reconciliation(
    receipt: Mapping[str, Any], status: str, reason: str
) -> dict[str, Any]:
    return {
        "schema": EFFECT_RECONCILIATION_SCHEMA,
        "effect_id": receipt["effect_id"],
        "receipt_hash": receipt["content_hash"],
        "status": status,
        "reason": reason,
    }


def reconcile_effect_receipt(
    value: Any,
    *,
    intent: Any,
    observed_postcondition: Mapping[str, Any] | None,
    at_ms: int,
    current_fence_evidence: Mapping[str, Any] | None = None,
    fence_verifier: FenceVerifier | None = None,
) -> dict[str, Any]:
    """Re-evaluate intent, current fence and postcondition before replay."""

    receipt = validate_effect_receipt(value)
    _uint(at_ms, "invalid_reconciliation_time")
    encoded_intent = _canonical(intent, "invalid_effect_intent")
    if len(encoded_intent) > MAX_POSTCONDITION_BYTES:
        raise ClusterEvidenceError("effect_intent_too_large")
    if hashlib.sha256(encoded_intent).hexdigest() != receipt["intent_hash"]:
        return _reconciliation(receipt, "effect-truth-discrepancy", "intent-mismatch")

    expected_fence = receipt["resource_fence"]
    if expected_fence is not None:
        if current_fence_evidence is None or fence_verifier is None:
            return _reconciliation(
                receipt, "effect-truth-unverifiable", "fence-observation-unavailable"
            )
        try:
            current = verify_resource_fence_evidence(
                current_fence_evidence,
                at_ms=at_ms,
                verifier=fence_verifier,
                holder_embodiment_id=cast(str, expected_fence["holder_embodiment_id"]),
                resource_ref=cast(str, expected_fence["resource_ref"]),
            )
        except FenceVerificationUnavailable:
            return _reconciliation(
                receipt, "effect-truth-unverifiable", "fence-verifier-unavailable"
            )
        except ClusterEvidenceError as exception:
            status = (
                "effect-truth-discrepancy"
                if exception.code in {"fence_binding_mismatch", "fence_not_current"}
                else "effect-truth-unverifiable"
            )
            return _reconciliation(receipt, status, exception.code)
        current_position = resource_fence_position(current)
        if current_position != expected_fence:
            reason = (
                "fence-epoch-mismatch"
                if current_position["epoch"] != expected_fence["epoch"]
                else "fence-evidence-mismatch"
            )
            return _reconciliation(receipt, "effect-truth-discrepancy", reason)
    elif current_fence_evidence is not None:
        return _reconciliation(receipt, "effect-truth-discrepancy", "unexpected-fence")

    if observed_postcondition is None:
        return _reconciliation(
            receipt, "effect-truth-unverifiable", "postcondition-unavailable"
        )
    try:
        observed = validate_observed_postcondition(observed_postcondition)
    except ClusterEvidenceError:
        return _reconciliation(
            receipt, "effect-truth-unverifiable", "postcondition-invalid"
        )
    if _canonical(observed, "invalid_postcondition") != _canonical(
        receipt["observed_postcondition"], "invalid_postcondition"
    ):
        return _reconciliation(
            receipt, "effect-truth-discrepancy", "postcondition-mismatch"
        )
    return _reconciliation(receipt, "verified", "effect-truth-matches")
