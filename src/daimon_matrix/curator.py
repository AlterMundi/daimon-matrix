"""Resource-scoped curator coordination for DM-031.

The coordinator owns a durable local work queue and compare-and-swap claims.
It never grants being identity, presence, or a Cluster resource fence.  Work
against an external/shared resource is accepted only with current evidence
from an injected Cluster verifier, and cached effects are replayed only after
observed effect truth is verified again.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
import sqlite3
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final, Protocol, cast

from .canonical import CanonicalError, b64url, canonical_bytes
from .cluster import (
    FenceVerifier,
    reconcile_effect_receipt,
    resource_fence_position,
    validate_effect_receipt,
    validate_observed_postcondition,
    validate_resource_fence_evidence,
    validate_resource_fence_position,
    verify_resource_fence_evidence,
)
from .ledger import Ledger, LedgerStateError

ITEM_SCHEMA: Final = "dm.curator.item/v1"
CLAIM_SCHEMA: Final = "dm.curator.claim/v1"
RESULT_SCHEMA: Final = "dm.curator.result/v1"
ENQUEUE_SCHEMA: Final = "dm.curator.enqueue-result/v1"
INSPECTION_SCHEMA: Final = "dm.curator.inspection/v1"

ITEM_DOMAIN: Final = b"daimon/curator/item/v1\x00"
CLAIM_DOMAIN: Final = b"daimon/curator/claim/v1\x00"
RESULT_DOMAIN: Final = b"daimon/curator/result/v1\x00"

WORK_KINDS: Final = frozenset(
    {
        "memory-evaluation",
        "memory-proposal",
        "memory-projection",
        "publication",
    }
)
COORDINATION_MODES: Final = frozenset({"queue-item", "resource-fence"})
AUTHORITIES: Final = frozenset({"daimon", "human"})
OUTCOMES: Final = frozenset({"completed", "proposed", "deferred", "failed"})
TERMINAL_STATES: Final = frozenset(
    {"completed", "review-required", "deferred", "failed"}
)
MAX_UINT: Final = 2**53 - 1
MAX_LEASE_MS: Final = 86_400_000
MAX_REFS: Final = 256
_SCOPED: Final = re.compile(r"^[A-Za-z0-9._:@-]{1,256}$")


class CuratorError(RuntimeError):
    """Stable fail-closed curator coordination error."""

    def __init__(self, code: str, *, retryable: bool = False) -> None:
        super().__init__(code)
        self.code = code
        self.retryable = retryable


class EffectTruthObserver(Protocol):
    """Observe current intent, postcondition, and optional fence evidence."""

    def __call__(
        self,
        item: Mapping[str, Any],
        receipt: Mapping[str, Any],
        at_ms: int,
    ) -> Mapping[str, Any]: ...


Clock = Callable[[], int]


def _canonical(value: Any, code: str) -> bytes:
    try:
        return canonical_bytes(value)
    except CanonicalError as exception:
        raise CuratorError(code) from exception


def _closed(value: Any, fields: set[str], code: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise CuratorError(code)
    return value


def _text(value: Any, code: str, *, maximum: int = 256) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value.encode("utf-8")) <= maximum
        or any(ord(character) < 0x20 for character in value)
    ):
        raise CuratorError(code)
    _canonical(value, code)
    return value


def _scoped(value: Any, code: str) -> str:
    text = _text(value, code)
    if _SCOPED.fullmatch(text) is None:
        raise CuratorError(code)
    return text


def _hash(value: Any, code: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise CuratorError(code)
    return value


def _uint(value: Any, code: str, *, minimum: int = 0) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not minimum <= value <= MAX_UINT
    ):
        raise CuratorError(code)
    return value


def _uuid(value: Any, code: str) -> str:
    if not isinstance(value, str):
        raise CuratorError(code)
    try:
        parsed = uuid.UUID(value)
    except ValueError as exception:
        raise CuratorError(code) from exception
    if str(parsed) != value:
        raise CuratorError(code)
    return value


def _origin(value: Any, code: str) -> dict[str, str]:
    row = _closed(
        value,
        {"body_ref", "embodiment_id", "incarnation_id", "principal_id"},
        code,
    )
    return {field: _scoped(row[field], code) for field in sorted(row)}


def _refs(value: Any, code: str) -> list[str]:
    if (
        not isinstance(value, list)
        or len(value) > MAX_REFS
        or value != sorted(set(value))
    ):
        raise CuratorError(code)
    return [_scoped(item, code) for item in value]


def _derived(prefix: str, domain: bytes, value: Mapping[str, Any]) -> str:
    return prefix + b64url(
        hashlib.sha256(domain + _canonical(value, "invalid_curator_artifact")).digest()
    )


def _derived_id(value: Any, prefix: str, code: str) -> str:
    text = _text(value, code)
    if not text.startswith(prefix) or len(text.removeprefix(prefix)) != 43:
        raise CuratorError(code)
    return text


def create_curator_item(
    *,
    subject_me_id: str,
    resource_ref: str,
    work_kind: str,
    input_ref: str,
    input_hash: str,
    coordination_mode: str,
    required_authority: str,
    effect_intent_hash: str | None,
    queued_at_ms: int,
) -> dict[str, Any]:
    """Create one immutable, content-addressed queue item."""

    core = {
        "schema": ITEM_SCHEMA,
        "subject_me_id": subject_me_id,
        "resource_ref": resource_ref,
        "work_kind": work_kind,
        "input_ref": input_ref,
        "input_hash": input_hash,
        "coordination_mode": coordination_mode,
        "required_authority": required_authority,
        "effect_intent_hash": effect_intent_hash,
        "queued_at_ms": queued_at_ms,
    }
    return validate_curator_item(
        {**core, "item_id": _derived("dm:curator-item:v1:", ITEM_DOMAIN, core)}
    )


def validate_curator_item(value: Any) -> dict[str, Any]:
    item = _closed(
        value,
        {
            "schema",
            "item_id",
            "subject_me_id",
            "resource_ref",
            "work_kind",
            "input_ref",
            "input_hash",
            "coordination_mode",
            "required_authority",
            "effect_intent_hash",
            "queued_at_ms",
        },
        "invalid_curator_item",
    )
    if item["schema"] != ITEM_SCHEMA:
        raise CuratorError("unsupported_curator_item")
    _derived_id(item["item_id"], "dm:curator-item:v1:", "invalid_curator_item")
    for field in ("subject_me_id", "resource_ref", "input_ref"):
        _scoped(item[field], "invalid_curator_item")
    if item["work_kind"] not in WORK_KINDS:
        raise CuratorError("invalid_curator_item")
    if item["coordination_mode"] not in COORDINATION_MODES:
        raise CuratorError("invalid_curator_item")
    if item["required_authority"] not in AUTHORITIES:
        raise CuratorError("invalid_curator_item")
    _hash(item["input_hash"], "invalid_curator_item")
    intent_hash = item["effect_intent_hash"]
    if item["coordination_mode"] == "resource-fence":
        _hash(intent_hash, "invalid_curator_item")
    elif intent_hash is not None:
        raise CuratorError("queue_item_effect_intent_forbidden")
    _uint(item["queued_at_ms"], "invalid_curator_item")
    core = {key: copy.deepcopy(item[key]) for key in item if key != "item_id"}
    if item["item_id"] != _derived("dm:curator-item:v1:", ITEM_DOMAIN, core):
        raise CuratorError("curator_item_id_mismatch")
    return copy.deepcopy(dict(item))


def create_curator_claim(
    *,
    claim_id: str,
    item: Mapping[str, Any],
    generation: int,
    actor_origin: Mapping[str, str],
    issued_at_ms: int,
    lease_until_ms: int,
    resource_fence: Mapping[str, Any] | None,
) -> dict[str, Any]:
    normalized_item = validate_curator_item(item)
    core = {
        "schema": CLAIM_SCHEMA,
        "claim_id": claim_id,
        "item_id": normalized_item["item_id"],
        "resource_ref": normalized_item["resource_ref"],
        "generation": generation,
        "actor_origin": copy.deepcopy(dict(actor_origin)),
        "issued_at_ms": issued_at_ms,
        "lease_until_ms": lease_until_ms,
        "resource_fence": copy.deepcopy(resource_fence),
    }
    return validate_curator_claim(
        {
            **core,
            "content_hash": hashlib.sha256(
                CLAIM_DOMAIN + _canonical(core, "invalid_curator_claim")
            ).hexdigest(),
        }
    )


def validate_curator_claim(value: Any) -> dict[str, Any]:
    claim = _closed(
        value,
        {
            "schema",
            "claim_id",
            "item_id",
            "resource_ref",
            "generation",
            "actor_origin",
            "issued_at_ms",
            "lease_until_ms",
            "resource_fence",
            "content_hash",
        },
        "invalid_curator_claim",
    )
    if claim["schema"] != CLAIM_SCHEMA:
        raise CuratorError("unsupported_curator_claim")
    _uuid(claim["claim_id"], "invalid_curator_claim")
    _derived_id(claim["item_id"], "dm:curator-item:v1:", "invalid_curator_claim")
    _scoped(claim["resource_ref"], "invalid_curator_claim")
    _uint(claim["generation"], "invalid_curator_claim", minimum=1)
    _origin(claim["actor_origin"], "invalid_curator_claim")
    issued = _uint(claim["issued_at_ms"], "invalid_curator_claim")
    expires = _uint(claim["lease_until_ms"], "invalid_curator_claim")
    if not issued < expires <= issued + MAX_LEASE_MS:
        raise CuratorError("invalid_curator_claim")
    if claim["resource_fence"] is not None:
        fence = validate_resource_fence_position(claim["resource_fence"])
        origin = _origin(claim["actor_origin"], "invalid_curator_claim")
        if (
            fence["resource_ref"] != claim["resource_ref"]
            or fence["holder_embodiment_id"] != origin["embodiment_id"]
        ):
            raise CuratorError("curator_claim_fence_mismatch")
    core = {key: copy.deepcopy(claim[key]) for key in claim if key != "content_hash"}
    expected = hashlib.sha256(
        CLAIM_DOMAIN + _canonical(core, "invalid_curator_claim")
    ).hexdigest()
    if _hash(claim["content_hash"], "invalid_curator_claim") != expected:
        raise CuratorError("curator_claim_hash_mismatch")
    return copy.deepcopy(dict(claim))


def create_curator_result(
    *,
    item: Mapping[str, Any],
    claim: Mapping[str, Any],
    outcome: str,
    output_refs: Sequence[str],
    effect_receipt: Mapping[str, Any] | None,
    completed_at_ms: int,
) -> dict[str, Any]:
    normalized_item = validate_curator_item(item)
    normalized_claim = validate_curator_claim(claim)
    if (
        normalized_claim["item_id"] != normalized_item["item_id"]
        or normalized_claim["resource_ref"] != normalized_item["resource_ref"]
    ):
        raise CuratorError("curator_result_claim_mismatch")
    core = {
        "schema": RESULT_SCHEMA,
        "item_id": normalized_item["item_id"],
        "claim_id": normalized_claim["claim_id"],
        "resource_ref": normalized_item["resource_ref"],
        "generation": normalized_claim["generation"],
        "actor_origin": copy.deepcopy(normalized_claim["actor_origin"]),
        "outcome": outcome,
        "output_refs": sorted(set(output_refs)),
        "human_review_required": normalized_item["required_authority"] == "human",
        "effect_receipt": copy.deepcopy(effect_receipt),
        "completed_at_ms": completed_at_ms,
    }
    return validate_curator_result(
        {**core, "result_id": _derived("dm:curator-result:v1:", RESULT_DOMAIN, core)}
    )


def validate_curator_result(value: Any) -> dict[str, Any]:
    result = _closed(
        value,
        {
            "schema",
            "result_id",
            "item_id",
            "claim_id",
            "resource_ref",
            "generation",
            "actor_origin",
            "outcome",
            "output_refs",
            "human_review_required",
            "effect_receipt",
            "completed_at_ms",
        },
        "invalid_curator_result",
    )
    if result["schema"] != RESULT_SCHEMA:
        raise CuratorError("unsupported_curator_result")
    _derived_id(result["result_id"], "dm:curator-result:v1:", "invalid_curator_result")
    _derived_id(result["item_id"], "dm:curator-item:v1:", "invalid_curator_result")
    _uuid(result["claim_id"], "invalid_curator_result")
    _scoped(result["resource_ref"], "invalid_curator_result")
    _uint(result["generation"], "invalid_curator_result", minimum=1)
    _origin(result["actor_origin"], "invalid_curator_result")
    if result["outcome"] not in OUTCOMES or not isinstance(
        result["human_review_required"], bool
    ):
        raise CuratorError("invalid_curator_result")
    refs = _refs(result["output_refs"], "invalid_curator_result")
    if result["outcome"] in {"completed", "proposed"} and not refs:
        raise CuratorError("curator_output_required")
    if result["human_review_required"] and result["outcome"] == "completed":
        raise CuratorError("human_review_not_satisfied")
    if result["effect_receipt"] is not None:
        if result["outcome"] != "completed":
            raise CuratorError("curator_noncompletion_effect_forbidden")
        validate_effect_receipt(result["effect_receipt"])
    _uint(result["completed_at_ms"], "invalid_curator_result")
    core = {key: copy.deepcopy(result[key]) for key in result if key != "result_id"}
    if result["result_id"] != _derived("dm:curator-result:v1:", RESULT_DOMAIN, core):
        raise CuratorError("curator_result_id_mismatch")
    return copy.deepcopy(dict(result))


@dataclass(frozen=True)
class CuratorCoordinator:
    """Durable per-ledger queue with resource-local CAS and truth-aware replay."""

    ledger: Ledger
    clock: Clock
    fence_verifier: FenceVerifier | None = None
    effect_observer: EffectTruthObserver | None = None

    def initialize(self) -> None:
        self.ledger.initialize()
        with self.ledger._database() as database:
            database.executescript(
                """
                CREATE TABLE IF NOT EXISTS curator_items (
                    item_id TEXT PRIMARY KEY,
                    resource_ref TEXT NOT NULL,
                    item_json BLOB NOT NULL,
                    state TEXT NOT NULL CHECK(state IN
                        ('queued','claimed','completed','review-required','deferred','failed')),
                    generation INTEGER NOT NULL,
                    current_claim_id TEXT,
                    result_json BLOB,
                    created_at_ms INTEGER NOT NULL,
                    updated_at_ms INTEGER NOT NULL
                ) WITHOUT ROWID;
                CREATE UNIQUE INDEX IF NOT EXISTS curator_active_resource
                    ON curator_items(resource_ref)
                    WHERE state IN ('queued','claimed');
                CREATE TABLE IF NOT EXISTS curator_claims (
                    claim_id TEXT PRIMARY KEY,
                    item_id TEXT NOT NULL REFERENCES curator_items(item_id),
                    generation INTEGER NOT NULL,
                    claim_json BLOB NOT NULL
                ) WITHOUT ROWID;
                CREATE TABLE IF NOT EXISTS curator_operations (
                    client_id TEXT NOT NULL,
                    request_id TEXT NOT NULL,
                    request_hash TEXT NOT NULL,
                    response_json BLOB NOT NULL,
                    PRIMARY KEY(client_id, request_id)
                ) WITHOUT ROWID;
                """
            )

    @property
    def actor_origin(self) -> dict[str, str]:
        return copy.deepcopy(self.ledger.local_origin)

    @staticmethod
    def _request_hash(operation: str, value: Mapping[str, Any]) -> str:
        return hashlib.sha256(
            canonical_bytes(
                {"operation": operation, "value": copy.deepcopy(dict(value))}
            )
        ).hexdigest()

    @staticmethod
    def _stored_operation(
        database: sqlite3.Connection,
        *,
        client_id: str,
        request_id: str,
        request_hash: str,
    ) -> dict[str, Any] | None:
        row = database.execute(
            "SELECT request_hash, response_json FROM curator_operations "
            "WHERE client_id=? AND request_id=?",
            (client_id, request_id),
        ).fetchone()
        if row is None:
            return None
        if row["request_hash"] != request_hash:
            raise CuratorError("curator_request_conflict")
        result = json.loads(bytes(row["response_json"]))
        if not isinstance(result, dict):
            raise LedgerStateError("curator_operation_corrupt")
        return result

    @staticmethod
    def _store_operation(
        database: sqlite3.Connection,
        *,
        client_id: str,
        request_id: str,
        request_hash: str,
        response: Mapping[str, Any],
    ) -> None:
        database.execute(
            "INSERT INTO curator_operations VALUES (?, ?, ?, ?)",
            (client_id, request_id, request_hash, canonical_bytes(response)),
        )

    def enqueue(
        self,
        item: Mapping[str, Any],
        *,
        client_id: str,
        request_id: str,
    ) -> dict[str, Any]:
        normalized = validate_curator_item(item)
        if normalized["subject_me_id"] != self.ledger.authority.manifest.being_ref:
            raise CuratorError("curator_subject_mismatch")
        request = {"item": normalized}
        request_hash = self._request_hash("enqueue", request)
        self.initialize()
        with self.ledger._database() as database:
            database.execute("BEGIN IMMEDIATE")
            try:
                stored = self._stored_operation(
                    database,
                    client_id=client_id,
                    request_id=request_id,
                    request_hash=request_hash,
                )
                if stored is not None:
                    database.commit()
                    return stored
                existing = database.execute(
                    "SELECT state, generation, item_json FROM curator_items "
                    "WHERE item_id=?",
                    (normalized["item_id"],),
                ).fetchone()
                if existing is not None:
                    if bytes(existing["item_json"]) != canonical_bytes(normalized):
                        raise CuratorError("curator_item_conflict")
                    result = {
                        "schema": ENQUEUE_SCHEMA,
                        "item": normalized,
                        "state": existing["state"],
                        "generation": int(existing["generation"]),
                    }
                else:
                    busy = database.execute(
                        "SELECT item_id FROM curator_items WHERE resource_ref=? "
                        "AND state IN ('queued','claimed')",
                        (normalized["resource_ref"],),
                    ).fetchone()
                    if busy is not None:
                        raise CuratorError("curator_resource_busy", retryable=True)
                    result = {
                        "schema": ENQUEUE_SCHEMA,
                        "item": normalized,
                        "state": "queued",
                        "generation": 0,
                    }
                    database.execute(
                        "INSERT INTO curator_items VALUES "
                        "(?, ?, ?, 'queued', 0, NULL, NULL, ?, ?)",
                        (
                            normalized["item_id"],
                            normalized["resource_ref"],
                            canonical_bytes(normalized),
                            normalized["queued_at_ms"],
                            normalized["queued_at_ms"],
                        ),
                    )
                self._store_operation(
                    database,
                    client_id=client_id,
                    request_id=request_id,
                    request_hash=request_hash,
                    response=result,
                )
                database.commit()
                return copy.deepcopy(result)
            except BaseException:
                database.rollback()
                raise

    def _verified_fence(
        self,
        item: Mapping[str, Any],
        evidence: Mapping[str, Any] | None,
        *,
        at_ms: int,
    ) -> dict[str, Any] | None:
        if item["coordination_mode"] == "queue-item":
            if evidence is not None:
                raise CuratorError("queue_item_fence_forbidden")
            return None
        if evidence is None or self.fence_verifier is None:
            raise CuratorError("curator_fence_unverifiable", retryable=True)
        try:
            frozen = validate_resource_fence_evidence(evidence)
            verified = verify_resource_fence_evidence(
                frozen,
                at_ms=at_ms,
                verifier=self.fence_verifier,
                body_ref=self.actor_origin["body_ref"],
                holder_embodiment_id=self.actor_origin["embodiment_id"],
                holder_incarnation_id=self.actor_origin["incarnation_id"],
                resource_ref=cast(str, item["resource_ref"]),
            )
        except Exception as exception:
            if isinstance(exception, CuratorError):
                raise
            raise CuratorError("curator_fence_rejected") from exception
        return verified

    def claim(
        self,
        *,
        item_id: str,
        claim_id: str,
        expected_generation: int,
        lease_until_ms: int,
        fence_evidence: Mapping[str, Any] | None,
        client_id: str,
        request_id: str,
    ) -> dict[str, Any]:
        _derived_id(item_id, "dm:curator-item:v1:", "invalid_curator_claim_request")
        _uuid(claim_id, "invalid_curator_claim_request")
        _uint(expected_generation, "invalid_curator_claim_request")
        now = _uint(self.clock(), "invalid_curator_clock")
        if not now < lease_until_ms <= now + MAX_LEASE_MS:
            raise CuratorError("invalid_curator_lease")
        self.initialize()
        with self.ledger._database() as database:
            row = database.execute(
                "SELECT item_json FROM curator_items WHERE item_id=?", (item_id,)
            ).fetchone()
        if row is None:
            raise CuratorError("curator_item_unknown", retryable=True)
        item = validate_curator_item(json.loads(bytes(row["item_json"])))
        verified_fence = self._verified_fence(item, fence_evidence, at_ms=now)
        request = {
            "item_id": item_id,
            "claim_id": claim_id,
            "expected_generation": expected_generation,
            "lease_until_ms": lease_until_ms,
            "fence_evidence": copy.deepcopy(fence_evidence),
        }
        request_hash = self._request_hash("claim", request)
        with self.ledger._database() as database:
            database.execute("BEGIN IMMEDIATE")
            try:
                stored = self._stored_operation(
                    database,
                    client_id=client_id,
                    request_id=request_id,
                    request_hash=request_hash,
                )
                if stored is not None:
                    claim = validate_curator_claim(stored)
                    if now >= claim["lease_until_ms"]:
                        raise CuratorError("curator_claim_expired", retryable=True)
                    database.commit()
                    return claim
                current = database.execute(
                    "SELECT state, generation, current_claim_id "
                    "FROM curator_items WHERE item_id=?",
                    (item_id,),
                ).fetchone()
                if current is None:
                    raise CuratorError("curator_item_unknown", retryable=True)
                generation = int(current["generation"])
                if generation != expected_generation:
                    raise CuratorError("curator_generation_conflict", retryable=True)
                if current["state"] in TERMINAL_STATES:
                    raise CuratorError("curator_item_terminal")
                if current["state"] == "claimed":
                    active_row = database.execute(
                        "SELECT claim_json FROM curator_claims WHERE claim_id=?",
                        (current["current_claim_id"],),
                    ).fetchone()
                    if active_row is None:
                        raise LedgerStateError("curator_claim_state_corrupt")
                    active = validate_curator_claim(
                        json.loads(bytes(active_row["claim_json"]))
                    )
                    if now < active["lease_until_ms"]:
                        raise CuratorError("curator_resource_claimed", retryable=True)
                reused = database.execute(
                    "SELECT 1 FROM curator_claims WHERE claim_id=?", (claim_id,)
                ).fetchone()
                if reused is not None:
                    raise CuratorError("curator_claim_id_conflict")
                next_generation = generation + 1
                position = (
                    None
                    if verified_fence is None
                    else resource_fence_position(verified_fence)
                )
                claim = create_curator_claim(
                    claim_id=claim_id,
                    item=item,
                    generation=next_generation,
                    actor_origin=self.actor_origin,
                    issued_at_ms=now,
                    lease_until_ms=lease_until_ms,
                    resource_fence=position,
                )
                if (
                    verified_fence is not None
                    and lease_until_ms > verified_fence["expires_at_ms"]
                ):
                    raise CuratorError("curator_lease_exceeds_fence")
                database.execute(
                    "INSERT INTO curator_claims VALUES (?, ?, ?, ?)",
                    (claim_id, item_id, next_generation, canonical_bytes(claim)),
                )
                database.execute(
                    "UPDATE curator_items SET state='claimed', generation=?, "
                    "current_claim_id=?, updated_at_ms=? WHERE item_id=?",
                    (next_generation, claim_id, now, item_id),
                )
                self._store_operation(
                    database,
                    client_id=client_id,
                    request_id=request_id,
                    request_hash=request_hash,
                    response=claim,
                )
                database.commit()
                return claim
            except BaseException:
                database.rollback()
                raise

    def _verify_effect_truth(
        self,
        item: Mapping[str, Any],
        receipt: Mapping[str, Any],
        *,
        at_ms: int,
    ) -> dict[str, Any]:
        if self.effect_observer is None:
            raise CuratorError("effect_truth_unverifiable", retryable=True)
        try:
            observed = _closed(
                self.effect_observer(
                    copy.deepcopy(item), copy.deepcopy(receipt), at_ms
                ),
                {"intent", "observed_postcondition", "current_fence_evidence"},
                "effect_truth_unverifiable",
            )
            postcondition = validate_observed_postcondition(
                observed["observed_postcondition"]
            )
            fence = observed["current_fence_evidence"]
            if fence is not None and not isinstance(fence, Mapping):
                raise CuratorError("effect_truth_unverifiable", retryable=True)
            reconciliation = reconcile_effect_receipt(
                receipt,
                intent=observed["intent"],
                observed_postcondition=postcondition,
                at_ms=at_ms,
                current_fence_evidence=fence,
                fence_verifier=self.fence_verifier,
            )
        except CuratorError:
            raise
        except Exception as exception:
            raise CuratorError(
                "effect_truth_unverifiable", retryable=True
            ) from exception
        if reconciliation["status"] != "verified":
            raise CuratorError(
                str(reconciliation["status"]),
                retryable=reconciliation["status"] == "effect-truth-unverifiable",
            )
        return reconciliation

    def verify_result_truth(self, result: Mapping[str, Any]) -> dict[str, Any]:
        """Reconcile a stored effect before any cached success is served."""

        normalized = validate_curator_result(result)
        receipt = normalized["effect_receipt"]
        if receipt is None:
            return {
                "schema": "dm.cluster-effect-reconciliation/v1",
                "effect_id": None,
                "receipt_hash": None,
                "status": "verified",
                "reason": "no-external-effect",
            }
        self.initialize()
        with self.ledger._database() as database:
            row = database.execute(
                "SELECT item_json FROM curator_items WHERE item_id=?",
                (normalized["item_id"],),
            ).fetchone()
        if row is None:
            raise LedgerStateError("curator_item_state_corrupt")
        item = validate_curator_item(json.loads(bytes(row["item_json"])))
        return self._verify_effect_truth(item, receipt, at_ms=self.clock())

    def complete(
        self,
        *,
        claim_id: str,
        expected_generation: int,
        outcome: str,
        output_refs: Sequence[str],
        effect_receipt: Mapping[str, Any] | None,
        client_id: str,
        request_id: str,
    ) -> dict[str, Any]:
        _uuid(claim_id, "invalid_curator_completion")
        _uint(expected_generation, "invalid_curator_completion", minimum=1)
        if outcome not in OUTCOMES:
            raise CuratorError("invalid_curator_completion")
        refs = _refs(list(output_refs), "invalid_curator_completion")
        receipt = (
            None if effect_receipt is None else validate_effect_receipt(effect_receipt)
        )
        if receipt is not None and outcome != "completed":
            raise CuratorError("curator_noncompletion_effect_forbidden")
        now = _uint(self.clock(), "invalid_curator_clock")
        request = {
            "claim_id": claim_id,
            "expected_generation": expected_generation,
            "outcome": outcome,
            "output_refs": refs,
            "effect_receipt": receipt,
        }
        request_hash = self._request_hash("complete", request)
        self.initialize()
        with self.ledger._database() as database:
            row = database.execute(
                "SELECT c.claim_json, i.item_json FROM curator_claims c "
                "JOIN curator_items i ON i.item_id=c.item_id WHERE c.claim_id=?",
                (claim_id,),
            ).fetchone()
        if row is None:
            raise CuratorError("curator_claim_unknown", retryable=True)
        claim = validate_curator_claim(json.loads(bytes(row["claim_json"])))
        item = validate_curator_item(json.loads(bytes(row["item_json"])))
        if receipt is not None:
            self._verify_effect_truth(item, receipt, at_ms=now)
        with self.ledger._database() as database:
            database.execute("BEGIN IMMEDIATE")
            try:
                stored = self._stored_operation(
                    database,
                    client_id=client_id,
                    request_id=request_id,
                    request_hash=request_hash,
                )
                if stored is not None:
                    result = validate_curator_result(stored)
                    database.commit()
                    return result
                current = database.execute(
                    "SELECT state, generation, current_claim_id, result_json "
                    "FROM curator_items WHERE item_id=?",
                    (item["item_id"],),
                ).fetchone()
                if current is None:
                    raise LedgerStateError("curator_item_state_corrupt")
                if current["result_json"] is not None:
                    result = validate_curator_result(
                        json.loads(bytes(current["result_json"]))
                    )
                    equivalent = (
                        result["claim_id"] == claim_id
                        and result["generation"] == expected_generation
                        and result["outcome"] == outcome
                        and result["output_refs"] == refs
                        and result["effect_receipt"] == receipt
                    )
                    if not equivalent:
                        raise CuratorError("curator_item_terminal")
                    self._store_operation(
                        database,
                        client_id=client_id,
                        request_id=request_id,
                        request_hash=request_hash,
                        response=result,
                    )
                    database.commit()
                    return result
                if (
                    current["state"] != "claimed"
                    or int(current["generation"]) != expected_generation
                    or current["current_claim_id"] != claim_id
                ):
                    raise CuratorError("curator_generation_conflict", retryable=True)
                if now >= claim["lease_until_ms"]:
                    raise CuratorError("curator_claim_expired", retryable=True)
                if claim["actor_origin"] != self.actor_origin:
                    raise CuratorError("curator_actor_mismatch")
                if item["required_authority"] == "human" and outcome == "completed":
                    raise CuratorError("human_review_not_satisfied")
                if item["coordination_mode"] == "queue-item" and receipt is not None:
                    raise CuratorError("queue_item_effect_receipt_forbidden")
                if item["coordination_mode"] == "resource-fence":
                    if outcome == "completed" and receipt is None:
                        raise CuratorError("effect_receipt_required")
                    if receipt is not None and (
                        receipt["intent_hash"] != item["effect_intent_hash"]
                        or receipt["actor"] != self.actor_origin["principal_id"]
                        or receipt["resource_fence"] != claim["resource_fence"]
                        or (
                            outcome == "completed"
                            and receipt["result"] not in {"applied", "reconciled"}
                        )
                    ):
                        raise CuratorError("effect_receipt_binding_mismatch")
                result = create_curator_result(
                    item=item,
                    claim=claim,
                    outcome=outcome,
                    output_refs=refs,
                    effect_receipt=receipt,
                    completed_at_ms=now,
                )
                state = {
                    "completed": "completed",
                    "proposed": "review-required",
                    "deferred": "deferred",
                    "failed": "failed",
                }[outcome]
                database.execute(
                    "UPDATE curator_items SET state=?, result_json=?, updated_at_ms=? "
                    "WHERE item_id=?",
                    (state, canonical_bytes(result), now, item["item_id"]),
                )
                self._store_operation(
                    database,
                    client_id=client_id,
                    request_id=request_id,
                    request_hash=request_hash,
                    response=result,
                )
                database.commit()
                return result
            except BaseException:
                database.rollback()
                raise

    def inspect(self, item_id: str) -> dict[str, Any]:
        _derived_id(item_id, "dm:curator-item:v1:", "invalid_curator_item_id")
        self.initialize()
        with self.ledger._database() as database:
            row = database.execute(
                "SELECT item_json, state, generation, current_claim_id, result_json "
                "FROM curator_items WHERE item_id=?",
                (item_id,),
            ).fetchone()
            if row is None:
                raise CuratorError("curator_item_unknown", retryable=True)
            claim = None
            if row["current_claim_id"] is not None:
                claim_row = database.execute(
                    "SELECT claim_json FROM curator_claims WHERE claim_id=?",
                    (row["current_claim_id"],),
                ).fetchone()
                if claim_row is None:
                    raise LedgerStateError("curator_claim_state_corrupt")
                claim = validate_curator_claim(
                    json.loads(bytes(claim_row["claim_json"]))
                )
            result = (
                None
                if row["result_json"] is None
                else validate_curator_result(json.loads(bytes(row["result_json"])))
            )
            return {
                "schema": INSPECTION_SCHEMA,
                "item": validate_curator_item(json.loads(bytes(row["item_json"]))),
                "state": row["state"],
                "generation": int(row["generation"]),
                "claim": claim,
                "result": result,
            }


__all__ = [
    "CLAIM_SCHEMA",
    "ENQUEUE_SCHEMA",
    "INSPECTION_SCHEMA",
    "ITEM_SCHEMA",
    "RESULT_SCHEMA",
    "CuratorCoordinator",
    "CuratorError",
    "EffectTruthObserver",
    "create_curator_claim",
    "create_curator_item",
    "create_curator_result",
    "validate_curator_claim",
    "validate_curator_item",
    "validate_curator_result",
]
