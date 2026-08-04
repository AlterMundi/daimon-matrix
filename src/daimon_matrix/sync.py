"""Transport-neutral, replay-safe ``/we.sync`` documents and transactions."""

from __future__ import annotations

import copy
import hashlib
import uuid
from collections.abc import Mapping, Sequence
from typing import Any, Final, cast

from .canonical import CanonicalError, b64url, canonical_bytes
from .ledger import Ledger, LedgerError
from .weave import MAX_PAGE_EVENTS, EventAuthority, WeaveProtocolError

HEADS_SCHEMA: Final = "dm.we.heads/v1"
REQUEST_SCHEMA: Final = "dm.we.sync-request/v1"
DELTA_SCHEMA: Final = "dm.we.delta/v1"
RECEIPT_SCHEMA: Final = "dm.we.sync-receipt/v1"
REQUEST_DOMAIN: Final = b"daimon/weave/sync-request/v1\x00"
DELTA_DOMAIN: Final = b"daimon/weave/delta/v1\x00"
RECEIPT_DOMAIN: Final = b"daimon/weave/sync-receipt/v1\x00"
MAX_SYNC_DOCUMENT_BYTES: Final = 2 * 1024 * 1024

Origin = Mapping[str, str]
Document = dict[str, Any]


class SyncProtocolError(ValueError):
    """A typed sync document failed closed validation."""


def _closed(value: Any, fields: set[str], error: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise SyncProtocolError(error)
    return value


def _canonical(value: Any, error: str = "invalid_sync_value") -> bytes:
    try:
        return canonical_bytes(value)
    except CanonicalError as exception:
        raise SyncProtocolError(error) from exception


def _uuid(value: Any, error: str) -> str:
    if not isinstance(value, str):
        raise SyncProtocolError(error)
    try:
        parsed = uuid.UUID(value)
    except ValueError as exception:
        raise SyncProtocolError(error) from exception
    if str(parsed) != value:
        raise SyncProtocolError(error)
    return value


def _hash(value: Any, error: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise SyncProtocolError(error)
    return value


def _uint(value: Any, error: str, *, minimum: int = 0) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not minimum <= value <= 2**53 - 1
    ):
        raise SyncProtocolError(error)
    return value


def _origin(value: Any, authority: EventAuthority) -> dict[str, str]:
    origin = _closed(
        value,
        {"body_ref", "embodiment_id", "incarnation_id", "principal_id"},
        "invalid_sync_origin",
    )
    for field, maximum in (
        ("body_ref", 256),
        ("embodiment_id", 256),
        ("incarnation_id", 256),
        ("principal_id", 128),
    ):
        item = origin[field]
        if not isinstance(item, str) or not 1 <= len(item.encode("utf-8")) <= maximum:
            raise SyncProtocolError("invalid_sync_origin")
        _canonical(item, "invalid_sync_origin")
    normalized = cast(dict[str, str], copy.deepcopy(dict(origin)))
    try:
        authority.validate_origin(normalized, require_active=True)
    except WeaveProtocolError as exception:
        raise SyncProtocolError("unauthorized_sync_origin") from exception
    return normalized


def validate_heads(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > 256:
        raise SyncProtocolError("invalid_sync_heads")
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    fields = {"incarnation_id", "max_sequence", "tip_event_id", "tip_hash"}
    for item in value:
        head = _closed(item, fields, "invalid_sync_head")
        incarnation_id = head["incarnation_id"]
        if (
            not isinstance(incarnation_id, str)
            or not 1 <= len(incarnation_id.encode("utf-8")) <= 256
        ):
            raise SyncProtocolError("invalid_sync_head")
        _canonical(incarnation_id, "invalid_sync_head")
        _uint(head["max_sequence"], "invalid_sync_head", minimum=1)
        _uuid(head["tip_event_id"], "invalid_sync_head")
        _hash(head["tip_hash"], "invalid_sync_head")
        if incarnation_id in seen:
            raise SyncProtocolError("duplicate_sync_head")
        seen.add(incarnation_id)
        result.append(copy.deepcopy(dict(head)))
    if result != sorted(result, key=lambda head: head["incarnation_id"]):
        raise SyncProtocolError("sync_heads_not_sorted")
    return result


def peer_id(origin: Mapping[str, str]) -> str:
    """Return a bounded internal cursor key for a fully attributed peer origin."""

    return "dm:peer:v1:" + b64url(hashlib.sha256(_canonical(origin)).digest())


def _digest(domain: bytes, value: Mapping[str, Any]) -> str:
    return hashlib.sha256(domain + _canonical(value)).hexdigest()


def validate_heads_document(
    value: Any,
    authority: EventAuthority,
    *,
    expected_sender: Mapping[str, str] | None = None,
) -> Document:
    document = _closed(
        value,
        {"being_ref", "heads", "manifest_hash", "schema", "sender"},
        "invalid_sync_heads_document",
    )
    if document["schema"] != HEADS_SCHEMA:
        raise SyncProtocolError("unsupported_sync_heads")
    if (
        document["being_ref"] != authority.manifest.being_ref
        or document["manifest_hash"] != authority.manifest.digest
    ):
        raise SyncProtocolError("sync_authority_mismatch")
    sender = _origin(document["sender"], authority)
    if expected_sender is not None and sender != expected_sender:
        raise SyncProtocolError("sync_wrong_sender")
    heads = validate_heads(document["heads"])
    normalized = {
        **copy.deepcopy(dict(document)),
        "sender": sender,
        "heads": heads,
    }
    if len(_canonical(normalized)) > MAX_SYNC_DOCUMENT_BYTES:
        raise SyncProtocolError("sync_heads_too_large")
    return normalized


def _validate_delta_content(
    *,
    events_value: Any,
    offered_value: Any,
    requested_heads: Sequence[Mapping[str, Any]],
    limit: int,
    more_value: Any,
    ledger: Ledger,
) -> list[dict[str, Any]]:
    offered = validate_heads(offered_value)
    if not isinstance(events_value, list):
        raise SyncProtocolError("invalid_sync_events")
    if len(events_value) > limit:
        raise SyncProtocolError("sync_delta_exceeds_requested_limit")
    if not isinstance(more_value, bool) or (more_value and not events_value):
        raise SyncProtocolError("invalid_sync_more")
    offered_by_incarnation = {head["incarnation_id"]: head for head in offered}
    requested_by_incarnation = {
        head["incarnation_id"]: head for head in requested_heads
    }
    for event in events_value:
        if not isinstance(event, Mapping):
            raise SyncProtocolError("invalid_sync_events")
        event_origin = event.get("origin")
        if not isinstance(event_origin, Mapping):
            raise SyncProtocolError("invalid_sync_events")
        incarnation_id = event_origin.get("incarnation_id")
        sequence = event.get("sequence")
        if not isinstance(incarnation_id, str) or not isinstance(sequence, int):
            raise SyncProtocolError("invalid_sync_events")
        head = offered_by_incarnation.get(incarnation_id)
        if head is None or sequence > head["max_sequence"]:
            raise SyncProtocolError("event_outside_offered_heads")
        requested = requested_by_incarnation.get(incarnation_id)
        if requested is not None and sequence <= requested["max_sequence"]:
            raise SyncProtocolError("sync_delta_cursor_regression")
        if sequence == head["max_sequence"] and (
            event.get("event_id") != head["tip_event_id"]
            or event.get("content_hash") != head["tip_hash"]
        ):
            raise SyncProtocolError("event_conflicts_with_offered_head")
    if not more_value:
        event_tips = {
            (event["origin"]["incarnation_id"], event["sequence"]): event
            for event in events_value
        }
        for head in offered:
            requested = requested_by_incarnation.get(head["incarnation_id"])
            requested_sequence = 0 if requested is None else requested["max_sequence"]
            if head["max_sequence"] <= requested_sequence:
                continue
            tip = event_tips.get((head["incarnation_id"], head["max_sequence"]))
            if tip is None:
                raise SyncProtocolError("sync_delta_hidden_remainder")
    try:
        ledger.preview(cast(Sequence[Mapping[str, Any]], events_value))
    except (LedgerError, WeaveProtocolError) as exception:
        raise SyncProtocolError(str(exception)) from exception
    return offered


def validate_receipt(
    value: Any,
    authority: EventAuthority,
    *,
    expected_sender: Mapping[str, str] | None = None,
    expected_receiver: Mapping[str, str] | None = None,
) -> Document:
    receipt = _closed(
        value,
        {
            "achieved_heads",
            "being_ref",
            "completed_at_ms",
            "incomplete",
            "inserted",
            "manifest_hash",
            "more",
            "page_hash",
            "receipt_hash",
            "received",
            "receiver",
            "replayed",
            "request_hash",
            "request_id",
            "schema",
            "sender",
        },
        "invalid_sync_receipt",
    )
    if receipt["schema"] != RECEIPT_SCHEMA:
        raise SyncProtocolError("unsupported_sync_receipt")
    if (
        receipt["being_ref"] != authority.manifest.being_ref
        or receipt["manifest_hash"] != authority.manifest.digest
    ):
        raise SyncProtocolError("sync_authority_mismatch")
    _uuid(receipt["request_id"], "invalid_sync_receipt")
    for field in ("request_hash", "page_hash", "receipt_hash"):
        _hash(receipt[field], "invalid_sync_receipt")
    sender = _origin(receipt["sender"], authority)
    receiver = _origin(receipt["receiver"], authority)
    if expected_sender is not None and sender != expected_sender:
        raise SyncProtocolError("sync_wrong_sender")
    if expected_receiver is not None and receiver != expected_receiver:
        raise SyncProtocolError("sync_wrong_receiver")
    if not isinstance(receipt["more"], bool):
        raise SyncProtocolError("invalid_sync_receipt")
    received = _uint(receipt["received"], "invalid_sync_receipt")
    inserted = _uint(receipt["inserted"], "invalid_sync_receipt")
    replayed = _uint(receipt["replayed"], "invalid_sync_receipt")
    _uint(receipt["incomplete"], "invalid_sync_receipt")
    _uint(receipt["completed_at_ms"], "invalid_sync_receipt")
    if received > MAX_PAGE_EVENTS or inserted + replayed != received:
        raise SyncProtocolError("invalid_sync_receipt_counts")
    heads = validate_heads(receipt["achieved_heads"])
    core = {
        key: copy.deepcopy(item)
        for key, item in receipt.items()
        if key != "receipt_hash"
    }
    if receipt["receipt_hash"] != _digest(RECEIPT_DOMAIN, core):
        raise SyncProtocolError("sync_receipt_hash_mismatch")
    return {
        **copy.deepcopy(dict(receipt)),
        "sender": sender,
        "receiver": receiver,
        "achieved_heads": heads,
    }


class SyncEngine:
    """Typed sync operations over one independent embodiment ledger."""

    def __init__(self, ledger: Ledger) -> None:
        self.ledger = ledger
        self.authority = ledger.authority
        if self.authority.manifest.trust_mode != "root-bound":
            raise SyncProtocolError("sync_requires_root_authority")
        self.origin = _origin(ledger.local_origin, self.authority)
        self.ledger.initialize()

    @property
    def being_ref(self) -> str:
        return self.authority.manifest.being_ref

    @property
    def manifest_hash(self) -> str:
        return self.authority.manifest.digest

    def heads(self) -> Document:
        document = {
            "schema": HEADS_SCHEMA,
            "being_ref": self.being_ref,
            "manifest_hash": self.manifest_hash,
            "sender": copy.deepcopy(self.origin),
            "heads": self.ledger.heads(),
        }
        return validate_heads_document(
            document, self.authority, expected_sender=self.origin
        )

    def request(self, *, request_id: str, limit: int = MAX_PAGE_EVENTS) -> Document:
        _uuid(request_id, "invalid_sync_request_id")
        _uint(limit, "invalid_sync_limit", minimum=1)
        if limit > MAX_PAGE_EVENTS:
            raise SyncProtocolError("invalid_sync_limit")
        cached_record = self.ledger.issued_request(request_id)
        if cached_record is not None:
            cached_hash, cached = cached_record
            if cached_hash != _digest(REQUEST_DOMAIN, cached):
                raise SyncProtocolError("issued_sync_request_corrupt")
            if cached.get("limit") != limit:
                raise SyncProtocolError("sync_request_id_conflict")
            return self._request(cached)
        request = {
            "schema": REQUEST_SCHEMA,
            "request_id": request_id,
            "being_ref": self.being_ref,
            "manifest_hash": self.manifest_hash,
            "requester": copy.deepcopy(self.origin),
            "heads": self.ledger.heads(),
            "limit": limit,
        }
        request_hash = _digest(REQUEST_DOMAIN, request)
        try:
            return self.ledger.store_issued_request(
                request_id=request_id,
                request_hash=request_hash,
                request=request,
            )
        except LedgerError as exception:
            raise SyncProtocolError(str(exception)) from exception

    def _request(self, value: Any) -> Document:
        request = _closed(
            value,
            {
                "being_ref",
                "heads",
                "limit",
                "manifest_hash",
                "request_id",
                "requester",
                "schema",
            },
            "invalid_sync_request",
        )
        if request["schema"] != REQUEST_SCHEMA:
            raise SyncProtocolError("unsupported_sync_request")
        _uuid(request["request_id"], "invalid_sync_request_id")
        if (
            request["being_ref"] != self.being_ref
            or request["manifest_hash"] != self.manifest_hash
        ):
            raise SyncProtocolError("sync_authority_mismatch")
        requester = _origin(request["requester"], self.authority)
        heads = validate_heads(request["heads"])
        limit = _uint(request["limit"], "invalid_sync_limit", minimum=1)
        if limit > MAX_PAGE_EVENTS:
            raise SyncProtocolError("invalid_sync_limit")
        normalized = {
            **copy.deepcopy(dict(request)),
            "requester": requester,
            "heads": heads,
        }
        if len(_canonical(normalized)) > MAX_SYNC_DOCUMENT_BYTES:
            raise SyncProtocolError("sync_request_too_large")
        return normalized

    def serve(self, value: Any) -> Document:
        request = self._request(value)
        request_hash = _digest(REQUEST_DOMAIN, request)
        try:
            frozen = self.ledger.delta_idempotent(
                request_id=request["request_id"],
                request_hash=request_hash,
                remote_heads=request["heads"],
                limit=request["limit"],
            )
        except LedgerError as exception:
            raise SyncProtocolError(str(exception)) from exception
        frozen_value = _closed(
            frozen,
            {"events", "more", "offered_heads"},
            "outbound_sync_response_corrupt",
        )
        offered = _validate_delta_content(
            events_value=frozen_value["events"],
            offered_value=frozen_value["offered_heads"],
            requested_heads=request["heads"],
            limit=request["limit"],
            more_value=frozen_value["more"],
            ledger=self.ledger,
        )
        core = {
            "schema": DELTA_SCHEMA,
            "request_id": request["request_id"],
            "request_hash": request_hash,
            "being_ref": self.being_ref,
            "manifest_hash": self.manifest_hash,
            "sender": copy.deepcopy(self.origin),
            "requester": copy.deepcopy(request["requester"]),
            "offered_heads": offered,
            "events": frozen_value["events"],
            "more": frozen_value["more"],
        }
        page = {**core, "page_hash": _digest(DELTA_DOMAIN, core)}
        if len(_canonical(page)) > MAX_SYNC_DOCUMENT_BYTES:
            raise SyncProtocolError("sync_delta_too_large")
        return page

    def validate_delta(self, value: Any) -> Document:
        page = _closed(
            value,
            {
                "being_ref",
                "events",
                "manifest_hash",
                "more",
                "offered_heads",
                "page_hash",
                "request_hash",
                "request_id",
                "requester",
                "schema",
                "sender",
            },
            "invalid_sync_delta",
        )
        if page["schema"] != DELTA_SCHEMA:
            raise SyncProtocolError("unsupported_sync_delta")
        if len(_canonical(page)) > MAX_SYNC_DOCUMENT_BYTES:
            raise SyncProtocolError("sync_delta_too_large")
        _uuid(page["request_id"], "invalid_sync_request_id")
        _hash(page["request_hash"], "invalid_sync_request_hash")
        if (
            page["being_ref"] != self.being_ref
            or page["manifest_hash"] != self.manifest_hash
        ):
            raise SyncProtocolError("sync_authority_mismatch")
        sender = _origin(page["sender"], self.authority)
        requester = _origin(page["requester"], self.authority)
        if requester != self.origin:
            raise SyncProtocolError("sync_wrong_requester")
        issued_record = self.ledger.issued_request(page["request_id"])
        if issued_record is None:
            raise SyncProtocolError("unsolicited_sync_delta")
        issued_hash, issued = issued_record
        issued = self._request(issued)
        if issued_hash != _digest(REQUEST_DOMAIN, issued):
            raise SyncProtocolError("issued_sync_request_corrupt")
        if page["request_hash"] != issued_hash:
            raise SyncProtocolError("sync_request_hash_mismatch")
        if not isinstance(page["events"], list):
            raise SyncProtocolError("invalid_sync_events")
        if len(page["events"]) > issued["limit"]:
            raise SyncProtocolError("sync_delta_exceeds_requested_limit")
        if not isinstance(page["more"], bool):
            raise SyncProtocolError("invalid_sync_more")
        if page["more"] and not page["events"]:
            raise SyncProtocolError("invalid_sync_more")
        core = {
            key: copy.deepcopy(item) for key, item in page.items() if key != "page_hash"
        }
        if page["page_hash"] != _digest(DELTA_DOMAIN, core):
            raise SyncProtocolError("sync_page_hash_mismatch")
        offered = _validate_delta_content(
            events_value=page["events"],
            offered_value=page["offered_heads"],
            requested_heads=issued["heads"],
            limit=issued["limit"],
            more_value=page["more"],
            ledger=self.ledger,
        )
        return {
            **copy.deepcopy(dict(page)),
            "sender": sender,
            "requester": requester,
            "offered_heads": offered,
        }

    def pull(self, value: Any) -> Document:
        page = self.validate_delta(value)
        source = peer_id(page["sender"])
        receipt_base = {
            "schema": RECEIPT_SCHEMA,
            "request_id": page["request_id"],
            "request_hash": page["request_hash"],
            "page_hash": page["page_hash"],
            "being_ref": self.being_ref,
            "manifest_hash": self.manifest_hash,
            "sender": copy.deepcopy(page["sender"]),
            "receiver": copy.deepcopy(self.origin),
            "more": page["more"],
        }
        try:
            receipt = self.ledger.ingest_idempotent(
                cast(Sequence[Mapping[str, Any]], page["events"]),
                source=source,
                request_id=page["request_id"],
                page_hash=page["page_hash"],
                receipt_base=receipt_base,
            )
        except (LedgerError, WeaveProtocolError) as exception:
            raise SyncProtocolError(str(exception)) from exception
        return validate_receipt(
            receipt,
            self.authority,
            expected_sender=page["sender"],
            expected_receiver=self.origin,
        )


__all__ = [
    "DELTA_SCHEMA",
    "HEADS_SCHEMA",
    "MAX_SYNC_DOCUMENT_BYTES",
    "RECEIPT_SCHEMA",
    "REQUEST_SCHEMA",
    "SyncEngine",
    "SyncProtocolError",
    "peer_id",
    "validate_heads",
    "validate_heads_document",
    "validate_receipt",
]
