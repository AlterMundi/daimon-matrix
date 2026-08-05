"""Deterministic disposable local projections derived from the Weave ledger."""

from __future__ import annotations

import copy
import hashlib
import uuid
from collections import defaultdict
from collections.abc import Callable, Mapping, Sequence
from typing import Any, Final

from .canonical import CanonicalError, canonical_bytes
from .ledger import Ledger
from .weave import Event

PROJECTION_SCHEMA: Final = "dm.we.projection/v1"
PROJECTION_DOMAIN: Final = b"daimon/weave/projection/v1\x00"


class ProjectionError(RuntimeError):
    """Canonical events cannot produce one coherent local projection."""


def _projection_uuid(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return str(uuid.UUID(value)) == value
    except ValueError:
        return False


def _projection_text(value: Any, maximum: int) -> bool:
    return isinstance(value, str) and 1 <= len(value.encode("utf-8")) <= maximum


def _projection_ids(value: Any, *, ordered: bool) -> bool:
    return bool(
        isinstance(value, list)
        and all(_projection_uuid(item) for item in value)
        and len(value) == len(set(value))
        and (not ordered or value == sorted(value))
    )


def _valid_projection_entry(entry: Any) -> bool:
    fields = {
        "decision_event_id",
        "event_id",
        "invalid_projection_receipt_ids",
        "kind",
        "local_decision_chain",
        "origin",
        "projection_receipt_ids",
        "remote_decision_event_ids",
        "remote_projection_receipt_ids",
        "state",
        "subject",
    }
    if not isinstance(entry, Mapping) or set(entry) != fields:
        return False
    origin = entry["origin"]
    if not isinstance(origin, Mapping) or set(origin) != {
        "body_ref",
        "embodiment_id",
        "incarnation_id",
        "principal_id",
    }:
        return False
    if not (
        _projection_text(origin["body_ref"], 256)
        and _projection_text(origin["embodiment_id"], 256)
        and _projection_text(origin["incarnation_id"], 256)
        and _projection_text(origin["principal_id"], 128)
        and _projection_uuid(entry["event_id"])
        and entry["kind"]
        in {
            "configuration.proposed",
            "experience.observed",
            "preference.proposed",
            "skill.proposed",
            "memory.recorded",
        }
        and _projection_text(entry["subject"], 256)
        and entry["state"]
        in {"pending", "adopted", "rejected", "deferred", "reverted", "failed"}
        and (
            entry["decision_event_id"] is None
            or _projection_uuid(entry["decision_event_id"])
        )
        and _projection_ids(entry["local_decision_chain"], ordered=False)
        and _projection_ids(entry["remote_decision_event_ids"], ordered=True)
        and _projection_ids(entry["projection_receipt_ids"], ordered=True)
        and _projection_ids(entry["remote_projection_receipt_ids"], ordered=True)
        and _projection_ids(entry["invalid_projection_receipt_ids"], ordered=True)
    ):
        return False
    chain = entry["local_decision_chain"]
    decision_id = entry["decision_event_id"]
    if entry["state"] == "pending":
        return decision_id is None and not chain
    if entry["state"] == "failed":
        return decision_id is None or bool(chain and decision_id == chain[-1])
    return bool(chain and decision_id == chain[-1])


def _decision_chain(decisions: Sequence[Event]) -> tuple[list[str], bool]:
    """Return the explicit local decision chain and whether it is malformed."""

    if not decisions:
        return [], False
    by_id = {event["event_id"]: event for event in decisions}
    target_ids = {event["payload"]["target_event_id"] for event in decisions}
    if len(target_ids) != 1:
        return sorted(by_id), True
    children: dict[str, list[str]] = defaultdict(list)
    roots: list[str] = []
    malformed = False
    for event in decisions:
        predecessor = event["supersedes"]
        if predecessor is None:
            roots.append(event["event_id"])
            continue
        prior = by_id.get(predecessor)
        if (
            prior is None
            or prior["payload"]["target_event_id"]
            != event["payload"]["target_event_id"]
        ):
            malformed = True
            continue
        children[predecessor].append(event["event_id"])
    if len(roots) != 1 or any(len(values) != 1 for values in children.values()):
        malformed = True
    if malformed:
        return sorted(by_id), True
    chain: list[str] = []
    current: str | None = roots[0]
    while current is not None:
        if current in chain:
            return sorted(by_id), True
        chain.append(current)
        successors = children.get(current, [])
        current = None if not successors else successors[0]
    if set(chain) != set(by_id):
        return sorted(by_id), True
    return chain, False


class ProjectionEngine:
    """Build and atomically cache a local view; never execute adapter effects."""

    def __init__(self, ledger: Ledger) -> None:
        self.ledger = ledger

    def snapshot(self) -> dict[str, Any]:
        known = self.ledger.events(include_incomplete=False)
        local_embodiment = self.ledger.local_origin["embodiment_id"]
        target_kinds = {
            "configuration.proposed",
            "experience.observed",
            "memory.recorded",
            "preference.proposed",
            "skill.proposed",
        }
        targets = {
            event["event_id"]: event for event in known if event["kind"] in target_kinds
        }
        local_decisions: dict[str, list[Event]] = defaultdict(list)
        remote_decisions: dict[str, list[str]] = defaultdict(list)
        decisions_by_id: dict[str, Event] = {}
        local_receipts: dict[str, list[Event]] = defaultdict(list)
        remote_receipts: dict[str, list[str]] = defaultdict(list)
        for event in known:
            if event["kind"] == "adoption.decided":
                target_id = event["payload"]["target_event_id"]
                decisions_by_id[event["event_id"]] = event
                if event["origin"]["embodiment_id"] == local_embodiment:
                    local_decisions[target_id].append(event)
                else:
                    remote_decisions[target_id].append(event["event_id"])
            elif event["kind"] == "projection.receipted":
                target_id = event["payload"]["target_event_id"]
                if event["origin"]["embodiment_id"] == local_embodiment:
                    local_receipts[target_id].append(event)
                else:
                    remote_receipts[target_id].append(event["event_id"])

        entries: list[dict[str, Any]] = []
        states = {
            "adopt": "adopted",
            "reject": "rejected",
            "defer": "deferred",
            "revert": "reverted",
        }
        for event_id, event in sorted(targets.items()):
            decisions = local_decisions.get(event_id, [])
            chain, failed = _decision_chain(decisions)
            tip = None if failed or not chain else decisions_by_id[chain[-1]]
            state = (
                "failed"
                if failed
                else "pending"
                if tip is None
                else states[tip["payload"]["decision"]]
            )
            receipt_ids: list[str] = []
            receipt_errors: list[str] = []
            for receipt in sorted(
                local_receipts.get(event_id, []), key=lambda item: item["event_id"]
            ):
                decision = decisions_by_id.get(receipt["payload"]["decision_event_id"])
                if (
                    decision is None
                    or decision["origin"]["embodiment_id"] != local_embodiment
                    or decision["payload"]["target_event_id"] != event_id
                    or decision["payload"]["decision"] != "adopt"
                ):
                    receipt_errors.append(receipt["event_id"])
                else:
                    receipt_ids.append(receipt["event_id"])
            if receipt_errors:
                state = "failed"
            entries.append(
                {
                    "event_id": event_id,
                    "kind": event["kind"],
                    "subject": event["subject"],
                    "origin": copy.deepcopy(event["origin"]),
                    "state": state,
                    "decision_event_id": None if tip is None else tip["event_id"],
                    "local_decision_chain": chain,
                    "remote_decision_event_ids": sorted(
                        remote_decisions.get(event_id, [])
                    ),
                    "projection_receipt_ids": receipt_ids,
                    "remote_projection_receipt_ids": sorted(
                        remote_receipts.get(event_id, [])
                    ),
                    "invalid_projection_receipt_ids": receipt_errors,
                }
            )
        core = {
            "schema": PROJECTION_SCHEMA,
            "being_ref": self.ledger.authority.manifest.being_ref,
            "manifest_hash": self.ledger.authority.manifest.digest,
            "local_embodiment_id": local_embodiment,
            "entries": entries,
        }
        snapshot = {
            **core,
            "projection_hash": hashlib.sha256(
                PROJECTION_DOMAIN + canonical_bytes(core)
            ).hexdigest(),
        }
        return self.verify(snapshot)

    @staticmethod
    def verify(snapshot: Any) -> dict[str, Any]:
        fields = {
            "being_ref",
            "entries",
            "local_embodiment_id",
            "manifest_hash",
            "projection_hash",
            "schema",
        }
        if (
            not isinstance(snapshot, Mapping)
            or set(snapshot) != fields
            or snapshot.get("schema") != PROJECTION_SCHEMA
            or not _projection_text(snapshot.get("being_ref"), 256)
            or not _projection_text(snapshot.get("local_embodiment_id"), 256)
            or not isinstance(snapshot.get("manifest_hash"), str)
            or len(snapshot["manifest_hash"]) != 64
            or any(
                character not in "0123456789abcdef"
                for character in snapshot["manifest_hash"]
            )
            or not isinstance(snapshot.get("projection_hash"), str)
            or len(snapshot["projection_hash"]) != 64
            or any(
                character not in "0123456789abcdef"
                for character in snapshot["projection_hash"]
            )
        ):
            raise ProjectionError("invalid_projection_snapshot")
        entries = snapshot.get("entries")
        if not isinstance(entries, list) or any(
            not _valid_projection_entry(entry) for entry in entries
        ):
            raise ProjectionError("invalid_projection_snapshot")
        event_ids = [entry["event_id"] for entry in entries]
        if event_ids != sorted(event_ids) or len(event_ids) != len(set(event_ids)):
            raise ProjectionError("projection_entries_not_sorted")
        core = {
            key: copy.deepcopy(value)
            for key, value in snapshot.items()
            if key != "projection_hash"
        }
        try:
            expected = hashlib.sha256(
                PROJECTION_DOMAIN + canonical_bytes(core)
            ).hexdigest()
        except CanonicalError as exception:
            raise ProjectionError("invalid_projection_snapshot") from exception
        if snapshot["projection_hash"] != expected:
            raise ProjectionError("projection_hash_mismatch")
        return copy.deepcopy(dict(snapshot))

    def rebuild(
        self,
        *,
        before_replace: Callable[[Mapping[str, Any]], None] | None = None,
    ) -> dict[str, Any]:
        snapshot = self.snapshot()
        if before_replace is not None:
            before_replace(snapshot)
        self.ledger.replace_projection_cache(snapshot)
        return snapshot

    def cached(self) -> dict[str, Any] | None:
        value = self.ledger.projection_cache()
        if value is None:
            return None
        snapshot = self.verify(value)
        if (
            snapshot["being_ref"] != self.ledger.authority.manifest.being_ref
            or snapshot["manifest_hash"] != self.ledger.authority.manifest.digest
            or snapshot["local_embodiment_id"]
            != self.ledger.local_origin["embodiment_id"]
        ):
            raise ProjectionError("projection_authority_mismatch")
        return snapshot


__all__ = [
    "PROJECTION_DOMAIN",
    "PROJECTION_SCHEMA",
    "ProjectionEngine",
    "ProjectionError",
]
