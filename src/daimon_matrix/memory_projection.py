"""Ledger-authoritative personal-memory projection into pinned HMK v1.

HMK is an untrusted, disposable retrieval view.  This module maps accepted
``memory.recorded`` lanes to the closed HMK contract, verifies every returned
effect against current Matrix truth, and journals transport recovery without
acquiring identity or memory authority.
"""

from __future__ import annotations

import copy
import fcntl
import hashlib
import json
import os
import re
import sqlite3
import stat
import unicodedata
import uuid
from collections import defaultdict
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Protocol, cast

from .canonical import CanonicalError, b64url, canonical_bytes, unb64url
from .ledger import Ledger
from .memory_policy import (
    MAX_CONTENT_BYTES,
    PERSONAL_CATEGORIES,
    validate_content_ref,
    validate_memory_record,
)
from .weave import Event

HMK_COMMIT: Final = "f10fd5c3089c0962920314c97e14bc024feffa7a"
HMK_API_VERSION: Final = "1.0.0"
HMK_SCHEMA_VERSION: Final = 1
HMK_ADAPTER_ID: Final = "hmk-daimon-projection"
PROJECTOR_ID: Final = "matrix:personal-memory-projector"
PROJECTOR_VERSION: Final = "1.0.0"
CONTRACT_VERSION: Final = "v1"

PROFILE_SCHEMA: Final = "dm.memory-projection.profile/v1"
MANIFEST_SCHEMA: Final = "daimon-adapter-manifest/v0"
NEGOTIATION_SCHEMA: Final = "dm.memory-projection.negotiation/v1"
INTENT_SCHEMA: Final = "dm.memory-projection.intent/v1"
RECEIPT_SCHEMA: Final = "dm.memory-projection.receipt/v1"
RECONCILIATION_SCHEMA: Final = "dm.memory-projection.reconciliation/v1"
REBUILD_PLAN_SCHEMA: Final = "dm.memory-projection.rebuild-plan/v1"
REBUILD_RECEIPT_SCHEMA: Final = "dm.memory-projection.rebuild-receipt/v1"
RECALL_SCHEMA: Final = "dm.memory-projection.recall/v1"
CHECKPOINT_SCHEMA: Final = "dm.memory-projection.checkpoint/v1"
CURRENT_PROJECTION_SCHEMA: Final = "dm.memory.current-projection/v1"

HMK_REQUEST_SCHEMA: Final = "hmk.daimon-projection.request/v1"
HMK_RECEIPT_SCHEMA: Final = "hmk.daimon-projection.receipt/v1"
HMK_INSPECT_SCHEMA: Final = "hmk.daimon-projection.inspect/v1"
HMK_INSPECT_RESULT_SCHEMA: Final = "hmk.daimon-projection.inspect-result/v1"
HMK_VERIFY_SCHEMA: Final = "hmk.daimon-projection.verify/v1"
HMK_VERIFY_RESULT_SCHEMA: Final = "hmk.daimon-projection.verify-result/v1"
HMK_REBUILD_REQUEST_SCHEMA: Final = "hmk.daimon-projection.rebuild-request/v1"
HMK_REBUILD_PLAN_SCHEMA: Final = "hmk.daimon-projection.rebuild-plan/v1"
HMK_REBUILD_APPLY_SCHEMA: Final = "hmk.daimon-projection.rebuild-apply/v1"
HMK_REBUILD_RECEIPT_SCHEMA: Final = "hmk.daimon-projection.rebuild-receipt/v1"

MAX_DOCUMENT_BYTES: Final = 17 * 1024 * 1024
MAX_REBUILD_ITEMS: Final = 4096
MAX_UINT: Final = 2**53 - 1
JOURNAL_SCHEMA_VERSION: Final = 1

CHECKPOINT_DOMAIN: Final = b"daimon/memory-projection/checkpoint/v1\x00"
CURRENT_PROJECTION_DOMAIN: Final = b"daimon/memory/current-projection/v1\x00"
ADAPTER_DOMAIN: Final = b"daimon/memory-projection/adapter/v1\x00"
RECEIPT_DOMAIN: Final = b"daimon/memory-projection/receipt/v1\x00"
REBUILD_PLAN_DOMAIN: Final = b"daimon/memory-projection/rebuild-plan/v1\x00"
REBUILD_RECEIPT_DOMAIN: Final = b"daimon/memory-projection/rebuild-receipt/v1\x00"
HMK_NAMESPACE_DOMAIN: Final = b"hmk/daimon-projection/namespace/v1\x00"
HMK_PROJECTION_DOMAIN: Final = b"hmk/daimon-projection/identity/v1\x00"
HMK_RECEIPT_DOMAIN: Final = b"hmk/daimon-projection/receipt/v1\x00"
HMK_REBUILD_PLAN_DOMAIN: Final = b"hmk/daimon-projection/rebuild-plan/v1\x00"
HMK_REBUILD_RECEIPT_DOMAIN: Final = b"hmk/daimon-projection/rebuild-receipt/v1\x00"

CAPABILITIES: Final = (
    "advance",
    "inspect",
    "project",
    "rebuild-apply",
    "rebuild-plan",
    "retract",
    "verify",
)
_TRANSPORT_OPERATIONS: Final = frozenset({*CAPABILITIES, "apply"})
MEDIA_TYPES: Final = frozenset({"text/plain", "text/markdown"})

_HASH: Final = re.compile(r"^[0-9a-f]{64}$")
_SCOPED: Final = re.compile(r"^[a-z][a-z0-9.-]{1,31}:[A-Za-z0-9._:-]{1,160}$")
_ME_ID: Final = re.compile(r"^dm:being:v1:[A-Za-z0-9_-]{43}$")
_TOKEN: Final = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


class MemoryProjectionError(RuntimeError):
    """Stable fail-closed projection error."""

    def __init__(self, code: str, *, retryable: bool = False) -> None:
        super().__init__(code)
        self.code = code
        self.retryable = retryable


class ProjectionTransport(Protocol):
    """One injected HMK operation; configuration is outside request bytes."""

    def __call__(
        self, operation: str, document: Mapping[str, Any]
    ) -> Mapping[str, Any]: ...


ContentResolver = Callable[[Mapping[str, Any]], bytes]


def _canonical(value: Any, code: str) -> bytes:
    try:
        result = canonical_bytes(value)
    except CanonicalError as exception:
        raise MemoryProjectionError(code) from exception
    if len(result) > MAX_DOCUMENT_BYTES:
        raise MemoryProjectionError("memory_projection_document_too_large")
    return result


def _closed(value: Any, fields: set[str], code: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise MemoryProjectionError(code)
    return value


def _text(value: Any, code: str, *, maximum: int = 256) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value.encode("utf-8")) <= maximum
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise MemoryProjectionError(code)
    _canonical(value, code)
    return value


def _scoped(value: Any, code: str) -> str:
    result = _text(value, code)
    if _SCOPED.fullmatch(result) is None or ".." in result:
        raise MemoryProjectionError(code)
    return result


def _me_id(value: Any, code: str) -> str:
    result = _text(value, code)
    if _ME_ID.fullmatch(result) is None:
        raise MemoryProjectionError(code)
    return result


def _hash(value: Any, code: str) -> str:
    if not isinstance(value, str) or _HASH.fullmatch(value) is None:
        raise MemoryProjectionError(code)
    return value


def _uuid(value: Any, code: str) -> str:
    if not isinstance(value, str):
        raise MemoryProjectionError(code)
    try:
        parsed = uuid.UUID(value)
    except ValueError as exception:
        raise MemoryProjectionError(code) from exception
    if parsed.version not in {4, 5} or str(parsed) != value:
        raise MemoryProjectionError(code)
    return value


def _uint(value: Any, code: str, *, minimum: int = 0) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= MAX_UINT
    ):
        raise MemoryProjectionError(code)
    return value


def _token(value: Any, code: str) -> str:
    if not isinstance(value, str) or _TOKEN.fullmatch(value) is None:
        raise MemoryProjectionError(code)
    return value


def _derived(prefix: str, domain: bytes, value: Any) -> str:
    return prefix + b64url(
        hashlib.sha256(domain + _canonical(value, "invalid_artifact")).digest()
    )


def _derived_id(value: Any, prefix: str, code: str) -> str:
    result = _text(value, code, maximum=192)
    if not result.startswith(prefix):
        raise MemoryProjectionError(code)
    try:
        unb64url(result.removeprefix(prefix), length=32)
    except CanonicalError as exception:
        raise MemoryProjectionError(code) from exception
    return result


def _authority_denial() -> dict[str, bool]:
    return {
        "matrix_authority": False,
        "may_append_ledger": False,
        "may_issue_presence": False,
        "may_mint_membership": False,
        "may_sign_as_me": False,
    }


def create_projection_manifest() -> dict[str, Any]:
    core = {
        "provider_kind": "memory-projection",
        "capabilities": list(CAPABILITIES),
        "contracts": [
            {"contract": "memory-projection", "versions": [CONTRACT_VERSION]}
        ],
        "limits": {
            "max_input_bytes": MAX_DOCUMENT_BYTES,
            "max_output_bytes": 2 * 1024 * 1024,
            "max_runtime_ms": 300_000,
        },
        "authority": _authority_denial(),
    }
    return validate_projection_manifest(
        {
            "schema": MANIFEST_SCHEMA,
            "adapter_id": _derived("dm:adapter:v0:", ADAPTER_DOMAIN, core),
            **core,
        }
    )


def validate_projection_manifest(value: Any) -> dict[str, Any]:
    row = _closed(
        value,
        {
            "schema",
            "adapter_id",
            "provider_kind",
            "capabilities",
            "contracts",
            "limits",
            "authority",
        },
        "invalid_memory_projection_manifest",
    )
    if (
        row["schema"] != MANIFEST_SCHEMA
        or row["provider_kind"] != "memory-projection"
        or row["capabilities"] != list(CAPABILITIES)
        or row["contracts"]
        != [{"contract": "memory-projection", "versions": [CONTRACT_VERSION]}]
        or row["authority"] != _authority_denial()
    ):
        raise MemoryProjectionError("unsupported_memory_projection_manifest")
    limits = _closed(
        row["limits"],
        {"max_input_bytes", "max_output_bytes", "max_runtime_ms"},
        "invalid_memory_projection_manifest",
    )
    expected_limits = {
        "max_input_bytes": MAX_DOCUMENT_BYTES,
        "max_output_bytes": 2 * 1024 * 1024,
        "max_runtime_ms": 300_000,
    }
    if dict(limits) != expected_limits:
        raise MemoryProjectionError("invalid_memory_projection_manifest")
    core = {
        key: copy.deepcopy(row[key])
        for key in row
        if key not in {"schema", "adapter_id"}
    }
    if row["adapter_id"] != _derived("dm:adapter:v0:", ADAPTER_DOMAIN, core):
        raise MemoryProjectionError("memory_projection_adapter_id_mismatch")
    _canonical(row, "invalid_memory_projection_manifest")
    return copy.deepcopy(dict(row))


def negotiate_projection_manifest(
    value: Any, *, accepted_versions: Sequence[str]
) -> dict[str, Any]:
    manifest = validate_projection_manifest(value)
    if list(accepted_versions) != [CONTRACT_VERSION]:
        raise MemoryProjectionError("memory_projection_contract_unsupported")
    return {
        "schema": NEGOTIATION_SCHEMA,
        "status": "accepted",
        "adapter_id": manifest["adapter_id"],
        "provider_kind": "memory-projection",
        "contract": "memory-projection",
        "version": CONTRACT_VERSION,
        "hmk_commit": HMK_COMMIT,
    }


def create_projection_profile(
    *, source_instance: str, target_instance: str
) -> dict[str, Any]:
    return validate_projection_profile(
        {
            "schema": PROFILE_SCHEMA,
            "adapter_id": create_projection_manifest()["adapter_id"],
            "contract_version": CONTRACT_VERSION,
            "hmk_commit": HMK_COMMIT,
            "source_instance": source_instance,
            "target": {
                "instance_id": target_instance,
                "api_version": HMK_API_VERSION,
                "schema_version": HMK_SCHEMA_VERSION,
            },
            "projector": {"id": PROJECTOR_ID, "version": PROJECTOR_VERSION},
        }
    )


def validate_projection_profile(value: Any) -> dict[str, Any]:
    row = _closed(
        value,
        {
            "schema",
            "adapter_id",
            "contract_version",
            "hmk_commit",
            "source_instance",
            "target",
            "projector",
        },
        "invalid_memory_projection_profile",
    )
    if (
        row["schema"] != PROFILE_SCHEMA
        or row["adapter_id"] != create_projection_manifest()["adapter_id"]
        or row["contract_version"] != CONTRACT_VERSION
        or row["hmk_commit"] != HMK_COMMIT
    ):
        raise MemoryProjectionError("unsupported_memory_projection_profile")
    _scoped(row["source_instance"], "invalid_memory_projection_source")
    target = _closed(
        row["target"],
        {"instance_id", "api_version", "schema_version"},
        "invalid_memory_projection_target",
    )
    if (
        _scoped(target["instance_id"], "invalid_memory_projection_target")
        != target["instance_id"]
        or target["api_version"] != HMK_API_VERSION
        or target["schema_version"] != HMK_SCHEMA_VERSION
    ):
        raise MemoryProjectionError("unsupported_memory_projection_target")
    projector = _closed(
        row["projector"], {"id", "version"}, "invalid_memory_projection_projector"
    )
    if dict(projector) != {"id": PROJECTOR_ID, "version": PROJECTOR_VERSION}:
        raise MemoryProjectionError("unsupported_memory_projection_projector")
    _canonical(row, "invalid_memory_projection_profile")
    return copy.deepcopy(dict(row))


def _namespace_identity(profile: Mapping[str, Any], subject: str) -> dict[str, str]:
    projector = cast(Mapping[str, Any], profile["projector"])
    return {
        "source_instance": cast(str, profile["source_instance"]),
        "subject_me_id": subject,
        "projector_id": cast(str, projector["id"]),
        "projector_version": cast(str, projector["version"]),
    }


def _namespace_id(profile: Mapping[str, Any], subject: str) -> str:
    return _derived(
        "hmk:daimon-namespace:v1:",
        HMK_NAMESPACE_DOMAIN,
        _namespace_identity(profile, subject),
    )


def _projection_id(profile: Mapping[str, Any], subject: str, memory_id: str) -> str:
    return _derived(
        "hmk:daimon-projection:v1:",
        HMK_PROJECTION_DOMAIN,
        {"namespace_id": _namespace_id(profile, subject), "memory_id": memory_id},
    )


def _personal_lanes(ledger: Ledger) -> dict[str, list[Event]]:
    subject = ledger.authority.manifest.being_ref
    _me_id(subject, "invalid_memory_projection_subject")
    lanes: dict[str, list[Event]] = defaultdict(list)
    for event in ledger.events(include_incomplete=False):
        if event["kind"] != "memory.recorded" or event["subject"] != subject:
            continue
        try:
            record = validate_memory_record(event["payload"])
        except (ValueError, RuntimeError) as exception:
            raise MemoryProjectionError("invalid_matrix_memory_record") from exception
        if record["category"] not in PERSONAL_CATEGORIES:
            continue
        if record["author_me_id"] != subject:
            raise MemoryProjectionError("memory_projection_authority_violation")
        lanes[cast(str, record["memory_id"])].append(event)
    for memory_id, events in lanes.items():
        events.sort(key=lambda event: (event["payload"]["sequence"], event["event_id"]))
        previous: Event | None = None
        invariant: tuple[str, str, str] | None = None
        for sequence, event in enumerate(events, start=1):
            record = event["payload"]
            current_invariant = (
                cast(str, record["category"]),
                cast(str, record["author_me_id"]),
                cast(str, record["context"]),
            )
            if invariant is None:
                invariant = current_invariant
            expected_event = None if previous is None else previous["event_id"]
            expected_hash = None if previous is None else previous["content_hash"]
            expected_operation = "assert" if previous is None else None
            if (
                record["memory_id"] != memory_id
                or record["sequence"] != sequence
                or record["predecessor_event_id"] != expected_event
                or record["predecessor_hash"] != expected_hash
                or event["supersedes"] != expected_event
                or current_invariant != invariant
                or (
                    expected_operation is not None
                    and record["operation"] != expected_operation
                )
                or (previous is not None and record["operation"] == "assert")
            ):
                raise MemoryProjectionError("memory_projection_lane_forked")
            previous = event
    return dict(lanes)


def projection_checkpoint(ledger: Ledger) -> dict[str, Any]:
    lanes = _personal_lanes(ledger)
    records = sorted(
        (
            {"event_id": event["event_id"], "event_hash": event["content_hash"]}
            for events in lanes.values()
            for event in events
        ),
        key=lambda row: row["event_id"],
    )
    core = {
        "schema": CHECKPOINT_SCHEMA,
        "being_ref": ledger.authority.manifest.being_ref,
        "manifest_hash": ledger.authority.manifest.digest,
        "events": records,
    }
    return {
        **core,
        "sequence": len(records),
        "hash": hashlib.sha256(
            CHECKPOINT_DOMAIN + _canonical(core, "invalid_checkpoint")
        ).hexdigest(),
    }


def validate_current_memory_projection(value: Any) -> dict[str, Any]:
    row = _closed(
        value,
        {
            "being_ref",
            "checkpoint",
            "entries",
            "manifest_hash",
            "projection_hash",
            "schema",
            "total_active",
            "truncated",
        },
        "invalid_current_memory_projection",
    )
    if row["schema"] != CURRENT_PROJECTION_SCHEMA:
        raise MemoryProjectionError("unsupported_current_memory_projection")
    subject = _me_id(row["being_ref"], "invalid_current_memory_projection")
    manifest_hash = _hash(row["manifest_hash"], "invalid_current_memory_projection")
    checkpoint = _closed(
        row["checkpoint"],
        {"hash", "sequence"},
        "invalid_current_memory_projection",
    )
    _hash(checkpoint["hash"], "invalid_current_memory_projection")
    _uint(checkpoint["sequence"], "invalid_current_memory_projection")
    entries = row["entries"]
    total = _uint(row["total_active"], "invalid_current_memory_projection")
    if (
        not isinstance(entries, list)
        or len(entries) > 64
        or total < len(entries)
        or row["truncated"] is not (total > len(entries))
    ):
        raise MemoryProjectionError("invalid_current_memory_projection")
    normalized: list[dict[str, Any]] = []
    previous_memory_id: str | None = None
    for entry in entries:
        item = _closed(
            entry,
            {
                "author_me_id",
                "candidate_id",
                "category",
                "content_ref",
                "context",
                "decision_id",
                "event_hash",
                "event_id",
                "evidence_refs",
                "memory_id",
                "origin",
                "policy_id",
                "sequence",
            },
            "invalid_current_memory_projection",
        )
        event_id = _uuid(item["event_id"], "invalid_current_memory_projection")
        event_hash = _hash(item["event_hash"], "invalid_current_memory_projection")
        memory_id = _uuid(item["memory_id"], "invalid_current_memory_projection")
        if previous_memory_id is not None and memory_id <= previous_memory_id:
            raise MemoryProjectionError("invalid_current_memory_projection")
        previous_memory_id = memory_id
        sequence = _uint(
            item["sequence"], "invalid_current_memory_projection", minimum=1
        )
        if item["category"] not in PERSONAL_CATEGORIES:
            raise MemoryProjectionError("invalid_current_memory_projection")
        author = _me_id(item["author_me_id"], "invalid_current_memory_projection")
        if author != subject:
            raise MemoryProjectionError("current_memory_authority_violation")
        context = _text(
            item["context"], "invalid_current_memory_projection", maximum=128
        )
        try:
            content_ref = validate_content_ref(item["content_ref"])
        except ValueError as exception:
            raise MemoryProjectionError(
                "invalid_current_memory_projection"
            ) from exception
        evidence_refs = item["evidence_refs"]
        if (
            not isinstance(evidence_refs, list)
            or evidence_refs != sorted(set(evidence_refs))
            or len(evidence_refs) > 256
        ):
            raise MemoryProjectionError("invalid_current_memory_projection")
        for reference in evidence_refs:
            _uuid(reference, "invalid_current_memory_projection")
        for field, prefix in (
            ("policy_id", "dm:memory-policy:v1:"),
            ("candidate_id", "dm:memory-candidate:v1:"),
            ("decision_id", "dm:memory-decision:v1:"),
        ):
            _derived_id(item[field], prefix, "invalid_current_memory_projection")
        origin = _closed(
            item["origin"],
            {"body_ref", "embodiment_id", "incarnation_id", "principal_id"},
            "invalid_current_memory_projection",
        )
        for origin_value in origin.values():
            _text(origin_value, "invalid_current_memory_projection")
        normalized.append(
            {
                "event_id": event_id,
                "event_hash": event_hash,
                "memory_id": memory_id,
                "sequence": sequence,
                "category": item["category"],
                "author_me_id": author,
                "context": context,
                "content_ref": content_ref,
                "evidence_refs": copy.deepcopy(evidence_refs),
                "policy_id": item["policy_id"],
                "candidate_id": item["candidate_id"],
                "decision_id": item["decision_id"],
                "origin": copy.deepcopy(dict(origin)),
            }
        )
    core = {
        key: copy.deepcopy(item)
        for key, item in row.items()
        if key != "projection_hash"
    }
    if (
        row["projection_hash"]
        != hashlib.sha256(
            CURRENT_PROJECTION_DOMAIN
            + _canonical(core, "invalid_current_memory_projection")
        ).hexdigest()
    ):
        raise MemoryProjectionError("current_memory_projection_hash_mismatch")
    if manifest_hash != row["manifest_hash"]:
        raise MemoryProjectionError("invalid_current_memory_projection")
    return {**copy.deepcopy(dict(row)), "entries": normalized}


def current_memory_projection(ledger: Ledger, *, limit: int = 64) -> dict[str, Any]:
    """Return current personal-memory heads as bounded provenance-only refs."""

    _uint(limit, "invalid_current_memory_projection_limit", minimum=1)
    if limit > 64:
        raise MemoryProjectionError("invalid_current_memory_projection_limit")
    lanes = _personal_lanes(ledger)
    active: list[dict[str, Any]] = []
    for memory_id in sorted(lanes):
        head = lanes[memory_id][-1]
        record = validate_memory_record(head["payload"])
        if record["operation"] == "retract":
            continue
        active.append(
            {
                "event_id": head["event_id"],
                "event_hash": head["content_hash"],
                "memory_id": memory_id,
                "sequence": record["sequence"],
                "category": record["category"],
                "author_me_id": record["author_me_id"],
                "context": record["context"],
                "content_ref": copy.deepcopy(record["content_ref"]),
                "evidence_refs": copy.deepcopy(record["evidence_refs"]),
                "policy_id": record["policy_id"],
                "candidate_id": record["candidate_id"],
                "decision_id": record["decision_id"],
                "origin": copy.deepcopy(head["origin"]),
            }
        )
    checkpoint = projection_checkpoint(ledger)
    core = {
        "schema": CURRENT_PROJECTION_SCHEMA,
        "being_ref": ledger.authority.manifest.being_ref,
        "manifest_hash": ledger.authority.manifest.digest,
        "checkpoint": {
            "sequence": checkpoint["sequence"],
            "hash": checkpoint["hash"],
        },
        "entries": active[:limit],
        "total_active": len(active),
        "truncated": len(active) > limit,
    }
    return validate_current_memory_projection(
        {
            **core,
            "projection_hash": hashlib.sha256(
                CURRENT_PROJECTION_DOMAIN
                + _canonical(core, "invalid_current_memory_projection")
            ).hexdigest(),
        }
    )


def _head_event(ledger: Ledger, memory_id: str) -> tuple[list[Event], Event]:
    _uuid(memory_id, "invalid_memory_id")
    lane = _personal_lanes(ledger).get(memory_id)
    if not lane:
        raise MemoryProjectionError("matrix_memory_unknown")
    return lane, lane[-1]


def _resolve_statement(
    event: Mapping[str, Any], resolver: ContentResolver
) -> tuple[dict[str, Any], str]:
    reference = event["payload"]["content_ref"]
    if reference is None:
        raise MemoryProjectionError("memory_projection_content_absent")
    try:
        normalized = validate_content_ref(reference)
        raw = resolver(copy.deepcopy(normalized))
    except MemoryProjectionError:
        raise
    except Exception as exception:
        raise MemoryProjectionError(
            "memory_projection_content_unavailable", retryable=True
        ) from exception
    if not isinstance(raw, bytes):
        raise MemoryProjectionError("memory_projection_content_invalid")
    if (
        normalized["media_type"] not in MEDIA_TYPES
        or not 1 <= len(raw) <= MAX_CONTENT_BYTES
        or len(raw) != normalized["byte_length"]
        or hashlib.sha256(raw).hexdigest() != normalized["sha256"]
    ):
        raise MemoryProjectionError("memory_projection_content_mismatch")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exception:
        raise MemoryProjectionError("memory_projection_content_not_utf8") from exception
    if unicodedata.normalize("NFC", text) != text:
        raise MemoryProjectionError("memory_projection_content_not_nfc")
    return normalized, text


def _assert_owner_directory(path: Path) -> None:
    if path.is_symlink():
        raise MemoryProjectionError("projection_journal_parent_symlink")
    try:
        info = path.stat()
    except FileNotFoundError as exception:
        raise MemoryProjectionError("projection_journal_parent_missing") from exception
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise MemoryProjectionError("projection_journal_parent_not_owner_only")


def _prepare_journal_path(path: Path) -> None:
    missing: list[Path] = []
    candidate = path.parent
    while not candidate.exists():
        if candidate.is_symlink():
            raise MemoryProjectionError("projection_journal_ancestor_symlink")
        missing.append(candidate)
        if candidate == candidate.parent:
            raise MemoryProjectionError("projection_journal_parent_missing")
        candidate = candidate.parent
    for directory in reversed(missing):
        directory.mkdir(mode=0o700)
        _assert_owner_directory(directory)
    _assert_owner_directory(path.parent)
    try:
        info = path.lstat()
    except FileNotFoundError:
        try:
            descriptor = os.open(
                path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
        except FileExistsError:
            pass
        else:
            os.close(descriptor)
        info = path.lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise MemoryProjectionError("projection_journal_not_owner_only")


@dataclass(frozen=True)
class JournalEntry:
    idempotency_key: str
    intent_hash: str
    source_event_id: str
    intent: dict[str, Any]
    request: dict[str, Any]
    state: str
    receipt: dict[str, Any] | None


class _ProjectionJournalBase:
    """Owner-only recovery journal; never a source of personal-memory truth."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(os.path.abspath(path))

    def _connect(self) -> sqlite3.Connection:
        _prepare_journal_path(self.path)
        connection = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=30000")
        mode = connection.execute("PRAGMA journal_mode=DELETE").fetchone()[0]
        if str(mode).lower() != "delete":
            connection.close()
            raise MemoryProjectionError("projection_journal_mode_unsupported")
        connection.execute("PRAGMA synchronous=FULL")
        return connection


def _hmk_checkpoint(value: Any, code: str) -> dict[str, Any]:
    row = _closed(value, {"sequence", "hash"}, code)
    return {
        "sequence": _uint(row["sequence"], code),
        "hash": _hash(row["hash"], code),
    }


def _hmk_head(value: Any, code: str) -> dict[str, Any]:
    row = _closed(value, {"event_id", "event_hash", "sequence"}, code)
    return {
        "event_id": _uuid(row["event_id"], code),
        "event_hash": _hash(row["event_hash"], code),
        "sequence": _uint(row["sequence"], code, minimum=1),
    }


def _statement_ref(value: Any, code: str) -> dict[str, Any]:
    row = _closed(
        value,
        {"sha256", "byte_length", "media_type", "classification"},
        code,
    )
    if row["media_type"] not in MEDIA_TYPES:
        raise MemoryProjectionError(code)
    if row["classification"] not in {"public", "personal", "private", "protected"}:
        raise MemoryProjectionError(code)
    length = _uint(row["byte_length"], code, minimum=1)
    if length > MAX_CONTENT_BYTES:
        raise MemoryProjectionError(code)
    return {
        "sha256": _hash(row["sha256"], code),
        "byte_length": length,
        "media_type": cast(str, row["media_type"]),
        "classification": cast(str, row["classification"]),
    }


def _source_statement(
    event: Mapping[str, Any], resolver: ContentResolver
) -> dict[str, Any] | None:
    if event["payload"]["operation"] == "retract":
        return None
    reference, text = _resolve_statement(event, resolver)
    return {
        "sha256": reference["sha256"],
        "byte_length": reference["byte_length"],
        "media_type": reference["media_type"],
        "classification": reference["classification"],
        "text": text,
    }


def _build_hmk_request(
    profile: Mapping[str, Any],
    ledger: Ledger,
    event: Event,
    *,
    idempotency_key: str,
    resolver: ContentResolver,
) -> tuple[dict[str, Any], dict[str, Any]]:
    record = validate_memory_record(event["payload"])
    operation = {"assert": "project", "correct": "advance", "retract": "retract"}[
        cast(str, record["operation"])
    ]
    checkpoint = projection_checkpoint(ledger)
    request_id = str(
        uuid.uuid5(
            uuid.NAMESPACE_URL,
            "daimon-hmk-projection:"
            + cast(str, profile["source_instance"])
            + ":"
            + event["event_id"],
        )
    )
    statement = _source_statement(event, resolver)
    request = {
        "schema": HMK_REQUEST_SCHEMA,
        "adapter": {"id": HMK_ADAPTER_ID, "version": HMK_API_VERSION},
        "request_id": request_id,
        "idempotency_key": idempotency_key,
        "operation": operation,
        "target": copy.deepcopy(profile["target"]),
        "source_instance": profile["source_instance"],
        "subject_me_id": event["subject"],
        "author_me_id": record["author_me_id"],
        "memory_id": record["memory_id"],
        "category": record["category"],
        "head": {
            "event_id": event["event_id"],
            "event_hash": event["content_hash"],
            "sequence": record["sequence"],
            "predecessor_event_id": record["predecessor_event_id"],
            "predecessor_hash": record["predecessor_hash"],
        },
        "statement": statement,
        "projector": copy.deepcopy(profile["projector"]),
        "source_checkpoint": {
            "sequence": checkpoint["sequence"],
            "hash": checkpoint["hash"],
        },
    }
    request_hash = hashlib.sha256(
        _canonical(request, "invalid_hmk_projection_request")
    ).hexdigest()
    intent = {
        "schema": INTENT_SCHEMA,
        "adapter_id": profile["adapter_id"],
        "hmk_commit": HMK_COMMIT,
        "operation": operation,
        "source_event": {
            "event_id": event["event_id"],
            "event_hash": event["content_hash"],
            "memory_id": record["memory_id"],
            "sequence": record["sequence"],
            "category": record["category"],
            "author_me_id": record["author_me_id"],
            "evidence_hash": hashlib.sha256(
                _canonical(record["evidence_refs"], "invalid_memory_evidence")
            ).hexdigest(),
            "content_ref": None
            if record["content_ref"] is None
            else copy.deepcopy(record["content_ref"]),
        },
        "source_checkpoint": copy.deepcopy(request["source_checkpoint"]),
        "target": copy.deepcopy(profile["target"]),
        "projector": copy.deepcopy(profile["projector"]),
        "hmk_request_hash": request_hash,
    }
    return request, intent


def _validate_hmk_state(
    value: Any,
    *,
    profile: Mapping[str, Any],
    subject: str,
    memory_id: str,
    include_text: bool,
) -> dict[str, Any]:
    fields = {
        "projection_id",
        "namespace_id",
        "memory_id",
        "author_me_id",
        "category",
        "head",
        "statement",
        "source_checkpoint",
        "active",
    }
    row = _closed(value, fields, "invalid_hmk_projection_state")
    expected_namespace = _namespace_id(profile, subject)
    expected_projection = _projection_id(profile, subject, memory_id)
    if (
        row["namespace_id"] != expected_namespace
        or row["projection_id"] != expected_projection
        or row["memory_id"] != memory_id
        or row["author_me_id"] != subject
        or row["category"] not in PERSONAL_CATEGORIES
        or not isinstance(row["active"], bool)
    ):
        raise MemoryProjectionError("hmk_projection_binding_mismatch")
    head = _hmk_head(row["head"], "invalid_hmk_projection_state")
    statement_value = row["statement"]
    if include_text:
        statement_row = _closed(
            statement_value,
            {"sha256", "byte_length", "media_type", "classification", "text"},
            "invalid_hmk_projection_state",
        )
        statement = _statement_ref(
            {key: statement_row[key] for key in statement_row if key != "text"},
            "invalid_hmk_projection_state",
        )
        if not isinstance(statement_row["text"], str):
            raise MemoryProjectionError("invalid_hmk_projection_state")
        raw = statement_row["text"].encode("utf-8")
        if (
            len(raw) != statement["byte_length"]
            or hashlib.sha256(raw).hexdigest() != statement["sha256"]
        ):
            raise MemoryProjectionError("hmk_projection_content_mismatch")
        statement["text"] = statement_row["text"]
    else:
        statement = _statement_ref(statement_value, "invalid_hmk_projection_state")
    return {
        "projection_id": expected_projection,
        "namespace_id": expected_namespace,
        "memory_id": memory_id,
        "author_me_id": subject,
        "category": row["category"],
        "head": head,
        "statement": statement,
        "source_checkpoint": _hmk_checkpoint(
            row["source_checkpoint"], "invalid_hmk_projection_state"
        ),
        "active": row["active"],
    }


def _hmk_derived_id(
    value: Any,
    *,
    prefix: str,
    domain: bytes,
    body: Mapping[str, Any],
    code: str,
) -> str:
    expected = _derived(prefix, domain, body)
    if value != expected:
        raise MemoryProjectionError(code)
    return expected


def _validate_hmk_receipt(
    value: Any, *, request: Mapping[str, Any], profile: Mapping[str, Any]
) -> dict[str, Any]:
    fields = {
        "schema",
        "receipt_id",
        "request_id",
        "idempotency_key",
        "request_hash",
        "operation",
        "outcome",
        "target",
        "namespace",
        "previous",
        "current",
    }
    row = _closed(value, fields, "invalid_hmk_projection_receipt")
    request_hash = hashlib.sha256(
        _canonical(request, "invalid_hmk_projection_request")
    ).hexdigest()
    if (
        row["schema"] != HMK_RECEIPT_SCHEMA
        or row["request_id"] != request["request_id"]
        or row["idempotency_key"] != request["idempotency_key"]
        or row["request_hash"] != request_hash
        or row["operation"] != request["operation"]
        or row["outcome"] != "applied"
        or row["target"] != profile["target"]
    ):
        raise MemoryProjectionError("hmk_projection_receipt_binding_mismatch")
    subject = cast(str, request["subject_me_id"])
    memory_id = cast(str, request["memory_id"])
    current = _validate_hmk_state(
        row["current"],
        profile=profile,
        subject=subject,
        memory_id=memory_id,
        include_text=False,
    )
    statement = request["statement"]
    expected_active = request["operation"] != "retract"
    if (
        current["head"]
        != {
            "event_id": request["head"]["event_id"],
            "event_hash": request["head"]["event_hash"],
            "sequence": request["head"]["sequence"],
        }
        or current["category"] != request["category"]
        or current["active"] != expected_active
        or current["source_checkpoint"] != request["source_checkpoint"]
    ):
        raise MemoryProjectionError("hmk_projection_effect_mismatch")
    if statement is not None:
        expected_statement = {key: statement[key] for key in statement if key != "text"}
        if current["statement"] != expected_statement:
            raise MemoryProjectionError("hmk_projection_effect_mismatch")
    previous = row["previous"]
    if request["operation"] == "project":
        if previous is not None:
            raise MemoryProjectionError("hmk_projection_effect_mismatch")
    else:
        if previous is None:
            raise MemoryProjectionError("hmk_projection_effect_mismatch")
        prior = _validate_hmk_state(
            previous,
            profile=profile,
            subject=subject,
            memory_id=memory_id,
            include_text=False,
        )
        if (
            prior["head"]["event_id"] != request["head"]["predecessor_event_id"]
            or prior["head"]["event_hash"] != request["head"]["predecessor_hash"]
            or prior["head"]["sequence"] + 1 != request["head"]["sequence"]
            or prior["active"] is not True
        ):
            raise MemoryProjectionError("hmk_projection_predecessor_mismatch")
    namespace = _closed(
        row["namespace"],
        {"namespace_id", "generation", "manifest_hash", "source_checkpoint"},
        "invalid_hmk_projection_receipt",
    )
    if (
        namespace["namespace_id"] != _namespace_id(profile, subject)
        or _hmk_checkpoint(
            namespace["source_checkpoint"], "invalid_hmk_projection_receipt"
        )
        != request["source_checkpoint"]
    ):
        raise MemoryProjectionError("hmk_projection_namespace_mismatch")
    _uint(namespace["generation"], "invalid_hmk_projection_receipt", minimum=1)
    _hash(namespace["manifest_hash"], "invalid_hmk_projection_receipt")
    body = {key: copy.deepcopy(row[key]) for key in row if key != "receipt_id"}
    _hmk_derived_id(
        row["receipt_id"],
        prefix="hmk:daimon-receipt:v1:",
        domain=HMK_RECEIPT_DOMAIN,
        body=body,
        code="hmk_projection_receipt_id_mismatch",
    )
    return copy.deepcopy(dict(row))


class ProjectionJournal(_ProjectionJournalBase):
    @contextmanager
    def exclusive(self) -> Iterator[None]:
        """Serialize recovery through an owner-only, crash-released process lock."""

        self.initialize()
        lock_path = self.path.with_name(self.path.name + ".lock")
        _prepare_journal_path(lock_path)
        descriptor = os.open(
            lock_path,
            os.O_RDWR | getattr(os, "O_NOFOLLOW", 0),
        )
        acquired = False
        try:
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) & 0o077
            ):
                raise MemoryProjectionError("projection_journal_lock_not_owner_only")
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            acquired = True
            yield
        finally:
            if acquired:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def initialize(self) -> None:
        connection = self._connect()
        try:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS metadata(
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                ) WITHOUT ROWID;
                CREATE TABLE IF NOT EXISTS projection_requests(
                    idempotency_key TEXT PRIMARY KEY,
                    intent_hash TEXT NOT NULL,
                    source_event_id TEXT NOT NULL,
                    intent_json BLOB NOT NULL,
                    request_json BLOB NOT NULL,
                    state TEXT NOT NULL CHECK(state IN ('pending', 'completed')),
                    receipt_json BLOB
                ) WITHOUT ROWID;
                """
            )
            existing = connection.execute(
                "SELECT value FROM metadata WHERE key='schema_version'"
            ).fetchone()
            if existing is None:
                connection.execute(
                    "INSERT INTO metadata(key, value) VALUES('schema_version', ?)",
                    (str(JOURNAL_SCHEMA_VERSION),),
                )
            elif existing["value"] != str(JOURNAL_SCHEMA_VERSION):
                raise MemoryProjectionError("projection_journal_schema_unsupported")
        finally:
            connection.close()

    @staticmethod
    def _entry(row: sqlite3.Row) -> JournalEntry:
        receipt = None
        if row["receipt_json"] is not None:
            receipt = json.loads(bytes(row["receipt_json"]))
        return JournalEntry(
            idempotency_key=cast(str, row["idempotency_key"]),
            intent_hash=cast(str, row["intent_hash"]),
            source_event_id=cast(str, row["source_event_id"]),
            intent=json.loads(bytes(row["intent_json"])),
            request=json.loads(bytes(row["request_json"])),
            state=cast(str, row["state"]),
            receipt=receipt,
        )

    def lookup(self, idempotency_key: str) -> JournalEntry | None:
        _token(idempotency_key, "invalid_projection_idempotency_key")
        self.initialize()
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT * FROM projection_requests WHERE idempotency_key=?",
                (idempotency_key,),
            ).fetchone()
            return None if row is None else self._entry(row)
        finally:
            connection.close()

    def reserve(
        self,
        *,
        idempotency_key: str,
        intent_hash: str,
        source_event_id: str,
        intent: Mapping[str, Any],
        request: Mapping[str, Any],
    ) -> JournalEntry:
        _token(idempotency_key, "invalid_projection_idempotency_key")
        _hash(intent_hash, "invalid_projection_intent_hash")
        _uuid(source_event_id, "invalid_projection_source_event")
        intent_raw = _canonical(intent, "invalid_projection_intent")
        request_raw = _canonical(request, "invalid_hmk_projection_request")
        self.initialize()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM projection_requests WHERE idempotency_key=?",
                (idempotency_key,),
            ).fetchone()
            if row is None:
                connection.execute(
                    """INSERT INTO projection_requests
                    VALUES(?, ?, ?, ?, ?, 'pending', NULL)""",
                    (
                        idempotency_key,
                        intent_hash,
                        source_event_id,
                        intent_raw,
                        request_raw,
                    ),
                )
                connection.commit()
                return JournalEntry(
                    idempotency_key,
                    intent_hash,
                    source_event_id,
                    copy.deepcopy(dict(intent)),
                    copy.deepcopy(dict(request)),
                    "pending",
                    None,
                )
            entry = self._entry(row)
            if (
                entry.intent_hash != intent_hash
                or entry.source_event_id != source_event_id
                or _canonical(entry.intent, "invalid_projection_intent") != intent_raw
                or _canonical(entry.request, "invalid_hmk_projection_request")
                != request_raw
            ):
                raise MemoryProjectionError("memory_projection_idempotency_conflict")
            connection.commit()
            return entry
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def complete(
        self, *, idempotency_key: str, intent_hash: str, receipt: Mapping[str, Any]
    ) -> dict[str, Any]:
        normalized = validate_projection_receipt(receipt)
        raw = _canonical(normalized, "invalid_memory_projection_receipt")
        self.initialize()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM projection_requests WHERE idempotency_key=?",
                (idempotency_key,),
            ).fetchone()
            if row is None or row["intent_hash"] != intent_hash:
                raise MemoryProjectionError("projection_journal_request_missing")
            entry = self._entry(row)
            if entry.state == "completed":
                if (
                    entry.receipt is None
                    or _canonical(entry.receipt, "invalid_memory_projection_receipt")
                    != raw
                ):
                    raise MemoryProjectionError("projection_journal_receipt_conflict")
                connection.commit()
                return entry.receipt
            connection.execute(
                """UPDATE projection_requests
                SET state='completed', receipt_json=? WHERE idempotency_key=?""",
                (raw, idempotency_key),
            )
            connection.commit()
            return normalized
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def integrity(self) -> dict[str, Any]:
        self.initialize()
        connection = self._connect()
        try:
            integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
            foreign_keys = connection.execute("PRAGMA foreign_key_check").fetchall()
            pending = connection.execute(
                "SELECT COUNT(*) FROM projection_requests WHERE state='pending'"
            ).fetchone()[0]
            completed = connection.execute(
                "SELECT COUNT(*) FROM projection_requests WHERE state='completed'"
            ).fetchone()[0]
            return {
                "schema": "dm.memory-projection.journal-status/v1",
                "integrity": str(integrity),
                "foreign_key_violations": len(foreign_keys),
                "pending": int(pending),
                "completed": int(completed),
            }
        finally:
            connection.close()


def _matrix_receipt(
    *,
    profile: Mapping[str, Any],
    intent: Mapping[str, Any],
    hmk_request: Mapping[str, Any],
    hmk_receipt: Mapping[str, Any],
) -> dict[str, Any]:
    current = cast(Mapping[str, Any], hmk_receipt["current"])
    namespace = cast(Mapping[str, Any], hmk_receipt["namespace"])
    source = cast(Mapping[str, Any], intent["source_event"])
    body = {
        "schema": RECEIPT_SCHEMA,
        "adapter_id": profile["adapter_id"],
        "hmk_commit": HMK_COMMIT,
        "source_instance": profile["source_instance"],
        "subject_me_id": hmk_request["subject_me_id"],
        "operation": intent["operation"],
        "request_id": hmk_request["request_id"],
        "idempotency_key": hmk_request["idempotency_key"],
        "intent_hash": hashlib.sha256(
            _canonical(intent, "invalid_projection_intent")
        ).hexdigest(),
        "source_event": copy.deepcopy(dict(source)),
        "source_checkpoint": copy.deepcopy(hmk_request["source_checkpoint"]),
        "target": copy.deepcopy(profile["target"]),
        "projector": copy.deepcopy(profile["projector"]),
        "hmk_request_hash": hashlib.sha256(
            _canonical(hmk_request, "invalid_hmk_projection_request")
        ).hexdigest(),
        "hmk_receipt": {
            "receipt_id": hmk_receipt["receipt_id"],
            "receipt_hash": hashlib.sha256(
                _canonical(hmk_receipt, "invalid_hmk_projection_receipt")
            ).hexdigest(),
        },
        "effect": {
            "namespace_id": current["namespace_id"],
            "projection_id": current["projection_id"],
            "generation": namespace["generation"],
            "manifest_hash": namespace["manifest_hash"],
            "head": copy.deepcopy(current["head"]),
            "statement": copy.deepcopy(current["statement"]),
            "active": current["active"],
        },
        "outcome": "applied",
    }
    return validate_projection_receipt(
        {
            **body,
            "receipt_id": _derived(
                "dm:memory-projection-receipt:v1:", RECEIPT_DOMAIN, body
            ),
        }
    )


def validate_projection_receipt(value: Any) -> dict[str, Any]:
    fields = {
        "schema",
        "receipt_id",
        "adapter_id",
        "hmk_commit",
        "source_instance",
        "subject_me_id",
        "operation",
        "request_id",
        "idempotency_key",
        "intent_hash",
        "source_event",
        "source_checkpoint",
        "target",
        "projector",
        "hmk_request_hash",
        "hmk_receipt",
        "effect",
        "outcome",
    }
    row = _closed(value, fields, "invalid_memory_projection_receipt")
    if (
        row["schema"] != RECEIPT_SCHEMA
        or row["adapter_id"] != create_projection_manifest()["adapter_id"]
        or row["hmk_commit"] != HMK_COMMIT
        or row["operation"] not in {"project", "advance", "retract"}
        or row["outcome"] != "applied"
    ):
        raise MemoryProjectionError("invalid_memory_projection_receipt")
    _uuid(row["request_id"], "invalid_memory_projection_receipt")
    _token(row["idempotency_key"], "invalid_memory_projection_receipt")
    _hash(row["intent_hash"], "invalid_memory_projection_receipt")
    _hash(row["hmk_request_hash"], "invalid_memory_projection_receipt")
    source_instance = _scoped(
        row["source_instance"], "invalid_memory_projection_receipt"
    )
    subject = _me_id(row["subject_me_id"], "invalid_memory_projection_receipt")
    source = _closed(
        row["source_event"],
        {
            "event_id",
            "event_hash",
            "memory_id",
            "sequence",
            "category",
            "author_me_id",
            "evidence_hash",
            "content_ref",
        },
        "invalid_memory_projection_receipt",
    )
    _uuid(source["event_id"], "invalid_memory_projection_receipt")
    _hash(source["event_hash"], "invalid_memory_projection_receipt")
    _uuid(source["memory_id"], "invalid_memory_projection_receipt")
    _uint(source["sequence"], "invalid_memory_projection_receipt", minimum=1)
    if source["category"] not in PERSONAL_CATEGORIES:
        raise MemoryProjectionError("invalid_memory_projection_receipt")
    _me_id(source["author_me_id"], "invalid_memory_projection_receipt")
    _hash(source["evidence_hash"], "invalid_memory_projection_receipt")
    if source["author_me_id"] != subject:
        raise MemoryProjectionError("invalid_memory_projection_receipt")
    if (row["operation"] == "project") != (source["sequence"] == 1):
        raise MemoryProjectionError("invalid_memory_projection_receipt")
    if source["content_ref"] is not None:
        try:
            validate_content_ref(source["content_ref"])
        except ValueError as exception:
            raise MemoryProjectionError(
                "invalid_memory_projection_receipt"
            ) from exception
    if (row["operation"] == "retract") != (source["content_ref"] is None):
        raise MemoryProjectionError("invalid_memory_projection_receipt")
    _hmk_checkpoint(row["source_checkpoint"], "invalid_memory_projection_receipt")
    target = _closed(
        row["target"],
        {"instance_id", "api_version", "schema_version"},
        "invalid_memory_projection_receipt",
    )
    if (
        _scoped(target["instance_id"], "invalid_memory_projection_receipt")
        != target["instance_id"]
        or target["api_version"] != HMK_API_VERSION
        or target["schema_version"] != HMK_SCHEMA_VERSION
    ):
        raise MemoryProjectionError("invalid_memory_projection_receipt")
    projector = _closed(
        row["projector"],
        {"id", "version"},
        "invalid_memory_projection_receipt",
    )
    if dict(projector) != {"id": PROJECTOR_ID, "version": PROJECTOR_VERSION}:
        raise MemoryProjectionError("invalid_memory_projection_receipt")
    hmk = _closed(
        row["hmk_receipt"],
        {"receipt_id", "receipt_hash"},
        "invalid_memory_projection_receipt",
    )
    _derived_id(
        hmk["receipt_id"], "hmk:daimon-receipt:v1:", "invalid_memory_projection_receipt"
    )
    _hash(hmk["receipt_hash"], "invalid_memory_projection_receipt")
    effect = _closed(
        row["effect"],
        {
            "namespace_id",
            "projection_id",
            "generation",
            "manifest_hash",
            "head",
            "statement",
            "active",
        },
        "invalid_memory_projection_receipt",
    )
    _derived_id(
        effect["namespace_id"],
        "hmk:daimon-namespace:v1:",
        "invalid_memory_projection_receipt",
    )
    _derived_id(
        effect["projection_id"],
        "hmk:daimon-projection:v1:",
        "invalid_memory_projection_receipt",
    )
    _uint(effect["generation"], "invalid_memory_projection_receipt", minimum=1)
    _hash(effect["manifest_hash"], "invalid_memory_projection_receipt")
    _hmk_head(effect["head"], "invalid_memory_projection_receipt")
    _statement_ref(effect["statement"], "invalid_memory_projection_receipt")
    if not isinstance(effect["active"], bool):
        raise MemoryProjectionError("invalid_memory_projection_receipt")
    identity = {
        "source_instance": source_instance,
        "subject_me_id": subject,
        "projector_id": PROJECTOR_ID,
        "projector_version": PROJECTOR_VERSION,
    }
    expected_namespace = _derived(
        "hmk:daimon-namespace:v1:", HMK_NAMESPACE_DOMAIN, identity
    )
    expected_projection = _derived(
        "hmk:daimon-projection:v1:",
        HMK_PROJECTION_DOMAIN,
        {"namespace_id": expected_namespace, "memory_id": source["memory_id"]},
    )
    expected_head = {
        "event_id": source["event_id"],
        "event_hash": source["event_hash"],
        "sequence": source["sequence"],
    }
    if (
        effect["namespace_id"] != expected_namespace
        or effect["projection_id"] != expected_projection
        or effect["head"] != expected_head
        or effect["active"] != (row["operation"] != "retract")
    ):
        raise MemoryProjectionError("memory_projection_receipt_effect_mismatch")
    if source["content_ref"] is not None:
        expected_statement = {
            key: source["content_ref"][key]
            for key in ("sha256", "byte_length", "media_type", "classification")
        }
        if effect["statement"] != expected_statement:
            raise MemoryProjectionError("memory_projection_receipt_effect_mismatch")
    body = {key: copy.deepcopy(row[key]) for key in row if key != "receipt_id"}
    expected = _derived("dm:memory-projection-receipt:v1:", RECEIPT_DOMAIN, body)
    if row["receipt_id"] != expected:
        raise MemoryProjectionError("memory_projection_receipt_id_mismatch")
    return copy.deepcopy(dict(row))


def _transport(
    transport: ProjectionTransport, operation: str, document: Mapping[str, Any]
) -> dict[str, Any]:
    if operation not in _TRANSPORT_OPERATIONS:
        raise MemoryProjectionError("memory_projection_operation_unsupported")
    try:
        result = transport(operation, copy.deepcopy(dict(document)))
    except MemoryProjectionError:
        raise
    except Exception as exception:
        raise MemoryProjectionError(
            "memory_projection_transport_unavailable", retryable=True
        ) from exception
    if not isinstance(result, Mapping):
        raise MemoryProjectionError("invalid_hmk_projection_response")
    _canonical(result, "invalid_hmk_projection_response")
    return copy.deepcopy(dict(result))


def _inspect_query(
    profile: Mapping[str, Any], subject: str, memory_id: str
) -> dict[str, Any]:
    return {
        "schema": HMK_INSPECT_SCHEMA,
        "target": copy.deepcopy(profile["target"]),
        "source_instance": profile["source_instance"],
        "subject_me_id": subject,
        "memory_id": memory_id,
        "projector": copy.deepcopy(profile["projector"]),
    }


def _verify_query(profile: Mapping[str, Any], subject: str) -> dict[str, Any]:
    return {
        "schema": HMK_VERIFY_SCHEMA,
        "target": copy.deepcopy(profile["target"]),
        "source_instance": profile["source_instance"],
        "subject_me_id": subject,
        "projector": copy.deepcopy(profile["projector"]),
    }


def _inspect_result(
    value: Any,
    *,
    profile: Mapping[str, Any],
    subject: str,
    memory_id: str,
) -> dict[str, Any]:
    row = _closed(
        value,
        {"schema", "target", "namespace", "projection"},
        "invalid_hmk_inspect_result",
    )
    if (
        row["schema"] != HMK_INSPECT_RESULT_SCHEMA
        or row["target"] != profile["target"]
        or row["namespace"] != _namespace_identity(profile, subject)
    ):
        raise MemoryProjectionError("hmk_inspect_binding_mismatch")
    projection = _validate_hmk_state(
        row["projection"],
        profile=profile,
        subject=subject,
        memory_id=memory_id,
        include_text=True,
    )
    return {
        "schema": HMK_INSPECT_RESULT_SCHEMA,
        "target": copy.deepcopy(row["target"]),
        "namespace": copy.deepcopy(row["namespace"]),
        "projection": projection,
    }


def _lane_statement(
    lane: Sequence[Event], resolver: ContentResolver
) -> tuple[dict[str, Any], str]:
    for event in reversed(lane):
        if event["payload"]["content_ref"] is not None:
            return _resolve_statement(event, resolver)
    raise MemoryProjectionError("memory_projection_content_absent")


def _expected_states(
    profile: Mapping[str, Any], ledger: Ledger, resolver: ContentResolver
) -> list[dict[str, Any]]:
    subject = ledger.authority.manifest.being_ref
    states: list[dict[str, Any]] = []
    for memory_id, lane in sorted(_personal_lanes(ledger).items()):
        head_event = lane[-1]
        head = head_event["payload"]
        reference, _text_value = _lane_statement(lane, resolver)
        states.append(
            {
                "projection_id": _projection_id(profile, subject, memory_id),
                "namespace_id": _namespace_id(profile, subject),
                "memory_id": memory_id,
                "author_me_id": subject,
                "category": head["category"],
                "head": {
                    "event_id": head_event["event_id"],
                    "event_hash": head_event["content_hash"],
                    "sequence": head["sequence"],
                },
                "statement": {
                    "sha256": reference["sha256"],
                    "byte_length": reference["byte_length"],
                    "media_type": reference["media_type"],
                    "classification": reference["classification"],
                },
                "active": head["operation"] != "retract",
            }
        )
    return states


def _rebuild_entries(ledger: Ledger, resolver: ContentResolver) -> list[dict[str, Any]]:
    subject = ledger.authority.manifest.being_ref
    entries: list[dict[str, Any]] = []
    for memory_id, lane in sorted(_personal_lanes(ledger).items()):
        head_event = lane[-1]
        record = head_event["payload"]
        if record["operation"] == "retract":
            continue
        reference, text = _resolve_statement(head_event, resolver)
        entries.append(
            {
                "memory_id": memory_id,
                "author_me_id": subject,
                "category": record["category"],
                "head": {
                    "event_id": head_event["event_id"],
                    "event_hash": head_event["content_hash"],
                    "sequence": record["sequence"],
                },
                "statement": {
                    "sha256": reference["sha256"],
                    "byte_length": reference["byte_length"],
                    "media_type": reference["media_type"],
                    "classification": reference["classification"],
                    "text": text,
                },
            }
        )
    return entries


def _manifest_entry(state: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "projection_id": state["projection_id"],
        "memory_id": state["memory_id"],
        "author_me_id": state["author_me_id"],
        "category": state["category"],
        "head": copy.deepcopy(state["head"]),
        "statement": copy.deepcopy(state["statement"]),
        "active": True,
    }


def _expected_manifest_hash(states: Sequence[Mapping[str, Any]]) -> str:
    manifest = [_manifest_entry(state) for state in states if state["active"] is True]
    return hashlib.sha256(
        _canonical(manifest, "invalid_projection_manifest")
    ).hexdigest()


@dataclass(frozen=True)
class MemoryProjectionAdapter:
    ledger: Ledger
    profile: Mapping[str, Any]
    transport: ProjectionTransport
    content_resolver: ContentResolver
    journal: ProjectionJournal

    def __post_init__(self) -> None:
        normalized = validate_projection_profile(self.profile)
        _me_id(
            self.ledger.authority.manifest.being_ref,
            "invalid_memory_projection_subject",
        )
        object.__setattr__(self, "profile", normalized)
        self.journal.initialize()

    @property
    def manifest(self) -> dict[str, Any]:
        return create_projection_manifest()

    def _current_event(self, event_id: str) -> Event:
        _uuid(event_id, "invalid_projection_source_event")
        event = self.ledger.event(event_id, include_incomplete=False)
        if event is None or event["kind"] != "memory.recorded":
            raise MemoryProjectionError("matrix_memory_event_unknown")
        subject = self.ledger.authority.manifest.being_ref
        record = validate_memory_record(event["payload"])
        if (
            event["subject"] != subject
            or record["category"] not in PERSONAL_CATEGORIES
            or record["author_me_id"] != subject
        ):
            raise MemoryProjectionError("memory_projection_authority_violation")
        _lane, head = _head_event(self.ledger, cast(str, record["memory_id"]))
        if head["event_id"] != event_id:
            raise MemoryProjectionError("memory_projection_event_not_current")
        return event

    def project(self, *, event_id: str, idempotency_key: str) -> dict[str, Any]:
        """Apply one current accepted personal-memory head exactly once."""

        with self.journal.exclusive():
            return self._project_exclusive(
                event_id=event_id, idempotency_key=idempotency_key
            )

    def _project_exclusive(
        self, *, event_id: str, idempotency_key: str
    ) -> dict[str, Any]:
        event = self._current_event(event_id)
        _token(idempotency_key, "invalid_projection_idempotency_key")
        existing = self.journal.lookup(idempotency_key)
        if existing is not None:
            if existing.source_event_id != event_id:
                raise MemoryProjectionError("memory_projection_idempotency_conflict")
            request = existing.request
            intent = existing.intent
            intent_hash = existing.intent_hash
            if existing.state == "completed":
                if existing.receipt is None:
                    raise MemoryProjectionError("projection_journal_receipt_missing")
                reconciliation = self.reconcile(existing.receipt)
                if reconciliation["status"] != "verified":
                    raise MemoryProjectionError(cast(str, reconciliation["reason"]))
                return validate_projection_receipt(existing.receipt)
        else:
            request, intent = _build_hmk_request(
                self.profile,
                self.ledger,
                event,
                idempotency_key=idempotency_key,
                resolver=self.content_resolver,
            )
            intent_hash = hashlib.sha256(
                _canonical(intent, "invalid_projection_intent")
            ).hexdigest()
            self.journal.reserve(
                idempotency_key=idempotency_key,
                intent_hash=intent_hash,
                source_event_id=event_id,
                intent=intent,
                request=request,
            )
        hmk_result = _transport(self.transport, "apply", request)
        hmk_receipt = _validate_hmk_receipt(
            hmk_result, request=request, profile=self.profile
        )
        receipt = _matrix_receipt(
            profile=self.profile,
            intent=intent,
            hmk_request=request,
            hmk_receipt=hmk_receipt,
        )
        reconciliation = self.reconcile(receipt)
        if reconciliation["status"] != "verified":
            raise MemoryProjectionError(cast(str, reconciliation["reason"]))
        return self.journal.complete(
            idempotency_key=idempotency_key,
            intent_hash=intent_hash,
            receipt=receipt,
        )

    def inspect(self, *, memory_id: str) -> dict[str, Any]:
        subject = self.ledger.authority.manifest.being_ref
        _head_event(self.ledger, memory_id)
        query = _inspect_query(self.profile, subject, memory_id)
        return _inspect_result(
            _transport(self.transport, "inspect", query),
            profile=self.profile,
            subject=subject,
            memory_id=memory_id,
        )

    def _verify_result(self, value: Any) -> dict[str, Any]:
        subject = self.ledger.authority.manifest.being_ref
        fields = {
            "schema",
            "target",
            "namespace",
            "namespace_id",
            "generation",
            "source_checkpoint",
            "manifest_hash",
            "logical_hash",
            "projections",
        }
        row = _closed(value, fields, "invalid_hmk_verify_result")
        expected_checkpoint = projection_checkpoint(self.ledger)
        expected_states = _expected_states(
            self.profile, self.ledger, self.content_resolver
        )
        expected_by_memory = {state["memory_id"]: state for state in expected_states}
        if (
            row["schema"] != HMK_VERIFY_RESULT_SCHEMA
            or row["target"] != self.profile["target"]
            or row["namespace"] != _namespace_identity(self.profile, subject)
            or row["namespace_id"] != _namespace_id(self.profile, subject)
            or _hmk_checkpoint(row["source_checkpoint"], "invalid_hmk_verify_result")
            != {
                "sequence": expected_checkpoint["sequence"],
                "hash": expected_checkpoint["hash"],
            }
        ):
            raise MemoryProjectionError("hmk_verify_binding_mismatch")
        generation = _uint(row["generation"], "invalid_hmk_verify_result", minimum=1)
        manifest_hash = _hash(row["manifest_hash"], "invalid_hmk_verify_result")
        logical_hash = _hash(row["logical_hash"], "invalid_hmk_verify_result")
        expected_manifest = _expected_manifest_hash(expected_states)
        if manifest_hash != expected_manifest or logical_hash != expected_manifest:
            raise MemoryProjectionError("hmk_projection_manifest_mismatch")
        raw_projections = row["projections"]
        if (
            not isinstance(raw_projections, list)
            or len(raw_projections) > MAX_REBUILD_ITEMS
        ):
            raise MemoryProjectionError("invalid_hmk_verify_result")
        actual: list[dict[str, Any]] = []
        for item in raw_projections:
            if not isinstance(item, Mapping):
                raise MemoryProjectionError("invalid_hmk_verify_result")
            memory_id = cast(str, item.get("memory_id"))
            if memory_id not in expected_by_memory:
                raise MemoryProjectionError("hmk_projection_extra_record")
            state = _validate_hmk_state(
                item,
                profile=self.profile,
                subject=subject,
                memory_id=memory_id,
                include_text=False,
            )
            expected = expected_by_memory[memory_id]
            for field in (
                "projection_id",
                "namespace_id",
                "memory_id",
                "author_me_id",
                "category",
                "head",
                "statement",
                "active",
            ):
                if state[field] != expected[field]:
                    raise MemoryProjectionError("hmk_projection_state_mismatch")
            if state["source_checkpoint"]["sequence"] > expected_checkpoint["sequence"]:
                raise MemoryProjectionError("hmk_projection_checkpoint_ahead")
            actual.append(state)
        if [state["memory_id"] for state in actual] != sorted(expected_by_memory):
            raise MemoryProjectionError("hmk_projection_set_mismatch")
        return {
            "schema": HMK_VERIFY_RESULT_SCHEMA,
            "target": copy.deepcopy(row["target"]),
            "namespace": copy.deepcopy(row["namespace"]),
            "namespace_id": row["namespace_id"],
            "generation": generation,
            "source_checkpoint": copy.deepcopy(row["source_checkpoint"]),
            "manifest_hash": manifest_hash,
            "logical_hash": logical_hash,
            "projections": actual,
        }

    def verify(self) -> dict[str, Any]:
        subject = self.ledger.authority.manifest.being_ref
        query = _verify_query(self.profile, subject)
        return self._verify_result(_transport(self.transport, "verify", query))

    def reconcile(self, receipt: Mapping[str, Any]) -> dict[str, Any]:
        normalized = validate_projection_receipt(receipt)
        source = cast(Mapping[str, Any], normalized["source_event"])
        try:
            _lane, current = _head_event(self.ledger, cast(str, source["memory_id"]))
            if (
                current["event_id"] != source["event_id"]
                or current["content_hash"] != source["event_hash"]
            ):
                return {
                    "schema": RECONCILIATION_SCHEMA,
                    "receipt_id": normalized["receipt_id"],
                    "status": "effect-truth-discrepancy",
                    "reason": "matrix-memory-head-changed",
                }
            inspected = self.inspect(memory_id=cast(str, source["memory_id"]))
        except MemoryProjectionError as exception:
            status = (
                "effect-truth-unverifiable"
                if exception.retryable
                else "effect-truth-discrepancy"
            )
            return {
                "schema": RECONCILIATION_SCHEMA,
                "receipt_id": normalized["receipt_id"],
                "status": status,
                "reason": exception.code,
            }
        projection = cast(Mapping[str, Any], inspected["projection"])
        effect = cast(Mapping[str, Any], normalized["effect"])
        comparison = {
            "projection_id": effect["projection_id"],
            "namespace_id": effect["namespace_id"],
            "head": effect["head"],
            "statement": effect["statement"],
            "source_checkpoint": normalized["source_checkpoint"],
            "active": effect["active"],
        }
        observed = {key: projection[key] for key in comparison}
        observed_statement = cast(Mapping[str, Any], observed["statement"])
        observed["statement"] = {
            key: observed_statement[key]
            for key in ("sha256", "byte_length", "media_type", "classification")
        }
        if observed != comparison:
            return {
                "schema": RECONCILIATION_SCHEMA,
                "receipt_id": normalized["receipt_id"],
                "status": "effect-truth-discrepancy",
                "reason": "hmk-observed-effect-mismatch",
            }
        return {
            "schema": RECONCILIATION_SCHEMA,
            "receipt_id": normalized["receipt_id"],
            "status": "verified",
            "reason": "effect-truth-matches",
        }

    def recall(self, *, memory_id: str) -> dict[str, Any]:
        verified = self.verify()
        inspected = self.inspect(memory_id=memory_id)
        projection = cast(Mapping[str, Any], inspected["projection"])
        if projection["active"] is not True:
            raise MemoryProjectionError("memory_projection_inactive")
        _lane, head = _head_event(self.ledger, memory_id)
        if (
            projection["head"]["event_id"] != head["event_id"]
            or projection["head"]["event_hash"] != head["content_hash"]
        ):
            raise MemoryProjectionError("memory_projection_head_mismatch")
        return {
            "schema": RECALL_SCHEMA,
            "origin": {
                "kind": "daimon-projection",
                "source_instance": self.profile["source_instance"],
                "subject_me_id": self.ledger.authority.manifest.being_ref,
                "author_me_id": projection["author_me_id"],
                "memory_id": memory_id,
                "category": projection["category"],
                "head": copy.deepcopy(projection["head"]),
                "classification": projection["statement"]["classification"],
                "projector": copy.deepcopy(self.profile["projector"]),
            },
            "statement": copy.deepcopy(projection["statement"]),
            "verified_against": {
                "checkpoint": copy.deepcopy(verified["source_checkpoint"]),
                "manifest_hash": verified["manifest_hash"],
            },
        }

    def rebuild_plan(self, *, request_id: str, idempotency_key: str) -> dict[str, Any]:
        _uuid(request_id, "invalid_rebuild_request_id")
        _token(idempotency_key, "invalid_projection_idempotency_key")
        subject = self.ledger.authority.manifest.being_ref
        checkpoint = projection_checkpoint(self.ledger)
        entries = _rebuild_entries(self.ledger, self.content_resolver)
        request = {
            "schema": HMK_REBUILD_REQUEST_SCHEMA,
            "request_id": request_id,
            "idempotency_key": idempotency_key,
            "target": copy.deepcopy(self.profile["target"]),
            "source_instance": self.profile["source_instance"],
            "subject_me_id": subject,
            "projector": copy.deepcopy(self.profile["projector"]),
            "source_checkpoint": {
                "sequence": checkpoint["sequence"],
                "hash": checkpoint["hash"],
            },
            "entries": entries,
        }
        hmk_plan = _validate_hmk_rebuild_plan(
            _transport(self.transport, "rebuild-plan", request),
            request=request,
            profile=self.profile,
        )
        hmk_plan_hash = hashlib.sha256(
            _canonical(hmk_plan, "invalid_hmk_rebuild_plan")
        ).hexdigest()
        body = {
            "schema": REBUILD_PLAN_SCHEMA,
            "adapter_id": self.profile["adapter_id"],
            "hmk_commit": HMK_COMMIT,
            "matrix_checkpoint": {
                "sequence": checkpoint["sequence"],
                "hash": checkpoint["hash"],
            },
            "matrix_manifest_hash": _expected_manifest_hash(
                _expected_states(self.profile, self.ledger, self.content_resolver)
            ),
            "hmk_plan_hash": hmk_plan_hash,
            "hmk_plan": hmk_plan,
        }
        return validate_rebuild_plan(
            {
                **body,
                "plan_id": _derived(
                    "dm:memory-projection-rebuild-plan:v1:",
                    REBUILD_PLAN_DOMAIN,
                    body,
                ),
            }
        )

    def rebuild_apply(self, value: Any) -> dict[str, Any]:
        with self.journal.exclusive():
            return self._rebuild_apply_exclusive(value)

    def _rebuild_apply_exclusive(self, value: Any) -> dict[str, Any]:
        plan = validate_rebuild_plan(value)
        if plan["adapter_id"] != self.profile["adapter_id"]:
            raise MemoryProjectionError("rebuild_adapter_mismatch")
        checkpoint = projection_checkpoint(self.ledger)
        current = {"sequence": checkpoint["sequence"], "hash": checkpoint["hash"]}
        if current != plan["matrix_checkpoint"]:
            raise MemoryProjectionError("rebuild_matrix_checkpoint_drift")
        manifest = _expected_manifest_hash(
            _expected_states(self.profile, self.ledger, self.content_resolver)
        )
        if manifest != plan["matrix_manifest_hash"]:
            raise MemoryProjectionError("rebuild_matrix_manifest_drift")
        hmk_plan = _closed(
            plan["hmk_plan"],
            {
                "schema",
                "plan_id",
                "request_id",
                "idempotency_key",
                "target",
                "namespace",
                "namespace_id",
                "source_checkpoint",
                "entries",
                "manifest_hash",
                "prior",
            },
            "invalid_hmk_rebuild_plan",
        )
        _uuid(hmk_plan["request_id"], "invalid_hmk_rebuild_plan")
        _token(hmk_plan["idempotency_key"], "invalid_hmk_rebuild_plan")
        expected_request = {
            "schema": HMK_REBUILD_REQUEST_SCHEMA,
            "request_id": hmk_plan["request_id"],
            "idempotency_key": hmk_plan["idempotency_key"],
            "target": copy.deepcopy(self.profile["target"]),
            "source_instance": self.profile["source_instance"],
            "subject_me_id": self.ledger.authority.manifest.being_ref,
            "projector": copy.deepcopy(self.profile["projector"]),
            "source_checkpoint": current,
            "entries": _rebuild_entries(self.ledger, self.content_resolver),
        }
        _validate_hmk_rebuild_plan(
            hmk_plan,
            request=expected_request,
            profile=self.profile,
        )
        apply = {"schema": HMK_REBUILD_APPLY_SCHEMA, "plan": plan["hmk_plan"]}
        hmk_receipt = _validate_hmk_rebuild_receipt(
            _transport(self.transport, "rebuild-apply", apply),
            hmk_plan=cast(Mapping[str, Any], plan["hmk_plan"]),
            profile=self.profile,
        )
        verified = self.verify()
        if verified["manifest_hash"] != plan["matrix_manifest_hash"]:
            raise MemoryProjectionError("rebuild_postcondition_mismatch")
        receipt_body = {
            "schema": REBUILD_RECEIPT_SCHEMA,
            "plan_id": plan["plan_id"],
            "adapter_id": self.profile["adapter_id"],
            "hmk_commit": HMK_COMMIT,
            "matrix_checkpoint": copy.deepcopy(plan["matrix_checkpoint"]),
            "matrix_manifest_hash": plan["matrix_manifest_hash"],
            "hmk_receipt_id": hmk_receipt["receipt_id"],
            "hmk_receipt_hash": hashlib.sha256(
                _canonical(hmk_receipt, "invalid_hmk_rebuild_receipt")
            ).hexdigest(),
            "namespace_id": hmk_receipt["namespace_id"],
            "generation": hmk_receipt["generation"],
            "outcome": "rebuilt",
        }
        return validate_rebuild_receipt(
            {
                **receipt_body,
                "receipt_id": _derived(
                    "dm:memory-projection-rebuild-receipt:v1:",
                    REBUILD_RECEIPT_DOMAIN,
                    receipt_body,
                ),
            }
        )


def _validate_hmk_rebuild_plan(
    value: Any, *, request: Mapping[str, Any], profile: Mapping[str, Any]
) -> dict[str, Any]:
    fields = {
        "schema",
        "plan_id",
        "request_id",
        "idempotency_key",
        "target",
        "namespace",
        "namespace_id",
        "source_checkpoint",
        "entries",
        "manifest_hash",
        "prior",
    }
    row = _closed(value, fields, "invalid_hmk_rebuild_plan")
    subject = cast(str, request["subject_me_id"])
    if (
        row["schema"] != HMK_REBUILD_PLAN_SCHEMA
        or row["request_id"] != request["request_id"]
        or row["idempotency_key"] != request["idempotency_key"]
        or row["target"] != profile["target"]
        or row["namespace"] != _namespace_identity(profile, subject)
        or row["namespace_id"] != _namespace_id(profile, subject)
        or row["source_checkpoint"] != request["source_checkpoint"]
        or row["entries"] != request["entries"]
    ):
        raise MemoryProjectionError("hmk_rebuild_plan_binding_mismatch")
    manifest = []
    for entry in cast(list[Mapping[str, Any]], request["entries"]):
        statement = cast(Mapping[str, Any], entry["statement"])
        manifest.append(
            {
                "projection_id": _projection_id(
                    profile, subject, cast(str, entry["memory_id"])
                ),
                "memory_id": entry["memory_id"],
                "author_me_id": entry["author_me_id"],
                "category": entry["category"],
                "head": copy.deepcopy(entry["head"]),
                "statement": {
                    key: statement[key]
                    for key in (
                        "sha256",
                        "byte_length",
                        "media_type",
                        "classification",
                    )
                },
                "active": True,
            }
        )
    expected_manifest = hashlib.sha256(
        _canonical(manifest, "invalid_hmk_rebuild_plan")
    ).hexdigest()
    if row["manifest_hash"] != expected_manifest:
        raise MemoryProjectionError("hmk_rebuild_manifest_mismatch")
    prior = row["prior"]
    if prior is not None:
        previous = _closed(
            prior,
            {"generation", "manifest_hash", "source_checkpoint"},
            "invalid_hmk_rebuild_plan",
        )
        _uint(previous["generation"], "invalid_hmk_rebuild_plan")
        _hash(previous["manifest_hash"], "invalid_hmk_rebuild_plan")
        _hmk_checkpoint(previous["source_checkpoint"], "invalid_hmk_rebuild_plan")
    body = {key: copy.deepcopy(row[key]) for key in row if key != "plan_id"}
    _hmk_derived_id(
        row["plan_id"],
        prefix="hmk:daimon-rebuild-plan:v1:",
        domain=HMK_REBUILD_PLAN_DOMAIN,
        body=body,
        code="hmk_rebuild_plan_id_mismatch",
    )
    return copy.deepcopy(dict(row))


def validate_rebuild_plan(value: Any) -> dict[str, Any]:
    row = _closed(
        value,
        {
            "schema",
            "plan_id",
            "adapter_id",
            "hmk_commit",
            "matrix_checkpoint",
            "matrix_manifest_hash",
            "hmk_plan_hash",
            "hmk_plan",
        },
        "invalid_memory_projection_rebuild_plan",
    )
    if (
        row["schema"] != REBUILD_PLAN_SCHEMA
        or row["adapter_id"] != create_projection_manifest()["adapter_id"]
        or row["hmk_commit"] != HMK_COMMIT
    ):
        raise MemoryProjectionError("invalid_memory_projection_rebuild_plan")
    _hmk_checkpoint(row["matrix_checkpoint"], "invalid_memory_projection_rebuild_plan")
    _hash(row["matrix_manifest_hash"], "invalid_memory_projection_rebuild_plan")
    hmk_hash = _hash(row["hmk_plan_hash"], "invalid_memory_projection_rebuild_plan")
    if (
        not isinstance(row["hmk_plan"], Mapping)
        or hashlib.sha256(
            _canonical(row["hmk_plan"], "invalid_memory_projection_rebuild_plan")
        ).hexdigest()
        != hmk_hash
    ):
        raise MemoryProjectionError("memory_projection_hmk_plan_hash_mismatch")
    body = {key: copy.deepcopy(row[key]) for key in row if key != "plan_id"}
    expected = _derived(
        "dm:memory-projection-rebuild-plan:v1:", REBUILD_PLAN_DOMAIN, body
    )
    if row["plan_id"] != expected:
        raise MemoryProjectionError("memory_projection_rebuild_plan_id_mismatch")
    return copy.deepcopy(dict(row))


def _validate_hmk_rebuild_receipt(
    value: Any, *, hmk_plan: Mapping[str, Any], profile: Mapping[str, Any]
) -> dict[str, Any]:
    row = _closed(
        value,
        {
            "schema",
            "receipt_id",
            "plan_id",
            "plan_hash",
            "target",
            "namespace_id",
            "generation",
            "source_checkpoint",
            "manifest_hash",
            "projection_ids",
            "outcome",
        },
        "invalid_hmk_rebuild_receipt",
    )
    expected_plan_hash = hashlib.sha256(
        _canonical(hmk_plan, "invalid_hmk_rebuild_plan")
    ).hexdigest()
    projection_ids = sorted(
        _projection_id(
            profile,
            cast(str, cast(Mapping[str, Any], hmk_plan["namespace"])["subject_me_id"]),
            cast(str, entry["memory_id"]),
        )
        for entry in cast(list[Mapping[str, Any]], hmk_plan["entries"])
    )
    if (
        row["schema"] != HMK_REBUILD_RECEIPT_SCHEMA
        or row["plan_id"] != hmk_plan["plan_id"]
        or row["plan_hash"] != expected_plan_hash
        or row["target"] != profile["target"]
        or row["namespace_id"] != hmk_plan["namespace_id"]
        or row["source_checkpoint"] != hmk_plan["source_checkpoint"]
        or row["manifest_hash"] != hmk_plan["manifest_hash"]
        or row["projection_ids"] != projection_ids
        or row["outcome"] != "rebuilt"
    ):
        raise MemoryProjectionError("hmk_rebuild_receipt_binding_mismatch")
    _uint(row["generation"], "invalid_hmk_rebuild_receipt", minimum=1)
    body = {key: copy.deepcopy(row[key]) for key in row if key != "receipt_id"}
    _hmk_derived_id(
        row["receipt_id"],
        prefix="hmk:daimon-rebuild-receipt:v1:",
        domain=HMK_REBUILD_RECEIPT_DOMAIN,
        body=body,
        code="hmk_rebuild_receipt_id_mismatch",
    )
    return copy.deepcopy(dict(row))


def validate_rebuild_receipt(value: Any) -> dict[str, Any]:
    row = _closed(
        value,
        {
            "schema",
            "receipt_id",
            "plan_id",
            "adapter_id",
            "hmk_commit",
            "matrix_checkpoint",
            "matrix_manifest_hash",
            "hmk_receipt_id",
            "hmk_receipt_hash",
            "namespace_id",
            "generation",
            "outcome",
        },
        "invalid_memory_projection_rebuild_receipt",
    )
    if (
        row["schema"] != REBUILD_RECEIPT_SCHEMA
        or row["adapter_id"] != create_projection_manifest()["adapter_id"]
        or row["hmk_commit"] != HMK_COMMIT
        or row["outcome"] != "rebuilt"
    ):
        raise MemoryProjectionError("invalid_memory_projection_rebuild_receipt")
    _derived_id(
        row["plan_id"],
        "dm:memory-projection-rebuild-plan:v1:",
        "invalid_memory_projection_rebuild_receipt",
    )
    _hmk_checkpoint(
        row["matrix_checkpoint"], "invalid_memory_projection_rebuild_receipt"
    )
    _hash(row["matrix_manifest_hash"], "invalid_memory_projection_rebuild_receipt")
    _derived_id(
        row["hmk_receipt_id"],
        "hmk:daimon-rebuild-receipt:v1:",
        "invalid_memory_projection_rebuild_receipt",
    )
    _hash(row["hmk_receipt_hash"], "invalid_memory_projection_rebuild_receipt")
    _derived_id(
        row["namespace_id"],
        "hmk:daimon-namespace:v1:",
        "invalid_memory_projection_rebuild_receipt",
    )
    _uint(row["generation"], "invalid_memory_projection_rebuild_receipt", minimum=1)
    body = {key: copy.deepcopy(row[key]) for key in row if key != "receipt_id"}
    expected = _derived(
        "dm:memory-projection-rebuild-receipt:v1:",
        REBUILD_RECEIPT_DOMAIN,
        body,
    )
    if row["receipt_id"] != expected:
        raise MemoryProjectionError("memory_projection_rebuild_receipt_id_mismatch")
    return copy.deepcopy(dict(row))


__all__ = [
    "CAPABILITIES",
    "CONTRACT_VERSION",
    "HMK_COMMIT",
    "MemoryProjectionAdapter",
    "MemoryProjectionError",
    "ProjectionJournal",
    "ProjectionTransport",
    "create_projection_manifest",
    "create_projection_profile",
    "current_memory_projection",
    "negotiate_projection_manifest",
    "projection_checkpoint",
    "validate_current_memory_projection",
    "validate_projection_manifest",
    "validate_projection_profile",
    "validate_projection_receipt",
    "validate_rebuild_plan",
    "validate_rebuild_receipt",
]
