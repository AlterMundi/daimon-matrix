"""Executable DM-015 source claims, publications, evidence, and local CAS.

Source assertions are attributed evidence, never identity, membership, routing,
disclosure, or truth authority.  This module deliberately keeps intrinsic wire
validation separate from receiver-local assessment and import state.
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
import threading
import uuid
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from functools import wraps
from pathlib import Path
from typing import Any, Concatenate, Final, ParamSpec, Protocol, TypeVar
from urllib.parse import urlsplit

from .canonical import CanonicalError, b64url, canonical_bytes, digest, unb64url

MAX_SAFE_INTEGER: Final = 2**53 - 1
MAX_CONTENT_BYTES: Final = 67_108_864
MAX_EVIDENCE_ENTRIES: Final = 256
MAX_PROVENANCE_NODES: Final = 256
MAX_PROVENANCE_EDGES: Final = 512
MAX_AUTHORS: Final = 64
MAX_AUTHOR_EVIDENCE: Final = 64
MAX_REASON_CODES: Final = 64
MAX_CURSOR_ROWS: Final = 4096
MAX_CURSOR_PAGES: Final = 16
MAX_CURSOR_PAGE_ROWS: Final = 256
MAX_SOURCE_GRAPH_DEPTH: Final = 64
MAX_BUNDLE_DECOMPRESSED_BYTES: Final = 536_870_912
BUSY_TIMEOUT_MS: Final = 30_000

CLAIM_EVENT_KIND: Final = "matrix/source-claim"
ASSESSMENT_EVENT_KIND: Final = "matrix/source-assessment"
PUBLICATION_EVENT_KIND: Final = "matrix/source-publication"
CURSOR_EVENT_KIND: Final = "matrix/source-cursor"
IMPORT_EVENT_KIND: Final = "matrix/source-import-decision"
SOURCE_EVENT_KINDS: Final = frozenset(
    {
        CLAIM_EVENT_KIND,
        ASSESSMENT_EVENT_KIND,
        PUBLICATION_EVENT_KIND,
        CURSOR_EVENT_KIND,
        IMPORT_EVENT_KIND,
    }
)

SOURCE_CORE_SCHEMA: Final = "daimon-source-core/v0"
CLAIM_SCHEMA: Final = "daimon-source-claim/v0"
EVIDENCE_SCHEMA: Final = "daimon-source-evidence-manifest/v0"
ASSESSMENT_SCHEMA: Final = "daimon-source-assessment/v0"
SNAPSHOT_SCHEMA: Final = "daimon-source-policy-evidence-snapshot/v0"
PUBLICATION_SCHEMA: Final = "daimon-source-publication/v0"
PROVENANCE_SCHEMA: Final = "daimon-source-provenance-manifest/v0"
CURSOR_SCHEMA: Final = "daimon-source-cursor/v0"
CURSOR_PAGE_SCHEMA: Final = "daimon-source-cursor-page/v0"
IMPORT_SCHEMA: Final = "daimon-source-import-decision/v0"
PROMOTION_POLICY_SCHEMA: Final = "daimon-source-promotion-policy/v0"

SOURCE_KINDS: Final = frozenset(
    {"collective", "corpus", "person", "project", "tradition", "other"}
)
RELATIONS: Final = frozenset(
    {
        "created-by",
        "descended-from",
        "derived-from",
        "formed-in",
        "influenced-by",
        "trained-on",
        "participates-in",
    }
)
EVIDENCE_ROLES: Final = frozenset(
    {"corroborates", "context", "contradicts", "derivation"}
)
EVIDENCE_ASSERTIONS: Final = frozenset(
    {
        "cryptographically-authored",
        "publisher-declared",
        "external-metadata",
        "unattributed",
    }
)
DISPOSITIONS: Final = frozenset({"admitted", "quarantined", "rejected"})
CLASSIFICATIONS: Final = frozenset({"public", "tribe-shared"})
AUTHOR_ASSERTIONS: Final = frozenset(
    {"cryptographic", "publisher-declared", "source-metadata", "unattributed"}
)
IMPORT_DECISIONS: Final = frozenset({"quarantined", "promoted", "rejected"})

_SOURCE_ID = re.compile(r"^dm:source:v0:[A-Za-z0-9_-]{43}$")
_CONTENT_ID = re.compile(r"^dm:source-content:v0:[A-Za-z0-9_-]{43}$")
_CLAIM_SERIES_ID = re.compile(r"^dm:source-claim-series:v0:[A-Za-z0-9_-]{43}$")
_ASSESSMENT_SERIES_ID = re.compile(
    r"^dm:source-assessment-series:v0:[A-Za-z0-9_-]{43}$"
)
_PUBLICATION_ID = re.compile(r"^dm:source-publication:v0:[A-Za-z0-9_-]{43}$")
_IMPORT_SERIES_ID = re.compile(r"^dm:source-import-series:v0:[A-Za-z0-9_-]{43}$")
_REASON_CODE = re.compile(r"^[a-z][a-z0-9-]{0,62}:[a-z][a-z0-9-]{0,62}$")
_PRINTABLE_ASCII = re.compile(r"^[\x20-\x7e]+$")
_HEX_HASH = re.compile(r"^[0-9a-f]{64}$")


class SourceError(ValueError):
    """A DM-015 object or local source transition failed closed."""

    def __init__(
        self, code: str, *, incomplete: bool = False, retryable: bool = False
    ) -> None:
        super().__init__(code)
        self.code = code
        self.incomplete = incomplete
        self.retryable = retryable


def _assert_source_graph_depth(value: Any, code: str, *, depth: int = 0) -> None:
    """Reject over-deep source input before recursive canonicalization.

    JSON scalar leaves do not add graph depth.  The root container is depth
    zero, so exactly 64 nested containers are accepted and a 65th is refused
    before JCS, hashing, storage, or any other effect.
    """

    if isinstance(value, Mapping):
        if depth > MAX_SOURCE_GRAPH_DEPTH:
            raise SourceError(code)
        for item in value.values():
            _assert_source_graph_depth(item, code, depth=depth + 1)
    elif isinstance(value, Sequence) and not isinstance(
        value, (str, bytes, bytearray, memoryview)
    ):
        if depth > MAX_SOURCE_GRAPH_DEPTH:
            raise SourceError(code)
        for item in value:
            _assert_source_graph_depth(item, code, depth=depth + 1)


def _canonical(value: Any, code: str) -> bytes:
    _assert_source_graph_depth(value, code)
    try:
        return canonical_bytes(value)
    except CanonicalError as exception:
        raise SourceError(code) from exception


def _closed(value: Any, fields: set[str], code: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise SourceError(code)
    _canonical(value, code)
    return value


def _uint(value: Any, code: str, minimum: int = 0) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not minimum <= value <= MAX_SAFE_INTEGER
    ):
        raise SourceError(code)
    return value


def _text(value: Any, code: str, maximum: int, *, ascii_only: bool = False) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value.encode("utf-8")) <= maximum
        or (ascii_only and _PRINTABLE_ASCII.fullmatch(value) is None)
    ):
        raise SourceError(code)
    _canonical(value, code)
    return value


def _me_id(value: Any, code: str = "invalid_source_me_id") -> str:
    return _text(value, code, 240)


def _uuid(value: Any, code: str) -> str:
    if not isinstance(value, str):
        raise SourceError(code)
    try:
        parsed = uuid.UUID(value)
    except ValueError as exception:
        raise SourceError(code) from exception
    if str(parsed) != value:
        raise SourceError(code)
    return value


def _event_hash(value: Any, code: str) -> str:
    if not isinstance(value, str) or _HEX_HASH.fullmatch(value) is None:
        raise SourceError(code)
    return value


def _hash43(value: Any, code: str) -> str:
    if not isinstance(value, str):
        raise SourceError(code)
    try:
        unb64url(value, length=32)
    except CanonicalError as exception:
        raise SourceError(code) from exception
    return value


def _typed_id(value: Any, pattern: re.Pattern[str], code: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise SourceError(code)
    _hash43(value.rsplit(":", 1)[1], code)
    return value


def _sorted_unique_strings(
    value: Any,
    code: str,
    *,
    minimum: int = 0,
    maximum: int,
    allowed: frozenset[str] | None = None,
) -> list[str]:
    if (
        not isinstance(value, list)
        or not minimum <= len(value) <= maximum
        or value != sorted(set(value))
    ):
        raise SourceError(code)
    for item in value:
        _text(item, code, 128, ascii_only=True)
        if allowed is not None and item not in allowed:
            raise SourceError(code)
    return list(value)


def _derived(prefix: str, domain: str, body: Mapping[str, Any]) -> str:
    return prefix + b64url(digest(domain, body))


def validate_source_core(value: Any) -> dict[str, str]:
    """Validate a source name as inert byte-exact data, never as a locator."""

    row = _closed(
        value,
        {"canonical_reference", "kind", "namespace", "schema"},
        "invalid_source_core",
    )
    if row["schema"] != SOURCE_CORE_SCHEMA or row["kind"] not in SOURCE_KINDS:
        raise SourceError("invalid_source_core")
    namespace = _text(row["namespace"], "invalid_source_core", 128, ascii_only=True)
    reference = _text(
        row["canonical_reference"], "invalid_source_core", 512, ascii_only=True
    )
    for text in (namespace, reference):
        if (
            "\\" in text
            or "@" in text
            or any(character.isspace() for character in text)
        ):
            raise SourceError("unsafe_source_core")
    lowered = reference.lower()
    if any(marker in lowered for marker in ("password=", "token=", "secret=")):
        raise SourceError("unsafe_source_core")
    return copy.deepcopy(dict(row))


def source_id(source_core: Mapping[str, Any]) -> str:
    core = validate_source_core(source_core)
    return _derived("dm:source:v0:", "daimon/source-id/v0", core)


def source_selector(source_core: Mapping[str, Any]) -> dict[str, str]:
    identifier = source_id(source_core)
    return {
        "source_core_hash": identifier.rsplit(":", 1)[1],
        "source_id": identifier,
    }


def validate_source_selector(value: Any) -> dict[str, str]:
    row = _closed(value, {"source_core_hash", "source_id"}, "invalid_source_selector")
    identifier = _typed_id(row["source_id"], _SOURCE_ID, "invalid_source_selector")
    suffix = _hash43(row["source_core_hash"], "invalid_source_selector")
    if identifier.rsplit(":", 1)[1] != suffix:
        raise SourceError("source_selector_mismatch")
    return copy.deepcopy(dict(row))


def source_content_ref(raw: bytes, media_type: str) -> dict[str, Any]:
    if not isinstance(raw, bytes) or len(raw) > MAX_CONTENT_BYTES:
        raise SourceError("source_content_size")
    media = _text(media_type, "invalid_source_media_type", 128, ascii_only=True)
    content_hash = b64url(hashlib.sha256(raw).digest())
    return {
        "byte_length": len(raw),
        "content_id": f"dm:source-content:v0:{content_hash}",
        "media_type": media,
        "sha256": content_hash,
    }


def validate_content_ref(value: Any) -> dict[str, Any]:
    row = _closed(
        value,
        {"byte_length", "content_id", "media_type", "sha256"},
        "invalid_source_content_ref",
    )
    content_id = _typed_id(row["content_id"], _CONTENT_ID, "invalid_source_content_ref")
    content_hash = _hash43(row["sha256"], "invalid_source_content_ref")
    if content_id.rsplit(":", 1)[1] != content_hash:
        raise SourceError("source_content_id_mismatch")
    _text(row["media_type"], "invalid_source_content_ref", 128, ascii_only=True)
    length = _uint(row["byte_length"], "invalid_source_content_ref")
    if length > MAX_CONTENT_BYTES:
        raise SourceError("source_content_size")
    return copy.deepcopy(dict(row))


def verify_content(reference: Mapping[str, Any], raw: bytes) -> None:
    expected = validate_content_ref(reference)
    if (
        not isinstance(raw, bytes)
        or len(raw) != expected["byte_length"]
        or b64url(hashlib.sha256(raw).digest()) != expected["sha256"]
    ):
        raise SourceError("source_content_mismatch")


def validate_artifact_ref(value: Any) -> dict[str, str]:
    row = _closed(
        value,
        {"artifact_domain", "artifact_hash", "artifact_id"},
        "invalid_source_artifact_ref",
    )
    for field in ("artifact_domain", "artifact_hash", "artifact_id"):
        _text(row[field], "invalid_source_artifact_ref", 256, ascii_only=True)
    return copy.deepcopy(dict(row))


def claim_series_id(claimant_me_id: str, source_identifier: str) -> str:
    return _derived(
        "dm:source-claim-series:v0:",
        "daimon/source-claim-series/v0",
        {
            "claimant_me_id": _me_id(claimant_me_id),
            "source_id": _typed_id(source_identifier, _SOURCE_ID, "invalid_source_id"),
        },
    )


def assessment_series_id(assessor_me_id: str, claim_series: str) -> str:
    return _derived(
        "dm:source-assessment-series:v0:",
        "daimon/source-assessment-series/v0",
        {
            "assessor_me_id": _me_id(assessor_me_id),
            "claim_series_id": _typed_id(
                claim_series, _CLAIM_SERIES_ID, "invalid_claim_series_id"
            ),
        },
    )


def publication_id(publisher_me_id: str, source_uri: str) -> str:
    return _derived(
        "dm:source-publication:v0:",
        "daimon/source-publication-id/v0",
        {
            "publisher_me_id": _me_id(publisher_me_id),
            "source_uri": validate_source_uri(source_uri),
        },
    )


def import_series_id(receiver_me_id: str, publication: str) -> str:
    return _derived(
        "dm:source-import-series:v0:",
        "daimon/source-import-decision-series/v0",
        {
            "publication_id": _typed_id(
                publication, _PUBLICATION_ID, "invalid_publication_id"
            ),
            "receiver_me_id": _me_id(receiver_me_id),
        },
    )


def validate_control_position(value: Any) -> dict[str, str]:
    row = _closed(
        value,
        {"embodiment_id", "incarnation_id", "manifest_hash"},
        "invalid_source_control_position",
    )
    _event_hash(row["manifest_hash"], "invalid_source_control_position")
    for field in ("embodiment_id", "incarnation_id"):
        _text(row[field], "invalid_source_control_position", 240)
    return copy.deepcopy(dict(row))


def source_claim_binding_hash(payload: Mapping[str, Any]) -> str:
    fields = {
        "action",
        "claim_sequence",
        "claim_series_id",
        "claimant_control_position",
        "claimant_me_id",
        "expires_at_ms",
        "issued_at_ms",
        "previous_claim_event_hash",
        "previous_claim_event_id",
        "relations",
        "schema",
        "source_core",
        "source_id",
    }
    if not isinstance(payload, Mapping) or set(payload) != fields | {
        "evidence_manifest_ref"
    }:
        raise SourceError("invalid_source_claim")
    body = {key: copy.deepcopy(payload[key]) for key in fields}
    return b64url(digest("daimon/source-claim-binding/v0", body))


def publication_binding_hash(payload: Mapping[str, Any]) -> str:
    fields = {
        "action",
        "classification",
        "consent",
        "content_ref",
        "issued_at_ms",
        "license",
        "previous_publication_event_hash",
        "previous_publication_event_id",
        "publication_id",
        "publication_sequence",
        "publisher_claim_event_id",
        "publisher_me_id",
        "reason",
        "schema",
        "source_id",
        "source_uri",
    }
    if not isinstance(payload, Mapping) or set(payload) != fields | {
        "provenance_manifest_ref"
    }:
        raise SourceError("invalid_source_publication")
    body = {key: copy.deepcopy(payload[key]) for key in fields}
    return b64url(digest("daimon/source-publication-binding/v0", body))


def validate_claim_payload(value: Any) -> dict[str, Any]:
    fields = {
        "action",
        "claim_sequence",
        "claim_series_id",
        "claimant_control_position",
        "claimant_me_id",
        "evidence_manifest_ref",
        "expires_at_ms",
        "issued_at_ms",
        "previous_claim_event_hash",
        "previous_claim_event_id",
        "relations",
        "schema",
        "source_core",
        "source_id",
    }
    row = _closed(value, fields, "invalid_source_claim")
    if row["schema"] != CLAIM_SCHEMA or row["action"] not in {"assert", "retract"}:
        raise SourceError("invalid_source_claim")
    core = validate_source_core(row["source_core"])
    identifier = _typed_id(row["source_id"], _SOURCE_ID, "invalid_source_id")
    if identifier != source_id(core):
        raise SourceError("source_id_mismatch")
    claimant = _me_id(row["claimant_me_id"])
    series = _typed_id(
        row["claim_series_id"], _CLAIM_SERIES_ID, "invalid_claim_series_id"
    )
    if series != claim_series_id(claimant, identifier):
        raise SourceError("claim_series_id_mismatch")
    validate_control_position(row["claimant_control_position"])
    sequence = _uint(row["claim_sequence"], "invalid_claim_sequence")
    predecessor_id = row["previous_claim_event_id"]
    predecessor_hash = row["previous_claim_event_hash"]
    if sequence == 0:
        if predecessor_id is not None or predecessor_hash is not None:
            raise SourceError("unexpected_claim_predecessor")
    else:
        _uuid(predecessor_id, "invalid_claim_predecessor")
        _event_hash(predecessor_hash, "invalid_claim_predecessor")
    _sorted_unique_strings(
        row["relations"],
        "invalid_source_relations",
        minimum=1,
        maximum=64,
        allowed=RELATIONS,
    )
    issued = _uint(row["issued_at_ms"], "invalid_claim_time")
    expires = row["expires_at_ms"]
    if expires is not None and _uint(expires, "invalid_claim_time", 1) <= issued:
        raise SourceError("invalid_claim_time")
    evidence = row["evidence_manifest_ref"]
    if row["action"] == "assert":
        if evidence is None:
            raise SourceError("claim_evidence_required")
        validate_content_ref(evidence)
    elif evidence is not None:
        raise SourceError("retraction_evidence_forbidden")
    return copy.deepcopy(dict(row))


def validate_evidence_manifest(value: Any, claim: Mapping[str, Any]) -> dict[str, Any]:
    row = _closed(
        value,
        {"claim_binding_hash", "entries", "schema"},
        "invalid_source_evidence_manifest",
    )
    if row["schema"] != EVIDENCE_SCHEMA:
        raise SourceError("invalid_source_evidence_manifest")
    if _hash43(
        row["claim_binding_hash"], "invalid_claim_binding_hash"
    ) != source_claim_binding_hash(claim):
        raise SourceError("claim_binding_hash_mismatch")
    entries = row["entries"]
    if not isinstance(entries, list) or not 1 <= len(entries) <= MAX_EVIDENCE_ENTRIES:
        raise SourceError("invalid_source_evidence_entries")
    markers: list[tuple[str, str, str]] = []
    for value_entry in entries:
        entry = _closed(
            value_entry,
            {
                "artifact",
                "assertion",
                "content",
                "evidence_id",
                "issuer_me_id",
                "kind",
                "role",
            },
            "invalid_source_evidence_entry",
        )
        if (
            entry["kind"] not in {"daimon-artifact", "content"}
            or entry["role"] not in EVIDENCE_ROLES
            or entry["assertion"] not in EVIDENCE_ASSERTIONS
        ):
            raise SourceError("invalid_source_evidence_entry")
        if entry["kind"] == "content":
            if entry["artifact"] is not None or entry["content"] is None:
                raise SourceError("invalid_source_evidence_entry")
            reference = validate_content_ref(entry["content"])
            expected_id = reference["content_id"]
        else:
            if entry["content"] is not None or entry["artifact"] is None:
                raise SourceError("invalid_source_evidence_entry")
            reference = validate_artifact_ref(entry["artifact"])
            expected_id = reference["artifact_id"]
        if entry["evidence_id"] != expected_id:
            raise SourceError("source_evidence_id_mismatch")
        issuer = entry["issuer_me_id"]
        if issuer is not None:
            _me_id(issuer)
        if entry["assertion"] == "cryptographically-authored" and (
            issuer is None or entry["kind"] != "daimon-artifact"
        ):
            raise SourceError("cryptographic_evidence_proof_required")
        markers.append((entry["evidence_id"], entry["role"], entry["assertion"]))
    if markers != sorted(set(markers)):
        raise SourceError("source_evidence_entries_not_sorted")
    return copy.deepcopy(dict(row))


def _refs(value: Any, code: str, *, artifacts: bool) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > MAX_EVIDENCE_ENTRIES:
        raise SourceError(code)
    rows = [
        validate_artifact_ref(item) if artifacts else validate_content_ref(item)
        for item in value
    ]
    encoded = [_canonical(item, code) for item in rows]
    if encoded != sorted(set(encoded)):
        raise SourceError(code)
    return rows


def validate_policy_snapshot(value: Any) -> dict[str, Any]:
    row = _closed(
        value,
        {
            "artifact_refs",
            "claim_event_ids",
            "content_refs",
            "contradiction_refs",
            "observed_cursor_event_hash",
            "observed_cursor_event_id",
            "schema",
            "source_id",
            "subject",
        },
        "invalid_source_policy_snapshot",
    )
    if row["schema"] != SNAPSHOT_SCHEMA:
        raise SourceError("invalid_source_policy_snapshot")
    _typed_id(row["source_id"], _SOURCE_ID, "invalid_source_policy_snapshot")
    subject = _closed(
        row["subject"],
        {"event_hash", "event_id", "id", "kind"},
        "invalid_source_policy_subject",
    )
    if subject["kind"] not in {"claim", "publication"}:
        raise SourceError("invalid_source_policy_subject")
    _uuid(subject["event_id"], "invalid_source_policy_subject")
    _event_hash(subject["event_hash"], "invalid_source_policy_subject")
    if subject["kind"] == "claim":
        _typed_id(subject["id"], _CLAIM_SERIES_ID, "invalid_source_policy_subject")
    else:
        _typed_id(subject["id"], _PUBLICATION_ID, "invalid_source_policy_subject")
    claim_ids = row["claim_event_ids"]
    if (
        not isinstance(claim_ids, list)
        or len(claim_ids) > MAX_CURSOR_ROWS
        or claim_ids != sorted(set(claim_ids))
    ):
        raise SourceError("invalid_source_policy_claims")
    for event_id in claim_ids:
        _uuid(event_id, "invalid_source_policy_claims")
    _refs(row["artifact_refs"], "invalid_source_policy_artifacts", artifacts=True)
    _refs(row["content_refs"], "invalid_source_policy_content", artifacts=False)
    contradictions = row["contradiction_refs"]
    if (
        not isinstance(contradictions, list)
        or len(contradictions) > MAX_EVIDENCE_ENTRIES
    ):
        raise SourceError("invalid_source_policy_contradictions")
    normalized: list[dict[str, Any]] = []
    for item in contradictions:
        if isinstance(item, Mapping) and set(item) == {
            "artifact_domain",
            "artifact_hash",
            "artifact_id",
        }:
            normalized.append(validate_artifact_ref(item))
        else:
            normalized.append(validate_content_ref(item))
    encoded = [
        _canonical(item, "invalid_source_policy_contradictions") for item in normalized
    ]
    if encoded != sorted(set(encoded)):
        raise SourceError("invalid_source_policy_contradictions")
    _uuid(row["observed_cursor_event_id"], "invalid_source_cursor_reference")
    _event_hash(row["observed_cursor_event_hash"], "invalid_source_cursor_reference")
    return copy.deepcopy(dict(row))


def validate_assessment_payload(value: Any) -> dict[str, Any]:
    fields = {
        "assessment_sequence",
        "assessment_series_id",
        "assessor_me_id",
        "claim_event_hash",
        "claim_event_id",
        "claimant_me_id",
        "decided_at_ms",
        "disposition",
        "evidence_manifest_ref",
        "evidence_snapshot_ref",
        "policy_ref",
        "previous_assessment_event_id",
        "reason_codes",
        "schema",
        "source_id",
    }
    row = _closed(value, fields, "invalid_source_assessment")
    if row["schema"] != ASSESSMENT_SCHEMA or row["disposition"] not in DISPOSITIONS:
        raise SourceError("invalid_source_assessment")
    assessor = _me_id(row["assessor_me_id"])
    claimant = _me_id(row["claimant_me_id"])
    source_identifier = _typed_id(row["source_id"], _SOURCE_ID, "invalid_source_id")
    claim_series = claim_series_id(claimant, source_identifier)
    series = _typed_id(
        row["assessment_series_id"],
        _ASSESSMENT_SERIES_ID,
        "invalid_assessment_series_id",
    )
    if series != assessment_series_id(assessor, claim_series):
        raise SourceError("assessment_series_id_mismatch")
    sequence = _uint(row["assessment_sequence"], "invalid_assessment_sequence")
    if sequence == 0:
        if row["previous_assessment_event_id"] is not None:
            raise SourceError("unexpected_assessment_predecessor")
    else:
        _uuid(row["previous_assessment_event_id"], "invalid_assessment_predecessor")
    _uuid(row["claim_event_id"], "invalid_assessment_claim")
    _event_hash(row["claim_event_hash"], "invalid_assessment_claim")
    for field in ("evidence_manifest_ref", "evidence_snapshot_ref", "policy_ref"):
        validate_content_ref(row[field])
    _sorted_unique_strings(
        row["reason_codes"],
        "invalid_source_reason_codes",
        minimum=1,
        maximum=MAX_REASON_CODES,
    )
    for reason in row["reason_codes"]:
        if _REASON_CODE.fullmatch(reason) is None:
            raise SourceError("invalid_source_reason_codes")
    _uint(row["decided_at_ms"], "invalid_assessment_time")
    return copy.deepcopy(dict(row))


def validate_source_uri(value: Any) -> str:
    uri = _text(value, "invalid_source_uri", 512, ascii_only=True)
    if "\\" in uri or "#" in uri or any(character.isspace() for character in uri):
        raise SourceError("invalid_source_uri")
    parsed = urlsplit(uri)
    if (
        not parsed.scheme
        or parsed.fragment
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise SourceError("invalid_source_uri")
    return uri


def validate_publication_payload(value: Any) -> dict[str, Any]:
    fields = {
        "action",
        "classification",
        "consent",
        "content_ref",
        "issued_at_ms",
        "license",
        "previous_publication_event_hash",
        "previous_publication_event_id",
        "provenance_manifest_ref",
        "publication_id",
        "publication_sequence",
        "publisher_claim_event_id",
        "publisher_me_id",
        "reason",
        "schema",
        "source_id",
        "source_uri",
    }
    row = _closed(value, fields, "invalid_source_publication")
    if row["schema"] != PUBLICATION_SCHEMA or row["action"] not in {
        "publish",
        "tombstone",
    }:
        raise SourceError("invalid_source_publication")
    publisher = _me_id(row["publisher_me_id"])
    uri = validate_source_uri(row["source_uri"])
    identifier = _typed_id(
        row["publication_id"], _PUBLICATION_ID, "invalid_publication_id"
    )
    if identifier != publication_id(publisher, uri):
        raise SourceError("publication_id_mismatch")
    _typed_id(row["source_id"], _SOURCE_ID, "invalid_source_id")
    _uuid(row["publisher_claim_event_id"], "invalid_publication_claim")
    sequence = _uint(row["publication_sequence"], "invalid_publication_sequence")
    if sequence == 0:
        if (
            row["previous_publication_event_id"] is not None
            or row["previous_publication_event_hash"] is not None
        ):
            raise SourceError("unexpected_publication_predecessor")
    else:
        _uuid(row["previous_publication_event_id"], "invalid_publication_predecessor")
        _event_hash(
            row["previous_publication_event_hash"], "invalid_publication_predecessor"
        )
    if row["action"] == "publish":
        if (
            row["classification"] not in CLASSIFICATIONS
            or row["consent"] != "explicit"
            or row["reason"] is not None
        ):
            raise SourceError("invalid_publication_export_policy")
        validate_content_ref(row["content_ref"])
        validate_content_ref(row["provenance_manifest_ref"])
        _text(row["license"], "invalid_publication_license", 128, ascii_only=True)
    else:
        if any(
            row[field] is not None
            for field in (
                "classification",
                "consent",
                "content_ref",
                "provenance_manifest_ref",
                "license",
            )
        ):
            raise SourceError("invalid_publication_tombstone")
        _text(row["reason"], "invalid_publication_tombstone", 1024)
    _uint(row["issued_at_ms"], "invalid_publication_time")
    return copy.deepcopy(dict(row))


def provenance_node_id(node: Mapping[str, Any]) -> str:
    fields = {"authors", "content_ref", "kind", "source_uri"}
    if not isinstance(node, Mapping) or set(node) != fields | {"node_id"}:
        raise SourceError("invalid_provenance_node")
    return _derived(
        "dm:source-provenance-node:v0:",
        "daimon/source-provenance-node/v0",
        {field: copy.deepcopy(node[field]) for field in fields},
    )


def validate_provenance_manifest(
    value: Any, publication: Mapping[str, Any]
) -> dict[str, Any]:
    published = validate_publication_payload(publication)
    if published["action"] != "publish":
        raise SourceError("provenance_requires_publication")
    row = _closed(
        value,
        {"edges", "nodes", "output_node_id", "publication_binding_hash", "schema"},
        "invalid_source_provenance",
    )
    if row["schema"] != PROVENANCE_SCHEMA or _hash43(
        row["publication_binding_hash"], "invalid_publication_binding_hash"
    ) != publication_binding_hash(published):
        raise SourceError("publication_binding_hash_mismatch")
    nodes = row["nodes"]
    if not isinstance(nodes, list) or not 1 <= len(nodes) <= MAX_PROVENANCE_NODES:
        raise SourceError("invalid_provenance_nodes")
    node_ids: list[str] = []
    node_by_id: dict[str, Mapping[str, Any]] = {}
    for value_node in nodes:
        node = _closed(
            value_node,
            {"authors", "content_ref", "kind", "node_id", "source_uri"},
            "invalid_provenance_node",
        )
        if node["kind"] not in {"original", "derivation"}:
            raise SourceError("invalid_provenance_node")
        validate_content_ref(node["content_ref"])
        validate_source_uri(node["source_uri"])
        authors = node["authors"]
        if not isinstance(authors, list) or not 1 <= len(authors) <= MAX_AUTHORS:
            raise SourceError("invalid_provenance_authors")
        author_markers: list[bytes] = []
        for value_author in authors:
            author = _closed(
                value_author,
                {"assertion", "evidence_refs", "subject_id", "subject_kind"},
                "invalid_provenance_author",
            )
            if (
                author["subject_kind"] not in {"me", "external"}
                or author["assertion"] not in AUTHOR_ASSERTIONS
            ):
                raise SourceError("invalid_provenance_author")
            _text(author["subject_id"], "invalid_provenance_author", 240)
            _refs(author["evidence_refs"], "invalid_provenance_author", artifacts=True)
            if author["assertion"] == "cryptographic" and (
                author["subject_kind"] != "me" or not author["evidence_refs"]
            ):
                raise SourceError("invalid_cryptographic_author")
            author_markers.append(_canonical(author, "invalid_provenance_author"))
        if author_markers != sorted(set(author_markers)):
            raise SourceError("provenance_authors_not_sorted")
        node_id = _text(
            node["node_id"], "invalid_provenance_node", 160, ascii_only=True
        )
        if node_id != provenance_node_id(node):
            raise SourceError("provenance_node_id_mismatch")
        node_ids.append(node_id)
        node_by_id[node_id] = node
    if node_ids != sorted(set(node_ids)):
        raise SourceError("provenance_nodes_not_sorted")
    output_id = _text(
        row["output_node_id"], "invalid_provenance_output", 160, ascii_only=True
    )
    output = node_by_id.get(output_id)
    if (
        output is None
        or output["content_ref"] != published["content_ref"]
        or output["source_uri"] != published["source_uri"]
    ):
        raise SourceError("provenance_output_mismatch")
    edges = row["edges"]
    if not isinstance(edges, list) or len(edges) > MAX_PROVENANCE_EDGES:
        raise SourceError("invalid_provenance_edges")
    edge_markers: list[bytes] = []
    outgoing: dict[str, set[str]] = {node_id: set() for node_id in node_ids}
    incoming: dict[str, int] = {node_id: 0 for node_id in node_ids}
    for value_edge in edges:
        edge = _closed(
            value_edge,
            {"from_node_id", "relation", "to_node_id", "transformation_ref"},
            "invalid_provenance_edge",
        )
        if (
            edge["relation"] != "derived-from"
            or edge["from_node_id"] not in node_by_id
            or edge["to_node_id"] not in node_by_id
            or edge["from_node_id"] == edge["to_node_id"]
        ):
            raise SourceError("invalid_provenance_edge")
        if edge["transformation_ref"] is not None:
            validate_content_ref(edge["transformation_ref"])
        outgoing[edge["from_node_id"]].add(edge["to_node_id"])
        incoming[edge["to_node_id"]] += 1
        edge_markers.append(_canonical(edge, "invalid_provenance_edge"))
    if edge_markers != sorted(set(edge_markers)):
        raise SourceError("provenance_edges_not_sorted")
    if any(
        node_by_id[node_id]["kind"] == "derivation" and incoming[node_id] == 0
        for node_id in node_ids
    ):
        raise SourceError("provenance_derivation_without_input")
    if any(
        incoming[node_id] == 0 and node_by_id[node_id]["kind"] != "original"
        for node_id in node_ids
    ):
        raise SourceError("provenance_root_not_original")
    visiting: set[str] = set()
    visited: set[str] = set()

    def reject_cycle(node_id: str) -> None:
        if node_id in visiting:
            raise SourceError("provenance_cycle")
        if node_id in visited:
            return
        visiting.add(node_id)
        for child in outgoing[node_id]:
            reject_cycle(child)
        visiting.remove(node_id)
        visited.add(node_id)

    for node_id in node_ids:
        reject_cycle(node_id)

    reaches_cache: dict[str, bool] = {}

    def reaches_output(node_id: str) -> bool:
        if node_id == output_id:
            return True
        if node_id in reaches_cache:
            return reaches_cache[node_id]
        reached = any(reaches_output(child) for child in outgoing[node_id])
        reaches_cache[node_id] = reached
        return reached

    if any(not reaches_output(node_id) for node_id in node_ids):
        raise SourceError("provenance_disconnected")
    return copy.deepcopy(dict(row))


def _validate_page_summary(value: Any) -> dict[str, Any]:
    row = _closed(
        value,
        {"first_page_ref", "page_count", "row_count"},
        "invalid_source_cursor_pages",
    )
    pages = _uint(row["page_count"], "invalid_source_cursor_pages")
    rows = _uint(row["row_count"], "invalid_source_cursor_pages")
    if (
        pages > MAX_CURSOR_PAGES
        or rows > MAX_CURSOR_ROWS
        or (rows == 0) != (pages == 0)
        or (rows == 0) != (row["first_page_ref"] is None)
    ):
        raise SourceError("invalid_source_cursor_pages")
    if row["first_page_ref"] is not None:
        validate_content_ref(row["first_page_ref"])
    return copy.deepcopy(dict(row))


def validate_cursor_payload(value: Any) -> dict[str, Any]:
    row = _closed(
        value,
        {
            "claim_pages",
            "created_at_ms",
            "identity_control_position",
            "observer_me_id",
            "publication_pages",
            "schema",
            "snapshot_hash",
            "source_id",
        },
        "invalid_source_cursor",
    )
    if row["schema"] != CURSOR_SCHEMA:
        raise SourceError("invalid_source_cursor")
    _me_id(row["observer_me_id"])
    _typed_id(row["source_id"], _SOURCE_ID, "invalid_source_id")
    validate_control_position(row["identity_control_position"])
    _validate_page_summary(row["claim_pages"])
    _validate_page_summary(row["publication_pages"])
    _hash43(row["snapshot_hash"], "invalid_source_cursor_hash")
    _uint(row["created_at_ms"], "invalid_source_cursor_time")
    return copy.deepcopy(dict(row))


def validate_cursor_page(value: Any) -> dict[str, Any]:
    row = _closed(
        value,
        {"kind", "next_page_ref", "page_index", "rows", "schema", "source_id"},
        "invalid_source_cursor_page",
    )
    if row["schema"] != CURSOR_PAGE_SCHEMA or row["kind"] not in {
        "claim",
        "publication",
    }:
        raise SourceError("invalid_source_cursor_page")
    _typed_id(row["source_id"], _SOURCE_ID, "invalid_source_id")
    _uint(row["page_index"], "invalid_source_cursor_page")
    rows = row["rows"]
    if not isinstance(rows, list) or not 1 <= len(rows) <= MAX_CURSOR_PAGE_ROWS:
        raise SourceError("invalid_source_cursor_rows")
    series_ids: list[str] = []
    for value_item in rows:
        if row["kind"] == "claim":
            item = _closed(
                value_item,
                {
                    "claim_series_id",
                    "claimant_me_id",
                    "event_hash",
                    "event_id",
                    "sequence",
                    "state",
                },
                "invalid_source_cursor_row",
            )
            _me_id(item["claimant_me_id"])
            series_ids.append(
                _typed_id(
                    item["claim_series_id"],
                    _CLAIM_SERIES_ID,
                    "invalid_source_cursor_row",
                )
            )
            if item["state"] not in {"asserted", "retracted", "forked"}:
                raise SourceError("invalid_source_cursor_row")
        else:
            item = _closed(
                value_item,
                {
                    "event_hash",
                    "event_id",
                    "publication_id",
                    "publisher_me_id",
                    "sequence",
                    "state",
                },
                "invalid_source_cursor_row",
            )
            _me_id(item["publisher_me_id"])
            series_ids.append(
                _typed_id(
                    item["publication_id"], _PUBLICATION_ID, "invalid_source_cursor_row"
                )
            )
            if item["state"] not in {"published", "tombstoned", "forked"}:
                raise SourceError("invalid_source_cursor_row")
        _uint(item["sequence"], "invalid_source_cursor_row")
        _uuid(item["event_id"], "invalid_source_cursor_row")
        _event_hash(item["event_hash"], "invalid_source_cursor_row")
    if series_ids != sorted(set(series_ids)):
        raise SourceError("source_cursor_rows_not_sorted")
    if row["next_page_ref"] is not None:
        validate_content_ref(row["next_page_ref"])
    return copy.deepcopy(dict(row))


def validate_import_payload(value: Any) -> dict[str, Any]:
    fields = {
        "content_ref",
        "decided_at_ms",
        "decision",
        "decision_sequence",
        "decision_series_id",
        "evidence_snapshot_ref",
        "policy_ref",
        "previous_decision_event_id",
        "provenance_manifest_ref",
        "publication_event_hash",
        "publication_event_id",
        "publication_id",
        "reason_codes",
        "receiver_me_id",
        "schema",
        "source_claim_event_ids",
        "source_id",
        "target_memory_category",
    }
    row = _closed(value, fields, "invalid_source_import_decision")
    if row["schema"] != IMPORT_SCHEMA or row["decision"] not in IMPORT_DECISIONS:
        raise SourceError("invalid_source_import_decision")
    receiver = _me_id(row["receiver_me_id"])
    publication = _typed_id(
        row["publication_id"], _PUBLICATION_ID, "invalid_publication_id"
    )
    series = _typed_id(
        row["decision_series_id"], _IMPORT_SERIES_ID, "invalid_import_series_id"
    )
    if series != import_series_id(receiver, publication):
        raise SourceError("import_series_id_mismatch")
    sequence = _uint(row["decision_sequence"], "invalid_import_sequence")
    if sequence == 0:
        if (
            row["previous_decision_event_id"] is not None
            or row["decision"] != "quarantined"
        ):
            raise SourceError("invalid_initial_import_decision")
    else:
        _uuid(row["previous_decision_event_id"], "invalid_import_predecessor")
    _uuid(row["publication_event_id"], "invalid_import_publication")
    _event_hash(row["publication_event_hash"], "invalid_import_publication")
    _typed_id(row["source_id"], _SOURCE_ID, "invalid_source_id")
    for field in (
        "content_ref",
        "provenance_manifest_ref",
        "policy_ref",
        "evidence_snapshot_ref",
    ):
        validate_content_ref(row[field])
    claim_ids = row["source_claim_event_ids"]
    if (
        not isinstance(claim_ids, list)
        or not 1 <= len(claim_ids) <= MAX_CURSOR_ROWS
        or claim_ids != sorted(set(claim_ids))
    ):
        raise SourceError("invalid_import_claims")
    for event_id in claim_ids:
        _uuid(event_id, "invalid_import_claims")
    _sorted_unique_strings(
        row["reason_codes"],
        "invalid_source_reason_codes",
        minimum=1,
        maximum=MAX_REASON_CODES,
    )
    for reason in row["reason_codes"]:
        if _REASON_CODE.fullmatch(reason) is None:
            raise SourceError("invalid_source_reason_codes")
    if row["decision"] == "promoted":
        if row["target_memory_category"] != "external-reference":
            raise SourceError("invalid_import_target")
    elif row["target_memory_category"] is not None:
        raise SourceError("invalid_import_target")
    _uint(row["decided_at_ms"], "invalid_import_time")
    return copy.deepcopy(dict(row))


def validate_promotion_policy(value: Any) -> dict[str, Any]:
    """Validate the immutable, exact review/safety gate for one promotion."""

    fields = {
        "classification",
        "consent",
        "content_ref",
        "content_safety_passed",
        "final_render_reviewed",
        "license",
        "provenance_manifest_ref",
        "publication_event_hash",
        "publication_event_id",
        "publication_id",
        "schema",
        "target_memory_category",
    }
    row = _closed(value, fields, "invalid_source_promotion_policy")
    if (
        row["schema"] != PROMOTION_POLICY_SCHEMA
        or row["classification"] not in CLASSIFICATIONS
        or row["consent"] != "explicit"
        or row["content_safety_passed"] is not True
        or row["final_render_reviewed"] is not True
        or row["target_memory_category"] != "external-reference"
    ):
        raise SourceError("invalid_source_promotion_policy")
    _typed_id(row["publication_id"], _PUBLICATION_ID, "invalid_source_promotion_policy")
    _uuid(row["publication_event_id"], "invalid_source_promotion_policy")
    _event_hash(row["publication_event_hash"], "invalid_source_promotion_policy")
    validate_content_ref(row["content_ref"])
    validate_content_ref(row["provenance_manifest_ref"])
    _text(row["license"], "invalid_source_promotion_policy", 128, ascii_only=True)
    return copy.deepcopy(dict(row))


def validate_source_event_payload(
    kind: str,
    payload: Any,
    *,
    author_me_id: str,
    origin: Mapping[str, Any],
    manifest_hash: str,
    causal_parents: Sequence[str],
) -> dict[str, Any]:
    """Bind one source payload to its exact signed DM-011 event author."""

    if kind == CLAIM_EVENT_KIND:
        row = validate_claim_payload(payload)
        author_field = "claimant_me_id"
        position_field = "claimant_control_position"
        predecessor = row["previous_claim_event_id"]
        extra_dependencies: Sequence[str] = ()
    elif kind == ASSESSMENT_EVENT_KIND:
        row = validate_assessment_payload(payload)
        author_field = "assessor_me_id"
        position_field = None
        predecessor = row["previous_assessment_event_id"]
        # The assessed claim may belong to another being's known ledger.  Its
        # exact ID/hash is a semantic cross-ledger reference, not an origin-
        # chain dependency in the assessor's owner-local ledger.
        extra_dependencies = ()
    elif kind == PUBLICATION_EVENT_KIND:
        row = validate_publication_payload(payload)
        author_field = "publisher_me_id"
        position_field = None
        predecessor = row["previous_publication_event_id"]
        extra_dependencies = [row["publisher_claim_event_id"]]
    elif kind == CURSOR_EVENT_KIND:
        row = validate_cursor_payload(payload)
        author_field = "observer_me_id"
        position_field = "identity_control_position"
        predecessor = None
        extra_dependencies = ()
    elif kind == IMPORT_EVENT_KIND:
        row = validate_import_payload(payload)
        author_field = "receiver_me_id"
        position_field = None
        predecessor = row["previous_decision_event_id"]
        # Publications and claims can be foreign-being evidence.  The source
        # registry verifies the exact cross-ledger references before applying
        # this local decision.
        extra_dependencies = ()
    else:
        raise SourceError("unsupported_source_event_kind")
    if row[author_field] != author_me_id:
        raise SourceError("false_source_self")
    if position_field is not None:
        position = row[position_field]
        if (
            position["manifest_hash"] != manifest_hash
            or position["embodiment_id"] != origin.get("embodiment_id")
            or position["incarnation_id"] != origin.get("incarnation_id")
        ):
            raise SourceError("source_control_position_mismatch")
    parents = set(causal_parents)
    if predecessor is not None and predecessor not in parents:
        raise SourceError("source_predecessor_not_causal")
    if any(dependency not in parents for dependency in extra_dependencies):
        raise SourceError("source_dependency_not_causal")
    return row


def _assert_owner_directory(path: Path) -> None:
    if path.is_symlink():
        raise SourceError("source_cas_parent_symlink")
    try:
        info = path.stat()
    except FileNotFoundError as exception:
        raise SourceError("source_cas_parent_missing") from exception
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise SourceError("source_cas_parent_not_owner_only")


def _prepare_private_path(path: Path) -> None:
    missing: list[Path] = []
    candidate = path.parent
    while not candidate.exists():
        if candidate.is_symlink():
            raise SourceError("source_cas_parent_symlink")
        missing.append(candidate)
        if candidate == candidate.parent:
            raise SourceError("source_cas_parent_missing")
        candidate = candidate.parent
    for directory in reversed(missing):
        with suppress(FileExistsError):
            directory.mkdir(mode=0o700)
        _assert_owner_directory(directory)
    _assert_owner_directory(path.parent)
    if path.exists():
        info = path.lstat()
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & 0o077
        ):
            raise SourceError("source_cas_file_not_owner_only")
    else:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        os.close(descriptor)


class SourceCAS:
    """Owner-local exact-byte CAS.  References contain no retrieval hints."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(os.path.abspath(path))

    @contextmanager
    def _database(self) -> Iterator[sqlite3.Connection]:
        _prepare_private_path(self.path)
        database = sqlite3.connect(
            self.path, timeout=BUSY_TIMEOUT_MS / 1000, isolation_level=None
        )
        database.row_factory = sqlite3.Row
        database.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
        mode = database.execute("PRAGMA journal_mode=DELETE").fetchone()[0]
        if str(mode).lower() != "delete":
            database.close()
            raise SourceError("source_cas_journal_mode")
        database.execute("PRAGMA synchronous=FULL")
        try:
            yield database
        finally:
            database.close()

    def initialize(self) -> None:
        with self._database() as database:
            database.executescript(
                "CREATE TABLE IF NOT EXISTS content ("
                "content_id TEXT PRIMARY KEY, media_type TEXT NOT NULL, "
                "byte_length INTEGER NOT NULL, sha256 TEXT NOT NULL, "
                "raw BLOB NOT NULL) WITHOUT ROWID;"
                "CREATE TABLE IF NOT EXISTS source_intake ("
                "operation_id TEXT PRIMARY KEY, bundle_hash TEXT NOT NULL, "
                "preview_hash TEXT NOT NULL, created_at_ms INTEGER NOT NULL, "
                "state TEXT NOT NULL CHECK(state IN "
                "('prepared','blobs','events','decisions','committed')), "
                "result_json BLOB) WITHOUT ROWID;"
            )
        os.chmod(self.path, 0o600)

    def put(self, raw: bytes, media_type: str) -> dict[str, Any]:
        reference = source_content_ref(raw, media_type)
        self.initialize()
        with self._database() as database:
            database.execute("BEGIN IMMEDIATE")
            try:
                existing = database.execute(
                    "SELECT media_type, byte_length, sha256, raw FROM content "
                    "WHERE content_id=?",
                    (reference["content_id"],),
                ).fetchone()
                if existing is None:
                    database.execute(
                        "INSERT INTO content VALUES (?, ?, ?, ?, ?)",
                        (
                            reference["content_id"],
                            reference["media_type"],
                            reference["byte_length"],
                            reference["sha256"],
                            raw,
                        ),
                    )
                elif (
                    existing["media_type"] != reference["media_type"]
                    or int(existing["byte_length"]) != len(raw)
                    or existing["sha256"] != reference["sha256"]
                    or bytes(existing["raw"]) != raw
                ):
                    raise SourceError("source_cas_conflict")
                database.commit()
            except BaseException:
                database.rollback()
                raise
        return reference

    def get(self, reference: Mapping[str, Any]) -> bytes:
        verified = validate_content_ref(reference)
        self.initialize()
        with self._database() as database:
            row = database.execute(
                "SELECT media_type, byte_length, sha256, raw FROM content "
                "WHERE content_id=?",
                (verified["content_id"],),
            ).fetchone()
        if row is None:
            raise SourceError("source_content_missing", incomplete=True)
        raw = bytes(row["raw"])
        if (
            row["media_type"] != verified["media_type"]
            or int(row["byte_length"]) != verified["byte_length"]
            or row["sha256"] != verified["sha256"]
        ):
            raise SourceError("source_cas_metadata_conflict")
        verify_content(verified, raw)
        return raw

    def has(self, reference: Mapping[str, Any]) -> bool:
        try:
            self.get(reference)
        except SourceError as error:
            if error.incomplete:
                return False
            raise
        return True

    def put_json(self, value: Mapping[str, Any], media_type: str) -> dict[str, Any]:
        """Store one strict JCS object without adding a locator or mutable alias."""

        return self.put(_canonical(value, "invalid_source_json"), media_type)

    def get_json(self, reference: Mapping[str, Any]) -> dict[str, Any]:
        raw = self.get(reference)
        try:
            value = json.loads(raw, object_pairs_hook=_unique_object)
        except (UnicodeDecodeError, json.JSONDecodeError) as exception:
            raise SourceError("invalid_source_json") from exception
        if (
            not isinstance(value, Mapping)
            or _canonical(value, "invalid_source_json") != raw
        ):
            raise SourceError("source_json_not_canonical")
        return copy.deepcopy(dict(value))


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SourceError("source_json_duplicate_key")
        result[key] = value
    return result


class ArtifactEvidenceVerifier(Protocol):
    """Validate the complete artifact, including relevant authorship binding."""

    def __call__(self, reference: Mapping[str, Any]) -> bool: ...


class SourceDisclosureAuthorizer(Protocol):
    """Authorize one exact requester/source/classification disclosure."""

    def __call__(
        self, requester_me_id: str, source_identifier: str, classification: str
    ) -> bool: ...


_P = ParamSpec("_P")
_R = TypeVar("_R")


def _serialized_source_operation(
    method: Callable[Concatenate[SourceRegistry, _P], _R],
) -> Callable[Concatenate[SourceRegistry, _P], _R]:
    """Serialize one public SourceRegistry view or transition."""

    @wraps(method)
    def serialized(self: SourceRegistry, *args: _P.args, **kwargs: _P.kwargs) -> _R:
        with self._intake_lock():
            return method(self, *args, **kwargs)

    return serialized  # type: ignore[return-value]


@dataclass(frozen=True)
class SourceServiceContext:
    registry: SourceRegistry


@dataclass(frozen=True)
class _Lane:
    state: str
    current: Mapping[str, Any] | None
    events: tuple[Mapping[str, Any], ...]
    reason_codes: tuple[str, ...]


class SourceRegistry:
    """Rebuildable DM-015 views over one signed ledger and owner-local CAS.

    No claim, assessment, publication, or import decision is authoritative in
    this object.  The signed ledger is the record; this class recomputes the two
    independent axes (intrinsic state and receiver-local disposition) whenever
    queried.
    """

    def __init__(
        self,
        ledger: Any,
        cas: SourceCAS,
        *,
        clock: Any,
        artifact_verifier: ArtifactEvidenceVerifier | None = None,
        known_ledgers: Mapping[str, Any] | None = None,
        disclosure_authorizer: SourceDisclosureAuthorizer | None = None,
    ) -> None:
        self.ledger = ledger
        self.cas = cas
        self.clock = clock
        self.artifact_verifier = artifact_verifier
        self.disclosure_authorizer = disclosure_authorizer
        self._source_mutex = threading.RLock()
        self._source_lock_state = threading.local()
        configured = {} if known_ledgers is None else dict(known_ledgers)
        local_me_id = str(ledger.authority.manifest.being_ref)
        if local_me_id in configured and configured[local_me_id] is not ledger:
            raise SourceError("source_local_ledger_conflict")
        configured[local_me_id] = ledger
        for being_ref, known in configured.items():
            if (
                not isinstance(being_ref, str)
                or str(known.authority.manifest.being_ref) != being_ref
            ):
                raise SourceError("source_known_ledger_mismatch")
        self.known_ledgers = configured

    @property
    def local_me_id(self) -> str:
        return str(self.ledger.authority.manifest.being_ref)

    def initialize(self) -> None:
        for ledger in self.known_ledgers.values():
            ledger.initialize()
        self.cas.initialize()

    def _events(self) -> list[dict[str, Any]]:
        result: dict[str, dict[str, Any]] = {}
        for ledger in self.known_ledgers.values():
            for event in ledger.events(include_incomplete=False):
                if event["kind"] not in SOURCE_EVENT_KINDS:
                    continue
                existing = result.get(event["event_id"])
                if existing is not None and existing != event:
                    raise SourceError("source_known_event_conflict")
                result[event["event_id"]] = copy.deepcopy(dict(event))
        return sorted(
            result.values(),
            key=lambda event: (
                event["being_ref"],
                event["origin"]["incarnation_id"],
                event["sequence"],
                event["event_id"],
            ),
        )

    def _event(self, event_id: str) -> dict[str, Any] | None:
        found: dict[str, Any] | None = None
        for ledger in self.known_ledgers.values():
            event = ledger.event(event_id)
            if event is None:
                continue
            if found is not None and found != event:
                raise SourceError("source_known_event_conflict")
            found = copy.deepcopy(dict(event))
        return found

    @staticmethod
    def _group(
        events: Sequence[Mapping[str, Any]], kind: str, series_field: str
    ) -> dict[str, list[Mapping[str, Any]]]:
        grouped: dict[str, list[Mapping[str, Any]]] = {}
        for event in events:
            if event["kind"] == kind:
                grouped.setdefault(str(event["payload"][series_field]), []).append(
                    event
                )
        return grouped

    @staticmethod
    def _ordered_lane(
        rows: Sequence[Mapping[str, Any]],
        *,
        sequence_field: str,
        predecessor_field: str,
        predecessor_hash_field: str | None,
        stable_fields: Sequence[str],
        retraction_relations: bool = False,
    ) -> _Lane:
        if not rows:
            return _Lane("incomplete", None, (), ("missing:series",))
        positions: dict[int, list[Mapping[str, Any]]] = {}
        for event in rows:
            positions.setdefault(int(event["payload"][sequence_field]), []).append(
                event
            )
        forked = any(len(values) != 1 for values in positions.values())
        high_water = max(positions)
        if set(positions) != set(range(high_water + 1)):
            return _Lane(
                "incomplete",
                None,
                tuple(copy.deepcopy(dict(row)) for row in rows),
                ("missing:series-position",),
            )
        ordered = [positions[index][0] for index in range(high_water + 1)]
        first = ordered[0]["payload"]
        malformed = False
        for index, event in enumerate(ordered):
            payload = event["payload"]
            if any(payload[field] != first[field] for field in stable_fields):
                malformed = True
            if index == 0:
                continue
            previous = ordered[index - 1]
            if payload[predecessor_field] != previous["event_id"]:
                malformed = True
            if (
                predecessor_hash_field is not None
                and payload[predecessor_hash_field] != previous["content_hash"]
            ):
                malformed = True
            if (
                retraction_relations
                and payload.get("action") == "retract"
                and payload["relations"] != previous["payload"]["relations"]
            ):
                malformed = True
        exact = tuple(copy.deepcopy(dict(row)) for row in ordered)
        if forked:
            all_rows = tuple(
                copy.deepcopy(dict(row))
                for position in sorted(positions)
                for row in sorted(
                    positions[position], key=lambda item: item["event_id"]
                )
            )
            return _Lane("forked", None, all_rows, ("quarantined:series-fork",))
        if malformed:
            return _Lane("invalid", None, exact, ("rejected:series-predecessor",))
        return _Lane("current", exact[-1], exact, ())

    def _content_complete(self, reference: Mapping[str, Any]) -> bool:
        try:
            self.cas.get(reference)
        except SourceError as error:
            if error.incomplete:
                return False
            raise
        return True

    def _artifact_complete(self, reference: Mapping[str, Any]) -> bool:
        verifier = self.artifact_verifier
        return False if verifier is None else verifier(reference) is True

    def _evidence_complete(self, claim: Mapping[str, Any]) -> tuple[bool, list[str]]:
        reference = claim["payload"]["evidence_manifest_ref"]
        if reference is None:
            return True, []
        try:
            manifest = self.cas.get_json(reference)
            validate_evidence_manifest(manifest, claim["payload"])
        except SourceError as error:
            if error.incomplete:
                return False, [reference["content_id"]]
            return False, [f"invalid:{error.code}"]
        missing: list[str] = []
        for entry in manifest["entries"]:
            if entry["kind"] == "content":
                if not self._content_complete(entry["content"]):
                    missing.append(entry["content"]["content_id"])
            elif not self._artifact_complete(entry["artifact"]):
                missing.append(entry["artifact"]["artifact_id"])
        return not missing, sorted(missing)

    def _claim_lanes(self, events: Sequence[Mapping[str, Any]]) -> dict[str, _Lane]:
        result: dict[str, _Lane] = {}
        for series, rows in self._group(
            events, CLAIM_EVENT_KIND, "claim_series_id"
        ).items():
            lane = self._ordered_lane(
                rows,
                sequence_field="claim_sequence",
                predecessor_field="previous_claim_event_id",
                predecessor_hash_field="previous_claim_event_hash",
                stable_fields=(
                    "claim_series_id",
                    "claimant_me_id",
                    "source_core",
                    "source_id",
                ),
                retraction_relations=True,
            )
            if lane.state == "current" and lane.current is not None:
                complete, missing = self._evidence_complete(lane.current)
                if not complete:
                    lane = _Lane(
                        "incomplete",
                        lane.current,
                        lane.events,
                        tuple(["quarantined:missing-evidence", *missing]),
                    )
            result[series] = lane
        return result

    def _assessment_lanes(
        self, events: Sequence[Mapping[str, Any]]
    ) -> dict[str, _Lane]:
        return {
            series: self._ordered_lane(
                rows,
                sequence_field="assessment_sequence",
                predecessor_field="previous_assessment_event_id",
                predecessor_hash_field=None,
                stable_fields=("assessment_series_id", "assessor_me_id"),
            )
            for series, rows in self._group(
                events, ASSESSMENT_EVENT_KIND, "assessment_series_id"
            ).items()
        }

    def _publication_lanes(
        self, events: Sequence[Mapping[str, Any]]
    ) -> dict[str, _Lane]:
        return {
            series: self._ordered_lane(
                rows,
                sequence_field="publication_sequence",
                predecessor_field="previous_publication_event_id",
                predecessor_hash_field="previous_publication_event_hash",
                stable_fields=(
                    "publication_id",
                    "publisher_me_id",
                    "source_id",
                    "source_uri",
                ),
            )
            for series, rows in self._group(
                events, PUBLICATION_EVENT_KIND, "publication_id"
            ).items()
        }

    def _import_lanes(self, events: Sequence[Mapping[str, Any]]) -> dict[str, _Lane]:
        return {
            series: self._ordered_lane(
                rows,
                sequence_field="decision_sequence",
                predecessor_field="previous_decision_event_id",
                predecessor_hash_field=None,
                stable_fields=(
                    "decision_series_id",
                    "publication_id",
                    "receiver_me_id",
                ),
            )
            for series, rows in self._group(
                events, IMPORT_EVENT_KIND, "decision_series_id"
            ).items()
        }

    def _assessment_state(
        self,
        claim_lane: _Lane,
        assessments: Mapping[str, _Lane],
        *,
        now_ms: int,
    ) -> tuple[str, list[str], Mapping[str, Any] | None]:
        claim = claim_lane.current
        if claim_lane.state == "forked":
            return "quarantined", ["quarantined:claim-fork"], None
        if claim_lane.state != "current" or claim is None:
            return "quarantined", list(claim_lane.reason_codes), None
        payload = claim["payload"]
        if payload["action"] == "retract":
            return "quarantined", ["quarantined:retracted"], None
        if payload["expires_at_ms"] is not None and payload["expires_at_ms"] <= now_ms:
            return "quarantined", ["quarantined:expired"], None
        series = assessment_series_id(self.local_me_id, payload["claim_series_id"])
        lane = assessments.get(series)
        if lane is None:
            return "quarantined", ["quarantined:initial"], None
        if lane.state == "forked":
            return "quarantined", ["quarantined:assessment-fork"], None
        if lane.state != "current" or lane.current is None:
            return "quarantined", list(lane.reason_codes), None
        decision = lane.current
        assessed = decision["payload"]
        if (
            assessed["claim_event_id"] != claim["event_id"]
            or assessed["claim_event_hash"] != claim["content_hash"]
        ):
            return "quarantined", ["quarantined:stale-assessment"], decision
        try:
            snapshot = self.cas.get_json(assessed["evidence_snapshot_ref"])
            validate_policy_snapshot(snapshot)
            self.cas.get(assessed["policy_ref"])
            self.cas.get(assessed["evidence_manifest_ref"])
        except SourceError:
            return "quarantined", ["quarantined:missing-evidence"], decision
        subject = snapshot["subject"]
        cursor = self._event(snapshot["observed_cursor_event_id"])
        if (
            subject["kind"] != "claim"
            or subject["id"] != payload["claim_series_id"]
            or subject["event_id"] != claim["event_id"]
            or subject["event_hash"] != claim["content_hash"]
            or snapshot["source_id"] != payload["source_id"]
            or claim["event_id"] not in snapshot["claim_event_ids"]
            or cursor is None
            or cursor["kind"] != CURSOR_EVENT_KIND
            or cursor["content_hash"] != snapshot["observed_cursor_event_hash"]
            or cursor["being_ref"] != self.local_me_id
        ):
            return "quarantined", ["quarantined:evidence-snapshot-mismatch"], decision
        return (
            str(assessed["disposition"]),
            list(assessed["reason_codes"]),
            decision,
        )

    def _publication_state(
        self,
        lane: _Lane,
        claims: Mapping[str, _Lane],
        *,
        now_ms: int,
    ) -> tuple[str, list[str], Mapping[str, Any] | None]:
        if lane.state == "forked":
            return "forked", ["quarantined:publication-fork"], None
        if lane.state != "current" or lane.current is None:
            return lane.state, list(lane.reason_codes), lane.current
        event = lane.current
        payload = event["payload"]
        if payload["action"] == "tombstone":
            return "tombstoned", [], event
        claim_series = claim_series_id(payload["publisher_me_id"], payload["source_id"])
        claim_lane = claims.get(claim_series)
        if (
            claim_lane is None
            or claim_lane.state != "current"
            or claim_lane.current is None
        ):
            return "incomplete", ["quarantined:publisher-claim"], event
        claim = claim_lane.current
        claim_payload = claim["payload"]
        if (
            claim["event_id"] != payload["publisher_claim_event_id"]
            or claim_payload["action"] != "assert"
            or (
                claim_payload["expires_at_ms"] is not None
                and claim_payload["expires_at_ms"] <= now_ms
            )
        ):
            return "incomplete", ["quarantined:publisher-claim"], event
        try:
            self.cas.get(payload["content_ref"])
            provenance = self.cas.get_json(payload["provenance_manifest_ref"])
            validate_provenance_manifest(provenance, payload)
        except SourceError as error:
            return "incomplete", [f"quarantined:{error.code}"], event
        complete, missing = self._provenance_complete(provenance)
        if not complete:
            return "incomplete", ["quarantined:missing-evidence", *missing], event
        return "published", [], event

    def _provenance_complete(
        self, provenance: Mapping[str, Any]
    ) -> tuple[bool, list[str]]:
        missing: list[str] = []
        for node in provenance["nodes"]:
            if not self._content_complete(node["content_ref"]):
                missing.append(node["content_ref"]["content_id"])
            for author in node["authors"]:
                if author["assertion"] == "cryptographic":
                    for reference in author["evidence_refs"]:
                        if not self._artifact_complete(reference):
                            missing.append(reference["artifact_id"])
        for edge in provenance["edges"]:
            reference = edge["transformation_ref"]
            if reference is not None and not self._content_complete(reference):
                missing.append(reference["content_id"])
        return not missing, sorted(set(missing))

    @_serialized_source_operation
    def status(self, selector: Mapping[str, Any]) -> dict[str, Any]:
        """Resolve one exact source without route, search, or alias authority."""

        selected = validate_source_selector(selector)
        now_ms = int(self.clock())
        events = self._events()
        claims = self._claim_lanes(events)
        assessments = self._assessment_lanes(events)
        publications = self._publication_lanes(events)
        claim_rows: list[dict[str, Any]] = []
        eligible: list[dict[str, Any]] = []
        for series in sorted(claims):
            lane = claims[series]
            representative = lane.current or (lane.events[-1] if lane.events else None)
            if (
                representative is None
                or representative["payload"]["source_id"] != selected["source_id"]
            ):
                continue
            disposition, reasons, assessment = self._assessment_state(
                lane, assessments, now_ms=now_ms
            )
            payload = representative["payload"]
            intrinsic = lane.state
            if lane.state == "current":
                intrinsic = (
                    "valid-retracted"
                    if payload["action"] == "retract"
                    else "valid-asserted"
                )
            row = {
                "assessment_event_id": (
                    None if assessment is None else assessment["event_id"]
                ),
                "claim_event_id": representative["event_id"],
                "claim_event_hash": representative["content_hash"],
                "claim_series_id": series,
                "claimant_me_id": payload["claimant_me_id"],
                "disposition": disposition,
                "intrinsic_state": intrinsic,
                "reason_codes": sorted(set(reasons)),
                "relations": copy.deepcopy(payload["relations"]),
                "sequence": payload["claim_sequence"],
            }
            claim_rows.append(row)
            if intrinsic == "valid-asserted" and disposition == "admitted":
                eligible.append(
                    {
                        "claim_event_id": representative["event_id"],
                        "claimant_me_id": payload["claimant_me_id"],
                        "relations": copy.deepcopy(payload["relations"]),
                    }
                )
        publication_rows: list[dict[str, Any]] = []
        for series in sorted(publications):
            state, reasons, current = self._publication_state(
                publications[series], claims, now_ms=now_ms
            )
            representative = current or (
                publications[series].events[-1] if publications[series].events else None
            )
            if (
                representative is None
                or representative["payload"]["source_id"] != selected["source_id"]
            ):
                continue
            publication_rows.append(
                {
                    "event_hash": representative["content_hash"],
                    "event_id": representative["event_id"],
                    "publication_id": series,
                    "publisher_me_id": representative["payload"]["publisher_me_id"],
                    "reason_codes": sorted(set(reasons)),
                    "sequence": representative["payload"]["publication_sequence"],
                    "state": state,
                }
            )
        return {
            "claims": claim_rows,
            "eligible_claimants": eligible,
            "evaluated_at_ms": now_ms,
            "observer_me_id": self.local_me_id,
            "publications": publication_rows,
            "schema": "dm.source-status/v0",
            "selector": copy.deepcopy(selected),
        }

    @staticmethod
    def _cursor_rows(status: Mapping[str, Any], kind: str) -> list[dict[str, Any]]:
        if kind == "claim":
            return [
                {
                    "claim_series_id": row["claim_series_id"],
                    "claimant_me_id": row["claimant_me_id"],
                    "event_hash": row["claim_event_hash"],
                    "event_id": row["claim_event_id"],
                    "sequence": row["sequence"],
                    "state": (
                        "forked"
                        if row["intrinsic_state"] == "forked"
                        else (
                            "retracted"
                            if row["intrinsic_state"] == "valid-retracted"
                            else "asserted"
                        )
                    ),
                }
                for row in status["claims"]
            ]
        return [
            {
                "event_hash": row["event_hash"],
                "event_id": row["event_id"],
                "publication_id": row["publication_id"],
                "publisher_me_id": row["publisher_me_id"],
                "sequence": row["sequence"],
                "state": row["state"],
            }
            for row in status["publications"]
            if row["state"] in {"published", "tombstoned", "forked"}
        ]

    def _page_rows(
        self, source_identifier: str, kind: str, rows: Sequence[Mapping[str, Any]]
    ) -> dict[str, Any]:
        if not rows:
            return {"first_page_ref": None, "page_count": 0, "row_count": 0}
        chunks = [
            list(rows[index : index + MAX_CURSOR_PAGE_ROWS])
            for index in range(0, len(rows), MAX_CURSOR_PAGE_ROWS)
        ]
        next_ref: dict[str, Any] | None = None
        refs: list[dict[str, Any]] = []
        for page_index in reversed(range(len(chunks))):
            page = {
                "kind": kind,
                "next_page_ref": next_ref,
                "page_index": page_index,
                "rows": copy.deepcopy(chunks[page_index]),
                "schema": CURSOR_PAGE_SCHEMA,
                "source_id": source_identifier,
            }
            validate_cursor_page(page)
            next_ref = self.cas.put_json(
                page, "application/vnd.daimon.source-cursor-page.v0+json"
            )
            refs.append(next_ref)
        assert next_ref is not None
        return {
            "first_page_ref": next_ref,
            "page_count": len(chunks),
            "row_count": len(rows),
        }

    @_serialized_source_operation
    def create_cursor(
        self,
        selector: Mapping[str, Any],
        *,
        signer: Any,
        occurred_at_ms: int | None = None,
        operation_id: str | None = None,
    ) -> dict[str, Any]:
        """Author one observer-relative cursor from a consistent local view."""

        selected = validate_source_selector(selector)
        status = self.status(selected)
        claim_rows = sorted(
            self._cursor_rows(status, "claim"), key=lambda row: row["claim_series_id"]
        )
        publication_rows = sorted(
            self._cursor_rows(status, "publication"),
            key=lambda row: row["publication_id"],
        )
        if len(claim_rows) > MAX_CURSOR_ROWS or len(publication_rows) > MAX_CURSOR_ROWS:
            raise SourceError("source_cursor_capacity")
        claim_pages = self._page_rows(selected["source_id"], "claim", claim_rows)
        publication_pages = self._page_rows(
            selected["source_id"], "publication", publication_rows
        )
        snapshot_body = {
            "claim_pages": claim_pages,
            "claim_rows": claim_rows,
            "publication_pages": publication_pages,
            "publication_rows": publication_rows,
            "source_id": selected["source_id"],
        }
        timestamp = int(self.clock()) if occurred_at_ms is None else occurred_at_ms
        payload = {
            "claim_pages": claim_pages,
            "created_at_ms": timestamp,
            "identity_control_position": {
                "embodiment_id": self.ledger.local_origin["embodiment_id"],
                "incarnation_id": self.ledger.local_origin["incarnation_id"],
                "manifest_hash": self.ledger.authority.manifest.digest,
            },
            "observer_me_id": self.local_me_id,
            "publication_pages": publication_pages,
            "schema": CURSOR_SCHEMA,
            "snapshot_hash": b64url(
                digest("daimon/source-cursor-snapshot/v0", snapshot_body)
            ),
            "source_id": selected["source_id"],
        }
        validate_cursor_payload(payload)
        if operation_id is None:
            event = self.ledger.append_local(
                kind=CURSOR_EVENT_KIND,
                subject=selected["source_id"],
                payload=payload,
                signer=signer,
                sensitivity="private",
                occurred_at_ms=timestamp,
            )
        else:
            normalized_operation = _uuid(operation_id, "invalid_source_operation_id")
            request_hash = hashlib.sha256(
                _canonical(payload, "invalid_source_cursor")
            ).hexdigest()
            event = self.ledger.append_local_idempotent(
                client_id="dm.source.pull",
                request_id=normalized_operation,
                request_hash=request_hash,
                kind=CURSOR_EVENT_KIND,
                subject=selected["source_id"],
                payload=payload,
                signer=signer,
                sensitivity="private",
                occurred_at_ms=timestamp,
                event_id=str(
                    uuid.uuid5(
                        uuid.UUID(normalized_operation),
                        "dm.source.pull/achieved-cursor",
                    )
                ),
            )
        return {"event": event, "status": status}

    def _cursor_page_chain(
        self, summary: Mapping[str, Any], kind: str, source_identifier: str
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        validated = _validate_page_summary(summary)
        reference = validated["first_page_ref"]
        pages: list[dict[str, Any]] = []
        rows: list[dict[str, Any]] = []
        for page_index in range(validated["page_count"]):
            if reference is None:
                raise SourceError("source_cursor_page_chain_truncated")
            page = self.cas.get_json(reference)
            validate_cursor_page(page)
            if (
                page["kind"] != kind
                or page["source_id"] != source_identifier
                or page["page_index"] != page_index
            ):
                raise SourceError("source_cursor_page_chain_mismatch")
            pages.append(
                {
                    "page": page,
                    "reference": copy.deepcopy(reference),
                }
            )
            rows.extend(copy.deepcopy(page["rows"]))
            reference = page["next_page_ref"]
        if reference is not None or len(rows) != validated["row_count"]:
            raise SourceError("source_cursor_page_chain_mismatch")
        return pages, rows

    @_serialized_source_operation
    def cursor_envelope(self, event: Mapping[str, Any]) -> dict[str, Any]:
        """Export a signed cursor plus every exact page needed to verify it."""

        if (
            event.get("kind") != CURSOR_EVENT_KIND
            or event.get("being_ref") != self.local_me_id
        ):
            raise SourceError("invalid_local_source_cursor")
        payload = validate_cursor_payload(event["payload"])
        claim_pages, claim_rows = self._cursor_page_chain(
            payload["claim_pages"], "claim", payload["source_id"]
        )
        publication_pages, publication_rows = self._cursor_page_chain(
            payload["publication_pages"], "publication", payload["source_id"]
        )
        snapshot_body = {
            "claim_pages": payload["claim_pages"],
            "claim_rows": claim_rows,
            "publication_pages": payload["publication_pages"],
            "publication_rows": publication_rows,
            "source_id": payload["source_id"],
        }
        expected = b64url(digest("daimon/source-cursor-snapshot/v0", snapshot_body))
        if payload["snapshot_hash"] != expected:
            raise SourceError("source_cursor_snapshot_mismatch")
        return {
            "claim_pages": claim_pages,
            "event": copy.deepcopy(dict(event)),
            "publication_pages": publication_pages,
            "schema": "dm.source-cursor-envelope/v0",
        }

    @_serialized_source_operation
    def latest_cursor(
        self, selector: Mapping[str, Any], *, require_current: bool = True
    ) -> dict[str, Any] | None:
        selected = validate_source_selector(selector)
        cursors = [
            event
            for event in self._events()
            if event["kind"] == CURSOR_EVENT_KIND
            and event["being_ref"] == self.local_me_id
            and event["payload"]["source_id"] == selected["source_id"]
        ]
        if not cursors:
            return None
        event = max(
            cursors,
            key=lambda item: (
                item["occurred_at_ms"],
                item["sequence"],
                item["event_id"],
            ),
        )
        envelope = self.cursor_envelope(event)
        if require_current:
            status = self.status(selected)
            current_claims = sorted(
                self._cursor_rows(status, "claim"),
                key=lambda row: row["claim_series_id"],
            )
            current_publications = sorted(
                self._cursor_rows(status, "publication"),
                key=lambda row: row["publication_id"],
            )
            envelope_claims = [
                row for page in envelope["claim_pages"] for row in page["page"]["rows"]
            ]
            envelope_publications = [
                row
                for page in envelope["publication_pages"]
                for row in page["page"]["rows"]
            ]
            if (
                envelope_claims != current_claims
                or envelope_publications != current_publications
            ):
                raise SourceError("source_cursor_stale", retryable=True)
        return envelope

    def _verify_cursor_envelope(
        self,
        value: Any,
        *,
        expected_source_id: str,
        expected_observer: str,
    ) -> tuple[dict[str, Any], set[str]]:
        envelope = _closed(
            value,
            {"claim_pages", "event", "publication_pages", "schema"},
            "invalid_source_cursor_envelope",
        )
        if envelope["schema"] != "dm.source-cursor-envelope/v0":
            raise SourceError("invalid_source_cursor_envelope")
        event = envelope["event"]
        if not isinstance(event, Mapping):
            raise SourceError("invalid_source_cursor_envelope")
        being_ref = event.get("being_ref")
        if not isinstance(being_ref, str):
            raise SourceError("invalid_source_cursor_envelope")
        known = self.known_ledgers.get(being_ref)
        if known is None:
            raise SourceError("source_cursor_authority_unknown", incomplete=True)
        from .weave import WeaveProtocolError, verify_event

        try:
            verified = verify_event(event, known.authority)
        except WeaveProtocolError as exception:
            raise SourceError("invalid_source_cursor_signature") from exception
        if (
            verified["kind"] != CURSOR_EVENT_KIND
            or verified["being_ref"] != expected_observer
            or verified["payload"]["observer_me_id"] != expected_observer
            or verified["payload"]["source_id"] != expected_source_id
        ):
            raise SourceError("source_cursor_scope_mismatch")
        payload = verified["payload"]
        all_rows: list[dict[str, Any]] = []
        for field, kind in (
            ("claim_pages", "claim"),
            ("publication_pages", "publication"),
        ):
            page_values = envelope[field]
            summary = _validate_page_summary(payload[field])
            if (
                not isinstance(page_values, list)
                or len(page_values) != summary["page_count"]
            ):
                raise SourceError("invalid_source_cursor_envelope")
            expected_ref = summary["first_page_ref"]
            for page_index, page_value in enumerate(page_values):
                wrapped = _closed(
                    page_value,
                    {"page", "reference"},
                    "invalid_source_cursor_envelope",
                )
                reference = validate_content_ref(wrapped["reference"])
                if reference != expected_ref:
                    raise SourceError("source_cursor_page_chain_mismatch")
                page = validate_cursor_page(wrapped["page"])
                raw = _canonical(page, "invalid_source_cursor_envelope")
                verify_content(reference, raw)
                if (
                    page["page_index"] != page_index
                    or page["kind"] != kind
                    or page["source_id"] != expected_source_id
                ):
                    raise SourceError("source_cursor_page_chain_mismatch")
                all_rows.extend(page["rows"])
                expected_ref = page["next_page_ref"]
            if expected_ref is not None:
                raise SourceError("source_cursor_page_chain_mismatch")
        claim_count = payload["claim_pages"]["row_count"]
        claim_rows = all_rows[:claim_count]
        publication_rows = all_rows[claim_count:]
        snapshot_body = {
            "claim_pages": payload["claim_pages"],
            "claim_rows": claim_rows,
            "publication_pages": payload["publication_pages"],
            "publication_rows": publication_rows,
            "source_id": expected_source_id,
        }
        if payload["snapshot_hash"] != b64url(
            digest("daimon/source-cursor-snapshot/v0", snapshot_body)
        ):
            raise SourceError("source_cursor_snapshot_mismatch")
        event_ids = {row["event_id"] for row in [*claim_rows, *publication_rows]}
        return copy.deepcopy(dict(verified)), event_ids

    def _disclosure_allowed(
        self, requester_me_id: str, source_identifier: str, classification: str
    ) -> bool:
        if requester_me_id == self.local_me_id:
            return True
        authorizer = self.disclosure_authorizer
        return bool(
            authorizer is not None
            and authorizer(requester_me_id, source_identifier, classification) is True
        )

    def _event_closure(
        self, seeds: Sequence[Mapping[str, Any]], *, requester_me_id: str
    ) -> list[dict[str, Any]]:
        selected_source = str(seeds[0]["subject"])
        pending = [str(event["event_id"]) for event in seeds]
        result: dict[str, dict[str, Any]] = {}
        while pending:
            event_id = pending.pop()
            if event_id in result:
                continue
            event = self._event(event_id)
            if event is None:
                raise SourceError("source_event_closure_incomplete", incomplete=True)
            closure_source = (
                str(event["subject"])
                if event["kind"] in SOURCE_EVENT_KINDS
                else selected_source
            )
            if (
                event["kind"] not in SOURCE_EVENT_KINDS
                or event["subject"] != selected_source
            ) and not self._disclosure_allowed(
                requester_me_id, closure_source, "origin-closure"
            ):
                raise SourceError("source_disclosure_denied")
            result[event_id] = event
            if event["previous_event_id"] is not None:
                pending.append(event["previous_event_id"])
            pending.extend(event["causal_parents"])
        return sorted(
            result.values(),
            key=lambda event: (
                event["being_ref"],
                event["origin"]["incarnation_id"],
                event["sequence"],
                event["event_id"],
            ),
        )

    def _blob_references(
        self,
        source_events: Sequence[Mapping[str, Any]],
        *,
        publication_heads: Mapping[str, str],
        requester_me_id: str,
    ) -> list[dict[str, Any]]:
        references: dict[str, dict[str, Any]] = {}

        def add(reference: Mapping[str, Any]) -> dict[str, Any]:
            normalized = validate_content_ref(reference)
            references[normalized["content_id"]] = normalized
            return normalized

        for event in source_events:
            payload = event["payload"]
            if event["kind"] == CLAIM_EVENT_KIND and payload["action"] == "assert":
                manifest_ref = add(payload["evidence_manifest_ref"])
                manifest = self.cas.get_json(manifest_ref)
                validate_evidence_manifest(manifest, payload)
                for entry in manifest["entries"]:
                    if entry["kind"] == "content":
                        add(entry["content"])
            if (
                event["kind"] == PUBLICATION_EVENT_KIND
                and payload["action"] == "publish"
                and publication_heads.get(payload["publication_id"])
                == event["event_id"]
            ):
                if not self._disclosure_allowed(
                    requester_me_id,
                    payload["source_id"],
                    payload["classification"],
                ):
                    raise SourceError("source_disclosure_denied")
                add(payload["content_ref"])
                provenance_ref = add(payload["provenance_manifest_ref"])
                provenance = self.cas.get_json(provenance_ref)
                validate_provenance_manifest(provenance, payload)
                for node in provenance["nodes"]:
                    add(node["content_ref"])
                for edge in provenance["edges"]:
                    if edge["transformation_ref"] is not None:
                        add(edge["transformation_ref"])
        return [references[key] for key in sorted(references)]

    def _diff_item(
        self,
        *,
        kind: str,
        series_id: str,
        lane_events: Sequence[Mapping[str, Any]],
        requester_me_id: str,
        publication_heads: Mapping[str, str],
    ) -> dict[str, Any]:
        closure = self._event_closure(lane_events, requester_me_id=requester_me_id)
        source_events = [
            event
            for event in closure
            if event["kind"] in {CLAIM_EVENT_KIND, PUBLICATION_EVENT_KIND}
            and event["subject"] == lane_events[0]["subject"]
        ]
        for series, lane in self._publication_lanes(source_events).items():
            if (
                lane.state == "current"
                and lane.current is not None
                and lane.current["payload"]["action"] == "publish"
                and publication_heads.get(series) != lane.current["event_id"]
            ):
                raise SourceError("source_diff_publication_not_offerable")
        blobs = [
            {
                "data": b64url(self.cas.get(reference)),
                "reference": reference,
            }
            for reference in self._blob_references(
                source_events,
                publication_heads=publication_heads,
                requester_me_id=requester_me_id,
            )
        ]
        core = {
            "blobs": blobs,
            "events": closure,
            "kind": kind,
            "series_id": series_id,
        }
        return {
            **core,
            "item_hash": b64url(digest("daimon/source-diff-item/v0", core)),
            "schema": "dm.source-diff-item/v0",
        }

    @staticmethod
    def _continuation_token(body: Mapping[str, Any]) -> dict[str, Any]:
        return {
            **copy.deepcopy(dict(body)),
            "schema": "dm.source-continuation/v0",
            "token_hash": b64url(digest("daimon/source-continuation/v0", dict(body))),
        }

    @staticmethod
    def _validate_continuation(value: Any) -> dict[str, Any]:
        fields = {
            "expires_at_ms",
            "next_offset",
            "next_page_index",
            "page_hash",
            "request_event_id",
            "requester_me_id",
            "responder_cursor_hash",
            "responder_me_id",
            "schema",
            "token_hash",
        }
        row = _closed(value, fields, "invalid_source_continuation")
        if row["schema"] != "dm.source-continuation/v0":
            raise SourceError("invalid_source_continuation")
        _uuid(row["request_event_id"], "invalid_source_continuation")
        for field in ("requester_me_id", "responder_me_id"):
            _me_id(row[field], "invalid_source_continuation")
        _event_hash(row["responder_cursor_hash"], "invalid_source_continuation")
        _hash43(row["page_hash"], "invalid_source_continuation")
        _uint(row["next_offset"], "invalid_source_continuation")
        page_index = _uint(row["next_page_index"], "invalid_source_continuation")
        if page_index > 63:
            raise SourceError("invalid_source_continuation")
        _uint(row["expires_at_ms"], "invalid_source_continuation")
        _hash43(row["token_hash"], "invalid_source_continuation")
        body = {
            key: copy.deepcopy(row[key]) for key in fields - {"schema", "token_hash"}
        }
        if row["token_hash"] != b64url(digest("daimon/source-continuation/v0", body)):
            raise SourceError("source_continuation_hash_mismatch")
        return copy.deepcopy(dict(row))

    @_serialized_source_operation
    def diff(
        self,
        *,
        selector: Mapping[str, Any],
        request_event_id: str,
        requester_me_id: str,
        requester_cursor: Mapping[str, Any],
        max_items: int,
        max_bytes: int,
        continuation: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Return one disclosure-authorized, content-bound, side-effect-free page."""

        selected = validate_source_selector(selector)
        request_id = _uuid(request_event_id, "invalid_source_diff_request")
        requester = _me_id(requester_me_id, "invalid_source_diff_request")
        item_limit = _uint(max_items, "invalid_source_diff_request", 1)
        byte_limit = _uint(max_bytes, "invalid_source_diff_request", 1)
        if item_limit > 4096 or byte_limit > 268_435_456:
            raise SourceError("invalid_source_diff_request")
        if requester_cursor.get("schema") == "dm.source-empty-cursor/v0":
            _closed(
                requester_cursor,
                {"observer_me_id", "schema", "source_id"},
                "invalid_source_empty_cursor",
            )
            if (
                requester_cursor["observer_me_id"] != requester
                or requester_cursor["source_id"] != selected["source_id"]
            ):
                raise SourceError("source_cursor_scope_mismatch")
            requester_cursor_hash: str | None = None
            known_event_ids: set[str] = set()
        else:
            cursor_event, known_event_ids = self._verify_cursor_envelope(
                requester_cursor,
                expected_source_id=selected["source_id"],
                expected_observer=requester,
            )
            requester_cursor_hash = cursor_event["content_hash"]
        responder_cursor = self.latest_cursor(selected)
        if responder_cursor is None:
            raise SourceError("source_cursor_missing", retryable=True)
        responder_event = responder_cursor["event"]
        responder_cursor_hash = responder_event["content_hash"]
        if not self._disclosure_allowed(requester, selected["source_id"], "claim"):
            raise SourceError("source_disclosure_denied")
        offset = 0
        page_index = 0
        previous_page_hash: str | None = None
        if continuation is not None:
            token = self._validate_continuation(continuation)
            if (
                token["request_event_id"] != request_id
                or token["requester_me_id"] != requester
                or token["responder_me_id"] != self.local_me_id
                or token["responder_cursor_hash"] != responder_cursor_hash
                or token["expires_at_ms"] < int(self.clock())
            ):
                raise SourceError("source_continuation_scope_mismatch")
            offset = token["next_offset"]
            page_index = token["next_page_index"]
            previous_page_hash = token["page_hash"]
        events = self._events()
        claims = self._claim_lanes(events)
        publications = self._publication_lanes(events)
        publication_states = {
            series: self._publication_state(lane, claims, now_ms=int(self.clock()))
            for series, lane in publications.items()
        }
        publication_heads = {
            series: str(representative["event_id"])
            for series, (state, _, representative) in publication_states.items()
            if state == "published" and representative is not None
        }
        candidates: list[dict[str, Any]] = []
        for series in sorted(claims):
            lane = claims[series]
            representative = lane.current or (lane.events[-1] if lane.events else None)
            if (
                representative is None
                or representative["payload"]["source_id"] != selected["source_id"]
            ):
                continue
            if representative["event_id"] in known_event_ids:
                continue
            try:
                item = self._diff_item(
                    kind="claim",
                    series_id=series,
                    lane_events=lane.events,
                    requester_me_id=requester,
                    publication_heads=publication_heads,
                )
            except SourceError as error:
                if error.code in {
                    "source_diff_publication_not_offerable",
                    "source_disclosure_denied",
                }:
                    continue
                raise
            candidates.append(item)
        for series in sorted(publications):
            lane = publications[series]
            state, _, representative = publication_states[series]
            if (
                representative is None
                or representative["payload"]["source_id"] != selected["source_id"]
            ):
                continue
            if representative["event_id"] in known_event_ids:
                continue
            if state == "published":
                classification = representative["payload"]["classification"]
                if not self._disclosure_allowed(
                    requester, selected["source_id"], classification
                ):
                    continue
            elif state == "tombstoned":
                pass
            else:
                continue
            try:
                item = self._diff_item(
                    kind="publication",
                    series_id=series,
                    lane_events=lane.events,
                    requester_me_id=requester,
                    publication_heads=publication_heads,
                )
            except SourceError as error:
                if error.code in {
                    "source_diff_publication_not_offerable",
                    "source_disclosure_denied",
                }:
                    continue
                raise
            candidates.append(item)
        candidates.sort(key=lambda item: (item["kind"], item["series_id"]))
        if offset > len(candidates):
            raise SourceError("source_continuation_offset_invalid")
        page_items: list[dict[str, Any]] = []
        for item in candidates[offset:]:
            if len(page_items) >= item_limit:
                break
            proposed = [*page_items, item]
            if len(_canonical(proposed, "source_diff_page_too_large")) > byte_limit:
                if not page_items:
                    raise SourceError("source_diff_item_too_large")
                break
            page_items.append(item)
        next_offset = offset + len(page_items)
        if next_offset < len(candidates) and page_index == 63:
            raise SourceError("source_diff_page_limit")
        expires_at_ms = int(self.clock()) + 300_000
        page_hash = b64url(
            digest(
                "daimon/source-diff-page/v0",
                {"items": page_items, "page_index": page_index},
            )
        )
        next_token = (
            None
            if next_offset == len(candidates)
            else self._continuation_token(
                {
                    "expires_at_ms": expires_at_ms,
                    "next_offset": next_offset,
                    "next_page_index": page_index + 1,
                    "page_hash": page_hash,
                    "request_event_id": request_id,
                    "requester_me_id": requester,
                    "responder_cursor_hash": responder_cursor_hash,
                    "responder_me_id": self.local_me_id,
                }
            )
        )
        core = {
            "continuation": next_token,
            "expires_at_ms": expires_at_ms,
            "items": page_items,
            "page_hash": page_hash,
            "page_index": page_index,
            "previous_page_hash": previous_page_hash,
            "request_event_id": request_id,
            "requester_cursor_hash": requester_cursor_hash,
            "requester_me_id": requester,
            "responder_cursor": responder_cursor,
            "responder_me_id": self.local_me_id,
            "selector": selected,
        }
        return {
            **core,
            "bundle_hash": b64url(digest("daimon/source-diff-bundle/v0", core)),
            "schema": "dm.source-diff-bundle/v0",
        }

    @staticmethod
    def _validate_diff_item(value: Any) -> dict[str, Any]:
        row = _closed(
            value,
            {"blobs", "events", "item_hash", "kind", "schema", "series_id"},
            "invalid_source_diff_item",
        )
        if row["schema"] != "dm.source-diff-item/v0" or row["kind"] not in {
            "claim",
            "publication",
        }:
            raise SourceError("invalid_source_diff_item")
        if row["kind"] == "claim":
            _typed_id(row["series_id"], _CLAIM_SERIES_ID, "invalid_source_diff_item")
        else:
            _typed_id(row["series_id"], _PUBLICATION_ID, "invalid_source_diff_item")
        if not isinstance(row["events"], list) or not 1 <= len(row["events"]) <= 4096:
            raise SourceError("invalid_source_diff_item")
        if not isinstance(row["blobs"], list) or len(row["blobs"]) > 4096:
            raise SourceError("invalid_source_diff_item")
        _hash43(row["item_hash"], "invalid_source_diff_item")
        core = {
            "blobs": copy.deepcopy(row["blobs"]),
            "events": copy.deepcopy(row["events"]),
            "kind": row["kind"],
            "series_id": row["series_id"],
        }
        if row["item_hash"] != b64url(digest("daimon/source-diff-item/v0", core)):
            raise SourceError("source_diff_item_hash_mismatch")
        return copy.deepcopy(dict(row))

    def _validate_diff_bundle(self, value: Any) -> dict[str, Any]:
        fields = {
            "bundle_hash",
            "continuation",
            "expires_at_ms",
            "items",
            "page_hash",
            "page_index",
            "previous_page_hash",
            "request_event_id",
            "requester_cursor_hash",
            "requester_me_id",
            "responder_cursor",
            "responder_me_id",
            "schema",
            "selector",
        }
        row = _closed(value, fields, "invalid_source_diff_bundle")
        if (
            len(_canonical(row, "invalid_source_diff_bundle"))
            > MAX_BUNDLE_DECOMPRESSED_BYTES
        ):
            raise SourceError("source_diff_bundle_too_large")
        if row["schema"] != "dm.source-diff-bundle/v0":
            raise SourceError("invalid_source_diff_bundle")
        _hash43(row["bundle_hash"], "invalid_source_diff_bundle")
        _hash43(row["page_hash"], "invalid_source_diff_bundle")
        _uuid(row["request_event_id"], "invalid_source_diff_bundle")
        _me_id(row["requester_me_id"], "invalid_source_diff_bundle")
        _me_id(row["responder_me_id"], "invalid_source_diff_bundle")
        _uint(row["expires_at_ms"], "invalid_source_diff_bundle")
        page_index = _uint(row["page_index"], "invalid_source_diff_bundle")
        if page_index > 63:
            raise SourceError("invalid_source_diff_bundle")
        if page_index == 0:
            if row["previous_page_hash"] is not None:
                raise SourceError("source_diff_page_chain_mismatch")
        else:
            _hash43(row["previous_page_hash"], "invalid_source_diff_bundle")
        if row["requester_cursor_hash"] is not None:
            _event_hash(row["requester_cursor_hash"], "invalid_source_diff_bundle")
        selected = validate_source_selector(row["selector"])
        items = row["items"]
        if not isinstance(items, list) or len(items) > 4096:
            raise SourceError("invalid_source_diff_bundle")
        normalized_items = [self._validate_diff_item(item) for item in items]
        markers = [(item["kind"], item["series_id"]) for item in normalized_items]
        if markers != sorted(set(markers)):
            raise SourceError("source_diff_items_not_sorted")
        if row["page_hash"] != b64url(
            digest(
                "daimon/source-diff-page/v0",
                {"items": normalized_items, "page_index": page_index},
            )
        ):
            raise SourceError("source_diff_page_hash_mismatch")
        if row["continuation"] is not None:
            token = self._validate_continuation(row["continuation"])
            if (
                token["request_event_id"] != row["request_event_id"]
                or token["requester_me_id"] != row["requester_me_id"]
                or token["responder_me_id"] != row["responder_me_id"]
                or token["page_hash"] != row["page_hash"]
                or token["next_page_index"] != page_index + 1
            ):
                raise SourceError("source_continuation_scope_mismatch")
        core = {
            key: copy.deepcopy(row[key]) for key in fields - {"bundle_hash", "schema"}
        }
        if row["bundle_hash"] != b64url(digest("daimon/source-diff-bundle/v0", core)):
            raise SourceError("source_diff_bundle_hash_mismatch")
        result = copy.deepcopy(dict(row))
        result["items"] = normalized_items
        result["selector"] = selected
        return result

    def _committed_page_prefix(
        self, bundle: Mapping[str, Any], starting_cursor_hash: str | None
    ) -> list[dict[str, Any]]:
        """Read and verify the durable prefix for a continuation page."""

        page_index = int(bundle["page_index"])
        if page_index == 0:
            return []
        with self.cas._database() as database:
            rows = database.execute(
                "SELECT result_json FROM source_intake "
                "WHERE state='committed' AND result_json IS NOT NULL"
            ).fetchall()
        prefix: dict[int, dict[str, Any]] = {}
        for row in rows:
            try:
                result = json.loads(bytes(row["result_json"]))
            except (UnicodeDecodeError, json.JSONDecodeError) as exception:
                raise SourceError("source_intake_journal_corrupt") from exception
            if (
                isinstance(result, Mapping)
                and result.get("schema") == "dm.source-pull-result/v0"
                and result.get("request_event_id") == bundle["request_event_id"]
            ):
                index = result.get("page_index")
                if not isinstance(index, int) or isinstance(index, bool):
                    raise SourceError("source_intake_journal_corrupt")
                existing = prefix.get(index)
                normalized = copy.deepcopy(dict(result))
                if existing is not None and existing != normalized:
                    raise SourceError("source_intake_page_conflict")
                prefix[index] = normalized
        if set(prefix) != set(range(page_index)):
            raise SourceError("source_incoming_page_prefix_missing", retryable=True)
        ordered = [prefix[index] for index in range(page_index)]
        previous_hash: str | None = None
        for index, result in enumerate(ordered):
            if (
                result.get("page_index") != index
                or result.get("previous_page_hash") != previous_hash
                or result.get("starting_cursor_hash") != starting_cursor_hash
                or result.get("achieved_cursor_hash") != starting_cursor_hash
                or not isinstance(result.get("accepted_event_ids"), list)
            ):
                raise SourceError("source_incoming_page_prefix_mismatch")
            previous_hash = result.get("page_hash")
            _hash43(previous_hash, "source_intake_journal_corrupt")
        if previous_hash != bundle["previous_page_hash"]:
            raise SourceError("source_incoming_page_prefix_mismatch")
        return ordered

    def _cursor_source_event_ids(self, envelope: Mapping[str, Any]) -> set[str]:
        pending = {
            str(row["event_id"])
            for field in ("claim_pages", "publication_pages")
            for wrapped in envelope[field]
            for row in wrapped["page"]["rows"]
        }
        result: set[str] = set()
        while pending:
            event_id = pending.pop()
            if event_id in result:
                continue
            event = self._event(event_id)
            if event is None or event["kind"] not in {
                CLAIM_EVENT_KIND,
                PUBLICATION_EVENT_KIND,
            }:
                raise SourceError("source_cursor_event_missing", incomplete=True)
            result.add(event_id)
            payload = event["payload"]
            predecessor = (
                payload["previous_claim_event_id"]
                if event["kind"] == CLAIM_EVENT_KIND
                else payload["previous_publication_event_id"]
            )
            if predecessor is not None:
                pending.add(predecessor)
        return result

    def _bundle_blob_map(
        self, bundle: Mapping[str, Any]
    ) -> dict[str, tuple[dict[str, Any], bytes]]:
        result: dict[str, tuple[dict[str, Any], bytes]] = {}
        for item in bundle["items"]:
            item_ids: list[str] = []
            for value in item["blobs"]:
                blob = _closed(
                    value,
                    {"data", "reference"},
                    "invalid_source_diff_blob",
                )
                reference = validate_content_ref(blob["reference"])
                if not isinstance(blob["data"], str):
                    raise SourceError("invalid_source_diff_blob")
                try:
                    raw = unb64url(blob["data"])
                except CanonicalError as exception:
                    raise SourceError("invalid_source_diff_blob") from exception
                verify_content(reference, raw)
                content_id = reference["content_id"]
                existing = result.get(content_id)
                if existing is not None and existing != (reference, raw):
                    raise SourceError("source_diff_blob_conflict")
                result[content_id] = (reference, raw)
                item_ids.append(content_id)
            if item_ids != sorted(set(item_ids)):
                raise SourceError("source_diff_blobs_not_sorted")
        return result

    def _bundle_event_map(self, bundle: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
        from .weave import WeaveProtocolError, verify_event

        result: dict[str, dict[str, Any]] = {}
        positions: dict[tuple[str, str, int], tuple[str, str]] = {}
        for item in bundle["items"]:
            item_markers: list[tuple[str, str, int, str]] = []
            item_events: dict[str, dict[str, Any]] = {}
            for value in item["events"]:
                if not isinstance(value, Mapping):
                    raise SourceError("invalid_source_diff_event")
                being_ref = value.get("being_ref")
                if not isinstance(being_ref, str):
                    raise SourceError("invalid_source_diff_event")
                known = self.known_ledgers.get(being_ref)
                if known is None:
                    raise SourceError("source_event_authority_unknown", incomplete=True)
                try:
                    event = verify_event(value, known.authority)
                except WeaveProtocolError as exception:
                    raise SourceError("invalid_source_diff_event") from exception
                event_id = event["event_id"]
                existing = result.get(event_id)
                if existing is not None and existing != event:
                    raise SourceError("source_diff_event_conflict")
                result[event_id] = event
                item_events[event_id] = event
                position = (
                    being_ref,
                    event["origin"]["incarnation_id"],
                    event["sequence"],
                )
                occupant = positions.get(position)
                marker = (event_id, event["content_hash"])
                if occupant is not None and occupant != marker:
                    raise SourceError("source_diff_origin_equivocation")
                positions[position] = marker
                item_markers.append((*position[:2], position[2], event_id))
            if item_markers != sorted(item_markers):
                raise SourceError("source_diff_events_not_sorted")
            target_kind = (
                CLAIM_EVENT_KIND if item["kind"] == "claim" else PUBLICATION_EVENT_KIND
            )
            series_field = (
                "claim_series_id" if item["kind"] == "claim" else "publication_id"
            )
            target_ids = {
                event_id
                for event_id, event in item_events.items()
                if event["kind"] == target_kind
                and event["subject"] == bundle["selector"]["source_id"]
                and event["payload"].get(series_field) == item["series_id"]
            }
            if not target_ids:
                raise SourceError("source_diff_item_target_missing")
            reachable: set[str] = set()
            pending = list(target_ids)
            while pending:
                event_id = pending.pop()
                if event_id in reachable:
                    continue
                reachable_event = item_events[event_id]
                reachable.add(event_id)
                if reachable_event["previous_event_id"] in item_events:
                    pending.append(reachable_event["previous_event_id"])
                pending.extend(
                    dependency
                    for dependency in reachable_event["causal_parents"]
                    if dependency in item_events
                )
            if reachable != set(item_events):
                raise SourceError("source_diff_unrelated_event")
        for event in result.values():
            previous_id = event["previous_event_id"]
            if previous_id is not None:
                previous = result.get(previous_id) or self._event(previous_id)
                if (
                    previous is None
                    or previous["being_ref"] != event["being_ref"]
                    or previous["origin"]["incarnation_id"]
                    != event["origin"]["incarnation_id"]
                    or previous["sequence"] != event["sequence"] - 1
                ):
                    raise SourceError("source_diff_origin_gap", incomplete=True)
            elif event["sequence"] != 1:
                raise SourceError("source_diff_origin_gap", incomplete=True)
            for dependency in event["causal_parents"]:
                if result.get(dependency) is None and self._event(dependency) is None:
                    raise SourceError("source_diff_causal_gap", incomplete=True)
        return result

    def _bundle_json(
        self,
        reference: Mapping[str, Any],
        blobs: Mapping[str, tuple[dict[str, Any], bytes]],
    ) -> dict[str, Any]:
        normalized = validate_content_ref(reference)
        present = blobs.get(normalized["content_id"])
        if present is None:
            return self.cas.get_json(normalized)
        raw = present[1]
        try:
            value = json.loads(raw, object_pairs_hook=_unique_object)
        except (UnicodeDecodeError, json.JSONDecodeError) as exception:
            raise SourceError("invalid_source_json") from exception
        if (
            not isinstance(value, Mapping)
            or _canonical(value, "invalid_source_json") != raw
        ):
            raise SourceError("source_json_not_canonical")
        return copy.deepcopy(dict(value))

    def _bundle_has(
        self,
        reference: Mapping[str, Any],
        blobs: Mapping[str, tuple[dict[str, Any], bytes]],
    ) -> bool:
        normalized = validate_content_ref(reference)
        return normalized["content_id"] in blobs or self.cas.has(normalized)

    @_serialized_source_operation
    def incoming(self, bundle: Mapping[str, Any]) -> dict[str, Any]:
        """Preview one bundle without any durable write, fetch, or cursor advance."""

        normalized = self._validate_diff_bundle(bundle)
        if normalized["requester_me_id"] != self.local_me_id:
            raise SourceError("source_diff_wrong_receiver")
        if normalized["expires_at_ms"] < int(self.clock()):
            raise SourceError("source_diff_expired")
        responder = normalized["responder_me_id"]
        self._verify_cursor_envelope(
            normalized["responder_cursor"],
            expected_source_id=normalized["selector"]["source_id"],
            expected_observer=responder,
        )
        local_cursor = self.latest_cursor(
            normalized["selector"],
            require_current=normalized["page_index"] == 0,
        )
        local_cursor_hash = (
            None if local_cursor is None else local_cursor["event"]["content_hash"]
        )
        if local_cursor_hash != normalized["requester_cursor_hash"]:
            raise SourceError("source_incoming_cursor_stale", retryable=True)
        prefix = self._committed_page_prefix(normalized, local_cursor_hash)
        if prefix:
            assert local_cursor is not None
            expected_source_events = self._cursor_source_event_ids(local_cursor)
            for result in prefix:
                expected_source_events.update(result["accepted_event_ids"])
            actual_source_events = {
                event["event_id"]
                for event in self._events()
                if event["kind"] in {CLAIM_EVENT_KIND, PUBLICATION_EVENT_KIND}
                and event["subject"] == normalized["selector"]["source_id"]
            }
            if actual_source_events != expected_source_events:
                raise SourceError("source_incoming_page_prefix_stale", retryable=True)
        locally_known = {event["event_id"] for event in self._events()}
        results: list[dict[str, Any]] = []
        for item in normalized["items"]:
            try:
                item_bundle = {**normalized, "items": [item]}
                blobs = self._bundle_blob_map(item_bundle)
                events = self._bundle_event_map(item_bundle)
                item_source_events = [
                    event
                    for event in events.values()
                    if event["kind"] in {CLAIM_EVENT_KIND, PUBLICATION_EVENT_KIND}
                    and event["subject"] == normalized["selector"]["source_id"]
                ]
            except SourceError as error:
                results.append(
                    {
                        "item_hash": item["item_hash"],
                        "kind": item["kind"],
                        "missing_references": [],
                        "outcome": "rejected",
                        "reason_codes": [f"rejected:{error.code}"],
                        "series_id": item["series_id"],
                    }
                )
                continue
            missing: list[str] = []
            reasons: list[str] = []
            try:
                publication_lanes = self._publication_lanes(item_source_events)
                current_publication_events = {
                    str(lane.current["event_id"])
                    for lane in publication_lanes.values()
                    if lane.state == "current"
                    and lane.current is not None
                    and lane.current["payload"]["action"] == "publish"
                }
                for event in item_source_events:
                    payload = event["payload"]
                    if (
                        event["kind"] == CLAIM_EVENT_KIND
                        and payload["action"] == "assert"
                    ):
                        manifest = self._bundle_json(
                            payload["evidence_manifest_ref"], blobs
                        )
                        validate_evidence_manifest(manifest, payload)
                        for entry in manifest["entries"]:
                            if entry["kind"] == "content" and not self._bundle_has(
                                entry["content"], blobs
                            ):
                                missing.append(entry["content"]["content_id"])
                            elif entry[
                                "kind"
                            ] == "daimon-artifact" and not self._artifact_complete(
                                entry["artifact"]
                            ):
                                missing.append(entry["artifact"]["artifact_id"])
                    if event["event_id"] in current_publication_events:
                        if not self._bundle_has(payload["content_ref"], blobs):
                            missing.append(payload["content_ref"]["content_id"])
                        provenance = self._bundle_json(
                            payload["provenance_manifest_ref"], blobs
                        )
                        validate_provenance_manifest(provenance, payload)
                        for node in provenance["nodes"]:
                            if not self._bundle_has(node["content_ref"], blobs):
                                missing.append(node["content_ref"]["content_id"])
                            for author in node["authors"]:
                                if author["assertion"] == "cryptographic":
                                    for reference in author["evidence_refs"]:
                                        if not self._artifact_complete(reference):
                                            missing.append(reference["artifact_id"])
                        for edge in provenance["edges"]:
                            reference = edge["transformation_ref"]
                            if reference is not None and not self._bundle_has(
                                reference, blobs
                            ):
                                missing.append(reference["content_id"])
                if missing:
                    outcome = "incomplete"
                elif all(
                    event["event_id"] in locally_known for event in item_source_events
                ):
                    outcome = "already-present"
                else:
                    lane_events = [
                        event
                        for event in item_source_events
                        if (
                            event["payload"].get("claim_series_id") == item["series_id"]
                            or event["payload"].get("publication_id")
                            == item["series_id"]
                        )
                    ]
                    sequence_field = (
                        "claim_sequence"
                        if item["kind"] == "claim"
                        else "publication_sequence"
                    )
                    positions = [
                        event["payload"][sequence_field] for event in lane_events
                    ]
                    if len(positions) != len(set(positions)):
                        outcome = "quarantined"
                        reasons = [
                            "quarantined:claim-fork"
                            if item["kind"] == "claim"
                            else "quarantined:publication-fork"
                        ]
                    else:
                        outcome = (
                            "admissible-claim-candidate"
                            if item["kind"] == "claim"
                            else "admissible-publication-candidate"
                        )
            except SourceError as error:
                outcome = "rejected"
                reasons = [f"rejected:{error.code}"]
            results.append(
                {
                    "item_hash": item["item_hash"],
                    "kind": item["kind"],
                    "missing_references": sorted(set(missing)),
                    "outcome": outcome,
                    "reason_codes": sorted(set(reasons)),
                    "series_id": item["series_id"],
                }
            )
        preview_core = {
            "bundle_hash": normalized["bundle_hash"],
            "local_cursor_hash": local_cursor_hash,
            "results": results,
        }
        return {
            **preview_core,
            "preview_hash": b64url(
                digest("daimon/source-incoming-preview/v0", preview_core)
            ),
            "schema": "dm.source-incoming-preview/v0",
        }

    @contextmanager
    def _intake_lock(self) -> Iterator[None]:
        with self._source_mutex:
            depth = int(getattr(self._source_lock_state, "depth", 0))
            if depth:
                self._source_lock_state.depth = depth + 1
                try:
                    yield
                finally:
                    self._source_lock_state.depth = depth
                return
            lock_path = self.cas.path.with_name(
                f"{self.cas.path.name}.source-intake.lock"
            )
            _prepare_private_path(lock_path)
            descriptor = os.open(
                lock_path,
                os.O_RDWR | getattr(os, "O_NOFOLLOW", 0),
            )
            try:
                info = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) & 0o077
                ):
                    raise SourceError("source_intake_lock_not_owner_only")
                fcntl.flock(descriptor, fcntl.LOCK_EX)
                self._source_lock_state.depth = 1
                yield
            finally:
                self._source_lock_state.depth = 0
                fcntl.flock(descriptor, fcntl.LOCK_UN)
                os.close(descriptor)

    def _intake_row(self, operation_id: str) -> dict[str, Any] | None:
        self.cas.initialize()
        with self.cas._database() as database:
            row = database.execute(
                "SELECT operation_id, bundle_hash, preview_hash, created_at_ms, "
                "state, result_json FROM source_intake WHERE operation_id=?",
                (operation_id,),
            ).fetchone()
        if row is None:
            return None
        result = None
        if row["result_json"] is not None:
            try:
                result = json.loads(bytes(row["result_json"]))
            except (UnicodeDecodeError, json.JSONDecodeError) as exception:
                raise SourceError("source_intake_journal_corrupt") from exception
        return {
            "bundle_hash": str(row["bundle_hash"]),
            "created_at_ms": int(row["created_at_ms"]),
            "operation_id": str(row["operation_id"]),
            "preview_hash": str(row["preview_hash"]),
            "result": result,
            "state": str(row["state"]),
        }

    def _begin_intake(
        self,
        operation_id: str,
        bundle_hash: str,
        preview_hash: str,
        created_at_ms: int,
    ) -> dict[str, Any]:
        self.cas.initialize()
        with self.cas._database() as database:
            database.execute("BEGIN IMMEDIATE")
            try:
                row = database.execute(
                    "SELECT bundle_hash, preview_hash FROM source_intake "
                    "WHERE operation_id=?",
                    (operation_id,),
                ).fetchone()
                if row is None:
                    database.execute(
                        "INSERT INTO source_intake VALUES "
                        "(?, ?, ?, ?, 'prepared', NULL)",
                        (operation_id, bundle_hash, preview_hash, created_at_ms),
                    )
                elif (
                    row["bundle_hash"] != bundle_hash
                    or row["preview_hash"] != preview_hash
                ):
                    raise SourceError("source_intake_operation_conflict")
                database.commit()
            except BaseException:
                database.rollback()
                raise
        row = self._intake_row(operation_id)
        if row is None:
            raise SourceError("source_intake_journal_corrupt")
        return row

    def _advance_intake(self, operation_id: str, state: str) -> None:
        ranks = {
            "prepared": 0,
            "blobs": 1,
            "events": 2,
            "decisions": 3,
            "committed": 4,
        }
        if state not in ranks:
            raise SourceError("invalid_source_intake_state")
        with self.cas._database() as database:
            database.execute("BEGIN IMMEDIATE")
            try:
                row = database.execute(
                    "SELECT state FROM source_intake WHERE operation_id=?",
                    (operation_id,),
                ).fetchone()
                if row is None or row["state"] not in ranks:
                    raise SourceError("source_intake_journal_corrupt")
                if ranks[str(row["state"])] < ranks[state]:
                    database.execute(
                        "UPDATE source_intake SET state=? WHERE operation_id=?",
                        (state, operation_id),
                    )
                database.commit()
            except BaseException:
                database.rollback()
                raise

    def _commit_intake(
        self, operation_id: str, result: Mapping[str, Any]
    ) -> dict[str, Any]:
        raw = _canonical(result, "invalid_source_pull_result")
        with self.cas._database() as database:
            database.execute("BEGIN IMMEDIATE")
            try:
                row = database.execute(
                    "SELECT state, result_json FROM source_intake WHERE operation_id=?",
                    (operation_id,),
                ).fetchone()
                if row is None:
                    raise SourceError("source_intake_journal_corrupt")
                if row["state"] == "committed":
                    if bytes(row["result_json"]) != raw:
                        raise SourceError("source_intake_result_conflict")
                else:
                    database.execute(
                        "UPDATE source_intake SET state='committed', result_json=? "
                        "WHERE operation_id=?",
                        (raw, operation_id),
                    )
                database.commit()
            except BaseException:
                database.rollback()
                raise
        return copy.deepcopy(dict(result))

    @staticmethod
    def _validate_incoming_preview(value: Any) -> dict[str, Any]:
        fields = {
            "bundle_hash",
            "local_cursor_hash",
            "preview_hash",
            "results",
            "schema",
        }
        row = _closed(value, fields, "invalid_source_incoming_preview")
        if row["schema"] != "dm.source-incoming-preview/v0":
            raise SourceError("invalid_source_incoming_preview")
        _hash43(row["bundle_hash"], "invalid_source_incoming_preview")
        _hash43(row["preview_hash"], "invalid_source_incoming_preview")
        if row["local_cursor_hash"] is not None:
            _event_hash(row["local_cursor_hash"], "invalid_source_incoming_preview")
        if not isinstance(row["results"], list) or len(row["results"]) > 4096:
            raise SourceError("invalid_source_incoming_preview")
        core = {
            "bundle_hash": row["bundle_hash"],
            "local_cursor_hash": row["local_cursor_hash"],
            "results": copy.deepcopy(row["results"]),
        }
        if row["preview_hash"] != b64url(
            digest("daimon/source-incoming-preview/v0", core)
        ):
            raise SourceError("source_incoming_preview_hash_mismatch")
        return copy.deepcopy(dict(row))

    def _initial_import_decisions(
        self,
        bundle: Mapping[str, Any],
        preview: Mapping[str, Any],
        *,
        signer: Any,
        created_at_ms: int,
    ) -> list[dict[str, Any]]:
        starting_hash = preview["local_cursor_hash"]
        if starting_hash is None:
            raise SourceError("source_pull_requires_signed_cursor")
        starting_cursor = next(
            (
                event
                for event in self._events()
                if event["kind"] == CURSOR_EVENT_KIND
                and event["being_ref"] == self.local_me_id
                and event["content_hash"] == starting_hash
            ),
            None,
        )
        if starting_cursor is None:
            raise SourceError("source_pull_starting_cursor_missing")
        policy = {
            "mode": "initial-quarantine-only",
            "schema": "daimon-source-import-policy/v0",
            "target_memory_category": None,
        }
        policy_ref = self.cas.put_json(
            policy, "application/vnd.daimon.source-import-policy.v0+json"
        )
        result_by_hash = {row["item_hash"]: row for row in preview["results"]}
        decisions: list[dict[str, Any]] = []
        publication_candidates: dict[str, tuple[dict[str, Any], Mapping[str, Any]]] = {}
        for item in bundle["items"]:
            outcome = result_by_hash[item["item_hash"]]["outcome"]
            if outcome not in {
                "admissible-claim-candidate",
                "admissible-publication-candidate",
                "already-present",
            }:
                continue
            publication_events = [
                event
                for event in item["events"]
                if event["kind"] == PUBLICATION_EVENT_KIND
                and event["subject"] == bundle["selector"]["source_id"]
            ]
            for series, lane in self._publication_lanes(publication_events).items():
                if (
                    lane.state == "current"
                    and lane.current is not None
                    and lane.current["payload"]["action"] == "publish"
                ):
                    publication_candidates.setdefault(
                        series, (copy.deepcopy(dict(lane.current)), item)
                    )
        for publication_identifier in sorted(publication_candidates):
            publication, item = publication_candidates[publication_identifier]
            payload = publication["payload"]
            claim_ids = sorted(
                {
                    event["event_id"]
                    for event in item["events"]
                    if event["kind"] == CLAIM_EVENT_KIND
                    and event["payload"]["source_id"] == payload["source_id"]
                    and event["payload"]["action"] == "assert"
                    and event["event_id"] == payload["publisher_claim_event_id"]
                }
            )
            if not claim_ids:
                raise SourceError("source_import_claims_missing", incomplete=True)
            content_refs = sorted(
                [validate_content_ref(blob["reference"]) for blob in item["blobs"]],
                key=canonical_bytes,
            )
            snapshot = {
                "artifact_refs": [],
                "claim_event_ids": claim_ids,
                "content_refs": content_refs,
                "contradiction_refs": [],
                "observed_cursor_event_hash": starting_cursor["content_hash"],
                "observed_cursor_event_id": starting_cursor["event_id"],
                "schema": SNAPSHOT_SCHEMA,
                "source_id": payload["source_id"],
                "subject": {
                    "event_hash": publication["content_hash"],
                    "event_id": publication["event_id"],
                    "id": payload["publication_id"],
                    "kind": "publication",
                },
            }
            snapshot_ref = self.cas.put_json(
                snapshot,
                "application/vnd.daimon.source-policy-evidence-snapshot.v0+json",
            )
            series = import_series_id(self.local_me_id, payload["publication_id"])
            existing = self._import_lanes(self._events()).get(series)
            decision_sequence = 0
            previous_decision_event_id = None
            if existing is not None:
                if (
                    existing.state == "current"
                    and existing.current is not None
                    and existing.current["payload"]["publication_event_id"]
                    == publication["event_id"]
                ):
                    decisions.append(copy.deepcopy(dict(existing.current)))
                    continue
                if existing.state != "current" or existing.current is None:
                    raise SourceError("source_import_series_conflict")
                decision_sequence = (
                    int(existing.current["payload"]["decision_sequence"]) + 1
                )
                previous_decision_event_id = existing.current["event_id"]
            decision_payload = {
                "content_ref": payload["content_ref"],
                "decided_at_ms": created_at_ms,
                "decision": "quarantined",
                "decision_sequence": decision_sequence,
                "decision_series_id": series,
                "evidence_snapshot_ref": snapshot_ref,
                "policy_ref": policy_ref,
                "previous_decision_event_id": previous_decision_event_id,
                "provenance_manifest_ref": payload["provenance_manifest_ref"],
                "publication_event_hash": publication["content_hash"],
                "publication_event_id": publication["event_id"],
                "publication_id": payload["publication_id"],
                "reason_codes": ["quarantined:initial-pull"],
                "receiver_me_id": self.local_me_id,
                "schema": IMPORT_SCHEMA,
                "source_claim_event_ids": claim_ids,
                "source_id": payload["source_id"],
                "target_memory_category": None,
            }
            decisions.append(
                self.append_import_decision(decision_payload, signer=signer)
            )
        return decisions

    @_serialized_source_operation
    def pull(
        self,
        *,
        operation_id: str,
        bundle: Mapping[str, Any],
        preview: Mapping[str, Any],
        signer: Any,
        _fault_after_stage: str | None = None,
    ) -> dict[str, Any]:
        """Crash-resumably land a preview in quarantine, never promotion."""

        operation = _uuid(operation_id, "invalid_source_operation_id")
        normalized_bundle = self._validate_diff_bundle(bundle)
        normalized_preview = self._validate_incoming_preview(preview)
        if normalized_preview["bundle_hash"] != normalized_bundle["bundle_hash"]:
            raise SourceError("source_pull_preview_bundle_mismatch")
        if normalized_bundle["requester_me_id"] != self.local_me_id:
            raise SourceError("source_diff_wrong_receiver")
        with self._intake_lock():
            journal = self._intake_row(operation)
            if journal is None:
                fresh = self.incoming(normalized_bundle)
                if fresh != normalized_preview:
                    raise SourceError("source_pull_preview_stale", retryable=True)
                journal = self._begin_intake(
                    operation,
                    normalized_bundle["bundle_hash"],
                    normalized_preview["preview_hash"],
                    int(self.clock()),
                )
            elif (
                journal["bundle_hash"] != normalized_bundle["bundle_hash"]
                or journal["preview_hash"] != normalized_preview["preview_hash"]
            ):
                raise SourceError("source_intake_operation_conflict")
            if journal["state"] == "committed":
                result = journal["result"]
                if not isinstance(result, Mapping):
                    raise SourceError("source_intake_journal_corrupt")
                return copy.deepcopy(dict(result))
            if _fault_after_stage == "prepared" and journal["state"] == "prepared":
                raise SourceError("source_pull_fault_injected", retryable=True)
            created_at_ms = int(journal["created_at_ms"])
            stages = {"prepared": 0, "blobs": 1, "events": 2, "decisions": 3}
            current_stage = stages[str(journal["state"])]
            result_by_hash = {
                row["item_hash"]: row for row in normalized_preview["results"]
            }
            landing_items = [
                item
                for item in normalized_bundle["items"]
                if result_by_hash[item["item_hash"]]["outcome"]
                not in {"incomplete", "rejected"}
            ]
            landing_bundle = {**normalized_bundle, "items": landing_items}
            blobs = self._bundle_blob_map(landing_bundle)
            events = self._bundle_event_map(landing_bundle)
            if current_stage < stages["blobs"]:
                for reference, raw in blobs.values():
                    stored = self.cas.put(raw, reference["media_type"])
                    if stored != reference:
                        raise SourceError("source_pull_blob_mismatch")
                self._advance_intake(operation, "blobs")
                current_stage = stages["blobs"]
                if _fault_after_stage == "blobs":
                    raise SourceError("source_pull_fault_injected", retryable=True)
            if current_stage < stages["events"]:
                by_being: dict[str, list[dict[str, Any]]] = {}
                for event in events.values():
                    by_being.setdefault(event["being_ref"], []).append(event)
                for being_ref in sorted(by_being):
                    ledger = self.known_ledgers[being_ref]
                    ordered = sorted(
                        by_being[being_ref],
                        key=lambda event: (
                            event["origin"]["incarnation_id"],
                            event["sequence"],
                            event["event_id"],
                        ),
                    )
                    for index in range(0, len(ordered), 256):
                        ledger.ingest(
                            ordered[index : index + 256],
                            source=f"dm.source:{normalized_bundle['responder_me_id']}",
                        )
                self._advance_intake(operation, "events")
                current_stage = stages["events"]
                if _fault_after_stage == "events":
                    raise SourceError("source_pull_fault_injected", retryable=True)
            decisions = self._initial_import_decisions(
                landing_bundle,
                normalized_preview,
                signer=signer,
                created_at_ms=created_at_ms,
            )
            if current_stage < stages["decisions"]:
                self._advance_intake(operation, "decisions")
                if _fault_after_stage == "decisions":
                    raise SourceError("source_pull_fault_injected", retryable=True)
            # A continuation page is one durable prefix of a frozen diff.  Its
            # starting cursor must remain current so the next content-bound
            # page can still be previewed.  Only the terminal page advances the
            # receiver cursor over the complete accepted prefix.
            if normalized_bundle["continuation"] is None:
                achieved = self.create_cursor(
                    normalized_bundle["selector"],
                    signer=signer,
                    occurred_at_ms=created_at_ms,
                    operation_id=operation,
                )["event"]
                achieved_cursor_hash = achieved["content_hash"]
                if _fault_after_stage == "cursor":
                    raise SourceError("source_pull_fault_injected", retryable=True)
            else:
                achieved_cursor_hash = normalized_preview["local_cursor_hash"]
            pull_outcomes = []
            for preview_result in normalized_preview["results"]:
                pull_result = copy.deepcopy(preview_result)
                if pull_result["outcome"] in {
                    "admissible-claim-candidate",
                    "admissible-publication-candidate",
                }:
                    pull_result["outcome"] = "admitted-to-quarantine"
                pull_outcomes.append(pull_result)
            result = {
                "accepted_event_ids": sorted(
                    event_id
                    for event_id, event in events.items()
                    if event["kind"] in {CLAIM_EVENT_KIND, PUBLICATION_EVENT_KIND}
                    and event["subject"] == normalized_bundle["selector"]["source_id"]
                ),
                "achieved_cursor_hash": achieved_cursor_hash,
                "bundle_hash": normalized_bundle["bundle_hash"],
                "decision_event_ids": sorted(
                    {event["event_id"] for event in decisions}
                ),
                "offered_cursor_hash": normalized_bundle["responder_cursor"]["event"][
                    "content_hash"
                ],
                "operation_id": operation,
                "outcomes": pull_outcomes,
                "page_hash": normalized_bundle["page_hash"],
                "page_index": normalized_bundle["page_index"],
                "previous_page_hash": normalized_bundle["previous_page_hash"],
                "request_event_id": normalized_bundle["request_event_id"],
                "schema": "dm.source-pull-result/v0",
                "starting_cursor_hash": normalized_preview["local_cursor_hash"],
            }
            return self._commit_intake(operation, result)

    @_serialized_source_operation
    def promote(
        self,
        *,
        publication_identifier: str,
        policy_ref: Mapping[str, Any],
        evidence_snapshot_ref: Mapping[str, Any],
        signer: Any,
        decided_at_ms: int | None = None,
    ) -> dict[str, Any]:
        """Separately promote quarantined knowledge as external-reference only."""

        publication_id_value = _typed_id(
            publication_identifier, _PUBLICATION_ID, "invalid_publication_id"
        )
        events = self._events()
        claims = self._claim_lanes(events)
        publication_lane = self._publication_lanes(events).get(publication_id_value)
        if publication_lane is None:
            raise SourceError("source_publication_missing", incomplete=True)
        publication_state, _, publication = self._publication_state(
            publication_lane, claims, now_ms=int(self.clock())
        )
        if publication_state != "published" or publication is None:
            raise SourceError("source_publication_not_promotable")
        payload = publication["payload"]
        decision_series = import_series_id(self.local_me_id, publication_id_value)
        import_lane = self._import_lanes(events).get(decision_series)
        if (
            import_lane is None
            or import_lane.state != "current"
            or import_lane.current is None
            or import_lane.current["payload"]["decision"] != "quarantined"
        ):
            raise SourceError("source_import_not_quarantined")
        previous = import_lane.current
        previous_payload = previous["payload"]
        assessments = self._assessment_lanes(events)
        for claim_event_id in previous_payload["source_claim_event_ids"]:
            claim = self._event(claim_event_id)
            if claim is None:
                raise SourceError("source_import_claim_missing", incomplete=True)
            lane = claims.get(claim["payload"]["claim_series_id"])
            if lane is None:
                raise SourceError("source_import_claim_missing", incomplete=True)
            disposition, _, _ = self._assessment_state(
                lane, assessments, now_ms=int(self.clock())
            )
            if disposition != "admitted":
                raise SourceError("source_import_claim_not_admitted")
        normalized_policy_ref = validate_content_ref(policy_ref)
        policy = self.cas.get_json(normalized_policy_ref)
        validate_promotion_policy(policy)
        if (
            policy["publication_id"] != publication_id_value
            or policy["publication_event_id"] != publication["event_id"]
            or policy["publication_event_hash"] != publication["content_hash"]
            or policy["content_ref"] != payload["content_ref"]
            or policy["provenance_manifest_ref"] != payload["provenance_manifest_ref"]
            or policy["classification"] != payload["classification"]
            or policy["consent"] != payload["consent"]
            or policy["license"] != payload["license"]
        ):
            raise SourceError("source_promotion_policy_mismatch")
        normalized_snapshot_ref = validate_content_ref(evidence_snapshot_ref)
        snapshot = self.cas.get_json(normalized_snapshot_ref)
        validate_policy_snapshot(snapshot)
        cursor = self._event(snapshot["observed_cursor_event_id"])
        if (
            snapshot["subject"]
            != {
                "event_hash": publication["content_hash"],
                "event_id": publication["event_id"],
                "id": publication_id_value,
                "kind": "publication",
            }
            or snapshot["source_id"] != payload["source_id"]
            or set(snapshot["claim_event_ids"])
            != set(previous_payload["source_claim_event_ids"])
            or cursor is None
            or cursor["kind"] != CURSOR_EVENT_KIND
            or cursor["being_ref"] != self.local_me_id
            or cursor["content_hash"] != snapshot["observed_cursor_event_hash"]
        ):
            raise SourceError("source_promotion_snapshot_mismatch")
        timestamp = int(self.clock()) if decided_at_ms is None else decided_at_ms
        promoted_payload = {
            **copy.deepcopy(previous_payload),
            "decided_at_ms": timestamp,
            "decision": "promoted",
            "decision_sequence": previous_payload["decision_sequence"] + 1,
            "evidence_snapshot_ref": normalized_snapshot_ref,
            "policy_ref": normalized_policy_ref,
            "previous_decision_event_id": previous["event_id"],
            "reason_codes": ["promoted:policy-and-review-satisfied"],
            "target_memory_category": "external-reference",
        }
        decision = self.append_import_decision(promoted_payload, signer=signer)
        return {
            "decision": decision,
            "projection": self.promotion_projection(publication_id_value),
        }

    @_serialized_source_operation
    def promotion_projection(self, publication_identifier: str) -> dict[str, Any]:
        """Rebuild the attributed external-reference projection from signed state."""

        publication_id_value = _typed_id(
            publication_identifier, _PUBLICATION_ID, "invalid_publication_id"
        )
        events = self._events()
        claims = self._claim_lanes(events)
        publication_lane = self._publication_lanes(events).get(publication_id_value)
        import_lane = self._import_lanes(events).get(
            import_series_id(self.local_me_id, publication_id_value)
        )
        if (
            publication_lane is None
            or import_lane is None
            or import_lane.state != "current"
            or import_lane.current is None
            or import_lane.current["payload"]["decision"] != "promoted"
        ):
            raise SourceError("source_projection_not_promoted")
        state, reasons, publication = self._publication_state(
            publication_lane, claims, now_ms=int(self.clock())
        )
        decision = import_lane.current
        decision_payload = decision["payload"]
        if publication is None:
            raise SourceError("source_projection_publication_missing", incomplete=True)
        decided_publication = self._event(decision_payload["publication_event_id"])
        if (
            decided_publication is None
            or decided_publication["kind"] != PUBLICATION_EVENT_KIND
            or decided_publication["content_hash"]
            != decision_payload["publication_event_hash"]
        ):
            raise SourceError("source_projection_publication_missing", incomplete=True)
        publication_payload = decided_publication["payload"]
        provenance = self.cas.get_json(decision_payload["provenance_manifest_ref"])
        validate_provenance_manifest(provenance, publication_payload)
        source_uri = publication_payload["source_uri"]
        authors = [
            {
                "node_id": node["node_id"],
                "authors": copy.deepcopy(node["authors"]),
            }
            for node in provenance["nodes"]
        ]
        return {
            "active": state == "published",
            "authors": authors,
            "content_ref": copy.deepcopy(decision_payload["content_ref"]),
            "decision_event_hash": decision["content_hash"],
            "decision_event_id": decision["event_id"],
            "provenance_manifest_ref": copy.deepcopy(
                decision_payload["provenance_manifest_ref"]
            ),
            "publication_event_hash": decision_payload["publication_event_hash"],
            "publication_event_id": decision_payload["publication_event_id"],
            "publication_id": publication_id_value,
            "reason_codes": reasons,
            "receiver_me_id": self.local_me_id,
            "schema": "dm.source-promotion-projection/v0",
            "source_id": decision_payload["source_id"],
            "source_uri": source_uri,
            "target_memory_category": "external-reference",
        }

    @_serialized_source_operation
    def append_claim(
        self, payload: Mapping[str, Any], *, signer: Any
    ) -> dict[str, Any]:
        """Author one self-claim only after its exact evidence is locally complete."""

        normalized = validate_claim_payload(payload)
        if normalized["claimant_me_id"] != self.local_me_id:
            raise SourceError("false_source_self")
        position = normalized["claimant_control_position"]
        if (
            position["manifest_hash"] != self.ledger.authority.manifest.digest
            or position["embodiment_id"] != self.ledger.local_origin["embodiment_id"]
            or position["incarnation_id"] != self.ledger.local_origin["incarnation_id"]
        ):
            raise SourceError("source_control_position_mismatch")
        existing_rows = self._group(
            self._events(), CLAIM_EVENT_KIND, "claim_series_id"
        ).get(normalized["claim_series_id"])
        existing = (
            None
            if existing_rows is None
            else self._ordered_lane(
                existing_rows,
                sequence_field="claim_sequence",
                predecessor_field="previous_claim_event_id",
                predecessor_hash_field="previous_claim_event_hash",
                stable_fields=(
                    "claim_series_id",
                    "claimant_me_id",
                    "source_core",
                    "source_id",
                ),
                retraction_relations=True,
            )
        )
        predecessor: Mapping[str, Any] | None = None
        if existing is None:
            if normalized["claim_sequence"] != 0:
                raise SourceError("claim_sequence_gap")
        else:
            if existing.state != "current" or existing.current is None:
                raise SourceError("claim_series_quarantined")
            predecessor = existing.current
            if (
                normalized["claim_sequence"]
                != predecessor["payload"]["claim_sequence"] + 1
                or normalized["previous_claim_event_id"] != predecessor["event_id"]
                or normalized["previous_claim_event_hash"]
                != predecessor["content_hash"]
            ):
                raise SourceError("claim_predecessor_mismatch")
            if (
                normalized["action"] == "retract"
                and normalized["relations"] != predecessor["payload"]["relations"]
            ):
                raise SourceError("claim_retraction_relation_mismatch")
        if normalized["action"] == "assert":
            synthetic = {
                "payload": normalized,
            }
            complete, missing = self._evidence_complete(synthetic)
            if not complete:
                raise SourceError(
                    "claim_evidence_incomplete:" + ",".join(missing), incomplete=True
                )
        event = self.ledger.append_local(
            kind=CLAIM_EVENT_KIND,
            subject=normalized["source_id"],
            payload=normalized,
            signer=signer,
            sensitivity="private",
            causal_parents=([] if predecessor is None else [predecessor["event_id"]]),
            occurred_at_ms=normalized["issued_at_ms"],
        )
        return copy.deepcopy(dict(event))

    @_serialized_source_operation
    def append_assessment(
        self, payload: Mapping[str, Any], *, signer: Any
    ) -> dict[str, Any]:
        """Author a receiver-local disposition without changing claim validity."""

        normalized = validate_assessment_payload(payload)
        if normalized["assessor_me_id"] != self.local_me_id:
            raise SourceError("false_source_self")
        claim = self._event(normalized["claim_event_id"])
        if (
            claim is None
            or claim["kind"] != CLAIM_EVENT_KIND
            or claim["content_hash"] != normalized["claim_event_hash"]
            or claim["payload"]["source_id"] != normalized["source_id"]
            or claim["payload"]["claimant_me_id"] != normalized["claimant_me_id"]
            or claim["payload"]["evidence_manifest_ref"]
            != normalized["evidence_manifest_ref"]
        ):
            raise SourceError("assessment_claim_mismatch", incomplete=claim is None)
        claim_lane = self._claim_lanes(self._events()).get(
            claim["payload"]["claim_series_id"]
        )
        if (
            claim_lane is None
            or claim_lane.state != "current"
            or claim_lane.current is None
            or claim_lane.current["event_id"] != claim["event_id"]
        ):
            raise SourceError("assessment_claim_not_current")
        snapshot = self.cas.get_json(normalized["evidence_snapshot_ref"])
        validate_policy_snapshot(snapshot)
        self.cas.get(normalized["policy_ref"])
        self.cas.get(normalized["evidence_manifest_ref"])
        subject = snapshot["subject"]
        cursor = self._event(snapshot["observed_cursor_event_id"])
        if (
            subject
            != {
                "event_hash": claim["content_hash"],
                "event_id": claim["event_id"],
                "id": claim["payload"]["claim_series_id"],
                "kind": "claim",
            }
            or snapshot["source_id"] != normalized["source_id"]
            or claim["event_id"] not in snapshot["claim_event_ids"]
            or cursor is None
            or cursor["kind"] != CURSOR_EVENT_KIND
            or cursor["being_ref"] != self.local_me_id
            or cursor["content_hash"] != snapshot["observed_cursor_event_hash"]
        ):
            raise SourceError("assessment_snapshot_mismatch")
        lanes = self._assessment_lanes(self._events())
        existing = lanes.get(normalized["assessment_series_id"])
        predecessor: Mapping[str, Any] | None = None
        if existing is None:
            if normalized["assessment_sequence"] != 0:
                raise SourceError("assessment_sequence_gap")
        else:
            if existing.state != "current" or existing.current is None:
                raise SourceError("assessment_series_quarantined")
            predecessor = existing.current
            if (
                normalized["assessment_sequence"]
                != predecessor["payload"]["assessment_sequence"] + 1
                or normalized["previous_assessment_event_id"] != predecessor["event_id"]
            ):
                raise SourceError("assessment_predecessor_mismatch")
        event = self.ledger.append_local(
            kind=ASSESSMENT_EVENT_KIND,
            subject=normalized["source_id"],
            payload=normalized,
            signer=signer,
            sensitivity="private",
            causal_parents=([] if predecessor is None else [predecessor["event_id"]]),
            occurred_at_ms=normalized["decided_at_ms"],
        )
        return copy.deepcopy(dict(event))

    @_serialized_source_operation
    def append_publication(
        self, payload: Mapping[str, Any], *, signer: Any
    ) -> dict[str, Any]:
        """Author a publication/tombstone after current self-claim validation."""

        normalized = validate_publication_payload(payload)
        if normalized["publisher_me_id"] != self.local_me_id:
            raise SourceError("false_source_self")
        claim = self._event(normalized["publisher_claim_event_id"])
        claims = self._claim_lanes(self._events())
        claim_lane = claims.get(
            claim_series_id(self.local_me_id, normalized["source_id"])
        )
        if (
            claim is None
            or claim["kind"] != CLAIM_EVENT_KIND
            or claim["being_ref"] != self.local_me_id
            or claim_lane is None
            or claim_lane.state != "current"
            or claim_lane.current is None
            or (
                normalized["action"] == "publish"
                and (
                    claim_lane.current["event_id"] != claim["event_id"]
                    or claim["payload"]["action"] != "assert"
                    or (
                        claim["payload"]["expires_at_ms"] is not None
                        and claim["payload"]["expires_at_ms"] <= int(self.clock())
                    )
                )
            )
        ):
            raise SourceError("publication_claim_not_current", incomplete=claim is None)
        lanes = self._publication_lanes(self._events())
        existing = lanes.get(normalized["publication_id"])
        predecessor: Mapping[str, Any] | None = None
        if existing is None:
            if normalized["publication_sequence"] != 0:
                raise SourceError("publication_sequence_gap")
        else:
            if existing.state != "current" or existing.current is None:
                raise SourceError("publication_series_quarantined")
            predecessor = existing.current
            if (
                normalized["publication_sequence"]
                != predecessor["payload"]["publication_sequence"] + 1
                or normalized["previous_publication_event_id"]
                != predecessor["event_id"]
                or normalized["previous_publication_event_hash"]
                != predecessor["content_hash"]
            ):
                raise SourceError("publication_predecessor_mismatch")
        if normalized["action"] == "publish":
            self.cas.get(normalized["content_ref"])
            provenance = self.cas.get_json(normalized["provenance_manifest_ref"])
            validate_provenance_manifest(provenance, normalized)
            complete, missing = self._provenance_complete(provenance)
            if not complete:
                raise SourceError(
                    "publication_provenance_incomplete:" + ",".join(missing),
                    incomplete=True,
                )
        causal = {claim["event_id"]}
        if predecessor is not None:
            causal.add(predecessor["event_id"])
        event = self.ledger.append_local(
            kind=PUBLICATION_EVENT_KIND,
            subject=normalized["source_id"],
            payload=normalized,
            signer=signer,
            sensitivity=(
                "shareable" if normalized["classification"] == "public" else "private"
            ),
            causal_parents=sorted(causal),
            occurred_at_ms=normalized["issued_at_ms"],
        )
        return copy.deepcopy(dict(event))

    @_serialized_source_operation
    def append_import_decision(
        self, payload: Mapping[str, Any], *, signer: Any
    ) -> dict[str, Any]:
        """Author one local import transition after exact foreign evidence checks."""

        normalized = validate_import_payload(payload)
        if normalized["receiver_me_id"] != self.local_me_id:
            raise SourceError("false_source_self")
        publication = self._event(normalized["publication_event_id"])
        if (
            publication is None
            or publication["kind"] != PUBLICATION_EVENT_KIND
            or publication["content_hash"] != normalized["publication_event_hash"]
            or publication["payload"]["publication_id"] != normalized["publication_id"]
            or publication["payload"]["source_id"] != normalized["source_id"]
            or publication["payload"]["content_ref"] != normalized["content_ref"]
            or publication["payload"]["provenance_manifest_ref"]
            != normalized["provenance_manifest_ref"]
        ):
            raise SourceError(
                "import_publication_mismatch", incomplete=publication is None
            )
        for event_id in normalized["source_claim_event_ids"]:
            claim = self._event(event_id)
            if (
                claim is None
                or claim["kind"] != CLAIM_EVENT_KIND
                or claim["payload"]["source_id"] != normalized["source_id"]
            ):
                raise SourceError("import_claim_mismatch", incomplete=claim is None)
        self.cas.get(normalized["content_ref"])
        provenance = self.cas.get_json(normalized["provenance_manifest_ref"])
        validate_provenance_manifest(provenance, publication["payload"])
        self.cas.get(normalized["policy_ref"])
        snapshot = self.cas.get_json(normalized["evidence_snapshot_ref"])
        validate_policy_snapshot(snapshot)
        if (
            snapshot["subject"]
            != {
                "event_hash": publication["content_hash"],
                "event_id": publication["event_id"],
                "id": publication["payload"]["publication_id"],
                "kind": "publication",
            }
            or snapshot["source_id"] != normalized["source_id"]
            or set(snapshot["claim_event_ids"])
            != set(normalized["source_claim_event_ids"])
        ):
            raise SourceError("import_snapshot_mismatch")
        lanes = self._import_lanes(self._events())
        existing = lanes.get(normalized["decision_series_id"])
        predecessor: Mapping[str, Any] | None = None
        if existing is None:
            if normalized["decision_sequence"] != 0:
                raise SourceError("import_sequence_gap")
        else:
            if existing.state != "current" or existing.current is None:
                raise SourceError("import_series_quarantined")
            predecessor = existing.current
            if (
                normalized["decision_sequence"]
                != predecessor["payload"]["decision_sequence"] + 1
                or normalized["previous_decision_event_id"] != predecessor["event_id"]
            ):
                raise SourceError("import_predecessor_mismatch")
        event = self.ledger.append_local(
            kind=IMPORT_EVENT_KIND,
            subject=normalized["source_id"],
            payload=normalized,
            signer=signer,
            sensitivity="private",
            causal_parents=([] if predecessor is None else [predecessor["event_id"]]),
            occurred_at_ms=normalized["decided_at_ms"],
        )
        return copy.deepcopy(dict(event))


__all__ = [
    "ASSESSMENT_EVENT_KIND",
    "CLAIM_EVENT_KIND",
    "CURSOR_EVENT_KIND",
    "IMPORT_EVENT_KIND",
    "PUBLICATION_EVENT_KIND",
    "SOURCE_EVENT_KINDS",
    "SourceCAS",
    "SourceError",
    "SourceRegistry",
    "SourceServiceContext",
    "assessment_series_id",
    "claim_series_id",
    "import_series_id",
    "provenance_node_id",
    "publication_binding_hash",
    "publication_id",
    "source_claim_binding_hash",
    "source_content_ref",
    "source_id",
    "source_selector",
    "validate_assessment_payload",
    "validate_claim_payload",
    "validate_content_ref",
    "validate_cursor_page",
    "validate_cursor_payload",
    "validate_evidence_manifest",
    "validate_import_payload",
    "validate_policy_snapshot",
    "validate_provenance_manifest",
    "validate_publication_payload",
    "validate_source_core",
    "validate_source_event_payload",
    "validate_source_selector",
    "verify_content",
]
