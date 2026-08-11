"""Separated collective-memory source and reviewed-publication adapters.

The inbound adapter imports immutable exchange generations into an owner-local
source log and authors one Matrix quarantine receipt.  The outbound adapter
submits only exact reviewed derived bytes to the pinned collective-memory
publication transaction.  The two adapters deliberately have different
identities, transports, stores and idempotency domains.
"""

from __future__ import annotations

import copy
import datetime as dt
import fcntl
import hashlib
import json
import os
import re
import sqlite3
import stat
import unicodedata
import uuid
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import closing, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Protocol, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .canonical import CanonicalError, b64url, canonical_bytes, unb64url
from .ledger import Ledger
from .weave import Event, EventSigner

COLLECTIVE_MEMORY_COMMIT: Final = "3e3b39416917f8e3c2bc5ca69362b20296205938"
COLLECTIVE_SCHEMA_SHA256: Final = (
    "2aad43d1b309ee95108c855fc8dc682a854e5fdf3a1e799ecfca96d3ebf7c5d9"
)
COLLECTIVE_CONTRACT_VERSION: Final = "v1"

SOURCE_ADAPTER_ID: Final = "dm:adapter:v0:Sh-2fDC4rpFOZz_ddjWqLptoX2SgUUzJPKhe6XQOtj8"
PUBLISHER_ADAPTER_ID: Final = (
    "dm:adapter:v0:Jsug9D2N641xJwE5Q_oLaHDy0wxT5knRJfxzV2ZEOXc"
)
SOURCE_IMPORTER_VERSION: Final = "daimon-matrix-collective-source/1.0.0"
PUBLISHER_VERSION: Final = "daimon-matrix-collective-publisher/1.0.0"

EXPORT_MANIFEST_SCHEMA: Final = "collective-export-manifest/v1"
EXPORT_PAGE_SCHEMA: Final = "collective-export-page/v1"
PUBLICATION_DRAFT_SCHEMA: Final = "collective-publication-draft/v1"
PUBLICATION_PREVIEW_SCHEMA: Final = "collective-publication-preview/v1"
PUBLICATION_EVIDENCE_SCHEMA: Final = "collective-publication-evidence/v1"
PUBLICATION_REQUEST_SCHEMA: Final = "collective-publication-request/v1"
PUBLICATION_PLAN_SCHEMA: Final = "collective-publication-plan/v1"
PUBLICATION_RECEIPT_SCHEMA: Final = "collective-publication-receipt/v1"
PUBLICATION_RECONCILIATION_SCHEMA: Final = "collective-publication-reconciliation/v1"

SOURCE_PROFILE_SCHEMA: Final = "dm.collective-source.profile/v1"
SOURCE_PREVIEW_SCHEMA: Final = "dm.collective-source.preview/v1"
SOURCE_RECEIPT_SCHEMA: Final = "dm.collective-source.receipt/v1"
PUBLISHER_PROFILE_SCHEMA: Final = "dm.collective-publisher.profile/v1"
PUBLISHER_REQUEST_SCHEMA: Final = "dm.collective-publisher.request/v1"
PUBLISHER_ACCEPTANCE_SCHEMA: Final = "dm.collective-publisher.acceptance/v1"

MAX_ARTIFACTS: Final = 4096
MAX_ARTIFACT_BYTES: Final = 2 * 1024 * 1024
MAX_EXPORT_BYTES: Final = 64 * 1024 * 1024
MAX_PUBLICATION_BYTES: Final = 1024 * 1024
MAX_PAGE: Final = 256
MAX_SOURCE_REFS: Final = 128
MAX_DOCUMENT_BYTES: Final = 70 * 1024 * 1024
MAX_SAFE_INTEGER: Final = 2**53 - 1

_HASH = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+\-]{0,255}$")
_B64_HASH = re.compile(r"^[A-Za-z0-9_-]{43}$")
_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$")
_SECRET_PATTERNS: Final = (
    re.compile(rb"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"),
    re.compile(rb"\bBearer\s+[A-Za-z0-9._~+/=-]{24,}\b", re.IGNORECASE),
    re.compile(rb"\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(rb"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    re.compile(rb"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(
        rb"\b(password|passwd|api_key|apikey|token)\b\s*[:=]\s*['\"]?[^'\"\s]{8,}",
        re.IGNORECASE,
    ),
    re.compile(rb"[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s@]+@[^/\s]+", re.IGNORECASE),
)

SOURCE_PREVIEW_DOMAIN: Final = b"daimon/collective-source-preview/v1\x00"
SOURCE_RECEIPT_DOMAIN: Final = b"daimon/collective-source-receipt/v1\x00"
PUBLISHER_REQUEST_DOMAIN: Final = b"daimon/collective-publisher-request/v1\x00"
PUBLISHER_ACCEPTANCE_DOMAIN: Final = b"daimon/collective-publisher-acceptance/v1\x00"
SOURCE_ADAPTER_DOMAIN: Final = b"daimon/collective-source/adapter/v1\x00"
PUBLISHER_ADAPTER_DOMAIN: Final = b"daimon/collective-publisher/adapter/v1\x00"


class CollectiveMemoryError(RuntimeError):
    """Stable fail-closed collective-memory adapter error."""

    def __init__(self, code: str, *, retryable: bool = False) -> None:
        super().__init__(code)
        self.code = code
        self.retryable = retryable


class SourceTransport(Protocol):
    """Injected read-only transport; credentials remain implementation-private."""

    def __call__(
        self, operation: str, document: Mapping[str, Any]
    ) -> Mapping[str, Any] | bytes: ...


class PublisherTransport(Protocol):
    """Injected write-only reviewed publisher transport."""

    def __call__(
        self, operation: str, document: Mapping[str, Any]
    ) -> Mapping[str, Any]: ...


Clock = Callable[[], int]
Fault = Callable[[str], None]


def _no_fault(_stage: str) -> None:
    return None


def _canonical(value: Any, code: str) -> bytes:
    try:
        raw = canonical_bytes(value)
    except CanonicalError as exception:
        raise CollectiveMemoryError(code) from exception
    if len(raw) > MAX_DOCUMENT_BYTES:
        raise CollectiveMemoryError("collective_document_too_large")
    return raw


def _closed(value: Any, fields: set[str], code: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise CollectiveMemoryError(code)
    return value


def _text(value: Any, code: str, *, maximum: int = 256, empty: bool = False) -> str:
    if not isinstance(value, str):
        raise CollectiveMemoryError(code)
    raw = value.encode("utf-8")
    if (not empty and not raw) or len(raw) > maximum:
        raise CollectiveMemoryError(code)
    if unicodedata.normalize("NFC", value) != value or any(
        0xD800 <= ord(character) <= 0xDFFF for character in value
    ):
        raise CollectiveMemoryError(code)
    return value


def _identifier(value: Any, code: str) -> str:
    result = _text(value, code)
    if _IDENTIFIER.fullmatch(result) is None:
        raise CollectiveMemoryError(code)
    return result


def _hash(value: Any, code: str) -> str:
    if not isinstance(value, str) or _HASH.fullmatch(value) is None:
        raise CollectiveMemoryError(code)
    return value


def _uint(
    value: Any, code: str, *, minimum: int = 0, maximum: int = MAX_SAFE_INTEGER
) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise CollectiveMemoryError(code)
    return value


def _nullable_identifier(value: Any, code: str) -> str | None:
    return None if value is None else _identifier(value, code)


def _nullable_hash(value: Any, code: str) -> str | None:
    return None if value is None else _hash(value, code)


def _timestamp(value: Any, code: str) -> str:
    result = _text(value, code, maximum=40)
    if _UTC.fullmatch(result) is None:
        raise CollectiveMemoryError(code)
    try:
        parsed = dt.datetime.fromisoformat(result.removesuffix("Z") + "+00:00")
    except ValueError as exception:
        raise CollectiveMemoryError(code) from exception
    if parsed.tzinfo != dt.UTC:
        raise CollectiveMemoryError(code)
    return result


def _uuid(value: Any, code: str) -> str:
    if not isinstance(value, str):
        raise CollectiveMemoryError(code)
    try:
        parsed = uuid.UUID(value)
    except ValueError as exception:
        raise CollectiveMemoryError(code) from exception
    if str(parsed) != value:
        raise CollectiveMemoryError(code)
    return value


def _content_id(prefix: str, body: Mapping[str, Any]) -> tuple[str, str]:
    digest = hashlib.sha256(_canonical(body, "invalid_collective_artifact")).digest()
    return f"{prefix}:{b64url(digest)}", digest.hex()


def _derived(prefix: str, domain: bytes, body: Mapping[str, Any]) -> str:
    return prefix + b64url(
        hashlib.sha256(
            domain + _canonical(body, "invalid_collective_artifact")
        ).digest()
    )


def _source_ref(value: Any, code: str) -> dict[str, str]:
    row = _closed(value, {"id", "hash"}, code)
    return {"id": _identifier(row["id"], code), "hash": _hash(row["hash"], code)}


def _checkpoint(value: Any, code: str) -> dict[str, str]:
    return _source_ref(value, code)


def _authority_denial() -> dict[str, bool]:
    return {
        "matrix_authority": False,
        "may_append_ledger": False,
        "may_issue_presence": False,
        "may_mint_membership": False,
        "may_sign_as_me": False,
    }


def create_source_manifest() -> dict[str, Any]:
    core = {
        "authority": _authority_denial(),
        "capabilities": ["inspect", "page", "read", "recover", "reconcile"],
        "contracts": [{"contract": "source", "versions": ["v1"]}],
        "limits": {
            "max_input_bytes": 1024 * 1024,
            "max_output_bytes": 2 * 1024 * 1024,
            "max_runtime_ms": 86_400_000,
        },
        "provider_kind": "source",
    }
    if _derived("dm:adapter:v0:", SOURCE_ADAPTER_DOMAIN, core) != SOURCE_ADAPTER_ID:
        raise CollectiveMemoryError("collective_source_manifest_identity_mismatch")
    return {
        "schema": "daimon-adapter-manifest/v0",
        "adapter_id": SOURCE_ADAPTER_ID,
        **core,
    }


def create_publisher_manifest() -> dict[str, Any]:
    core = {
        "authority": _authority_denial(),
        "capabilities": ["apply", "plan", "preview", "recover", "reconcile"],
        "contracts": [{"contract": "artifact-store", "versions": ["v1"]}],
        "limits": {
            "max_input_bytes": 2 * 1024 * 1024,
            "max_output_bytes": 2 * 1024 * 1024,
            "max_runtime_ms": 86_400_000,
        },
        "provider_kind": "artifact-store",
    }
    if (
        _derived("dm:adapter:v0:", PUBLISHER_ADAPTER_DOMAIN, core)
        != PUBLISHER_ADAPTER_ID
    ):
        raise CollectiveMemoryError("collective_publisher_manifest_identity_mismatch")
    return {
        "schema": "daimon-adapter-manifest/v0",
        "adapter_id": PUBLISHER_ADAPTER_ID,
        **core,
    }


def create_source_profile(
    *, producer_instance: str, producer_release: str, policy_version: str, scope_id: str
) -> dict[str, Any]:
    return validate_source_profile(
        {
            "schema": SOURCE_PROFILE_SCHEMA,
            "adapter_id": SOURCE_ADAPTER_ID,
            "contract_version": COLLECTIVE_CONTRACT_VERSION,
            "upstream_commit": COLLECTIVE_MEMORY_COMMIT,
            "upstream_schema_sha256": COLLECTIVE_SCHEMA_SHA256,
            "producer_instance": producer_instance,
            "producer_release": producer_release,
            "policy_version": policy_version,
            "scope_id": scope_id,
        }
    )


def validate_source_profile(value: Any) -> dict[str, Any]:
    row = _closed(
        value,
        {
            "schema",
            "adapter_id",
            "contract_version",
            "upstream_commit",
            "upstream_schema_sha256",
            "producer_instance",
            "producer_release",
            "policy_version",
            "scope_id",
        },
        "invalid_collective_source_profile",
    )
    if (
        row["schema"] != SOURCE_PROFILE_SCHEMA
        or row["adapter_id"] != SOURCE_ADAPTER_ID
        or row["contract_version"] != COLLECTIVE_CONTRACT_VERSION
        or row["upstream_commit"] != COLLECTIVE_MEMORY_COMMIT
        or row["upstream_schema_sha256"] != COLLECTIVE_SCHEMA_SHA256
    ):
        raise CollectiveMemoryError("collective_source_profile_pin_mismatch")
    return {
        **dict(row),
        "producer_instance": _identifier(
            row["producer_instance"], "invalid_collective_source_profile"
        ),
        "producer_release": _identifier(
            row["producer_release"], "invalid_collective_source_profile"
        ),
        "policy_version": _identifier(
            row["policy_version"], "invalid_collective_source_profile"
        ),
        "scope_id": _identifier(row["scope_id"], "invalid_collective_source_profile"),
    }


def create_publisher_profile(
    *, requester_id: str, policy_version: str, target_ids: Sequence[str]
) -> dict[str, Any]:
    return validate_publisher_profile(
        {
            "schema": PUBLISHER_PROFILE_SCHEMA,
            "adapter_id": PUBLISHER_ADAPTER_ID,
            "contract_version": COLLECTIVE_CONTRACT_VERSION,
            "upstream_commit": COLLECTIVE_MEMORY_COMMIT,
            "upstream_schema_sha256": COLLECTIVE_SCHEMA_SHA256,
            "requester_id": requester_id,
            "policy_version": policy_version,
            "target_ids": sorted(target_ids),
        }
    )


def validate_publisher_profile(value: Any) -> dict[str, Any]:
    row = _closed(
        value,
        {
            "schema",
            "adapter_id",
            "contract_version",
            "upstream_commit",
            "upstream_schema_sha256",
            "requester_id",
            "policy_version",
            "target_ids",
        },
        "invalid_collective_publisher_profile",
    )
    if (
        row["schema"] != PUBLISHER_PROFILE_SCHEMA
        or row["adapter_id"] != PUBLISHER_ADAPTER_ID
        or row["contract_version"] != COLLECTIVE_CONTRACT_VERSION
        or row["upstream_commit"] != COLLECTIVE_MEMORY_COMMIT
        or row["upstream_schema_sha256"] != COLLECTIVE_SCHEMA_SHA256
    ):
        raise CollectiveMemoryError("collective_publisher_profile_pin_mismatch")
    raw_targets = row["target_ids"]
    if not isinstance(raw_targets, list) or not raw_targets:
        raise CollectiveMemoryError("invalid_collective_publisher_profile")
    targets = [
        _identifier(item, "invalid_collective_publisher_profile")
        for item in raw_targets
    ]
    if targets != sorted(set(targets)):
        raise CollectiveMemoryError("invalid_collective_publisher_profile")
    return {
        **dict(row),
        "requester_id": _identifier(
            row["requester_id"], "invalid_collective_publisher_profile"
        ),
        "policy_version": _identifier(
            row["policy_version"], "invalid_collective_publisher_profile"
        ),
        "target_ids": targets,
    }


def _validate_export_artifact(value: Any) -> dict[str, Any]:
    code = "invalid_collective_export_artifact"
    row = _closed(
        value,
        {
            "artifact_id",
            "logical_id",
            "media_type",
            "authors",
            "source_refs",
            "license",
            "consent_scope",
            "classification",
            "predecessor_artifact_id",
            "state",
            "content_hash",
            "content_length",
            "content_ref",
        },
        code,
    )
    artifact_id = _identifier(row["artifact_id"], code)
    logical_id = _identifier(row["logical_id"], code)
    if row["media_type"] not in {
        "text/markdown; charset=utf-8",
        "text/plain; charset=utf-8",
    }:
        raise CollectiveMemoryError("collective_unsupported_media_type")
    if not isinstance(row["authors"], list) or not row["authors"]:
        raise CollectiveMemoryError("collective_missing_provenance")
    authors = [_identifier(item, code) for item in row["authors"]]
    if authors != sorted(set(authors)):
        raise CollectiveMemoryError("collective_noncanonical_provenance")
    if not isinstance(row["source_refs"], list) or not row["source_refs"]:
        raise CollectiveMemoryError("collective_missing_provenance")
    source_refs = [_source_ref(item, code) for item in row["source_refs"]]
    if source_refs != sorted(source_refs, key=lambda item: (item["id"], item["hash"])):
        raise CollectiveMemoryError("collective_noncanonical_sources")
    if len({(item["id"], item["hash"]) for item in source_refs}) != len(source_refs):
        raise CollectiveMemoryError("collective_duplicate_source")
    state = row["state"]
    if state not in {"active", "tombstone"}:
        raise CollectiveMemoryError(code)
    content_hash = _nullable_hash(row["content_hash"], code)
    length = _uint(row["content_length"], code, maximum=MAX_ARTIFACT_BYTES)
    content_ref = row["content_ref"]
    if state == "active":
        if (
            content_hash is None
            or length < 1
            or content_ref != f"sha256:{content_hash}"
        ):
            raise CollectiveMemoryError("collective_invalid_active_artifact")
    elif content_hash is not None or length != 0 or content_ref is not None:
        raise CollectiveMemoryError("collective_invalid_tombstone")
    return {
        "artifact_id": artifact_id,
        "logical_id": logical_id,
        "media_type": row["media_type"],
        "authors": authors,
        "source_refs": source_refs,
        "license": _identifier(row["license"], code),
        "consent_scope": _identifier(row["consent_scope"], code),
        "classification": _identifier(row["classification"], code),
        "predecessor_artifact_id": _nullable_identifier(
            row["predecessor_artifact_id"], code
        ),
        "state": state,
        "content_hash": content_hash,
        "content_length": length,
        "content_ref": content_ref,
    }


def validate_export_manifest(value: Any) -> dict[str, Any]:
    code = "invalid_collective_export_manifest"
    row = _closed(value, {"schema", "generation_id", "manifest_hash", "body"}, code)
    if row["schema"] != EXPORT_MANIFEST_SCHEMA:
        raise CollectiveMemoryError("collective_unsupported_schema")
    body = _closed(
        row["body"],
        {
            "producer_instance",
            "producer_release",
            "policy_version",
            "scope_id",
            "projection",
            "created_at",
            "predecessor_generation",
            "state_digest",
            "artifact_count",
            "total_content_bytes",
            "artifacts",
        },
        code,
    )
    projection = _closed(
        body["projection"], {"index_generation", "ui_generation"}, code
    )
    for field, maximum in (("index_generation", 128), ("ui_generation", 256)):
        if projection[field] is not None:
            _text(projection[field], code, maximum=maximum)
    raw_artifacts = body["artifacts"]
    if not isinstance(raw_artifacts, list) or len(raw_artifacts) > MAX_ARTIFACTS:
        raise CollectiveMemoryError("collective_export_too_large")
    artifacts = [_validate_export_artifact(item) for item in raw_artifacts]
    if artifacts != sorted(artifacts, key=lambda item: item["artifact_id"]):
        raise CollectiveMemoryError("collective_noncanonical_artifacts")
    if len({item["artifact_id"] for item in artifacts}) != len(artifacts) or len(
        {item["logical_id"] for item in artifacts}
    ) != len(artifacts):
        raise CollectiveMemoryError("collective_duplicate_artifact")
    artifact_count = _uint(body["artifact_count"], code, maximum=MAX_ARTIFACTS)
    total = _uint(body["total_content_bytes"], code, maximum=MAX_EXPORT_BYTES)
    if artifact_count != len(artifacts) or total != sum(
        cast(int, item["content_length"]) for item in artifacts
    ):
        raise CollectiveMemoryError("collective_manifest_count_mismatch")
    scope_id = _identifier(body["scope_id"], code)
    if any(
        item["consent_scope"] != scope_id or item["classification"] != scope_id
        for item in artifacts
    ):
        raise CollectiveMemoryError("collective_scope_violation")
    normalized_body = {
        "producer_instance": _identifier(body["producer_instance"], code),
        "producer_release": _identifier(body["producer_release"], code),
        "policy_version": _identifier(body["policy_version"], code),
        "scope_id": scope_id,
        "projection": dict(projection),
        "created_at": _timestamp(body["created_at"], code),
        "predecessor_generation": _nullable_identifier(
            body["predecessor_generation"], code
        ),
        "state_digest": _hash(body["state_digest"], code),
        "artifact_count": artifact_count,
        "total_content_bytes": total,
        "artifacts": artifacts,
    }
    generation_id, manifest_hash = _content_id("cm:export:v1", normalized_body)
    if row["generation_id"] != generation_id or row["manifest_hash"] != manifest_hash:
        raise CollectiveMemoryError("collective_manifest_identity_mismatch")
    return {
        "schema": EXPORT_MANIFEST_SCHEMA,
        "generation_id": generation_id,
        "manifest_hash": manifest_hash,
        "body": normalized_body,
    }


def validate_export_page(
    value: Any,
    manifest: Mapping[str, Any],
    *,
    expected_offset: int,
    expected_limit: int,
) -> dict[str, Any]:
    code = "invalid_collective_export_page"
    row = _closed(
        value,
        {
            "schema",
            "generation_id",
            "manifest_hash",
            "offset",
            "limit",
            "artifacts",
            "next_cursor",
        },
        code,
    )
    if (
        row["schema"] != EXPORT_PAGE_SCHEMA
        or row["generation_id"] != manifest["generation_id"]
        or row["manifest_hash"] != manifest["manifest_hash"]
    ):
        raise CollectiveMemoryError("collective_mixed_generation")
    if (
        _uint(row["offset"], code) != expected_offset
        or _uint(row["limit"], code, minimum=1, maximum=MAX_PAGE) != expected_limit
    ):
        raise CollectiveMemoryError("collective_page_position_mismatch")
    raw = row["artifacts"]
    if not isinstance(raw, list) or len(raw) > expected_limit:
        raise CollectiveMemoryError(code)
    artifacts = [_validate_export_artifact(item) for item in raw]
    cursor = row["next_cursor"]
    if cursor is not None:
        _text(cursor, code, maximum=4096)
        try:
            unb64url(cursor)
        except CanonicalError as exception:
            raise CollectiveMemoryError(code) from exception
    return {**dict(row), "artifacts": artifacts}


def _validate_draft(value: Any, profile: Mapping[str, Any]) -> dict[str, Any]:
    code = "invalid_collective_publication_draft"
    row = _closed(
        value,
        {
            "schema",
            "action",
            "requester_id",
            "subject_id",
            "target_id",
            "source_refs",
            "source_checkpoint",
            "classification",
            "policy_version",
            "media_type",
            "title",
            "body",
            "predecessor_receipt_id",
            "predecessor_receipt_hash",
        },
        code,
    )
    if row["schema"] != PUBLICATION_DRAFT_SCHEMA:
        raise CollectiveMemoryError("collective_unsupported_schema")
    if row["action"] not in {"publish", "successor", "tombstone"}:
        raise CollectiveMemoryError(code)
    requester = _identifier(row["requester_id"], code)
    target = _identifier(row["target_id"], code)
    if requester != profile["requester_id"] or target not in profile["target_ids"]:
        raise CollectiveMemoryError("collective_publication_authority_mismatch")
    raw_refs = row["source_refs"]
    if not isinstance(raw_refs, list) or not 1 <= len(raw_refs) <= MAX_SOURCE_REFS:
        raise CollectiveMemoryError(code)
    refs = [_source_ref(item, code) for item in raw_refs]
    if refs != sorted(refs, key=lambda item: (item["id"], item["hash"])) or len(
        {(item["id"], item["hash"]) for item in refs}
    ) != len(refs):
        raise CollectiveMemoryError("collective_noncanonical_sources")
    if row["policy_version"] != profile["policy_version"]:
        raise CollectiveMemoryError("collective_policy_mismatch")
    if row["media_type"] != "text/markdown; charset=utf-8":
        raise CollectiveMemoryError("collective_unsupported_media_type")
    title = _text(row["title"], code, maximum=1024, empty=row["action"] == "tombstone")
    body = _text(
        row["body"],
        code,
        maximum=MAX_PUBLICATION_BYTES,
        empty=row["action"] == "tombstone",
    )
    predecessor_id = _nullable_identifier(row["predecessor_receipt_id"], code)
    predecessor_hash = _nullable_hash(row["predecessor_receipt_hash"], code)
    if (predecessor_id is None) != (predecessor_hash is None):
        raise CollectiveMemoryError("collective_invalid_predecessor")
    if row["action"] == "publish" and predecessor_id is not None:
        raise CollectiveMemoryError("collective_invalid_predecessor")
    if row["action"] != "publish" and predecessor_id is None:
        raise CollectiveMemoryError("collective_missing_predecessor")
    if row["action"] == "tombstone" and (title or body):
        raise CollectiveMemoryError("collective_invalid_tombstone")
    return {
        "schema": PUBLICATION_DRAFT_SCHEMA,
        "action": row["action"],
        "requester_id": requester,
        "subject_id": _identifier(row["subject_id"], code),
        "target_id": target,
        "source_refs": refs,
        "source_checkpoint": _checkpoint(row["source_checkpoint"], code),
        "classification": _identifier(row["classification"], code),
        "policy_version": row["policy_version"],
        "media_type": row["media_type"],
        "title": title,
        "body": body,
        "predecessor_receipt_id": predecessor_id,
        "predecessor_receipt_hash": predecessor_hash,
    }


def _render_collective(draft: Mapping[str, Any]) -> bytes:
    metadata = {
        "action": draft["action"],
        "classification": draft["classification"],
        "policy_version": draft["policy_version"],
        "schema": "collective-publication-artifact/v1",
        "source_checkpoint": draft["source_checkpoint"],
        "source_refs": draft["source_refs"],
        "subject_id": draft["subject_id"],
        "target_id": draft["target_id"],
    }
    if draft["action"] == "tombstone":
        title = "Publication withdrawn"
        body = "This logical artifact was withdrawn by an explicit reviewed successor."
    else:
        title = (
            cast(str, draft["title"]).replace("\r\n", "\n").replace("\r", "\n").strip()
        )
        body = (
            cast(str, draft["body"]).replace("\r\n", "\n").replace("\r", "\n").rstrip()
        )
    rendered = (
        b"---\n"
        + _canonical(metadata, "invalid_collective_render")
        + b"\n---\n# "
        + title.encode()
        + b"\n\n"
        + body.encode()
        + b"\n"
    )
    if len(rendered) > MAX_PUBLICATION_BYTES:
        raise CollectiveMemoryError("collective_publication_too_large")
    if any(pattern.search(rendered) for pattern in _SECRET_PATTERNS):
        raise CollectiveMemoryError("collective_secret_detected")
    return rendered


def validate_publication_preview(
    value: Any,
    draft: Mapping[str, Any],
    *,
    expected_before: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    code = "invalid_collective_publication_preview"
    row = _closed(value, {"schema", "preview_id", "preview_hash", "body"}, code)
    if row["schema"] != PUBLICATION_PREVIEW_SCHEMA:
        raise CollectiveMemoryError("collective_unsupported_schema")
    body = _closed(
        row["body"], {"draft_hash", "state_hash", "before", "rendered"}, code
    )
    if body["draft_hash"] != hashlib.sha256(_canonical(draft, code)).hexdigest():
        raise CollectiveMemoryError("collective_preview_draft_mismatch")
    state_hash = _hash(body["state_hash"], code)
    before = body["before"]
    if before is not None:
        before_row = _closed(
            before,
            {"receipt_id", "receipt_hash", "content_hash", "content_length", "state"},
            code,
        )
        before = {
            "receipt_id": _identifier(before_row["receipt_id"], code),
            "receipt_hash": _hash(before_row["receipt_hash"], code),
            "content_hash": _hash(before_row["content_hash"], code),
            "content_length": _uint(
                before_row["content_length"],
                code,
                minimum=1,
                maximum=MAX_PUBLICATION_BYTES,
            ),
            "state": before_row["state"],
        }
        if before["state"] not in {"active", "tombstone"}:
            raise CollectiveMemoryError(code)
    if expected_before is not None and before != expected_before:
        raise CollectiveMemoryError("collective_preview_predecessor_mismatch")
    rendered_row = _closed(
        body["rendered"],
        {"content_hash", "content_length", "media_type", "bytes_b64"},
        code,
    )
    if rendered_row["media_type"] != "text/markdown; charset=utf-8":
        raise CollectiveMemoryError("collective_unsupported_media_type")
    encoded = _text(rendered_row["bytes_b64"], code, maximum=1_398_104)
    try:
        rendered = unb64url(encoded)
    except CanonicalError as exception:
        raise CollectiveMemoryError(code) from exception
    expected_rendered = _render_collective(draft)
    if (
        rendered != expected_rendered
        or rendered_row["content_hash"] != hashlib.sha256(rendered).hexdigest()
        or rendered_row["content_length"] != len(rendered)
    ):
        raise CollectiveMemoryError("collective_preview_render_mismatch")
    normalized_body = {
        "draft_hash": body["draft_hash"],
        "state_hash": state_hash,
        "before": before,
        "rendered": {
            "content_hash": _hash(rendered_row["content_hash"], code),
            "content_length": _uint(
                rendered_row["content_length"],
                code,
                minimum=1,
                maximum=MAX_PUBLICATION_BYTES,
            ),
            "media_type": rendered_row["media_type"],
            "bytes_b64": encoded,
        },
    }
    preview_id, preview_hash = _content_id("cm:publication-preview:v1", normalized_body)
    if row["preview_id"] != preview_id or row["preview_hash"] != preview_hash:
        raise CollectiveMemoryError("collective_preview_identity_mismatch")
    return {
        "schema": PUBLICATION_PREVIEW_SCHEMA,
        "preview_id": preview_id,
        "preview_hash": preview_hash,
        "body": normalized_body,
    }


def evidence_issuer(
    principal: str,
    key: Ed25519PublicKey,
    *,
    valid_from_ms: int = 0,
    valid_until_ms: int = MAX_SAFE_INTEGER,
    revoked_at_ms: int | None = None,
) -> dict[str, Any]:
    valid_from_ms = _uint(valid_from_ms, "invalid_collective_evidence_issuer")
    valid_until_ms = _uint(valid_until_ms, "invalid_collective_evidence_issuer")
    if valid_until_ms <= valid_from_ms:
        raise CollectiveMemoryError("invalid_collective_evidence_issuer")
    if revoked_at_ms is not None:
        revoked_at_ms = _uint(revoked_at_ms, "invalid_collective_evidence_issuer")
    return {
        "principal": _identifier(principal, "invalid_collective_evidence_issuer"),
        "public_key": b64url(key.public_bytes_raw()),
        "kid": "ed25519:" + b64url(hashlib.sha256(key.public_bytes_raw()).digest()),
        "valid_from_ms": valid_from_ms,
        "valid_until_ms": valid_until_ms,
        "revoked_at_ms": revoked_at_ms,
    }


def _evidence_core(
    draft: Mapping[str, Any],
    preview: Mapping[str, Any],
    *,
    kind: str,
    evidence_id: str,
    issuer: str,
    issued_at: str,
    not_before: str,
    not_after: str,
) -> dict[str, Any]:
    if kind not in {"consent", "review"}:
        raise CollectiveMemoryError("invalid_collective_evidence")
    return {
        "schema": PUBLICATION_EVIDENCE_SCHEMA,
        "kind": kind,
        "evidence_id": _identifier(evidence_id, "invalid_collective_evidence"),
        "issuer": _identifier(issuer, "invalid_collective_evidence"),
        "subject_id": draft["subject_id"],
        "requester_id": draft["requester_id"],
        "action": draft["action"],
        "target_id": draft["target_id"],
        "source_checkpoint": copy.deepcopy(draft["source_checkpoint"]),
        "classification": draft["classification"],
        "policy_version": draft["policy_version"],
        "preview_hash": preview["preview_hash"],
        "content_hash": preview["body"]["rendered"]["content_hash"],
        "issued_at": _timestamp(issued_at, "invalid_collective_evidence"),
        "not_before": _timestamp(not_before, "invalid_collective_evidence"),
        "not_after": _timestamp(not_after, "invalid_collective_evidence"),
    }


def sign_publication_evidence(
    draft: Mapping[str, Any],
    preview: Mapping[str, Any],
    *,
    kind: str,
    evidence_id: str,
    issuer: Mapping[str, Any],
    private_key: Ed25519PrivateKey,
    issued_at: str,
    not_before: str,
    not_after: str,
) -> dict[str, Any]:
    if set(issuer) != {
        "principal",
        "public_key",
        "kid",
        "valid_from_ms",
        "valid_until_ms",
        "revoked_at_ms",
    }:
        raise CollectiveMemoryError("invalid_collective_evidence_issuer")
    if b64url(private_key.public_key().public_bytes_raw()) != issuer["public_key"]:
        raise CollectiveMemoryError("collective_evidence_key_mismatch")
    body = _evidence_core(
        draft,
        preview,
        kind=kind,
        evidence_id=evidence_id,
        issuer=issuer["principal"],
        issued_at=issued_at,
        not_before=not_before,
        not_after=not_after,
    )
    signature = private_key.sign(_canonical(body, "invalid_collective_evidence"))
    return {
        "schema": PUBLICATION_EVIDENCE_SCHEMA,
        "body": body,
        "signature": {
            "alg": "Ed25519",
            "kid": issuer["kid"],
            "value": b64url(signature),
        },
    }


def validate_publication_evidence(
    value: Any,
    draft: Mapping[str, Any],
    preview: Mapping[str, Any],
    *,
    kind: str,
    issuer: Mapping[str, Any],
    at: str,
) -> tuple[dict[str, Any], str]:
    code = "invalid_collective_evidence"
    row = _closed(value, {"schema", "body", "signature"}, code)
    if row["schema"] != PUBLICATION_EVIDENCE_SCHEMA:
        raise CollectiveMemoryError("collective_unsupported_schema")
    body = _closed(
        row["body"],
        {
            "schema",
            "kind",
            "evidence_id",
            "issuer",
            "subject_id",
            "requester_id",
            "action",
            "target_id",
            "source_checkpoint",
            "classification",
            "policy_version",
            "preview_hash",
            "content_hash",
            "issued_at",
            "not_before",
            "not_after",
        },
        code,
    )
    expected = _evidence_core(
        draft,
        preview,
        kind=kind,
        evidence_id=cast(str, body["evidence_id"]),
        issuer=issuer["principal"],
        issued_at=cast(str, body["issued_at"]),
        not_before=cast(str, body["not_before"]),
        not_after=cast(str, body["not_after"]),
    )
    if dict(body) != expected:
        raise CollectiveMemoryError("collective_evidence_binding_mismatch")
    signature = _closed(row["signature"], {"alg", "kid", "value"}, code)
    if signature["alg"] != "Ed25519" or signature["kid"] != issuer["kid"]:
        raise CollectiveMemoryError(code)
    try:
        raw_signature = unb64url(cast(str, signature["value"]), length=64)
        public = Ed25519PublicKey.from_public_bytes(
            unb64url(issuer["public_key"], length=32)
        )
        public.verify(raw_signature, _canonical(expected, code))
    except (CanonicalError, InvalidSignature, ValueError) as exception:
        raise CollectiveMemoryError(
            "collective_evidence_signature_invalid"
        ) from exception
    instant = dt.datetime.fromisoformat(
        _timestamp(at, code).removesuffix("Z") + "+00:00"
    )
    before = dt.datetime.fromisoformat(
        expected["not_before"].removesuffix("Z") + "+00:00"
    )
    after = dt.datetime.fromisoformat(
        expected["not_after"].removesuffix("Z") + "+00:00"
    )
    issued = dt.datetime.fromisoformat(
        expected["issued_at"].removesuffix("Z") + "+00:00"
    )
    if not before <= issued <= instant <= after:
        raise CollectiveMemoryError("collective_evidence_expired")
    issued_ms = int(issued.timestamp() * 1000)
    instant_ms = int(instant.timestamp() * 1000)
    if not (
        issuer["valid_from_ms"] <= issued_ms <= issuer["valid_until_ms"]
        and issuer["valid_from_ms"] <= instant_ms <= issuer["valid_until_ms"]
    ):
        raise CollectiveMemoryError("collective_evidence_key_expired")
    revoked_at_ms = issuer["revoked_at_ms"]
    if revoked_at_ms is not None and (
        issued_ms >= revoked_at_ms or instant_ms >= revoked_at_ms
    ):
        raise CollectiveMemoryError("collective_evidence_key_revoked")
    normalized = {
        "schema": PUBLICATION_EVIDENCE_SCHEMA,
        "body": expected,
        "signature": dict(signature),
    }
    return normalized, hashlib.sha256(_canonical(normalized, code)).hexdigest()


def create_publication_request(
    draft: Mapping[str, Any],
    preview: Mapping[str, Any],
    *,
    idempotency_key: str,
    consent: Mapping[str, Any],
    review: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "schema": PUBLICATION_REQUEST_SCHEMA,
        "draft": copy.deepcopy(dict(draft)),
        "preview_hash": preview["preview_hash"],
        "idempotency_key": _identifier(idempotency_key, "invalid_collective_request"),
        "consent": copy.deepcopy(dict(consent)),
        "review": copy.deepcopy(dict(review)),
    }


def validate_publication_plan(
    value: Any,
    request: Mapping[str, Any],
    preview: Mapping[str, Any],
    *,
    consent_hash: str,
    review_hash: str,
) -> dict[str, Any]:
    code = "invalid_collective_publication_plan"
    row = _closed(value, {"schema", "plan_id", "plan_hash", "body"}, code)
    if row["schema"] != PUBLICATION_PLAN_SCHEMA:
        raise CollectiveMemoryError("collective_unsupported_schema")
    body = _closed(
        row["body"],
        {
            "request_hash",
            "preview_hash",
            "target_id",
            "action",
            "before",
            "after",
            "consent_hash",
            "review_hash",
        },
        code,
    )
    draft = cast(Mapping[str, Any], request["draft"])
    after = _closed(
        body["after"], {"content_hash", "content_length", "media_type", "state"}, code
    )
    expected_body = {
        "request_hash": hashlib.sha256(_canonical(request, code)).hexdigest(),
        "preview_hash": preview["preview_hash"],
        "target_id": draft["target_id"],
        "action": draft["action"],
        "before": preview["body"]["before"],
        "after": {
            "content_hash": preview["body"]["rendered"]["content_hash"],
            "content_length": preview["body"]["rendered"]["content_length"],
            "media_type": draft["media_type"],
            "state": "tombstone" if draft["action"] == "tombstone" else "active",
        },
        "consent_hash": consent_hash,
        "review_hash": review_hash,
    }
    if dict(body) != expected_body or dict(after) != expected_body["after"]:
        raise CollectiveMemoryError("collective_publication_plan_mismatch")
    plan_id, plan_hash = _content_id("cm:publication-plan:v1", expected_body)
    if row["plan_id"] != plan_id or row["plan_hash"] != plan_hash:
        raise CollectiveMemoryError("collective_publication_plan_identity_mismatch")
    return {
        "schema": PUBLICATION_PLAN_SCHEMA,
        "plan_id": plan_id,
        "plan_hash": plan_hash,
        "body": expected_body,
    }


def _validate_target_record(value: Any, code: str) -> dict[str, Any] | None:
    if value is None:
        return None
    row = _closed(
        value,
        {"receipt_id", "receipt_hash", "content_hash", "content_length", "state"},
        code,
    )
    if row["state"] not in {"active", "tombstone"}:
        raise CollectiveMemoryError(code)
    return {
        "receipt_id": _identifier(row["receipt_id"], code),
        "receipt_hash": _hash(row["receipt_hash"], code),
        "content_hash": _hash(row["content_hash"], code),
        "content_length": _uint(
            row["content_length"], code, minimum=1, maximum=MAX_PUBLICATION_BYTES
        ),
        "state": row["state"],
    }


def _validate_publication_receipt_shape(value: Any) -> dict[str, Any]:
    code = "invalid_collective_publication_receipt"
    row = _closed(value, {"schema", "receipt_id", "receipt_hash", "body"}, code)
    if row["schema"] != PUBLICATION_RECEIPT_SCHEMA:
        raise CollectiveMemoryError("collective_unsupported_schema")
    body = _closed(
        row["body"],
        {
            "transaction_id",
            "request_hash",
            "plan_id",
            "idempotency_key",
            "target_id",
            "action",
            "before",
            "after",
            "source_refs",
            "source_checkpoint",
            "classification",
            "policy_version",
            "consent",
            "review",
            "projection",
            "committed_at",
            "status",
        },
        code,
    )
    if body["action"] not in {"publish", "successor", "tombstone"}:
        raise CollectiveMemoryError(code)
    before = _validate_target_record(body["before"], code)
    if (body["action"] == "publish") != (before is None):
        raise CollectiveMemoryError(
            "collective_publication_receipt_predecessor_mismatch"
        )
    after = _closed(
        body["after"], {"content_hash", "content_length", "media_type", "state"}, code
    )
    expected_state = "tombstone" if body["action"] == "tombstone" else "active"
    if (
        after["media_type"] != "text/markdown; charset=utf-8"
        or after["state"] != expected_state
    ):
        raise CollectiveMemoryError(code)
    raw_refs = body["source_refs"]
    if not isinstance(raw_refs, list) or not 1 <= len(raw_refs) <= MAX_SOURCE_REFS:
        raise CollectiveMemoryError(code)
    source_refs = [_source_ref(item, code) for item in raw_refs]
    if source_refs != sorted(source_refs, key=lambda item: (item["id"], item["hash"])):
        raise CollectiveMemoryError("collective_noncanonical_sources")
    consent = _closed(body["consent"], {"evidence_id", "evidence_hash"}, code)
    review = _closed(body["review"], {"evidence_id", "evidence_hash"}, code)
    projection = _closed(
        body["projection"],
        {"index_generation", "ui_generation", "index_content_hash"},
        code,
    )
    if body["status"] != "committed":
        raise CollectiveMemoryError(code)
    normalized_body = {
        "transaction_id": _identifier(body["transaction_id"], code),
        "request_hash": _hash(body["request_hash"], code),
        "plan_id": _identifier(body["plan_id"], code),
        "idempotency_key": _identifier(body["idempotency_key"], code),
        "target_id": _identifier(body["target_id"], code),
        "action": body["action"],
        "before": before,
        "after": {
            "content_hash": _hash(after["content_hash"], code),
            "content_length": _uint(
                after["content_length"],
                code,
                minimum=1,
                maximum=MAX_PUBLICATION_BYTES,
            ),
            "media_type": after["media_type"],
            "state": after["state"],
        },
        "source_refs": source_refs,
        "source_checkpoint": _checkpoint(body["source_checkpoint"], code),
        "classification": _identifier(body["classification"], code),
        "policy_version": _identifier(body["policy_version"], code),
        "consent": {
            "evidence_id": _identifier(consent["evidence_id"], code),
            "evidence_hash": _hash(consent["evidence_hash"], code),
        },
        "review": {
            "evidence_id": _identifier(review["evidence_id"], code),
            "evidence_hash": _hash(review["evidence_hash"], code),
        },
        "projection": {
            "index_generation": _text(
                projection["index_generation"], code, maximum=128
            ),
            "ui_generation": _text(projection["ui_generation"], code, maximum=256),
            "index_content_hash": _hash(projection["index_content_hash"], code),
        },
        "committed_at": _timestamp(body["committed_at"], code),
        "status": "committed",
    }
    receipt_id, receipt_hash = _content_id("cm:publication-receipt:v1", normalized_body)
    if row["receipt_id"] != receipt_id or row["receipt_hash"] != receipt_hash:
        raise CollectiveMemoryError("collective_publication_receipt_identity_mismatch")
    return {
        "schema": PUBLICATION_RECEIPT_SCHEMA,
        "receipt_id": receipt_id,
        "receipt_hash": receipt_hash,
        "body": normalized_body,
    }


def validate_publication_receipt(
    value: Any,
    request: Mapping[str, Any],
    plan: Mapping[str, Any],
    *,
    consent_hash: str,
    review_hash: str,
) -> dict[str, Any]:
    code = "invalid_collective_publication_receipt"
    row = _validate_publication_receipt_shape(value)
    body = _closed(
        row["body"],
        {
            "transaction_id",
            "request_hash",
            "plan_id",
            "idempotency_key",
            "target_id",
            "action",
            "before",
            "after",
            "source_refs",
            "source_checkpoint",
            "classification",
            "policy_version",
            "consent",
            "review",
            "projection",
            "committed_at",
            "status",
        },
        code,
    )
    draft = cast(Mapping[str, Any], request["draft"])
    before = _validate_target_record(body["before"], code)
    after = _closed(
        body["after"], {"content_hash", "content_length", "media_type", "state"}, code
    )
    if after["state"] not in {"active", "tombstone"}:
        raise CollectiveMemoryError(code)
    normalized_after = {
        "content_hash": _hash(after["content_hash"], code),
        "content_length": _uint(
            after["content_length"], code, minimum=1, maximum=MAX_PUBLICATION_BYTES
        ),
        "media_type": after["media_type"],
        "state": after["state"],
    }
    consent = _closed(body["consent"], {"evidence_id", "evidence_hash"}, code)
    review = _closed(body["review"], {"evidence_id", "evidence_hash"}, code)
    projection = _closed(
        body["projection"],
        {"index_generation", "ui_generation", "index_content_hash"},
        code,
    )
    expected_bindings = {
        "request_hash": plan["body"]["request_hash"],
        "plan_id": plan["plan_id"],
        "idempotency_key": request["idempotency_key"],
        "target_id": draft["target_id"],
        "action": draft["action"],
        "before": plan["body"]["before"],
        "after": plan["body"]["after"],
        "source_refs": draft["source_refs"],
        "source_checkpoint": draft["source_checkpoint"],
        "classification": draft["classification"],
        "policy_version": draft["policy_version"],
        "consent_hash": consent_hash,
        "review_hash": review_hash,
    }
    observed = {
        "request_hash": body["request_hash"],
        "plan_id": body["plan_id"],
        "idempotency_key": body["idempotency_key"],
        "target_id": body["target_id"],
        "action": body["action"],
        "before": before,
        "after": normalized_after,
        "source_refs": body["source_refs"],
        "source_checkpoint": body["source_checkpoint"],
        "classification": body["classification"],
        "policy_version": body["policy_version"],
        "consent_hash": consent["evidence_hash"],
        "review_hash": review["evidence_hash"],
    }
    if observed != expected_bindings:
        raise CollectiveMemoryError("collective_publication_receipt_mismatch")
    if (
        consent["evidence_id"] != request["consent"]["body"]["evidence_id"]
        or review["evidence_id"] != request["review"]["body"]["evidence_id"]
        or body["status"] != "committed"
    ):
        raise CollectiveMemoryError("collective_publication_receipt_mismatch")
    normalized_body = {
        "transaction_id": _identifier(body["transaction_id"], code),
        "request_hash": _hash(body["request_hash"], code),
        "plan_id": _identifier(body["plan_id"], code),
        "idempotency_key": _identifier(body["idempotency_key"], code),
        "target_id": _identifier(body["target_id"], code),
        "action": body["action"],
        "before": before,
        "after": normalized_after,
        "source_refs": [_source_ref(item, code) for item in body["source_refs"]],
        "source_checkpoint": _checkpoint(body["source_checkpoint"], code),
        "classification": _identifier(body["classification"], code),
        "policy_version": _identifier(body["policy_version"], code),
        "consent": {
            "evidence_id": _identifier(consent["evidence_id"], code),
            "evidence_hash": _hash(consent["evidence_hash"], code),
        },
        "review": {
            "evidence_id": _identifier(review["evidence_id"], code),
            "evidence_hash": _hash(review["evidence_hash"], code),
        },
        "projection": {
            "index_generation": _text(
                projection["index_generation"], code, maximum=128
            ),
            "ui_generation": _text(projection["ui_generation"], code, maximum=256),
            "index_content_hash": _hash(projection["index_content_hash"], code),
        },
        "committed_at": _timestamp(body["committed_at"], code),
        "status": "committed",
    }
    receipt_id, receipt_hash = _content_id("cm:publication-receipt:v1", normalized_body)
    if row["receipt_id"] != receipt_id or row["receipt_hash"] != receipt_hash:
        raise CollectiveMemoryError("collective_publication_receipt_identity_mismatch")
    return {
        "schema": PUBLICATION_RECEIPT_SCHEMA,
        "receipt_id": receipt_id,
        "receipt_hash": receipt_hash,
        "body": normalized_body,
    }


def validate_publication_reconciliation(
    value: Any, receipt: Mapping[str, Any]
) -> dict[str, Any]:
    code = "invalid_collective_publication_reconciliation"
    row = _closed(
        value,
        {"schema", "receipt_id", "receipt_hash", "state_hash", "effect", "projection"},
        code,
    )
    if (
        row["schema"] != PUBLICATION_RECONCILIATION_SCHEMA
        or row["receipt_id"] != receipt["receipt_id"]
        or row["receipt_hash"] != receipt["receipt_hash"]
        or row["effect"] != "verified"
        or row["projection"] != receipt["body"]["projection"]
    ):
        raise CollectiveMemoryError("collective_effect_truth_discrepancy")
    _hash(row["state_hash"], code)
    return dict(row)


def _assert_private_parent(path: Path) -> None:
    parent = path.parent
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    current = parent
    while True:
        try:
            information = current.lstat()
        except OSError as exception:
            raise CollectiveMemoryError("collective_store_unavailable") from exception
        if stat.S_ISLNK(information.st_mode) or not stat.S_ISDIR(information.st_mode):
            raise CollectiveMemoryError("collective_store_unsafe")
        if information.st_uid != os.getuid() or information.st_mode & 0o077:
            raise CollectiveMemoryError("collective_store_permissions")
        if current.parent == current:
            break
        if current == Path(parent.anchor):
            break
        # Only the adapter-created leaf hierarchy is required to be private;
        # system ancestors such as /tmp and /home may be shared/traversable.
        if current.parent == parent.parent:
            break
        current = current.parent


class _Store:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(os.path.abspath(path))
        self.lock_path = self.path.with_suffix(self.path.suffix + ".lock")

    def _prepare(self) -> None:
        _assert_private_parent(self.path)
        for candidate in (self.path, self.lock_path):
            if candidate.exists() or candidate.is_symlink():
                info = candidate.lstat()
                if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                    raise CollectiveMemoryError("collective_store_unsafe")
                if info.st_uid != os.getuid() or info.st_mode & 0o077:
                    raise CollectiveMemoryError("collective_store_permissions")

    def connect(self) -> sqlite3.Connection:
        self._prepare()
        connection = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=30000")
        connection.execute("PRAGMA foreign_keys=ON")
        if (
            str(connection.execute("PRAGMA journal_mode=DELETE").fetchone()[0]).lower()
            != "delete"
        ):
            connection.close()
            raise CollectiveMemoryError("collective_store_journal_mode")
        connection.execute("PRAGMA synchronous=FULL")
        os.chmod(self.path, 0o600)
        return connection

    @contextmanager
    def exclusive(self) -> Iterator[None]:
        self._prepare()
        descriptor = os.open(
            self.lock_path,
            os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            os.fchmod(descriptor, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)


class CollectiveSourceStore(_Store):
    """Append-only inbound source log; never reused by the publisher."""

    def initialize(self) -> None:
        with closing(self.connect()) as database:
            database.executescript(
                """
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                ) WITHOUT ROWID;
                CREATE TABLE IF NOT EXISTS generations (
                    generation_id TEXT PRIMARY KEY,
                    manifest_hash TEXT NOT NULL,
                    predecessor_generation TEXT,
                    state_digest TEXT NOT NULL,
                    source_log_hash TEXT NOT NULL,
                    preview_id TEXT NOT NULL UNIQUE,
                    preview_hash TEXT NOT NULL,
                    manifest_json BLOB NOT NULL,
                    state TEXT NOT NULL
                        CHECK(state IN ('prepared','active','superseded')),
                    import_event_id TEXT NOT NULL UNIQUE,
                    prepared_at_ms INTEGER NOT NULL,
                    import_event_hash TEXT,
                    receipt_json BLOB
                );
                CREATE TABLE IF NOT EXISTS artifacts (
                    generation_id TEXT NOT NULL REFERENCES generations(generation_id),
                    artifact_id TEXT NOT NULL,
                    logical_id TEXT NOT NULL,
                    descriptor_json BLOB NOT NULL,
                    content BLOB,
                    PRIMARY KEY(generation_id, artifact_id),
                    UNIQUE(generation_id, logical_id)
                );
                CREATE TABLE IF NOT EXISTS errors (
                    error_id TEXT PRIMARY KEY,
                    code TEXT NOT NULL,
                    retryable INTEGER NOT NULL,
                    occurred_at_ms INTEGER NOT NULL,
                    context_hash TEXT NOT NULL
                ) WITHOUT ROWID;
                """
            )
            expected = {
                "adapter_id": SOURCE_ADAPTER_ID,
                "schema_version": "1",
                "upstream_commit": COLLECTIVE_MEMORY_COMMIT,
            }
            observed = {
                str(row["key"]): str(row["value"])
                for row in database.execute("SELECT key,value FROM metadata")
            }
            if not observed:
                database.executemany(
                    "INSERT INTO metadata(key,value) VALUES (?,?)",
                    sorted(expected.items()),
                )
            elif observed != expected:
                raise CollectiveMemoryError("collective_source_store_mismatch")

    def current(self) -> dict[str, Any] | None:
        self.initialize()
        with closing(self.connect()) as database:
            row = database.execute(
                "SELECT manifest_json FROM generations WHERE state='active'"
            ).fetchone()
        return None if row is None else json.loads(bytes(row["manifest_json"]))

    def artifact_heads(self) -> dict[str, dict[str, Any]]:
        current = self.current()
        if current is None:
            return {}
        return {
            cast(str, item["logical_id"]): copy.deepcopy(item)
            for item in current["body"]["artifacts"]
        }

    def pending(self) -> list[dict[str, Any]]:
        self.initialize()
        with closing(self.connect()) as database:
            rows = database.execute(
                "SELECT manifest_json,preview_id,preview_hash,source_log_hash,"
                "import_event_id,prepared_at_ms FROM generations "
                "WHERE state='prepared' "
                "ORDER BY generation_id"
            ).fetchall()
        return [
            {
                "manifest": json.loads(bytes(row["manifest_json"])),
                "preview_id": row["preview_id"],
                "preview_hash": row["preview_hash"],
                "source_log_hash": row["source_log_hash"],
                "import_event_id": row["import_event_id"],
                "prepared_at_ms": int(row["prepared_at_ms"]),
            }
            for row in rows
        ]

    def recorded_receipt(self, generation_id: str) -> dict[str, Any] | None:
        self.initialize()
        with closing(self.connect()) as database:
            row = database.execute(
                "SELECT receipt_json FROM generations WHERE generation_id=?",
                (generation_id,),
            ).fetchone()
        if row is None or row["receipt_json"] is None:
            return None
        return cast(dict[str, Any], json.loads(bytes(row["receipt_json"])))

    def prepare(
        self,
        preview: Mapping[str, Any],
        contents: Mapping[str, bytes],
        *,
        prepared_at_ms: int,
    ) -> dict[str, Any]:
        self.initialize()
        manifest = cast(Mapping[str, Any], preview["manifest"])
        generation_id = cast(str, manifest["generation_id"])
        with self.exclusive(), closing(self.connect()) as database:
            database.execute("BEGIN IMMEDIATE")
            try:
                replay = database.execute(
                    "SELECT preview_hash,state,receipt_json FROM generations "
                    "WHERE generation_id=?",
                    (generation_id,),
                ).fetchone()
                if replay is not None:
                    if replay["preview_hash"] != preview["preview_hash"]:
                        raise CollectiveMemoryError("collective_generation_collision")
                    database.commit()
                    return {
                        "state": replay["state"],
                        "receipt": None
                        if replay["receipt_json"] is None
                        else json.loads(bytes(replay["receipt_json"])),
                    }
                active = database.execute(
                    "SELECT generation_id,source_log_hash,manifest_json "
                    "FROM generations "
                    "WHERE state='active'"
                ).fetchone()
                predecessor = manifest["body"]["predecessor_generation"]
                if (active is None and predecessor is not None) or (
                    active is not None and predecessor != active["generation_id"]
                ):
                    raise CollectiveMemoryError("collective_generation_fork")
                previous_heads: dict[str, Mapping[str, Any]] = {}
                previous_log_hash: str | None = None
                if active is not None:
                    previous = json.loads(bytes(active["manifest_json"]))
                    previous_heads = {
                        item["logical_id"]: item
                        for item in previous["body"]["artifacts"]
                    }
                    previous_log_hash = cast(str, active["source_log_hash"])
                for item in manifest["body"]["artifacts"]:
                    prior = previous_heads.get(item["logical_id"])
                    if prior is None and item["predecessor_artifact_id"] is not None:
                        raise CollectiveMemoryError("collective_dangling_predecessor")
                    if prior is not None:
                        if item["artifact_id"] == prior["artifact_id"]:
                            if item != prior:
                                raise CollectiveMemoryError(
                                    "collective_artifact_collision"
                                )
                        elif item["predecessor_artifact_id"] != prior["artifact_id"]:
                            raise CollectiveMemoryError("collective_artifact_fork")
                if set(previous_heads) - {
                    item["logical_id"] for item in manifest["body"]["artifacts"]
                }:
                    raise CollectiveMemoryError("collective_implicit_removal")
                source_log_core = {
                    "previous_source_log_hash": previous_log_hash,
                    "generation_id": generation_id,
                    "manifest_hash": manifest["manifest_hash"],
                    "state_digest": manifest["body"]["state_digest"],
                    "artifacts": [
                        {
                            "artifact_id": item["artifact_id"],
                            "logical_id": item["logical_id"],
                            "state": item["state"],
                            "content_hash": item["content_hash"],
                        }
                        for item in manifest["body"]["artifacts"]
                    ],
                }
                source_log_hash = hashlib.sha256(
                    _canonical(source_log_core, "invalid_collective_source_log")
                ).hexdigest()
                event_id = str(
                    uuid.uuid5(uuid.NAMESPACE_URL, cast(str, preview["preview_id"]))
                )
                database.execute(
                    "INSERT INTO generations VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        generation_id,
                        manifest["manifest_hash"],
                        predecessor,
                        manifest["body"]["state_digest"],
                        source_log_hash,
                        preview["preview_id"],
                        preview["preview_hash"],
                        _canonical(manifest, "invalid_collective_export_manifest"),
                        "prepared",
                        event_id,
                        _uint(prepared_at_ms, "invalid_collective_clock"),
                        None,
                        None,
                    ),
                )
                for item in manifest["body"]["artifacts"]:
                    content = None
                    if item["state"] == "active":
                        content = contents.get(item["artifact_id"])
                        if content is None:
                            raise CollectiveMemoryError("collective_content_missing")
                    database.execute(
                        "INSERT INTO artifacts VALUES (?,?,?,?,?)",
                        (
                            generation_id,
                            item["artifact_id"],
                            item["logical_id"],
                            _canonical(item, "invalid_collective_export_artifact"),
                            content,
                        ),
                    )
                database.commit()
                return {
                    "state": "prepared",
                    "receipt": None,
                    "source_log_hash": source_log_hash,
                    "import_event_id": event_id,
                }
            except BaseException:
                database.rollback()
                raise

    def finalize(
        self, generation_id: str, receipt: Mapping[str, Any], event: Mapping[str, Any]
    ) -> None:
        self.initialize()
        with self.exclusive(), closing(self.connect()) as database:
            database.execute("BEGIN IMMEDIATE")
            try:
                row = database.execute(
                    "SELECT state,import_event_id,preview_hash FROM generations "
                    "WHERE generation_id=?",
                    (generation_id,),
                ).fetchone()
                if row is None:
                    raise CollectiveMemoryError("collective_generation_unknown")
                if row["import_event_id"] != event["event_id"]:
                    raise CollectiveMemoryError("collective_import_event_mismatch")
                if row["state"] == "active":
                    existing = database.execute(
                        "SELECT receipt_json,import_event_hash FROM generations "
                        "WHERE generation_id=?",
                        (generation_id,),
                    ).fetchone()
                    if (
                        json.loads(bytes(existing["receipt_json"])) != receipt
                        or existing["import_event_hash"] != event["content_hash"]
                    ):
                        raise CollectiveMemoryError("collective_source_replay_mismatch")
                    database.commit()
                    return
                database.execute(
                    "UPDATE generations SET state='superseded' WHERE state='active'"
                )
                database.execute(
                    "UPDATE generations SET state='active',import_event_hash=?,"
                    "receipt_json=? "
                    "WHERE generation_id=? AND state='prepared'",
                    (
                        event["content_hash"],
                        _canonical(receipt, "invalid_collective_source_receipt"),
                        generation_id,
                    ),
                )
                if database.total_changes < 1:
                    raise CollectiveMemoryError("collective_source_state_conflict")
                database.commit()
            except BaseException:
                database.rollback()
                raise

    def rebuild_projection(
        self, ledger: Ledger, *, repair: bool = True
    ) -> dict[str, Any]:
        """Rebuild the active pointer from the immutable source log and ledger.

        Generation manifests, descriptors, content bytes and source-log hashes are
        authoritative local source evidence.  Matrix ``source.imported`` events
        decide which durable prefix was accepted.  This operation repairs only
        derived state/receipt columns and refuses contradictory source evidence.
        """

        self.initialize()
        with self.exclusive(), closing(self.connect()) as database:
            database.execute("BEGIN IMMEDIATE")
            try:
                rows = database.execute(
                    "SELECT * FROM generations ORDER BY generation_id"
                ).fetchall()
                if not rows:
                    database.commit()
                    empty = {
                        "accepted_generation_count": 0,
                        "generation_count": 0,
                        "head_generation_id": None,
                        "source_log_head": None,
                    }
                    return {
                        "schema": "dm.collective-source.rebuild/v1",
                        **empty,
                        "state_hash": hashlib.sha256(
                            _canonical(empty, "invalid_collective_source_rebuild")
                        ).hexdigest(),
                    }

                decoded: dict[str, tuple[sqlite3.Row, dict[str, Any]]] = {}
                children: dict[str | None, list[str]] = {}
                for row in rows:
                    manifest = validate_export_manifest(
                        json.loads(bytes(row["manifest_json"]))
                    )
                    generation_id = cast(str, manifest["generation_id"])
                    body = cast(Mapping[str, Any], manifest["body"])
                    predecessor = cast(str | None, body["predecessor_generation"])
                    if generation_id in decoded or any(
                        (
                            row["generation_id"] != generation_id,
                            row["manifest_hash"] != manifest["manifest_hash"],
                            row["predecessor_generation"] != predecessor,
                            row["state_digest"] != body["state_digest"],
                        )
                    ):
                        raise CollectiveMemoryError("collective_source_log_drift")
                    bindings = [
                        {
                            "artifact_id": item["artifact_id"],
                            "content_hash": item["content_hash"],
                            "content_length": item["content_length"],
                            "state": item["state"],
                        }
                        for item in body["artifacts"]
                    ]
                    preview_core = {
                        "manifest": manifest,
                        "content_bindings": bindings,
                    }
                    if (
                        row["preview_id"]
                        != _derived(
                            "dm:collective-source-preview:v1:",
                            SOURCE_PREVIEW_DOMAIN,
                            preview_core,
                        )
                        or row["preview_hash"]
                        != hashlib.sha256(
                            _canonical(
                                preview_core, "invalid_collective_source_preview"
                            )
                        ).hexdigest()
                    ):
                        raise CollectiveMemoryError("collective_source_log_drift")
                    decoded[generation_id] = (row, manifest)
                    children.setdefault(predecessor, []).append(generation_id)

                roots = children.get(None, [])
                if len(roots) != 1:
                    raise CollectiveMemoryError("collective_source_log_fork")
                ordered: list[str] = []
                candidate = roots[0]
                while True:
                    if candidate in ordered:
                        raise CollectiveMemoryError("collective_source_log_cycle")
                    ordered.append(candidate)
                    successors = children.get(candidate, [])
                    if len(successors) > 1:
                        raise CollectiveMemoryError("collective_source_log_fork")
                    if not successors:
                        break
                    candidate = successors[0]
                if len(ordered) != len(decoded):
                    raise CollectiveMemoryError("collective_source_log_disconnected")

                previous_source_log_hash: str | None = None
                accepted: list[tuple[str, dict[str, Any], Event]] = []
                prepared: list[str] = []
                missing_event_seen = False
                for generation_id in ordered:
                    row, manifest = decoded[generation_id]
                    body = cast(Mapping[str, Any], manifest["body"])
                    artifact_rows = database.execute(
                        "SELECT artifact_id,logical_id,descriptor_json,content "
                        "FROM artifacts WHERE generation_id=? ORDER BY artifact_id",
                        (generation_id,),
                    ).fetchall()
                    artifacts = cast(list[Mapping[str, Any]], body["artifacts"])
                    if len(artifact_rows) != len(artifacts):
                        raise CollectiveMemoryError("collective_source_log_drift")
                    stored_artifacts = {
                        cast(str, item["artifact_id"]): item for item in artifact_rows
                    }
                    for descriptor in artifacts:
                        stored = stored_artifacts.get(
                            cast(str, descriptor["artifact_id"])
                        )
                        if (
                            stored is None
                            or stored["logical_id"] != descriptor["logical_id"]
                            or json.loads(bytes(stored["descriptor_json"]))
                            != descriptor
                        ):
                            raise CollectiveMemoryError("collective_source_log_drift")
                        content = stored["content"]
                        if descriptor["state"] == "tombstone":
                            if content is not None:
                                raise CollectiveMemoryError(
                                    "collective_source_log_drift"
                                )
                        elif (
                            content is None
                            or len(bytes(content)) != descriptor["content_length"]
                            or hashlib.sha256(bytes(content)).hexdigest()
                            != descriptor["content_hash"]
                        ):
                            raise CollectiveMemoryError("collective_source_log_drift")

                    source_log_core = {
                        "previous_source_log_hash": previous_source_log_hash,
                        "generation_id": generation_id,
                        "manifest_hash": manifest["manifest_hash"],
                        "state_digest": body["state_digest"],
                        "artifacts": [
                            {
                                "artifact_id": item["artifact_id"],
                                "logical_id": item["logical_id"],
                                "state": item["state"],
                                "content_hash": item["content_hash"],
                            }
                            for item in artifacts
                        ],
                    }
                    observed_source_log_hash = hashlib.sha256(
                        _canonical(source_log_core, "invalid_collective_source_log")
                    ).hexdigest()
                    if row["source_log_hash"] != observed_source_log_hash:
                        raise CollectiveMemoryError("collective_source_log_drift")
                    previous_source_log_hash = observed_source_log_hash

                    event = ledger.event(cast(str, row["import_event_id"]))
                    if event is None:
                        missing_event_seen = True
                        if (
                            row["receipt_json"] is not None
                            or row["import_event_hash"] is not None
                        ):
                            raise CollectiveMemoryError("collective_source_log_drift")
                        prepared.append(generation_id)
                        continue
                    if missing_event_seen or event["kind"] != "source.imported":
                        raise CollectiveMemoryError("collective_source_log_event_drift")
                    receipt = validate_source_receipt(
                        _source_receipt(
                            manifest,
                            preview_id=cast(str, row["preview_id"]),
                            preview_hash=cast(str, row["preview_hash"]),
                            source_log_hash=observed_source_log_hash,
                            import_event_id=cast(str, row["import_event_id"]),
                            imported_at_ms=int(row["prepared_at_ms"]),
                        )
                    )
                    if (
                        event["payload"] != receipt
                        or event["subject"] != ledger.authority.manifest.being_ref
                        or (
                            row["receipt_json"] is not None
                            and json.loads(bytes(row["receipt_json"])) != receipt
                        )
                        or (
                            row["import_event_hash"] is not None
                            and row["import_event_hash"] != event["content_hash"]
                        )
                    ):
                        raise CollectiveMemoryError("collective_source_log_event_drift")
                    accepted.append((generation_id, receipt, event))

                if len(prepared) > 1:
                    raise CollectiveMemoryError(
                        "collective_source_log_uncommitted_tail"
                    )
                head = None if not accepted else accepted[-1][0]
                if repair:
                    database.execute("UPDATE generations SET state='prepared'")
                    for generation_id, receipt, event in accepted:
                        database.execute(
                            "UPDATE generations SET state='superseded',"
                            "receipt_json=?,import_event_hash=? WHERE generation_id=?",
                            (
                                _canonical(
                                    receipt, "invalid_collective_source_receipt"
                                ),
                                event["content_hash"],
                                generation_id,
                            ),
                        )
                    if head is not None:
                        database.execute(
                            "UPDATE generations SET state='active' "
                            "WHERE generation_id=?",
                            (head,),
                        )
                else:
                    accepted_by_id = {
                        generation_id: (receipt, event)
                        for generation_id, receipt, event in accepted
                    }
                    for generation_id in ordered:
                        row, _manifest = decoded[generation_id]
                        expected_state = (
                            "prepared"
                            if generation_id not in accepted_by_id
                            else "active"
                            if generation_id == head
                            else "superseded"
                        )
                        if row["state"] != expected_state:
                            raise CollectiveMemoryError(
                                "collective_source_effect_truth_discrepancy"
                            )
                        accepted_row = accepted_by_id.get(generation_id)
                        if accepted_row is not None:
                            receipt, event = accepted_row
                            if (
                                row["receipt_json"] is None
                                or row["import_event_hash"] is None
                                or json.loads(bytes(row["receipt_json"])) != receipt
                                or row["import_event_hash"] != event["content_hash"]
                            ):
                                raise CollectiveMemoryError(
                                    "collective_source_effect_truth_discrepancy"
                                )
                state = {
                    "accepted_generation_count": len(accepted),
                    "generation_count": len(ordered),
                    "head_generation_id": head,
                    "source_log_head": previous_source_log_hash,
                }
                database.commit()
                return {
                    "schema": "dm.collective-source.rebuild/v1",
                    **state,
                    "state_hash": hashlib.sha256(
                        _canonical(state, "invalid_collective_source_rebuild")
                    ).hexdigest(),
                }
            except BaseException:
                database.rollback()
                raise

    def record_error(
        self,
        code: str,
        *,
        retryable: bool,
        occurred_at_ms: int,
        context: Mapping[str, Any],
    ) -> None:
        self.initialize()
        context_hash = hashlib.sha256(
            _canonical(context, "invalid_collective_error")
        ).hexdigest()
        error_id = "dm:collective-error:v1:" + b64url(
            hashlib.sha256(f"{code}:{occurred_at_ms}:{context_hash}".encode()).digest()
        )
        with closing(self.connect()) as database:
            database.execute(
                "INSERT OR IGNORE INTO errors VALUES (?,?,?,?,?)",
                (error_id, code, int(retryable), occurred_at_ms, context_hash),
            )


def validate_source_preview(value: Any) -> dict[str, Any]:
    code = "invalid_collective_source_preview"
    row = _closed(
        value,
        {"schema", "preview_id", "preview_hash", "manifest", "content_bindings"},
        code,
    )
    if row["schema"] != SOURCE_PREVIEW_SCHEMA:
        raise CollectiveMemoryError(code)
    manifest = validate_export_manifest(row["manifest"])
    raw = row["content_bindings"]
    if not isinstance(raw, list):
        raise CollectiveMemoryError(code)
    bindings: list[dict[str, Any]] = []
    for item in raw:
        binding = _closed(
            item, {"artifact_id", "content_hash", "content_length", "state"}, code
        )
        if binding["state"] not in {"active", "tombstone"}:
            raise CollectiveMemoryError(code)
        bindings.append(
            {
                "artifact_id": _identifier(binding["artifact_id"], code),
                "content_hash": _nullable_hash(binding["content_hash"], code),
                "content_length": _uint(
                    binding["content_length"], code, maximum=MAX_ARTIFACT_BYTES
                ),
                "state": binding["state"],
            }
        )
    expected = [
        {
            "artifact_id": item["artifact_id"],
            "content_hash": item["content_hash"],
            "content_length": item["content_length"],
            "state": item["state"],
        }
        for item in manifest["body"]["artifacts"]
    ]
    if bindings != expected:
        raise CollectiveMemoryError("collective_source_preview_manifest_mismatch")
    core = {"manifest": manifest, "content_bindings": bindings}
    preview_id = _derived(
        "dm:collective-source-preview:v1:", SOURCE_PREVIEW_DOMAIN, core
    )
    preview_hash = hashlib.sha256(_canonical(core, code)).hexdigest()
    if row["preview_id"] != preview_id or row["preview_hash"] != preview_hash:
        raise CollectiveMemoryError("collective_source_preview_identity_mismatch")
    return {
        "schema": SOURCE_PREVIEW_SCHEMA,
        "preview_id": preview_id,
        "preview_hash": preview_hash,
        **core,
    }


def _source_receipt(
    manifest: Mapping[str, Any],
    *,
    preview_id: str,
    preview_hash: str,
    source_log_hash: str,
    import_event_id: str,
    imported_at_ms: int,
) -> dict[str, Any]:
    active = sum(item["state"] == "active" for item in manifest["body"]["artifacts"])
    tombstones = manifest["body"]["artifact_count"] - active
    body = {
        "adapter_id": SOURCE_ADAPTER_ID,
        "importer_version": SOURCE_IMPORTER_VERSION,
        "producer_instance": manifest["body"]["producer_instance"],
        "producer_release": manifest["body"]["producer_release"],
        "policy_version": manifest["body"]["policy_version"],
        "scope_id": manifest["body"]["scope_id"],
        "generation_id": manifest["generation_id"],
        "manifest_hash": manifest["manifest_hash"],
        "predecessor_generation": manifest["body"]["predecessor_generation"],
        "state_digest": manifest["body"]["state_digest"],
        "artifact_count": manifest["body"]["artifact_count"],
        "total_content_bytes": manifest["body"]["total_content_bytes"],
        "outcomes": {
            "admitted_to_quarantine": active,
            "tombstoned": tombstones,
            "personal_memory_assertions": 0,
        },
        "preview_id": preview_id,
        "preview_hash": preview_hash,
        "source_log_hash": source_log_hash,
        "import_event_id": import_event_id,
        "imported_at_ms": _uint(imported_at_ms, "invalid_collective_clock"),
        "decision": "quarantined",
        "reason_codes": ["quarantined:initial-pull"],
    }
    receipt_id = _derived(
        "dm:collective-source-receipt:v1:", SOURCE_RECEIPT_DOMAIN, body
    )
    return {"schema": SOURCE_RECEIPT_SCHEMA, "receipt_id": receipt_id, "body": body}


def validate_source_receipt(value: Any) -> dict[str, Any]:
    code = "invalid_collective_source_receipt"
    row = _closed(value, {"schema", "receipt_id", "body"}, code)
    if row["schema"] != SOURCE_RECEIPT_SCHEMA:
        raise CollectiveMemoryError(code)
    body = _closed(
        row["body"],
        {
            "adapter_id",
            "importer_version",
            "producer_instance",
            "producer_release",
            "policy_version",
            "scope_id",
            "generation_id",
            "manifest_hash",
            "predecessor_generation",
            "state_digest",
            "artifact_count",
            "total_content_bytes",
            "outcomes",
            "preview_id",
            "preview_hash",
            "source_log_hash",
            "import_event_id",
            "imported_at_ms",
            "decision",
            "reason_codes",
        },
        code,
    )
    if (
        body["adapter_id"] != SOURCE_ADAPTER_ID
        or body["importer_version"] != SOURCE_IMPORTER_VERSION
        or body["decision"] != "quarantined"
        or body["reason_codes"] != ["quarantined:initial-pull"]
    ):
        raise CollectiveMemoryError(code)
    outcomes = _closed(
        body["outcomes"],
        {"admitted_to_quarantine", "tombstoned", "personal_memory_assertions"},
        code,
    )
    artifact_count = _uint(body["artifact_count"], code, maximum=MAX_ARTIFACTS)
    active = _uint(outcomes["admitted_to_quarantine"], code, maximum=MAX_ARTIFACTS)
    tombstones = _uint(outcomes["tombstoned"], code, maximum=MAX_ARTIFACTS)
    if (
        active + tombstones != artifact_count
        or outcomes["personal_memory_assertions"] != 0
    ):
        raise CollectiveMemoryError(code)
    normalized_body = {
        **dict(body),
        "producer_instance": _identifier(body["producer_instance"], code),
        "producer_release": _identifier(body["producer_release"], code),
        "policy_version": _identifier(body["policy_version"], code),
        "scope_id": _identifier(body["scope_id"], code),
        "generation_id": _identifier(body["generation_id"], code),
        "manifest_hash": _hash(body["manifest_hash"], code),
        "predecessor_generation": _nullable_identifier(
            body["predecessor_generation"], code
        ),
        "state_digest": _hash(body["state_digest"], code),
        "artifact_count": artifact_count,
        "total_content_bytes": _uint(
            body["total_content_bytes"], code, maximum=MAX_EXPORT_BYTES
        ),
        "outcomes": {
            "admitted_to_quarantine": active,
            "tombstoned": tombstones,
            "personal_memory_assertions": 0,
        },
        "preview_id": _identifier(body["preview_id"], code),
        "preview_hash": _hash(body["preview_hash"], code),
        "source_log_hash": _hash(body["source_log_hash"], code),
        "import_event_id": _uuid(body["import_event_id"], code),
        "imported_at_ms": _uint(body["imported_at_ms"], code),
    }
    expected_id = _derived(
        "dm:collective-source-receipt:v1:", SOURCE_RECEIPT_DOMAIN, normalized_body
    )
    if row["receipt_id"] != expected_id:
        raise CollectiveMemoryError("collective_source_receipt_identity_mismatch")
    return {
        "schema": SOURCE_RECEIPT_SCHEMA,
        "receipt_id": expected_id,
        "body": normalized_body,
    }


@dataclass(frozen=True)
class CollectiveSourceAdapter:
    ledger: Ledger
    profile: Mapping[str, Any]
    transport: SourceTransport
    store: CollectiveSourceStore
    signer: EventSigner
    clock: Clock
    fault: Fault = _no_fault

    def __post_init__(self) -> None:
        profile = validate_source_profile(self.profile)
        object.__setattr__(self, "profile", profile)
        self.store.initialize()

    def _fetch(
        self, generation_id: str | None = None
    ) -> tuple[dict[str, Any], dict[str, bytes]]:
        try:
            manifest_raw = self.transport(
                "manifest",
                {
                    "scope_id": self.profile["scope_id"],
                    "generation_id": generation_id,
                },
            )
            manifest = validate_export_manifest(manifest_raw)
            if generation_id is not None and manifest["generation_id"] != generation_id:
                raise CollectiveMemoryError("collective_mixed_generation")
            body = manifest["body"]
            for field in (
                "producer_instance",
                "producer_release",
                "policy_version",
                "scope_id",
            ):
                if body[field] != self.profile[field]:
                    raise CollectiveMemoryError("collective_source_profile_mismatch")
            artifacts: list[dict[str, Any]] = []
            cursor: str | None = None
            offset = 0
            seen: set[str] = set()
            while offset < body["artifact_count"] or (offset == 0 and not artifacts):
                request = {
                    "generation_id": manifest["generation_id"],
                    "cursor": cursor,
                    "limit": MAX_PAGE,
                }
                page_raw = self.transport("page", request)
                page = validate_export_page(
                    page_raw,
                    manifest,
                    expected_offset=offset,
                    expected_limit=MAX_PAGE,
                )
                page_artifacts = cast(list[dict[str, Any]], page["artifacts"])
                artifacts.extend(page_artifacts)
                offset += len(page_artifacts)
                next_cursor = cast(str | None, page["next_cursor"])
                if next_cursor is None:
                    break
                if next_cursor in seen or not page_artifacts:
                    raise CollectiveMemoryError("collective_cursor_cycle")
                seen.add(next_cursor)
                cursor = next_cursor
            if artifacts != body["artifacts"]:
                raise CollectiveMemoryError("collective_partial_or_mixed_generation")
            contents: dict[str, bytes] = {}
            for item in artifacts:
                if item["state"] == "tombstone":
                    continue
                raw = self.transport(
                    "object",
                    {
                        "generation_id": manifest["generation_id"],
                        "content_ref": item["content_ref"],
                    },
                )
                if not isinstance(raw, bytes):
                    raise CollectiveMemoryError("collective_invalid_content_response")
                if (
                    len(raw) != item["content_length"]
                    or hashlib.sha256(raw).hexdigest() != item["content_hash"]
                ):
                    raise CollectiveMemoryError("collective_content_mismatch")
                try:
                    raw.decode("utf-8")
                except UnicodeDecodeError as exception:
                    raise CollectiveMemoryError(
                        "collective_content_not_utf8"
                    ) from exception
                existing = contents.get(item["artifact_id"])
                if existing is not None and existing != raw:
                    raise CollectiveMemoryError("collective_artifact_collision")
                contents[item["artifact_id"]] = raw
            return manifest, contents
        except CollectiveMemoryError:
            raise
        except (ConnectionError, TimeoutError, OSError) as exception:
            raise CollectiveMemoryError(
                "collective_source_unavailable", retryable=True
            ) from exception
        except Exception as exception:
            raise CollectiveMemoryError(
                "collective_source_invalid_response"
            ) from exception

    @staticmethod
    def _preview_value(manifest: Mapping[str, Any]) -> dict[str, Any]:
        bindings = [
            {
                "artifact_id": item["artifact_id"],
                "content_hash": item["content_hash"],
                "content_length": item["content_length"],
                "state": item["state"],
            }
            for item in manifest["body"]["artifacts"]
        ]
        core = {"manifest": manifest, "content_bindings": bindings}
        preview = {
            "schema": SOURCE_PREVIEW_SCHEMA,
            "preview_id": _derived(
                "dm:collective-source-preview:v1:", SOURCE_PREVIEW_DOMAIN, core
            ),
            "preview_hash": hashlib.sha256(
                _canonical(core, "invalid_collective_source_preview")
            ).hexdigest(),
            **core,
        }
        return validate_source_preview(preview)

    def preview(self, generation_id: str | None = None) -> dict[str, Any]:
        manifest, _contents = self._fetch(generation_id)
        current = self.store.current()
        if current is None:
            if manifest["body"]["predecessor_generation"] is not None:
                raise CollectiveMemoryError("collective_generation_gap")
        elif (
            manifest["generation_id"] != current["generation_id"]
            and manifest["body"]["predecessor_generation"] != current["generation_id"]
        ):
            raise CollectiveMemoryError("collective_generation_gap")
        return self._preview_value(manifest)

    def preview_catch_up(self) -> list[dict[str, Any]]:
        latest, _contents = self._fetch()
        current = self.store.current()
        stop = None if current is None else current["generation_id"]
        if latest["generation_id"] == stop:
            return []
        reverse: list[dict[str, Any]] = []
        seen: set[str] = set()
        candidate = latest
        while candidate["generation_id"] != stop:
            generation_id = cast(str, candidate["generation_id"])
            if generation_id in seen or len(reverse) >= MAX_ARTIFACTS:
                raise CollectiveMemoryError("collective_generation_cycle")
            seen.add(generation_id)
            reverse.append(candidate)
            predecessor = candidate["body"]["predecessor_generation"]
            if predecessor is None:
                if stop is not None:
                    raise CollectiveMemoryError("collective_generation_gap")
                break
            candidate, _contents = self._fetch(predecessor)
            if (
                reverse[-1]["body"]["predecessor_generation"]
                != candidate["generation_id"]
            ):
                raise CollectiveMemoryError("collective_generation_fork")
        chain = list(reversed(reverse))
        predecessor = stop
        for manifest in chain:
            if manifest["body"]["predecessor_generation"] != predecessor:
                raise CollectiveMemoryError("collective_generation_fork")
            predecessor = manifest["generation_id"]
        return [self._preview_value(manifest) for manifest in chain]

    def catch_up(self) -> list[dict[str, Any]]:
        return [self.apply(preview) for preview in self.preview_catch_up()]

    def apply(self, preview: Mapping[str, Any]) -> dict[str, Any]:
        try:
            return self._apply(preview)
        except CollectiveMemoryError as exception:
            self.store.record_error(
                exception.code,
                retryable=exception.retryable,
                occurred_at_ms=self.clock(),
                context={"operation": "apply", "scope_id": self.profile["scope_id"]},
            )
            raise

    def _apply(self, preview: Mapping[str, Any]) -> dict[str, Any]:
        normalized = validate_source_preview(preview)
        recorded = self.store.recorded_receipt(normalized["manifest"]["generation_id"])
        if recorded is not None:
            recorded = validate_source_receipt(recorded)
            self.reconcile(recorded)
            return recorded
        fresh_manifest, contents = self._fetch(normalized["manifest"]["generation_id"])
        if fresh_manifest != normalized["manifest"]:
            raise CollectiveMemoryError("collective_source_preview_stale")
        fresh = self._preview_value(fresh_manifest)
        if fresh != normalized:
            raise CollectiveMemoryError("collective_source_preview_stale")
        prepared_at = self.clock()
        prepared = self.store.prepare(normalized, contents, prepared_at_ms=prepared_at)
        if prepared.get("receipt") is not None:
            return validate_source_receipt(prepared["receipt"])
        self.fault("source-prepared")
        return self._commit_pending(
            {
                "manifest": normalized["manifest"],
                "preview_id": normalized["preview_id"],
                "preview_hash": normalized["preview_hash"],
                "source_log_hash": prepared["source_log_hash"],
                "import_event_id": prepared["import_event_id"],
                "prepared_at_ms": prepared_at,
            }
        )

    def _commit_pending(self, pending: Mapping[str, Any]) -> dict[str, Any]:
        manifest = pending["manifest"]
        receipt = _source_receipt(
            manifest,
            preview_id=pending["preview_id"],
            preview_hash=pending["preview_hash"],
            source_log_hash=pending["source_log_hash"],
            import_event_id=pending["import_event_id"],
            imported_at_ms=pending["prepared_at_ms"],
        )
        receipt = validate_source_receipt(receipt)
        event = self.ledger.append_local_idempotent(
            client_id="collective-source-v1",
            request_id=pending["import_event_id"],
            request_hash=pending["preview_hash"],
            kind="source.imported",
            subject=self.ledger.authority.manifest.being_ref,
            payload=receipt,
            signer=self.signer,
            sensitivity="shareable"
            if manifest["body"]["scope_id"] == "public"
            else "private",
            occurred_at_ms=pending["prepared_at_ms"],
            event_id=pending["import_event_id"],
        )
        self.fault("source-ledger-appended")
        self.store.finalize(manifest["generation_id"], receipt, event)
        self.fault("source-activated")
        return receipt

    def recover(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for pending in self.store.pending():
            receipt = self._commit_pending(pending)
            results.append(
                {
                    "generation_id": pending["manifest"]["generation_id"],
                    "receipt_id": receipt["receipt_id"],
                    "outcome": "activated",
                }
            )
        return results

    def rebuild(self) -> dict[str, Any]:
        """Rebuild the derived active generation without remote input."""

        return self.store.rebuild_projection(self.ledger)

    def reconcile(self, receipt: Mapping[str, Any]) -> dict[str, Any]:
        normalized = validate_source_receipt(receipt)
        self.store.rebuild_projection(self.ledger, repair=False)
        current = self.store.current()
        if (
            current is None
            or current["generation_id"] != normalized["body"]["generation_id"]
        ):
            raise CollectiveMemoryError("collective_source_effect_truth_discrepancy")
        stored = self.store.recorded_receipt(current["generation_id"])
        if stored != normalized:
            raise CollectiveMemoryError("collective_source_effect_truth_discrepancy")
        event = self.ledger.event(normalized["body"]["import_event_id"])
        if (
            event is None
            or event["kind"] != "source.imported"
            or event["payload"] != normalized
        ):
            raise CollectiveMemoryError("collective_source_effect_truth_discrepancy")
        return {
            "schema": "dm.collective-source.reconciliation/v1",
            "receipt_id": normalized["receipt_id"],
            "generation_id": current["generation_id"],
            "effect": "verified",
        }


class CollectivePublisherJournal(_Store):
    """Outbound-only queue and recovery journal."""

    def initialize(self) -> None:
        with closing(self.connect()) as database:
            database.executescript(
                """
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                ) WITHOUT ROWID;
                CREATE TABLE IF NOT EXISTS requests (
                    request_id TEXT PRIMARY KEY,
                    request_hash TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL UNIQUE,
                    target_id TEXT NOT NULL,
                    request_json BLOB NOT NULL,
                    preview_json BLOB NOT NULL,
                    plan_json BLOB NOT NULL,
                    consent_hash TEXT NOT NULL,
                    review_hash TEXT NOT NULL,
                    request_event_id TEXT NOT NULL UNIQUE,
                    request_event_hash TEXT,
                    provider_receipt_json BLOB,
                    reconciliation_json BLOB,
                    acceptance_json BLOB,
                    acceptance_event_id TEXT UNIQUE,
                    acceptance_event_hash TEXT,
                    state TEXT NOT NULL
                        CHECK(state IN ('prepared','queued','effected','accepted')),
                    created_at_ms INTEGER NOT NULL
                );
                CREATE UNIQUE INDEX IF NOT EXISTS one_pending_target
                    ON requests(target_id)
                    WHERE state IN ('prepared','queued','effected');
                """
            )
            expected = {
                "adapter_id": PUBLISHER_ADAPTER_ID,
                "schema_version": "1",
                "upstream_commit": COLLECTIVE_MEMORY_COMMIT,
            }
            observed = {
                str(row["key"]): str(row["value"])
                for row in database.execute("SELECT key,value FROM metadata")
            }
            if not observed:
                database.executemany(
                    "INSERT INTO metadata(key,value) VALUES (?,?)",
                    sorted(expected.items()),
                )
            elif observed != expected:
                raise CollectiveMemoryError("collective_publisher_store_mismatch")

    @staticmethod
    def _decode(row: sqlite3.Row) -> dict[str, Any]:
        result: dict[str, Any] = dict(row)
        for field in (
            "request_json",
            "preview_json",
            "plan_json",
            "provider_receipt_json",
            "reconciliation_json",
            "acceptance_json",
        ):
            if result[field] is not None:
                result[field.removesuffix("_json")] = json.loads(bytes(result[field]))
            result.pop(field)
        return result

    def prepare(
        self,
        *,
        request_id: str,
        request: Mapping[str, Any],
        preview: Mapping[str, Any],
        plan: Mapping[str, Any],
        consent_hash: str,
        review_hash: str,
        request_event_id: str,
        created_at_ms: int,
    ) -> dict[str, Any]:
        self.initialize()
        request_hash = hashlib.sha256(
            _canonical(request, "invalid_collective_publication_request")
        ).hexdigest()
        with self.exclusive(), closing(self.connect()) as database:
            database.execute("BEGIN IMMEDIATE")
            try:
                replay = database.execute(
                    "SELECT * FROM requests WHERE idempotency_key=?",
                    (request["idempotency_key"],),
                ).fetchone()
                if replay is not None:
                    decoded = self._decode(replay)
                    if (
                        decoded["request_hash"] != request_hash
                        or decoded["request_id"] != request_id
                    ):
                        raise CollectiveMemoryError("collective_idempotency_conflict")
                    database.commit()
                    return decoded
                database.execute(
                    "INSERT INTO requests VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        request_id,
                        request_hash,
                        request["idempotency_key"],
                        request["draft"]["target_id"],
                        _canonical(request, "invalid_collective_publication_request"),
                        _canonical(preview, "invalid_collective_publication_preview"),
                        _canonical(plan, "invalid_collective_publication_plan"),
                        consent_hash,
                        review_hash,
                        request_event_id,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        "prepared",
                        created_at_ms,
                    ),
                )
                row = database.execute(
                    "SELECT * FROM requests WHERE request_id=?", (request_id,)
                ).fetchone()
                database.commit()
                return self._decode(row)
            except sqlite3.IntegrityError as exception:
                database.rollback()
                raise CollectiveMemoryError(
                    "collective_publication_target_pending", retryable=True
                ) from exception
            except BaseException:
                database.rollback()
                raise

    def rows(self, *, states: Sequence[str] | None = None) -> list[dict[str, Any]]:
        self.initialize()
        query = "SELECT * FROM requests"
        parameters: tuple[Any, ...] = ()
        if states:
            query += " WHERE state IN (" + ",".join("?" for _ in states) + ")"
            parameters = tuple(states)
        query += " ORDER BY request_id"
        with closing(self.connect()) as database:
            rows = database.execute(query, parameters).fetchall()
        return [self._decode(row) for row in rows]

    def by_event(self, event_id: str) -> dict[str, Any]:
        self.initialize()
        with closing(self.connect()) as database:
            row = database.execute(
                "SELECT * FROM requests WHERE request_event_id=?", (event_id,)
            ).fetchone()
        if row is None:
            raise CollectiveMemoryError("collective_publication_request_unknown")
        return self._decode(row)

    def mark_queued(self, request_id: str, event: Mapping[str, Any]) -> None:
        self.initialize()
        with self.exclusive(), closing(self.connect()) as database:
            database.execute("BEGIN IMMEDIATE")
            row = database.execute(
                "SELECT state,request_event_id,request_event_hash FROM requests "
                "WHERE request_id=?",
                (request_id,),
            ).fetchone()
            if row is None or row["request_event_id"] != event["event_id"]:
                database.rollback()
                raise CollectiveMemoryError("collective_publication_request_mismatch")
            if (
                row["state"] != "prepared"
                and row["request_event_hash"] != event["content_hash"]
            ):
                database.rollback()
                raise CollectiveMemoryError("collective_publication_request_mismatch")
            database.execute(
                "UPDATE requests SET state='queued',request_event_hash=? "
                "WHERE request_id=? AND state='prepared'",
                (event["content_hash"], request_id),
            )
            database.commit()

    def mark_effected(
        self,
        request_id: str,
        receipt: Mapping[str, Any],
        reconciliation: Mapping[str, Any],
    ) -> None:
        self.initialize()
        with self.exclusive(), closing(self.connect()) as database:
            database.execute("BEGIN IMMEDIATE")
            row = database.execute(
                "SELECT state,provider_receipt_json,reconciliation_json FROM requests "
                "WHERE request_id=?",
                (request_id,),
            ).fetchone()
            if row is None or row["state"] not in {"queued", "effected"}:
                database.rollback()
                raise CollectiveMemoryError("collective_publication_state_conflict")
            if row["state"] == "effected" and (
                json.loads(bytes(row["provider_receipt_json"])) != receipt
                or json.loads(bytes(row["reconciliation_json"])) != reconciliation
            ):
                database.rollback()
                raise CollectiveMemoryError("collective_publication_effect_collision")
            database.execute(
                "UPDATE requests SET state='effected',provider_receipt_json=?,"
                "reconciliation_json=? WHERE request_id=?",
                (
                    _canonical(receipt, "invalid_collective_publication_receipt"),
                    _canonical(
                        reconciliation, "invalid_collective_publication_reconciliation"
                    ),
                    request_id,
                ),
            )
            database.commit()

    def mark_accepted(
        self,
        request_id: str,
        acceptance: Mapping[str, Any],
        event: Mapping[str, Any],
    ) -> None:
        self.initialize()
        with self.exclusive(), closing(self.connect()) as database:
            database.execute("BEGIN IMMEDIATE")
            row = database.execute(
                "SELECT state,acceptance_json,acceptance_event_id,"
                "acceptance_event_hash "
                "FROM requests WHERE request_id=?",
                (request_id,),
            ).fetchone()
            if row is None:
                database.rollback()
                raise CollectiveMemoryError("collective_publication_request_unknown")
            if row["state"] == "accepted":
                if (
                    json.loads(bytes(row["acceptance_json"])) != acceptance
                    or row["acceptance_event_id"] != event["event_id"]
                    or row["acceptance_event_hash"] != event["content_hash"]
                ):
                    database.rollback()
                    raise CollectiveMemoryError(
                        "collective_publication_acceptance_collision"
                    )
                database.commit()
                return
            if row["state"] != "effected":
                database.rollback()
                raise CollectiveMemoryError("collective_publication_state_conflict")
            database.execute(
                "UPDATE requests SET state='accepted',acceptance_json=?,"
                "acceptance_event_id=?,acceptance_event_hash=? WHERE request_id=?",
                (
                    _canonical(acceptance, "invalid_collective_publication_acceptance"),
                    event["event_id"],
                    event["content_hash"],
                    request_id,
                ),
            )
            database.commit()


def assert_separate_collective_stores(
    source: CollectiveSourceStore, publisher: CollectivePublisherJournal
) -> None:
    if source.path == publisher.path:
        raise CollectiveMemoryError("collective_direction_store_shared")
    for left, right in (
        (source.path, publisher.path),
        (source.lock_path, publisher.lock_path),
    ):
        if left.exists() and right.exists() and os.path.samefile(left, right):
            raise CollectiveMemoryError("collective_direction_store_shared")


def _utc_from_ms(value: int) -> str:
    instant = dt.datetime.fromtimestamp(
        _uint(value, "invalid_collective_clock") / 1000, tz=dt.UTC
    )
    return instant.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _known_events(ledger: Ledger) -> list[Event]:
    return ledger.events(include_incomplete=False)


def collective_checkpoint(
    ledger: Ledger, source_event_ids: Sequence[str]
) -> dict[str, Any]:
    if not source_event_ids or len(source_event_ids) > MAX_SOURCE_REFS:
        raise CollectiveMemoryError("invalid_collective_source_events")
    by_id = {event["event_id"]: event for event in _known_events(ledger)}
    superseded = {
        event["supersedes"]
        for event in by_id.values()
        if event["supersedes"] is not None
    }
    refs: list[dict[str, str]] = []
    for event_id in source_event_ids:
        event = by_id.get(_uuid(event_id, "invalid_collective_source_events"))
        if event is None or event_id in superseded:
            raise CollectiveMemoryError("collective_source_event_unavailable")
        refs.append({"id": event_id, "hash": event["content_hash"]})
    refs.sort(key=lambda item: (item["id"], item["hash"]))
    if len({item["id"] for item in refs}) != len(refs):
        raise CollectiveMemoryError("invalid_collective_source_events")
    core = {
        "being_ref": ledger.authority.manifest.being_ref,
        "manifest_hash": ledger.authority.manifest.digest,
        "source_refs": refs,
    }
    return {
        "id": _derived("dm:collective-checkpoint:v1:", PUBLISHER_REQUEST_DOMAIN, core),
        "hash": hashlib.sha256(
            _canonical(core, "invalid_collective_checkpoint")
        ).hexdigest(),
        "core": core,
    }


def _request_summary(
    request: Mapping[str, Any],
    preview: Mapping[str, Any],
    plan: Mapping[str, Any],
    *,
    request_id: str,
    consent_hash: str,
    review_hash: str,
    requested_at_ms: int,
) -> dict[str, Any]:
    draft = request["draft"]
    body = {
        "adapter_id": PUBLISHER_ADAPTER_ID,
        "publisher_version": PUBLISHER_VERSION,
        "request_id": request_id,
        "request_hash": hashlib.sha256(
            _canonical(request, "invalid_collective_publication_request")
        ).hexdigest(),
        "plan_id": plan["plan_id"],
        "plan_hash": plan["plan_hash"],
        "idempotency_key": request["idempotency_key"],
        "requester_id": draft["requester_id"],
        "subject_id": draft["subject_id"],
        "target_id": draft["target_id"],
        "action": draft["action"],
        "source_refs": copy.deepcopy(draft["source_refs"]),
        "source_checkpoint": copy.deepcopy(draft["source_checkpoint"]),
        "classification": draft["classification"],
        "policy_version": draft["policy_version"],
        "preview_id": preview["preview_id"],
        "preview_hash": preview["preview_hash"],
        "content_hash": preview["body"]["rendered"]["content_hash"],
        "content_length": preview["body"]["rendered"]["content_length"],
        "consent": {
            "evidence_id": request["consent"]["body"]["evidence_id"],
            "evidence_hash": consent_hash,
        },
        "review": {
            "evidence_id": request["review"]["body"]["evidence_id"],
            "evidence_hash": review_hash,
            "reviewer": request["review"]["body"]["issuer"],
        },
        "predecessor": {
            "receipt_id": draft["predecessor_receipt_id"],
            "receipt_hash": draft["predecessor_receipt_hash"],
        }
        if draft["predecessor_receipt_id"] is not None
        else None,
        "requested_at_ms": requested_at_ms,
    }
    summary_id = _derived(
        "dm:collective-publisher-request:v1:", PUBLISHER_REQUEST_DOMAIN, body
    )
    return {"schema": PUBLISHER_REQUEST_SCHEMA, "summary_id": summary_id, "body": body}


def validate_publisher_request_payload(value: Any) -> dict[str, Any]:
    code = "invalid_collective_publisher_request"
    row = _closed(value, {"schema", "summary_id", "body"}, code)
    if row["schema"] != PUBLISHER_REQUEST_SCHEMA:
        raise CollectiveMemoryError(code)
    body = _closed(
        row["body"],
        {
            "adapter_id",
            "publisher_version",
            "request_id",
            "request_hash",
            "plan_id",
            "plan_hash",
            "idempotency_key",
            "requester_id",
            "subject_id",
            "target_id",
            "action",
            "source_refs",
            "source_checkpoint",
            "classification",
            "policy_version",
            "preview_id",
            "preview_hash",
            "content_hash",
            "content_length",
            "consent",
            "review",
            "predecessor",
            "requested_at_ms",
        },
        code,
    )
    if (
        body["adapter_id"] != PUBLISHER_ADAPTER_ID
        or body["publisher_version"] != PUBLISHER_VERSION
    ):
        raise CollectiveMemoryError(code)
    if body["action"] not in {"publish", "successor", "tombstone"}:
        raise CollectiveMemoryError(code)
    refs = body["source_refs"]
    if not isinstance(refs, list) or not refs:
        raise CollectiveMemoryError(code)
    normalized_refs = [_source_ref(item, code) for item in refs]
    if normalized_refs != sorted(
        normalized_refs, key=lambda item: (item["id"], item["hash"])
    ):
        raise CollectiveMemoryError(code)
    consent = _closed(body["consent"], {"evidence_id", "evidence_hash"}, code)
    review = _closed(body["review"], {"evidence_id", "evidence_hash", "reviewer"}, code)
    predecessor = body["predecessor"]
    if predecessor is not None:
        predecessor = _closed(predecessor, {"receipt_id", "receipt_hash"}, code)
        predecessor = {
            "receipt_id": _identifier(predecessor["receipt_id"], code),
            "receipt_hash": _hash(predecessor["receipt_hash"], code),
        }
    normalized_body = {
        **dict(body),
        "request_id": _identifier(body["request_id"], code),
        "request_hash": _hash(body["request_hash"], code),
        "plan_id": _identifier(body["plan_id"], code),
        "plan_hash": _hash(body["plan_hash"], code),
        "idempotency_key": _identifier(body["idempotency_key"], code),
        "requester_id": _identifier(body["requester_id"], code),
        "subject_id": _identifier(body["subject_id"], code),
        "target_id": _identifier(body["target_id"], code),
        "source_refs": normalized_refs,
        "source_checkpoint": _checkpoint(body["source_checkpoint"], code),
        "classification": _identifier(body["classification"], code),
        "policy_version": _identifier(body["policy_version"], code),
        "preview_id": _identifier(body["preview_id"], code),
        "preview_hash": _hash(body["preview_hash"], code),
        "content_hash": _hash(body["content_hash"], code),
        "content_length": _uint(
            body["content_length"], code, minimum=1, maximum=MAX_PUBLICATION_BYTES
        ),
        "consent": {
            "evidence_id": _identifier(consent["evidence_id"], code),
            "evidence_hash": _hash(consent["evidence_hash"], code),
        },
        "review": {
            "evidence_id": _identifier(review["evidence_id"], code),
            "evidence_hash": _hash(review["evidence_hash"], code),
            "reviewer": _identifier(review["reviewer"], code),
        },
        "predecessor": predecessor,
        "requested_at_ms": _uint(body["requested_at_ms"], code),
    }
    expected_id = _derived(
        "dm:collective-publisher-request:v1:", PUBLISHER_REQUEST_DOMAIN, normalized_body
    )
    if row["summary_id"] != expected_id:
        raise CollectiveMemoryError("collective_publisher_request_identity_mismatch")
    return {
        "schema": PUBLISHER_REQUEST_SCHEMA,
        "summary_id": expected_id,
        "body": normalized_body,
    }


def _publisher_acceptance(
    summary: Mapping[str, Any],
    receipt: Mapping[str, Any],
    reconciliation: Mapping[str, Any],
    *,
    request_event_id: str,
    request_event_hash: str,
    accepted_at_ms: int,
) -> dict[str, Any]:
    body = {
        "adapter_id": PUBLISHER_ADAPTER_ID,
        "publisher_version": PUBLISHER_VERSION,
        "request_event_id": request_event_id,
        "request_event_hash": request_event_hash,
        "request_id": summary["body"]["request_id"],
        "request_hash": summary["body"]["request_hash"],
        "summary_id": summary["summary_id"],
        "provider_receipt": copy.deepcopy(dict(receipt)),
        "reconciliation_state_hash": reconciliation["state_hash"],
        "accepted_at_ms": _uint(accepted_at_ms, "invalid_collective_clock"),
    }
    acceptance_id = _derived(
        "dm:collective-publisher-acceptance:v1:",
        PUBLISHER_ACCEPTANCE_DOMAIN,
        body,
    )
    return {
        "schema": PUBLISHER_ACCEPTANCE_SCHEMA,
        "acceptance_id": acceptance_id,
        "body": body,
    }


def validate_publisher_acceptance_payload(value: Any) -> dict[str, Any]:
    code = "invalid_collective_publisher_acceptance"
    row = _closed(value, {"schema", "acceptance_id", "body"}, code)
    if row["schema"] != PUBLISHER_ACCEPTANCE_SCHEMA:
        raise CollectiveMemoryError(code)
    body = _closed(
        row["body"],
        {
            "adapter_id",
            "publisher_version",
            "request_event_id",
            "request_event_hash",
            "request_id",
            "request_hash",
            "summary_id",
            "provider_receipt",
            "reconciliation_state_hash",
            "accepted_at_ms",
        },
        code,
    )
    if (
        body["adapter_id"] != PUBLISHER_ADAPTER_ID
        or body["publisher_version"] != PUBLISHER_VERSION
    ):
        raise CollectiveMemoryError(code)
    provider = body["provider_receipt"]
    provider_row = _validate_publication_receipt_shape(provider)
    provider_body = provider_row["body"]
    if not isinstance(provider_body, Mapping):
        raise CollectiveMemoryError(code)
    normalized_body = {
        **dict(body),
        "request_event_id": _uuid(body["request_event_id"], code),
        "request_event_hash": _hash(body["request_event_hash"], code),
        "request_id": _identifier(body["request_id"], code),
        "request_hash": _hash(body["request_hash"], code),
        "summary_id": _identifier(body["summary_id"], code),
        "provider_receipt": provider_row,
        "reconciliation_state_hash": _hash(body["reconciliation_state_hash"], code),
        "accepted_at_ms": _uint(body["accepted_at_ms"], code),
    }
    if (
        provider_row["receipt_hash"] != _hash(provider_row["receipt_hash"], code)
        or provider_body.get("request_hash") != normalized_body["request_hash"]
    ):
        raise CollectiveMemoryError("collective_publisher_acceptance_mismatch")
    expected_id = _derived(
        "dm:collective-publisher-acceptance:v1:",
        PUBLISHER_ACCEPTANCE_DOMAIN,
        normalized_body,
    )
    if row["acceptance_id"] != expected_id:
        raise CollectiveMemoryError("collective_publisher_acceptance_identity_mismatch")
    return {
        "schema": PUBLISHER_ACCEPTANCE_SCHEMA,
        "acceptance_id": expected_id,
        "body": normalized_body,
    }


@dataclass(frozen=True)
class CollectivePublisherAdapter:
    ledger: Ledger
    profile: Mapping[str, Any]
    transport: PublisherTransport
    journal: CollectivePublisherJournal
    signer: EventSigner
    consent_issuers: Mapping[str, Mapping[str, Any]]
    review_issuers: Mapping[str, Mapping[str, Any]]
    clock: Clock
    fault: Fault = _no_fault

    def __post_init__(self) -> None:
        profile = validate_publisher_profile(self.profile)
        object.__setattr__(self, "profile", profile)
        if not self.consent_issuers or not self.review_issuers:
            raise CollectiveMemoryError("collective_publication_trust_empty")
        consent = {
            key: self._issuer(value) for key, value in self.consent_issuers.items()
        }
        reviewers = {
            key: self._issuer(value) for key, value in self.review_issuers.items()
        }
        if set(consent) & set(reviewers):
            raise CollectiveMemoryError("collective_publication_roles_overlap")
        object.__setattr__(self, "consent_issuers", consent)
        object.__setattr__(self, "review_issuers", reviewers)
        self.journal.initialize()

    @staticmethod
    def _issuer(value: Mapping[str, Any]) -> dict[str, Any]:
        if set(value) != {
            "principal",
            "public_key",
            "kid",
            "valid_from_ms",
            "valid_until_ms",
            "revoked_at_ms",
        }:
            raise CollectiveMemoryError("invalid_collective_evidence_issuer")
        principal = _identifier(
            value["principal"], "invalid_collective_evidence_issuer"
        )
        try:
            public = unb64url(value["public_key"], length=32)
            kid_hash = unb64url(value["kid"].removeprefix("ed25519:"), length=32)
        except CanonicalError as exception:
            raise CollectiveMemoryError(
                "invalid_collective_evidence_issuer"
            ) from exception
        if (
            not value["kid"].startswith("ed25519:")
            or kid_hash != hashlib.sha256(public).digest()
        ):
            raise CollectiveMemoryError("invalid_collective_evidence_issuer")
        valid_from_ms = _uint(
            value["valid_from_ms"], "invalid_collective_evidence_issuer"
        )
        valid_until_ms = _uint(
            value["valid_until_ms"], "invalid_collective_evidence_issuer"
        )
        revoked_at_ms = value["revoked_at_ms"]
        if revoked_at_ms is not None:
            revoked_at_ms = _uint(revoked_at_ms, "invalid_collective_evidence_issuer")
        if valid_until_ms <= valid_from_ms:
            raise CollectiveMemoryError("invalid_collective_evidence_issuer")
        return {
            "principal": principal,
            "public_key": value["public_key"],
            "kid": value["kid"],
            "valid_from_ms": valid_from_ms,
            "valid_until_ms": valid_until_ms,
            "revoked_at_ms": revoked_at_ms,
        }

    def _verify_sources(self, draft: Mapping[str, Any]) -> None:
        by_id = {event["event_id"]: event for event in _known_events(self.ledger)}
        superseded = {
            event["supersedes"]
            for event in by_id.values()
            if event["supersedes"] is not None
        }
        for ref in draft["source_refs"]:
            event = by_id.get(ref["id"])
            if (
                event is None
                or event["content_hash"] != ref["hash"]
                or ref["id"] in superseded
            ):
                raise CollectiveMemoryError("collective_publication_source_drift")
        checkpoint = collective_checkpoint(
            self.ledger, [cast(str, ref["id"]) for ref in draft["source_refs"]]
        )
        if draft["source_checkpoint"] != {
            "id": checkpoint["id"],
            "hash": checkpoint["hash"],
        }:
            raise CollectiveMemoryError("collective_publication_checkpoint_mismatch")

    def _call(self, operation: str, document: Mapping[str, Any]) -> Mapping[str, Any]:
        try:
            return self.transport(operation, document)
        except CollectiveMemoryError:
            raise
        except (ConnectionError, TimeoutError, OSError) as exception:
            raise CollectiveMemoryError(
                "collective_publisher_unavailable", retryable=True
            ) from exception
        except Exception as exception:
            raise CollectiveMemoryError("collective_publisher_rejected") from exception

    def draft(
        self,
        *,
        source_event_ids: Sequence[str],
        subject_id: str,
        target_id: str,
        action: str,
        classification: str,
        title: str,
        body: str,
        predecessor_receipt_id: str | None,
        predecessor_receipt_hash: str | None,
    ) -> dict[str, Any]:
        checkpoint = collective_checkpoint(self.ledger, source_event_ids)
        value = {
            "schema": PUBLICATION_DRAFT_SCHEMA,
            "action": action,
            "requester_id": self.profile["requester_id"],
            "subject_id": subject_id,
            "target_id": target_id,
            "source_refs": checkpoint["core"]["source_refs"],
            "source_checkpoint": {"id": checkpoint["id"], "hash": checkpoint["hash"]},
            "classification": classification,
            "policy_version": self.profile["policy_version"],
            "media_type": "text/markdown; charset=utf-8",
            "title": title,
            "body": body,
            "predecessor_receipt_id": predecessor_receipt_id,
            "predecessor_receipt_hash": predecessor_receipt_hash,
        }
        return _validate_draft(value, self.profile)

    def preview(self, draft: Mapping[str, Any]) -> dict[str, Any]:
        normalized = _validate_draft(draft, self.profile)
        self._verify_sources(normalized)
        _render_collective(normalized)
        response = self._call("preview", {"draft": normalized})
        return validate_publication_preview(response, normalized)

    def submit(
        self,
        draft: Mapping[str, Any],
        preview: Mapping[str, Any],
        *,
        idempotency_key: str,
        consent: Mapping[str, Any],
        review: Mapping[str, Any],
    ) -> Event:
        normalized_draft = _validate_draft(draft, self.profile)
        normalized_preview = validate_publication_preview(preview, normalized_draft)
        self._verify_sources(normalized_draft)
        consent_body = consent.get("body") if isinstance(consent, Mapping) else None
        review_body = review.get("body") if isinstance(review, Mapping) else None
        if not isinstance(consent_body, Mapping) or not isinstance(
            review_body, Mapping
        ):
            raise CollectiveMemoryError("invalid_collective_evidence")
        consent_issuer = self.consent_issuers.get(cast(str, consent_body.get("issuer")))
        review_issuer = self.review_issuers.get(cast(str, review_body.get("issuer")))
        if consent_issuer is None or review_issuer is None:
            raise CollectiveMemoryError("collective_evidence_issuer_untrusted")
        at = _utc_from_ms(self.clock())
        normalized_consent, consent_hash = validate_publication_evidence(
            consent,
            normalized_draft,
            normalized_preview,
            kind="consent",
            issuer=consent_issuer,
            at=at,
        )
        normalized_review, review_hash = validate_publication_evidence(
            review,
            normalized_draft,
            normalized_preview,
            kind="review",
            issuer=review_issuer,
            at=at,
        )
        if (
            consent_issuer["principal"] != normalized_draft["subject_id"]
            or review_issuer["principal"]
            in {normalized_draft["subject_id"], normalized_draft["requester_id"]}
            or not cast(str, review_issuer["principal"]).startswith("human:")
        ):
            raise CollectiveMemoryError("collective_self_review")
        request = create_publication_request(
            normalized_draft,
            normalized_preview,
            idempotency_key=idempotency_key,
            consent=normalized_consent,
            review=normalized_review,
        )
        raw_plan = self._call("plan", {"request": request})
        plan = validate_publication_plan(
            raw_plan,
            request,
            normalized_preview,
            consent_hash=consent_hash,
            review_hash=review_hash,
        )
        request_hash = hashlib.sha256(
            _canonical(request, "invalid_collective_publication_request")
        ).hexdigest()
        request_id = _derived(
            "dm:collective-publisher-operation:v1:",
            PUBLISHER_REQUEST_DOMAIN,
            {
                "idempotency_key": request["idempotency_key"],
                "request_hash": request_hash,
            },
        )
        request_event_id = str(uuid.uuid5(uuid.NAMESPACE_URL, request_id))
        created_at = self.clock()
        row = self.journal.prepare(
            request_id=request_id,
            request=request,
            preview=normalized_preview,
            plan=plan,
            consent_hash=consent_hash,
            review_hash=review_hash,
            request_event_id=request_event_id,
            created_at_ms=created_at,
        )
        self.fault("publisher-prepared")
        if row["state"] != "prepared":
            event = self.ledger.event(row["request_event_id"])
            if event is None:
                raise CollectiveMemoryError("collective_publication_journal_drift")
            return event
        return self._queue(row)

    def _queue(self, row: Mapping[str, Any]) -> Event:
        summary = _request_summary(
            row["request"],
            row["preview"],
            row["plan"],
            request_id=row["request_id"],
            consent_hash=row["consent_hash"],
            review_hash=row["review_hash"],
            requested_at_ms=row["created_at_ms"],
        )
        summary = validate_publisher_request_payload(summary)
        causal = [item["id"] for item in summary["body"]["source_refs"]]
        predecessor_event = self._predecessor_acceptance(summary["body"]["predecessor"])
        if predecessor_event is not None:
            causal.append(predecessor_event["event_id"])
        event = self.ledger.append_local_idempotent(
            client_id="collective-publisher-v1",
            request_id=row["request_event_id"],
            request_hash=row["request_hash"],
            kind="collective.publication.requested",
            subject=self.ledger.authority.manifest.being_ref,
            payload=summary,
            signer=self.signer,
            sensitivity="shareable"
            if summary["body"]["classification"] == "public"
            else "private",
            causal_parents=causal,
            occurred_at_ms=row["created_at_ms"],
            event_id=row["request_event_id"],
        )
        self.journal.mark_queued(row["request_id"], event)
        self.fault("publisher-queued")
        return event

    def _predecessor_acceptance(
        self, predecessor: Mapping[str, Any] | None
    ) -> Event | None:
        if predecessor is None:
            return None
        matches = []
        for event in _known_events(self.ledger):
            if event["kind"] != "collective.publication.receipted":
                continue
            acceptance = validate_publisher_acceptance_payload(event["payload"])
            receipt = acceptance["body"]["provider_receipt"]
            if (
                receipt["receipt_id"] == predecessor["receipt_id"]
                and receipt["receipt_hash"] == predecessor["receipt_hash"]
            ):
                matches.append(event)
        if len(matches) != 1:
            raise CollectiveMemoryError("collective_publication_predecessor_unknown")
        return matches[0]

    def execute(self, request_event_id: str) -> dict[str, Any]:
        row = self.journal.by_event(
            _uuid(request_event_id, "invalid_collective_request_event")
        )
        if row["state"] == "prepared":
            self._queue(row)
            row = self.journal.by_event(request_event_id)
        request_event = self.ledger.event(request_event_id)
        if (
            request_event is None
            or request_event["kind"] != "collective.publication.requested"
        ):
            raise CollectiveMemoryError("collective_publication_request_event_missing")
        summary = validate_publisher_request_payload(request_event["payload"])
        if summary["body"]["request_hash"] != row["request_hash"]:
            raise CollectiveMemoryError("collective_publication_request_mismatch")
        self._verify_sources(row["request"]["draft"])
        if row["state"] == "accepted":
            acceptance = validate_publisher_acceptance_payload(row["acceptance"])
            self._fresh_reconcile(row["provider_receipt"])
            event = self.ledger.event(row["acceptance_event_id"])
            if event is None or event["payload"] != acceptance:
                raise CollectiveMemoryError("collective_publication_acceptance_missing")
            return {"event": event, "acceptance": acceptance}
        if row["state"] == "queued":
            raw_receipt = self._call(
                "apply", {"request": row["request"], "plan": row["plan"]}
            )
            receipt = validate_publication_receipt(
                raw_receipt,
                row["request"],
                row["plan"],
                consent_hash=row["consent_hash"],
                review_hash=row["review_hash"],
            )
            reconciliation = self._fresh_reconcile(receipt)
            self.journal.mark_effected(row["request_id"], receipt, reconciliation)
            self.fault("publisher-effected")
            row = self.journal.by_event(request_event_id)
        if row["state"] != "effected":
            raise CollectiveMemoryError("collective_publication_state_conflict")
        receipt = validate_publication_receipt(
            row["provider_receipt"],
            row["request"],
            row["plan"],
            consent_hash=row["consent_hash"],
            review_hash=row["review_hash"],
        )
        reconciliation = self._fresh_reconcile(receipt)
        acceptance = _publisher_acceptance(
            summary,
            receipt,
            reconciliation,
            request_event_id=request_event_id,
            request_event_hash=request_event["content_hash"],
            accepted_at_ms=row["created_at_ms"],
        )
        acceptance = validate_publisher_acceptance_payload(acceptance)
        acceptance_event_id = str(
            uuid.uuid5(uuid.NAMESPACE_URL, acceptance["acceptance_id"])
        )
        predecessor_event = self._predecessor_acceptance(summary["body"]["predecessor"])
        event = self.ledger.append_local_idempotent(
            client_id="collective-publisher-acceptance-v1",
            request_id=acceptance_event_id,
            request_hash=hashlib.sha256(
                _canonical(acceptance, "invalid_collective_publication_acceptance")
            ).hexdigest(),
            kind="collective.publication.receipted",
            subject=self.ledger.authority.manifest.being_ref,
            payload=acceptance,
            signer=self.signer,
            sensitivity=request_event["sensitivity"],
            causal_parents=[request_event_id],
            supersedes=None
            if predecessor_event is None
            else predecessor_event["event_id"],
            occurred_at_ms=row["created_at_ms"],
            event_id=acceptance_event_id,
        )
        self.fault("publisher-ledger-appended")
        self.journal.mark_accepted(row["request_id"], acceptance, event)
        self.fault("publisher-accepted")
        return {"event": event, "acceptance": acceptance}

    def _fresh_reconcile(self, receipt: Mapping[str, Any]) -> dict[str, Any]:
        try:
            raw = self._call("reconcile", {"receipt_id": receipt["receipt_id"]})
        except CollectiveMemoryError as exception:
            if exception.retryable:
                raise CollectiveMemoryError(
                    "collective_effect_unverifiable", retryable=True
                ) from exception
            raise
        return validate_publication_reconciliation(raw, receipt)

    def recover(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        self._call("recover", {})
        for row in self.journal.rows(states=["prepared", "queued", "effected"]):
            if row["state"] == "prepared":
                self._queue(row)
            result = self.execute(row["request_event_id"])
            results.append(
                {
                    "request_id": row["request_id"],
                    "acceptance_id": result["acceptance"]["acceptance_id"],
                    "outcome": "accepted",
                }
            )
        return results

    def reconcile(self, acceptance_event_id: str) -> dict[str, Any]:
        event = self.ledger.event(
            _uuid(acceptance_event_id, "invalid_collective_acceptance_event")
        )
        if event is None or event["kind"] != "collective.publication.receipted":
            raise CollectiveMemoryError("collective_publication_acceptance_missing")
        acceptance = validate_publisher_acceptance_payload(event["payload"])
        reconciliation = self._fresh_reconcile(acceptance["body"]["provider_receipt"])
        return {
            "schema": "dm.collective-publisher.reconciliation/v1",
            "acceptance_event_id": acceptance_event_id,
            "acceptance_id": acceptance["acceptance_id"],
            "provider_receipt_id": acceptance["body"]["provider_receipt"]["receipt_id"],
            "state_hash": reconciliation["state_hash"],
            "effect": "verified",
        }


__all__ = [
    "COLLECTIVE_CONTRACT_VERSION",
    "COLLECTIVE_MEMORY_COMMIT",
    "COLLECTIVE_SCHEMA_SHA256",
    "PUBLISHER_ADAPTER_ID",
    "SOURCE_ADAPTER_ID",
    "CollectiveMemoryError",
    "CollectivePublisherAdapter",
    "CollectivePublisherJournal",
    "CollectiveSourceAdapter",
    "CollectiveSourceStore",
    "assert_separate_collective_stores",
    "collective_checkpoint",
    "create_publication_request",
    "create_publisher_manifest",
    "create_publisher_profile",
    "create_source_manifest",
    "create_source_profile",
    "evidence_issuer",
    "sign_publication_evidence",
    "validate_export_manifest",
    "validate_publication_evidence",
    "validate_publication_plan",
    "validate_publication_preview",
    "validate_publication_receipt",
    "validate_publisher_acceptance_payload",
    "validate_publisher_profile",
    "validate_publisher_request_payload",
    "validate_source_preview",
    "validate_source_profile",
    "validate_source_receipt",
]
