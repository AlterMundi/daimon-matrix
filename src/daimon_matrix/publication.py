"""Ledger-authoritative publication through the pinned compaii-state provider.

Matrix owns policy, reviewed intent, source provenance, queue state and accepted
receipts.  The provider owns its configured Wiki/state/HMK transaction roots.
Only closed logical records cross this module's injected transport boundary.
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
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import closing, contextmanager, suppress
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

COMPAII_STATE_COMMIT: Final = "cf56e9de703f68f44b85fdf21f503d55a5557984"
HMK_COMMIT: Final = "f10fd5c3089c0962920314c97e14bc024feffa7a"
PROVIDER_API_VERSION: Final = "1.0.0"
PROVIDER_SCHEMA_VERSION: Final = 1
PROVIDER_CONTRACT_VERSION: Final = "v1"
PROVIDER_ADAPTER_ID: Final = "dm:adapter:v0:OnDIAMjSu2T_8EqLG_wxxygVXCPGXaTJsA41-IMcpSo"
PROVIDER_POLICY_ID: Final = (
    "dm:publisher-policy:v1:iRujh8Aq7rEcAQEERfe2MVUFqhm0TlA5him3TWPm-XY"
)
PROVIDER_POLICY_HASH: Final = (
    "800929a4d56687ca224c5df767ab05c4c259acc75904530848683a92e2484b88"
)
PUBLISHER_PRINCIPAL: Final = "daimon-matrix@localhost"

POLICY_SCHEMA: Final = "dm.publication.policy/v1"
PROFILE_SCHEMA: Final = "dm.publication.profile/v1"
CONTENT_REF_SCHEMA: Final = "dm.publication.content-ref/v1"
CHECKPOINT_SCHEMA: Final = "dm.publication.checkpoint/v1"
PROPOSAL_SCHEMA: Final = "dm.publication.proposal/v1"
REVIEW_SCHEMA: Final = "dm.publication.review/v1"
REQUEST_SCHEMA: Final = "dm.publication.request/v1"
CLAIM_SCHEMA: Final = "dm.publication.claim/v1"
QUEUE_SCHEMA: Final = "dm.publication.queue/v1"
ACCEPTANCE_SCHEMA: Final = "dm.publication.acceptance/v1"
RECONCILIATION_SCHEMA: Final = "dm.publication.reconciliation/v1"
PROVIDER_REQUEST_SCHEMA: Final = "dm.publisher.request/v1"
PROVIDER_PLAN_SCHEMA: Final = "dm.publisher.plan/v1"
PROVIDER_RECEIPT_SCHEMA: Final = "dm.publisher.receipt/v1"
PROVIDER_LEASE_SCHEMA: Final = "dm.publisher.lease/v1"
PROVIDER_RECONCILIATION_SCHEMA: Final = "dm.publisher.reconciliation/v1"
PROVIDER_MANIFEST_SCHEMA: Final = "daimon-adapter-manifest/v0"

ARTIFACT_CLASSES: Final = frozenset(
    {"identity-summary", "decision", "release", "documentation"}
)
TARGET_KINDS: Final = frozenset({"llm-wiki", "compaii-state"})
CLASSIFICATIONS: Final = frozenset({"public", "tribe-shared", "private"})
OPERATIONS: Final = frozenset({"publish", "withdraw", "rollback"})
MAX_CONTENT_BYTES: Final = 16 * 1024 * 1024
MAX_DOCUMENT_BYTES: Final = MAX_CONTENT_BYTES + 2 * 1024 * 1024
MAX_PENDING: Final = 128
MAX_LEASE_MS: Final = 15 * 60 * 1000
MIN_LEASE_MS: Final = 1_000
MAX_UINT: Final = 2**53 - 1

POLICY_DOMAIN: Final = b"daimon/publication/policy/v1\x00"
PROFILE_DOMAIN: Final = b"daimon/publication/profile/v1\x00"
CHECKPOINT_DOMAIN: Final = b"daimon/publication/checkpoint/v1\x00"
PROPOSAL_DOMAIN: Final = b"daimon/publication/proposal/v1\x00"
REVIEW_DOMAIN: Final = b"daimon/publication/review/v1\x00"
REQUEST_DOMAIN: Final = b"daimon/publication/request/v1\x00"
CLAIM_DOMAIN: Final = b"daimon/publication/claim/v1\x00"
ACCEPTANCE_DOMAIN: Final = b"daimon/publication/acceptance/v1\x00"

_HASH = re.compile(r"^[0-9a-f]{64}$")
_DERIVED = re.compile(r"^[A-Za-z0-9_-]{43}$")
_SLUG = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,255}$")
_SECRET = re.compile(
    r"-----BEGIN (?:OPENSSH|RSA|EC|DSA|PGP) PRIVATE KEY-----|"
    r"\b(?:github_"
    r"pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|"
    r"sk-[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{20,})\b"
)
_CREDENTIAL_URL = re.compile(
    r"\b[a-z][a-z0-9+.-]{1,20}://[^/\s:@]{1,128}:[^/\s@]{8,256}@",
    re.IGNORECASE,
)
_CREDENTIAL_ASSIGNMENT = re.compile(
    r"(?im)\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|"
    r"password|private[_-]?key|secret)\b\s*[:=]\s*[\"']?"
    r"(?P<value>[A-Za-z0-9_./+=:@-]{20,512})"
)
_PLACEHOLDERS = (
    "example",
    "placeholder",
    "redacted",
    "replace",
    "sample",
    "your",
    "xxxx",
)


class PublicationError(RuntimeError):
    """Stable fail-closed publication error."""

    def __init__(self, code: str, *, retryable: bool = False) -> None:
        super().__init__(code)
        self.code = code
        self.retryable = retryable


class PublisherTransport(Protocol):
    """Injected provider operation; host configuration never enters documents."""

    def __call__(
        self, operation: str, document: Mapping[str, Any]
    ) -> Mapping[str, Any]: ...


ContentResolver = Callable[[Mapping[str, Any]], bytes]
Clock = Callable[[], int]
Fault = Callable[[str], None]


def _no_fault(_stage: str) -> None:
    return None


def _canonical(value: Any, code: str) -> bytes:
    try:
        raw = canonical_bytes(value)
    except CanonicalError as exception:
        raise PublicationError(code) from exception
    if len(raw) > MAX_DOCUMENT_BYTES:
        raise PublicationError("publication_document_too_large")
    return raw


def _closed(value: Any, fields: set[str], code: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise PublicationError(code)
    return value


def _text(value: Any, code: str, *, maximum: int = 256) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value.encode("utf-8")) <= maximum
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
        or unicodedata.normalize("NFC", value) != value
    ):
        raise PublicationError(code)
    return value


def _token(value: Any, code: str, *, maximum: int = 256) -> str:
    result = _text(value, code, maximum=maximum)
    if _TOKEN.fullmatch(result) is None:
        raise PublicationError(code)
    return result


def _slug(value: Any, code: str) -> str:
    if not isinstance(value, str) or _SLUG.fullmatch(value) is None:
        raise PublicationError(code)
    return value


def _hash(value: Any, code: str) -> str:
    if not isinstance(value, str) or _HASH.fullmatch(value) is None:
        raise PublicationError(code)
    return value


def _derived_hash(value: Any, code: str) -> str:
    if not isinstance(value, str) or _DERIVED.fullmatch(value) is None:
        raise PublicationError(code)
    try:
        unb64url(value, length=32)
    except CanonicalError as exception:
        raise PublicationError(code) from exception
    return value


def _uuid(value: Any, code: str, *, version: int | None = None) -> str:
    if not isinstance(value, str):
        raise PublicationError(code)
    try:
        parsed = uuid.UUID(value)
    except ValueError as exception:
        raise PublicationError(code) from exception
    if str(parsed) != value or (version is not None and parsed.version != version):
        raise PublicationError(code)
    return value


def _uint(value: Any, code: str, *, minimum: int = 0) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= MAX_UINT
    ):
        raise PublicationError(code)
    return value


def _identifier(prefix: str, domain: bytes, value: Mapping[str, Any]) -> str:
    return prefix + b64url(
        hashlib.sha256(domain + _canonical(value, "invalid_artifact")).digest()
    )


def _validate_identifier(value: Any, prefix: str, code: str) -> str:
    result = _text(value, code, maximum=192)
    if not result.startswith(prefix):
        raise PublicationError(code)
    _derived_hash(result.removeprefix(prefix), code)
    return result


def _public_key(value: Any, code: str) -> Ed25519PublicKey:
    raw = unb64url(_text(value, code, maximum=64), length=32)
    return Ed25519PublicKey.from_public_bytes(raw)


def _signature(value: Any, code: str) -> bytes:
    return unb64url(_text(value, code, maximum=128), length=64)


def create_content_ref(
    raw: bytes, *, media_type: str = "text/markdown"
) -> dict[str, Any]:
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= MAX_CONTENT_BYTES:
        raise PublicationError("invalid_publication_content")
    if media_type != "text/markdown":
        raise PublicationError("unsupported_publication_content_type")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exception:
        raise PublicationError("publication_content_not_utf8") from exception
    if unicodedata.normalize("NFC", text) != text:
        raise PublicationError("publication_content_not_nfc")
    return {
        "schema": CONTENT_REF_SCHEMA,
        "media_type": media_type,
        "byte_length": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def validate_content_ref(value: Any) -> dict[str, Any]:
    row = _closed(
        value,
        {"schema", "media_type", "byte_length", "sha256"},
        "invalid_publication_content_ref",
    )
    if row["schema"] != CONTENT_REF_SCHEMA or row["media_type"] != "text/markdown":
        raise PublicationError("invalid_publication_content_ref")
    length = _uint(row["byte_length"], "invalid_publication_content_ref", minimum=1)
    if length > MAX_CONTENT_BYTES:
        raise PublicationError("invalid_publication_content_ref")
    _hash(row["sha256"], "invalid_publication_content_ref")
    return copy.deepcopy(dict(row))


def _resolve_content(reference: Mapping[str, Any], resolver: ContentResolver) -> str:
    normalized = validate_content_ref(reference)
    try:
        raw = resolver(copy.deepcopy(normalized))
    except PublicationError:
        raise
    except Exception as exception:
        raise PublicationError(
            "publication_content_unavailable", retryable=True
        ) from exception
    if (
        not isinstance(raw, bytes)
        or len(raw) != normalized["byte_length"]
        or hashlib.sha256(raw).hexdigest() != normalized["sha256"]
    ):
        raise PublicationError("publication_content_mismatch")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exception:
        raise PublicationError("publication_content_not_utf8") from exception
    if unicodedata.normalize("NFC", text) != text:
        raise PublicationError("publication_content_not_nfc")
    return text


def reviewer_descriptor(principal: str, key: Ed25519PublicKey) -> dict[str, str]:
    principal = _token(principal, "invalid_publication_reviewer", maximum=128)
    encoded = b64url(key.public_bytes_raw())
    key_id = "dm:publication-review-key:v1:" + b64url(
        hashlib.sha256(
            b"daimon/publication/review-key/v1\x00" + key.public_bytes_raw()
        ).digest()
    )
    return {"principal": principal, "key_id": key_id, "public_key": encoded}


def _validate_reviewer(value: Any) -> dict[str, str]:
    row = _closed(
        value,
        {"principal", "key_id", "public_key"},
        "invalid_publication_reviewer",
    )
    principal = _token(row["principal"], "invalid_publication_reviewer", maximum=128)
    key = _public_key(row["public_key"], "invalid_publication_reviewer")
    expected = reviewer_descriptor(principal, key)
    if dict(row) != expected:
        raise PublicationError("invalid_publication_reviewer")
    return expected


def create_publication_policy(
    *,
    subject_me_id: str,
    version: int,
    predecessor_policy_id: str | None,
    reviewers: Sequence[Mapping[str, Any]],
    max_pending: int = MAX_PENDING,
) -> dict[str, Any]:
    normalized_reviewers = sorted(
        (_validate_reviewer(item) for item in reviewers),
        key=lambda item: item["key_id"],
    )
    max_pending_value = _uint(max_pending, "invalid_publication_policy", minimum=1)
    core: dict[str, Any] = {
        "schema": POLICY_SCHEMA,
        "subject_me_id": _token(subject_me_id, "invalid_publication_subject"),
        "version": _uint(version, "invalid_publication_policy", minimum=1),
        "predecessor_policy_id": predecessor_policy_id,
        "publisher_principal": PUBLISHER_PRINCIPAL,
        "renderer": {"id": "matrix:publication-renderer", "version": "1.0.0"},
        "provider": {
            "commit": COMPAII_STATE_COMMIT,
            "adapter_id": PROVIDER_ADAPTER_ID,
            "api_version": PROVIDER_API_VERSION,
            "schema_version": PROVIDER_SCHEMA_VERSION,
            "contract_version": PROVIDER_CONTRACT_VERSION,
            "policy_id": PROVIDER_POLICY_ID,
            "policy_hash": PROVIDER_POLICY_HASH,
            "hmk_commit": HMK_COMMIT,
        },
        "reviewers": normalized_reviewers,
        "targets": [
            {
                "kind": "compaii-state",
                "namespace": "daimon-matrix",
                "artifact_classes": sorted(ARTIFACT_CLASSES),
                "classifications": sorted(CLASSIFICATIONS),
                "licenses": ["CC-BY-SA-4.0", "MPL-2.0"],
            },
            {
                "kind": "llm-wiki",
                "namespace": "daimon-matrix",
                "artifact_classes": sorted(ARTIFACT_CLASSES),
                "classifications": ["public", "tribe-shared"],
                "licenses": ["CC-BY-SA-4.0", "MPL-2.0"],
            },
        ],
        "max_content_bytes": MAX_CONTENT_BYTES,
        "max_pending": max_pending_value,
    }
    if max_pending_value > MAX_PENDING:
        raise PublicationError("invalid_publication_policy")
    if predecessor_policy_id is not None:
        _validate_identifier(
            predecessor_policy_id,
            "dm:publication-policy:v1:",
            "invalid_publication_policy",
        )
    return validate_publication_policy(
        {
            **core,
            "policy_id": _identifier("dm:publication-policy:v1:", POLICY_DOMAIN, core),
        }
    )


def validate_publication_policy(value: Any) -> dict[str, Any]:
    fields = {
        "schema",
        "policy_id",
        "subject_me_id",
        "version",
        "predecessor_policy_id",
        "publisher_principal",
        "renderer",
        "provider",
        "reviewers",
        "targets",
        "max_content_bytes",
        "max_pending",
    }
    row = _closed(value, fields, "invalid_publication_policy")
    if row["schema"] != POLICY_SCHEMA:
        raise PublicationError("unsupported_publication_policy")
    _token(row["subject_me_id"], "invalid_publication_policy")
    version = _uint(row["version"], "invalid_publication_policy", minimum=1)
    predecessor = row["predecessor_policy_id"]
    if (version == 1) != (predecessor is None):
        raise PublicationError("invalid_publication_policy")
    if predecessor is not None:
        _validate_identifier(
            predecessor, "dm:publication-policy:v1:", "invalid_publication_policy"
        )
    if row["publisher_principal"] != PUBLISHER_PRINCIPAL:
        raise PublicationError("unsupported_publication_publisher")
    if row["renderer"] != {"id": "matrix:publication-renderer", "version": "1.0.0"}:
        raise PublicationError("unsupported_publication_renderer")
    expected_provider = {
        "commit": COMPAII_STATE_COMMIT,
        "adapter_id": PROVIDER_ADAPTER_ID,
        "api_version": PROVIDER_API_VERSION,
        "schema_version": PROVIDER_SCHEMA_VERSION,
        "contract_version": PROVIDER_CONTRACT_VERSION,
        "policy_id": PROVIDER_POLICY_ID,
        "policy_hash": PROVIDER_POLICY_HASH,
        "hmk_commit": HMK_COMMIT,
    }
    if row["provider"] != expected_provider:
        raise PublicationError("unsupported_publication_provider")
    raw_reviewers = row["reviewers"]
    if not isinstance(raw_reviewers, list) or not raw_reviewers:
        raise PublicationError("invalid_publication_reviewers")
    reviewers = [_validate_reviewer(item) for item in raw_reviewers]
    if reviewers != sorted(reviewers, key=lambda item: item["key_id"]) or len(
        {item["key_id"] for item in reviewers}
    ) != len(reviewers):
        raise PublicationError("invalid_publication_reviewers")
    targets = row["targets"]
    if not isinstance(targets, list) or len(targets) != 2:
        raise PublicationError("invalid_publication_targets")
    normalized_targets: list[dict[str, Any]] = []
    for value_target in targets:
        target = _closed(
            value_target,
            {"kind", "namespace", "artifact_classes", "classifications", "licenses"},
            "invalid_publication_target_policy",
        )
        if target["kind"] not in TARGET_KINDS or target["namespace"] != "daimon-matrix":
            raise PublicationError("invalid_publication_target_policy")
        if target["artifact_classes"] != sorted(ARTIFACT_CLASSES):
            raise PublicationError("invalid_publication_target_policy")
        expected_classes = (
            sorted(CLASSIFICATIONS)
            if target["kind"] == "compaii-state"
            else ["public", "tribe-shared"]
        )
        if target["classifications"] != expected_classes or target["licenses"] != [
            "CC-BY-SA-4.0",
            "MPL-2.0",
        ]:
            raise PublicationError("invalid_publication_target_policy")
        normalized_targets.append(copy.deepcopy(dict(target)))
    if normalized_targets != sorted(normalized_targets, key=lambda item: item["kind"]):
        raise PublicationError("invalid_publication_targets")
    if row["max_content_bytes"] != MAX_CONTENT_BYTES:
        raise PublicationError("invalid_publication_policy")
    maximum = _uint(row["max_pending"], "invalid_publication_policy", minimum=1)
    if maximum > MAX_PENDING:
        raise PublicationError("invalid_publication_policy")
    core = {key: copy.deepcopy(row[key]) for key in row if key != "policy_id"}
    expected_id = _identifier("dm:publication-policy:v1:", POLICY_DOMAIN, core)
    if row["policy_id"] != expected_id:
        raise PublicationError("publication_policy_id_mismatch")
    return copy.deepcopy(dict(row))


def create_publication_profile(*, source_instance: str) -> dict[str, Any]:
    core = {
        "schema": PROFILE_SCHEMA,
        "source_instance": _token(
            source_instance, "invalid_publication_source_instance"
        ),
        "provider_commit": COMPAII_STATE_COMMIT,
        "provider_adapter_id": PROVIDER_ADAPTER_ID,
        "provider_api_version": PROVIDER_API_VERSION,
        "provider_contract_version": PROVIDER_CONTRACT_VERSION,
        "provider_policy_id": PROVIDER_POLICY_ID,
        "provider_policy_hash": PROVIDER_POLICY_HASH,
        "hmk_commit": HMK_COMMIT,
        "publisher_principal": PUBLISHER_PRINCIPAL,
    }
    return validate_publication_profile(
        {
            **core,
            "profile_id": _identifier(
                "dm:publication-profile:v1:", PROFILE_DOMAIN, core
            ),
        }
    )


def validate_publication_profile(value: Any) -> dict[str, Any]:
    fields = {
        "schema",
        "profile_id",
        "source_instance",
        "provider_commit",
        "provider_adapter_id",
        "provider_api_version",
        "provider_contract_version",
        "provider_policy_id",
        "provider_policy_hash",
        "hmk_commit",
        "publisher_principal",
    }
    row = _closed(value, fields, "invalid_publication_profile")
    fixed = {
        "schema": PROFILE_SCHEMA,
        "provider_commit": COMPAII_STATE_COMMIT,
        "provider_adapter_id": PROVIDER_ADAPTER_ID,
        "provider_api_version": PROVIDER_API_VERSION,
        "provider_contract_version": PROVIDER_CONTRACT_VERSION,
        "provider_policy_id": PROVIDER_POLICY_ID,
        "provider_policy_hash": PROVIDER_POLICY_HASH,
        "hmk_commit": HMK_COMMIT,
        "publisher_principal": PUBLISHER_PRINCIPAL,
    }
    if any(row[key] != expected for key, expected in fixed.items()):
        raise PublicationError("unsupported_publication_profile")
    _token(row["source_instance"], "invalid_publication_profile")
    core = {key: copy.deepcopy(row[key]) for key in row if key != "profile_id"}
    if row["profile_id"] != _identifier(
        "dm:publication-profile:v1:", PROFILE_DOMAIN, core
    ):
        raise PublicationError("publication_profile_id_mismatch")
    return copy.deepcopy(dict(row))


def _known_events(ledger: Ledger) -> list[Event]:
    return ledger.events(include_incomplete=False)


def publication_checkpoint(
    ledger: Ledger, source_event_ids: Sequence[str], *, captured_at_ms: int
) -> dict[str, Any]:
    if list(source_event_ids) != sorted(set(source_event_ids)) or not source_event_ids:
        raise PublicationError("invalid_publication_sources")
    events = _known_events(ledger)
    by_id = {event["event_id"]: event for event in events}
    refs = []
    for event_id in source_event_ids:
        _uuid(event_id, "invalid_publication_source_event")
        event = by_id.get(event_id)
        if event is None:
            raise PublicationError("publication_source_unknown")
        refs.append({"event_id": event_id, "event_hash": event["content_hash"]})
    core = {
        "schema": CHECKPOINT_SCHEMA,
        "being_ref": ledger.authority.manifest.being_ref,
        "manifest_hash": ledger.authority.manifest.digest,
        "source_events": refs,
        "high_waters": {"ledger-events": len(events)},
        "captured_at_ms": _uint(captured_at_ms, "invalid_publication_checkpoint"),
    }
    checkpoint_hash = hashlib.sha256(
        CHECKPOINT_DOMAIN + _canonical(core, "invalid_publication_checkpoint")
    ).hexdigest()
    return {
        **core,
        "checkpoint_id": "dm:publication-checkpoint:v1:" + checkpoint_hash,
        "checkpoint_hash": checkpoint_hash,
    }


def validate_publication_checkpoint(value: Any) -> dict[str, Any]:
    fields = {
        "schema",
        "checkpoint_id",
        "checkpoint_hash",
        "being_ref",
        "manifest_hash",
        "source_events",
        "high_waters",
        "captured_at_ms",
    }
    row = _closed(value, fields, "invalid_publication_checkpoint")
    if row["schema"] != CHECKPOINT_SCHEMA:
        raise PublicationError("unsupported_publication_checkpoint")
    _token(row["being_ref"], "invalid_publication_checkpoint")
    _hash(row["manifest_hash"], "invalid_publication_checkpoint")
    refs = row["source_events"]
    if not isinstance(refs, list) or not refs:
        raise PublicationError("invalid_publication_checkpoint")
    normalized = []
    for value_ref in refs:
        ref = _closed(
            value_ref, {"event_id", "event_hash"}, "invalid_publication_checkpoint"
        )
        normalized.append(
            {
                "event_id": _uuid(ref["event_id"], "invalid_publication_checkpoint"),
                "event_hash": _hash(
                    ref["event_hash"], "invalid_publication_checkpoint"
                ),
            }
        )
    if normalized != sorted(normalized, key=lambda item: item["event_id"]) or len(
        {item["event_id"] for item in normalized}
    ) != len(normalized):
        raise PublicationError("invalid_publication_checkpoint")
    high_waters = row["high_waters"]
    if not isinstance(high_waters, Mapping) or high_waters != {
        "ledger-events": _uint(
            high_waters.get("ledger-events"),
            "invalid_publication_checkpoint",
        )
    }:
        raise PublicationError("invalid_publication_checkpoint")
    _uint(row["captured_at_ms"], "invalid_publication_checkpoint")
    core = {
        key: copy.deepcopy(row[key])
        for key in row
        if key not in {"checkpoint_id", "checkpoint_hash"}
    }
    digest = hashlib.sha256(
        CHECKPOINT_DOMAIN + _canonical(core, "invalid_publication_checkpoint")
    ).hexdigest()
    if row["checkpoint_hash"] != digest or row["checkpoint_id"] != (
        "dm:publication-checkpoint:v1:" + digest
    ):
        raise PublicationError("publication_checkpoint_hash_mismatch")
    return copy.deepcopy(dict(row))


def _target_policy(policy: Mapping[str, Any], kind: str) -> Mapping[str, Any]:
    matches = [item for item in policy["targets"] if item["kind"] == kind]
    if len(matches) != 1:
        raise PublicationError("publication_target_not_allowed")
    return cast(Mapping[str, Any], matches[0])


def _render(
    proposal: Mapping[str, Any], body: str | None, *, validate_ref: bool = True
) -> str:
    governance = cast(Mapping[str, Any], proposal["governance"])
    source = cast(Mapping[str, Any], proposal["source"])
    checkpoint = cast(Mapping[str, Any], source["checkpoint"])
    if proposal["operation"] == "withdraw":
        if body is not None:
            raise PublicationError("withdrawal_content_forbidden")
        rendered_body = "This reviewed publication has been withdrawn.\n"
    else:
        if body is None:
            raise PublicationError("publication_content_required")
        rendered_body = body.rstrip() + "\n"
    text = (
        "---\n"
        f"artifact_class: {proposal['artifact_class']}\n"
        f"source_checkpoint: {checkpoint['checkpoint_id']}\n"
        f"review_decision: {proposal['review_decision_id']}\n"
        f"policy: {proposal['provider_policy_id']}\n"
        f"classification: {governance['classification']}\n"
        f"consent: {governance['consent']}\n"
        f"license: {governance['license']}\n"
        f"derivation: {governance['derivation_ref']}\n"
        "---\n\n"
        f"# {proposal['title']}\n\n"
        f"{rendered_body}"
    )
    raw = text.encode("utf-8")
    if len(raw) > MAX_CONTENT_BYTES:
        raise PublicationError("publication_render_too_large")
    assignment = _CREDENTIAL_ASSIGNMENT.search(text)
    assignment_secret = assignment is not None and not any(
        marker in assignment.group("value").lower() for marker in _PLACEHOLDERS
    )
    if _SECRET.search(text) or _CREDENTIAL_URL.search(text) or assignment_secret:
        raise PublicationError("publication_final_render_secret")
    if validate_ref:
        reference = cast(Mapping[str, Any], proposal["rendered_ref"])
        if (
            reference["media_type"] != "text/markdown; charset=utf-8"
            or reference["byte_length"] != len(raw)
            or reference["sha256"] != hashlib.sha256(raw).hexdigest()
        ):
            raise PublicationError("publication_rendered_ref_mismatch")
    return text


def _current_acceptance(ledger: Ledger, target: Mapping[str, Any]) -> Event | None:
    candidates = []
    for event in _known_events(ledger):
        if event["kind"] != "publication.receipted":
            continue
        acceptance = validate_publication_acceptance(event["payload"])
        if acceptance["target"] == target:
            candidates.append(event)
    if not candidates:
        return None
    by_id = {event["event_id"]: event for event in candidates}
    children: dict[str, list[Event]] = {event_id: [] for event_id in by_id}
    roots = []
    for event in candidates:
        predecessor = event["payload"]["predecessor_acceptance_event_id"]
        if predecessor is None:
            roots.append(event)
        elif predecessor in children:
            children[predecessor].append(event)
        else:
            raise PublicationError("publication_acceptance_chain_gap")
    if len(roots) != 1 or any(len(items) > 1 for items in children.values()):
        raise PublicationError("publication_acceptance_chain_fork")
    current = roots[0]
    seen = set()
    while children[current["event_id"]]:
        if current["event_id"] in seen:
            raise PublicationError("publication_acceptance_chain_fork")
        seen.add(current["event_id"])
        current = children[current["event_id"]][0]
    if len(seen | {current["event_id"]}) != len(candidates):
        raise PublicationError("publication_acceptance_chain_fork")
    return current


def _validate_predecessor(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    row = _closed(
        value,
        {
            "acceptance_event_id",
            "acceptance_event_hash",
            "provider_receipt_id",
            "provider_receipt_hash",
        },
        "invalid_publication_predecessor",
    )
    _uuid(row["acceptance_event_id"], "invalid_publication_predecessor")
    _hash(row["acceptance_event_hash"], "invalid_publication_predecessor")
    _validate_identifier(
        row["provider_receipt_id"],
        "dm:publisher-receipt:v1:",
        "invalid_publication_predecessor",
    )
    _derived_hash(row["provider_receipt_hash"], "invalid_publication_predecessor")
    return copy.deepcopy(dict(row))


def validate_publication_proposal(value: Any) -> dict[str, Any]:
    fields = {
        "schema",
        "proposal_id",
        "provider_request_id",
        "review_decision_id",
        "requested_at_ms",
        "operation",
        "artifact_class",
        "source",
        "title",
        "body_ref",
        "rendered_ref",
        "target",
        "governance",
        "matrix_policy_id",
        "matrix_policy_hash",
        "provider_policy_id",
        "provider_policy_hash",
        "predecessor",
        "relation",
    }
    row = _closed(value, fields, "invalid_publication_proposal")
    if row["schema"] != PROPOSAL_SCHEMA:
        raise PublicationError("unsupported_publication_proposal")
    _uuid(row["provider_request_id"], "invalid_publication_proposal", version=4)
    _uuid(row["review_decision_id"], "invalid_publication_proposal", version=4)
    _uint(row["requested_at_ms"], "invalid_publication_proposal")
    if (
        row["operation"] not in OPERATIONS
        or row["artifact_class"] not in ARTIFACT_CLASSES
    ):
        raise PublicationError("invalid_publication_proposal")
    source = _closed(
        row["source"],
        {"subject_me_id", "author_me_id", "event_refs", "release_ref", "checkpoint"},
        "invalid_publication_source",
    )
    subject = _token(source["subject_me_id"], "invalid_publication_source")
    if _token(source["author_me_id"], "invalid_publication_source") != subject:
        raise PublicationError("publication_author_not_subject")
    checkpoint = validate_publication_checkpoint(source["checkpoint"])
    if (
        checkpoint["being_ref"] != subject
        or source["event_refs"] != checkpoint["source_events"]
    ):
        raise PublicationError("publication_source_checkpoint_mismatch")
    release_ref = source["release_ref"]
    if release_ref is not None:
        release = _closed(
            release_ref,
            {"release_id", "release_hash"},
            "invalid_publication_release_ref",
        )
        _uuid(release["release_id"], "invalid_publication_release_ref")
        _hash(release["release_hash"], "invalid_publication_release_ref")
        if dict(release) not in source["event_refs"]:
            matching = [
                item
                for item in source["event_refs"]
                if item["event_id"] == release["release_id"]
                and item["event_hash"] == release["release_hash"]
            ]
            if not matching:
                raise PublicationError("publication_release_not_source")
    if (row["artifact_class"] == "release") != (release_ref is not None):
        raise PublicationError("publication_release_binding_mismatch")
    _text(row["title"], "invalid_publication_title", maximum=160)
    if row["operation"] == "withdraw":
        if row["body_ref"] is not None:
            raise PublicationError("withdrawal_content_forbidden")
    else:
        validate_content_ref(row["body_ref"])
    rendered = _closed(
        row["rendered_ref"],
        {"media_type", "byte_length", "sha256"},
        "invalid_publication_rendered_ref",
    )
    if rendered["media_type"] != "text/markdown; charset=utf-8":
        raise PublicationError("invalid_publication_rendered_ref")
    if (
        _uint(rendered["byte_length"], "invalid_publication_rendered_ref", minimum=1)
        > MAX_CONTENT_BYTES
    ):
        raise PublicationError("invalid_publication_rendered_ref")
    _hash(rendered["sha256"], "invalid_publication_rendered_ref")
    target = _closed(
        row["target"], {"kind", "logical_id"}, "invalid_publication_target"
    )
    if target["kind"] not in TARGET_KINDS:
        raise PublicationError("invalid_publication_target")
    prefix = "project" if target["kind"] == "llm-wiki" else "projection"
    document = _slug(
        str(target["logical_id"]).rsplit("/", 1)[-1],
        "invalid_publication_target",
    )
    expected = f"{prefix}/daimon-matrix/{document}"
    if target["logical_id"] != expected:
        raise PublicationError("invalid_publication_target")
    governance = _closed(
        row["governance"],
        {"classification", "consent", "license", "derivation_ref"},
        "invalid_publication_governance",
    )
    if (
        governance["classification"] not in CLASSIFICATIONS
        or governance["consent"] != "explicit"
    ):
        raise PublicationError("invalid_publication_governance")
    _token(governance["license"], "invalid_publication_governance", maximum=64)
    _token(governance["derivation_ref"], "invalid_publication_governance")
    _validate_identifier(
        row["matrix_policy_id"],
        "dm:publication-policy:v1:",
        "invalid_publication_policy_ref",
    )
    _hash(row["matrix_policy_hash"], "invalid_publication_policy_ref")
    if (
        row["provider_policy_id"] != PROVIDER_POLICY_ID
        or row["provider_policy_hash"] != PROVIDER_POLICY_HASH
    ):
        raise PublicationError("unsupported_publication_provider_policy")
    predecessor = _validate_predecessor(row["predecessor"])
    relation = _closed(
        row["relation"],
        {"supersedes_acceptance_event_id", "compensates_acceptance_event_id"},
        "invalid_publication_relation",
    )
    for field in relation:
        if relation[field] is not None:
            _uuid(relation[field], "invalid_publication_relation")
    if predecessor is None:
        if row["operation"] != "publish" or any(relation.values()):
            raise PublicationError("invalid_initial_publication")
    elif (
        relation["supersedes_acceptance_event_id"] != predecessor["acceptance_event_id"]
    ):
        raise PublicationError("publication_successor_mismatch")
    if (row["operation"] == "rollback") != (
        relation["compensates_acceptance_event_id"] is not None
    ):
        raise PublicationError("publication_compensation_mismatch")
    if (
        row["operation"] == "rollback"
        and predecessor is not None
        and relation["compensates_acceptance_event_id"]
        != predecessor["acceptance_event_id"]
    ):
        raise PublicationError("publication_compensation_not_predecessor")
    core = {key: copy.deepcopy(row[key]) for key in row if key != "proposal_id"}
    if row["proposal_id"] != _identifier(
        "dm:publication-proposal:v1:", PROPOSAL_DOMAIN, core
    ):
        raise PublicationError("publication_proposal_id_mismatch")
    return copy.deepcopy(dict(row))


def sign_publication_review(
    proposal: Mapping[str, Any],
    *,
    reviewer: Mapping[str, Any],
    private_key: Ed25519PrivateKey,
    issued_at_ms: int,
    expires_at_ms: int,
) -> dict[str, Any]:
    normalized = validate_publication_proposal(proposal)
    descriptor = _validate_reviewer(reviewer)
    if private_key.public_key().public_bytes_raw() != unb64url(
        descriptor["public_key"], length=32
    ):
        raise PublicationError("publication_review_key_mismatch")
    core = {
        "schema": REVIEW_SCHEMA,
        "decision_id": normalized["review_decision_id"],
        "proposal_id": normalized["proposal_id"],
        "proposal_hash": hashlib.sha256(
            _canonical(normalized, "invalid_publication_proposal")
        ).hexdigest(),
        "decision": "approved",
        "reviewer": descriptor,
        "issued_at_ms": _uint(issued_at_ms, "invalid_publication_review"),
        "expires_at_ms": _uint(expires_at_ms, "invalid_publication_review"),
    }
    if (
        not core["issued_at_ms"]
        <= normalized["requested_at_ms"]
        < core["expires_at_ms"]
    ):
        raise PublicationError("invalid_publication_review_window")
    signature = b64url(
        private_key.sign(REVIEW_DOMAIN + _canonical(core, "invalid_publication_review"))
    )
    signed = {**core, "signature": signature}
    return {
        **signed,
        "decision_hash": hashlib.sha256(
            _canonical(signed, "invalid_publication_review")
        ).hexdigest(),
    }


def validate_publication_review(
    value: Any, proposal: Mapping[str, Any], policy: Mapping[str, Any]
) -> dict[str, Any]:
    row = _closed(
        value,
        {
            "schema",
            "decision_id",
            "proposal_id",
            "proposal_hash",
            "decision",
            "reviewer",
            "issued_at_ms",
            "expires_at_ms",
            "signature",
            "decision_hash",
        },
        "invalid_publication_review",
    )
    normalized = validate_publication_proposal(proposal)
    if (
        row["schema"] != REVIEW_SCHEMA
        or row["decision_id"] != normalized["review_decision_id"]
        or row["proposal_id"] != normalized["proposal_id"]
        or row["proposal_hash"]
        != hashlib.sha256(
            _canonical(normalized, "invalid_publication_proposal")
        ).hexdigest()
        or row["decision"] != "approved"
    ):
        raise PublicationError("publication_review_binding_mismatch")
    reviewer = _validate_reviewer(row["reviewer"])
    known = {item["key_id"]: item for item in policy["reviewers"]}
    if (
        known.get(reviewer["key_id"]) != reviewer
        or reviewer["principal"] == policy["publisher_principal"]
    ):
        raise PublicationError("publication_reviewer_not_authorized")
    issued = _uint(row["issued_at_ms"], "invalid_publication_review")
    expires = _uint(row["expires_at_ms"], "invalid_publication_review")
    if not issued <= normalized["requested_at_ms"] < expires:
        raise PublicationError("invalid_publication_review_window")
    core = {
        key: copy.deepcopy(row[key])
        for key in row
        if key not in {"signature", "decision_hash"}
    }
    try:
        _public_key(reviewer["public_key"], "invalid_publication_review").verify(
            _signature(row["signature"], "invalid_publication_review"),
            REVIEW_DOMAIN + _canonical(core, "invalid_publication_review"),
        )
    except InvalidSignature as exception:
        raise PublicationError("publication_review_signature_invalid") from exception
    signed = {**core, "signature": row["signature"]}
    if (
        row["decision_hash"]
        != hashlib.sha256(_canonical(signed, "invalid_publication_review")).hexdigest()
    ):
        raise PublicationError("publication_review_hash_mismatch")
    return copy.deepcopy(dict(row))


def create_publication_request(
    proposal: Mapping[str, Any], policy: Mapping[str, Any], review: Mapping[str, Any]
) -> dict[str, Any]:
    normalized_policy = validate_publication_policy(policy)
    normalized_proposal = validate_publication_proposal(proposal)
    normalized_review = validate_publication_review(
        review, normalized_proposal, normalized_policy
    )
    if (
        normalized_proposal["matrix_policy_id"] != normalized_policy["policy_id"]
        or normalized_proposal["matrix_policy_hash"]
        != hashlib.sha256(
            _canonical(normalized_policy, "invalid_publication_policy")
        ).hexdigest()
    ):
        raise PublicationError("publication_policy_binding_mismatch")
    core = {
        "schema": REQUEST_SCHEMA,
        "proposal": normalized_proposal,
        "policy": normalized_policy,
        "review": normalized_review,
    }
    return validate_publication_request(
        {
            **core,
            "request_id": _identifier(
                "dm:publication-request:v1:", REQUEST_DOMAIN, core
            ),
        }
    )


def validate_publication_request(value: Any) -> dict[str, Any]:
    row = _closed(
        value,
        {"schema", "request_id", "proposal", "policy", "review"},
        "invalid_publication_request",
    )
    if row["schema"] != REQUEST_SCHEMA:
        raise PublicationError("unsupported_publication_request")
    policy = validate_publication_policy(row["policy"])
    proposal = validate_publication_proposal(row["proposal"])
    validate_publication_review(row["review"], proposal, policy)
    if (
        proposal["matrix_policy_id"] != policy["policy_id"]
        or proposal["matrix_policy_hash"]
        != hashlib.sha256(_canonical(policy, "invalid_publication_policy")).hexdigest()
    ):
        raise PublicationError("publication_policy_binding_mismatch")
    target_policy = _target_policy(policy, proposal["target"]["kind"])
    if (
        proposal["artifact_class"] not in target_policy["artifact_classes"]
        or proposal["governance"]["classification"]
        not in target_policy["classifications"]
        or proposal["governance"]["license"] not in target_policy["licenses"]
    ):
        raise PublicationError("publication_policy_refused")
    core = {key: copy.deepcopy(row[key]) for key in row if key != "request_id"}
    if row["request_id"] != _identifier(
        "dm:publication-request:v1:", REQUEST_DOMAIN, core
    ):
        raise PublicationError("publication_request_id_mismatch")
    return copy.deepcopy(dict(row))


def validate_publication_request_payload(value: Any) -> dict[str, Any]:
    """Standalone Weave payload validator used by the event boundary."""

    return validate_publication_request(value)


def _provider_content_id(kind: str, value: Mapping[str, Any]) -> str:
    return f"dm:publisher-{kind}:v1:" + b64url(
        hashlib.sha256(
            f"dm/publisher/{kind}/v1\x00".encode() + canonical_bytes(value)
        ).digest()
    )


def _provider_request(request: Mapping[str, Any], rendered: str) -> dict[str, Any]:
    proposal = cast(Mapping[str, Any], request["proposal"])
    review = cast(Mapping[str, Any], request["review"])
    source = cast(Mapping[str, Any], proposal["source"])
    checkpoint = cast(Mapping[str, Any], source["checkpoint"])
    predecessor = cast(Mapping[str, Any] | None, proposal["predecessor"])
    relation = cast(Mapping[str, Any], proposal["relation"])
    idempotency = b64url(
        hashlib.sha256(
            b"daimon/publication/provider-request/v1\x00" + canonical_bytes(request)
        ).digest()
    )
    return {
        "schema": PROVIDER_REQUEST_SCHEMA,
        "request_id": proposal["provider_request_id"],
        "idempotency_key": idempotency,
        "requested_at_ms": proposal["requested_at_ms"],
        "operation": proposal["operation"],
        "artifact_class": proposal["artifact_class"],
        "source": {
            "subject_me_id": source["subject_me_id"],
            "author_me_id": source["author_me_id"],
            "event_refs": source["event_refs"],
            "release_ref": source["release_ref"],
            "checkpoint": {
                "checkpoint_id": checkpoint["checkpoint_id"],
                "checkpoint_hash": checkpoint["checkpoint_hash"],
                "high_waters": checkpoint["high_waters"],
            },
        },
        "content": {
            "media_type": "text/markdown; charset=utf-8",
            "text": rendered,
            "byte_length": len(rendered.encode("utf-8")),
            "sha256": hashlib.sha256(rendered.encode("utf-8")).hexdigest(),
        },
        "target": copy.deepcopy(proposal["target"]),
        "governance": copy.deepcopy(proposal["governance"]),
        "policy": {
            "policy_id": PROVIDER_POLICY_ID,
            "policy_hash": PROVIDER_POLICY_HASH,
        },
        "review": {
            "decision_id": review["decision_id"],
            "decision_hash": review["decision_hash"],
            "decision": "approved",
            "reviewer_principal": review["reviewer"]["principal"],
            "expires_at_ms": review["expires_at_ms"],
        },
        "publisher_principal": PUBLISHER_PRINCIPAL,
        "predecessor": None
        if predecessor is None
        else {
            "receipt_id": predecessor["provider_receipt_id"],
            "receipt_hash": predecessor["provider_receipt_hash"],
        },
        "relation": {
            "supersedes_receipt_id": None
            if predecessor is None
            else predecessor["provider_receipt_id"],
            "compensates_receipt_id": None
            if relation["compensates_acceptance_event_id"] is None
            else _compensated_provider_receipt(request),
        },
    }


def _compensated_provider_receipt(request: Mapping[str, Any]) -> str:
    proposal = cast(Mapping[str, Any], request["proposal"])
    acceptance_id = proposal["relation"]["compensates_acceptance_event_id"]
    predecessor = cast(Mapping[str, Any] | None, proposal["predecessor"])
    if acceptance_id is None or predecessor is None:
        raise PublicationError("publication_compensation_missing")
    # V1 permits compensation only of the current predecessor.  A later card may
    # explicitly model multi-hop compensation without guessing provider history.
    if acceptance_id != predecessor["acceptance_event_id"]:
        raise PublicationError("publication_compensation_not_predecessor")
    return cast(str, predecessor["provider_receipt_id"])


def _provider_manifest(value: Any) -> dict[str, Any]:
    row = _closed(
        value,
        {
            "schema",
            "adapter_id",
            "authority",
            "capabilities",
            "contracts",
            "limits",
            "provider_kind",
        },
        "invalid_publication_provider_manifest",
    )
    if (
        row["schema"] != PROVIDER_MANIFEST_SCHEMA
        or row["adapter_id"] != PROVIDER_ADAPTER_ID
        or row["provider_kind"] != "artifact-store"
        or row["capabilities"] != ["inspect", "plan", "publish", "reconcile", "recover"]
        or row["contracts"]
        != [{"contract": "publisher-transaction", "versions": ["v1"]}]
        or row["authority"]
        != {
            "matrix_authority": False,
            "may_append_ledger": False,
            "may_issue_presence": False,
            "may_mint_membership": False,
            "may_sign_as_me": False,
        }
        or row["limits"]
        != {
            "max_input_bytes": 17_825_792,
            "max_output_bytes": 2_097_152,
            "max_runtime_ms": 86_400_000,
        }
    ):
        raise PublicationError("unsupported_publication_provider")
    return copy.deepcopy(dict(row))


def _provider_plan(value: Any, request: Mapping[str, Any]) -> dict[str, Any]:
    fields = {
        "schema",
        "plan_id",
        "adapter",
        "hmk_commit",
        "request",
        "request_hash",
        "policy_hash",
        "target",
        "sequence",
        "predecessor_receipt_id",
        "effects",
        "scan",
        "expected_result_hash",
    }
    row = _closed(value, fields, "invalid_publication_provider_plan")
    if (
        row["schema"] != PROVIDER_PLAN_SCHEMA
        or row["adapter"]
        != {
            "id": PROVIDER_ADAPTER_ID,
            "version": PROVIDER_API_VERSION,
            "schema_version": 1,
        }
        or row["hmk_commit"] != HMK_COMMIT
        or row["request"] != request
        or row["request_hash"] != hashlib.sha256(canonical_bytes(request)).hexdigest()
        or row["policy_hash"] != PROVIDER_POLICY_HASH
        or row["target"] != request["target"]
        or row["scan"] != {"engine": "compaii-state-secret-scan/v1", "result": "clean"}
    ):
        raise PublicationError("publication_provider_plan_binding_mismatch")
    sequence = _uint(row["sequence"], "invalid_publication_provider_plan", minimum=1)
    predecessor = cast(Mapping[str, Any] | None, request["predecessor"])
    expected_predecessor = None if predecessor is None else predecessor["receipt_id"]
    if row["predecessor_receipt_id"] != expected_predecessor or (sequence == 1) != (
        predecessor is None
    ):
        raise PublicationError("publication_provider_plan_predecessor_mismatch")
    effects = row["effects"]
    expected_roles = (
        {"artifact", "audit-log", "evidence", "machine-index", "visible-index"}
        if request["target"]["kind"] == "llm-wiki"
        else {"artifact", "audit-log", "evidence", "machine-index"}
    )
    if (
        not isinstance(effects, list)
        or len(effects) != len(expected_roles)
        or [item.get("role") for item in effects if isinstance(item, Mapping)]
        != sorted(expected_roles)
    ):
        raise PublicationError("invalid_publication_provider_effects")
    for value_effect in effects:
        effect = _closed(
            value_effect,
            {
                "role",
                "handle",
                "media_type",
                "text",
                "byte_length",
                "before_sha256",
                "after_sha256",
            },
            "invalid_publication_provider_effect",
        )
        expected_handle = (
            f"{request['target']['kind']}:"
            f"{request['target']['logical_id']}:{effect['role']}"
        )
        expected_media = (
            "application/json"
            if effect["role"] in {"evidence", "machine-index"}
            else "text/markdown; charset=utf-8"
        )
        if (
            effect["handle"] != expected_handle
            or effect["media_type"] != expected_media
            or not isinstance(effect["text"], str)
        ):
            raise PublicationError("invalid_publication_provider_effect")
        raw = effect["text"].encode("utf-8")
        if (
            effect["byte_length"] != len(raw)
            or effect["after_sha256"] != hashlib.sha256(raw).hexdigest()
        ):
            raise PublicationError("invalid_publication_provider_effect")
        if effect["before_sha256"] is not None:
            _hash(effect["before_sha256"], "invalid_publication_provider_effect")
    expected_result = hashlib.sha256(
        canonical_bytes(
            {"target": row["target"], "sequence": sequence, "effects": effects}
        )
    ).hexdigest()
    if row["expected_result_hash"] != expected_result:
        raise PublicationError("publication_provider_result_hash_mismatch")
    core = {key: copy.deepcopy(row[key]) for key in row if key != "plan_id"}
    if row["plan_id"] != _provider_content_id("plan", core):
        raise PublicationError("publication_provider_plan_id_mismatch")
    return copy.deepcopy(dict(row))


def _provider_lease(
    value: Any, *, target: Mapping[str, Any], now: int
) -> dict[str, Any]:
    row = _closed(
        value,
        {
            "schema",
            "lease_id",
            "target_kind",
            "namespace",
            "owner",
            "generation",
            "issued_at_ms",
            "expires_at_ms",
            "state",
            "released_at_ms",
        },
        "invalid_publication_provider_lease",
    )
    if (
        row["schema"] != PROVIDER_LEASE_SCHEMA
        or row["target_kind"] != target["kind"]
        or row["namespace"] != "daimon-matrix"
        or row["owner"] != PUBLISHER_PRINCIPAL
        or row["state"] != "active"
        or row["released_at_ms"] is not None
    ):
        raise PublicationError("publication_provider_lease_binding_mismatch")
    _validate_identifier(
        row["lease_id"], "dm:publisher-lease:v1:", "invalid_publication_provider_lease"
    )
    _uint(row["generation"], "invalid_publication_provider_lease", minimum=1)
    issued = _uint(row["issued_at_ms"], "invalid_publication_provider_lease")
    expires = _uint(row["expires_at_ms"], "invalid_publication_provider_lease")
    if not issued <= now < expires <= issued + MAX_LEASE_MS:
        raise PublicationError("publication_provider_lease_not_live", retryable=True)
    identity = {
        key: row[key]
        for key in (
            "schema",
            "target_kind",
            "namespace",
            "owner",
            "generation",
            "issued_at_ms",
            "expires_at_ms",
        )
    }
    if row["lease_id"] != _provider_content_id("lease", identity):
        raise PublicationError("publication_provider_lease_id_mismatch")
    return copy.deepcopy(dict(row))


def _provider_receipt(
    value: Any,
    *,
    request: Mapping[str, Any],
    plan: Mapping[str, Any],
    lease: Mapping[str, Any],
) -> dict[str, Any]:
    fields = {
        "schema",
        "request_id",
        "request_hash",
        "plan_id",
        "expected_result_hash",
        "target",
        "artifact_class",
        "operation",
        "sequence",
        "predecessor_receipt_id",
        "relation",
        "source_event_refs",
        "source_release_ref",
        "source_checkpoint_id",
        "source_checkpoint_hash",
        "source_checkpoint_high_waters",
        "policy",
        "review",
        "governance",
        "publisher_principal",
        "transaction_id",
        "lease",
        "effects",
        "artifact_sha256",
        "audit_head_sha256",
        "hmk",
        "outcome",
        "committed_at_ms",
        "receipt_id",
        "receipt_hash",
    }
    row = _closed(value, fields, "invalid_publication_provider_receipt")
    _closed(
        row["target"], {"kind", "logical_id"}, "invalid_publication_provider_receipt"
    )
    _closed(
        row["relation"],
        {"supersedes_receipt_id", "compensates_receipt_id"},
        "invalid_publication_provider_receipt",
    )
    if (
        row["schema"] != PROVIDER_RECEIPT_SCHEMA
        or row["request_id"] != request["request_id"]
        or row["request_hash"] != plan["request_hash"]
        or row["plan_id"] != plan["plan_id"]
        or row["expected_result_hash"] != plan["expected_result_hash"]
        or row["target"] != request["target"]
        or row["artifact_class"] != request["artifact_class"]
        or row["operation"] != request["operation"]
        or row["sequence"] != plan["sequence"]
        or row["predecessor_receipt_id"] != plan["predecessor_receipt_id"]
        or row["relation"] != request["relation"]
        or row["source_event_refs"] != request["source"]["event_refs"]
        or row["source_release_ref"] != request["source"]["release_ref"]
        or row["source_checkpoint_id"]
        != request["source"]["checkpoint"]["checkpoint_id"]
        or row["source_checkpoint_hash"]
        != request["source"]["checkpoint"]["checkpoint_hash"]
        or row["source_checkpoint_high_waters"]
        != request["source"]["checkpoint"]["high_waters"]
        or row["policy"] != request["policy"]
        or row["review"] != request["review"]
        or row["governance"] != request["governance"]
        or row["publisher_principal"] != PUBLISHER_PRINCIPAL
        or row["lease"]
        != {"lease_id": lease["lease_id"], "generation": lease["generation"]}
        or row["artifact_sha256"] != request["content"]["sha256"]
    ):
        raise PublicationError("publication_provider_receipt_binding_mismatch")
    expected_effects = [
        {
            "role": effect["role"],
            "handle": effect["handle"],
            "sha256": effect["after_sha256"],
            "byte_length": effect["byte_length"],
        }
        for effect in plan["effects"]
    ]
    if row["effects"] != expected_effects:
        raise PublicationError("publication_provider_receipt_effect_mismatch")
    audit = next(effect for effect in expected_effects if effect["role"] == "audit-log")
    if row["audit_head_sha256"] != audit["sha256"]:
        raise PublicationError("publication_provider_receipt_audit_mismatch")
    hmk = _closed(
        row["hmk"],
        {
            "artifact_chapter_id",
            "evidence_chapter_id",
            "artifact_sha256",
            "evidence_sha256",
            "derived_from",
            "state_hash",
        },
        "invalid_publication_provider_receipt",
    )
    _uint(hmk["artifact_chapter_id"], "invalid_publication_provider_receipt", minimum=1)
    _uint(hmk["evidence_chapter_id"], "invalid_publication_provider_receipt", minimum=1)
    for key in ("artifact_sha256", "evidence_sha256", "state_hash"):
        _hash(hmk[key], "invalid_publication_provider_receipt")
    if hmk["derived_from"] is not True:
        raise PublicationError("invalid_publication_provider_receipt")
    hmk_core = {key: hmk[key] for key in hmk if key != "state_hash"}
    if hmk["state_hash"] != hashlib.sha256(canonical_bytes(hmk_core)).hexdigest():
        raise PublicationError("publication_provider_hmk_hash_mismatch")
    _validate_identifier(
        row["transaction_id"],
        "dm:publisher-transaction:v1:",
        "invalid_publication_provider_receipt",
    )
    outcome = {
        "publish": "published" if plan["sequence"] == 1 else "superseded",
        "withdraw": "tombstoned",
        "rollback": "rolled-back",
    }[request["operation"]]
    if row["outcome"] != outcome:
        raise PublicationError("publication_provider_outcome_mismatch")
    _uint(row["committed_at_ms"], "invalid_publication_provider_receipt")
    body = {
        key: copy.deepcopy(row[key])
        for key in row
        if key not in {"receipt_id", "receipt_hash"}
    }
    expected_id = _provider_content_id("receipt", body)
    digest = expected_id.rsplit(":", 1)[-1]
    if row["receipt_id"] != expected_id or row["receipt_hash"] != digest:
        raise PublicationError("publication_provider_receipt_id_mismatch")
    return copy.deepcopy(dict(row))


def _transport(
    transport: PublisherTransport, operation: str, document: Mapping[str, Any]
) -> dict[str, Any]:
    if operation not in {
        "manifest",
        "plan",
        "acquire",
        "apply",
        "reconcile",
        "release",
    }:
        raise PublicationError("publication_transport_operation_forbidden")
    try:
        result = transport(operation, copy.deepcopy(dict(document)))
    except PublicationError:
        raise
    except Exception as exception:
        raise PublicationError(
            "publication_provider_unavailable", retryable=True
        ) from exception
    if not isinstance(result, Mapping):
        raise PublicationError("invalid_publication_provider_result")
    _canonical(result, "invalid_publication_provider_result")
    return copy.deepcopy(dict(result))


def _provider_receipt_shape(value: Any) -> dict[str, Any]:
    fields = {
        "schema",
        "request_id",
        "request_hash",
        "plan_id",
        "expected_result_hash",
        "target",
        "artifact_class",
        "operation",
        "sequence",
        "predecessor_receipt_id",
        "relation",
        "source_event_refs",
        "source_release_ref",
        "source_checkpoint_id",
        "source_checkpoint_hash",
        "source_checkpoint_high_waters",
        "policy",
        "review",
        "governance",
        "publisher_principal",
        "transaction_id",
        "lease",
        "effects",
        "artifact_sha256",
        "audit_head_sha256",
        "hmk",
        "outcome",
        "committed_at_ms",
        "receipt_id",
        "receipt_hash",
    }
    row = _closed(value, fields, "invalid_publication_provider_receipt")
    target = _closed(
        row["target"], {"kind", "logical_id"}, "invalid_publication_provider_receipt"
    )
    relation = _closed(
        row["relation"],
        {"supersedes_receipt_id", "compensates_receipt_id"},
        "invalid_publication_provider_receipt",
    )
    if (
        row["schema"] != PROVIDER_RECEIPT_SCHEMA
        or row["publisher_principal"] != PUBLISHER_PRINCIPAL
        or row["policy"]
        != {"policy_id": PROVIDER_POLICY_ID, "policy_hash": PROVIDER_POLICY_HASH}
        or row["operation"] not in OPERATIONS
        or target["kind"] not in TARGET_KINDS
        or row["artifact_class"] not in ARTIFACT_CLASSES
    ):
        raise PublicationError("invalid_publication_provider_receipt")
    prefix = "project" if target["kind"] == "llm-wiki" else "projection"
    document = _slug(
        str(target["logical_id"]).rsplit("/", 1)[-1],
        "invalid_publication_provider_receipt",
    )
    if target["logical_id"] != f"{prefix}/daimon-matrix/{document}":
        raise PublicationError("invalid_publication_provider_receipt")
    _uuid(row["request_id"], "invalid_publication_provider_receipt", version=4)
    _validate_identifier(
        row["plan_id"],
        "dm:publisher-plan:v1:",
        "invalid_publication_provider_receipt",
    )
    sequence = _uint(row["sequence"], "invalid_publication_provider_receipt", minimum=1)
    predecessor = row["predecessor_receipt_id"]
    if predecessor is not None:
        _validate_identifier(
            predecessor,
            "dm:publisher-receipt:v1:",
            "invalid_publication_provider_receipt",
        )
    for key in relation:
        if relation[key] is not None:
            _validate_identifier(
                relation[key],
                "dm:publisher-receipt:v1:",
                "invalid_publication_provider_receipt",
            )
    if (sequence == 1) != (predecessor is None):
        raise PublicationError("invalid_publication_provider_receipt")
    if predecessor is None:
        if any(relation.values()) or row["operation"] != "publish":
            raise PublicationError("invalid_publication_provider_receipt")
    elif relation["supersedes_receipt_id"] != predecessor:
        raise PublicationError("invalid_publication_provider_receipt")
    if (row["operation"] == "rollback") != (
        relation["compensates_receipt_id"] is not None
    ):
        raise PublicationError("invalid_publication_provider_receipt")
    for key in (
        "request_hash",
        "expected_result_hash",
        "artifact_sha256",
        "audit_head_sha256",
        "source_checkpoint_hash",
    ):
        _hash(row[key], "invalid_publication_provider_receipt")
    source_refs = row["source_event_refs"]
    if not isinstance(source_refs, list) or not source_refs:
        raise PublicationError("invalid_publication_provider_receipt")
    normalized_refs: list[dict[str, Any]] = []
    for value_ref in source_refs:
        ref = _closed(
            value_ref,
            {"event_id", "event_hash"},
            "invalid_publication_provider_receipt",
        )
        normalized_refs.append(
            {
                "event_id": _token(
                    ref["event_id"], "invalid_publication_provider_receipt"
                ),
                "event_hash": _hash(
                    ref["event_hash"], "invalid_publication_provider_receipt"
                ),
            }
        )
    if normalized_refs != sorted(
        normalized_refs, key=lambda item: cast(str, item["event_id"])
    ) or len({item["event_id"] for item in normalized_refs}) != len(normalized_refs):
        raise PublicationError("invalid_publication_provider_receipt")
    release = row["source_release_ref"]
    if release is not None:
        release_ref = _closed(
            release,
            {"release_id", "release_hash"},
            "invalid_publication_provider_receipt",
        )
        _token(release_ref["release_id"], "invalid_publication_provider_receipt")
        _hash(release_ref["release_hash"], "invalid_publication_provider_receipt")
    if (row["artifact_class"] == "release") != (release is not None):
        raise PublicationError("invalid_publication_provider_receipt")
    _token(row["source_checkpoint_id"], "invalid_publication_provider_receipt")
    waters = row["source_checkpoint_high_waters"]
    if not isinstance(waters, Mapping) or not waters or list(waters) != sorted(waters):
        raise PublicationError("invalid_publication_provider_receipt")
    for name, high_water in waters.items():
        _token(name, "invalid_publication_provider_receipt", maximum=64)
        _uint(high_water, "invalid_publication_provider_receipt")
    review = _closed(
        row["review"],
        {
            "decision_id",
            "decision_hash",
            "decision",
            "reviewer_principal",
            "expires_at_ms",
        },
        "invalid_publication_provider_receipt",
    )
    if review["decision"] != "approved":
        raise PublicationError("invalid_publication_provider_receipt")
    _token(review["decision_id"], "invalid_publication_provider_receipt")
    _hash(review["decision_hash"], "invalid_publication_provider_receipt")
    _token(
        review["reviewer_principal"],
        "invalid_publication_provider_receipt",
        maximum=128,
    )
    expires = _uint(
        review["expires_at_ms"], "invalid_publication_provider_receipt", minimum=1
    )
    governance = _closed(
        row["governance"],
        {"classification", "consent", "license", "derivation_ref"},
        "invalid_publication_provider_receipt",
    )
    if (
        governance["classification"] not in CLASSIFICATIONS
        or governance["consent"] != "explicit"
    ):
        raise PublicationError("invalid_publication_provider_receipt")
    _token(governance["license"], "invalid_publication_provider_receipt", maximum=64)
    _token(governance["derivation_ref"], "invalid_publication_provider_receipt")
    _validate_identifier(
        row["transaction_id"],
        "dm:publisher-transaction:v1:",
        "invalid_publication_provider_receipt",
    )
    lease = _closed(
        row["lease"],
        {"lease_id", "generation"},
        "invalid_publication_provider_receipt",
    )
    _validate_identifier(
        lease["lease_id"],
        "dm:publisher-lease:v1:",
        "invalid_publication_provider_receipt",
    )
    _uint(lease["generation"], "invalid_publication_provider_receipt", minimum=1)
    effects = row["effects"]
    expected_roles = (
        {"artifact", "audit-log", "evidence", "machine-index", "visible-index"}
        if target["kind"] == "llm-wiki"
        else {"artifact", "audit-log", "evidence", "machine-index"}
    )
    if (
        not isinstance(effects, list)
        or len(effects) != len(expected_roles)
        or [item.get("role") for item in effects if isinstance(item, Mapping)]
        != sorted(expected_roles)
    ):
        raise PublicationError("invalid_publication_provider_receipt")
    by_role: dict[str, Mapping[str, Any]] = {}
    for value_effect in effects:
        effect = _closed(
            value_effect,
            {"role", "handle", "sha256", "byte_length"},
            "invalid_publication_provider_receipt",
        )
        role = cast(str, effect["role"])
        expected_handle = f"{target['kind']}:{target['logical_id']}:{role}"
        if role not in expected_roles or effect["handle"] != expected_handle:
            raise PublicationError("invalid_publication_provider_receipt")
        _hash(effect["sha256"], "invalid_publication_provider_receipt")
        _uint(effect["byte_length"], "invalid_publication_provider_receipt")
        by_role[role] = effect
    if (
        row["artifact_sha256"] != by_role["artifact"]["sha256"]
        or row["audit_head_sha256"] != by_role["audit-log"]["sha256"]
    ):
        raise PublicationError("invalid_publication_provider_receipt")
    hmk = _closed(
        row["hmk"],
        {
            "artifact_chapter_id",
            "evidence_chapter_id",
            "artifact_sha256",
            "evidence_sha256",
            "derived_from",
            "state_hash",
        },
        "invalid_publication_provider_receipt",
    )
    _uint(
        hmk["artifact_chapter_id"],
        "invalid_publication_provider_receipt",
        minimum=1,
    )
    _uint(
        hmk["evidence_chapter_id"],
        "invalid_publication_provider_receipt",
        minimum=1,
    )
    for key in ("artifact_sha256", "evidence_sha256", "state_hash"):
        _hash(hmk[key], "invalid_publication_provider_receipt")
    hmk_core = {key: hmk[key] for key in hmk if key != "state_hash"}
    if (
        hmk["derived_from"] is not True
        or hmk["state_hash"] != hashlib.sha256(canonical_bytes(hmk_core)).hexdigest()
    ):
        raise PublicationError("invalid_publication_provider_receipt")
    outcome = {
        "publish": "published" if sequence == 1 else "superseded",
        "withdraw": "tombstoned",
        "rollback": "rolled-back",
    }[cast(str, row["operation"])]
    committed = _uint(row["committed_at_ms"], "invalid_publication_provider_receipt")
    if row["outcome"] != outcome or committed > expires:
        raise PublicationError("invalid_publication_provider_receipt")
    body = {
        key: copy.deepcopy(row[key])
        for key in row
        if key not in {"receipt_id", "receipt_hash"}
    }
    expected_id = _provider_content_id("receipt", body)
    digest = expected_id.rsplit(":", 1)[-1]
    if row["receipt_id"] != expected_id or row["receipt_hash"] != digest:
        raise PublicationError("publication_provider_receipt_id_mismatch")
    return copy.deepcopy(dict(row))


def validate_publication_acceptance(value: Any) -> dict[str, Any]:
    fields = {
        "schema",
        "acceptance_id",
        "request_event_id",
        "request_event_hash",
        "request_id",
        "proposal_id",
        "target",
        "operation",
        "sequence",
        "predecessor_acceptance_event_id",
        "claim_id",
        "claim_generation",
        "provider_commit",
        "provider_receipt",
        "accepted_at_ms",
    }
    row = _closed(value, fields, "invalid_publication_acceptance")
    if (
        row["schema"] != ACCEPTANCE_SCHEMA
        or row["provider_commit"] != COMPAII_STATE_COMMIT
    ):
        raise PublicationError("unsupported_publication_acceptance")
    _uuid(row["request_event_id"], "invalid_publication_acceptance")
    _hash(row["request_event_hash"], "invalid_publication_acceptance")
    _validate_identifier(
        row["request_id"],
        "dm:publication-request:v1:",
        "invalid_publication_acceptance",
    )
    _validate_identifier(
        row["proposal_id"],
        "dm:publication-proposal:v1:",
        "invalid_publication_acceptance",
    )
    target = _closed(
        row["target"], {"kind", "logical_id"}, "invalid_publication_acceptance"
    )
    if target["kind"] not in TARGET_KINDS:
        raise PublicationError("invalid_publication_acceptance")
    if row["operation"] not in OPERATIONS:
        raise PublicationError("invalid_publication_acceptance")
    _uint(row["sequence"], "invalid_publication_acceptance", minimum=1)
    if row["predecessor_acceptance_event_id"] is not None:
        _uuid(row["predecessor_acceptance_event_id"], "invalid_publication_acceptance")
    _uuid(row["claim_id"], "invalid_publication_acceptance", version=4)
    _uint(row["claim_generation"], "invalid_publication_acceptance", minimum=1)
    receipt = _provider_receipt_shape(row["provider_receipt"])
    if (
        receipt["target"] != target
        or receipt["operation"] != row["operation"]
        or receipt["sequence"] != row["sequence"]
        or (row["predecessor_acceptance_event_id"] is None)
        != (receipt["predecessor_receipt_id"] is None)
        or receipt["predecessor_receipt_id"]
        != (
            None
            if row["predecessor_acceptance_event_id"] is None
            else cast(Mapping[str, Any], receipt["relation"])["supersedes_receipt_id"]
        )
    ):
        raise PublicationError("publication_acceptance_provider_mismatch")
    _uint(row["accepted_at_ms"], "invalid_publication_acceptance")
    core = {key: copy.deepcopy(row[key]) for key in row if key != "acceptance_id"}
    if row["acceptance_id"] != _identifier(
        "dm:publication-acceptance:v1:", ACCEPTANCE_DOMAIN, core
    ):
        raise PublicationError("publication_acceptance_id_mismatch")
    return copy.deepcopy(dict(row))


def validate_publication_acceptance_payload(value: Any) -> dict[str, Any]:
    return validate_publication_acceptance(value)


def validate_publication_claim(value: Any) -> dict[str, Any]:
    fields = {
        "schema",
        "claim_id",
        "request_event_id",
        "request_event_hash",
        "target",
        "generation",
        "actor_origin",
        "issued_at_ms",
        "lease_until_ms",
        "content_hash",
    }
    row = _closed(value, fields, "invalid_publication_claim")
    if row["schema"] != CLAIM_SCHEMA:
        raise PublicationError("unsupported_publication_claim")
    _uuid(row["claim_id"], "invalid_publication_claim", version=4)
    _uuid(row["request_event_id"], "invalid_publication_claim")
    _hash(row["request_event_hash"], "invalid_publication_claim")
    target = _closed(row["target"], {"kind", "logical_id"}, "invalid_publication_claim")
    if target["kind"] not in TARGET_KINDS:
        raise PublicationError("invalid_publication_claim")
    _uint(row["generation"], "invalid_publication_claim", minimum=1)
    origin = _closed(
        row["actor_origin"],
        {"body_ref", "embodiment_id", "incarnation_id", "principal_id"},
        "invalid_publication_claim",
    )
    for field in origin:
        _token(origin[field], "invalid_publication_claim")
    issued = _uint(row["issued_at_ms"], "invalid_publication_claim")
    expires = _uint(row["lease_until_ms"], "invalid_publication_claim")
    if not issued + MIN_LEASE_MS <= expires <= issued + MAX_LEASE_MS:
        raise PublicationError("invalid_publication_claim")
    core = {key: copy.deepcopy(row[key]) for key in row if key != "content_hash"}
    expected = hashlib.sha256(
        CLAIM_DOMAIN + _canonical(core, "invalid_publication_claim")
    ).hexdigest()
    if row["content_hash"] != expected:
        raise PublicationError("publication_claim_hash_mismatch")
    return copy.deepcopy(dict(row))


def _assert_no_symlink_ancestors(path: Path) -> None:
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        try:
            info = current.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode):
            raise PublicationError("publication_journal_parent_symlink")
        if not stat.S_ISDIR(info.st_mode):
            raise PublicationError("publication_journal_parent_not_directory")


def _prepare_journal(path: Path) -> None:
    parent = Path(os.path.abspath(path.parent))
    _assert_no_symlink_ancestors(parent)
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    _assert_no_symlink_ancestors(parent)
    info = parent.stat()
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise PublicationError("publication_journal_parent_not_owner_only")
    target = parent / path.name
    try:
        target.lstat()
    except FileNotFoundError:
        try:
            descriptor = os.open(
                target,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
        except OSError as exception:
            raise PublicationError("publication_journal_create_failed") from exception
        os.close(descriptor)
    info = target.lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise PublicationError("publication_journal_not_owner_only")


@dataclass(frozen=True)
class PublicationJournal:
    path: Path

    def initialize(self) -> None:
        _prepare_journal(self.path)
        with closing(self.connect()) as database:
            database.executescript(
                """
                PRAGMA journal_mode=DELETE;
                PRAGMA synchronous=FULL;
                CREATE TABLE IF NOT EXISTS publication_claims (
                    claim_id TEXT PRIMARY KEY,
                    request_event_id TEXT NOT NULL,
                    target_key TEXT NOT NULL,
                    generation INTEGER NOT NULL,
                    issued_at_ms INTEGER NOT NULL,
                    lease_until_ms INTEGER NOT NULL,
                    state TEXT NOT NULL,
                    claim_json BLOB NOT NULL
                ) WITHOUT ROWID;
                CREATE INDEX IF NOT EXISTS publication_claim_target
                    ON publication_claims(target_key, generation);
                CREATE TABLE IF NOT EXISTS publication_attempts (
                    request_event_id TEXT PRIMARY KEY,
                    request_hash TEXT NOT NULL,
                    plan_json BLOB,
                    lease_json BLOB,
                    receipt_json BLOB,
                    acceptance_event_id TEXT,
                    state TEXT NOT NULL
                ) WITHOUT ROWID;
                """
            )

    def connect(self) -> sqlite3.Connection:
        database = sqlite3.connect(self.path, timeout=0, isolation_level=None)
        database.row_factory = sqlite3.Row
        database.execute("PRAGMA foreign_keys=ON")
        database.execute("PRAGMA busy_timeout=0")
        return database

    @contextmanager
    def exclusive(self) -> Iterator[None]:
        lock_path = self.path.with_suffix(self.path.suffix + ".lock")
        _prepare_journal(lock_path)
        descriptor = os.open(lock_path, os.O_RDWR | getattr(os, "O_NOFOLLOW", 0))
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise PublicationError("publication_lock_unsafe")
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exception:
                raise PublicationError(
                    "publication_writer_busy", retryable=True
                ) from exception
            yield
        finally:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)


@dataclass(frozen=True)
class PublicationCoordinator:
    ledger: Ledger
    profile: Mapping[str, Any]
    policy: Mapping[str, Any]
    transport: PublisherTransport
    content_resolver: ContentResolver
    journal: PublicationJournal
    signer: EventSigner
    clock: Clock
    fault: Fault = _no_fault

    def __post_init__(self) -> None:
        profile = validate_publication_profile(self.profile)
        policy = validate_publication_policy(self.policy)
        if policy["subject_me_id"] != self.ledger.authority.manifest.being_ref:
            raise PublicationError("publication_policy_subject_mismatch")
        object.__setattr__(self, "profile", profile)
        object.__setattr__(self, "policy", policy)
        self.journal.initialize()

    def _verify_sources(self, proposal: Mapping[str, Any]) -> None:
        checkpoint = validate_publication_checkpoint(proposal["source"]["checkpoint"])
        if (
            checkpoint["being_ref"] != self.ledger.authority.manifest.being_ref
            or checkpoint["manifest_hash"] != self.ledger.authority.manifest.digest
        ):
            raise PublicationError("publication_checkpoint_authority_mismatch")
        events = _known_events(self.ledger)
        by_id = {event["event_id"]: event for event in events}
        superseded = {
            event["supersedes"] for event in events if event["supersedes"] is not None
        }
        for ref in checkpoint["source_events"]:
            event = by_id.get(ref["event_id"])
            if event is None or event["content_hash"] != ref["event_hash"]:
                raise PublicationError("publication_source_drift")
            if ref["event_id"] in superseded:
                raise PublicationError("publication_source_superseded")
        if len(events) < checkpoint["high_waters"]["ledger-events"]:
            raise PublicationError("publication_checkpoint_regression")

    def draft(
        self,
        *,
        source_event_ids: Sequence[str],
        artifact_class: str,
        target_kind: str,
        document: str,
        title: str,
        body_ref: Mapping[str, Any] | None,
        classification: str,
        license_name: str,
        derivation_ref: str,
        operation: str,
        predecessor_acceptance_event_id: str | None,
        compensates_acceptance_event_id: str | None,
        release_event_id: str | None,
        provider_request_id: str,
        review_decision_id: str,
        requested_at_ms: int,
    ) -> dict[str, Any]:
        if (
            artifact_class not in ARTIFACT_CLASSES
            or target_kind not in TARGET_KINDS
            or operation not in OPERATIONS
        ):
            raise PublicationError("invalid_publication_draft")
        document = _slug(document, "invalid_publication_document")
        title = _text(title, "invalid_publication_title", maximum=160)
        checkpoint = publication_checkpoint(
            self.ledger, source_event_ids, captured_at_ms=requested_at_ms
        )
        source_refs = checkpoint["source_events"]
        release_ref = None
        if release_event_id is not None:
            matches = [
                item for item in source_refs if item["event_id"] == release_event_id
            ]
            if len(matches) != 1:
                raise PublicationError("publication_release_not_source")
            release_ref = {
                "release_id": release_event_id,
                "release_hash": matches[0]["event_hash"],
            }
        prefix = "project" if target_kind == "llm-wiki" else "projection"
        target = {
            "kind": target_kind,
            "logical_id": f"{prefix}/daimon-matrix/{document}",
        }
        current = _current_acceptance(self.ledger, target)
        predecessor = None
        if predecessor_acceptance_event_id is not None:
            if (
                current is None
                or current["event_id"] != predecessor_acceptance_event_id
            ):
                raise PublicationError("publication_predecessor_not_current")
            acceptance = validate_publication_acceptance(current["payload"])
            provider = cast(Mapping[str, Any], acceptance["provider_receipt"])
            predecessor = {
                "acceptance_event_id": current["event_id"],
                "acceptance_event_hash": current["content_hash"],
                "provider_receipt_id": provider["receipt_id"],
                "provider_receipt_hash": provider["receipt_hash"],
            }
        elif current is not None:
            raise PublicationError("publication_predecessor_required")
        relation = {
            "supersedes_acceptance_event_id": predecessor_acceptance_event_id,
            "compensates_acceptance_event_id": compensates_acceptance_event_id,
        }
        normalized_body = None if body_ref is None else validate_content_ref(body_ref)
        core = {
            "schema": PROPOSAL_SCHEMA,
            "provider_request_id": _uuid(
                provider_request_id, "invalid_publication_draft", version=4
            ),
            "review_decision_id": _uuid(
                review_decision_id, "invalid_publication_draft", version=4
            ),
            "requested_at_ms": _uint(requested_at_ms, "invalid_publication_draft"),
            "operation": operation,
            "artifact_class": artifact_class,
            "source": {
                "subject_me_id": self.ledger.authority.manifest.being_ref,
                "author_me_id": self.ledger.authority.manifest.being_ref,
                "event_refs": source_refs,
                "release_ref": release_ref,
                "checkpoint": checkpoint,
            },
            "title": title,
            "body_ref": normalized_body,
            "rendered_ref": {
                "media_type": "text/markdown; charset=utf-8",
                "byte_length": 1,
                "sha256": "0" * 64,
            },
            "target": target,
            "governance": {
                "classification": classification,
                "consent": "explicit",
                "license": license_name,
                "derivation_ref": derivation_ref,
            },
            "matrix_policy_id": self.policy["policy_id"],
            "matrix_policy_hash": hashlib.sha256(
                _canonical(self.policy, "invalid_publication_policy")
            ).hexdigest(),
            "provider_policy_id": PROVIDER_POLICY_ID,
            "provider_policy_hash": PROVIDER_POLICY_HASH,
            "predecessor": predecessor,
            "relation": relation,
        }
        body = (
            None
            if normalized_body is None
            else _resolve_content(normalized_body, self.content_resolver)
        )
        rendered = _render(core, body, validate_ref=False)
        core["rendered_ref"] = {
            "media_type": "text/markdown; charset=utf-8",
            "byte_length": len(rendered.encode("utf-8")),
            "sha256": hashlib.sha256(rendered.encode("utf-8")).hexdigest(),
        }
        proposal = {
            **core,
            "proposal_id": _identifier(
                "dm:publication-proposal:v1:", PROPOSAL_DOMAIN, core
            ),
        }
        normalized = validate_publication_proposal(proposal)
        target_policy = _target_policy(self.policy, target_kind)
        if (
            artifact_class not in target_policy["artifact_classes"]
            or classification not in target_policy["classifications"]
            or license_name not in target_policy["licenses"]
        ):
            raise PublicationError("publication_policy_refused")
        return normalized

    def submit(
        self,
        proposal: Mapping[str, Any],
        review: Mapping[str, Any],
        *,
        client_id: str,
        rpc_request_id: str,
    ) -> Event:
        request = create_publication_request(proposal, self.policy, review)
        normalized = validate_publication_request(request)
        existing = [
            event
            for event in _known_events(self.ledger)
            if event["kind"] == "publication.requested"
            and event["payload"].get("request_id") == normalized["request_id"]
        ]
        if len(existing) > 1:
            raise PublicationError("publication_request_duplicate")
        if existing:
            if existing[0]["payload"] != normalized:
                raise PublicationError("publication_request_equivocation")
            return existing[0]
        self._verify_sources(normalized["proposal"])
        if normalized["review"]["expires_at_ms"] <= self.clock():
            raise PublicationError("publication_review_expired")
        body_ref = normalized["proposal"]["body_ref"]
        body = (
            None
            if body_ref is None
            else _resolve_content(body_ref, self.content_resolver)
        )
        _render(normalized["proposal"], body)
        queue = self.queue()["items"]
        if (
            len([item for item in queue if item["state"] == "pending"])
            >= self.policy["max_pending"]
        ):
            raise PublicationError("publication_backpressure", retryable=True)
        for item in queue:
            if (
                item["state"] == "pending"
                and item["target"] == normalized["proposal"]["target"]
            ):
                raise PublicationError("publication_target_pending", retryable=True)
        causal = [
            item["event_id"] for item in normalized["proposal"]["source"]["event_refs"]
        ]
        predecessor = normalized["proposal"]["predecessor"]
        if predecessor is not None:
            causal.append(predecessor["acceptance_event_id"])
        request_hash = hashlib.sha256(
            _canonical(normalized, "invalid_publication_request")
        ).hexdigest()
        event_id = str(
            uuid.uuid5(uuid.NAMESPACE_URL, normalized["request_id"] + ":event")
        )
        return self.ledger.append_local_idempotent(
            client_id=client_id,
            request_id=rpc_request_id,
            request_hash=request_hash,
            kind="publication.requested",
            subject=self.ledger.authority.manifest.being_ref,
            payload=normalized,
            signer=self.signer,
            sensitivity="private"
            if normalized["proposal"]["governance"]["classification"] == "private"
            else "shareable",
            causal_parents=sorted(set(causal)),
            supersedes=None,
            occurred_at_ms=self.clock(),
            event_id=event_id,
        )

    def _publication_events(self) -> tuple[list[Event], list[Event]]:
        events = _known_events(self.ledger)
        requests = [
            event for event in events if event["kind"] == "publication.requested"
        ]
        acceptances = [
            event for event in events if event["kind"] == "publication.receipted"
        ]
        return requests, acceptances

    def queue(self, cutoff: Mapping[str, Any] | None = None) -> dict[str, Any]:
        all_requests, all_acceptances = self._publication_events()
        by_id = {
            event["event_id"]: event for event in [*all_requests, *all_acceptances]
        }
        current_refs = sorted(
            [
                {"event_id": event["event_id"], "event_hash": event["content_hash"]}
                for event in by_id.values()
            ],
            key=lambda item: item["event_id"],
        )
        refs = current_refs
        if cutoff is not None:
            frozen = _closed(
                cutoff,
                {"events", "checkpoint_id"},
                "invalid_publication_queue_cutoff",
            )
            raw_refs = frozen["events"]
            if not isinstance(raw_refs, list):
                raise PublicationError("invalid_publication_queue_cutoff")
            refs = []
            for raw in raw_refs:
                ref = _closed(
                    raw,
                    {"event_id", "event_hash"},
                    "invalid_publication_queue_cutoff",
                )
                event_id = _uuid(ref["event_id"], "invalid_publication_queue_cutoff")
                event_hash = _hash(
                    ref["event_hash"], "invalid_publication_queue_cutoff"
                )
                event = by_id.get(event_id)
                if event is None or event["content_hash"] != event_hash:
                    raise PublicationError("publication_queue_cutoff_drift")
                refs.append({"event_id": event_id, "event_hash": event_hash})
            if refs != sorted(refs, key=lambda item: item["event_id"]) or len(
                {item["event_id"] for item in refs}
            ) != len(refs):
                raise PublicationError("invalid_publication_queue_cutoff")
        checkpoint_core = {"events": refs}
        checkpoint = {
            "events": refs,
            "checkpoint_id": "dm:publication-queue-checkpoint:v1:"
            + b64url(
                hashlib.sha256(
                    b"daimon/publication/queue-checkpoint/v1\x00"
                    + canonical_bytes(checkpoint_core)
                ).digest()
            ),
        }
        if cutoff is not None and dict(cutoff) != checkpoint:
            raise PublicationError("publication_queue_cutoff_mismatch")
        selected = {item["event_id"] for item in refs}
        requests = [event for event in all_requests if event["event_id"] in selected]
        acceptances = [
            event for event in all_acceptances if event["event_id"] in selected
        ]
        accepted: dict[str, Event] = {}
        for event in acceptances:
            value = validate_publication_acceptance(event["payload"])
            request_event_id = cast(str, value["request_event_id"])
            if request_event_id in accepted:
                raise PublicationError("publication_acceptance_duplicate")
            accepted[request_event_id] = event
        items = []
        seen_requests: set[str] = set()
        for event in sorted(requests, key=lambda item: item["payload"]["request_id"]):
            request = validate_publication_request(event["payload"])
            if request["request_id"] in seen_requests:
                raise PublicationError("publication_request_duplicate")
            seen_requests.add(cast(str, request["request_id"]))
            acceptance = accepted.get(event["event_id"])
            if acceptance is not None:
                accepted_value = validate_publication_acceptance(acceptance["payload"])
                proposal = request["proposal"]
                review = request["review"]
                receipt = accepted_value["provider_receipt"]
                predecessor = proposal["predecessor"]
                expected_predecessor_receipt = (
                    None if predecessor is None else predecessor["provider_receipt_id"]
                )
                if (
                    accepted_value["request_event_hash"] != event["content_hash"]
                    or accepted_value["request_id"] != request["request_id"]
                    or accepted_value["proposal_id"] != proposal["proposal_id"]
                    or accepted_value["target"] != proposal["target"]
                    or accepted_value["operation"] != proposal["operation"]
                    or accepted_value["predecessor_acceptance_event_id"]
                    != (
                        None
                        if predecessor is None
                        else predecessor["acceptance_event_id"]
                    )
                    or receipt["request_id"] != proposal["provider_request_id"]
                    or receipt["artifact_class"] != proposal["artifact_class"]
                    or receipt["source_event_refs"] != proposal["source"]["event_refs"]
                    or receipt["source_release_ref"]
                    != proposal["source"]["release_ref"]
                    or receipt["source_checkpoint_id"]
                    != proposal["source"]["checkpoint"]["checkpoint_id"]
                    or receipt["source_checkpoint_hash"]
                    != proposal["source"]["checkpoint"]["checkpoint_hash"]
                    or receipt["source_checkpoint_high_waters"]
                    != proposal["source"]["checkpoint"]["high_waters"]
                    or receipt["governance"] != proposal["governance"]
                    or receipt["artifact_sha256"] != proposal["rendered_ref"]["sha256"]
                    or receipt["review"]
                    != {
                        "decision_id": review["decision_id"],
                        "decision_hash": review["decision_hash"],
                        "decision": "approved",
                        "reviewer_principal": review["reviewer"]["principal"],
                        "expires_at_ms": review["expires_at_ms"],
                    }
                    or receipt["predecessor_receipt_id"] != expected_predecessor_receipt
                    or receipt["relation"]
                    != {
                        "supersedes_receipt_id": expected_predecessor_receipt,
                        "compensates_receipt_id": expected_predecessor_receipt
                        if proposal["operation"] == "rollback"
                        else None,
                    }
                ):
                    raise PublicationError("publication_acceptance_request_mismatch")
            items.append(
                {
                    "request_event_id": event["event_id"],
                    "request_event_hash": event["content_hash"],
                    "request_id": request["request_id"],
                    "proposal_id": request["proposal"]["proposal_id"],
                    "target": copy.deepcopy(request["proposal"]["target"]),
                    "operation": request["proposal"]["operation"],
                    "state": "completed" if acceptance is not None else "pending",
                    "acceptance_event_id": None
                    if acceptance is None
                    else acceptance["event_id"],
                }
            )
        unknown = set(accepted) - {event["event_id"] for event in requests}
        if unknown:
            raise PublicationError("publication_acceptance_request_missing")
        return {"schema": QUEUE_SCHEMA, "cutoff": checkpoint, "items": items}

    def claim(
        self,
        *,
        request_event_id: str,
        claim_id: str,
        expected_generation: int,
        lease_until_ms: int,
    ) -> dict[str, Any]:
        _uuid(request_event_id, "invalid_publication_claim")
        _uuid(claim_id, "invalid_publication_claim", version=4)
        expected_generation = _uint(expected_generation, "invalid_publication_claim")
        now = _uint(self.clock(), "invalid_publication_clock")
        if not now + MIN_LEASE_MS <= lease_until_ms <= now + MAX_LEASE_MS:
            raise PublicationError("invalid_publication_claim_lease")
        items = {item["request_event_id"]: item for item in self.queue()["items"]}
        item = items.get(request_event_id)
        if item is None:
            raise PublicationError("publication_request_event_unknown")
        if item["state"] != "pending":
            raise PublicationError("publication_request_completed")
        target_key = f"{item['target']['kind']}:{item['target']['logical_id']}"
        with closing(self.journal.connect()) as database:
            database.execute("BEGIN IMMEDIATE")
            try:
                replay = database.execute(
                    "SELECT claim_json FROM publication_claims WHERE claim_id=?",
                    (claim_id,),
                ).fetchone()
                if replay is not None:
                    result = validate_publication_claim(
                        json.loads(bytes(replay["claim_json"]))
                    )
                    if (
                        result["request_event_id"] != request_event_id
                        or result["generation"] != expected_generation + 1
                        or result["lease_until_ms"] != lease_until_ms
                        or now >= result["lease_until_ms"]
                    ):
                        raise PublicationError("publication_claim_conflict")
                    database.commit()
                    return result
                rows = database.execute(
                    "SELECT generation, lease_until_ms, state "
                    "FROM publication_claims WHERE target_key=? "
                    "ORDER BY generation",
                    (target_key,),
                ).fetchall()
                generation = 0 if not rows else int(rows[-1]["generation"])
                if generation != expected_generation:
                    raise PublicationError(
                        "publication_claim_generation_conflict", retryable=True
                    )
                if any(
                    row["state"] == "active" and int(row["lease_until_ms"]) > now
                    for row in rows
                ):
                    raise PublicationError("publication_target_claimed", retryable=True)
                database.execute(
                    "UPDATE publication_claims SET state='expired' "
                    "WHERE target_key=? AND state='active' AND lease_until_ms<=?",
                    (target_key, now),
                )
                core = {
                    "schema": CLAIM_SCHEMA,
                    "claim_id": claim_id,
                    "request_event_id": request_event_id,
                    "request_event_hash": item["request_event_hash"],
                    "target": item["target"],
                    "generation": generation + 1,
                    "actor_origin": copy.deepcopy(self.ledger.local_origin),
                    "issued_at_ms": now,
                    "lease_until_ms": lease_until_ms,
                }
                claim = validate_publication_claim(
                    {
                        **core,
                        "content_hash": hashlib.sha256(
                            CLAIM_DOMAIN + _canonical(core, "invalid_publication_claim")
                        ).hexdigest(),
                    }
                )
                database.execute(
                    "INSERT INTO publication_claims VALUES "
                    "(?, ?, ?, ?, ?, ?, 'active', ?)",
                    (
                        claim_id,
                        request_event_id,
                        target_key,
                        generation + 1,
                        now,
                        lease_until_ms,
                        canonical_bytes(claim),
                    ),
                )
                database.commit()
                return claim
            except BaseException:
                database.rollback()
                raise

    def _request_event(self, event_id: str) -> Event:
        event = self.ledger.event(event_id, include_incomplete=False)
        if event is None or event["kind"] != "publication.requested":
            raise PublicationError("publication_request_event_unknown")
        validate_publication_request(event["payload"])
        return event

    def _load_claim(self, claim_id: str) -> dict[str, Any]:
        with closing(self.journal.connect()) as database:
            row = database.execute(
                "SELECT claim_json, state FROM publication_claims WHERE claim_id=?",
                (claim_id,),
            ).fetchone()
        if row is None:
            raise PublicationError("publication_claim_unknown")
        claim = validate_publication_claim(json.loads(bytes(row["claim_json"])))
        if row["state"] not in {"active", "completed"}:
            raise PublicationError("publication_claim_not_live", retryable=True)
        if row["state"] == "active" and claim["lease_until_ms"] <= self.clock():
            raise PublicationError("publication_claim_not_live", retryable=True)
        return claim

    def _accepted_for_request(self, event_id: str) -> Event | None:
        matches = [
            event
            for event in _known_events(self.ledger)
            if event["kind"] == "publication.receipted"
            and event["payload"].get("request_event_id") == event_id
        ]
        if len(matches) > 1:
            raise PublicationError("publication_acceptance_duplicate")
        return None if not matches else matches[0]

    def _reconcile_provider(self, receipt: Mapping[str, Any]) -> None:
        result = _transport(self.transport, "reconcile", {"receipt": receipt})
        row = _closed(
            result,
            {"schema", "receipt_id", "target", "status"},
            "invalid_publication_reconciliation",
        )
        if (
            row["schema"] != PROVIDER_RECONCILIATION_SCHEMA
            or row["receipt_id"] != receipt["receipt_id"]
            or row["target"] != receipt["target"]
            or row["status"] != "verified"
        ):
            raise PublicationError("publication_effect_truth_discrepancy")

    def execute(self, *, claim_id: str) -> dict[str, Any]:
        with self.journal.exclusive():
            claim = self._load_claim(claim_id)
            request_event = self._request_event(claim["request_event_id"])
            if request_event["content_hash"] != claim["request_event_hash"]:
                raise PublicationError("publication_claim_request_drift")
            request = validate_publication_request(request_event["payload"])
            existing = self._accepted_for_request(request_event["event_id"])
            if existing is not None:
                acceptance = validate_publication_acceptance(existing["payload"])
                self._reconcile_provider(acceptance["provider_receipt"])
                self._finish_claim(claim_id)
                return {"event": existing, "acceptance": acceptance}
            proposal = request["proposal"]
            self._verify_sources(proposal)
            if request["review"]["expires_at_ms"] <= self.clock():
                raise PublicationError("publication_review_expired")
            current = _current_acceptance(self.ledger, proposal["target"])
            predecessor = proposal["predecessor"]
            if (current is None) != (predecessor is None) or (
                current is not None
                and current["event_id"] != predecessor["acceptance_event_id"]
            ):
                raise PublicationError("publication_predecessor_not_current")
            body_ref = proposal["body_ref"]
            body = (
                None
                if body_ref is None
                else _resolve_content(body_ref, self.content_resolver)
            )
            rendered = _render(proposal, body)
            provider_request = _provider_request(request, rendered)
            _provider_manifest(_transport(self.transport, "manifest", {}))
            request_hash = hashlib.sha256(
                _canonical(request, "invalid_publication_request")
            ).hexdigest()
            with closing(self.journal.connect()) as database:
                row = database.execute(
                    "SELECT * FROM publication_attempts WHERE request_event_id=?",
                    (request_event["event_id"],),
                ).fetchone()
                if row is None:
                    database.execute(
                        "INSERT INTO publication_attempts VALUES "
                        "(?, ?, NULL, NULL, NULL, NULL, 'pending')",
                        (request_event["event_id"], request_hash),
                    )
                    plan = None
                    lease = None
                else:
                    if row["request_hash"] != request_hash:
                        raise PublicationError("publication_attempt_conflict")
                    plan = (
                        None
                        if row["plan_json"] is None
                        else json.loads(bytes(row["plan_json"]))
                    )
                    lease = (
                        None
                        if row["lease_json"] is None
                        else json.loads(bytes(row["lease_json"]))
                    )
            if plan is None:
                plan = _provider_plan(
                    _transport(self.transport, "plan", {"request": provider_request}),
                    provider_request,
                )
                self._store_attempt(request_event["event_id"], plan=plan)
            else:
                plan = _provider_plan(plan, provider_request)
            now = self.clock()
            if (
                lease is None
                or lease.get("expires_at_ms", 0) <= now
                or lease.get("state") != "active"
            ):
                ttl = min(600_000, claim["lease_until_ms"] - now)
                if ttl < MIN_LEASE_MS:
                    raise PublicationError(
                        "publication_claim_near_expiry", retryable=True
                    )
                lease = _provider_lease(
                    _transport(
                        self.transport,
                        "acquire",
                        {
                            "target_kind": proposal["target"]["kind"],
                            "namespace": "daimon-matrix",
                            "owner": PUBLISHER_PRINCIPAL,
                            "ttl_ms": ttl,
                        },
                    ),
                    target=proposal["target"],
                    now=now,
                )
                self._store_attempt(request_event["event_id"], lease=lease)
            else:
                lease = _provider_lease(lease, target=proposal["target"], now=now)
            provider_receipt = _provider_receipt(
                _transport(self.transport, "apply", {"plan": plan, "lease": lease}),
                request=provider_request,
                plan=plan,
                lease=lease,
            )
            self._reconcile_provider(provider_receipt)
            self._store_attempt(request_event["event_id"], receipt=provider_receipt)
            self.fault("after_provider_receipt")
            acceptance_core = {
                "schema": ACCEPTANCE_SCHEMA,
                "request_event_id": request_event["event_id"],
                "request_event_hash": request_event["content_hash"],
                "request_id": request["request_id"],
                "proposal_id": proposal["proposal_id"],
                "target": copy.deepcopy(proposal["target"]),
                "operation": proposal["operation"],
                "sequence": provider_receipt["sequence"],
                "predecessor_acceptance_event_id": None
                if predecessor is None
                else predecessor["acceptance_event_id"],
                "claim_id": claim["claim_id"],
                "claim_generation": claim["generation"],
                "provider_commit": COMPAII_STATE_COMMIT,
                "provider_receipt": provider_receipt,
                "accepted_at_ms": self.clock(),
            }
            acceptance = validate_publication_acceptance(
                {
                    **acceptance_core,
                    "acceptance_id": _identifier(
                        "dm:publication-acceptance:v1:",
                        ACCEPTANCE_DOMAIN,
                        acceptance_core,
                    ),
                }
            )
            event_uuid = str(
                uuid.uuid5(uuid.NAMESPACE_URL, acceptance["acceptance_id"] + ":event")
            )
            rpc_uuid = str(
                uuid.uuid5(uuid.NAMESPACE_URL, acceptance["acceptance_id"] + ":rpc")
            )
            event = self.ledger.append_local_idempotent(
                client_id="matrix-publication",
                request_id=rpc_uuid,
                request_hash=hashlib.sha256(
                    _canonical(acceptance, "invalid_publication_acceptance")
                ).hexdigest(),
                kind="publication.receipted",
                subject=self.ledger.authority.manifest.being_ref,
                payload=acceptance,
                signer=self.signer,
                sensitivity=request_event["sensitivity"],
                causal_parents=[request_event["event_id"]],
                supersedes=None
                if predecessor is None
                else predecessor["acceptance_event_id"],
                occurred_at_ms=self.clock(),
                event_id=event_uuid,
            )
            self.fault("after_matrix_acceptance")
            self._store_attempt(
                request_event["event_id"],
                acceptance_event_id=event["event_id"],
                state="completed",
            )
            self._finish_claim(claim_id)
            with suppress(PublicationError):
                _transport(self.transport, "release", {"lease": lease})
            return {"event": event, "acceptance": acceptance}

    def _store_attempt(
        self,
        request_event_id: str,
        *,
        plan: Mapping[str, Any] | None = None,
        lease: Mapping[str, Any] | None = None,
        receipt: Mapping[str, Any] | None = None,
        acceptance_event_id: str | None = None,
        state: str | None = None,
    ) -> None:
        fields = []
        values: list[Any] = []
        for name, value in (
            ("plan_json", plan),
            ("lease_json", lease),
            ("receipt_json", receipt),
        ):
            if value is not None:
                fields.append(f"{name}=?")
                values.append(canonical_bytes(value))
        if acceptance_event_id is not None:
            fields.append("acceptance_event_id=?")
            values.append(acceptance_event_id)
        if state is not None:
            fields.append("state=?")
            values.append(state)
        if not fields:
            return
        values.append(request_event_id)
        with closing(self.journal.connect()) as database:
            database.execute(
                f"UPDATE publication_attempts SET {', '.join(fields)} "
                "WHERE request_event_id=?",
                values,
            )

    def _finish_claim(self, claim_id: str) -> None:
        with closing(self.journal.connect()) as database:
            database.execute(
                "UPDATE publication_claims SET state='completed' WHERE claim_id=?",
                (claim_id,),
            )

    def reconcile(self, acceptance_event_id: str) -> dict[str, Any]:
        event = self.ledger.event(acceptance_event_id, include_incomplete=False)
        if event is None or event["kind"] != "publication.receipted":
            raise PublicationError("publication_acceptance_unknown")
        acceptance = validate_publication_acceptance(event["payload"])
        request_event = self._request_event(acceptance["request_event_id"])
        if request_event["content_hash"] != acceptance["request_event_hash"]:
            raise PublicationError("publication_request_event_drift")
        current = _current_acceptance(self.ledger, acceptance["target"])
        if current is None or current["event_id"] != event["event_id"]:
            return {
                "schema": RECONCILIATION_SCHEMA,
                "acceptance_event_id": event["event_id"],
                "status": "superseded",
            }
        try:
            self._reconcile_provider(acceptance["provider_receipt"])
        except PublicationError as exception:
            return {
                "schema": RECONCILIATION_SCHEMA,
                "acceptance_event_id": event["event_id"],
                "status": "effect-truth-unverifiable"
                if exception.retryable
                else "effect-truth-discrepancy",
            }
        return {
            "schema": RECONCILIATION_SCHEMA,
            "acceptance_event_id": event["event_id"],
            "status": "verified",
        }


__all__ = [
    "ACCEPTANCE_SCHEMA",
    "ARTIFACT_CLASSES",
    "COMPAII_STATE_COMMIT",
    "HMK_COMMIT",
    "PROVIDER_ADAPTER_ID",
    "PROVIDER_API_VERSION",
    "PROVIDER_POLICY_HASH",
    "PROVIDER_POLICY_ID",
    "PublicationCoordinator",
    "PublicationError",
    "PublicationJournal",
    "PublisherTransport",
    "create_content_ref",
    "create_publication_policy",
    "create_publication_profile",
    "create_publication_request",
    "publication_checkpoint",
    "reviewer_descriptor",
    "sign_publication_review",
    "validate_content_ref",
    "validate_publication_acceptance",
    "validate_publication_acceptance_payload",
    "validate_publication_checkpoint",
    "validate_publication_claim",
    "validate_publication_policy",
    "validate_publication_profile",
    "validate_publication_proposal",
    "validate_publication_request",
    "validate_publication_request_payload",
    "validate_publication_review",
]
