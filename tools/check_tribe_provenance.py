#!/usr/bin/env python3
"""Validate the closed DM-050 Tribe Bridge no-copy provenance manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Any, Final

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from daimon_matrix.canonical import CanonicalError, canonical_bytes

SCHEMA: Final = "tribe-import-manifest/v1"
EXPECTED_REPOSITORY: Final = "https://github.com/nicoechaniz/tribe-bridge"
EXPECTED_COMMIT: Final = "b81a6838dd81167f7a8ffcae82cd7ebaadfa21e2"
EXPECTED_TREE: Final = "1fc32b48867b8068a3ce6949bd84694bfd34177f"
EXPECTED_MANIFEST_SHA256: Final = (
    "68acd3655763c6db04aa694965bccdc56b253062d949398c47c28b9aa62e2eaf"
)
MAX_MANIFEST_BYTES: Final = 256 * 1024
ROOT_FIELDS: Final = {"items", "policy", "schema", "upstream"}
UPSTREAM_FIELDS: Final = {
    "commit",
    "commit_date",
    "license_paths",
    "license_status",
    "repository",
    "tree",
}
POLICY_FIELDS: Final = {
    "authorization_required_for_copy",
    "copy_allowed",
    "live_state_imported",
    "reuse_mode",
    "runtime_dependency_added",
    "source_imported",
}
ITEM_FIELDS: Final = {
    "artifact_kind",
    "behaviors",
    "classification",
    "copy_allowed",
    "destination_cards",
    "git_blob_sha1",
    "path",
    "rationale",
    "sha256",
    "size",
}
ARTIFACT_KINDS: Final = {
    "manifest",
    "operations_doc",
    "schema",
    "source",
    "specification",
    "test",
}
CLASSIFICATIONS: Final = {"behavioral_reference_only", "superseded"}
GIT_HASH = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
CARD = re.compile(r"^DM-[0-9]{3}$")
TOKEN = re.compile(r"^[a-z][a-z0-9-]{2,63}$")
SAFE_PATH = re.compile(r"^[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+$")
FORBIDDEN_PARTS: Final = {
    ".env",
    "backups",
    "credentials",
    "keys",
    "messages",
    "runtime",
    "secrets",
    "state",
}
FORBIDDEN_SUFFIXES: Final = (".db", ".key", ".pem", ".sqlite", ".sqlite3")


class ProvenanceError(ValueError):
    """The provenance manifest can widen or misrepresent the no-copy gate."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProvenanceError("duplicate_json_key")
        result[key] = value
    return result


def _closed(value: Any, fields: set[str], reason: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ProvenanceError(reason)
    return value


def _sorted_strings(
    value: Any,
    *,
    pattern: re.Pattern[str],
    maximum: int,
    reason: str,
) -> list[str]:
    if not isinstance(value, list) or not 1 <= len(value) <= maximum:
        raise ProvenanceError(reason)
    if any(
        not isinstance(item, str) or pattern.fullmatch(item) is None for item in value
    ):
        raise ProvenanceError(reason)
    if value != sorted(set(value)):
        raise ProvenanceError(reason)
    return value


def _validate_item(raw: Any) -> dict[str, Any]:
    item = _closed(raw, ITEM_FIELDS, "invalid_item_shape")
    path_value = item["path"]
    if (
        not isinstance(path_value, str)
        or len(path_value) > 256
        or SAFE_PATH.fullmatch(path_value) is None
    ):
        raise ProvenanceError("invalid_upstream_path")
    path = PurePosixPath(path_value)
    if (
        path.is_absolute()
        or any(part in FORBIDDEN_PARTS for part in path.parts)
        or path.name.lower().endswith(FORBIDDEN_SUFFIXES)
    ):
        raise ProvenanceError("forbidden_upstream_artifact")
    if (
        not isinstance(item["git_blob_sha1"], str)
        or GIT_HASH.fullmatch(item["git_blob_sha1"]) is None
    ):
        raise ProvenanceError("invalid_blob_hash")
    if not isinstance(item["sha256"], str) or SHA256.fullmatch(item["sha256"]) is None:
        raise ProvenanceError("invalid_sha256")
    size = item["size"]
    if (
        isinstance(size, bool)
        or not isinstance(size, int)
        or not 1 <= size <= 1024 * 1024
    ):
        raise ProvenanceError("invalid_item_size")
    if (
        not isinstance(item["artifact_kind"], str)
        or item["artifact_kind"] not in ARTIFACT_KINDS
    ):
        raise ProvenanceError("invalid_artifact_kind")
    if (
        not isinstance(item["classification"], str)
        or item["classification"] not in CLASSIFICATIONS
    ):
        raise ProvenanceError("invalid_classification")
    _sorted_strings(
        item["destination_cards"], pattern=CARD, maximum=8, reason="invalid_cards"
    )
    _sorted_strings(
        item["behaviors"], pattern=TOKEN, maximum=16, reason="invalid_behaviors"
    )
    rationale = item["rationale"]
    if (
        not isinstance(rationale, str)
        or not 1 <= len(rationale.encode()) <= 512
        or any(ord(character) < 0x20 for character in rationale)
    ):
        raise ProvenanceError("invalid_rationale")
    if item["copy_allowed"] is not False:
        raise ProvenanceError("source_copy_forbidden")
    return dict(item)


def validate_manifest(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
    except OSError as exception:
        raise ProvenanceError("manifest_unavailable") from exception
    if not 1 <= len(raw) <= MAX_MANIFEST_BYTES:
        raise ProvenanceError("manifest_size_invalid")
    try:
        value = json.loads(raw, object_pairs_hook=_unique_object)
        canonical = canonical_bytes(value)
    except (CanonicalError, UnicodeDecodeError, json.JSONDecodeError) as exception:
        raise ProvenanceError("manifest_json_invalid") from exception
    root = _closed(value, ROOT_FIELDS, "invalid_manifest_shape")
    if root["schema"] != SCHEMA:
        raise ProvenanceError("invalid_manifest_schema")
    upstream = _closed(root["upstream"], UPSTREAM_FIELDS, "invalid_upstream_shape")
    if (
        upstream["repository"] != EXPECTED_REPOSITORY
        or upstream["commit"] != EXPECTED_COMMIT
        or upstream["tree"] != EXPECTED_TREE
        or upstream["commit_date"] != "2026-08-04T05:04:28Z"
        or upstream["license_status"] != "no_license_detected"
        or upstream["license_paths"] != []
    ):
        raise ProvenanceError("upstream_pin_mismatch")
    policy = _closed(root["policy"], POLICY_FIELDS, "invalid_policy_shape")
    expected_policy = {
        "authorization_required_for_copy": True,
        "copy_allowed": False,
        "live_state_imported": False,
        "reuse_mode": "behavioral_reference_only",
        "runtime_dependency_added": False,
        "source_imported": False,
    }
    if dict(policy) != expected_policy:
        raise ProvenanceError("no_copy_policy_mismatch")
    raw_items = root["items"]
    if not isinstance(raw_items, list) or not 1 <= len(raw_items) <= 64:
        raise ProvenanceError("invalid_item_count")
    items = [_validate_item(item) for item in raw_items]
    paths = [item["path"] for item in items]
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        raise ProvenanceError("item_paths_not_unique_sorted")
    digest = hashlib.sha256(canonical).hexdigest()
    if digest != EXPECTED_MANIFEST_SHA256:
        raise ProvenanceError("manifest_digest_mismatch")
    return {
        "schema": SCHEMA,
        "manifest_sha256": digest,
        "upstream_commit": EXPECTED_COMMIT,
        "item_count": len(items),
        "behavioral_reference_count": sum(
            item["classification"] == "behavioral_reference_only" for item in items
        ),
        "superseded_count": sum(
            item["classification"] == "superseded" for item in items
        ),
        "copy_allowed": False,
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("manifest", type=Path)
    return result


def main(argv: Sequence[str] | None = None) -> int:
    try:
        summary = validate_manifest(parser().parse_args(argv).manifest)
    except (OSError, ProvenanceError) as exception:
        print(str(exception), file=sys.stderr)
        return 1
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["ProvenanceError", "main", "parser", "validate_manifest"]
